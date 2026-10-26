package workload

import (
	"context"
	"time"

	"github.com/SantanaCharles/sentinels/internal/discovery"
	"github.com/SantanaCharles/sentinels/internal/event"
	"github.com/SantanaCharles/sentinels/internal/fingerprint"
)

// Monitor is the event source for the inside of the containers: it follows
// the logs of PostgreSQL and application containers and checks who connects
// to each database.
type Monitor struct {
	Docker   *discovery.Client
	Logs     bool     // database and application logs
	Clients  *Clients // nil: connection baseline off
	Exclude  map[string]bool
	Interval time.Duration // log polling (default 10s)
	Refresh  time.Duration // container list and connections (default 60s)
	Log      func(format string, args ...any)
}

const (
	maxTails    = 30
	maxLogBytes = 2 << 20 // per container per poll; beyond that the backlog is skipped
)

func (m *Monitor) Name() string { return "containers" }

type tail struct {
	id, label string
	tty       bool
	since     time.Time
	pg        *Postgres
	app       *App
}

func (m *Monitor) Run(ctx context.Context, out chan<- event.Event) error {
	if m.Interval <= 0 {
		m.Interval = 10 * time.Second
	}
	if m.Refresh <= 0 {
		m.Refresh = time.Minute
	}
	if m.Log == nil {
		m.Log = func(string, ...any) {}
	}
	tails := map[string]*tail{}
	var all []discovery.Container
	var dbs []Database
	var lastWarn time.Time
	warn := func(format string, args ...any) {
		if time.Since(lastWarn) > time.Hour {
			lastWarn = time.Now()
			m.Log(format, args...)
		}
	}

	refresh := func() {
		cs, err := m.Docker.Containers(ctx)
		if err != nil {
			warn("containers: %v", err)
			return
		}
		all, dbs = cs, nil
		selfID := discovery.SelfContainerID("/proc")
		seen := map[string]bool{}
		for _, c := range cs {
			label := Label(c)
			if discovery.IsSelf(c, selfID) || m.Exclude[c.Name] || m.Exclude[label] {
				continue
			}
			st := fingerprint.Detect(c)
			if st.Kind == fingerprint.KindDatabase || st.Kind == fingerprint.KindCache {
				dbs = append(dbs, Database{Label: label, Container: c})
			}
			kind := logKind(st)
			if !m.Logs || kind == "" {
				continue
			}
			seen[c.ID] = true
			if tails[c.ID] != nil || len(tails) >= maxTails {
				continue
			}
			t := &tail{id: c.ID, label: label, tty: c.TTY, since: time.Now()}
			if kind == "postgres" {
				t.pg = NewPostgres(label)
			} else {
				t.app = NewApp(label)
			}
			tails[c.ID] = t
			m.Log("containers: lendo o log de %s (%s)", label, kind)
		}
		for id := range tails {
			if !seen[id] {
				delete(tails, id)
			}
		}
	}

	emit := func(evs []event.Event) bool {
		for _, e := range evs {
			select {
			case out <- e:
			case <-ctx.Done():
				return false
			}
		}
		return true
	}

	checkClients := func() bool {
		if m.Clients == nil {
			return true
		}
		evs, err := m.Clients.Check(dbs, all, time.Now())
		if err != nil {
			warn("containers: conexões dos bancos indisponíveis: %v", err)
		}
		return emit(evs)
	}

	readLogs := func() bool {
		for _, t := range tails {
			lines, truncated, err := m.Docker.Logs(ctx, t.id, t.since, t.tty, maxLogBytes)
			if err != nil {
				if ctx.Err() != nil {
					return false
				}
				continue // container stopping; the next refresh drops it
			}
			for _, l := range lines {
				var evs []event.Event
				if t.pg != nil {
					evs = t.pg.Line(l.Text, l.Time)
				} else {
					evs = t.app.Line(l.Text, l.Time)
				}
				if !emit(evs) {
					return false
				}
				t.since = l.Time.Add(time.Nanosecond)
			}
			if t.pg != nil && !emit(t.pg.Flush()) {
				return false
			}
			if truncated {
				t.since = time.Now()
				warn("containers: log de %s grande demais para analisar tudo; parte foi pulada", t.label)
			}
		}
		return true
	}

	refresh()
	if !checkClients() {
		return nil
	}
	logTick, refreshTick := time.NewTicker(m.Interval), time.NewTicker(m.Refresh)
	defer logTick.Stop()
	defer refreshTick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-logTick.C:
			if !readLogs() {
				return nil
			}
		case <-refreshTick.C:
			refresh()
			if !checkClients() {
				return nil
			}
		}
	}
}

// logKind decides which analyzer reads a container's log. Reverse proxies
// are left to CrowdSec; caches and other databases log nothing useful by default.
func logKind(st fingerprint.Stack) string {
	switch st.Kind {
	case fingerprint.KindDatabase:
		for _, c := range st.Components {
			if c == "PostgreSQL" {
				return "postgres"
			}
		}
	case fingerprint.KindApp, fingerprint.KindAdmin, fingerprint.KindAutomation, fingerprint.KindUnknown:
		return "app"
	}
	return ""
}
