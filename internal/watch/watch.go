// Package watch runs Sentinels continuously: it consumes real-time events,
// correlates them with the latest scan and raises deduplicated alerts.
package watch

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/SantanaCharles/sentinels/internal/event"
	"github.com/SantanaCharles/sentinels/internal/finding"
	"github.com/SantanaCharles/sentinels/internal/integrations"
	"github.com/SantanaCharles/sentinels/internal/scan"
	"github.com/SantanaCharles/sentinels/internal/store"
)

// Alert is what reaches the administrator: either a real-time event or a new
// finding from a periodic scan.
type Alert struct {
	Severity finding.Severity
	Title    string
	Target   string
	Lines    []string
	Event    *event.Event
	Finding  *finding.Finding
	Count    int
	EventID  int64    // stored event, for `sentinels feedback <id>`
	Stack    []string // components of the target, from the last scan
}

// Alerter delivers alerts (log, Telegram, Slack…).
type Alerter interface {
	Alert(ctx context.Context, a Alert) error
}

type Watcher struct {
	Store        *store.Store
	Sources      []integrations.Source
	Alerter      Alerter
	MinSeverity  finding.Severity
	DedupWindow  time.Duration
	ScanInterval time.Duration
	Retention    time.Duration
	// Scan runs a full audit; nil disables periodic scans.
	Scan func(ctx context.Context) *scan.Result
	Log  func(format string, args ...any)
	// AfterScan hooks run after each scan (e.g. the Telegram bot replying
	// to "/varrer" with the new status).
	AfterScan []func(*scan.Result)

	mu          sync.RWMutex
	state       targetState
	scanning    atomic.Bool
	triggerOnce sync.Once
	triggerCh   chan struct{}
}

// targetState is what the last scan taught about each target.
type targetState struct {
	portToTarget map[int]string
	vulns        map[string][]finding.Finding // High+ findings with a CVE or advisory
	stacks       map[string][]string
}

// exploitTechniques are the ATT&CK techniques for which a known vulnerability
// on the target makes success likely.
var exploitTechniques = map[string]bool{
	"T1190": true, "T1505.003": true, "T1059": true, "T1068": true, "T1611": true, "T1133": true,
}

const multiSourceWindow = time.Hour

func (w *Watcher) Run(ctx context.Context) error {
	if w.Log == nil {
		w.Log = func(string, ...any) {}
	}
	events := make(chan event.Event, 256)
	var wg sync.WaitGroup
	for _, src := range w.Sources {
		wg.Add(1)
		go func(src integrations.Source) {
			defer wg.Done()
			w.runSource(ctx, src, events)
		}(src)
	}

	if w.Scan != nil {
		go w.scanLoop(ctx)
	}
	prune := time.NewTicker(6 * time.Hour)
	defer prune.Stop()

	w.Log("monitorando %d fonte(s); alertas a partir de %s", len(w.Sources), w.MinSeverity.Label())
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return nil
		case e := <-events:
			if err := w.Handle(ctx, e); err != nil {
				w.Log("erro ao processar evento de %s: %v", e.Source, err)
			}
		case <-prune.C:
			if w.Retention > 0 {
				if n, err := w.Store.Prune(ctx, time.Now().Add(-w.Retention)); err == nil && n > 0 {
					w.Log("retenção: %d evento(s) antigo(s) removido(s)", n)
				}
			}
		}
	}
}

// runSource restarts a source after failures, with growing backoff.
func (w *Watcher) runSource(ctx context.Context, src integrations.Source, out chan<- event.Event) {
	backoff := 5 * time.Second
	for {
		start := time.Now()
		err := src.Run(ctx, out)
		if ctx.Err() != nil {
			return
		}
		if time.Since(start) > 5*time.Minute {
			backoff = 5 * time.Second
		}
		w.Log("fonte %s parou (%v); nova tentativa em %s", src.Name(), err, backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 5*time.Minute)
	}
}

func (w *Watcher) scanLoop(ctx context.Context) {
	if w.Log == nil { // Run sets it; tests may call scanLoop directly
		w.Log = func(string, ...any) {}
	}
	for {
		w.scanning.Store(true)
		res := w.Scan(ctx)
		w.scanning.Store(false)
		if ctx.Err() != nil {
			return
		}
		w.UpdateState(res)
		for _, a := range ScanAlerts(res, w.MinSeverity) {
			if err := w.Alerter.Alert(ctx, a); err != nil {
				w.Log("erro ao enviar alerta: %v", err)
			}
		}
		for _, fn := range w.AfterScan {
			fn(res)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(w.ScanInterval):
		case <-w.trigger():
			w.Log("varredura pedida sob demanda")
		}
	}
}

// ScanRequest is the outcome of RequestScan.
type ScanRequest int

const (
	ScanStarted     ScanRequest = iota // a new scan begins now
	ScanRunning                        // one is already running; its result will be reported
	ScanUnavailable                    // periodic scans are disabled (--no-scan)
)

// RequestScan asks for a scan now instead of waiting for the interval.
func (w *Watcher) RequestScan() ScanRequest {
	if w.Scan == nil {
		return ScanUnavailable
	}
	if w.scanning.Load() {
		return ScanRunning
	}
	select {
	case w.trigger() <- struct{}{}:
	default: // already queued
	}
	return ScanStarted
}

// Scanning reports whether a scan is in progress (the first one included).
func (w *Watcher) Scanning() bool { return w.scanning.Load() }

func (w *Watcher) trigger() chan struct{} {
	w.triggerOnce.Do(func() { w.triggerCh = make(chan struct{}, 1) })
	return w.triggerCh
}

// UpdateState indexes the scan for correlation.
func (w *Watcher) UpdateState(res *scan.Result) {
	st := targetState{portToTarget: map[int]string{}, vulns: map[string][]finding.Finding{}, stacks: map[string][]string{}}
	for _, a := range res.Assets {
		st.stacks[a.Name] = a.Stack.Components
		for _, p := range append(append([]string{}, a.PublicPorts...), a.LocalPorts...) {
			hostPort, _, _ := strings.Cut(p, "→")
			if n, err := strconv.Atoi(hostPort); err == nil {
				st.portToTarget[n] = a.Name
			}
		}
	}
	for _, f := range res.Findings {
		if f.Severity < finding.High || f.CVE == "" {
			continue
		}
		// CVE findings from Trivy list several containers sharing an image.
		for _, t := range strings.Split(f.Target, ", ") {
			st.vulns[t] = append(st.vulns[t], f)
		}
	}
	w.mu.Lock()
	w.state = st
	w.mu.Unlock()
}

// Handle correlates, stores and, when new and severe enough, alerts on e.
func (w *Watcher) Handle(ctx context.Context, e event.Event) error {
	vulnerable := w.correlate(ctx, &e)

	// Admin false-positive rules silence an event, except when it hits a
	// target with a known vulnerability: that safety net cannot be muted.
	suppressed, err := w.Store.Suppressed(ctx, e)
	if err != nil {
		return err
	}
	if suppressed && vulnerable {
		suppressed = false
		e.Context = append(e.Context, "Uma regra de falso positivo casou, mas foi ignorada porque o alvo tem vulnerabilidade conhecida")
	}

	id, count, isNew, err := w.Store.Record(ctx, e, w.DedupWindow, suppressed)
	if err != nil {
		return err
	}
	if !isNew || suppressed || e.Severity < w.MinSeverity {
		return nil
	}
	title := e.Rule
	if name := e.TechniqueName(); name != "" {
		title = fmt.Sprintf("%s — %s (%s)", e.TechniqueName(), e.Rule, e.Technique)
	}
	lines := []string{e.Summary}
	lines = append(lines, e.Context...)
	return w.Alerter.Alert(ctx, Alert{
		Severity: e.Severity, Title: title, Target: e.Target, Lines: lines, Event: &e, Count: count, EventID: id,
		Stack: w.stackOf(e.Target),
	})
}

func (w *Watcher) stackOf(target string) []string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.state.stacks[target]
}

// correlate enriches e with what the agent knows and reports whether the
// target has a known vulnerability matching the technique.
func (w *Watcher) correlate(ctx context.Context, e *event.Event) (vulnerable bool) {
	w.mu.RLock()
	st := w.state
	w.mu.RUnlock()

	if e.Target == "" && e.DestPort > 0 {
		if t, ok := st.portToTarget[e.DestPort]; ok {
			e.Target = t
		}
	}

	if exploitTechniques[e.Technique] && e.Target != "" {
		if vs := st.vulns[e.Target]; len(vs) > 0 {
			vulnerable = true
			e.Severity = finding.Critical
			for i, v := range vs {
				if i == 3 {
					e.Context = append(e.Context, fmt.Sprintf("… e mais %d vulnerabilidade(s) conhecida(s)", len(vs)-3))
					break
				}
				e.Context = append(e.Context, fmt.Sprintf("Alvo tem vulnerabilidade conhecida: %s (%s)", v.Title, v.CVE))
			}
		}
	}

	if e.SourceIP != "" && w.Store != nil {
		srcs, err := w.Store.SourcesForIP(ctx, e.SourceIP, e.Time.Add(-multiSourceWindow))
		if err == nil {
			var others []string
			for _, s := range srcs {
				if s != e.Source {
					others = append(others, s)
				}
			}
			if len(others) > 0 {
				if e.Severity < finding.Critical {
					e.Severity++
				}
				e.Context = append(e.Context, fmt.Sprintf("IP %s também detectado por %s na última hora", e.SourceIP, strings.Join(others, ", ")))
			}
		}
		if hostile, err := w.Store.ConfirmedIP(ctx, e.SourceIP); err == nil && hostile {
			if e.Severity < finding.Critical {
				e.Severity++
			}
			e.Context = append(e.Context, fmt.Sprintf("IP %s já foi confirmado como atacante pelo administrador", e.SourceIP))
		}
	}
	return vulnerable
}
