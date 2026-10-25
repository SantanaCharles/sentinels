package watch

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/SantanaCharles/sentinels/internal/finding"
)

// A security agent that dies silently is dangerous: you believe you are
// protected. Two signals cover it:
//   - heartbeatLoop sends a short "still alive" summary to every channel;
//   - pingLoop hits an external dead-man's-switch URL every 5 minutes, which
//     alerts you on its own if the pings stop (host down, agent crashed).

const pingEvery = 5 * time.Minute

func (w *Watcher) heartbeatLoop(ctx context.Context) {
	start := time.Now()
	t := time.NewTicker(w.Heartbeat)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := w.Alerter.Alert(ctx, w.heartbeatAlert(ctx, start)); err != nil {
				w.Log("sinal de vida: %v", err)
			}
		}
	}
}

func (w *Watcher) heartbeatAlert(ctx context.Context, start time.Time) Alert {
	lines := []string{fmt.Sprintf("Rodando há %s, monitorando %d fonte(s) em tempo real.", since(start), len(w.Sources))}
	if evs, err := w.Store.Events(ctx, time.Now().Add(-w.Heartbeat), finding.Low, 1000); err == nil {
		crit := 0
		for _, e := range evs {
			if e.Event.Severity == finding.Critical {
				crit++
			}
		}
		lines = append(lines, fmt.Sprintf("Desde o último aviso: %d evento(s), %d crítico(s).", len(evs), crit))
	}
	if m, err := w.Store.Metrics(ctx, time.Now()); err == nil {
		l := fmt.Sprintf("Abertos: %d crítico(s), %d alto(s).", m.OpenCritical, m.OpenHigh)
		if m.CriticalOver7d > 0 {
			l += fmt.Sprintf(" ⚠️ %d crítico(s) há mais de 7 dias.", m.CriticalOver7d)
		}
		lines = append(lines, l)
	}
	if len(w.Sources) == 0 {
		lines = append(lines, "Detecção em tempo real desligada: instale o CrowdSec (sentinels setup install).")
	}
	lines = append(lines, "Se este aviso parar de chegar, o agente ou o servidor caiu.")
	return Alert{Severity: finding.Info, Title: "🟢 Sentinels ativo", Lines: lines, Always: true}
}

func (w *Watcher) pingLoop(ctx context.Context) {
	client := &http.Client{Timeout: 10 * time.Second}
	var lastErrLog time.Time
	ping := func() {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, w.HeartbeatURL, nil)
		if err != nil {
			return
		}
		req.Header.Set("User-Agent", "Sentinels")
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 300 {
				return
			}
			err = fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		if time.Since(lastErrLog) > time.Hour { // one log line per hour at most
			lastErrLog = time.Now()
			w.Log("ping de monitoramento externo falhou: %s", strings.ReplaceAll(err.Error(), w.HeartbeatURL, "<url>"))
		}
	}
	ping()
	t := time.NewTicker(pingEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			ping()
		}
	}
}

func since(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%d dias", int(d.Hours()/24))
}
