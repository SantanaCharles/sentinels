package watch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// Multi sends each alert to every alerter, returning the first error.
type Multi []Alerter

func (m Multi) Alert(ctx context.Context, a Alert) error {
	var first error
	for _, al := range m {
		if err := al.Alert(ctx, a); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// LogAlerter writes alerts to a stream (stdout → journald under systemd).
// It is the default until notifiers are configured.
type LogAlerter struct {
	W    io.Writer
	JSON bool
	mu   sync.Mutex
}

func (l *LogAlerter) Alert(_ context.Context, a Alert) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.JSON {
		return json.NewEncoder(l.W).Encode(map[string]any{
			"time":     time.Now().Format(time.RFC3339),
			"severity": a.Severity.String(),
			"title":    a.Title,
			"target":   a.Target,
			"details":  a.Lines,
			"event_id": a.EventID,
			"event":    a.Event,
			"finding":  a.Finding,
		})
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] %s", strings.ToUpper(a.Severity.Label()), oneLine(a.Title))
	if a.Target != "" {
		fmt.Fprintf(&b, " — alvo: %s", oneLine(a.Target))
	}
	b.WriteByte('\n')
	for _, line := range a.Lines {
		if line != "" {
			fmt.Fprintf(&b, "    %s\n", oneLine(line))
		}
	}
	if a.EventID > 0 {
		fmt.Fprintf(&b, "    evento #%d — falso positivo? sentinels feedback %d fp\n", a.EventID, a.EventID)
	}
	_, err := io.WriteString(l.W, b.String())
	return err
}

// oneLine keeps attacker-controlled text from forging extra log lines.
func oneLine(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r < 0x20 && r != '\t' {
			return ' '
		}
		return r
	}, s)
	if r := []rune(s); len(r) > 500 {
		s = string(r[:500]) + "…"
	}
	return s
}
