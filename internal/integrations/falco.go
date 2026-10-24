package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/SantanaCharles/sentinels/internal/event"
	"github.com/SantanaCharles/sentinels/internal/finding"
)

// Falco receives alerts from Falco's http_output:
//
//	http_output: { enabled: true, url: "http://127.0.0.1:2801/falco" }
//
// The listener must stay on loopback: anyone able to post here can inject
// events into Sentinels.
type Falco struct {
	Listen string
}

func (f *Falco) Name() string { return "falco" }

// IsLoopback reports whether addr only accepts local connections.
func IsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (f *Falco) Run(ctx context.Context, out chan<- event.Event) error {
	if !IsLoopback(f.Listen) {
		return fmt.Errorf("falco: listen %q não é loopback; use 127.0.0.1", f.Listen)
	}
	srv := &http.Server{
		Addr:              f.Listen,
		Handler:           f.Handler(ctx, out),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("falco: %w", err)
	}
	return nil
}

type falcoAlert struct {
	Output       string         `json:"output"`
	Priority     string         `json:"priority"`
	Rule         string         `json:"rule"`
	Time         time.Time      `json:"time"`
	OutputFields map[string]any `json:"output_fields"`
	Tags         []string       `json:"tags"`
	Hostname     string         `json:"hostname"`
}

func (f *Falco) Handler(ctx context.Context, out chan<- event.Event) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "use POST", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 256<<10))
		if err != nil {
			http.Error(w, "corpo inválido", http.StatusBadRequest)
			return
		}
		e, err := ParseFalco(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !send(ctx, out, e) {
			http.Error(w, "encerrando", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

// ParseFalco converts one Falco JSON alert.
func ParseFalco(body []byte) (event.Event, error) {
	var a falcoAlert
	if err := json.Unmarshal(body, &a); err != nil {
		return event.Event{}, fmt.Errorf("falco: JSON inválido: %w", err)
	}
	if a.Rule == "" {
		return event.Event{}, errors.New("falco: alerta sem regra")
	}
	t := a.Time
	if t.IsZero() {
		t = time.Now()
	}
	e := event.Event{
		Source:   "falco",
		Rule:     a.Rule,
		Severity: falcoSeverity(a.Priority),
		Time:     t,
		Target:   field(a.OutputFields, "container.name"),
		Summary:  a.Output,
		Raw:      event.TrimRaw(body),
	}
	if e.Target == "" || e.Target == "host" {
		e.Target = "host"
	}
	if ip := field(a.OutputFields, "fd.rip"); ip != "" {
		e.SourceIP = ip
	}
	event.Classify(&e, a.Tags...)
	return e, nil
}

func field(m map[string]any, k string) string {
	if v, ok := m[k]; ok && v != nil {
		return fmt.Sprint(v)
	}
	return ""
}

func falcoSeverity(p string) finding.Severity {
	switch strings.ToLower(p) {
	case "emergency", "alert", "critical":
		return finding.Critical
	case "error":
		return finding.High
	case "warning":
		return finding.Medium
	case "notice":
		return finding.Low
	default:
		return finding.Info
	}
}
