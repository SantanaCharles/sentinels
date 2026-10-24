package integrations

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/SantanaCharles/sentinels/internal/event"
	"github.com/SantanaCharles/sentinels/internal/finding"
)

// Suricata follows eve.json and reports "alert" records. It starts at the end
// of the file and reopens it after logrotate.
type Suricata struct {
	Path     string
	Interval time.Duration
	// FromStart reads existing content (tests and one-shot imports).
	FromStart bool
}

func (s *Suricata) Name() string { return "suricata" }

const maxEveLine = 1 << 20

func (s *Suricata) Run(ctx context.Context, out chan<- event.Event) error {
	if s.Interval <= 0 {
		s.Interval = time.Second
	}
	f, err := os.Open(s.Path)
	if err != nil {
		return fmt.Errorf("suricata: %w", err)
	}
	defer func() { f.Close() }()
	if !s.FromStart {
		if _, err := f.Seek(0, io.SeekEnd); err != nil {
			return err
		}
	}
	r := bufio.NewReaderSize(f, 64<<10)
	var partial []byte
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			partial = append(partial, line...)
			if len(partial) > maxEveLine {
				partial = partial[:0] // oversized record: drop
				continue
			}
			if partial[len(partial)-1] == '\n' {
				if e, ok := ParseEveAlert(partial); ok {
					if !send(ctx, out, e) {
						return nil
					}
				}
				partial = partial[:0]
			}
		}
		if err == nil {
			continue
		}
		if !errors.Is(err, io.EOF) {
			return fmt.Errorf("suricata: %w", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(s.Interval):
		}
		if rotated(f, s.Path) {
			nf, err := os.Open(s.Path)
			if err != nil {
				continue // new file not created yet
			}
			f.Close()
			f = nf
			r.Reset(f)
			partial = partial[:0]
		}
	}
}

// rotated reports whether path now names a different or truncated file.
func rotated(f *os.File, path string) bool {
	cur, err := f.Stat()
	if err != nil {
		return true
	}
	next, err := os.Stat(path)
	if err != nil {
		return false
	}
	if !os.SameFile(cur, next) {
		return true
	}
	pos, err := f.Seek(0, io.SeekCurrent)
	return err == nil && next.Size() < pos
}

type eveRecord struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
	DestIP    string `json:"dest_ip"`
	DestPort  int    `json:"dest_port"`
	Proto     string `json:"proto"`
	Alert     struct {
		Action      string              `json:"action"`
		SignatureID int64               `json:"signature_id"`
		Signature   string              `json:"signature"`
		Category    string              `json:"category"`
		Severity    int                 `json:"severity"`
		Metadata    map[string][]string `json:"metadata"`
	} `json:"alert"`
}

// ParseEveAlert converts one eve.json line; non-alert records return false.
func ParseEveAlert(line []byte) (event.Event, bool) {
	var r eveRecord
	if err := json.Unmarshal(line, &r); err != nil || r.EventType != "alert" {
		return event.Event{}, false
	}
	t, err := time.Parse("2006-01-02T15:04:05.999999-0700", r.Timestamp)
	if err != nil {
		t = time.Now()
	}
	e := event.Event{
		Source:   "suricata",
		Rule:     fmt.Sprintf("%d %s", r.Alert.SignatureID, r.Alert.Signature),
		Severity: suricataSeverity(r.Alert.Severity),
		Time:     t,
		SourceIP: r.SrcIP,
		DestPort: r.DestPort,
		Summary:  fmt.Sprintf("%s [%s] %s → %s:%d/%s", r.Alert.Signature, r.Alert.Category, r.SrcIP, r.DestIP, r.DestPort, r.Proto),
		Raw:      event.TrimRaw(line),
	}
	if r.Alert.Action == "blocked" {
		e.Summary += " (bloqueado pelo Suricata)"
	}
	// ET Open rules carry ATT&CK IDs in metadata (mitre_technique_id).
	var hints []string
	hints = append(hints, r.Alert.Metadata["mitre_technique_id"]...)
	hints = append(hints, r.Alert.Category, strings.Join(r.Alert.Metadata["signature_severity"], " "))
	event.Classify(&e, hints...)
	return e, true
}

// Suricata priority: 1 is the most severe.
func suricataSeverity(p int) finding.Severity {
	switch p {
	case 1:
		return finding.High
	case 2:
		return finding.Medium
	default:
		return finding.Low
	}
}
