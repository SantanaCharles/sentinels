// Package notify delivers alerts to the administrators' channels.
//
// Alert text includes attacker-controlled data (rule payloads, URLs, user
// agents). Every channel sends it as plain text with mentions, markup and
// link previews disabled, and control characters removed.
package notify

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/SantanaCharles/sentinels/internal/finding"
	"github.com/SantanaCharles/sentinels/internal/watch"
)

// Message is the channel-independent form of an alert.
type Message struct {
	Severity finding.Severity `json:"severity"`
	Title    string           `json:"title"`
	Target   string           `json:"target,omitempty"`
	Lines    []string         `json:"lines,omitempty"`
	Host     string           `json:"host"`
	Time     time.Time        `json:"time"`
	EventID  int64            `json:"event_id,omitempty"`
	Finding  string           `json:"finding_key,omitempty"`
	Count    int              `json:"count,omitempty"`
}

type Notifier interface {
	Name() string
	Send(ctx context.Context, m Message) error
}

var httpClient = &http.Client{Timeout: 10 * time.Second}

// FromAlert converts a watcher alert, cleaning every text field.
func FromAlert(a watch.Alert, host string) Message {
	m := Message{
		Severity: a.Severity,
		Title:    Clean(a.Title, 300),
		Target:   Clean(a.Target, 200),
		Host:     Clean(host, 100),
		Time:     time.Now(),
		EventID:  a.EventID,
		Count:    a.Count,
	}
	if a.Finding != nil {
		m.Finding = a.Finding.Key()
	}
	for _, l := range a.Lines {
		if l = Clean(l, 600); l != "" {
			m.Lines = append(m.Lines, l)
		}
	}
	return m
}

var icons = map[finding.Severity]string{
	finding.Critical: "🔴", finding.High: "🟠", finding.Medium: "🟡", finding.Low: "🔵", finding.Info: "⚪",
}

// Text renders m as plain text, shared by Telegram, Discord, Slack and e-mail.
func Text(m Message) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s — %s\n", icons[m.Severity], strings.ToUpper(m.Severity.Label()), m.Title)
	if m.Target != "" {
		fmt.Fprintf(&b, "Alvo: %s\n", m.Target)
	}
	for _, l := range m.Lines {
		fmt.Fprintf(&b, "• %s\n", l)
	}
	fmt.Fprintf(&b, "\nServidor: %s · %s\n", m.Host, m.Time.Format("02/01/2006 15:04"))
	switch {
	case m.EventID > 0:
		fmt.Fprintf(&b, "Evento #%d — falso positivo? sentinels feedback %d fp\n", m.EventID, m.EventID)
	case m.Finding != "":
		fmt.Fprintf(&b, "Risco aceito? sentinels accept %q --reason \"...\"\n", m.Finding)
	}
	return b.String()
}

// Subject is a one-line summary for e-mail.
func Subject(m Message) string {
	return Clean(fmt.Sprintf("[Sentinels %s] %s — %s", m.Severity.Label(), m.Host, m.Title), 180)
}

// Clean removes control characters (so no line or header can be forged) and
// bounds the length, keeping valid UTF-8.
func Clean(s string, max int) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			return ' '
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == ' ' || r == ' ':
			return -1
		case r >= '‪' && r <= '‮' || r >= '⁦' && r <= '⁩':
			return -1 // bidi overrides could disguise text
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	return Truncate(s, max)
}

// Truncate cuts s to at most max bytes on a rune boundary.
func Truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max - len("…")
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

var (
	mdBold = regexp.MustCompile(`\*\*([^*
]+)\*\*`)
	mdHeading = regexp.MustCompile(`(?m)^#{1,6}[ 	]+`)
)

// PlainText drops the Markdown the AI writes (bold, headings) for channels
// that show text as is, like Telegram without parse_mode.
func PlainText(s string) string {
	return mdHeading.ReplaceAllString(mdBold.ReplaceAllString(s, "$1"), "")
}
