// Package event defines real-time security signals coming from external
// detection engines, and their classification with MITRE ATT&CK.
package event

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/SantanaCharles/sentinels/internal/finding"
)

// Event is one detection reported by CrowdSec, Suricata or Falco.
// Summary and Raw may contain attacker-controlled text: they are data, never
// instructions, wherever they end up (report, alert, AI prompt).
type Event struct {
	Source    string           `json:"source"` // crowdsec | suricata | falco
	Rule      string           `json:"rule"`   // scenario, signature or rule name
	Severity  finding.Severity `json:"severity"`
	Time      time.Time        `json:"time"`
	SourceIP  string           `json:"source_ip,omitempty"`
	DestPort  int              `json:"dest_port,omitempty"`
	Target    string           `json:"target,omitempty"` // container or host
	Summary   string           `json:"summary"`
	Technique string           `json:"technique,omitempty"` // ATT&CK ID, e.g. T1190
	Tactic    string           `json:"tactic,omitempty"`
	Context   []string         `json:"context,omitempty"` // added by correlation
	Raw       json.RawMessage  `json:"raw,omitempty"`     // kept locally only
}

// Key identifies repetitions of the same detection for deduplication.
func (e Event) Key() string {
	h := sha256.Sum256([]byte(e.Source + "\x00" + e.Rule + "\x00" + e.SourceIP + "\x00" + e.Target))
	return hex.EncodeToString(h[:12])
}

// TechniqueName returns the ATT&CK name for the event's technique.
func (e Event) TechniqueName() string {
	if t, ok := Techniques[e.Technique]; ok {
		return t.Name
	}
	return ""
}

const maxRaw = 16 << 10

// TrimRaw bounds the stored copy of the original record.
func TrimRaw(b []byte) json.RawMessage {
	if len(b) > maxRaw || !json.Valid(b) {
		return nil
	}
	return json.RawMessage(append([]byte(nil), b...))
}
