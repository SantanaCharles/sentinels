// Package finding defines the result type shared by every check.
package finding

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var severityNames = []string{"info", "low", "medium", "high", "critical"}

var severityLabels = []string{"Info", "Baixo", "Médio", "Alto", "Crítico"}

func (s Severity) String() string {
	if s < Info || s > Critical {
		return "unknown"
	}
	return severityNames[s]
}

// Label is the Portuguese name used in reports.
func (s Severity) Label() string {
	if s < Info || s > Critical {
		return "?"
	}
	return severityLabels[s]
}

func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

func (s *Severity) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	p, err := ParseSeverity(v)
	*s = p
	return err
}

// ParseSeverity accepts the English names and Trivy's upper-case names.
func ParseSeverity(v string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "info", "unknown", "negligible", "":
		return Info, nil
	case "low":
		return Low, nil
	case "medium", "moderate":
		return Medium, nil
	case "high":
		return High, nil
	case "critical":
		return Critical, nil
	}
	return Info, fmt.Errorf("severidade desconhecida: %q", v)
}

type Finding struct {
	ID          string   `json:"id"`
	Severity    Severity `json:"severity"`
	Target      string   `json:"target"`
	Title       string   `json:"title"`
	Detail      string   `json:"detail,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	References  []string `json:"references,omitempty"`
	CIS         string   `json:"cis,omitempty"`
	CWE         []string `json:"cwe,omitempty"`
	CVE         string   `json:"cve,omitempty"`
	KEV         bool     `json:"kev,omitempty"`
	EPSS        float64  `json:"epss,omitempty"`
	New         bool     `json:"new,omitempty"`      // first seen in this scan (needs the local store)
	Accepted    string   `json:"accepted,omitempty"` // reason, when the admin accepted the risk
}

// Key identifies a finding across scans (used by feedback commands).
func (f Finding) Key() string { return f.ID + "|" + f.Target }

// Sort orders by severity, then KEV, then EPSS, then target — most urgent first.
func Sort(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.KEV != b.KEV {
			return a.KEV
		}
		if a.EPSS != b.EPSS {
			return a.EPSS > b.EPSS
		}
		if a.Target != b.Target {
			return a.Target < b.Target
		}
		return a.ID < b.ID
	})
}

// Count returns how many open findings exist per severity; accepted risks
// are left out.
func Count(fs []Finding) map[Severity]int {
	c := make(map[Severity]int)
	for _, f := range fs {
		if f.Accepted == "" {
			c[f.Severity]++
		}
	}
	return c
}
