// Package intel provides public vulnerability intelligence: emergency
// advisories maintained by the project, CISA KEV and FIRST EPSS.
package intel

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// AdvisoryFeedURL is refreshed so installed agents learn about new emergencies
// (vulnerabilities exploited before they reach KEV) without a new release.
// The file is signed: AdvisoryFeedURL + ".sig" holds its Ed25519 signature.
const AdvisoryFeedURL = "https://raw.githubusercontent.com/SantanaCharles/sentinels/main/internal/intel/advisories.json"

var advisoryFeedURL = AdvisoryFeedURL // overridden in tests

// SupportedProducts are the runtimes whose version the scanner detects, so
// advisories for them take effect. Add detection before adding a product.
var SupportedProducts = []string{"php"}

//go:embed advisories.json
var embeddedAdvisories []byte

type Advisory struct {
	ID            string            `json:"id"`
	Title         string            `json:"title"`
	CVEs          []string          `json:"cves"`
	Product       string            `json:"product"`
	Published     string            `json:"published"`
	Severity      string            `json:"severity"`
	Fixed         map[string]string `json:"fixed"` // branch "8.3" -> first fixed "8.3.36"
	AffectedMin   string            `json:"affected_min"`
	EOLVulnerable bool              `json:"eol_vulnerable"` // branches older than any in Fixed are affected
	Summary       string            `json:"summary"`
	Remediation   string            `json:"remediation"`
	References    []string          `json:"references"`
}

type Status int

const (
	NotAffected Status = iota
	Vulnerable
	VulnerableEOL // branch has no official fix
	NeedsVendorCheck
)

// Check classifies version against the advisory. suffix is a distribution
// tag such as "-1ubuntu2.3": distributions backport fixes without changing
// the upstream number, so a suffixed old version needs a vendor check.
func (a Advisory) Check(version, suffix string) Status {
	v, ok := parseVersion(version)
	if !ok {
		return NotAffected
	}
	if min, ok := parseVersion(a.AffectedMin); ok && less(v, min) {
		return NotAffected
	}
	branch := fmt.Sprintf("%d.%d", v[0], v[1])
	if fixed, ok := a.Fixed[branch]; ok {
		f, ok := parseVersion(fixed)
		if !ok || !less(v, f) {
			return NotAffected
		}
		if suffix != "" {
			return NeedsVendorCheck
		}
		return Vulnerable
	}
	// Branch not listed: newer than every fixed branch means not affected;
	// older than every one means end-of-life without an official fix.
	newer, older := true, true
	for b := range a.Fixed {
		bv, ok := parseVersion(b + ".0")
		if !ok {
			continue
		}
		if less(v, bv) {
			newer = false
		} else {
			older = false
		}
	}
	if newer {
		return NotAffected
	}
	if !older {
		return NeedsVendorCheck // a gap between listed branches: data is incomplete
	}
	if !a.EOLVulnerable {
		return NotAffected
	}
	if suffix != "" {
		return NeedsVendorCheck
	}
	return VulnerableEOL
}

// LoadAdvisories returns the embedded list plus any new entries from the
// remote feed. Remote entries never replace embedded ones with the same ID,
// so a tampered feed cannot silence an advisory shipped in the binary.
func LoadAdvisories(ctx context.Context, cacheDir string, offline bool) ([]Advisory, error) {
	var base []Advisory
	if err := json.Unmarshal(embeddedAdvisories, &base); err != nil {
		return nil, fmt.Errorf("advisories embutidos inválidos: %w", err)
	}
	if offline {
		return base, nil
	}
	raw, err := fetchSignedFeed(ctx, advisoryFeedURL, cacheDir, "advisories.json", 6*time.Hour)
	if err != nil {
		return base, err
	}
	var remote []Advisory
	if err := json.Unmarshal(raw, &remote); err != nil {
		return base, fmt.Errorf("feed de advisories inválido: %w", err)
	}
	seen := map[string]bool{}
	for _, a := range base {
		seen[a.ID] = true
	}
	for _, a := range remote {
		if a.ID != "" && !seen[a.ID] {
			base = append(base, a)
			seen[a.ID] = true
		}
	}
	return base, nil
}

func parseVersion(s string) ([3]int, bool) {
	var v [3]int
	parts := strings.SplitN(strings.TrimSpace(s), ".", 3)
	if len(parts) < 2 {
		return v, false
	}
	for i, p := range parts {
		// Stop at the first non-digit: "36-1ubuntu" -> 36, "0RC1" -> 0.
		end := 0
		for end < len(p) && p[end] >= '0' && p[end] <= '9' {
			end++
		}
		n, err := strconv.Atoi(p[:end])
		if err != nil {
			return v, false
		}
		v[i] = n
	}
	return v, true
}

func less(a, b [3]int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}
