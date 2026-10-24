package intel

import (
	"sort"
	"strings"

	"github.com/SantanaCharles/sentinels/internal/finding"
)

// EPSSHigh is the score from which a CVE is treated as likely to be exploited.
const EPSSHigh = 0.5

// CVEs lists the distinct CVE IDs referenced by findings.
func CVEs(fs []finding.Finding) []string {
	set := map[string]bool{}
	for _, f := range fs {
		for _, c := range splitCVEs(f.CVE) {
			set[c] = true
		}
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Enrich marks KEV entries as critical and raises CVEs with a high EPSS score.
// Either source may be nil when it could not be loaded.
func Enrich(fs []finding.Finding, kev KEV, epss map[string]float64) {
	for i := range fs {
		f := &fs[i]
		for _, c := range splitCVEs(f.CVE) {
			if e, ok := kev[c]; ok {
				f.KEV = true
				f.Severity = finding.Critical
				ref := "CISA KEV: explorada ativamente (adicionada em " + e.DateAdded + ")"
				if strings.EqualFold(e.Ransomware, "Known") {
					ref += ", usada em campanhas de ransomware"
				}
				f.References = append(f.References, ref)
			}
			if s := epss[c]; s > f.EPSS {
				f.EPSS = s
			}
		}
		if f.EPSS >= EPSSHigh && f.Severity < finding.High {
			f.Severity = finding.High
		}
	}
}

func splitCVEs(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); strings.HasPrefix(p, "CVE-") {
			out = append(out, p)
		}
	}
	return out
}
