package intel

import (
	"context"
	"testing"

	"github.com/SantanaCharles/sentinels/internal/finding"
)

func php2shell(t *testing.T) Advisory {
	t.Helper()
	advs, err := LoadAdvisories(context.Background(), "", true)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range advs {
		if a.ID == "php2shell-2026-10" {
			return a
		}
	}
	t.Fatal("advisory php2shell ausente")
	return Advisory{}
}

func TestPHP2ShellVersions(t *testing.T) {
	a := php2shell(t)
	cases := []struct {
		version, suffix string
		want            Status
	}{
		{"8.3.35", "", Vulnerable},
		{"8.3.36", "", NotAffected},
		{"8.3.40", "", NotAffected},
		{"8.4.26", "", Vulnerable},
		{"8.4.27", "", NotAffected},
		{"8.5.11", "", Vulnerable},
		{"8.5.12", "", NotAffected},
		{"8.2.34", "", Vulnerable},
		{"8.2.35", "", NotAffected},
		{"8.1.31", "", VulnerableEOL},
		{"7.4.33", "", VulnerableEOL},
		{"5.3.29", "", NotAffected}, // older than affected_min
		{"8.6.0", "", NotAffected},  // branch newer than every fix
		{"9.0.0", "", NotAffected},
		{"8.3.6", "-1ubuntu2.5", NeedsVendorCheck},
		{"8.1.2", "-1ubuntu2.20", NeedsVendorCheck},
		{"8.3.36", "-1ubuntu1", NotAffected},
		{"lixo", "", NotAffected},
	}
	for _, c := range cases {
		if got := a.Check(c.version, c.suffix); got != c.want {
			t.Errorf("Check(%q, %q) = %v, quer %v", c.version, c.suffix, got, c.want)
		}
	}
}

func TestEnrich(t *testing.T) {
	fs := []finding.Finding{
		{ID: "cve.CVE-1", CVE: "CVE-2024-0001", Severity: finding.High},
		{ID: "cve.CVE-2", CVE: "CVE-2024-0002", Severity: finding.Medium},
		{ID: "advisory.x", CVE: "CVE-2024-0003, CVE-2024-0004", Severity: finding.High},
		{ID: "web.no_csp", Severity: finding.Low},
	}
	kev := KEV{"CVE-2024-0001": {CVE: "CVE-2024-0001", DateAdded: "2024-05-01", Ransomware: "Known"}}
	epss := map[string]float64{"CVE-2024-0002": 0.7, "CVE-2024-0004": 0.2}
	Enrich(fs, kev, epss)

	if !fs[0].KEV || fs[0].Severity != finding.Critical {
		t.Errorf("KEV não elevou para crítico: %+v", fs[0])
	}
	if fs[1].Severity != finding.High || fs[1].EPSS != 0.7 {
		t.Errorf("EPSS alto não elevou para alto: %+v", fs[1])
	}
	if fs[2].EPSS != 0.2 {
		t.Errorf("EPSS de CVE múltipla não aplicado: %+v", fs[2])
	}
	if fs[3].Severity != finding.Low {
		t.Errorf("achado sem CVE alterado: %+v", fs[3])
	}
	if got := CVEs(fs); len(got) != 4 {
		t.Errorf("CVEs() = %v", got)
	}
}
