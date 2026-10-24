package watch

import (
	"fmt"
	"strings"
	"testing"

	"github.com/SantanaCharles/sentinels/internal/finding"
	"github.com/SantanaCharles/sentinels/internal/scan"
)

func manyCVEs(target string, n int, new bool) []finding.Finding {
	var fs []finding.Finding
	for i := 0; i < n; i++ {
		fs = append(fs, finding.Finding{ID: fmt.Sprintf("cve.CVE-2026-%04d", i), CVE: fmt.Sprintf("CVE-2026-%04d", i),
			Target: target, Severity: finding.High, Title: fmt.Sprintf("CVE-2026-%04d em libx 1.0", i), New: new})
	}
	return fs
}

func TestBaselineSendsOneSummary(t *testing.T) {
	fs := append(manyCVEs("lab-php", 300, true),
		finding.Finding{ID: "advisory.php2shell-2026-10", Target: "lab-php", Severity: finding.Critical, Title: "PHP2Shell", New: true},
		finding.Finding{ID: "exposure.database_public", Target: "db", Severity: finding.Critical, Title: "Postgres exposto", New: true})
	res := &scan.Result{Findings: fs, History: &scan.History{First: true, New: len(fs)}}
	finding.Sort(res.Findings)
	alerts := ScanAlerts(res, finding.High)
	if len(alerts) != 1 {
		t.Fatalf("primeira varredura gerou %d alertas, quer 1", len(alerts))
	}
	text := strings.Join(alerts[0].Lines, "\n")
	if alerts[0].Severity != finding.Critical || !strings.Contains(text, "PHP2Shell") || !strings.Contains(text, "Postgres exposto") {
		t.Errorf("resumo não destaca o urgente:\n%s", text)
	}
	if strings.Contains(text, "CVE-2026-0001 em libx") {
		t.Error("resumo listou CVE comum em vez dos problemas acionáveis")
	}
}

func TestLaterScanGroupsCVEs(t *testing.T) {
	fs := append(manyCVEs("lab-php", 40, true), manyCVEs("api", 2, true)...)
	fs = append(fs,
		finding.Finding{ID: "cve.CVE-2026-9999", CVE: "CVE-2026-9999", KEV: true, Target: "api", Severity: finding.Critical, Title: "CVE-2026-9999 em openssl", New: true},
		finding.Finding{ID: "container.privileged", Target: "worker", Severity: finding.Critical, Title: "Container privilegiado", New: true},
		finding.Finding{ID: "container.root_user", Target: "worker", Severity: finding.Medium, Title: "root", New: true}, // below min
		finding.Finding{ID: "web.no_csp", Target: "worker", Severity: finding.High, Title: "velho", New: false},          // not new
	)
	alerts := ScanAlerts(&scan.Result{Findings: fs, History: &scan.History{}}, finding.High)
	var titles []string
	for _, a := range alerts {
		titles = append(titles, a.Title)
	}
	want := []string{"Novo achado: CVE-2026-9999 em openssl", "Novo achado: Container privilegiado",
		"2 nova(s) CVE(s) nas imagens de api", "40 nova(s) CVE(s) nas imagens de lab-php"}
	if strings.Join(titles, " | ") != strings.Join(want, " | ") {
		t.Errorf("alertas:\n%s\nquer:\n%s", strings.Join(titles, "\n"), strings.Join(want, "\n"))
	}
}

func TestIndividualAlertsAreCapped(t *testing.T) {
	var fs []finding.Finding
	for i := 0; i < 25; i++ {
		fs = append(fs, finding.Finding{ID: fmt.Sprintf("container.x%d", i), Target: "c", Severity: finding.High, Title: "x", New: true})
	}
	alerts := ScanAlerts(&scan.Result{Findings: fs, History: &scan.History{}}, finding.High)
	if len(alerts) != maxIndividual+1 || !strings.Contains(alerts[maxIndividual].Title, "Mais 15") {
		t.Errorf("%d alertas; último: %q", len(alerts), alerts[len(alerts)-1].Title)
	}
}
