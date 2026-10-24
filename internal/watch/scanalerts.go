package watch

import (
	"fmt"
	"sort"
	"strings"

	"github.com/SantanaCharles/sentinels/internal/finding"
	"github.com/SantanaCharles/sentinels/internal/scan"
)

// maxIndividual caps per-finding alerts from one scan; the rest are summarized.
const maxIndividual = 10

// ScanAlerts decides what a periodic scan sends to the administrators,
// keeping the volume readable:
//   - the first scan (baseline) sends one summary, not one alert per finding;
//   - later scans alert one by one only for new configuration problems and
//     for CVEs that are exploited in the wild (KEV) or emergency advisories;
//   - other new CVEs are grouped into one alert per target.
func ScanAlerts(res *scan.Result, min finding.Severity) []Alert {
	if res == nil || res.History == nil {
		return nil
	}
	if res.History.First {
		return baselineAlert(res, min)
	}

	var individual []finding.Finding
	cvesByTarget := map[string][]finding.Finding{}
	for _, f := range res.Findings {
		if !f.New || f.Accepted != "" || f.Severity < min {
			continue
		}
		if strings.HasPrefix(f.ID, "cve.") && !f.KEV {
			cvesByTarget[f.Target] = append(cvesByTarget[f.Target], f)
			continue
		}
		individual = append(individual, f)
	}

	var out []Alert
	for i := range individual {
		f := individual[i]
		if i == maxIndividual {
			out = append(out, Alert{
				Severity: individual[i].Severity,
				Title:    fmt.Sprintf("Mais %d achado(s) novo(s) nesta varredura", len(individual)-maxIndividual),
				Lines:    []string{"Veja todos com: sentinels findings"},
			})
			break
		}
		out = append(out, Alert{
			Severity: f.Severity, Title: "Novo achado: " + f.Title, Target: f.Target, Finding: &f,
			Lines: []string{f.Detail, "Como corrigir: " + f.Remediation},
		})
	}

	targets := make([]string, 0, len(cvesByTarget))
	for t := range cvesByTarget {
		targets = append(targets, t)
	}
	sort.Strings(targets)
	for _, t := range targets {
		out = append(out, cveGroupAlert(t, cvesByTarget[t]))
	}
	return out
}

func cveGroupAlert(target string, fs []finding.Finding) Alert {
	finding.Sort(fs)
	c := finding.Count(fs)
	lines := []string{fmt.Sprintf("%d crítica(s), %d alta(s). As mais urgentes:", c[finding.Critical], c[finding.High])}
	for i, f := range fs {
		if i == 3 {
			break
		}
		l := f.Title
		if f.EPSS > 0 {
			l += fmt.Sprintf(" (EPSS %.0f%%)", f.EPSS*100)
		}
		lines = append(lines, l)
	}
	lines = append(lines, "Correção usual: atualizar a imagem base e reconstruir. Lista completa: sentinels findings")
	return Alert{
		Severity: fs[0].Severity,
		Title:    fmt.Sprintf("%d nova(s) CVE(s) nas imagens de %s", len(fs), target),
		Target:   target,
		Lines:    lines,
	}
}

func baselineAlert(res *scan.Result, min finding.Severity) []Alert {
	var open []finding.Finding
	for _, f := range res.Findings {
		if f.Accepted == "" && f.Severity >= min {
			open = append(open, f)
		}
	}
	if len(open) == 0 {
		return []Alert{{Severity: finding.Info, Title: "Primeira varredura concluída: nenhum achado grave",
			Lines: []string{fmt.Sprintf("%d ativo(s) inventariado(s). O monitoramento está ativo.", len(res.Assets))}}}
	}
	finding.Sort(open)
	c := finding.Count(open)
	cves := 0
	for _, f := range open {
		if strings.HasPrefix(f.ID, "cve.") {
			cves++
		}
	}
	lines := []string{fmt.Sprintf("%d ativo(s); %d crítico(s) e %d alto(s), dos quais %d são CVEs em imagens.",
		len(res.Assets), c[finding.Critical], c[finding.High], cves)}
	shown := 0
	for _, f := range open {
		// Lead with what needs action first: configuration problems, KEV and advisories.
		if strings.HasPrefix(f.ID, "cve.") && !f.KEV {
			continue
		}
		if shown == 5 {
			break
		}
		lines = append(lines, fmt.Sprintf("%s — %s (%s)", f.Severity.Label(), f.Title, f.Target))
		shown++
	}
	lines = append(lines, "A partir de agora você recebe só o que for novo. Relatório completo e lista: sentinels findings")
	return []Alert{{Severity: open[0].Severity, Title: "Primeira varredura concluída", Lines: lines}}
}
