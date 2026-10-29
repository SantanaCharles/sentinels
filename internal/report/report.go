// Package report renders scan results as Markdown (for people) and JSON
// (for automation and the AI layer).
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/SantanaCharles/sentinels/internal/finding"
	"github.com/SantanaCharles/sentinels/internal/scan"
)

// Write saves report-<timestamp>.md and .json in dir and returns their paths.
func Write(dir string, r *scan.Result) (mdPath, jsonPath string, err error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", "", err
	}
	stamp := r.Started.Format("20060102-150405")
	mdPath = filepath.Join(dir, "report-"+stamp+".md")
	jsonPath = filepath.Join(dir, "report-"+stamp+".json")

	var md strings.Builder
	Markdown(&md, r)
	if err := os.WriteFile(mdPath, []byte(md.String()), 0o640); err != nil {
		return "", "", err
	}
	js, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", "", err
	}
	return mdPath, jsonPath, os.WriteFile(jsonPath, js, 0o640)
}

var order = []finding.Severity{finding.Critical, finding.High, finding.Medium, finding.Low, finding.Info}

func Markdown(w io.Writer, r *scan.Result) {
	p := func(format string, args ...any) { fmt.Fprintf(w, format, args...) }
	count := finding.Count(r.Findings)

	p("# Relatório de segurança — %s\n\n", r.Host)
	p("Gerado em %s pelo Sentinels %s em %s.\n\n", r.Started.Format("02/01/2006 15:04"), r.Version, r.Duration)

	if len(r.Warnings) > 0 {
		p("> **Avisos da varredura**\n")
		for _, w := range r.Warnings {
			p("> - %s\n", w)
		}
		p("\n")
	}

	p("## Resumo\n\n| Severidade | Achados |\n|---|---|\n")
	for _, s := range order {
		p("| %s | %d |\n", s.Label(), count[s])
	}
	p("\nFontes: %d alerta(s) emergencial(is), CISA KEV %s, EPSS %s, Trivy %s (CVEs do SO do host %s).\n\n",
		r.Intel.Advisories, yesNo(r.Intel.KEV), yesNo(r.Intel.EPSS), yesNo(r.Intel.Trivy), yesNo(r.Intel.HostOS))
	if n := r.Intel.KernelCVEsSkipped; n > 0 {
		p("%d CVE(s) de pacotes do kernel dentro das imagens foram desconsideradas: containers usam o kernel do host. Mantenha o kernel do servidor atualizado (`unattended-upgrades`).\n\n", n)
	}

	if r.AISummary != "" {
		p("## Resumo executivo (IA)\n\n> Gerado automaticamente a partir dos achados abaixo; confira antes de agir.\n\n%s\n\n", r.AISummary)
	}

	if h := r.History; h != nil {
		p("## Desde a última varredura\n\n- **%d** achado(s) novo(s)\n- **%d** resolvido(s)\n", h.New, len(h.Resolved))
		for _, t := range h.Resolved {
			p("  - ✓ %s\n", cell(t))
		}
		p("\n")
	}

	var urgent []finding.Finding
	for _, f := range r.Findings {
		if f.Severity == finding.Critical && f.Accepted == "" {
			urgent = append(urgent, f)
		}
	}
	if len(urgent) > 0 {
		p("## Ação imediata\n\n")
		for _, f := range urgent {
			tag := ""
			if f.New {
				tag += " **[novo]**"
			}
			if f.KEV {
				tag += " **[explorada ativamente — CISA KEV]**"
			}
			p("1. **%s** — `%s`%s\n", cell(f.Title), f.Target, tag)
		}
		p("\n")
	}

	if len(r.Assets) > 0 {
		p("## Inventário\n\n| Container | Imagem | Tipo | Stack | Portas públicas |\n|---|---|---|---|---|\n")
		for _, a := range r.Assets {
			p("| %s | `%s` | %s | %s | %s |\n", cell(a.Name), a.Image, a.Stack.Kind,
				cell(strings.Join(a.Stack.Components, ", ")), cell(strings.Join(a.PublicPorts, ", ")))
		}
		p("\n")
	}

	var cves, others, accepted []finding.Finding
	for _, f := range r.Findings {
		if f.Accepted != "" {
			accepted = append(accepted, f)
			continue
		}
		if strings.HasPrefix(f.ID, "cve.") {
			cves = append(cves, f)
		} else {
			others = append(others, f)
		}
	}

	p("## Achados\n\n")
	if len(others) == 0 {
		p("Nenhum problema de configuração encontrado.\n\n")
	}
	for _, f := range others {
		if f.Severity < finding.Medium {
			continue
		}
		novo := ""
		if f.New {
			novo = " (novo)"
		}
		p("### [%s] %s%s\n\n", f.Severity.Label(), f.Title, novo)
		p("- **Alvo:** `%s`\n", f.Target)
		if f.CVE != "" {
			p("- **CVE:** %s\n", f.CVE)
		}
		if refs := standards(f); refs != "" {
			p("- **Referências:** %s\n", refs)
		}
		if f.Detail != "" {
			p("\n%s\n", f.Detail)
		}
		if f.Remediation != "" {
			p("\n**Como corrigir:** %s\n", f.Remediation)
		}
		for _, ref := range f.References {
			if strings.HasPrefix(ref, "http") {
				p("\n- %s", ref)
			}
		}
		p("\n\n")
	}

	var low []finding.Finding
	for _, f := range others {
		if f.Severity < finding.Medium {
			low = append(low, f)
		}
	}
	if len(low) > 0 {
		p("### Baixa severidade\n\n| Severidade | Alvo | Achado | Como corrigir |\n|---|---|---|---|\n")
		for _, f := range low {
			p("| %s | `%s` | %s | %s |\n", f.Severity.Label(), f.Target, cell(f.Title), cell(f.Remediation))
		}
		p("\n")
	}

	if len(accepted) > 0 {
		p("## Riscos aceitos\n\nNão entram na contagem nem nos alertas. Revise periodicamente.\n\n")
		p("| Severidade | Alvo | Achado | Motivo |\n|---|---|---|---|\n")
		for _, f := range accepted {
			p("| %s | `%s` | %s | %s |\n", f.Severity.Label(), f.Target, cell(f.Title), cell(f.Accepted))
		}
		p("\n")
	}

	if m := r.Metrics; m != nil {
		metricsSection(p, m)
	}

	if len(cves) > 0 {
		p("## Vulnerabilidades nas imagens (CVEs)\n\n")
		p("Ordenadas por urgência: explorada ativamente (KEV) e probabilidade de exploração (EPSS).\n\n")
		p("| Severidade | CVE | KEV | EPSS | Pacote | Correção | Containers |\n|---|---|---|---|---|---|---|\n")
		for _, f := range cves {
			kev := ""
			if f.KEV {
				kev = "**sim**"
			}
			epss := ""
			if f.EPSS > 0 {
				epss = fmt.Sprintf("%.1f%%", f.EPSS*100)
			}
			pkg := strings.TrimPrefix(f.Title, f.CVE+" em ")
			p("| %s | %s | %s | %s | %s | %s | %s |\n", f.Severity.Label(), f.CVE, kev, epss,
				cell(pkg), cell(f.Remediation), cell(f.Target))
		}
		p("\n")
	}
}

func standards(f finding.Finding) string {
	var parts []string
	if f.CIS != "" {
		parts = append(parts, "CIS Docker "+f.CIS)
	}
	parts = append(parts, f.CWE...)
	for _, ref := range f.References {
		if !strings.HasPrefix(ref, "http") && !strings.HasPrefix(ref, "CIS Docker Benchmark") {
			parts = append(parts, ref)
		}
	}
	return strings.Join(parts, " · ")
}

func cell(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	return strings.ReplaceAll(s, "\n", " ")
}

func yesNo(b bool) string {
	if b {
		return "ok"
	}
	return "indisponível"
}
