package checks

import (
	"fmt"
	"strings"

	"github.com/SantanaCharles/sentinels/internal/finding"
	"github.com/SantanaCharles/sentinels/internal/intel"
)

// ProductVersion is a runtime detected on a target, with where it came from.
type ProductVersion struct {
	Target  string
	Product string // "php"
	Version string // "8.3.12"; empty when the product was seen without a version
	Suffix  string // distribution suffix, e.g. "-1ubuntu2.3"
	Source  string // "PHP_VERSION da imagem", "header X-Powered-By"
	ModPHP  bool   // Apache + mod_php: highest-risk deployment for PHP2Shell
}

// Advisories matches detected runtimes against the emergency advisory list.
func Advisories(pv ProductVersion, advs []intel.Advisory) []finding.Finding {
	var out []finding.Finding
	for _, a := range advs {
		if !strings.EqualFold(a.Product, pv.Product) {
			continue
		}
		base := finding.Finding{
			ID:          "advisory." + a.ID,
			Target:      pv.Target,
			CVE:         strings.Join(a.CVEs, ", "),
			Remediation: a.Remediation,
			References:  a.References,
		}
		sev, err := finding.ParseSeverity(a.Severity)
		if err != nil {
			sev = finding.Critical
		}
		risk := ""
		if pv.ModPHP {
			risk = " Este container usa Apache + mod_php, o cenário de maior risco."
		}

		if pv.Version == "" {
			base.Severity = finding.High
			base.Title = fmt.Sprintf("%s: versão não identificada — verifique agora", a.Title)
			base.Detail = fmt.Sprintf("%s detectado, mas sem versão visível. %s%s Confira com `docker exec %s php -v`.",
				strings.ToUpper(pv.Product), a.Summary, risk, pv.Target)
			out = append(out, base)
			continue
		}

		where := fmt.Sprintf("%s %s%s (fonte: %s).", strings.ToUpper(pv.Product), pv.Version, pv.Suffix, pv.Source)
		switch a.Check(pv.Version, pv.Suffix) {
		case intel.Vulnerable:
			base.Severity = sev
			base.Title = a.Title
			base.Detail = where + " " + a.Summary + risk
		case intel.VulnerableEOL:
			base.Severity = sev
			base.Title = a.Title + " (versão sem suporte, sem correção oficial)"
			base.Detail = where + " " + a.Summary + risk
		case intel.NeedsVendorCheck:
			base.Severity = finding.High
			base.Title = a.Title + " — confirme o patch do fornecedor"
			base.Detail = where + " Pacotes de distribuição (Debian, Ubuntu, RHEL) recebem a correção sem mudar o número da versão; confirme no aviso de segurança da distribuição. " + a.Summary + risk
		default:
			continue
		}
		out = append(out, base)
	}
	return out
}
