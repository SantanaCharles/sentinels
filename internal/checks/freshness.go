package checks

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/SantanaCharles/sentinels/internal/finding"
)

// Freshness flags detection data that stopped updating. Downloads fail
// quietly (DNS, firewall, rate limits) and an agent with week-old rules
// misses exactly the newest attacks. Files that do not exist or cannot be
// read (e.g. host paths not mounted in the container) are skipped.
type FreshnessPaths struct {
	CacheDir      string // Sentinels cache: advisories.json, kev.json
	TrivyCacheDir string
	Offline       bool // KEV/feed are not downloaded on purpose
	HostRoot      string
}

func Freshness(p FreshnessPaths, now time.Time) []finding.Finding {
	var out []finding.Finding
	stale := func(id string, sev finding.Severity, title, detail, fix string, age time.Duration) {
		out = append(out, finding.Finding{
			ID: "agent." + id, Severity: sev, Target: "agente",
			Title:  fmt.Sprintf("%s (há %d dias)", title, int(age.Hours()/24)),
			Detail: detail, Remediation: fix,
		})
	}
	age := func(path string) (time.Duration, bool) {
		st, err := os.Stat(filepath.Join(p.HostRoot, path))
		if err != nil {
			return 0, false
		}
		return now.Sub(st.ModTime()), true
	}

	if !p.Offline && p.CacheDir != "" {
		if a, ok := age(filepath.Join(p.CacheDir, "advisories.json")); ok && a > 48*time.Hour {
			stale("stale_advisories", finding.Medium, "Feed de alertas emergenciais sem atualizar",
				"É por ele que chegam falhas graves exploradas antes de entrarem no catálogo KEV (como o PHP2Shell).",
				"Confira se o servidor alcança raw.githubusercontent.com (DNS, firewall de saída).", a)
		}
		if a, ok := age(filepath.Join(p.CacheDir, "kev.json")); ok && a > 4*24*time.Hour {
			stale("stale_kev", finding.Low, "Catálogo CISA KEV sem atualizar",
				"Sem ele, CVEs exploradas ativamente não sobem para Crítico.",
				"Confira se o servidor alcança www.cisa.gov.", a)
		}
	}

	if p.TrivyCacheDir != "" {
		if b, err := os.ReadFile(filepath.Join(p.HostRoot, p.TrivyCacheDir, "db", "metadata.json")); err == nil {
			var meta struct{ UpdatedAt time.Time }
			if json.Unmarshal(b, &meta) == nil && !meta.UpdatedAt.IsZero() {
				if a := now.Sub(meta.UpdatedAt); a > 3*24*time.Hour {
					stale("stale_trivy_db", finding.Medium, "Base de vulnerabilidades do Trivy desatualizada",
						"CVEs publicadas depois da última atualização não aparecem nos relatórios.",
						"O Trivy atualiza sozinho a cada varredura; confira se o servidor alcança ghcr.io e mirror.gcr.io.", a)
				}
			}
		}
	}

	if a, ok := age("/var/lib/suricata/rules/suricata.rules"); ok && a > 7*24*time.Hour {
		stale("stale_suricata_rules", finding.Medium, "Regras do Suricata desatualizadas",
			"Regras novas cobrem ataques e campanhas recentes.",
			"suricata-update && systemctl reload suricata — e agende diariamente (cron ou systemd timer).", a)
	}
	if a, ok := age("/etc/crowdsec/hub/.index.json"); ok && a > 14*24*time.Hour {
		stale("stale_crowdsec_hub", finding.Low, "Cenários do CrowdSec desatualizados",
			"Cenários novos detectam ataques e CVEs recentes.",
			"cscli hub update && cscli hub upgrade && systemctl reload crowdsec", a)
	}
	return out
}

// DefaultTrivyCache mirrors Trivy's own default when TRIVY_CACHE_DIR is unset.
func DefaultTrivyCache() string {
	if d := os.Getenv("TRIVY_CACHE_DIR"); d != "" {
		return d
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".cache", "trivy")
	}
	return ""
}
