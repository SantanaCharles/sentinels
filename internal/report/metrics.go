package report

import (
	"fmt"

	"github.com/SantanaCharles/sentinels/internal/store"
)

// Days formats a duration in days, or "—" when there is no data (-1).
func Days(d float64) string {
	switch {
	case d < 0:
		return "—"
	case d < 1:
		return fmt.Sprintf("%.0f h", d*24)
	}
	return fmt.Sprintf("%.1f dias", d)
}

// Percent formats a ratio, or "—" when there is no data (-1).
func Percent(r float64) string {
	if r < 0 {
		return "—"
	}
	return fmt.Sprintf("%.0f%%", r*100)
}

func metricsSection(p func(string, ...any), m *store.Metrics) {
	p("## Métricas\n\n")
	p("| Indicador | Valor |\n|---|---|\n")
	p("| Críticos abertos / há mais de 7 dias | %d / %d |\n", m.OpenCritical, m.CriticalOver7d)
	p("| Altos abertos | %d |\n", m.OpenHigh)
	p("| Crítico aberto mais antigo | %d dia(s) |\n", m.OldestCritDays)
	p("| Idade média dos achados altos/críticos abertos | %s |\n", Days(m.AvgOpenDays))
	p("| Tempo médio de correção (MTTR) — críticos | %s |\n", Days(m.MTTRCritDays))
	p("| Tempo médio de correção (MTTR) — altos | %s |\n", Days(m.MTTRHighDays))
	p("| Achados resolvidos nos últimos 30 dias | %d |\n", m.ResolvedLast30d)
	p("| Eventos nos últimos 30 dias | %d |\n", m.Events30d)
	p("| Taxa de falso positivo (feedback de 30 dias) | %s (%d falso(s) · %d confirmado(s)) |\n", Percent(m.FPRate), m.FalsePos30d, m.Confirmed30d)
	p("| Alertas altos/críticos sem feedback | %d |\n", m.Unreviewed30d)
	p("\n")
	if len(m.TopAttackers) > 0 {
		p("**IPs que mais atacaram (30 dias):** ")
		for i, r := range m.TopAttackers {
			if i > 0 {
				p(" · ")
			}
			p("`%s` (%d)", r.Key, r.Count)
		}
		p("\n\n")
	}
	if len(m.TopTechniques) > 0 {
		p("**Técnicas mais vistas (MITRE ATT&CK):** ")
		for i, r := range m.TopTechniques {
			if i > 0 {
				p(" · ")
			}
			p("%s (%d)", r.Key, r.Count)
		}
		p("\n\n")
	}
}
