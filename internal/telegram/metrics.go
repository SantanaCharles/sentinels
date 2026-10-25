package telegram

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/SantanaCharles/sentinels/internal/event"
	"github.com/SantanaCharles/sentinels/internal/report"
)

func (b *Bot) metrics(ctx context.Context) reply {
	m, err := b.Store.Metrics(ctx, time.Now())
	if err != nil {
		return reply{text: "Erro ao calcular as métricas: " + err.Error()}
	}
	var s strings.Builder
	fmt.Fprintf(&s, "📊 Métricas — %s\n\n", b.Host)

	s.WriteString("Correção\n")
	fmt.Fprintf(&s, "• Críticos abertos: %d (%d há mais de 7 dias; o mais antigo tem %d dia(s))\n", m.OpenCritical, m.CriticalOver7d, m.OldestCritDays)
	fmt.Fprintf(&s, "• Altos abertos: %d · idade média: %s\n", m.OpenHigh, report.Days(m.AvgOpenDays))
	fmt.Fprintf(&s, "• Tempo médio de correção: críticos %s · altos %s\n", report.Days(m.MTTRCritDays), report.Days(m.MTTRHighDays))
	fmt.Fprintf(&s, "• Resolvidos em 30 dias: %d\n\n", m.ResolvedLast30d)

	s.WriteString("Alertas (30 dias)\n")
	fmt.Fprintf(&s, "• Eventos: %d · últimos 7 dias: 🔴 %d · 🟠 %d · 🟡 %d\n", m.Events30d,
		m.Events7d["critical"], m.Events7d["high"], m.Events7d["medium"])
	fmt.Fprintf(&s, "• Falso positivo: %s (%d falso · %d confirmado)\n", report.Percent(m.FPRate), m.FalsePos30d, m.Confirmed30d)
	fmt.Fprintf(&s, "• Altos/críticos sem seu feedback: %d · silenciados: %d\n", m.Unreviewed30d, m.Suppressed30d)

	if len(m.TopAttackers) > 0 {
		s.WriteString("\nQuem mais atacou\n")
		for _, r := range m.TopAttackers {
			fmt.Fprintf(&s, "• %s — %d ocorrência(s)\n", r.Key, r.Count)
		}
	}
	if len(m.TopTechniques) > 0 {
		s.WriteString("\nTécnicas mais vistas (MITRE ATT&CK)\n")
		for _, r := range m.TopTechniques {
			name := ""
			if t, ok := event.Techniques[r.Key]; ok {
				name = " " + t.Name
			}
			fmt.Fprintf(&s, "• %s%s — %d\n", r.Key, name, r.Count)
		}
	}
	if m.CriticalOver7d > 0 {
		s.WriteString("\n⚠️ Há críticos abertos há mais de uma semana: veja /findings critical.")
	}
	return reply{text: secretsOnly(s.String())}
}
