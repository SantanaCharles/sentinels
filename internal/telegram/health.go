package telegram

import (
	"context"
	"fmt"
	"strings"
)

// Check is one line of /doctor: what the running agent actually uses.
type Check struct {
	Name   string
	OK     bool
	Detail string
	Fix    string // shown when !OK: exact steps to run over SSH
}

// HealthFunc reports the agent's components; set by the watch command.
type HealthFunc func(ctx context.Context) []Check

func (b *Bot) doctor(ctx context.Context) reply {
	if b.Health == nil {
		return reply{text: "Diagnóstico indisponível neste agente."}
	}
	checks := b.Health(ctx)
	var ok, missing strings.Builder
	nMissing := 0
	for _, c := range checks {
		if c.OK {
			fmt.Fprintf(&ok, "✅ %s — %s\n", c.Name, c.Detail)
			continue
		}
		nMissing++
		fmt.Fprintf(&missing, "❌ %s — %s\n", c.Name, c.Detail)
		if c.Fix != "" {
			fmt.Fprintf(&missing, "%s\n", indent(c.Fix))
		}
		missing.WriteString("\n")
	}
	var s strings.Builder
	fmt.Fprintf(&s, "🩺 Sentinels — %s\n\n%s", b.Host, ok.String())
	if nMissing == 0 {
		s.WriteString("\nTudo ativo. 🎉")
		return reply{text: s.String()}
	}
	fmt.Fprintf(&s, "\nFaltando (%d) — rode no SSH do servidor, como root:\n\n%s", nMissing, missing.String())
	s.WriteString("Depois de instalar: recrie o agente (docker compose up -d --force-recreate sentinels) e mande /doctor de novo.\n")
	s.WriteString("Por segurança o bot não instala nada: isso exigiria root no servidor a partir do chat.")
	return reply{text: s.String()}
}

func indent(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = "   " + l
	}
	return strings.Join(lines, "\n")
}
