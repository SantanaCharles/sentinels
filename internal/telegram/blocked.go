package telegram

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/SantanaCharles/sentinels/internal/integrations"
)

// Blocklist is the CrowdSec source's view of the decisions in force.
type Blocklist interface {
	Blocked(now time.Time) ([]integrations.Blocked, bool)
}

const maxBlockedLines = 40

// blocked lists who CrowdSec is blocking right now. Read-only: unblocking is
// done by the admin over SSH, never from the chat.
func (b *Bot) blocked(ctx context.Context, args []string) reply {
	if b.Blocklist == nil {
		return reply{text: "O CrowdSec não está ativo neste agente, então não há bloqueios para mostrar. Veja /doctor."}
	}
	now := time.Now()
	list, ok := b.Blocklist.Blocked(now)
	if !ok {
		return reply{text: "⏳ Ainda lendo as decisões do CrowdSec. Tente de novo em alguns segundos."}
	}
	filter := strings.ToLower(strings.Join(args, " "))
	if filter != "" {
		kept := list[:0:0]
		for _, d := range list {
			if strings.Contains(strings.ToLower(d.Value), filter) || strings.Contains(strings.ToLower(d.Scenario), filter) {
				kept = append(kept, d)
			}
		}
		list = kept
	}
	if len(list) == 0 {
		if filter != "" {
			return reply{text: fmt.Sprintf("Nenhum bloqueio ativo com %q.", filter)}
		}
		return reply{text: "✅ Nenhum IP bloqueado agora por detecções deste servidor.\n(A lista da comunidade do CrowdSec, se ativa, não entra aqui.)"}
	}

	var s strings.Builder
	head := fmt.Sprintf("⛔ %d bloqueio(s) ativo(s) — %s", len(list), b.Host)
	if filter != "" {
		head += fmt.Sprintf(" · filtro %q", filter)
	}
	s.WriteString(head + "\n")

	byScenario := map[string]int{}
	for _, d := range list {
		byScenario[shortScenario(d.Scenario)]++
	}
	if len(byScenario) > 1 {
		type kv struct {
			k string
			n int
		}
		var top []kv
		for k, n := range byScenario {
			top = append(top, kv{k, n})
		}
		sort.Slice(top, func(i, j int) bool { return top[i].n > top[j].n || top[i].n == top[j].n && top[i].k < top[j].k })
		parts := []string{}
		for i, t := range top {
			if i == 5 {
				break
			}
			parts = append(parts, fmt.Sprintf("%s %d", t.k, t.n))
		}
		s.WriteString("Por cenário: " + strings.Join(parts, " · ") + "\n")
	}
	s.WriteString("\n")

	seen, _ := b.Store.EventsByIP(ctx, now.AddDate(0, 0, -30))
	for i, d := range list {
		if i == maxBlockedLines {
			fmt.Fprintf(&s, "… e mais %d. Filtre com /blocked <ip ou cenário>.\n", len(list)-i)
			break
		}
		target := d.Value
		if !strings.EqualFold(d.Scope, "ip") {
			target = d.Scope + " " + d.Value
		}
		extra := ""
		if d.Type != "ban" {
			extra = " · " + d.Type
		}
		if d.Origin == "cscli" {
			extra += " · manual"
		}
		fmt.Fprintf(&s, "• %s — %s — mais %s%s", target, shortScenario(d.Scenario), remaining(d.Until.Sub(now)), extra)
		if n := seen[d.Value]; n > 1 {
			fmt.Fprintf(&s, " · %d eventos em 30d", n)
		}
		s.WriteString("\n")
	}
	s.WriteString("\nOs desbloqueios são feitos no SSH: sudo cscli decisions delete --ip <IP>")
	return reply{text: s.String()}
}

// shortScenario drops the hub author: crowdsecurity/ssh-slow-bf → ssh-slow-bf.
// Manual bans carry the admin's reason instead, which is kept as is.
func shortScenario(s string) string {
	if author, name, ok := strings.Cut(s, "/"); ok && !strings.ContainsAny(s, " '") && !strings.Contains(name, "/") && author != "" {
		s = name
	}
	if s == "" {
		return "manual"
	}
	return s
}

func remaining(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	case d >= time.Hour:
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%dm", int(d.Minutes())+1)
	}
}
