package telegram

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/SantanaCharles/sentinels/internal/ai"
	"github.com/SantanaCharles/sentinels/internal/finding"
	"github.com/SantanaCharles/sentinels/internal/scan"
	"github.com/SantanaCharles/sentinels/internal/store"
	"github.com/SantanaCharles/sentinels/internal/watch"
)

var icon = map[finding.Severity]string{
	finding.Critical: "🔴", finding.High: "🟠", finding.Medium: "🟡", finding.Low: "🔵", finding.Info: "⚪",
}

const help = `🛡 Sentinels — comandos

/status — resumo do servidor
/achados — problemas abertos (ou: /achados critico | alto | medio | todos)
/eventos — ataques e eventos das últimas 24h (ou: /eventos 72)
/evento 12 — detalhe de um evento, com botões
/silenciados — regras de falso positivo ativas

Nos alertas: ✅ Ataque real · 🔕 Falso positivo · 🤖 Explicar.
Ou escreva uma pergunta, ex.: "o que aconteceu hoje?" (usa a IA configurada).

O bot só consulta e registra seu feedback: nada é alterado no servidor.`

func (b *Bot) onMessage(ctx context.Context, m *message) reply {
	text := strings.TrimSpace(m.Text)
	if !strings.HasPrefix(text, "/") {
		return b.ask(ctx, m.Chat.ID, text)
	}
	fields := strings.Fields(text)
	cmd := strings.ToLower(strings.SplitN(fields[0], "@", 2)[0]) // "/status@MeuBot" in groups
	args := fields[1:]
	switch cmd {
	case "/status":
		return b.status(ctx)
	case "/achados":
		return b.findings(args)
	case "/eventos":
		return b.events(ctx, args)
	case "/evento":
		if len(args) == 0 {
			return reply{text: "Use: /evento 12 (os números aparecem em /eventos e nos alertas)"}
		}
		id, err := strconv.ParseInt(strings.TrimPrefix(args[0], "#"), 10, 64)
		if err != nil {
			return reply{text: "Número de evento inválido."}
		}
		return b.event(ctx, id)
	case "/silenciados":
		return b.suppressions(ctx)
	default:
		return reply{text: help}
	}
}

func ago(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "agora"
	case d < time.Hour:
		return fmt.Sprintf("há %d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("há %dh", int(d.Hours()))
	}
	return fmt.Sprintf("há %d dias", int(d.Hours()/24))
}

func (b *Bot) status(ctx context.Context) reply {
	var s strings.Builder
	fmt.Fprintf(&s, "🛡 Sentinels — %s\n\n", b.Host)
	r, err := scan.Latest(b.ReportDir)
	if err != nil {
		s.WriteString(err.Error() + "\n")
	} else {
		c := finding.Count(r.Findings)
		fmt.Fprintf(&s, "Última varredura: %s · %d ativo(s)\n", ago(r.Started), len(r.Assets))
		fmt.Fprintf(&s, "Abertos: 🔴 %d críticos · 🟠 %d altos · 🟡 %d médios\n", c[finding.Critical], c[finding.High], c[finding.Medium])
		n := 0
		for _, f := range r.Findings {
			if f.Severity == finding.Critical && f.Accepted == "" {
				if n == 0 {
					s.WriteString("\nCríticos:\n")
				}
				if n++; n > 6 {
					fmt.Fprintf(&s, "… e mais %d (veja /achados critico)\n", c[finding.Critical]-6)
					break
				}
				fmt.Fprintf(&s, "• %s — %s\n", f.Title, f.Target)
			}
		}
	}
	evs, err := b.Store.Events(ctx, time.Now().Add(-24*time.Hour), finding.Low, 500)
	if err == nil {
		crit := 0
		for _, e := range evs {
			if e.Event.Severity == finding.Critical {
				crit++
			}
		}
		fmt.Fprintf(&s, "\nÚltimas 24h: %d evento(s), %d crítico(s) — /eventos\n", len(evs), crit)
	}
	return reply{text: secretsOnly(s.String())}
}

var levelArg = map[string]finding.Severity{
	"critico": finding.Critical, "crítico": finding.Critical, "critical": finding.Critical,
	"alto": finding.High, "high": finding.High, "medio": finding.Medium, "médio": finding.Medium,
	"medium": finding.Medium, "baixo": finding.Low, "low": finding.Low, "todos": finding.Info,
}

func (b *Bot) findings(args []string) reply {
	min := finding.High
	if len(args) > 0 {
		if v, ok := levelArg[strings.ToLower(args[0])]; ok {
			min = v
		}
	}
	r, err := scan.Latest(b.ReportDir)
	if err != nil {
		return reply{text: err.Error()}
	}
	var s strings.Builder
	shown, total := 0, 0
	for _, f := range r.Findings {
		if f.Accepted != "" || f.Severity < min {
			continue
		}
		total++
		if shown < 15 {
			shown++
			extra := ""
			if f.KEV {
				extra = " ⚠️ explorada ativamente"
			}
			fmt.Fprintf(&s, "%s %s — %s%s\n", icon[f.Severity], f.Title, f.Target, extra)
		}
	}
	if total == 0 {
		return reply{text: fmt.Sprintf("✅ Nenhum achado %s ou acima. Varredura %s.", min.Label(), ago(r.Started))}
	}
	head := fmt.Sprintf("%d achado(s) %s ou acima (varredura %s):\n\n", total, min.Label(), ago(r.Started))
	if total > shown {
		s.WriteString(fmt.Sprintf("\n… e mais %d. Correções detalhadas no relatório do servidor.", total-shown))
	}
	return reply{text: secretsOnly(head + s.String())}
}

func (b *Bot) events(ctx context.Context, args []string) reply {
	hours := 24
	if len(args) > 0 {
		if h, err := strconv.Atoi(args[0]); err == nil && h > 0 && h <= 2160 {
			hours = h
		}
	}
	evs, err := b.Store.Events(ctx, time.Now().Add(-time.Duration(hours)*time.Hour), finding.Medium, 15)
	if err != nil {
		return reply{text: "Erro ao ler eventos: " + err.Error()}
	}
	if len(evs) == 0 {
		return reply{text: fmt.Sprintf("✅ Nenhum evento médio ou acima nas últimas %dh.", hours)}
	}
	var s strings.Builder
	fmt.Fprintf(&s, "Eventos das últimas %dh (mais recentes primeiro):\n\n", hours)
	for _, se := range evs {
		e := se.Event
		tech := e.Technique
		if n := e.TechniqueName(); n != "" {
			tech = n
		}
		mark := ""
		switch {
		case se.Verdict == store.VerdictFalsePositive:
			mark = " · falso positivo"
		case se.Verdict == store.VerdictConfirmed:
			mark = " · confirmado"
		case se.Suppressed:
			mark = " · silenciado"
		}
		fmt.Fprintf(&s, "#%d %s %s — %s · %s · %dx%s\n", se.ID, icon[e.Severity], clip(tech, 40), orDash(e.Target), ago(se.LastSeen), se.Count, mark)
	}
	s.WriteString("\nDetalhes: /evento <número>")
	return reply{text: secretsOnly(s.String())}
}

func (b *Bot) event(ctx context.Context, id int64) reply {
	se, err := b.Store.Event(ctx, id)
	if err != nil {
		return reply{text: err.Error()}
	}
	e := se.Event
	var s strings.Builder
	fmt.Fprintf(&s, "%s Evento #%d — %s\n", icon[e.Severity], se.ID, e.Severity.Label())
	if n := e.TechniqueName(); n != "" {
		fmt.Fprintf(&s, "Técnica: %s %s (%s)\n", e.Technique, n, e.Tactic)
	}
	fmt.Fprintf(&s, "Fonte: %s · Regra: %s\nAlvo: %s · Origem: %s\n", e.Source, e.Rule, orDash(e.Target), orDash(e.SourceIP))
	fmt.Fprintf(&s, "Visto %d vez(es), última %s\n\n%s\n", se.Count, ago(se.LastSeen), e.Summary)
	for _, c := range e.Context {
		fmt.Fprintf(&s, "• %s\n", c)
	}
	if se.AINote != "" {
		fmt.Fprintf(&s, "\n🤖 Análise da IA:\n%s\n", plain(se.AINote))
	}
	var buttons []Button
	switch se.Verdict {
	case store.VerdictFalsePositive:
		s.WriteString("\nMarcado como falso positivo.")
	case store.VerdictConfirmed:
		s.WriteString("\nConfirmado como ataque real.")
	default:
		buttons = FeedbackButtons(id, b.Analyst != nil && se.AINote == "")
	}
	return reply{text: secretsOnly(s.String()), buttons: buttons}
}

// FeedbackButtons are attached to alerts and to /evento replies.
func FeedbackButtons(eventID int64, explain bool) []Button {
	id := strconv.FormatInt(eventID, 10)
	bs := []Button{{"✅ Ataque real", "ok:" + id}, {"🔕 Falso positivo", "fp:" + id}}
	if explain {
		bs = append(bs, Button{"🤖 Explicar", "ex:" + id})
	}
	return bs
}

func (b *Bot) suppressions(ctx context.Context) reply {
	list, err := b.Store.Suppressions(ctx)
	if err != nil {
		return reply{text: err.Error()}
	}
	if len(list) == 0 {
		return reply{text: "Nenhum silenciamento ativo."}
	}
	var s strings.Builder
	s.WriteString("Silenciamentos ativos (falso positivo):\n\n")
	for _, x := range list {
		scope := "em qualquer alvo"
		if x.SourceIP != "" {
			scope = "vindo de " + x.SourceIP
		}
		if x.Target != "" {
			scope = "contra " + x.Target
		}
		fmt.Fprintf(&s, "#%d %s — %s · até %s · %d silenciado(s)\n", x.ID, clip(x.Rule, 50), scope, x.ExpiresAt.Format("02/01"), x.Hits)
	}
	s.WriteString("\nPara remover: sentinels suppressions remove <id> (no servidor)")
	return reply{text: secretsOnly(s.String())}
}

// onButton handles alert buttons; the returned text is the short toast.
func (b *Bot) onButton(ctx context.Context, chatID, messageID int64, data string, from user) string {
	kind, idStr, ok := strings.Cut(data, ":")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if !ok || err != nil {
		return "Botão inválido"
	}
	switch kind {
	case "ok", "fp":
		verdict := store.VerdictConfirmed
		if kind == "fp" {
			verdict = store.VerdictFalsePositive
		}
		msg, err := b.Store.AddFeedback(ctx, store.Feedback{EventID: id, Verdict: verdict, Note: "via Telegram por " + from.name()})
		if err != nil {
			return "Erro: " + err.Error()
		}
		b.clearButtons(ctx, chatID, messageID)
		label := map[string]string{"ok": "✅ confirmado como ataque real", "fp": "🔕 marcado como falso positivo"}[kind]
		b.send(ctx, chatID, fmt.Sprintf("Evento #%d %s por %s.\n%s", id, label, from.name(), msg), nil)
		b.Log("telegram: evento #%d: %s por %s", id, verdict, from.name())
		return "Registrado"
	case "ex":
		if b.Analyst == nil {
			return "IA não configurada (sentinels setup → IA)"
		}
		if !b.takeAI() {
			return "Limite de análises por hora atingido"
		}
		go b.explain(ctx, chatID, id)
		return "Analisando…"
	}
	return "Botão desconhecido"
}

func (b *Bot) explain(ctx context.Context, chatID, id int64) {
	b.typing(ctx, chatID)
	se, err := b.Store.Event(ctx, id)
	if err != nil {
		b.send(ctx, chatID, err.Error(), nil)
		return
	}
	e := se.Event
	actx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	text, err := b.Analyst.ExplainAlert(actx, watch.Alert{
		Severity: e.Severity, Title: strings.TrimSpace(e.TechniqueName() + " — " + e.Rule), Target: e.Target,
		Lines: append([]string{e.Summary}, e.Context...), Event: &e, Count: se.Count, EventID: id,
	})
	if err != nil {
		b.send(ctx, chatID, "A IA não respondeu: "+err.Error(), nil)
		return
	}
	_ = b.Store.SetAINote(ctx, id, text)
	b.send(ctx, chatID, fmt.Sprintf("🤖 Evento #%d\n\n%s", id, plain(text)), nil)
}

// ask answers a free-form question with the AI and a snapshot of what the
// agent knows.
func (b *Bot) ask(ctx context.Context, chatID int64, question string) reply {
	if b.Analyst == nil {
		return reply{text: "A IA não está configurada, então só entendo comandos. Veja /ajuda — ou configure a IA no servidor: sentinels setup → IA."}
	}
	if len([]rune(question)) > 1000 {
		return reply{text: "Pergunta longa demais (máx. 1000 caracteres)."}
	}
	if !b.takeAI() {
		return reply{text: "Limite de perguntas à IA por hora atingido (ai.max_calls_per_hour). Os comandos continuam funcionando: /ajuda"}
	}
	b.typing(ctx, chatID)
	snap, tags := b.snapshot(ctx)
	actx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	text, err := b.Analyst.Answer(actx, question, snap, tags)
	if err != nil {
		return reply{text: "A IA não respondeu: " + err.Error()}
	}
	return reply{text: plain(text)}
}

// snapshot summarizes the latest report and recent events for the AI.
func (b *Bot) snapshot(ctx context.Context) (string, []string) {
	var s strings.Builder
	var tags []string
	fmt.Fprintf(&s, "Servidor: %s. Agora: %s.\n", b.Host, time.Now().Format("02/01/2006 15:04"))
	if r, err := scan.Latest(b.ReportDir); err == nil {
		c := finding.Count(r.Findings)
		fmt.Fprintf(&s, "\nÚltima varredura %s: %d crítico, %d alto, %d médio.\n", ago(r.Started), c[finding.Critical], c[finding.High], c[finding.Medium])
		if r.AISummary != "" {
			s.WriteString("Resumo executivo anterior: " + r.AISummary + "\n")
		}
		s.WriteString("\nInventário:\n")
		for _, a := range r.Assets {
			fmt.Fprintf(&s, "- %s (%s): %s; portas públicas: %s\n", a.Name, a.Stack.Kind, strings.Join(a.Stack.Components, ", "), strings.Join(a.PublicPorts, ", "))
			for _, comp := range a.Stack.Components {
				tags = append(tags, "stack:"+strings.ToLower(comp))
			}
		}
		s.WriteString("\nAchados abertos (alto ou mais):\n")
		n := 0
		for _, f := range r.Findings {
			if f.Accepted != "" || f.Severity < finding.High {
				continue
			}
			tags = append(tags, f.ID)
			if n++; n <= 30 {
				fmt.Fprintf(&s, "- [%s] %s — %s", f.Severity.Label(), f.Title, f.Target)
				if f.KEV {
					s.WriteString(" (explorada ativamente)")
				}
				s.WriteString("\n")
			}
		}
	} else {
		s.WriteString("Nenhuma varredura concluída ainda.\n")
	}
	if evs, err := b.Store.Events(ctx, time.Now().Add(-72*time.Hour), finding.Medium, 30); err == nil {
		s.WriteString("\nEventos das últimas 72h:\n")
		for _, se := range evs {
			e := se.Event
			fmt.Fprintf(&s, "- #%d %s %s %s alvo=%s origem=%s %dx %s; %s\n", se.ID, ago(se.LastSeen), e.Severity.Label(),
				e.Technique, e.Target, e.SourceIP, se.Count, se.Verdict, clip(e.Summary, 200))
			if e.Technique != "" {
				tags = append(tags, strings.ToLower(e.Technique))
			}
		}
	}
	return s.String(), tags
}

func (b *Bot) takeAI() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	if now.Sub(b.aiWindow) >= time.Hour {
		b.aiWindow, b.aiCalls = now, 0
	}
	if b.MaxAIPerHour > 0 && b.aiCalls >= b.MaxAIPerHour {
		return false
	}
	b.aiCalls++
	return true
}

// plain turns the model's Markdown into readable plain text (messages are
// sent without parse_mode, so attacker text can never become formatting).
func plain(s string) string {
	s = strings.ReplaceAll(s, "**", "")
	s = strings.ReplaceAll(s, "__", "")
	var out []string
	for _, l := range strings.Split(s, "\n") {
		out = append(out, strings.TrimLeft(l, "# "))
	}
	return strings.TrimSpace(strings.Join(out, "\n"))
}

// secretsOnly masks credentials that may sit in log text; IPs stay, as in
// the alerts this chat already receives.
func secretsOnly(s string) string { return ai.NewRedactor(true).Redact(s) }

func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
