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
/scan — varredura completa agora; mando o status quando terminar
/inventory — o que está rodando: containers, stack, portas (ou: /inventory php)
/metrics — tempo de correção, falsos positivos, quem mais ataca
/report — resumo de ontem: países de origem e tipo de ataque (ou: /report hoje)
/update — verifica se há uma versão mais nova (não atualiza sozinho)
/blocked — IPs bloqueados agora pelo CrowdSec (ou: /blocked 13.140 | ssh)
/doctor — o que o Sentinels tem ativo e como instalar o que falta
/findings — problemas abertos (ou: /findings critical | high | medium | all)
/events — ataques e eventos das últimas 24h (ou: /events 72)
/event 12 — detalhe de um evento, com botões
/muted — regras de falso positivo ativas
/help — esta ajuda

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
		if _, err := scan.Latest(b.ReportDir); err != nil && b.Scanner != nil && b.Scanner.Scanning() {
			b.waitForScan(m.Chat.ID)
			return reply{text: "⏳ Ainda estou fazendo a primeira varredura (inclui as CVEs das imagens). Mando o status assim que terminar."}
		}
		return b.status(ctx)
	case "/scan", "/varrer":
		return b.requestScan(m.Chat.ID)
	case "/findings", "/achados":
		return b.findings(args)
	case "/events", "/eventos":
		return b.events(ctx, args)
	case "/event", "/evento":
		if len(args) == 0 {
			return reply{text: "Use: /event 12 (os números aparecem em /events e nos alertas)"}
		}
		id, err := strconv.ParseInt(strings.TrimPrefix(args[0], "#"), 10, 64)
		if err != nil {
			return reply{text: "Número de evento inválido."}
		}
		return b.event(ctx, id)
	case "/muted", "/silenciados":
		return b.suppressions(ctx)
	case "/blocked", "/bloqueados", "/bans":
		return b.blocked(ctx, args)
	case "/inventory", "/inventario", "/inventário":
		return b.inventory(args)
	case "/metrics", "/metricas", "/métricas":
		return b.metrics(ctx)
	case "/report", "/relatorio", "/relatório":
		return b.report(ctx, args)
	case "/update", "/atualizar", "/atualizacao", "/atualização":
		return b.update(ctx)
	case "/doctor", "/setup", "/saude", "/saúde":
		return b.doctor(ctx)
	default:
		return reply{text: help}
	}
}

func (b *Bot) requestScan(chatID int64) reply {
	if b.Scanner == nil {
		return reply{text: "Varredura sob demanda indisponível neste agente (iniciado com --no-scan)."}
	}
	switch b.Scanner.RequestScan() {
	case watch.ScanRunning:
		b.waitForScan(chatID)
		return reply{text: "⏳ Já tem uma varredura em andamento. Assim que ela terminar eu mando o status aqui."}
	case watch.ScanStarted:
		b.waitForScan(chatID)
		b.Log("telegram: varredura pedida pelo chat %d", chatID)
		return reply{text: "🔎 Iniciando uma varredura completa agora (containers, exposição, chaves vazadas e CVEs das imagens). Em poucos minutos te mando o status."}
	}
	return reply{text: "Varredura sob demanda indisponível neste agente."}
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
					fmt.Fprintf(&s, "… e mais %d (veja /findings critical)\n", c[finding.Critical]-6)
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
		fmt.Fprintf(&s, "\nÚltimas 24h: %d evento(s), %d crítico(s) — /events\n", len(evs), crit)
	}
	return reply{text: secretsOnly(s.String())}
}

var levelArg = map[string]finding.Severity{
	"critico": finding.Critical, "crítico": finding.Critical, "critical": finding.Critical,
	"alto": finding.High, "high": finding.High, "medio": finding.Medium, "médio": finding.Medium,
	"medium": finding.Medium, "baixo": finding.Low, "low": finding.Low, "todos": finding.Info, "all": finding.Info,
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
	s.WriteString("\nDetalhes: /event <número>")
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

// FeedbackButtons are attached to alerts and to /event replies.
func FeedbackButtons(eventID int64, explain bool) []Button {
	id := strconv.FormatInt(eventID, 10)
	bs := []Button{{"✅ Ataque real", "ok:" + id}, {"🔕 Falso positivo", "fp:" + id}}
	if explain {
		bs = append(bs, Button{"🤖 Explicar", "ex:" + id})
	}
	return bs
}

// inventory lists what the last scan found: containers with image, stack,
// public ports and open findings, plus services listening on the host.
func (b *Bot) inventory(args []string) reply {
	r, err := scan.Latest(b.ReportDir)
	if err != nil {
		return reply{text: err.Error()}
	}
	filter := ""
	if len(args) > 0 {
		filter = strings.ToLower(args[0])
	}
	type counts struct{ crit, high int }
	byTarget := map[string]*counts{}
	var hostLines []string
	for _, f := range r.Findings {
		if f.Accepted != "" || f.Severity < finding.High {
			continue
		}
		if strings.HasPrefix(f.Target, "host:") {
			hostLines = append(hostLines, fmt.Sprintf("%s %s", icon[f.Severity], f.Title))
			continue
		}
		for _, t := range strings.Split(f.Target, ", ") {
			c := byTarget[t]
			if c == nil {
				c = &counts{}
				byTarget[t] = c
			}
			if f.Severity == finding.Critical {
				c.crit++
			} else {
				c.high++
			}
		}
	}

	var s strings.Builder
	shown := 0
	for _, a := range r.Assets {
		line := strings.ToLower(a.Name + " " + a.Image + " " + strings.Join(a.Stack.Components, " "))
		if filter != "" && !strings.Contains(line, filter) {
			continue
		}
		shown++
		fmt.Fprintf(&s, "🐳 %s\n   imagem: %s\n", a.Name, a.Image)
		if len(a.Stack.Components) > 0 {
			fmt.Fprintf(&s, "   stack: %s (%s)\n", strings.Join(a.Stack.Components, ", "), a.Stack.Kind)
		}
		if len(a.PublicPorts) > 0 {
			fmt.Fprintf(&s, "   🌐 portas públicas: %s\n", strings.Join(a.PublicPorts, ", "))
		}
		if c := byTarget[a.Name]; c != nil {
			fmt.Fprintf(&s, "   problemas: 🔴 %d · 🟠 %d — /findings\n", c.crit, c.high)
		} else {
			s.WriteString("   ✅ nenhum problema alto ou crítico\n")
		}
		s.WriteString("\n")
	}
	head := fmt.Sprintf("📦 Inventário — %s (varredura %s)\n%d container(s)", b.Host, ago(r.Started), len(r.Assets))
	if filter != "" {
		head += fmt.Sprintf(", %d com %q", shown, filter)
	}
	head += "\n\n"
	if shown == 0 {
		s.WriteString("Nenhum container encontrado.\n\n")
	}
	if len(hostLines) > 0 {
		s.WriteString("🖥 Serviços do host expostos:\n")
		for _, l := range hostLines {
			s.WriteString("• " + l + "\n")
		}
		s.WriteString("\n")
	}
	s.WriteString("Inclui o que roda em containers Docker; pacotes instalados direto no sistema não aparecem.")
	return reply{text: secretsOnly(head + s.String())}
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
		b.send(ctx, chatID, fmt.Sprintf("🤖 Analisando o evento #%d… respondo em instantes.", id), nil)
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
		return reply{text: "A IA não está configurada, então só entendo comandos. Veja /help — ou configure a IA no servidor: sentinels setup → IA."}
	}
	if len([]rune(question)) > 1000 {
		return reply{text: "Pergunta longa demais (máx. 1000 caracteres)."}
	}
	if !b.takeAI() {
		return reply{text: "Limite de perguntas à IA por hora atingido (ai.max_calls_per_hour). Os comandos continuam funcionando: /help"}
	}
	b.send(ctx, chatID, "🤔 Analisando sua pergunta com os dados do servidor… respondo em instantes.", nil)
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
