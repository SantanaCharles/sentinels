package setup

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/charmbracelet/huh"

	"github.com/SantanaCharles/sentinels/internal/config"
	"github.com/SantanaCharles/sentinels/internal/finding"
	"github.com/SantanaCharles/sentinels/internal/notify"
	"github.com/SantanaCharles/sentinels/internal/watch"
)

var telegramTokenRe = regexp.MustCompile(`^\d{6,12}:[A-Za-z0-9_-]{30,}$`)

func (s *Session) sectionNotify(ctx context.Context) error {
	for {
		opts := []huh.Option[string]{}
		for i, n := range s.Cfg.Alerts.Notifiers {
			if n.Type == "telegram" {
				label := "💬 ativar conversa (comandos, botões e perguntas): "
				if n.Interactive {
					label = "💬 desativar conversa: "
				}
				opts = append(opts, huh.NewOption(label+describe(n), fmt.Sprintf("chat:%d", i)))
			}
			opts = append(opts, huh.NewOption("✖ remover: "+describe(n), fmt.Sprintf("rm:%d", i)))
		}
		opts = append(opts,
			huh.NewOption("+ adicionar canal", "add"),
			huh.NewOption("✉ enviar mensagem de teste para todos", "test"),
			huh.NewOption("← voltar", "back"))
		choice := "add"
		if len(s.Cfg.Alerts.Notifiers) > 0 {
			choice = "back"
		}
		title := fmt.Sprintf("Notificações — %d canal(is)", len(s.Cfg.Alerts.Notifiers))
		if err := s.form(huh.NewSelect[string]().Title(title).Options(opts...).Value(&choice)); err != nil {
			return err
		}
		switch {
		case choice == "back":
			return nil
		case choice == "add":
			if err := s.addNotifier(ctx); err != nil && !errors.Is(err, huh.ErrUserAborted) {
				fmt.Fprintln(s.Out, "erro:", err)
			}
		case choice == "test":
			s.testNotifiers(ctx)
		case strings.HasPrefix(choice, "chat:"):
			var i int
			fmt.Sscanf(choice, "chat:%d", &i)
			n := &s.Cfg.Alerts.Notifiers[i]
			n.Interactive = !n.Interactive
			s.dirty = true
			if n.Interactive {
				fmt.Fprintln(s.Out, "✔ Conversa ativada. Salve e reinicie o agente; depois mande /ajuda para o bot.")
			} else {
				fmt.Fprintln(s.Out, "Conversa desativada: o bot só enviará alertas.")
			}
		case strings.HasPrefix(choice, "rm:"):
			var i int
			fmt.Sscanf(choice, "rm:%d", &i)
			if s.confirm("Remover "+describe(s.Cfg.Alerts.Notifiers[i])+"?", false) {
				s.Cfg.Alerts.Notifiers = append(s.Cfg.Alerts.Notifiers[:i], s.Cfg.Alerts.Notifiers[i+1:]...)
				s.dirty = true
			}
		}
	}
}

func describe(n config.Notifier) string {
	d := n.Type
	switch n.Type {
	case "telegram":
		d += " (chat " + n.ChatID + ")"
		if n.Interactive {
			d += " 💬"
		}
	case "email":
		d += " (" + strings.Join(n.To, ", ") + ")"
	}
	if n.Name != "" {
		d += " — " + n.Name
	}
	if n.MinSeverity != "" {
		d += " — a partir de " + n.MinSeverity
	}
	return d
}

func (s *Session) usedEnv() map[string]bool {
	used := map[string]bool{}
	for _, n := range s.Cfg.Alerts.Notifiers {
		for _, e := range []string{n.TokenEnv, n.WebhookEnv, n.URLEnv, n.SecretEnv, n.UserEnv, n.PasswordEnv} {
			if e != "" {
				used[e] = true
			}
		}
	}
	return used
}

func (s *Session) addNotifier(ctx context.Context) error {
	kind := "telegram"
	if err := s.form(huh.NewSelect[string]().Title("Onde você quer receber os alertas?").Options(
		huh.NewOption("Telegram (recomendado: chega no celular)", "telegram"),
		huh.NewOption("Slack", "slack"),
		huh.NewOption("Discord", "discord"),
		huh.NewOption("E-mail (SMTP)", "email"),
		huh.NewOption("Webhook (n8n, Zapier, sistema próprio)", "webhook"),
	).Value(&kind)); err != nil {
		return err
	}
	used := s.usedEnv()
	n := config.Notifier{Type: kind}
	var err error
	switch kind {
	case "telegram":
		err = s.addTelegram(ctx, &n, used)
	case "slack":
		n.WebhookEnv = freeEnvName(used, "SENTINELS_SLACK_WEBHOOK")
		err = s.secret("URL do Incoming Webhook (api.slack.com/apps → Incoming Webhooks)", n.WebhookEnv, prefix("https://hooks.slack.com/"))
	case "discord":
		n.WebhookEnv = freeEnvName(used, "SENTINELS_DISCORD_WEBHOOK")
		err = s.secret("URL do webhook (canal → Editar → Integrações → Webhooks)", n.WebhookEnv,
			prefix("https://discord.com/api/webhooks/", "https://discordapp.com/api/webhooks/"))
	case "email":
		err = s.addEmail(&n, used)
	case "webhook":
		n.URLEnv = freeEnvName(used, "SENTINELS_WEBHOOK_URL")
		if err = s.secret("URL do webhook (https)", n.URLEnv, prefix("https://", "http://127.0.0.1", "http://localhost")); err == nil {
			n.SecretEnv = freeEnvName(used, "SENTINELS_WEBHOOK_SECRET")
			if s.Env.Get(n.SecretEnv) == "" {
				s.Env.Set(n.SecretEnv, randomToken())
			}
			fmt.Fprintf(s.Out, "Segredo HMAC gerado em %s: valide o header X-Sentinels-Signature no receptor.\n", n.SecretEnv)
		}
	}
	if err != nil {
		return err
	}

	min := ""
	if err := s.form(huh.NewSelect[string]().Title("Que alertas vão para este canal?").Options(
		append([]huh.Option[string]{huh.NewOption("O padrão geral ("+s.Cfg.Alerts.MinSeverity+")", "")}, severityOptions...)...,
	).Value(&min)); err != nil {
		return err
	}
	n.MinSeverity = min
	if kind == "telegram" {
		n.Interactive = s.confirm("Conversar com o agente por este chat? (/status, botões nos alertas e perguntas à IA — só este chat é atendido)", true)
	}
	s.Cfg.Alerts.Notifiers = append(s.Cfg.Alerts.Notifiers, n)
	s.dirty = true
	fmt.Fprintln(s.Out, "✔ Canal adicionado:", describe(n))
	if s.confirm("Enviar uma mensagem de teste agora?", true) {
		s.testNotifiers(ctx)
	}
	return nil
}

func (s *Session) addTelegram(ctx context.Context, n *config.Notifier, used map[string]bool) error {
	s.note("Telegram", "1. No Telegram, fale com @BotFather e envie /newbot.\n2. Copie o token que ele devolver.\n3. Mande qualquer mensagem para o seu bot (ou adicione-o ao grupo da equipe e mande uma mensagem lá).")
	n.TokenEnv = freeEnvName(used, "SENTINELS_TELEGRAM_TOKEN")
	if err := s.secret("Token do bot", n.TokenEnv, func(v string) error {
		if !telegramTokenRe.MatchString(v) {
			return errors.New("formato esperado: 123456789:ABC…")
		}
		return nil
	}); err != nil {
		return err
	}
	for attempt := 0; attempt < 3; attempt++ {
		fmt.Fprintln(s.Out, "Procurando conversas do bot…")
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		chats, err := notify.TelegramChats(cctx, s.Env.Get(n.TokenEnv), "")
		cancel()
		if err != nil {
			fmt.Fprintln(s.Out, "✖", err)
			break
		}
		if len(chats) > 0 {
			opts := make([]huh.Option[string], 0, len(chats)+1)
			for _, c := range chats {
				opts = append(opts, huh.NewOption(c.Label+"  ("+c.ID+")", c.ID))
			}
			opts = append(opts, huh.NewOption("✎ digitar o chat_id", ""))
			id := chats[0].ID
			if err := s.form(huh.NewSelect[string]().Title("Para qual conversa enviar?").Options(opts...).Value(&id)); err != nil {
				return err
			}
			if id != "" {
				n.ChatID = id
				return nil
			}
			break
		}
		if !s.confirm("Nenhuma conversa encontrada. Já mandou uma mensagem para o bot? Tentar de novo?", true) {
			break
		}
	}
	return s.form(huh.NewInput().Title("chat_id (grupos começam com -100)").Value(&n.ChatID).Validate(func(v string) error {
		if !regexp.MustCompile(`^-?\d+$`).MatchString(v) {
			return errors.New("só números (pode começar com -)")
		}
		return nil
	}))
}

func (s *Session) addEmail(n *config.Notifier, used map[string]bool) error {
	to := ""
	if err := s.form(
		huh.NewInput().Title("Servidor SMTP (host:porta)").Description("465 = TLS direto; 587 = STARTTLS").Placeholder("smtp.gmail.com:587").
			Value(&n.SMTPHost).Validate(func(v string) error {
			if !strings.Contains(v, ":") {
				return errors.New("inclua a porta, ex.: smtp.exemplo.com:587")
			}
			return nil
		}),
		huh.NewInput().Title("Remetente").Placeholder("Sentinels <alertas@empresa.com.br>").Value(&n.From).Validate(addr),
		huh.NewInput().Title("Destinatários (separados por vírgula)").Value(&to).Validate(func(v string) error {
			for _, a := range strings.Split(v, ",") {
				if err := addr(strings.TrimSpace(a)); err != nil {
					return err
				}
			}
			return nil
		}),
	); err != nil {
		return err
	}
	for _, a := range strings.Split(to, ",") {
		n.To = append(n.To, strings.TrimSpace(a))
	}
	if !s.confirm("O servidor exige login?", true) {
		return nil
	}
	n.UserEnv = freeEnvName(used, "SENTINELS_SMTP_USER")
	n.PasswordEnv = freeEnvName(used, "SENTINELS_SMTP_PASSWORD")
	if err := s.secret("Usuário SMTP", n.UserEnv, nil); err != nil {
		return err
	}
	return s.secret("Senha SMTP (Gmail/Outlook: use senha de app)", n.PasswordEnv, nil)
}

func addr(v string) error {
	if _, err := mail.ParseAddress(v); err != nil {
		return errors.New("endereço de e-mail inválido")
	}
	return nil
}

func prefix(ps ...string) func(string) error {
	return func(v string) error {
		for _, p := range ps {
			if strings.HasPrefix(v, p) {
				return nil
			}
		}
		return fmt.Errorf("deve começar com %s", ps[0])
	}
}

func (s *Session) testNotifiers(ctx context.Context) {
	chans, err := notify.Build(s.Cfg.Alerts)
	if err != nil {
		fmt.Fprintln(s.Out, "✖", err)
		return
	}
	if len(chans) == 0 {
		fmt.Fprintln(s.Out, "Nenhum canal configurado.")
		return
	}
	m := notify.FromAlert(watch.Alert{Severity: finding.Critical, Title: "Teste do Sentinels", Target: "setup",
		Lines: []string{"Se você recebeu esta mensagem, o canal está funcionando."}}, s.hostname())
	for _, c := range chans {
		tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := c.Notifier.Send(tctx, m)
		cancel()
		if err != nil {
			fmt.Fprintf(s.Out, "✖ %-14s %v\n", c.Notifier.Name(), err)
		} else {
			fmt.Fprintf(s.Out, "✔ %-14s enviado\n", c.Notifier.Name())
		}
	}
}
