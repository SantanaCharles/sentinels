package notify

import (
	"fmt"
	"strings"

	"github.com/SantanaCharles/sentinels/internal/config"
	"github.com/SantanaCharles/sentinels/internal/finding"
)

// Build creates the channels from configuration. Secrets come from the
// environment; a missing variable is a configuration error, reported upfront.
func Build(cfg config.Alerts) ([]Channel, error) {
	defMin, err := finding.ParseSeverity(cfg.MinSeverity)
	if err != nil {
		return nil, fmt.Errorf("alerts.min_severity: %w", err)
	}
	var out []Channel
	for i, n := range cfg.Notifiers {
		where := fmt.Sprintf("alerts.notifiers[%d] (%s)", i, n.Type)
		min := defMin
		if n.MinSeverity != "" {
			if min, err = finding.ParseSeverity(n.MinSeverity); err != nil {
				return nil, fmt.Errorf("%s: %w", where, err)
			}
		}
		need := func(env string) (string, error) {
			if env == "" {
				return "", fmt.Errorf("%s: campo *_env obrigatório não informado", where)
			}
			v := config.Secret(env)
			if v == "" {
				return "", fmt.Errorf("%s: variável de ambiente %s vazia", where, env)
			}
			return v, nil
		}

		var nt Notifier
		switch strings.ToLower(n.Type) {
		case "telegram":
			tok, err := need(n.TokenEnv)
			if err != nil {
				return nil, err
			}
			if n.ChatID == "" {
				return nil, fmt.Errorf("%s: chat_id obrigatório", where)
			}
			nt = &Telegram{Token: tok, ChatID: n.ChatID, Buttons: n.Interactive}
		case "slack":
			u, err := need(n.WebhookEnv)
			if err != nil {
				return nil, err
			}
			nt = &Slack{WebhookURL: u}
		case "discord":
			u, err := need(n.WebhookEnv)
			if err != nil {
				return nil, err
			}
			nt = &Discord{WebhookURL: u}
		case "webhook":
			u, err := need(n.URLEnv)
			if err != nil {
				return nil, err
			}
			if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://127.0.0.1") && !strings.HasPrefix(u, "http://localhost") {
				return nil, fmt.Errorf("%s: use https (http só para localhost)", where)
			}
			nt = &Webhook{URL: u, Secret: config.Secret(n.SecretEnv)}
		case "email":
			if n.SMTPHost == "" || n.From == "" || len(n.To) == 0 {
				return nil, fmt.Errorf("%s: smtp_host, from e to são obrigatórios", where)
			}
			e := &Email{Host: n.SMTPHost, From: n.From, To: n.To}
			if n.UserEnv != "" {
				if e.User, err = need(n.UserEnv); err != nil {
					return nil, err
				}
				if e.Password, err = need(n.PasswordEnv); err != nil {
					return nil, err
				}
			}
			nt = e
		default:
			return nil, fmt.Errorf("%s: tipo desconhecido (use telegram, slack, discord, email ou webhook)", where)
		}
		out = append(out, Channel{Notifier: named{nt, n.Name}, MinSeverity: min})
	}
	return out, nil
}

// named lets two channels of the same type be told apart in logs.
type named struct {
	Notifier
	label string
}

func (n named) Name() string {
	if n.label != "" {
		return n.Notifier.Name() + ":" + n.label
	}
	return n.Notifier.Name()
}
