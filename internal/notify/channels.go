package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// postJSON sends body and treats any non-2xx status as an error.
func postJSON(ctx context.Context, url string, body any, headers map[string]string) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Sentinels/0.1")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return redact(err, url)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, Clean(string(msg), 200))
	}
	return nil
}

// redact keeps tokens embedded in webhook URLs out of error logs.
func redact(err error, url string) error {
	return fmt.Errorf("%s", strings.ReplaceAll(err.Error(), url, "<url>"))
}

// Telegram sends plain text (no parse_mode) so attacker text cannot inject
// formatting or links.
type Telegram struct {
	Token   string
	ChatID  string
	Buttons bool   // feedback buttons on event alerts (needs the interactive bot)
	APIBase string // tests only; default https://api.telegram.org
}

func (t *Telegram) Name() string { return "telegram" }

func (t *Telegram) Send(ctx context.Context, m Message) error {
	base := t.APIBase
	if base == "" {
		base = "https://api.telegram.org"
	}
	text := Text(m)
	params := map[string]any{"chat_id": t.ChatID, "disable_web_page_preview": true}
	if t.Buttons && m.EventID > 0 {
		// The buttons replace the "sentinels feedback" hint; the bot in
		// internal/telegram handles these callback formats.
		text = strings.Replace(text, fmt.Sprintf("Evento #%d — falso positivo? sentinels feedback %d fp", m.EventID, m.EventID), fmt.Sprintf("Evento #%d", m.EventID), 1)
		id := strconv.FormatInt(m.EventID, 10)
		params["reply_markup"] = map[string]any{"inline_keyboard": [][]map[string]string{{
			{"text": "✅ Ataque real", "callback_data": "ok:" + id},
			{"text": "🔕 Falso positivo", "callback_data": "fp:" + id},
			{"text": "🤖 Explicar", "callback_data": "ex:" + id},
		}}}
	}
	params["text"] = Truncate(text, 4000)
	return postJSON(ctx, base+"/bot"+t.Token+"/sendMessage", params, nil)
}

// Slack uses an incoming webhook. &, < and > are escaped so text like
// <!channel> or <https://…|label> cannot ping people or forge links.
type Slack struct {
	WebhookURL string
}

func (s *Slack) Name() string { return "slack" }

var slackEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

func (s *Slack) Send(ctx context.Context, m Message) error {
	return postJSON(ctx, s.WebhookURL, map[string]any{
		"text":         slackEscaper.Replace(Truncate(Text(m), 3500)),
		"unfurl_links": false,
		"unfurl_media": false,
	}, nil)
}

// Discord uses a channel webhook with every mention type disabled and link
// embeds suppressed.
type Discord struct {
	WebhookURL string
}

func (d *Discord) Name() string { return "discord" }

const discordSuppressEmbeds = 1 << 2

func (d *Discord) Send(ctx context.Context, m Message) error {
	return postJSON(ctx, d.WebhookURL, map[string]any{
		"content":          Truncate(Text(m), 1900),
		"allowed_mentions": map[string]any{"parse": []string{}},
		"flags":            discordSuppressEmbeds,
	}, nil)
}

// Webhook posts the structured message as JSON. With a secret, the body is
// signed: X-Sentinels-Signature = "sha256=" + HMAC-SHA256(secret, timestamp + "." + body).
type Webhook struct {
	URL    string
	Secret string
}

func (w *Webhook) Name() string { return "webhook" }

func (w *Webhook) Send(ctx context.Context, m Message) error {
	payload := struct {
		Message
		Text string `json:"text"`
	}{m, Text(m)}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	headers := map[string]string{}
	if w.Secret != "" {
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		headers["X-Sentinels-Timestamp"] = ts
		headers["X-Sentinels-Signature"] = "sha256=" + Sign(w.Secret, ts, body)
	}
	return postJSON(ctx, w.URL, json.RawMessage(body), headers)
}

// Sign computes the webhook signature; receivers should recompute it, compare
// in constant time and reject timestamps older than a few minutes.
func Sign(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
