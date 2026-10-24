package notify

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SantanaCharles/sentinels/internal/config"
	"github.com/SantanaCharles/sentinels/internal/finding"
	"github.com/SantanaCharles/sentinels/internal/watch"
)

// hostile simulates attacker-controlled text reaching an alert.
const hostile = "regra\r\nBcc: vitima@example.com\n@everyone <!channel> ‮olleh\x1b[31m"

func sample() Message {
	return FromAlert(watch.Alert{Severity: finding.Critical, Title: hostile, Target: "lab-php",
		Lines: []string{"linha 1", hostile}, EventID: 42}, "vps-01")
}

func TestCleanRemovesControlAndBidi(t *testing.T) {
	c := Clean(hostile, 500)
	for _, bad := range []string{"\r", "\n", "‮", "\x1b"} {
		if strings.Contains(c, bad) {
			t.Errorf("Clean manteve %q: %q", bad, c)
		}
	}
	if got := Clean(strings.Repeat("é", 100), 11); len(got) > 11 || !strings.HasSuffix(got, "…") {
		t.Errorf("truncamento: %q (%d bytes)", got, len(got))
	}
	m := sample()
	if !strings.Contains(Text(m), "sentinels feedback 42 fp") {
		t.Errorf("texto sem instrução de feedback: %s", Text(m))
	}
}

func capture(t *testing.T) (*httptest.Server, func() (string, map[string]any, http.Header)) {
	t.Helper()
	var mu sync.Mutex
	var path string
	var body map[string]any
	var hdr http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		path, hdr = r.URL.Path, r.Header.Clone()
		body = map[string]any{}
		json.Unmarshal(b, &body)
		body["_raw"] = string(b)
		mu.Unlock()
	}))
	t.Cleanup(srv.Close)
	return srv, func() (string, map[string]any, http.Header) {
		mu.Lock()
		defer mu.Unlock()
		return path, body, hdr
	}
}

func TestTelegram(t *testing.T) {
	srv, got := capture(t)
	if err := (&Telegram{Token: "123:abc", ChatID: "-100", APIBase: srv.URL}).Send(context.Background(), sample()); err != nil {
		t.Fatal(err)
	}
	path, body, _ := got()
	if path != "/bot123:abc/sendMessage" || body["chat_id"] != "-100" {
		t.Errorf("requisição: %s %v", path, body)
	}
	if _, ok := body["parse_mode"]; ok {
		t.Error("parse_mode definido: texto do atacante seria interpretado como formatação")
	}
	if body["disable_web_page_preview"] != true {
		t.Error("prévia de links habilitada")
	}
}

func TestTelegramErrorHidesToken(t *testing.T) {
	err := (&Telegram{Token: "SEGREDO", ChatID: "1", APIBase: "http://127.0.0.1:1"}).Send(context.Background(), sample())
	if err == nil || strings.Contains(err.Error(), "SEGREDO") {
		t.Errorf("erro expõe o token: %v", err)
	}
}

func TestSlackEscapesMentions(t *testing.T) {
	srv, got := capture(t)
	if err := (&Slack{WebhookURL: srv.URL}).Send(context.Background(), sample()); err != nil {
		t.Fatal(err)
	}
	_, body, _ := got()
	text := body["text"].(string)
	if strings.Contains(text, "<!channel>") || !strings.Contains(text, "&lt;!channel&gt;") {
		t.Errorf("menção do Slack não escapada: %q", text)
	}
}

func TestDiscordDisablesMentions(t *testing.T) {
	srv, got := capture(t)
	if err := (&Discord{WebhookURL: srv.URL}).Send(context.Background(), sample()); err != nil {
		t.Fatal(err)
	}
	_, body, _ := got()
	am, _ := body["allowed_mentions"].(map[string]any)
	if parse, ok := am["parse"].([]any); !ok || len(parse) != 0 {
		t.Errorf("allowed_mentions: %v", body["allowed_mentions"])
	}
	if body["flags"] != float64(discordSuppressEmbeds) {
		t.Errorf("embeds não suprimidos: %v", body["flags"])
	}
	if len(body["content"].(string)) > 2000 {
		t.Error("conteúdo acima do limite do Discord")
	}
}

func TestWebhookSignature(t *testing.T) {
	srv, got := capture(t)
	if err := (&Webhook{URL: srv.URL, Secret: "s3"}).Send(context.Background(), sample()); err != nil {
		t.Fatal(err)
	}
	_, body, hdr := got()
	want := "sha256=" + Sign("s3", hdr.Get("X-Sentinels-Timestamp"), []byte(body["_raw"].(string)))
	if hdr.Get("X-Sentinels-Signature") != want {
		t.Errorf("assinatura %q, quer %q", hdr.Get("X-Sentinels-Signature"), want)
	}
	if body["event_id"] != float64(42) || body["severity"] != "critical" {
		t.Errorf("payload: %v", body)
	}
}

// fakeSMTP accepts one message on loopback (no TLS, no auth) and returns it.
func fakeSMTP(t *testing.T) (string, <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	out := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		w := func(s string) { io.WriteString(c, s+"\r\n") }
		w("220 fake")
		var data strings.Builder
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if inData {
				if line == ".\r\n" {
					inData = false
					out <- data.String()
					w("250 ok")
					continue
				}
				data.WriteString(line)
				continue
			}
			switch cmd := strings.ToUpper(strings.TrimSpace(line)); {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				w("250 fake")
			case cmd == "DATA":
				inData = true
				w("354 go")
			case cmd == "QUIT":
				w("221 bye")
				return
			default:
				w("250 ok")
			}
		}
	}()
	return ln.Addr().String(), out
}

func TestEmailHeadersCannotBeInjected(t *testing.T) {
	addr, got := fakeSMTP(t)
	e := &Email{Host: addr, From: "Sentinels <sentinels@example.com>", To: []string{"admin@example.com"}}
	if err := e.Send(context.Background(), sample()); err != nil {
		t.Fatal(err)
	}
	var msg string
	select {
	case msg = <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("e-mail não recebido")
	}
	headers, _, _ := strings.Cut(msg, "\r\n\r\n")
	for _, line := range strings.Split(headers, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "bcc:") {
			t.Fatalf("cabeçalho injetado: %q", line)
		}
	}
	if !strings.Contains(headers, "Subject: =?utf-8?q?") {
		t.Errorf("assunto não codificado: %s", headers)
	}
}

func TestLimiter(t *testing.T) {
	l := newLimiter()
	now := time.Now()
	ok := 0
	for i := 0; i < 15; i++ {
		if l.allow(finding.High, now) {
			ok++
		}
	}
	if ok != 10 {
		t.Errorf("rajada permitida = %d, quer 10", ok)
	}
	if !l.allow(finding.Critical, now) {
		t.Error("alerta crítico bloqueado pela cota dos outros")
	}
	if !l.allow(finding.High, now.Add(61*time.Second)) {
		t.Error("cota não repôs após 1 minuto")
	}
}

type slowNotifier struct{ calls atomic.Int32 }

func (s *slowNotifier) Name() string { return "lento" }
func (s *slowNotifier) Send(ctx context.Context, _ Message) error {
	s.calls.Add(1)
	select {
	case <-time.After(2 * time.Second):
	case <-ctx.Done():
	}
	return nil
}

type recNotifier struct {
	mu   sync.Mutex
	msgs []Message
}

func (r *recNotifier) Name() string { return "rec" }
func (r *recNotifier) Send(_ context.Context, m Message) error {
	r.mu.Lock()
	r.msgs = append(r.msgs, m)
	r.mu.Unlock()
	return nil
}

func TestFanoutRoutingAndIsolation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	slow, rec := &slowNotifier{}, &recNotifier{}
	f := NewFanout(ctx, "vps", []Channel{
		{Notifier: slow, MinSeverity: finding.Low},
		{Notifier: rec, MinSeverity: finding.Critical},
	}, nil)

	start := time.Now()
	f.Alert(ctx, watch.Alert{Severity: finding.High, Title: "alto"})
	f.Alert(ctx, watch.Alert{Severity: finding.Critical, Title: "crítico"})
	if time.Since(start) > 100*time.Millisecond {
		t.Error("Alert bloqueou esperando um canal lento")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		rec.mu.Lock()
		n := len(rec.msgs)
		rec.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	f.Wait()
	if len(rec.msgs) != 1 || rec.msgs[0].Title != "crítico" {
		t.Errorf("canal crítico recebeu: %+v", rec.msgs)
	}
	if slow.calls.Load() == 0 {
		t.Error("canal lento não recebeu nada")
	}
}

func TestBuildValidates(t *testing.T) {
	os.Setenv("SENT_TEST_TG", "tok")
	defer os.Unsetenv("SENT_TEST_TG")
	cases := []struct {
		n       config.Notifier
		wantErr string
	}{
		{config.Notifier{Type: "telegram", TokenEnv: "SENT_TEST_TG", ChatID: "1"}, ""},
		{config.Notifier{Type: "telegram", TokenEnv: "SENT_TEST_VAZIA", ChatID: "1"}, "vazia"},
		{config.Notifier{Type: "telegram", TokenEnv: "SENT_TEST_TG"}, "chat_id"},
		{config.Notifier{Type: "pombo"}, "tipo desconhecido"},
		{config.Notifier{Type: "email", SMTPHost: "smtp:587"}, "obrigatórios"},
		{config.Notifier{Type: "telegram", TokenEnv: "SENT_TEST_TG", ChatID: "1", MinSeverity: "urgente"}, "severidade"},
	}
	for _, c := range cases {
		_, err := Build(config.Alerts{MinSeverity: "high", Notifiers: []config.Notifier{c.n}})
		switch {
		case c.wantErr == "" && err != nil:
			t.Errorf("%+v: erro inesperado %v", c.n, err)
		case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
			t.Errorf("%+v: erro %v, quer %q", c.n, err, c.wantErr)
		}
	}
	os.Setenv("SENT_TEST_WH", "http://exemplo.com/hook")
	defer os.Unsetenv("SENT_TEST_WH")
	if _, err := Build(config.Alerts{MinSeverity: "high", Notifiers: []config.Notifier{{Type: "webhook", URLEnv: "SENT_TEST_WH"}}}); err == nil {
		t.Error("webhook http público aceito")
	}
}

func TestTelegramButtonsOnEventAlerts(t *testing.T) {
	srv, got := capture(t)
	tg := &Telegram{Token: "1:x", ChatID: "-100", APIBase: srv.URL, Buttons: true}
	if err := tg.Send(context.Background(), sample()); err != nil {
		t.Fatal(err)
	}
	_, body, _ := got()
	kb, ok := body["reply_markup"].(map[string]any)
	if !ok || !strings.Contains(body["_raw"].(string), `"callback_data":"fp:42"`) {
		t.Fatalf("botões ausentes: %v", body["reply_markup"])
	}
	_ = kb
	if strings.Contains(body["text"].(string), "sentinels feedback") {
		t.Error("dica de linha de comando deveria sair quando há botões")
	}
	// Without the interactive bot, no buttons (nobody would answer them).
	tg.Buttons = false
	tg.Send(context.Background(), sample())
	if _, body, _ = got(); body["reply_markup"] != nil {
		t.Error("botões enviados sem conversa ativa")
	}
}
