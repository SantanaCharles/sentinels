package telegram

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SantanaCharles/sentinels/internal/ai"
	"github.com/SantanaCharles/sentinels/internal/event"
	"github.com/SantanaCharles/sentinels/internal/finding"
	"github.com/SantanaCharles/sentinels/internal/fingerprint"
	"github.com/SantanaCharles/sentinels/internal/integrations"
	"github.com/SantanaCharles/sentinels/internal/scan"
	"github.com/SantanaCharles/sentinels/internal/store"
	"github.com/SantanaCharles/sentinels/internal/watch"
)

// fakeAPI is a minimal Telegram Bot API: it serves queued updates once and
// records every other call.
type fakeAPI struct {
	mu      sync.Mutex
	backlog []map[string]any
	queue   []map[string]any
	calls   []call
}

type call struct {
	method string
	params map[string]any
}

func (f *fakeAPI) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/botTOKEN/") {
			w.Write([]byte(`{"ok":false,"error_code":401,"description":"Unauthorized"}`))
			return
		}
		method := strings.TrimPrefix(r.URL.Path, "/botTOKEN/")
		body, _ := io.ReadAll(r.Body)
		var p map[string]any
		json.Unmarshal(body, &p)
		f.mu.Lock()
		var result any = true
		if method == "getUpdates" {
			if p["offset"] == float64(-1) {
				result = f.backlog
			} else {
				result = f.queue
				f.queue = nil
			}
		} else {
			f.calls = append(f.calls, call{method, p})
			if method == "sendMessage" {
				result = map[string]any{"message_id": 1}
			}
		}
		f.mu.Unlock()
		if method == "getUpdates" && result == nil {
			time.Sleep(30 * time.Millisecond) // long poll with nothing new
		}
		out, _ := json.Marshal(map[string]any{"ok": true, "result": result})
		w.Write(out)
	}
}

func (f *fakeAPI) sent(chatID float64) []call {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []call
	for _, c := range f.calls {
		if c.method == "sendMessage" && c.params["chat_id"] == chatID {
			out = append(out, c)
		}
	}
	return out
}

func (f *fakeAPI) count(method string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c.method == method {
			n++
		}
	}
	return n
}

func msg(id int, chatID int64, text string) map[string]any {
	return map[string]any{"update_id": id, "message": map[string]any{
		"message_id": id, "chat": map[string]any{"id": chatID}, "from": map[string]any{"id": 7, "username": "charles"}, "text": text}}
}

func callback(id int, chatID int64, data string) map[string]any {
	return map[string]any{"update_id": id, "callback_query": map[string]any{
		"id": "cb" + string(rune('0'+id%10)), "from": map[string]any{"id": 7, "username": "charles"}, "data": data,
		"message": map[string]any{"message_id": 50, "chat": map[string]any{"id": chatID}}}}
}

type fakeProvider struct {
	mu   sync.Mutex
	reqs []ai.Request
}

func (p *fakeProvider) Name() string { return "fake" }
func (p *fakeProvider) Complete(_ context.Context, r ai.Request) (string, error) {
	p.mu.Lock()
	p.reqs = append(p.reqs, r)
	p.mu.Unlock()
	return "**Resumo:** um ataque ao lab-php foi detectado.\n### Faça agora\n1. Atualize o PHP.", nil
}

func setup(t *testing.T) (*Bot, *fakeAPI, *store.Store, *fakeProvider) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	st.Record(context.Background(), event.Event{Source: "suricata", Rule: "regra web", Severity: finding.Critical,
		Time: time.Now(), SourceIP: "203.0.113.7", Target: "lab-php", Technique: "T1190",
		Summary: "ataque com token=segredo123abc"}, time.Minute, false)
	res := scan.Result{Host: "vps-01", Started: time.Now().Add(-2 * time.Hour),
		Assets:   []scan.Asset{{Name: "lab-php"}},
		Findings: []finding.Finding{{ID: "advisory.php2shell-2026-10", Target: "lab-php", Severity: finding.Critical, Title: "PHP2Shell"}}}
	b, _ := json.Marshal(res)
	os.WriteFile(filepath.Join(dir, "report-20261024-010000.json"), b, 0o640)

	api := &fakeAPI{}
	srv := httptest.NewServer(api.handler(t))
	t.Cleanup(srv.Close)
	fp := &fakeProvider{}
	bot := &Bot{Token: "TOKEN", AllowedChats: map[string]bool{"555": true}, APIBase: srv.URL, Store: st,
		ReportDir: dir, Host: "vps-01", Analyst: &ai.Analyst{Provider: fp}, MaxAIPerHour: 5}
	return bot, api, st, fp
}

func runUntil(t *testing.T, bot *Bot, done func() bool) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	go bot.Run(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for !done() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	time.Sleep(50 * time.Millisecond)
}

func TestBotCommandsAndAuthorization(t *testing.T) {
	bot, api, st, _ := setup(t)
	api.backlog = []map[string]any{msg(100, 555, "/status antigo")}
	api.queue = []map[string]any{
		msg(101, 999, "/status"), // stranger
		msg(102, 555, "/status"),
		msg(103, 555, "/event 1"),
		callback(104, 999, "fp:1"), // stranger pressing a forwarded button
		callback(105, 555, "fp:1"),
	}
	runUntil(t, bot, func() bool { return len(api.sent(555)) >= 3 })

	if n := len(api.sent(999)); n != 0 {
		t.Errorf("respondeu a chat não autorizado (%d mensagens)", n)
	}
	got := api.sent(555)
	if len(got) != 3 {
		t.Fatalf("mensagens para o chat autorizado: %d (backlog respondido?) %+v", len(got), got)
	}
	status := got[0].params["text"].(string)
	if !strings.Contains(status, "Sentinels — vps-01") || !strings.Contains(status, "PHP2Shell") || !strings.Contains(status, "1 críticos") {
		t.Errorf("/status:\n%s", status)
	}
	ev := got[1]
	if !strings.Contains(ev.params["text"].(string), "Evento #1") || strings.Contains(ev.params["text"].(string), "segredo123abc") {
		t.Errorf("/evento (segredo deveria estar mascarado):\n%s", ev.params["text"])
	}
	if ev.params["reply_markup"] == nil {
		t.Error("/evento sem botões")
	}
	if !strings.Contains(got[2].params["text"].(string), "falso positivo por @charles") {
		t.Errorf("confirmação do botão: %s", got[2].params["text"])
	}
	se, _ := st.Event(context.Background(), 1)
	if se.Verdict != store.VerdictFalsePositive {
		t.Errorf("feedback não gravado: %q", se.Verdict)
	}
	if api.count("editMessageReplyMarkup") != 1 || api.count("setMyCommands") != 1 || api.count("answerCallbackQuery") != 2 {
		t.Errorf("chamadas: edit=%d setMyCommands=%d answers=%d", api.count("editMessageReplyMarkup"), api.count("setMyCommands"), api.count("answerCallbackQuery"))
	}
}

func TestBotFreeQuestionUsesAI(t *testing.T) {
	bot, api, _, fp := setup(t)
	api.queue = []map[string]any{msg(10, 555, "o que aconteceu hoje no servidor?")}
	runUntil(t, bot, func() bool { return len(api.sent(555)) >= 2 })
	got := api.sent(555)
	if len(got) != 2 {
		t.Fatalf("respostas: %d (quer confirmação + resposta)", len(got))
	}
	if !strings.Contains(got[0].params["text"].(string), "Analisando sua pergunta") {
		t.Errorf("confirmação imediata ausente: %s", got[0].params["text"])
	}
	text := got[1].params["text"].(string)
	if strings.Contains(text, "**") || strings.Contains(text, "###") || !strings.Contains(text, "Atualize o PHP") {
		t.Errorf("resposta deveria vir em texto simples:\n%s", text)
	}
	if _, ok := got[1].params["parse_mode"]; ok {
		t.Error("parse_mode definido: texto de log poderia virar formatação")
	}
	r := fp.reqs[0]
	if !strings.Contains(r.User, "o que aconteceu hoje") || !strings.Contains(r.User, "<dados>") || !strings.Contains(r.User, "PHP2Shell") {
		t.Errorf("pergunta/contexto não enviados corretamente:\n%s", r.User)
	}
	if strings.Contains(r.User, "203.0.113.7") || strings.Contains(r.User, "segredo123abc") {
		t.Error("IP ou segredo enviado à IA sem redação")
	}
}

func TestBotAIBudget(t *testing.T) {
	bot, _, _, _ := setup(t)
	bot.MaxAIPerHour = 2
	if !bot.takeAI() || !bot.takeAI() || bot.takeAI() {
		t.Error("limite por hora não respeitado")
	}
}

func TestSplitLongReply(t *testing.T) {
	long := strings.Repeat("linha de teste com algum texto\n", 400)
	parts := split(reply{text: long, buttons: FeedbackButtons(1, true)})
	if len(parts) < 2 {
		t.Fatalf("partes: %d", len(parts))
	}
	for i, p := range parts {
		if len(p.text) > 4096 {
			t.Errorf("parte %d com %d bytes", i, len(p.text))
		}
		if (p.buttons != nil) != (i == len(parts)-1) {
			t.Errorf("botões fora da última parte (parte %d)", i)
		}
	}
}

type fakeScanner struct {
	mu       sync.Mutex
	running  bool
	requests int
}

func (f *fakeScanner) RequestScan() watch.ScanRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests++
	if f.running {
		return watch.ScanRunning
	}
	f.running = true
	return watch.ScanStarted
}

func (f *fakeScanner) Scanning() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.running
}

func TestVarrerAcksAndReportsWhenDone(t *testing.T) {
	bot, api, _, _ := setup(t)
	sc := &fakeScanner{}
	bot.Scanner = sc
	api.queue = []map[string]any{msg(20, 555, "/scan"), msg(21, 555, "/varrer")}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go bot.Run(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for len(api.sent(555)) < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	got := api.sent(555)
	if len(got) != 2 || !strings.Contains(got[0].params["text"].(string), "Em poucos minutos te mando o status") ||
		!strings.Contains(got[1].params["text"].(string), "Já tem uma varredura em andamento") {
		t.Fatalf("confirmações: %+v", got)
	}

	// The watcher finishes the scan: the chat gets the status once.
	bot.ScanDone(&scan.Result{})
	bot.ScanDone(&scan.Result{})
	for len(api.sent(555)) < 3 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	got = api.sent(555)
	if len(got) != 3 || !strings.Contains(got[2].params["text"].(string), "✅ Varredura concluída") ||
		!strings.Contains(got[2].params["text"].(string), "Sentinels — vps-01") {
		t.Errorf("status pós-varredura (uma vez só): %d mensagens; última: %v", len(got), got[len(got)-1].params["text"])
	}
}

func TestStatusDuringFirstScanPromisesReport(t *testing.T) {
	bot, api, _, _ := setup(t)
	os.Remove(filepath.Join(bot.ReportDir, "report-20261024-010000.json")) // no scan finished yet
	bot.Scanner = &fakeScanner{running: true}
	api.queue = []map[string]any{msg(30, 555, "/status")}
	runUntil(t, bot, func() bool { return len(api.sent(555)) >= 1 })
	if got := api.sent(555); len(got) != 1 || !strings.Contains(got[0].params["text"].(string), "Mando o status assim que terminar") {
		t.Fatalf("resposta: %+v", got)
	}
}

func TestWebhookConflictIsExplained(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":false,"error_code":409,"description":"Conflict: can't use getUpdates method while webhook is active; use deleteWebhook to delete the webhook first"}`))
	}))
	defer srv.Close()
	b := &Bot{Token: "TOKEN", APIBase: srv.URL, client: srv.Client()}
	_, err := b.getUpdates(context.Background(), 0)
	if err == nil || !strings.Contains(err.Error(), "webhook ativo") || !strings.Contains(err.Error(), "n8n") {
		t.Errorf("erro de webhook não explicado: %v", err)
	}
}

func TestInventory(t *testing.T) {
	bot, _, _, _ := setup(t)
	res := scan.Result{Host: "vps-01", Started: time.Now(),
		Assets: []scan.Asset{
			{Name: "loja", Image: "php:8.3.10-apache", Stack: fingerprint.Stack{Kind: fingerprint.KindApp, Components: []string{"PHP"}}, PublicPorts: []string{"8080→80/tcp"}},
			{Name: "n8n", Image: "n8nio/n8n:1.90", Stack: fingerprint.Stack{Kind: fingerprint.KindAutomation, Components: []string{"n8n"}}},
		},
		Findings: []finding.Finding{
			{ID: "advisory.php2shell-2026-10", Target: "loja", Severity: finding.Critical, Title: "PHP2Shell"},
			{ID: "cve.CVE-1", Target: "loja, n8n", Severity: finding.High, Title: "CVE-1"},
			{ID: "host.public_listener", Target: "host:5432", Severity: finding.High, Title: "PostgreSQL escutando em 0.0.0.0:5432"},
		}}
	b, _ := json.Marshal(res)
	os.WriteFile(filepath.Join(bot.ReportDir, "report-20261024-020000.json"), b, 0o640)

	all := bot.inventory(nil).text
	for _, want := range []string{"2 container(s)", "🐳 loja", "php:8.3.10-apache", "PHP (app)", "8080→80/tcp",
		"🔴 1 · 🟠 1", "🐳 n8n", "🔴 0 · 🟠 1", "PostgreSQL escutando em 0.0.0.0:5432", "pacotes instalados"} {
		if !strings.Contains(all, want) {
			t.Errorf("inventário sem %q:\n%s", want, all)
		}
	}
	php := bot.inventory([]string{"php"}).text
	if !strings.Contains(php, "1 com \"php\"") || strings.Contains(php, "🐳 n8n") {
		t.Errorf("filtro:\n%s", php)
	}
}

func TestDoctorShowsMissingWithInstallSteps(t *testing.T) {
	bot, _, _, _ := setup(t)
	bot.Health = func(context.Context) []Check {
		return []Check{
			{Name: "Docker", OK: true, Detail: "lendo containers via tcp://127.0.0.1:2375"},
			{Name: "CrowdSec", OK: false, Detail: "sem detecção", Fix: "curl -s https://install.crowdsec.net | sh\ncscli bouncers add sentinels"},
		}
	}
	text := bot.doctor(context.Background()).text
	for _, want := range []string{"✅ Docker", "❌ CrowdSec", "   cscli bouncers add sentinels", "Faltando (1)", "não instala nada"} {
		if !strings.Contains(text, want) {
			t.Errorf("/doctor sem %q:\n%s", want, text)
		}
	}
	bot.Health = func(context.Context) []Check { return []Check{{Name: "Docker", OK: true, Detail: "ok"}} }
	if text := bot.doctor(context.Background()).text; !strings.Contains(text, "Tudo ativo") {
		t.Errorf("tudo ok:\n%s", text)
	}
	bot.Health = nil
	if text := bot.doctor(context.Background()).text; !strings.Contains(text, "indisponível") {
		t.Errorf("sem Health: %s", text)
	}
}

func TestMetricsCommand(t *testing.T) {
	bot, _, _, _ := setup(t)
	out := bot.metrics(context.Background()).text
	for _, want := range []string{"📊 Métricas — vps-01", "Eventos: 1", "🔴 1", "203.0.113.7 — 1",
		"T1190 Exploit Public-Facing Application", "Falso positivo: — (0 falso"} {
		if !strings.Contains(out, want) {
			t.Errorf("/metrics sem %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "segredo123abc") {
		t.Error("vazou segredo")
	}
}

type fakeBlocklist struct {
	list []integrations.Blocked
	ok   bool
}

func (f fakeBlocklist) Blocked(time.Time) ([]integrations.Blocked, bool) { return f.list, f.ok }

func TestBlockedCommand(t *testing.T) {
	bot, _, _, _ := setup(t)
	if out := bot.blocked(context.Background(), nil).text; !strings.Contains(out, "não está ativo") {
		t.Errorf("sem CrowdSec: %s", out)
	}
	bot.Blocklist = fakeBlocklist{}
	if out := bot.blocked(context.Background(), nil).text; !strings.Contains(out, "Ainda lendo") {
		t.Errorf("antes da primeira leitura: %s", out)
	}
	now := time.Now()
	bot.Blocklist = fakeBlocklist{ok: true, list: []integrations.Blocked{
		{ID: 9, Value: "203.0.113.7", Scope: "Ip", Type: "ban", Scenario: "crowdsecurity/ssh-slow-bf", Origin: "crowdsec", Until: now.Add(3*time.Hour + 59*time.Minute + 30*time.Second)},
		{ID: 5, Value: "198.51.100.9", Scope: "Ip", Type: "ban", Scenario: "", Origin: "cscli", Until: now.Add(73 * time.Hour)},
		{ID: 3, Value: "192.0.2.0/24", Scope: "Range", Type: "captcha", Scenario: "crowdsecurity/http-probing", Origin: "crowdsec", Until: now.Add(10 * time.Minute)},
	}}
	out := bot.blocked(context.Background(), nil).text
	for _, want := range []string{"⛔ 3 bloqueio(s) ativo(s) — vps-01", "203.0.113.7 — ssh-slow-bf — mais 3h59m",
		"198.51.100.9 — manual — mais 3d · manual", "Range 192.0.2.0/24 — http-probing — mais 10m · captcha",
		"cscli decisions delete --ip"} {
		if !strings.Contains(out, want) {
			t.Errorf("/blocked sem %q:\n%s", want, out)
		}
	}
	ssh := bot.blocked(context.Background(), []string{"ssh"}).text
	if !strings.Contains(ssh, "⛔ 1 bloqueio") || strings.Contains(ssh, "198.51.100.9") {
		t.Errorf("filtro:\n%s", ssh)
	}
	if out := bot.blocked(context.Background(), []string{"10.9.9.9"}).text; !strings.Contains(out, "Nenhum bloqueio ativo") {
		t.Errorf("filtro sem resultado: %s", out)
	}
}
