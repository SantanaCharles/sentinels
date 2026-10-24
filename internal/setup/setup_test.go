package setup

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SantanaCharles/sentinels/internal/config"
)

// session runs the wizard in plain mode with scripted answers, one per line.
func session(t *testing.T, answers ...string) (*Session, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "sentinels.yaml"), "")
	if err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	s.Accessible, s.Out, s.In = true, out, strings.NewReader(strings.Join(answers, "\n")+"\n")
	return s, out
}

func reload(t *testing.T, s *Session) (config.Config, *config.EnvFile) {
	t.Helper()
	cfg, err := config.Load(s.ConfigPath, false)
	if err != nil {
		t.Fatal(err)
	}
	env, _ := config.LoadEnvFile(s.EnvPath)
	return cfg, env
}

func TestScanSection(t *testing.T) {
	s, _ := session(t, "2", "1", "3", "https://exemplo.com.br", "", "30", "y")
	if err := s.Run(context.Background(), "scan"); err != nil {
		t.Fatal(err)
	}
	cfg, _ := reload(t, s)
	if cfg.Scan.Interval != "3h" || cfg.Alerts.MinSeverity != "critical" || cfg.Alerts.DedupWindow != "30m" ||
		len(cfg.Scan.URLs) != 1 || cfg.Storage.RetentionDays != 30 {
		t.Errorf("config: %+v %+v %+v", cfg.Scan, cfg.Alerts, cfg.Storage)
	}
}

func TestAISectionWithLocalServer(t *testing.T) {
	var asked bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			w.Write([]byte(`{"data":[{"id":"qwen-segurança-7b"},{"id":"llama-x"}]}`))
		case "/v1/chat/completions":
			asked = true
			w.Write([]byte(`{"choices":[{"message":{"content":"OK"}}]}`))
		}
	}))
	defer srv.Close()
	// provider 6 = LM Studio; base URL; model 2 of the list (sorted: llama-x, qwen…);
	// severity 2 (high); 15 calls/hour; summary yes; keep IPs no; test yes; save yes.
	s, out := session(t, "6", srv.URL+"/v1", "2", "2", "15", "y", "n", "y", "y")
	if err := s.Run(context.Background(), "ai"); err != nil {
		t.Fatal(err)
	}
	cfg, _ := reload(t, s)
	a := cfg.AI
	if !a.Enabled || a.Provider != "lmstudio" || a.Model != "qwen-segurança-7b" || a.MinSeverity != "high" || a.MaxCallsHour != 15 || a.KeepIPs {
		t.Errorf("ai: %+v", a)
	}
	if !asked || !strings.Contains(out.String(), "✔ lmstudio/qwen-segurança-7b respondeu") {
		t.Errorf("teste da IA não executado:\n%s", out.String())
	}
}

func TestWebhookChannelKeepsSecretsOutOfYAML(t *testing.T) {
	// add: type 5 (webhook); URL; default severity; no test; save.
	s, _ := session(t, "5", "https://n8n.exemplo.com/webhook/abc-SEGREDO", "1", "n", "y")
	if err := s.addNotifier(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.save(); err != nil {
		t.Fatal(err)
	}
	cfg, env := reload(t, s)
	n := cfg.Alerts.Notifiers
	if len(n) != 1 || n[0].Type != "webhook" || n[0].URLEnv != "SENTINELS_WEBHOOK_URL" || n[0].SecretEnv == "" {
		t.Fatalf("canal: %+v", n)
	}
	yaml, _ := os.ReadFile(s.ConfigPath)
	if strings.Contains(string(yaml), "SEGREDO") {
		t.Error("URL secreta foi parar no YAML")
	}
	if env.Get("SENTINELS_WEBHOOK_URL") != "https://n8n.exemplo.com/webhook/abc-SEGREDO" || len(env.Get(n[0].SecretEnv)) != 64 {
		t.Errorf("segredos no env: %q", env.Get("SENTINELS_WEBHOOK_URL"))
	}
}

func TestInvalidAnswerIsAskedAgain(t *testing.T) {
	// Slack with a wrong URL first, then the right one.
	s, out := session(t, "2", "https://exemplo.com/nao-e-slack", "https://hooks.slack.com/services/T/B/x", "1", "n")
	if err := s.addNotifier(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "deve começar com https://hooks.slack.com/") {
		t.Errorf("validação não exibida:\n%s", out.String())
	}
	if s.Env.Get("SENTINELS_SLACK_WEBHOOK") != "https://hooks.slack.com/services/T/B/x" {
		t.Error("valor válido não gravado")
	}
}

func TestFreeEnvNameAndSuggestion(t *testing.T) {
	used := map[string]bool{"SENTINELS_TELEGRAM_TOKEN": true, "SENTINELS_TELEGRAM_TOKEN_2": true}
	if got := freeEnvName(used, "SENTINELS_TELEGRAM_TOKEN"); got != "SENTINELS_TELEGRAM_TOKEN_3" {
		t.Errorf("nome livre = %s", got)
	}
	if got := suggestedModel("anthropic", []string{"claude-haiku-5-5", "claude-sonnet-4-5", "claude-sonnet-5-5"}); got != "claude-sonnet-5-5" {
		t.Errorf("sugestão = %s", got)
	}
	if got := suggestedModel("lmstudio", []string{"a", "b"}); got != "a" {
		t.Errorf("sugestão sem preferência = %s", got)
	}
}

func TestPortugueseSectionAliasStillWorks(t *testing.T) {
	s, _ := session(t, "2", "1", "3", "", "", "30", "y")
	if err := s.Run(context.Background(), "varredura"); err != nil {
		t.Fatalf("alias em português quebrou: %v", err)
	}
	if err := s.Run(context.Background(), "inexistente"); err == nil || !strings.Contains(err.Error(), "quick") {
		t.Errorf("seção desconhecida deveria listar os nomes em inglês: %v", err)
	}
}
