package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSaveRoundTripAndBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sentinels.yaml")
	cfg := Default()
	cfg.AI.Enabled, cfg.AI.Provider, cfg.AI.Model = true, "anthropic", "claude-sonnet-5-5"
	cfg.AI.ReportSummary = false // default true: must survive a save as false
	cfg.Scan.URLs = []string{"https://exemplo.com.br"}
	cfg.Alerts.Notifiers = []Notifier{{Type: "telegram", TokenEnv: "SENTINELS_TELEGRAM_TOKEN", ChatID: "-100123"}}
	if err := Save(cfg, path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.AI.Model != "claude-sonnet-5-5" || got.AI.ReportSummary || len(got.Scan.URLs) != 1 || got.Alerts.Notifiers[0].ChatID != "-100123" {
		t.Errorf("ida e volta perdeu dados: %+v", got.AI)
	}
	b, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(b), "# Sentinels") || strings.Contains(string(b), "url_env") {
		t.Errorf("arquivo sem cabeçalho ou com campos vazios:\n%s", b)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(path); st.Mode().Perm() != 0o640 {
			t.Errorf("permissão %v", st.Mode().Perm())
		}
	}
	cfg.Scan.Interval = "12h"
	Save(cfg, path)
	if bak, err := os.ReadFile(path + ".bak"); err != nil || !strings.Contains(string(bak), "interval: 6h") {
		t.Error("backup da versão anterior não criado")
	}
}

func TestValidateRejectsBadValues(t *testing.T) {
	for _, mut := range []func(*Config){
		func(c *Config) { c.Scan.Interval = "toda hora" },
		func(c *Config) { c.Alerts.MinSeverity = "urgente" },
		func(c *Config) { c.AI.MinSeverity = "max" },
	} {
		c := Default()
		mut(&c)
		if err := Save(c, filepath.Join(t.TempDir(), "x.yaml")); err == nil {
			t.Errorf("valor inválido aceito: %+v", c.Scan.Interval)
		}
	}
}

func TestEnvFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sentinels.env")
	os.WriteFile(path, []byte("# segredos\nSENTINELS_AI_KEY=\"antiga\"\n\nexport OUTRA=x\n"), 0o600)
	f, err := LoadEnvFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if f.Get("SENTINELS_AI_KEY") != "antiga" || f.Get("OUTRA") != "x" {
		t.Errorf("leitura: %q %q", f.Get("SENTINELS_AI_KEY"), f.Get("OUTRA"))
	}
	f.Set("SENTINELS_AI_KEY", "nova")
	f.Set("SENTINELS_TELEGRAM_TOKEN", "123:abc")
	if err := f.Set("SENTINELS_X", "a\nB=injetado"); err == nil {
		t.Error("valor com quebra de linha aceito (injetaria outra variável)")
	}
	if err := f.Set("minúscula", "x"); err == nil {
		t.Error("nome inválido aceito")
	}
	if err := f.Save(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	want := "# segredos\nSENTINELS_AI_KEY=nova\n\nexport OUTRA=x\nSENTINELS_TELEGRAM_TOKEN=123:abc\n"
	if string(b) != want {
		t.Errorf("arquivo:\n%q\nquer:\n%q", b, want)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
			t.Errorf("permissão %v", st.Mode().Perm())
		}
	}
	missing, err := LoadEnvFile(filepath.Join(t.TempDir(), "nao-existe.env"))
	if err != nil || missing.Get("X") != "" {
		t.Error("arquivo ausente deveria ser vazio")
	}
}
