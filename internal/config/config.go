// Package config loads sentinels.yaml. Secrets are never stored in the file:
// fields ending in _env name the environment variable that holds the value.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Docker       Docker       `yaml:"docker"`
	Scan         Scan         `yaml:"scan"`
	Storage      Storage      `yaml:"storage"`
	Databases    []Database   `yaml:"databases"`
	Integrations Integrations `yaml:"integrations"`
	Alerts       Alerts       `yaml:"alerts"`
	AI           AI           `yaml:"ai"`
	Vault        Vault        `yaml:"vault"`
	MCP          MCP          `yaml:"mcp"`
}

type Docker struct {
	Socket string `yaml:"socket"`
}

type Scan struct {
	Interval  string   `yaml:"interval"`
	ReportDir string   `yaml:"report_dir"`
	CacheDir  string   `yaml:"cache_dir"`
	URLs      []string `yaml:"urls"`    // public URLs to check besides published ports
	Offline   bool     `yaml:"offline"` // skip KEV/EPSS downloads
}

type Storage struct {
	Path          string `yaml:"path"`
	RetentionDays int    `yaml:"retention_days"`
}

type Database struct {
	Name    string `yaml:"name"`
	Driver  string `yaml:"driver"`
	DSNEnv  string `yaml:"dsn_env"`
	AppRole string `yaml:"app_role"`
}

type Toggle struct {
	Enabled   string `yaml:"enabled"` // auto | true | false
	URL       string `yaml:"url"`
	APIKeyEnv string `yaml:"api_key_env"`
	EveLog    string `yaml:"eve_log"`
	Listen    string `yaml:"listen"`
}

type Integrations struct {
	Trivy    Toggle `yaml:"trivy"`
	CrowdSec Toggle `yaml:"crowdsec"`
	Suricata Toggle `yaml:"suricata"`
	Falco    Toggle `yaml:"falco"`
}

type Alerts struct {
	MinSeverity string     `yaml:"min_severity"`
	DedupWindow string     `yaml:"dedup_window"`
	Notifiers   []Notifier `yaml:"notifiers"`
}

// Notifier is one alert channel. Which fields apply depends on Type:
// telegram (token_env, chat_id), slack/discord (webhook_env),
// email (smtp_host, user_env, password_env, from, to), webhook (url_env, secret_env).
type Notifier struct {
	Type        string   `yaml:"type"`
	Name        string   `yaml:"name"`         // optional label for logs
	MinSeverity string   `yaml:"min_severity"` // defaults to alerts.min_severity
	TokenEnv    string   `yaml:"token_env"`
	ChatID      string   `yaml:"chat_id"`
	WebhookEnv  string   `yaml:"webhook_env"`
	URLEnv      string   `yaml:"url_env"`
	SecretEnv   string   `yaml:"secret_env"`
	SMTPHost    string   `yaml:"smtp_host"` // host:port; 465 = implicit TLS, others use STARTTLS
	UserEnv     string   `yaml:"user_env"`
	PasswordEnv string   `yaml:"password_env"`
	From        string   `yaml:"from"`
	To          []string `yaml:"to"`
}

type AI struct {
	Enabled   bool   `yaml:"enabled"`
	Provider  string `yaml:"provider"` // anthropic | openai | gemini | openrouter | ollama | lmstudio | openai-compatible
	Model     string `yaml:"model"`
	APIKeyEnv string `yaml:"api_key_env"`
	BaseURL   string `yaml:"base_url"`
	// MinSeverity: alerts at or above it get an AI explanation as a follow-up message.
	MinSeverity    string `yaml:"min_severity"`
	MaxCallsHour   int    `yaml:"max_calls_per_hour"` // cost guard for alert explanations
	ReportSummary  bool   `yaml:"report_summary"`     // executive summary at the top of each report
	KeepIPs        bool   `yaml:"keep_ips"`           // send real IPs instead of pseudonyms (LGPD: off by default)
	SkillsDir      string `yaml:"skills_dir"`         // extra/override SKILL.md files
	TimeoutSeconds int    `yaml:"timeout_seconds"`
}

// MCP configures `sentinels mcp`, the read-only Model Context Protocol server.
type MCP struct {
	KeepIPs  bool   `yaml:"keep_ips"`  // send real IPs to the MCP client (default: pseudonyms)
	TokenEnv string `yaml:"token_env"` // bearer token for the HTTP transport (required there)
}

// Vault is an optional Obsidian-compatible folder the agent writes notes to.
type Vault struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
}

func Default() Config {
	return Config{
		Docker: Docker{Socket: dockerHostDefault()},
		Scan: Scan{
			Interval:  "6h",
			ReportDir: "/var/lib/sentinels/reports",
			CacheDir:  "/var/lib/sentinels/cache",
		},
		Storage: Storage{Path: "/var/lib/sentinels/sentinels.db", RetentionDays: 90},
		Integrations: Integrations{
			Trivy:    Toggle{Enabled: "auto"},
			CrowdSec: Toggle{Enabled: "auto", URL: "http://127.0.0.1:8080", APIKeyEnv: "SENTINELS_CROWDSEC_KEY"},
			Suricata: Toggle{Enabled: "auto", EveLog: "/var/log/suricata/eve.json"},
			Falco:    Toggle{Enabled: "auto", Listen: "127.0.0.1:2801"},
		},
		Alerts: Alerts{MinSeverity: "high", DedupWindow: "15m"},
		AI: AI{
			Provider: "anthropic", Model: "claude-sonnet-5-5", APIKeyEnv: "SENTINELS_AI_KEY",
			MinSeverity: "critical", MaxCallsHour: 20, ReportSummary: true,
			SkillsDir: "/etc/sentinels/skills", TimeoutSeconds: 60,
		},
		Vault: Vault{Path: "/var/lib/sentinels/vault"},
		MCP:   MCP{TokenEnv: "SENTINELS_MCP_TOKEN"},
	}
}

// dockerHostDefault honors DOCKER_HOST (e.g. tcp://127.0.0.1:2375 for a
// read-only socket proxy), the same variable the Docker CLI and Trivy use.
func dockerHostDefault() string {
	if h := os.Getenv("DOCKER_HOST"); h != "" {
		return h
	}
	return "/var/run/docker.sock"
}

// Load reads path over the defaults. A missing file is not an error when
// optional is true, so `sentinels scan` works with zero configuration.
func Load(path string, optional bool) (Config, error) {
	cfg := Default()
	b, err := os.ReadFile(path)
	if err != nil {
		if optional && os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("lendo %s: %w", path, err)
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("interpretando %s: %w", path, err)
	}
	if _, err := time.ParseDuration(cfg.Scan.Interval); err != nil {
		return cfg, fmt.Errorf("scan.interval inválido: %w", err)
	}
	if _, err := time.ParseDuration(cfg.Alerts.DedupWindow); err != nil {
		return cfg, fmt.Errorf("alerts.dedup_window inválido: %w", err)
	}
	return cfg, nil
}

// Duration parses a duration already validated by Load, with a fallback.
func Duration(v string, fallback time.Duration) time.Duration {
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		return d
	}
	return fallback
}

// Mode returns "true", "false" or "auto" for an integration toggle.
func (t Toggle) Mode() string {
	switch t.Enabled {
	case "true", "false":
		return t.Enabled
	}
	return "auto"
}

// Secret resolves an *_env field. Empty name or unset variable returns "".
func Secret(envName string) string {
	if envName == "" {
		return ""
	}
	return os.Getenv(envName)
}
