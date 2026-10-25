// Package config loads sentinels.yaml. Secrets are never stored in the file:
// fields ending in _env name the environment variable that holds the value.
package config

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Docker       Docker       `yaml:"docker,omitempty"`
	Scan         Scan         `yaml:"scan"`
	Storage      Storage      `yaml:"storage"`
	Databases    []Database   `yaml:"databases,omitempty"`
	Integrations Integrations `yaml:"integrations"`
	Alerts       Alerts       `yaml:"alerts"`
	AI           AI           `yaml:"ai"`
	Vault        Vault        `yaml:"vault"`
	MCP          MCP          `yaml:"mcp"`
}

type Docker struct {
	// Socket: Unix path or tcp://host:port. DOCKER_HOST, when set, always
	// wins: it is how Docker deployments point the agent at the read-only proxy.
	Socket string `yaml:"socket,omitempty"`
}

type Scan struct {
	Interval  string   `yaml:"interval"`
	ReportDir string   `yaml:"report_dir"`
	CacheDir  string   `yaml:"cache_dir"`
	URLs      []string `yaml:"urls,omitempty"`    // public URLs to check besides published ports
	Offline   bool     `yaml:"offline,omitempty"` // skip KEV/EPSS downloads
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
	URL       string `yaml:"url,omitempty"`
	APIKeyEnv string `yaml:"api_key_env,omitempty"`
	EveLog    string `yaml:"eve_log,omitempty"`
	Listen    string `yaml:"listen,omitempty"`
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
	Notifiers   []Notifier `yaml:"notifiers,omitempty"`
	// Heartbeat: "24h" sends a periodic "still alive" summary to every channel
	// (empty = off). HeartbeatURLEnv names a URL pinged every 5 minutes
	// (healthchecks.io, Uptime Kuma push): it alerts you if the pings stop.
	Heartbeat       string `yaml:"heartbeat,omitempty"`
	HeartbeatURLEnv string `yaml:"heartbeat_url_env,omitempty"`
}

// Notifier is one alert channel. Which fields apply depends on Type:
// telegram (token_env, chat_id), slack/discord (webhook_env),
// email (smtp_host, user_env, password_env, from, to), webhook (url_env, secret_env).
type Notifier struct {
	Type        string   `yaml:"type"`
	Name        string   `yaml:"name,omitempty"`         // optional label for logs
	MinSeverity string   `yaml:"min_severity,omitempty"` // defaults to alerts.min_severity
	TokenEnv    string   `yaml:"token_env,omitempty"`
	ChatID      string   `yaml:"chat_id,omitempty"`
	WebhookEnv  string   `yaml:"webhook_env,omitempty"`
	URLEnv      string   `yaml:"url_env,omitempty"`
	SecretEnv   string   `yaml:"secret_env,omitempty"`
	SMTPHost    string   `yaml:"smtp_host,omitempty"` // host:port; 465 = implicit TLS, others use STARTTLS
	UserEnv     string   `yaml:"user_env,omitempty"`
	PasswordEnv string   `yaml:"password_env,omitempty"`
	From        string   `yaml:"from,omitempty"`
	To          []string `yaml:"to,omitempty"`
	// Interactive (telegram): the agent answers commands, questions and alert
	// buttons in this chat. Only this chat_id is obeyed.
	Interactive bool `yaml:"interactive,omitempty"`
}

type AI struct {
	Enabled   bool   `yaml:"enabled"`
	Provider  string `yaml:"provider"` // anthropic | openai | gemini | openrouter | ollama | lmstudio | openai-compatible
	Model     string `yaml:"model"`
	APIKeyEnv string `yaml:"api_key_env"`
	BaseURL   string `yaml:"base_url,omitempty"`
	// MinSeverity: alerts at or above it get an AI explanation as a follow-up message.
	MinSeverity    string `yaml:"min_severity"`
	MaxCallsHour   int    `yaml:"max_calls_per_hour"` // cost guard for alert explanations
	ReportSummary  bool   `yaml:"report_summary"`     // executive summary at the top of each report
	KeepIPs        bool   `yaml:"keep_ips,omitempty"` // send real IPs instead of pseudonyms (LGPD: off by default)
	SkillsDir      string `yaml:"skills_dir"`         // extra/override SKILL.md files
	TimeoutSeconds int    `yaml:"timeout_seconds"`
}

// MCP configures `sentinels mcp`, the read-only Model Context Protocol server.
type MCP struct {
	KeepIPs  bool   `yaml:"keep_ips,omitempty"` // send real IPs to the MCP client (default: pseudonyms)
	TokenEnv string `yaml:"token_env"`          // bearer token for the HTTP transport (required there)
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
func dockerHostDefault() string { return resolveSocket("") }

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
	cfg.Docker.Socket = resolveSocket(cfg.Docker.Socket)
	return cfg, cfg.Validate()
}

const defaultSocket = "/var/run/docker.sock"

// resolveSocket applies DOCKER_HOST over the file. A file written by setup on
// another machine (or in a container without DOCKER_HOST) must not pull the
// agent away from the proxy its deployment configured.
func resolveSocket(fromFile string) string {
	if h := os.Getenv("DOCKER_HOST"); h != "" {
		return h
	}
	if fromFile == "" {
		return defaultSocket
	}
	return fromFile
}

// Validate checks values that would only fail later, at runtime.
func (c Config) Validate() error {
	if _, err := time.ParseDuration(c.Scan.Interval); err != nil {
		return fmt.Errorf("scan.interval inválido: %w", err)
	}
	if c.Alerts.Heartbeat != "" {
		if d, err := time.ParseDuration(c.Alerts.Heartbeat); err != nil || d < time.Hour {
			return fmt.Errorf("alerts.heartbeat inválido: %q (use ex.: 24h; mínimo 1h)", c.Alerts.Heartbeat)
		}
	}
	if _, err := time.ParseDuration(c.Alerts.DedupWindow); err != nil {
		return fmt.Errorf("alerts.dedup_window inválido: %w", err)
	}
	for _, s := range []struct{ name, v string }{
		{"alerts.min_severity", c.Alerts.MinSeverity}, {"ai.min_severity", c.AI.MinSeverity},
	} {
		switch s.v {
		case "", "info", "low", "medium", "high", "critical":
		default:
			return fmt.Errorf("%s inválido: %q (use info, low, medium, high ou critical)", s.name, s.v)
		}
	}
	return nil
}

const header = `# Sentinels — configuração. Gerado por "sentinels setup"; pode editar à mão.
# Segredos NUNCA ficam aqui: os campos *_env apontam para variáveis do sentinels.env.
# Referência comentada: sentinels.example.yaml

`

// Save validates and writes cfg to path atomically, keeping a .bak of the
// previous file and its owner, group and permissions.
func Save(cfg Config, path string) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	// Never persist an address that came from the defaults or the
	// environment: only an explicit custom socket belongs in the file.
	if s := cfg.Docker.Socket; s == defaultSocket || s == os.Getenv("DOCKER_HOST") {
		cfg.Docker.Socket = ""
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(cfg); err != nil {
		return err
	}
	enc.Close()
	b := buf.Bytes()
	mode := os.FileMode(0o640)
	old, statErr := os.Stat(path)
	if statErr == nil {
		mode = old.Mode().Perm()
		if prev, err := os.ReadFile(path); err == nil {
			_ = os.WriteFile(path+".bak", prev, mode)
			copyOwner(path+".bak", old)
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append([]byte(header), b...), mode); err != nil {
		return err
	}
	if statErr == nil {
		copyOwner(tmp, old)
	}
	return os.Rename(tmp, path)
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
