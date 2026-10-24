// Package setup is the interactive configuration wizard (`sentinels setup`):
// arrow-key menus in the terminal, or plain prompts when there is no TTY.
// Settings go to sentinels.yaml and secrets to sentinels.env (0600).
package setup

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/huh"
	"golang.org/x/term"

	"github.com/SantanaCharles/sentinels/internal/config"
)

type Session struct {
	ConfigPath string
	EnvPath    string
	Cfg        config.Config
	Env        *config.EnvFile
	Accessible bool // plain prompts (no TTY, screen readers, tests)
	Out        io.Writer
	In         io.Reader
	// Doctor runs `sentinels doctor` against the current (saved) config.
	Doctor func(ctx context.Context, configPath string)

	dirty bool
}

// Open loads the config (or defaults when missing) and the secrets file.
func Open(configPath, envPath string) (*Session, error) {
	cfg, err := config.Load(configPath, true)
	if err != nil {
		return nil, err
	}
	if envPath == "" {
		envPath = filepath.Join(filepath.Dir(configPath), "sentinels.env")
	}
	env, err := config.LoadEnvFile(envPath)
	if err != nil {
		return nil, err
	}
	env.Apply() // tests inside the wizard see the saved secrets
	if err := checkWritable(filepath.Dir(configPath)); err != nil {
		return nil, fmt.Errorf("sem permissão para gravar em %s: rode com sudo (%v)", filepath.Dir(configPath), err)
	}
	return &Session{ConfigPath: configPath, EnvPath: envPath, Cfg: cfg, Env: env, Out: os.Stdout, In: os.Stdin}, nil
}

func checkWritable(dir string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".sentinels-setup-*")
	if err != nil {
		return err
	}
	f.Close()
	return os.Remove(f.Name())
}

var sections = []struct{ key, label, desc string }{
	{"rapida", "⚡ Configuração rápida", "IA + um canal de alerta + teste, em 2 minutos"},
	{"ia", "🤖 Inteligência artificial", "provedor, modelo, chave e uso"},
	{"notificacoes", "🔔 Notificações", "Telegram, Slack, Discord, e-mail, webhook"},
	{"integracoes", "🛰  Integrações", "Trivy, CrowdSec, Suricata, Falco"},
	{"bancos", "🐘 Bancos PostgreSQL", "auditoria de Row-Level Security"},
	{"varredura", "🔍 Varredura e alertas", "intervalo, severidade, URLs públicas"},
	{"cofre", "📓 Cofre Obsidian", "notas de relatórios e incidentes"},
	{"mcp", "🔌 Servidor MCP", "consultar o agente pelo Claude/ChatGPT"},
}

// SectionKeys lists valid arguments for `sentinels setup <seção>`.
func SectionKeys() []string {
	keys := make([]string, len(sections))
	for i, s := range sections {
		keys[i] = s.key
	}
	return keys
}

// Run opens the main menu, or goes straight to one section.
func (s *Session) Run(ctx context.Context, section string) error {
	if section != "" {
		if err := s.runSection(ctx, section); err != nil {
			return err
		}
		return s.saveIfDirty(true)
	}
	fmt.Fprintf(s.Out, "\nSentinels — configuração\n  config:   %s\n  segredos: %s\n\n", s.ConfigPath, s.EnvPath)
	for {
		choice := ""
		opts := make([]huh.Option[string], 0, len(sections)+3)
		for _, sec := range sections {
			opts = append(opts, huh.NewOption(fmt.Sprintf("%-28s %s", sec.label, sec.desc), sec.key))
		}
		opts = append(opts,
			huh.NewOption("🩺 Verificar instalação (doctor)", "doctor"),
			huh.NewOption("💾 Salvar e sair", "salvar"),
			huh.NewOption("✖  Sair sem salvar", "sair"))
		title := "O que você quer configurar?"
		if s.dirty {
			title += "  (há alterações não salvas)"
		}
		if err := s.form(huh.NewSelect[string]().Title(title).Options(opts...).Value(&choice)); err != nil {
			if errors.Is(err, huh.ErrUserAborted) {
				choice = "sair"
			} else {
				return err
			}
		}
		switch choice {
		case "salvar":
			return s.saveIfDirty(false)
		case "sair":
			if s.dirty && !s.confirm("Descartar as alterações não salvas?", false) {
				continue
			}
			fmt.Fprintln(s.Out, "Nada foi alterado.")
			return nil
		case "doctor":
			if s.dirty && s.confirm("Salvar antes de verificar?", true) {
				if err := s.save(); err != nil {
					return err
				}
			}
			if s.Doctor != nil {
				s.Doctor(ctx, s.ConfigPath)
			}
		default:
			if err := s.runSection(ctx, choice); err != nil && !errors.Is(err, huh.ErrUserAborted) {
				fmt.Fprintln(s.Out, "erro:", err)
			}
		}
	}
}

func (s *Session) runSection(ctx context.Context, key string) error {
	switch key {
	case "rapida":
		return s.quick(ctx)
	case "ia":
		return s.sectionAI(ctx)
	case "notificacoes":
		return s.sectionNotify(ctx)
	case "integracoes":
		return s.sectionIntegrations()
	case "bancos":
		return s.sectionDatabases(ctx)
	case "varredura":
		return s.sectionScan()
	case "cofre":
		return s.sectionVault()
	case "mcp":
		return s.sectionMCP()
	}
	return fmt.Errorf("seção desconhecida %q (use: %s)", key, strings.Join(SectionKeys(), ", "))
}

func (s *Session) quick(ctx context.Context) error {
	s.note("Configuração rápida", "Três passos: IA (opcional), um canal de alerta e um teste. O resto tem padrões seguros e pode ser ajustado depois.")
	if s.confirm("Usar IA para resumir relatórios e explicar alertas?", true) {
		if err := s.sectionAI(ctx); err != nil {
			return err
		}
	}
	if err := s.addNotifier(ctx); err != nil && !errors.Is(err, huh.ErrUserAborted) {
		return err
	}
	return nil
}

func (s *Session) saveIfDirty(ask bool) error {
	if !s.dirty {
		fmt.Fprintln(s.Out, "Nenhuma alteração para salvar.")
		return nil
	}
	if ask && !s.confirm("Salvar as alterações?", true) {
		fmt.Fprintln(s.Out, "Nada foi alterado.")
		return nil
	}
	return s.save()
}

func (s *Session) save() error {
	if err := config.Save(s.Cfg, s.ConfigPath); err != nil {
		return err
	}
	if err := s.Env.Save(); err != nil {
		return err
	}
	s.dirty = false
	fmt.Fprintf(s.Out, "\n✔ Salvo: %s e %s (0600)\n", s.ConfigPath, s.EnvPath)
	fmt.Fprintln(s.Out, "  Se o serviço já estiver rodando: sudo systemctl restart sentinels  (ou docker compose restart sentinels)")
	return nil
}

// --- form helpers ---------------------------------------------------------

func (s *Session) form(fields ...huh.Field) error {
	f := huh.NewForm(huh.NewGroup(fields...)).WithAccessible(s.Accessible).WithTheme(huh.ThemeCharm())
	if s.Accessible {
		if _, ok := s.In.(*byteReader); !ok {
			s.In = &byteReader{r: s.In}
		}
		f = f.WithInput(s.In).WithOutput(s.Out)
	}
	return f.Run()
}

// byteReader hands out one byte per Read. In plain mode every prompt wraps
// the input in its own buffered scanner; without this, the first prompt
// would swallow the answers typed (or piped) for the next ones.
type byteReader struct{ r io.Reader }

func (b *byteReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return b.r.Read(p[:1])
}

func (s *Session) confirm(title string, def bool) bool {
	v := def
	if err := s.form(huh.NewConfirm().Title(title).Affirmative("Sim").Negative("Não").Value(&v)); err != nil {
		return false
	}
	return v
}

func (s *Session) note(title, desc string) {
	if s.Accessible {
		fmt.Fprintf(s.Out, "\n== %s ==\n%s\n", title, desc)
		return
	}
	_ = s.form(huh.NewNote().Title(title).Description(desc).Next(true).NextLabel("Continuar"))
}

// secret asks for a value and stores it in the env file under name. Empty
// input keeps the current value.
func (s *Session) secret(title, name string, validate func(string) error) error {
	cur := s.Env.Get(name)
	placeholder := "cole aqui"
	if cur != "" {
		placeholder = "já configurado — Enter mantém o atual"
	}
	check := func(x string) error {
		x = strings.TrimSpace(x)
		if x == "" {
			if cur == "" {
				return errors.New("obrigatório")
			}
			return nil
		}
		if validate != nil {
			return validate(x)
		}
		return nil
	}
	desc := "Fica em " + filepath.Base(s.EnvPath) + " como " + name + ", nunca no YAML."
	v := ""
	var err error
	if s.Accessible {
		v, err = s.plainSecret(title, desc, placeholder, check)
	} else {
		err = s.form(huh.NewInput().Title(title).Description(desc).
			Placeholder(placeholder).EchoMode(huh.EchoModePassword).Value(&v).Validate(check))
	}
	if err != nil {
		return err
	}
	if v = strings.TrimSpace(v); v != "" {
		if err := s.Env.Set(name, v); err != nil {
			return err
		}
		os.Setenv(name, v)
		s.dirty = true
	}
	return nil
}

// plainSecret asks for a secret without menus: no echo on a real terminal,
// a plain line otherwise (pipes, tests). Invalid values are asked again.
func (s *Session) plainSecret(title, desc, placeholder string, check func(string) error) (string, error) {
	if _, ok := s.In.(*byteReader); !ok {
		s.In = &byteReader{r: s.In}
	}
	tty := false
	if f, ok := s.In.(*byteReader).r.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		tty = true
	}
	for attempt := 0; attempt < 5; attempt++ {
		fmt.Fprintf(s.Out, "\n%s\n%s\n(%s): ", title, desc, placeholder)
		var line string
		if tty {
			b, err := term.ReadPassword(int(s.In.(*byteReader).r.(*os.File).Fd()))
			fmt.Fprintln(s.Out)
			if err != nil {
				return "", err
			}
			line = string(b)
		} else {
			var err error
			if line, err = readLine(s.In); err != nil && line == "" {
				return "", huh.ErrUserAborted
			}
		}
		if err := check(line); err != nil {
			fmt.Fprintf(s.Out, "Inválido: %v\n", err)
			continue
		}
		return strings.TrimSpace(line), nil
	}
	return "", errors.New("muitas tentativas inválidas")
}

func readLine(r io.Reader) (string, error) {
	var b strings.Builder
	buf := make([]byte, 1)
	for {
		n, err := r.Read(buf)
		if n == 1 {
			if buf[0] == '\n' {
				return strings.TrimRight(b.String(), "\r"), nil
			}
			b.WriteByte(buf[0])
		}
		if err != nil {
			return b.String(), err
		}
	}
}

// freeEnvName returns base, or base_2, base_3… when base already holds a
// different channel's secret.
func freeEnvName(used map[string]bool, base string) string {
	if !used[base] {
		return base
	}
	for i := 2; ; i++ {
		n := fmt.Sprintf("%s_%d", base, i)
		if !used[n] {
			return n
		}
	}
}

func randomToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

var severityOptions = []huh.Option[string]{
	huh.NewOption("Crítico — só o que exige ação imediata", "critical"),
	huh.NewOption("Alto ou mais (recomendado)", "high"),
	huh.NewOption("Médio ou mais", "medium"),
	huh.NewOption("Baixo ou mais (muito volume)", "low"),
}
