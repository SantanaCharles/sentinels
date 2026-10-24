package setup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/huh"

	"github.com/SantanaCharles/sentinels/internal/checks"
	"github.com/SantanaCharles/sentinels/internal/config"
	"github.com/SantanaCharles/sentinels/internal/finding"
)

func (s *Session) hostname() string {
	h, _ := os.Hostname()
	return h
}

func status(ok bool, yes, no string) string {
	if ok {
		return "✔ " + yes
	}
	return "✖ " + no
}

var modeOptions = []huh.Option[string]{
	huh.NewOption("automático (usa se estiver instalado)", "auto"),
	huh.NewOption("ligado (erro se faltar)", "true"),
	huh.NewOption("desligado", "false"),
}

func (s *Session) sectionIntegrations() error {
	in := &s.Cfg.Integrations
	_, trivyErr := exec.LookPath("trivy")
	_, eveErr := os.Stat(in.Suricata.EveLog)
	_, falcoErr := exec.LookPath("falco")
	_, falcoDir := os.Stat("/etc/falco")
	s.note("Integrações detectadas neste servidor", strings.Join([]string{
		"Trivy     " + status(trivyErr == nil, "instalado", "não encontrado — https://trivy.dev"),
		"CrowdSec  " + status(s.Env.Get(in.CrowdSec.APIKeyEnv) != "", "chave configurada", "sem chave (cscli bouncers add sentinels)"),
		"Suricata  " + status(eveErr == nil, in.Suricata.EveLog, "eve.json não encontrado — https://suricata.io"),
		"Falco     " + status(falcoErr == nil || falcoDir == nil, "instalado", "não encontrado — https://falco.org"),
	}, "\n"))

	trivy, cs, sur, fal := in.Trivy.Mode(), in.CrowdSec.Mode(), in.Suricata.Mode(), in.Falco.Mode()
	if err := s.form(
		huh.NewSelect[string]().Title("Trivy — CVEs das imagens").Options(modeOptions...).Value(&trivy),
		huh.NewSelect[string]().Title("CrowdSec — ataques em logs web e SSH").Options(modeOptions...).Value(&cs),
		huh.NewInput().Title("URL da API local do CrowdSec").Value(&in.CrowdSec.URL),
		huh.NewSelect[string]().Title("Suricata — tráfego de rede").Options(modeOptions...).Value(&sur),
		huh.NewInput().Title("Arquivo eve.json do Suricata").Value(&in.Suricata.EveLog),
		huh.NewSelect[string]().Title("Falco — comportamento dentro dos containers").Options(modeOptions...).Value(&fal),
	); err != nil {
		return err
	}
	in.Trivy.Enabled, in.CrowdSec.Enabled, in.Suricata.Enabled, in.Falco.Enabled = trivy, cs, sur, fal
	s.dirty = true
	if cs != "false" {
		if in.CrowdSec.APIKeyEnv == "" {
			in.CrowdSec.APIKeyEnv = "SENTINELS_CROWDSEC_KEY"
		}
		if s.Env.Get(in.CrowdSec.APIKeyEnv) != "" || s.confirm("Informar a chave do bouncer do CrowdSec agora? (sudo cscli bouncers add sentinels)", true) {
			if err := s.secret("Chave do bouncer do CrowdSec", in.CrowdSec.APIKeyEnv, nil); err != nil {
				return err
			}
		}
	}
	if fal != "false" {
		s.note("Falco", "No /etc/falco/falco.yaml habilite:\n  json_output: true\n  http_output:\n    enabled: true\n    url: \"http://"+in.Falco.Listen+"/falco\"")
	}
	return nil
}

var dbNameRe = regexp.MustCompile(`^[a-z0-9_-]{1,40}$`)

func (s *Session) sectionDatabases(ctx context.Context) error {
	for {
		opts := []huh.Option[string]{}
		for i, d := range s.Cfg.Databases {
			opts = append(opts, huh.NewOption(fmt.Sprintf("✖ remover: %s (role %s)", d.Name, d.AppRole), fmt.Sprintf("rm:%d", i)))
		}
		opts = append(opts, huh.NewOption("+ adicionar banco PostgreSQL", "add"), huh.NewOption("← voltar", "back"))
		choice := "add"
		if len(s.Cfg.Databases) > 0 {
			choice = "back"
		}
		if err := s.form(huh.NewSelect[string]().Title("Bancos auditados (Row-Level Security)").
			Description("Use um usuário SOMENTE LEITURA. O agente lê só o catálogo, nunca os dados das tabelas.").
			Options(opts...).Value(&choice)); err != nil {
			return err
		}
		switch {
		case choice == "back":
			return nil
		case strings.HasPrefix(choice, "rm:"):
			var i int
			fmt.Sscanf(choice, "rm:%d", &i)
			if s.confirm("Remover "+s.Cfg.Databases[i].Name+"?", false) {
				s.Cfg.Databases = append(s.Cfg.Databases[:i], s.Cfg.Databases[i+1:]...)
				s.dirty = true
			}
		case choice == "add":
			d := config.Database{Driver: "postgres"}
			if err := s.form(
				huh.NewInput().Title("Nome curto do banco").Placeholder("educare").Value(&d.Name).Validate(func(v string) error {
					if !dbNameRe.MatchString(v) {
						return errors.New("minúsculas, números, - e _")
					}
					return nil
				}),
				huh.NewInput().Title("Role que a APLICAÇÃO usa para conectar").Description("Para verificar SUPERUSER, BYPASSRLS e owner das tabelas.").Value(&d.AppRole),
			); err != nil {
				return err
			}
			d.DSNEnv = "SENTINELS_DB_" + strings.ToUpper(strings.NewReplacer("-", "_").Replace(d.Name))
			if err := s.secret("DSN de um usuário somente leitura (postgres://auditor:senha@host:5432/banco?sslmode=require)", d.DSNEnv,
				prefix("postgres://", "postgresql://")); err != nil {
				return err
			}
			s.Cfg.Databases = append(s.Cfg.Databases, d)
			s.dirty = true
			if s.confirm("Testar a conexão e a auditoria de RLS agora?", true) {
				tctx, cancel := context.WithTimeout(ctx, 40*time.Second)
				fs, err := checks.Postgres(tctx, d.Name, config.Secret(d.DSNEnv), d.AppRole)
				cancel()
				if err != nil {
					fmt.Fprintln(s.Out, "✖", err)
				} else {
					c := finding.Count(fs)
					fmt.Fprintf(s.Out, "✔ conectado: %d crítico(s), %d alto(s), %d médio(s) de RLS\n", c[finding.Critical], c[finding.High], c[finding.Medium])
				}
			}
		}
	}
}

func (s *Session) sectionScan() error {
	sc, al := &s.Cfg.Scan, &s.Cfg.Alerts
	urls := strings.Join(sc.URLs, "\n")
	retention := strconv.Itoa(s.Cfg.Storage.RetentionDays)
	if err := s.form(
		huh.NewSelect[string]().Title("Varredura completa a cada").Options(
			huh.NewOption("1 hora", "1h"), huh.NewOption("3 horas", "3h"), huh.NewOption("6 horas (recomendado)", "6h"),
			huh.NewOption("12 horas", "12h"), huh.NewOption("24 horas", "24h")).Value(&sc.Interval),
		huh.NewSelect[string]().Title("Severidade mínima para alertar").Options(severityOptions...).Value(&al.MinSeverity),
		huh.NewSelect[string]().Title("Repetições do mesmo evento viram um alerta só dentro de").Options(
			huh.NewOption("5 minutos", "5m"), huh.NewOption("15 minutos", "15m"), huh.NewOption("30 minutos", "30m"),
			huh.NewOption("1 hora", "1h")).Value(&al.DedupWindow),
		huh.NewText().Title("URLs públicas para verificar (uma por linha)").Description("Ex.: https://meusite.com.br — headers, .env/.git expostos, versão do PHP.").
			Value(&urls).Validate(func(v string) error {
			for _, u := range lines(v) {
				if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
					return fmt.Errorf("%q deve começar com https://", u)
				}
			}
			return nil
		}),
		huh.NewInput().Title("Guardar eventos por quantos dias").Value(&retention).Validate(func(v string) error {
			if n, err := strconv.Atoi(v); err != nil || n < 1 || n > 3650 {
				return errors.New("entre 1 e 3650")
			}
			return nil
		}),
	); err != nil {
		return err
	}
	sc.URLs = lines(urls)
	s.Cfg.Storage.RetentionDays, _ = strconv.Atoi(retention)
	s.dirty = true
	return nil
}

func lines(v string) []string {
	var out []string
	for _, l := range strings.FieldsFunc(v, func(r rune) bool { return r == '\n' || r == ',' || r == ' ' }) {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func (s *Session) sectionVault() error {
	v := &s.Cfg.Vault
	if err := s.form(
		huh.NewConfirm().Title("Manter um cofre de notas compatível com o Obsidian?").
			Description("Relatórios, incidentes, uma nota por aplicação e por técnica ATT&CK, ligadas por [[links]].").
			Affirmative("Sim").Negative("Não").Value(&v.Enabled),
	); err != nil {
		return err
	}
	if v.Enabled {
		if err := s.form(huh.NewInput().Title("Pasta do cofre").Value(&v.Path)); err != nil {
			return err
		}
	}
	s.dirty = true
	return nil
}

func (s *Session) sectionMCP() error {
	m := &s.Cfg.MCP
	httpMode := s.Env.Get(m.TokenEnv) != ""
	if err := s.form(
		huh.NewConfirm().Title("Mostrar IPs reais para o cliente MCP?").Description("Não (recomendado): IPs viram [IP-1].").
			Affirmative("Sim").Negative("Não").Value(&m.KeepIPs),
		huh.NewConfirm().Title("Vai usar o modo HTTP (sentinels mcp --http)?").Description("Não precisa para Claude Code/Desktop via SSH.").
			Affirmative("Sim").Negative("Não").Value(&httpMode),
	); err != nil {
		return err
	}
	s.dirty = true
	if httpMode && s.Env.Get(m.TokenEnv) == "" {
		s.Env.Set(m.TokenEnv, randomToken())
		fmt.Fprintf(s.Out, "Token gerado em %s (use como Bearer no cliente).\n", m.TokenEnv)
	}
	s.note("Conectar no Claude Code", "claude mcp add sentinels -- ssh SEU_SERVIDOR sudo -u sentinels sentinels mcp -config "+s.ConfigPath+"\n\nDetalhes e outros clientes: docs/MCP.md")
	return nil
}
