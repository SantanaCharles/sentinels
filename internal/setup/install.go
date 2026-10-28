package setup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/huh"
)

// Installing needs root on the host. Unlike the Telegram bot, setup runs in
// the administrator's own terminal, shows every command and asks first.

func (s *Session) facts() HostFacts {
	if s.Host == nil {
		f := probeHost(s.ConfigPath)
		s.Host = &f
	}
	return *s.Host
}

func (s *Session) runner() Runner {
	if s.Runner == nil {
		s.Runner = shellRunner{out: s.Out}
	}
	return s.Runner
}

// hostPath maps an absolute path into HostRoot (tests use a temp dir).
func (s *Session) hostPath(p string) string {
	if s.HostRoot == "" {
		return p
	}
	return filepath.Join(s.HostRoot, p)
}

func (s *Session) writeHostFile(p, content string) error {
	full := s.hostPath(p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	if old, err := os.ReadFile(full); err == nil && string(old) != content {
		_ = os.WriteFile(full+".sentinels.bak", old, 0o644)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(s.Out, "  ✎ %s\n", p)
	return nil
}

// runPlan shows the exact script and runs it only after confirmation.
func (s *Session) runPlan(ctx context.Context, title, script string) (bool, error) {
	fmt.Fprintf(s.Out, "\n%s — comandos que serão executados como root:\n\n%s\n\n", title, indentScript(script))
	if !s.confirm("Executar agora?", true) {
		fmt.Fprintln(s.Out, "Pulado.")
		return false, nil
	}
	if err := s.runner().Run(ctx, script); err != nil {
		return false, fmt.Errorf("%s falhou: %w (a saída acima mostra o motivo)", title, err)
	}
	fmt.Fprintf(s.Out, "✔ %s concluído\n", title)
	return true, nil
}

func indentScript(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = "    " + l
	}
	return strings.Join(lines, "\n")
}

func installedStatus(installed bool, extra string) string {
	if installed {
		return "✔ instalado" + extra
	}
	return "✖ não instalado" + extra
}

func (s *Session) sectionInstall(ctx context.Context) error {
	f := s.facts()
	switch {
	case f.InContainer:
		s.note("Rode no servidor, não no container",
			"Instalar componentes exige o host. Na VPS (fora do container):\n\n"+
				"  curl -fsSL https://github.com/SantanaCharles/sentinels/releases/latest/download/install.sh -o install.sh\n"+
				"  sudo sh install.sh --cli-only\n"+
				"  cd ~/sentinels/deploy && sudo sentinels setup install")
		return nil
	case !f.Root:
		return errors.New("instalar componentes exige root: rode sudo sentinels setup install")
	case !f.Apt:
		s.note("Sistema não suportado pelo instalador automático",
			fmt.Sprintf("%s não é Debian/Ubuntu. Instale seguindo docs/INTEGRATIONS.md e depois volte em \"Integrações\".", f.OSName))
		return nil
	}

	for {
		f = s.facts()
		trivyNote := ""
		if f.ComposeFile != "" {
			trivyNote = " (já vem na imagem Docker do Sentinels)"
		}
		choice := "back"
		if err := s.form(huh.NewSelect[string]().Title("Componentes de segurança — instalar ou reconfigurar").
			Description("Cada passo mostra os comandos e pede confirmação antes de executar.").
			Options(
				huh.NewOption("CrowdSec — ataques em logs web e SSH, bloqueio de IPs  "+installedStatus(f.Installed["crowdsec"], " · recomendado"), "crowdsec"),
				huh.NewOption("Suricata — tráfego de rede  "+installedStatus(f.Installed["suricata"], " · usa ~500 MB de RAM"), "suricata"),
				huh.NewOption("Falco — o que acontece dentro dos containers  "+installedStatus(f.Installed["falco"], ""), "falco"),
				huh.NewOption("Trivy — CVEs e chaves vazadas nas imagens  "+installedStatus(f.Installed["trivy"] || f.ComposeFile != "", trivyNote), "trivy"),
				huh.NewOption("Geolocalização — país de origem dos ataques, para o relatório diário  "+installedStatus(s.geoipReady(), ""), "geoip"),
				huh.NewOption("← voltar", "back"),
			).Value(&choice)); err != nil {
			return err
		}
		var err error
		switch choice {
		case "back":
			return nil
		case "crowdsec":
			err = s.installCrowdSec(ctx)
		case "suricata":
			err = s.installSuricata(ctx)
		case "falco":
			err = s.installFalco(ctx)
		case "trivy":
			err = s.installTrivy(ctx)
		case "geoip":
			err = s.installGeoIP(ctx)
		}
		s.Host = nil // re-detect after changes
		if err != nil && !errors.Is(err, huh.ErrUserAborted) {
			fmt.Fprintln(s.Out, "✖", err)
		}
	}
}

func (s *Session) installCrowdSec(ctx context.Context) error {
	f := s.facts()
	cs := &s.Cfg.Integrations.CrowdSec
	if !f.Installed["crowdsec"] {
		portBusy := !f.PortFree(8080)
		ok, err := s.runPlan(ctx, "Instalar o CrowdSec", crowdsecInstall)
		if err != nil || !ok {
			return err
		}
		if portBusy {
			if err := s.moveLAPI(ctx, f); err != nil {
				return err
			}
		}
	} else if !s.confirm("CrowdSec já instalado. Reconectar ao Sentinels e revisar a configuração?", true) {
		return nil
	}

	// Connect: a fresh bouncer key for the agent.
	fmt.Fprintln(s.Out, "\nCriando a chave de acesso do Sentinels no CrowdSec…")
	key, err := s.runner().Output(ctx, "cscli bouncers delete sentinels >/dev/null 2>&1 || true; cscli bouncers add sentinels -o raw")
	if err != nil || key == "" {
		return fmt.Errorf("não consegui criar a chave (cscli bouncers add): %v", err)
	}
	if cs.APIKeyEnv == "" {
		cs.APIKeyEnv = "SENTINELS_CROWDSEC_KEY"
	}
	if err := s.Env.Set(cs.APIKeyEnv, key); err != nil {
		return err
	}
	cs.Enabled = "true"
	if cs.URL == "" {
		cs.URL = "http://127.0.0.1:8080"
	}
	s.dirty = true
	fmt.Fprintf(s.Out, "✔ Chave gravada em %s (%s)\n", filepath.Base(s.EnvPath), cs.APIKeyEnv)

	// Web logs: read the reverse proxy's access log through Docker.
	reload := false
	for _, p := range f.Proxies {
		if !s.confirm(fmt.Sprintf("Ler os logs de acesso do container %s (%s) para detectar ataques aos sites?", p.Container, p.Kind), true) {
			continue
		}
		if err := s.writeHostFile("/etc/crowdsec/acquis.d/sentinels-"+p.Container+".yaml", crowdsecAcquis(p)); err != nil {
			return err
		}
		if ok, err := s.runPlan(ctx, "Coleção do CrowdSec para "+p.Kind, "cscli collections install crowdsecurity/"+p.Kind); err != nil || !ok {
			return err
		}
		reload = true
		if p.Kind == "traefik" || p.Kind == "caddy" {
			s.note("Ative o log de acesso do "+p.Kind,
				"O "+p.Kind+" não grava log de acesso por padrão. Sem ele o CrowdSec não vê os ataques web.\n"+
					map[string]string{
						"traefik": "Traefik: acrescente --accesslog=true nos argumentos (command) do serviço e atualize a stack.",
						"caddy":   "Caddy: no Caddyfile, dentro de cada site, acrescente:  log",
					}[p.Kind])
		}
	}
	if len(f.Proxies) == 0 {
		fmt.Fprintln(s.Out, "Nenhum proxy (Traefik/Nginx/Caddy) encontrado em container; o CrowdSec segue protegendo SSH e o sistema.")
	}
	for _, p := range f.Proxies {
		if p.Kind == "traefik" {
			ok, err := s.offerAppSec(ctx, f)
			if err != nil {
				return err
			}
			reload = reload || ok
			break
		}
	}

	// Optional: actually block attackers.
	if s.confirm("Bloquear automaticamente no firewall os IPs que atacarem? (recomendado)", true) {
		if f.AdminIP != "" {
			if err := s.writeHostFile("/etc/crowdsec/parsers/s02-enrich/sentinels-admin-whitelist.yaml", crowdsecWhitelist(f.AdminIP)); err != nil {
				return err
			}
			fmt.Fprintf(s.Out, "  seu IP atual (%s) nunca será bloqueado\n", f.AdminIP)
			reload = true
		}
		if ok, err := s.runPlan(ctx, "Instalar o bloqueio no firewall (bouncer)", firewallBouncerInstall); err != nil || !ok {
			return err
		}
		bpath := s.hostPath("/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml")
		if b, err := os.ReadFile(bpath); err == nil {
			if out, changed, err := addDockerUserChain(b); err == nil && changed {
				_ = os.WriteFile(bpath+".sentinels.bak", b, 0o600)
				if err := os.WriteFile(bpath, out, 0o600); err != nil {
					return err
				}
				fmt.Fprintln(s.Out, "  ✎ bloqueio vale também para as portas dos containers (cadeia DOCKER-USER)")
				if _, err := s.runPlan(ctx, "Reiniciar o bouncer", "systemctl restart crowdsec-firewall-bouncer"); err != nil {
					return err
				}
			}
		}
	}
	if reload {
		if _, err := s.runPlan(ctx, "Recarregar o CrowdSec", "systemctl reload crowdsec || systemctl restart crowdsec"); err != nil {
			return err
		}
	}
	s.note("CrowdSec pronto", "Teste depois de salvar e aplicar:\n  cscli decisions add --ip 192.0.2.10 --duration 5m --reason teste\nUm alerta deve chegar no Telegram em segundos. Limpe com:\n  cscli decisions delete --ip 192.0.2.10")
	return nil
}

// offerAppSec enables CrowdSec's WAF and prints the Traefik side: requests
// are inspected before reaching the app, logged-in users included.
func (s *Session) offerAppSec(ctx context.Context, f HostFacts) (bool, error) {
	if !s.confirm("Ativar o WAF do CrowdSec (AppSec) no Traefik? Bloqueia exploits conhecidos antes de chegarem à aplicação e bane quem insiste em SQL injection/XSS — inclusive usuários logados.", true) {
		return false, nil
	}
	if f.DockerIP == "" {
		s.note("WAF não ativado", "Não encontrei a interface docker0, por onde o Traefik alcança o CrowdSec do host.\nVeja docs/INTEGRATIONS.md (WAF do CrowdSec) para configurar manualmente.")
		return false, nil
	}
	listen := f.DockerIP + ":7422"
	if ok, err := s.runPlan(ctx, "Regras do WAF do CrowdSec (AppSec)", appsecCollections); err != nil || !ok {
		return false, err
	}
	if err := s.writeHostFile("/etc/crowdsec/acquis.d/sentinels-appsec.yaml", crowdsecAppsecAcquis(listen)); err != nil {
		return false, err
	}
	key, err := s.runner().Output(ctx, "cscli bouncers delete traefik-appsec >/dev/null 2>&1 || true; cscli bouncers add traefik-appsec -o raw")
	if err != nil || key == "" {
		return false, fmt.Errorf("não consegui criar a chave do Traefik (cscli bouncers add traefik-appsec): %v", err)
	}
	s.note("Ligue o WAF no Traefik", traefikAppsecSnippet(listen, key))
	return true, nil
}

// moveLAPI puts CrowdSec's Local API on a free port when 8080 was taken.
func (s *Session) moveLAPI(ctx context.Context, f HostFacts) error {
	port := 0
	for p := 8081; p < 8100; p++ {
		if f.PortFree(p) {
			port = p
			break
		}
	}
	if port == 0 {
		return errors.New("porta 8080 ocupada e nenhuma livre entre 8081 e 8099 para o CrowdSec")
	}
	cfgPath, credsPath := s.hostPath("/etc/crowdsec/config.yaml"), s.hostPath("/etc/crowdsec/local_api_credentials.yaml")
	cfg, err1 := os.ReadFile(cfgPath)
	creds, err2 := os.ReadFile(credsPath)
	if err1 != nil || err2 != nil {
		return fmt.Errorf("não consegui ler a configuração do CrowdSec: %v %v", err1, err2)
	}
	newCfg, newCreds, err := setLAPIPort(cfg, creds, port)
	if err != nil {
		return err
	}
	if err := os.WriteFile(cfgPath, newCfg, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(credsPath, newCreds, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(s.Out, "  porta 8080 ocupada: API do CrowdSec movida para 127.0.0.1:%d\n", port)
	s.Cfg.Integrations.CrowdSec.URL = fmt.Sprintf("http://127.0.0.1:%d", port)
	s.dirty = true
	_, err = s.runPlan(ctx, "Reiniciar o CrowdSec na nova porta", "systemctl restart crowdsec")
	return err
}

func (s *Session) installSuricata(ctx context.Context) error {
	f := s.facts()
	script := suricataInstall
	if sed := suricataIfaceScript(f.Iface); sed != "" {
		script += "\n" + sed
	}
	script += "\nsystemctl enable suricata\nsystemctl restart suricata"
	if f.Installed["suricata"] && !s.confirm("Suricata já instalado. Reaplicar a configuração e atualizar as regras?", true) {
		return nil
	}
	ok, err := s.runPlan(ctx, "Instalar/configurar o Suricata", script)
	if err != nil || !ok {
		return err
	}
	sur := &s.Cfg.Integrations.Suricata
	sur.Enabled = "true"
	if sur.EveLog == "" {
		sur.EveLog = "/var/log/suricata/eve.json"
	}
	s.dirty = true
	if f.ComposeFile != "" {
		if b, err := os.ReadFile(f.ComposeFile); err == nil {
			if out, changed := enableSuricataVolume(b); changed {
				if s.confirm("Liberar o log do Suricata para o container do Sentinels (docker-compose.yml)?", true) {
					_ = os.WriteFile(f.ComposeFile+".sentinels.bak", b, 0o644)
					if err := os.WriteFile(f.ComposeFile, out, 0o644); err != nil {
						return err
					}
					fmt.Fprintf(s.Out, "  ✎ %s: /var/log/suricata montado no container\n", f.ComposeFile)
				}
			}
		}
	}
	fmt.Fprintln(s.Out, "Regras do Suricata: mantenha atualizadas com  suricata-update && systemctl reload suricata  (ex.: cron diário).")
	return nil
}

func (s *Session) installFalco(ctx context.Context) error {
	f := s.facts()
	fa := &s.Cfg.Integrations.Falco
	if fa.Listen == "" {
		fa.Listen = "127.0.0.1:2801"
	}
	if !f.Installed["falco"] {
		ok, err := s.runPlan(ctx, "Instalar o Falco", falcoInstall)
		if err != nil || !ok {
			return err
		}
	} else if !s.confirm("Falco já instalado. Reconfigurar o envio de alertas e atualizar as regras do Sentinels?", true) {
		return nil
	}
	if err := s.writeHostFile("/etc/falco/config.d/sentinels.yaml", falcoConfig(fa.Listen)); err != nil {
		return err
	}
	// Rules for app and database containers: PHP or a database opening a
	// shell, webshells, databases connecting out, attack tools, miners.
	if err := s.writeHostFile("/etc/falco/rules.d/sentinels.yaml", falcoRules); err != nil {
		return err
	}
	if _, err := s.runPlan(ctx, "Ativar o Falco", "systemctl enable falco-modern-bpf.service\nsystemctl restart falco-modern-bpf.service"); err != nil {
		return err
	}
	fa.Enabled = "true" // inside a container the agent cannot detect Falco by itself
	s.dirty = true
	return nil
}

func (s *Session) installTrivy(ctx context.Context) error {
	f := s.facts()
	if f.ComposeFile != "" {
		s.note("Trivy", "Na instalação via Docker o Trivy já vem dentro da imagem do Sentinels — nada a instalar.")
		s.Cfg.Integrations.Trivy.Enabled = "auto"
		return nil
	}
	if f.Installed["trivy"] {
		fmt.Fprintln(s.Out, "Trivy já instalado.")
		return nil
	}
	ok, err := s.runPlan(ctx, "Instalar o Trivy", trivyInstall)
	if err == nil && ok {
		s.Cfg.Integrations.Trivy.Enabled = "auto"
		s.dirty = true
	}
	return err
}

// geoipDir is where the DB-IP database lives, next to the agent's own store.
func (s *Session) geoipDir() string {
	dir := filepath.Dir(s.Cfg.Storage.Path)
	if dir == "" || dir == "." {
		dir = "/var/lib/sentinels"
	}
	return dir
}

// geoipReady reports whether some country database is already available
// (CrowdSec's GeoLite2 or a DB-IP file downloaded earlier).
func (s *Session) geoipReady() bool {
	for _, p := range []string{
		filepath.Join(s.geoipDir(), "dbip-country.mmdb"),
		"/var/lib/crowdsec/data/GeoLite2-City.mmdb",
		"/var/lib/crowdsec/data/GeoLite2-Country.mmdb",
	} {
		if _, err := os.Stat(s.hostPath(p)); err == nil {
			return true
		}
	}
	return false
}

// installGeoIP downloads the free DB-IP Lite Country database so the daily
// report can group attacks by country. CrowdSec's GeoLite2, when present, is
// used automatically; this covers Docker and CrowdSec-less setups.
func (s *Session) installGeoIP(ctx context.Context) error {
	dir := s.geoipDir()
	ok, err := s.runPlan(ctx, "Baixar a base de geolocalização DB-IP Lite (país dos IPs)", geoipDownload(dir))
	if err != nil || !ok {
		return err
	}
	if s.Cfg.Alerts.DailyReport == "" && s.confirm("Enviar um relatório diário com os ataques por país às 08:00?", true) {
		s.Cfg.Alerts.DailyReport = "08:00"
		s.dirty = true
	}
	s.note("Geolocalização pronta",
		"Base DB-IP Lite (CC-BY — https://db-ip.com) salva em "+dir+"/dbip-country.mmdb.\n"+
			"Ela é mensal: rode este passo de novo quando quiser atualizá-la.\n"+
			"O relatório diário é controlado por alerts.daily_report (HH:MM); vazio desliga.")
	return nil
}

// geoipDownload tries the current month's DB-IP Lite file, then the previous
// month's (the newest is sometimes not published yet near the turn).
func geoipDownload(dir string) string {
	return "set -e\n" +
		"DIR='" + dir + "'\n" +
		"mkdir -p \"$DIR\"\n" +
		"TMP=\"$(mktemp)\"\n" +
		"ok=\n" +
		"for M in \"$(date -u +%Y-%m)\" \"$(date -u -d 'last month' +%Y-%m 2>/dev/null || true)\"; do\n" +
		"  [ -n \"$M\" ] || continue\n" +
		"  echo \"Tentando dbip-country-lite-$M...\"\n" +
		"  if curl -fsSL \"https://download.db-ip.com/free/dbip-country-lite-$M.mmdb.gz\" -o \"$TMP.gz\"; then\n" +
		"    gunzip -f \"$TMP.gz\"\n" +
		"    mv \"$TMP\" \"$DIR/dbip-country.mmdb\"\n" +
		"    ok=1; break\n" +
		"  fi\n" +
		"done\n" +
		"[ -n \"$ok\" ] || { echo 'Nao foi possivel baixar a base DB-IP (verifique a internet).'; rm -f \"$TMP\" \"$TMP.gz\"; exit 1; }\n" +
		"chmod 644 \"$DIR/dbip-country.mmdb\"\n" +
		"echo \"Base salva em $DIR/dbip-country.mmdb (DB-IP Lite, CC-BY - https://db-ip.com).\"\n"
}

// offerApply restarts the agent so saved changes take effect.
func (s *Session) offerApply(ctx context.Context) {
	f := s.facts()
	if f.InContainer || !f.Root {
		return
	}
	switch {
	case f.ComposeFile != "" && f.Installed["docker"]:
		if s.confirm("Aplicar agora? (recria o container do Sentinels)", true) {
			_ = s.runner().Run(ctx, "cd '"+filepath.Dir(f.ComposeFile)+"' && docker compose up -d --force-recreate sentinels")
		}
	case f.SystemdUnit:
		if s.confirm("Aplicar agora? (reinicia o serviço sentinels)", true) {
			_ = s.runner().Run(ctx, "systemctl restart sentinels")
		}
	}
}
