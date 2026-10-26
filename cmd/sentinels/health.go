package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/SantanaCharles/sentinels/internal/config"
	"github.com/SantanaCharles/sentinels/internal/discovery"
	"github.com/SantanaCharles/sentinels/internal/integrations"
	"github.com/SantanaCharles/sentinels/internal/notify"
	"github.com/SantanaCharles/sentinels/internal/scan"
	"github.com/SantanaCharles/sentinels/internal/telegram"
	"github.com/SantanaCharles/sentinels/internal/version"
)

const integrationsDoc = "https://github.com/SantanaCharles/sentinels/blob/main/docs/INTEGRACOES.md"

// healthFunc describes what the running agent actually uses, for /doctor
// on Telegram. Install steps are only text: nothing is executed.
func healthFunc(cfg config.Config, sources []integrations.Source, chans []notify.Channel, ex extras, started time.Time) telegram.HealthFunc {
	active := map[string]bool{}
	for _, s := range sources {
		active[s.Name()] = true
	}
	return func(ctx context.Context) []telegram.Check {
		var out []telegram.Check
		add := func(name string, ok bool, detail, fix string) {
			out = append(out, telegram.Check{Name: name, OK: ok, Detail: detail, Fix: fix})
		}

		add("Agente", true, fmt.Sprintf("%s, rodando há %s", version.Version, time.Since(started).Round(time.Minute)), "")

		pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := discovery.NewClient(cfg.Docker.Socket).Ping(pctx)
		cancel()
		if err == nil {
			add("Docker", true, "lendo containers via "+cfg.Docker.Socket, "")
		} else {
			add("Docker", false, "sem acesso a "+cfg.Docker.Socket,
				"docker compose ps   (o socket-proxy precisa estar Up)\nconfira se sentinels.yaml não fixa docker.socket")
		}

		if r, err := scan.Latest(cfg.Scan.ReportDir); err == nil {
			add("Varredura", true, fmt.Sprintf("última há %s, %d container(s), a cada %s", time.Since(r.Started).Round(time.Minute), len(r.Assets), cfg.Scan.Interval), "")
		} else {
			add("Varredura", false, "nenhuma concluída ainda", "aguarde alguns minutos ou mande /scan")
		}

		if _, ok := integrations.TrivyAvailable(); ok && cfg.Integrations.Trivy.Mode() != "false" {
			add("Trivy", true, "CVEs e chaves vazadas nas imagens", "")
		} else {
			add("Trivy", false, "CVEs e chaves vazadas nas imagens não são verificadas",
				"Docker: já vem na imagem do Sentinels (confira integrations.trivy.enabled)\nsystemd: apt install trivy  — https://trivy.dev")
		}

		rt := 0
		if active["crowdsec"] {
			rt++
			add("CrowdSec", true, "ataques em logs web e SSH, em tempo real", "")
		} else {
			add("CrowdSec", false, "sem detecção de ataques em logs web/SSH (recomendado)",
				"curl -s https://install.crowdsec.net | sh\napt install -y crowdsec crowdsec-firewall-bouncer-iptables\ncscli bouncers add sentinels      # copie a chave exibida\nno sentinels.env: SENTINELS_CROWDSEC_KEY=<chave>")
		}
		if active["suricata"] {
			rt++
			add("Suricata", true, "tráfego de rede ("+cfg.Integrations.Suricata.EveLog+")", "")
		} else {
			add("Suricata", false, "sem análise do tráfego de rede (opcional)",
				"apt install -y suricata && suricata-update && systemctl enable --now suricata\nDocker: no docker-compose.yml do Sentinels descomente\n  - /var/log/suricata:/var/log/suricata:ro")
		}
		if active["falco"] {
			rt++
			add("Falco", true, "comportamento dentro dos containers ("+cfg.Integrations.Falco.Listen+")", "")
		} else {
			add("Falco", false, "sem detecção do que acontece dentro dos containers (opcional)",
				"instale: https://falco.org/docs/setup/packages/\n/etc/falco/falco.yaml: json_output: true e\n  http_output: {enabled: true, url: \"http://"+cfg.Integrations.Falco.Listen+"/falco\"}\nDocker: no sentinels.yaml use integrations.falco.enabled: \"true\"")
		}
		if active["containers"] {
			rt++
			add("Bancos e apps", true, "logs do Postgres e das aplicações, novos clientes dos bancos", "")
		} else if cfg.Integrations.Containers.Mode() != "false" {
			add("Bancos e apps", false, "sem leitura dos logs dos bancos/apps (precisa do Docker)", "confira o socket-proxy: docker compose ps")
		}
		if rt == 0 {
			add("Tempo real", false, "nenhum motor ativo: só varreduras periódicas", "instale ao menos o CrowdSec (acima) — "+integrationsDoc)
		}

		if ex.analyst != nil {
			add("IA", true, ex.analyst.Provider.Name(), "")
		} else {
			add("IA", false, "desativada (sem resumos, explicações e perguntas livres)", "sentinels setup ai")
		}

		names := make([]string, 0, len(chans))
		for _, c := range chans {
			names = append(names, c.Notifier.Name())
		}
		if len(names) > 0 {
			add("Alertas", true, strings.Join(names, ", "), "")
		} else {
			add("Alertas", false, "nenhum canal", "sentinels setup notifications")
		}

		if n := len(cfg.Databases); n > 0 {
			add("Bancos (RLS)", true, fmt.Sprintf("%d auditado(s)", n), "")
		}
		return out
	}
}
