package setup

import (
	_ "embed"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Scripts and file contents written by the installer. They are pure
// functions so tests can check exactly what would run on a server.

const crowdsecInstall = `curl -fsSL https://install.crowdsec.net | sh
apt-get install -y crowdsec`

const firewallBouncerInstall = `apt-get install -y crowdsec-firewall-bouncer-iptables`

const suricataInstall = `apt-get install -y suricata
suricata-update`

const falcoInstall = `apt-get install -y curl gnupg
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | gpg --dearmor --yes -o /usr/share/keyrings/falco-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" > /etc/apt/sources.list.d/falcosecurity.list
apt-get update
FALCO_FRONTEND=noninteractive FALCO_DRIVER_CHOICE=modern_ebpf apt-get install -y falco`

const trivyInstall = `apt-get install -y wget gnupg
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor --yes -o /usr/share/keyrings/trivy.gpg
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" > /etc/apt/sources.list.d/trivy.list
apt-get update
apt-get install -y trivy`

// falcoRules is the Sentinels rule pack for app and database containers,
// written to /etc/falco/rules.d/sentinels.yaml.
//
//go:embed falco_rules.yaml
var falcoRules string

// crowdsecAcquis reads a proxy container's log through Docker.
func crowdsecAcquis(p Proxy) string {
	return fmt.Sprintf(`# Gerado pelo sentinels setup: logs de acesso do %s
source: docker
container_name:
  - %s
labels:
  type: %s
`, p.Container, p.Container, p.Kind)
}

// appsecCollections: virtual patching blocks known CVEs in-band; the OWASP
// CRS only observes (out-of-band) and bans an IP after repeated SQLi/XSS, so
// a false positive never breaks a legitimate request.
const appsecCollections = `cscli collections install crowdsecurity/appsec-virtual-patching crowdsecurity/appsec-generic-rules crowdsecurity/appsec-crs`

// traefikPluginVersion is pinned on purpose; see
// https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/releases before bumping.
const traefikPluginVersion = "v1.7.1"

// crowdsecAppsecAcquis turns on CrowdSec's WAF component. It listens on the
// docker0 address so the Traefik container can reach it, but not the internet.
func crowdsecAppsecAcquis(listen string) string {
	return fmt.Sprintf(`# Gerado pelo sentinels setup: WAF do CrowdSec (AppSec) consultado pelo Traefik
appsec_configs:
  - crowdsecurity/appsec-default
  - crowdsecurity/crs
labels:
  type: appsec
listen_addr: %s
source: appsec
`, listen)
}

// traefikAppsecSnippet is what the admin adds to the Traefik stack. Sentinels
// never edits the proxy: a mistake there takes every site down.
func traefikAppsecSnippet(listen, key string) string {
	return fmt.Sprintf(`1) No serviço do Traefik, acrescente aos argumentos (command):
  - --experimental.plugins.crowdsec.modulename=github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin
  - --experimental.plugins.crowdsec.version=%s

2) Nos labels do serviço do Traefik (define o middleware):
  - traefik.http.middlewares.crowdsec.plugin.crowdsec.enabled=true
  - traefik.http.middlewares.crowdsec.plugin.crowdsec.crowdsecmode=appsec
  - traefik.http.middlewares.crowdsec.plugin.crowdsec.crowdsecappsecenabled=true
  - traefik.http.middlewares.crowdsec.plugin.crowdsec.crowdsecappsechost=%s
  - traefik.http.middlewares.crowdsec.plugin.crowdsec.crowdsecappsecunreachableblock=false
  - traefik.http.middlewares.crowdsec.plugin.crowdsec.crowdseclapikey=%s

3) Em cada aplicação a proteger, inclua o middleware no router:
  - traefik.http.routers.<app>.middlewares=crowdsec@docker
    (Traefik v3 no Swarm com --providers.swarm: crowdsec@swarm)

Atualize a stack e teste (deve responder 403):
  curl -s -o /dev/null -w "%%{http_code}\n" https://seu-site/.env

Como funciona: exploits de CVEs conhecidos são bloqueados na hora (403). SQL injection
e XSS genéricos (OWASP CRS) não bloqueiam a requisição, para não barrar usuário legítimo:
após algumas tentativas o IP é banido e o alerta chega no Telegram.
Se o CrowdSec cair, os sites continuam no ar (unreachableblock=false).
Guarde a chave acima: ela só aparece agora (nova: cscli bouncers add traefik-appsec).`, traefikPluginVersion, listen, key)
}

// crowdsecWhitelist keeps the administrator's own IP from ever being banned.
func crowdsecWhitelist(ip string) string {
	return fmt.Sprintf(`# Gerado pelo sentinels setup: o IP do administrador nunca é bloqueado.
name: sentinels/admin-whitelist
description: "IP do administrador (sentinels setup)"
whitelist:
  reason: "administrador"
  ip:
    - "%s"
`, ip)
}

// falcoConfig is a config.d drop-in: Falco sends JSON alerts to the agent.
// rule_matching: all lets the Sentinels rules fire on events that a default
// rule (with a lower priority) already matched.
func falcoConfig(listen string) string {
	return fmt.Sprintf(`# Gerado pelo sentinels setup: alertas do Falco para o Sentinels
json_output: true
rule_matching: all
http_output:
  enabled: true
  url: "http://%s/falco"
`, listen)
}

var (
	listenURIRe = regexp.MustCompile(`(?m)^(\s*listen_uri:\s*)\S+`)
	lapiURLRe   = regexp.MustCompile(`(?m)^(\s*url:\s*)http://[^\s]+`)
)

// setLAPIPort moves CrowdSec's Local API to another loopback port, editing
// config.yaml and local_api_credentials.yaml in place (comments kept).
func setLAPIPort(config, creds []byte, port int) ([]byte, []byte, error) {
	if !listenURIRe.Match(config) || !lapiURLRe.Match(creds) {
		return nil, nil, fmt.Errorf("formato inesperado em config.yaml/local_api_credentials.yaml")
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	config = listenURIRe.ReplaceAll(config, []byte("${1}"+addr))
	creds = lapiURLRe.ReplaceAll(creds, []byte("${1}http://"+addr+"/"))
	return config, creds, nil
}

// addDockerUserChain makes the firewall bouncer also block traffic to
// published container ports, which bypasses the INPUT chain.
func addDockerUserChain(bouncerYAML []byte) ([]byte, bool, error) {
	var doc map[string]any
	if err := yaml.Unmarshal(bouncerYAML, &doc); err != nil {
		return nil, false, err
	}
	chains, _ := doc["iptables_chains"].([]any)
	for _, c := range chains {
		if c == "DOCKER-USER" {
			return bouncerYAML, false, nil
		}
	}
	if len(chains) == 0 {
		chains = []any{"INPUT"}
	}
	doc["iptables_chains"] = append(chains, "DOCKER-USER")
	out, err := yaml.Marshal(doc)
	return out, err == nil, err
}

var suricataVolumeRe = regexp.MustCompile(`(?m)^(\s*)#\s*(- /var/log/suricata:/var/log/suricata:ro)\s*$`)

// enableSuricataVolume uncomments the eve.json mount in the compose file.
func enableSuricataVolume(compose []byte) ([]byte, bool) {
	if !suricataVolumeRe.Match(compose) {
		return compose, false
	}
	return suricataVolumeRe.ReplaceAll(compose, []byte("${1}${2}")), true
}

// suricataIfaceScript points af-packet/pcap at the real interface; Debian's
// default config assumes eth0.
func suricataIfaceScript(iface string) string {
	if iface == "" || iface == "eth0" || strings.ContainsAny(iface, " /;'\"$`\\") {
		return ""
	}
	return fmt.Sprintf("sed -i 's/interface: eth0/interface: %s/g' /etc/suricata/suricata.yaml", iface)
}
