package setup

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeRunner struct {
	scripts []string
	outputs map[string]string // substring of script -> output
}

func (f *fakeRunner) Run(_ context.Context, script string) error {
	f.scripts = append(f.scripts, script)
	return nil
}

func (f *fakeRunner) Output(_ context.Context, script string) (string, error) {
	f.scripts = append(f.scripts, script)
	for k, v := range f.outputs {
		if strings.Contains(script, k) {
			return v, nil
		}
	}
	return "", nil
}

func (f *fakeRunner) ran(sub string) bool {
	for _, s := range f.scripts {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func host(root string, installed ...string) *HostFacts {
	h := &HostFacts{Root: true, Apt: true, Installed: map[string]bool{}, PortFree: func(int) bool { return true }}
	for _, i := range installed {
		h.Installed[i] = true
	}
	return h
}

func readHost(t *testing.T, s *Session, p string) string {
	t.Helper()
	b, err := os.ReadFile(s.hostPath(p))
	if err != nil {
		t.Fatalf("%s não foi escrito: %v", p, err)
	}
	return string(b)
}

func TestInstallCrowdSecFullFlow(t *testing.T) {
	// install, proxy logs, collection, WAF, WAF rules, firewall, bouncer, restart bouncer, reload: all yes
	s, out := session(t, "y", "y", "y", "y", "y", "y", "y", "y", "y", "y")
	s.Host = host(s.HostRoot, "docker")
	s.Host.DockerIP = "172.17.0.1"
	s.Host.Proxies = []Proxy{{"traefik_traefik.1.abc", "traefik"}}
	s.Host.AdminIP = "191.8.223.230"
	fr := &fakeRunner{outputs: map[string]string{"bouncers add sentinels": "CHAVE-DO-BOUNCER-123", "bouncers add traefik-appsec": "CHAVE-TRAEFIK-456"}}
	s.Runner = fr
	os.MkdirAll(s.hostPath("/etc/crowdsec/bouncers"), 0o755)
	os.WriteFile(s.hostPath("/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"), []byte("mode: iptables\niptables_chains:\n  - INPUT\n"), 0o600)

	if err := s.installCrowdSec(context.Background()); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{"install.crowdsec.net", "cscli bouncers add sentinels -o raw", "cscli collections install crowdsecurity/traefik",
		"crowdsec-firewall-bouncer-iptables", "systemctl restart crowdsec-firewall-bouncer", "systemctl reload crowdsec"} {
		if !fr.ran(want) {
			t.Errorf("não executou %q", want)
		}
	}
	if s.Env.Get("SENTINELS_CROWDSEC_KEY") != "CHAVE-DO-BOUNCER-123" || s.Cfg.Integrations.CrowdSec.Enabled != "true" {
		t.Errorf("chave/integração: %q %q", s.Env.Get("SENTINELS_CROWDSEC_KEY"), s.Cfg.Integrations.CrowdSec.Enabled)
	}
	if acq := readHost(t, s, "/etc/crowdsec/acquis.d/sentinels-traefik_traefik.1.abc.yaml"); !strings.Contains(acq, "source: docker") || !strings.Contains(acq, "type: traefik") {
		t.Errorf("acquis:\n%s", acq)
	}
	if wl := readHost(t, s, "/etc/crowdsec/parsers/s02-enrich/sentinels-admin-whitelist.yaml"); !strings.Contains(wl, `"191.8.223.230"`) {
		t.Errorf("whitelist:\n%s", wl)
	}
	if b := readHost(t, s, "/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"); !strings.Contains(b, "DOCKER-USER") || !strings.Contains(b, "INPUT") {
		t.Errorf("bouncer sem DOCKER-USER:\n%s", b)
	}
	if !strings.Contains(out.String(), "--accesslog=true") {
		t.Error("faltou o aviso de ativar o access log do Traefik")
	}
	if acq := readHost(t, s, "/etc/crowdsec/acquis.d/sentinels-appsec.yaml"); !strings.Contains(acq, "listen_addr: 172.17.0.1:7422") || !strings.Contains(acq, "source: appsec") {
		t.Errorf("acquis do WAF:\n%s", acq)
	}
	if !fr.ran("appsec-virtual-patching") || !strings.Contains(out.String(), "crowdsecappsechost=172.17.0.1:7422") ||
		!strings.Contains(out.String(), "crowdseclapikey=CHAVE-TRAEFIK-456") || !strings.Contains(out.String(), "version="+traefikPluginVersion) {
		t.Errorf("WAF: coleções ou instruções do Traefik faltando:\n%s", out.String())
	}
}

func TestDeclinedPlanRunsNothing(t *testing.T) {
	s, _ := session(t, "n")
	s.Host = host(s.HostRoot)
	fr := &fakeRunner{}
	s.Runner = fr
	if err := s.installCrowdSec(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fr.scripts) != 0 {
		t.Errorf("executou sem confirmação: %v", fr.scripts)
	}
}

func TestCrowdSecMovesLAPIWhen8080IsBusy(t *testing.T) {
	s, _ := session(t, "y", "y", "n", "y")
	s.Host = host(s.HostRoot)
	s.Host.PortFree = func(p int) bool { return p != 8080 && p != 8081 }
	s.Runner = &fakeRunner{outputs: map[string]string{"bouncers add": "K"}}
	os.MkdirAll(s.hostPath("/etc/crowdsec"), 0o755)
	os.WriteFile(s.hostPath("/etc/crowdsec/config.yaml"), []byte("api:\n  server:\n    listen_uri: 127.0.0.1:8080 # padrão\n"), 0o644)
	os.WriteFile(s.hostPath("/etc/crowdsec/local_api_credentials.yaml"), []byte("url: http://127.0.0.1:8080/\nlogin: x\n"), 0o600)
	if err := s.installCrowdSec(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c := readHost(t, s, "/etc/crowdsec/config.yaml"); !strings.Contains(c, "listen_uri: 127.0.0.1:8082 # padrão") {
		t.Errorf("config.yaml:\n%s", c)
	}
	if c := readHost(t, s, "/etc/crowdsec/local_api_credentials.yaml"); !strings.Contains(c, "url: http://127.0.0.1:8082/") {
		t.Errorf("credentials:\n%s", c)
	}
	if s.Cfg.Integrations.CrowdSec.URL != "http://127.0.0.1:8082" {
		t.Errorf("URL no sentinels.yaml: %s", s.Cfg.Integrations.CrowdSec.URL)
	}
}

func TestSuricataAndFalco(t *testing.T) {
	s, _ := session(t, "y", "y", "y", "y")
	s.Host = host(s.HostRoot)
	s.Host.Iface = "ens18"
	compose := filepath.Join(t.TempDir(), "docker-compose.yml")
	os.WriteFile(compose, []byte("    volumes:\n      - sentinels-data:/var/lib/sentinels\n      # - /var/log/suricata:/var/log/suricata:ro\n"), 0o644)
	s.Host.ComposeFile = compose
	fr := &fakeRunner{}
	s.Runner = fr
	if err := s.installSuricata(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !fr.ran("interface: ens18") || !fr.ran("suricata-update") {
		t.Errorf("script do Suricata: %v", fr.scripts)
	}
	if b, _ := os.ReadFile(compose); !strings.Contains(string(b), "      - /var/log/suricata:/var/log/suricata:ro") || strings.Contains(string(b), "# -") {
		t.Errorf("volume não liberado:\n%s", b)
	}
	if s.Cfg.Integrations.Suricata.Enabled != "true" {
		t.Error("suricata não habilitado na config")
	}

	if err := s.installFalco(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fc := readHost(t, s, "/etc/falco/config.d/sentinels.yaml"); !strings.Contains(fc, `url: "http://127.0.0.1:2801/falco"`) || !strings.Contains(fc, "rule_matching: all") {
		t.Errorf("config do Falco:\n%s", fc)
	}
	if rules := readHost(t, s, "/etc/falco/rules.d/sentinels.yaml"); !strings.Contains(rules, "- rule: Sentinels database spawned shell") || !strings.Contains(rules, "T1505.003") {
		t.Errorf("regras do Falco não gravadas:\n%.300s", rules)
	}
	if !fr.ran("FALCO_DRIVER_CHOICE=modern_ebpf") || s.Cfg.Integrations.Falco.Enabled != "true" {
		t.Error("Falco não instalado/habilitado")
	}
}

func TestInstallRefusesWhereItCannotWork(t *testing.T) {
	s, out := session(t)
	s.Host = &HostFacts{InContainer: true, Installed: map[string]bool{}}
	fr := &fakeRunner{}
	s.Runner = fr
	s.sectionInstall(context.Background())
	if len(fr.scripts) != 0 || !strings.Contains(out.String(), "--cli-only") {
		t.Errorf("dentro de container deveria orientar a rodar no host:\n%s", out)
	}
	s.Host = &HostFacts{Root: false, Apt: true, Installed: map[string]bool{}}
	if err := s.sectionInstall(context.Background()); err == nil || !strings.Contains(err.Error(), "root") {
		t.Errorf("sem root: %v", err)
	}
}

func TestPureHelpers(t *testing.T) {
	if got := suricataIfaceScript("eth0; rm -rf /"); got != "" {
		t.Errorf("interface com caracteres perigosos aceita: %q", got)
	}
	if out, changed, _ := addDockerUserChain([]byte("iptables_chains:\n  - INPUT\n  - DOCKER-USER\n")); changed || !strings.Contains(string(out), "DOCKER-USER") {
		t.Error("DOCKER-USER duplicado")
	}
	ps := "traefik_traefik.1.x traefik:v3.1\nn8n n8nio/n8n:1\nnpm jc21/nginx-proxy-manager:latest\n"
	if p := detectProxies(ps); len(p) != 2 || p[0].Kind != "traefik" || p[1].Kind != "nginx" {
		t.Errorf("proxies: %+v", p)
	}
}
