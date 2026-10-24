// Package checks holds the configuration audits. Each check is a pure
// function over discovered data so it can be unit tested without Docker.
package checks

import (
	"fmt"
	"strings"

	"github.com/SantanaCharles/sentinels/internal/discovery"
	"github.com/SantanaCharles/sentinels/internal/finding"
	"github.com/SantanaCharles/sentinels/internal/fingerprint"
)

const cisRef = "CIS Docker Benchmark v1.6"

// Host paths whose mount gives a container control over the host.
var sensitiveHostPaths = []string{"/", "/etc", "/root", "/boot", "/proc", "/sys", "/dev", "/var/lib/docker", "/usr"}

// Capabilities that are close to full root on the host.
var dangerousCaps = map[string]bool{
	"ALL": true, "SYS_ADMIN": true, "SYS_PTRACE": true, "SYS_MODULE": true,
	"NET_ADMIN": true, "DAC_READ_SEARCH": true, "SYS_RAWIO": true, "BPF": true,
}

// Env var names that suggest a secret passed in plain text.
var secretHints = []string{"PASSWORD", "PASSWD", "SECRET", "TOKEN", "API_KEY", "APIKEY", "PRIVATE_KEY", "DATABASE_URL", "DSN"}

// Container audits one container's runtime configuration.
func Container(c discovery.Container, st fingerprint.Stack) []finding.Finding {
	var out []finding.Finding
	add := func(f finding.Finding) {
		f.Target = c.Name
		if f.CIS != "" {
			f.References = append(f.References, cisRef+" "+f.CIS)
		}
		out = append(out, f)
	}

	if c.Privileged {
		add(finding.Finding{
			ID: "container.privileged", Severity: finding.Critical, CIS: "5.5", CWE: []string{"CWE-250"},
			Title:       "Container privilegiado",
			Detail:      "Com --privileged o container tem acesso a todos os dispositivos e capacidades do kernel; escapar para o host é trivial.",
			Remediation: "Remova `privileged: true` e conceda apenas as capacidades necessárias com `cap_add`.",
		})
	}

	for _, m := range c.Mounts {
		if m.Source == "/var/run/docker.sock" || m.Source == "/run/docker.sock" {
			sev := finding.Critical
			detail := "Quem controla o socket do Docker controla o host inteiro."
			if !m.RW {
				sev = finding.High
				detail += " Montado como somente leitura, ainda permite ler segredos de todos os containers."
			}
			add(finding.Finding{
				ID: "container.docker_socket", Severity: sev, CIS: "5.32", CWE: []string{"CWE-269"},
				Title:       "Socket do Docker montado no container",
				Detail:      detail,
				Remediation: "Remova o volume do socket. Se for indispensável (proxy reverso, monitoramento), use um proxy de socket com permissões mínimas como tecnativa/docker-socket-proxy.",
			})
			continue
		}
		if isSensitivePath(m.Source) {
			sev := finding.High
			if m.RW {
				sev = finding.Critical
			}
			add(finding.Finding{
				ID: "container.sensitive_mount", Severity: sev, CIS: "5.6", CWE: []string{"CWE-668"},
				Title:       fmt.Sprintf("Diretório sensível do host montado: %s", m.Source),
				Detail:      fmt.Sprintf("%s está montado em %s (%s).", m.Source, m.Destination, rwLabel(m.RW)),
				Remediation: "Monte apenas o subdiretório necessário e, quando possível, como somente leitura (`:ro`).",
			})
		}
	}

	if c.NetworkMode == "host" {
		add(finding.Finding{
			ID: "container.host_network", Severity: finding.High, CIS: "5.10", CWE: []string{"CWE-668"},
			Title:       "Container usa a rede do host",
			Detail:      "Todas as portas do container ficam expostas diretamente no host e o isolamento de rede é perdido.",
			Remediation: "Use uma rede bridge e publique só as portas necessárias.",
		})
	}
	if c.PidMode == "host" {
		add(finding.Finding{
			ID: "container.host_pid", Severity: finding.High, CIS: "5.16", CWE: []string{"CWE-668"},
			Title:       "Container compartilha os processos do host",
			Remediation: "Remova `pid: host`.",
		})
	}
	if c.IpcMode == "host" {
		add(finding.Finding{
			ID: "container.host_ipc", Severity: finding.Medium, CIS: "5.17", CWE: []string{"CWE-668"},
			Title:       "Container compartilha o IPC do host",
			Remediation: "Remova `ipc: host`.",
		})
	}

	var caps []string
	for _, cp := range c.CapAdd {
		if dangerousCaps[strings.TrimPrefix(strings.ToUpper(cp), "CAP_")] {
			caps = append(caps, cp)
		}
	}
	if len(caps) > 0 {
		add(finding.Finding{
			ID: "container.dangerous_caps", Severity: finding.High, CIS: "5.4", CWE: []string{"CWE-250"},
			Title:       "Capacidades perigosas do kernel concedidas",
			Detail:      "cap_add: " + strings.Join(caps, ", "),
			Remediation: "Remova as capacidades que a aplicação não usa; prefira `cap_drop: [ALL]` e adicione só o mínimo.",
		})
	}

	if c.Devices > 0 {
		add(finding.Finding{
			ID: "container.devices", Severity: finding.Medium, CIS: "5.18",
			Title:       "Dispositivos do host expostos ao container",
			Detail:      fmt.Sprintf("%d dispositivo(s) mapeado(s).", c.Devices),
			Remediation: "Mapeie apenas os dispositivos indispensáveis.",
		})
	}

	if isRoot(c.User) {
		add(finding.Finding{
			ID: "container.root_user", Severity: finding.Medium, CIS: "4.1", CWE: []string{"CWE-250"},
			Title:       "Processo principal roda como root",
			Detail:      "Uma falha na aplicação dá ao invasor root dentro do container, o que facilita escapar para o host.",
			Remediation: "Defina `USER` no Dockerfile ou `user:` no compose com um usuário sem privilégios.",
		})
	}

	if !hasSecOpt(c.SecurityOpt, "no-new-privileges") {
		add(finding.Finding{
			ID: "container.no_new_privileges", Severity: finding.Low, CIS: "5.26",
			Title:       "no-new-privileges não está ativo",
			Remediation: "Adicione `security_opt: [\"no-new-privileges:true\"]`.",
		})
	}

	if c.Memory == 0 {
		add(finding.Finding{
			ID: "container.no_memory_limit", Severity: finding.Low, CIS: "5.11", CWE: []string{"CWE-770"},
			Title:       "Sem limite de memória",
			Detail:      "Um vazamento ou abuso nesse container pode derrubar todos os outros serviços da VPS.",
			Remediation: "Defina `mem_limit` (ou `deploy.resources.limits.memory`).",
		})
	}

	out = append(out, exposure(c, st)...)

	var secretKeys []string
	for _, k := range c.EnvKeys {
		if looksSecret(k) {
			secretKeys = append(secretKeys, k)
		}
	}
	if len(secretKeys) > 0 {
		add(finding.Finding{
			ID: "container.env_secrets", Severity: finding.Low, CWE: []string{"CWE-526"},
			Title:       "Segredos passados como variável de ambiente",
			Detail:      "Variáveis: " + strings.Join(secretKeys, ", ") + ". Qualquer pessoa com acesso ao Docker lê os valores com `docker inspect`. (O Sentinels não lê os valores.)",
			Remediation: "Use Docker secrets ou arquivos montados com permissão restrita, e restrinja quem acessa o Docker.",
		})
	}
	return out
}

// exposure flags services that should never be reachable from the internet.
func exposure(c discovery.Container, st fingerprint.Stack) []finding.Finding {
	var out []finding.Finding
	seen := map[string]bool{}
	for _, p := range c.Ports {
		if !p.Public() || seen[p.HostPort] {
			continue
		}
		seen[p.HostPort] = true
		switch st.Kind {
		case fingerprint.KindDatabase, fingerprint.KindCache:
			out = append(out, finding.Finding{
				ID: "exposure.database_public", Severity: finding.Critical, Target: c.Name, CIS: "5.14", CWE: []string{"CWE-668"},
				Title:       fmt.Sprintf("%s publicado em todas as interfaces (porta %s)", strings.Join(st.Components, "/"), p.HostPort),
				Detail:      "O serviço aceita conexões de qualquer endereço da internet. Bancos e caches expostos são alvo constante de varreduras automáticas e ataques de senha.",
				Remediation: fmt.Sprintf("Publique só em localhost (`127.0.0.1:%s:%s`) ou remova a publicação e use a rede interna do Docker. Para acesso administrativo, use túnel SSH ou VPN.", p.HostPort, strings.Split(p.ContainerPort, "/")[0]),
				References:  []string{cisRef + " 5.14"},
			})
		case fingerprint.KindAdmin:
			out = append(out, finding.Finding{
				ID: "exposure.admin_public", Severity: finding.High, Target: c.Name, CWE: []string{"CWE-668"},
				Title:       fmt.Sprintf("Painel administrativo %s publicado na porta %s", strings.Join(st.Components, "/"), p.HostPort),
				Remediation: "Coloque o painel atrás de VPN, túnel SSH ou autenticação adicional no proxy, e restrinja por IP.",
			})
		}
	}
	return out
}

func isSensitivePath(src string) bool {
	src = strings.TrimRight(src, "/")
	if src == "" {
		src = "/"
	}
	for _, p := range sensitiveHostPaths {
		if src == p {
			return true
		}
	}
	return false
}

func isRoot(user string) bool {
	u, _, _ := strings.Cut(user, ":")
	return u == "" || u == "root" || u == "0"
}

func hasSecOpt(opts []string, name string) bool {
	for _, o := range opts {
		if o == name || strings.HasPrefix(o, name+":true") || strings.HasPrefix(o, name+"=true") {
			return true
		}
	}
	return false
}

func looksSecret(key string) bool {
	k := strings.ToUpper(key)
	if strings.HasSuffix(k, "_FILE") { // already points at a secrets file
		return false
	}
	for _, h := range secretHints {
		if strings.Contains(k, h) {
			return true
		}
	}
	return false
}

func rwLabel(rw bool) string {
	if rw {
		return "leitura e escrita"
	}
	return "somente leitura"
}
