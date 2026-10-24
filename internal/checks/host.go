package checks

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/SantanaCharles/sentinels/internal/finding"
)

// Services that should listen only on localhost or a private network.
var sensitivePorts = map[int]string{
	5432: "PostgreSQL", 3306: "MySQL/MariaDB", 27017: "MongoDB", 6379: "Redis",
	9200: "Elasticsearch", 11211: "Memcached", 5984: "CouchDB", 8086: "InfluxDB",
	2375: "API do Docker sem TLS", 2379: "etcd", 15672: "RabbitMQ (painel)",
}

// HostListeners finds services bound to every interface on the host itself
// (outside Docker), e.g. a PostgreSQL installed with apt. skipPorts holds
// ports already reported for a container.
func HostListeners(procRoot string, skipPorts map[int]bool) []finding.Finding {
	seen := map[int]bool{}
	for _, f := range []string{"net/tcp", "net/tcp6"} {
		for _, port := range publicListeners(procRoot + "/" + f) {
			seen[port] = true
		}
	}
	var out []finding.Finding
	for port := range seen {
		svc, ok := sensitivePorts[port]
		if !ok || skipPorts[port] {
			continue
		}
		sev := finding.High
		detail := "O serviço escuta em todas as interfaces. Se o firewall não bloquear a porta, ele está acessível pela internet."
		if port == 2375 {
			sev = finding.Critical
			detail = "A API do Docker sem TLS em todas as interfaces dá controle total do servidor a quem alcançar a porta."
		}
		out = append(out, finding.Finding{
			ID: "host.public_listener", Severity: sev, Target: fmt.Sprintf("host:%d", port), CWE: []string{"CWE-668"},
			Title:       fmt.Sprintf("%s escutando em 0.0.0.0:%d", svc, port),
			Detail:      detail,
			Remediation: "Configure o serviço para escutar só em 127.0.0.1 (PostgreSQL: `listen_addresses = 'localhost'`), bloqueie a porta no firewall (`ufw deny " + strconv.Itoa(port) + "`) e use túnel SSH ou VPN para acesso remoto.",
		})
	}
	return out
}

// publicListeners parses /proc/net/tcp{,6}: state 0A is LISTEN, and an
// all-zero local address means every interface.
func publicListeners(path string) []int {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var ports []int
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 || fields[3] != "0A" {
			continue
		}
		addr, portHex, ok := strings.Cut(fields[1], ":")
		if !ok || strings.Trim(addr, "0") != "" {
			continue
		}
		if p, err := strconv.ParseInt(portHex, 16, 32); err == nil {
			ports = append(ports, int(p))
		}
	}
	return ports
}
