package setup

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/SantanaCharles/sentinels/internal/discovery"
)

// Runner executes shell scripts on the host. The setup always shows a script
// and asks before calling Run; tests replace it with a recorder.
type Runner interface {
	// Run streams the script's output to the terminal.
	Run(ctx context.Context, script string) error
	// Output returns stdout (e.g. a key printed by cscli).
	Output(ctx context.Context, script string) (string, error)
}

type shellRunner struct{ out io.Writer }

func (r shellRunner) Run(ctx context.Context, script string) error {
	cmd := exec.CommandContext(ctx, "sh", "-c", "set -e\n"+script)
	cmd.Stdout, cmd.Stderr = r.out, r.out
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	return cmd.Run()
}

func (r shellRunner) Output(ctx context.Context, script string) (string, error) {
	cmd := exec.CommandContext(ctx, "sh", "-c", script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}

// Proxy is a reverse-proxy container whose access log CrowdSec can read.
type Proxy struct {
	Container string
	Kind      string // traefik | nginx | caddy
}

// HostFacts is what the installer needs to know about the machine.
type HostFacts struct {
	Root        bool
	InContainer bool
	Apt         bool            // Debian/Ubuntu family
	Installed   map[string]bool // crowdsec, suricata, falco, trivy, docker
	Proxies     []Proxy         // reverse proxies running in Docker
	PortFree    func(int) bool  // true when 127.0.0.1:port can be bound
	Iface       string          // interface of the default route
	AdminIP     string          // client IP of the current SSH session
	ComposeFile string          // docker-compose.yml next to the config, if any
	SystemdUnit bool            // sentinels.service is installed
	OSName      string
	Extra       map[string]string // free-form, for messages
}

func probeHost(configPath string) HostFacts {
	f := HostFacts{
		Root: os.Geteuid() == 0,
		// SENTINELS_INSTALL_IN_CONTAINER=1: advanced/testing — a container
		// that is meant to act as the host (systemd inside, privileged).
		InContainer: os.Getenv("SENTINELS_INSTALL_IN_CONTAINER") != "1" &&
			(discovery.SelfContainerID("/proc") != "" || fileExists("/.dockerenv")),
		Installed: map[string]bool{},
		PortFree: func(port int) bool {
			ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
			if err != nil {
				return false
			}
			ln.Close()
			return true
		},
	}
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		vals := parseOSRelease(b)
		f.OSName = vals["PRETTY_NAME"]
		like := vals["ID"] + " " + vals["ID_LIKE"]
		f.Apt = strings.Contains(like, "debian") || strings.Contains(like, "ubuntu")
	}
	for name, bin := range map[string]string{"crowdsec": "cscli", "suricata": "suricata", "falco": "falco", "trivy": "trivy", "docker": "docker"} {
		_, err := exec.LookPath(bin)
		f.Installed[name] = err == nil
	}
	if f.Installed["docker"] {
		if out, err := exec.Command("docker", "ps", "--format", "{{.Names}} {{.Image}}").Output(); err == nil {
			f.Proxies = detectProxies(string(out))
		}
	}
	if out, err := exec.Command("sh", "-c", "ip route show default 2>/dev/null | awk '{print $5; exit}'").Output(); err == nil {
		f.Iface = strings.TrimSpace(string(out))
	}
	if c := strings.Fields(os.Getenv("SSH_CLIENT")); len(c) > 0 && net.ParseIP(c[0]) != nil {
		f.AdminIP = c[0]
	}
	if p := filepath.Join(filepath.Dir(configPath), "docker-compose.yml"); fileExists(p) {
		f.ComposeFile = p
	}
	f.SystemdUnit = fileExists("/etc/systemd/system/sentinels.service")
	return f
}

func parseOSRelease(b []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if ok {
			out[k] = strings.Trim(v, `"`)
		}
	}
	return out
}

// detectProxies reads "name image" lines from docker ps.
func detectProxies(psOutput string) []Proxy {
	var out []Proxy
	for _, line := range strings.Split(psOutput, "\n") {
		name, image, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		img := strings.ToLower(image)
		switch {
		case strings.Contains(img, "traefik"):
			out = append(out, Proxy{name, "traefik"})
		case strings.Contains(img, "nginx-proxy-manager"), strings.Contains(img, "nginx"):
			out = append(out, Proxy{name, "nginx"})
		case strings.Contains(img, "caddy"):
			out = append(out, Proxy{name, "caddy"})
		}
	}
	return out
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
