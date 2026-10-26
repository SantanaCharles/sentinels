// Package discovery reads running containers from the Docker Engine API.
// It only issues GET requests; nothing is ever changed on the host.
package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type PortBinding struct {
	ContainerPort string // "5432/tcp"
	HostIP        string // "0.0.0.0", "127.0.0.1", "::"
	HostPort      string
}

// Public reports whether the binding listens on every interface.
func (p PortBinding) Public() bool {
	return p.HostIP == "" || p.HostIP == "0.0.0.0" || p.HostIP == "::"
}

type Mount struct {
	Type        string
	Source      string
	Destination string
	RW          bool
}

type Container struct {
	ID          string
	Name        string
	Image       string
	ImageID     string
	User        string
	EnvKeys     []string          // names only; values are discarded on read
	Versions    map[string]string // runtime versions set by official images, e.g. PHP_VERSION
	Labels      map[string]string
	Privileged  bool
	NetworkMode string
	PidMode     string
	IpcMode     string
	CapAdd      []string
	SecurityOpt []string
	Devices     int
	Memory      int64
	ReadOnlyFS  bool
	Ports       []PortBinding
	Mounts      []Mount
	Pid         int      // host PID of the main process (0 when stopped)
	TTY         bool     // logs come as raw text instead of multiplexed frames
	IPs         []string // addresses on the container's networks
	Gateways    []string // the networks' gateways: traffic from the host itself
}

// versionVars are the only env values kept: official images set them and they
// never hold secrets. Everything else is reduced to its name.
var versionVars = map[string]bool{
	"PHP_VERSION": true, "NODE_VERSION": true, "PYTHON_VERSION": true, "JAVA_VERSION": true,
	"GOLANG_VERSION": true, "RUBY_VERSION": true, "NGINX_VERSION": true, "HTTPD_VERSION": true,
	"PG_VERSION": true, "PG_MAJOR": true, "MYSQL_VERSION": true, "MARIADB_VERSION": true,
	"REDIS_VERSION": true, "MONGO_VERSION": true, "WORDPRESS_VERSION": true, "NEXTCLOUD_VERSION": true,
}

type Client struct {
	http *http.Client
}

// NewClient accepts a Unix socket path ("/var/run/docker.sock", "unix://…")
// or a TCP address ("tcp://127.0.0.1:2375"), the latter meant for a
// read-only socket proxy so the agent never holds the real socket.
func NewClient(socket string) *Client {
	network, addr := "unix", strings.TrimPrefix(socket, "unix://")
	if rest, ok := strings.CutPrefix(socket, "tcp://"); ok {
		network, addr = "tcp", rest
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
	return &Client{http: &http.Client{Transport: tr, Timeout: 15 * time.Second}}
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("API do Docker: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API do Docker %s: HTTP %d", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Ping checks that the socket is reachable.
func (c *Client) Ping(ctx context.Context) error {
	var v struct{ Version string }
	return c.get(ctx, "/version", &v)
}

// Containers returns every running container, fully inspected.
func (c *Client) Containers(ctx context.Context) ([]Container, error) {
	var list []struct{ Id string }
	if err := c.get(ctx, "/containers/json", &list); err != nil {
		return nil, err
	}
	out := make([]Container, 0, len(list))
	for _, item := range list {
		var raw inspect
		if err := c.get(ctx, "/containers/"+url.PathEscape(item.Id)+"/json", &raw); err != nil {
			return nil, err
		}
		out = append(out, raw.toContainer())
	}
	return out, nil
}

// inspect mirrors the subset of GET /containers/{id}/json that the checks use.
type inspect struct {
	Id    string
	Name  string
	Image string
	State struct {
		Pid int
	}
	Config struct {
		Image  string
		User   string
		Env    []string
		Labels map[string]string
		Tty    bool
	}
	HostConfig struct {
		Privileged     bool
		NetworkMode    string
		PidMode        string
		IpcMode        string
		CapAdd         []string
		SecurityOpt    []string
		Devices        []json.RawMessage
		Memory         int64
		ReadonlyRootfs bool
	}
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIp   string
			HostPort string
		}
		Networks map[string]struct {
			IPAddress         string
			GlobalIPv6Address string
			Gateway           string
		}
	}
	Mounts []struct {
		Type        string
		Source      string
		Destination string
		RW          bool
	}
}

func (r inspect) toContainer() Container {
	c := Container{
		ID:          r.Id,
		Name:        strings.TrimPrefix(r.Name, "/"),
		Image:       r.Config.Image,
		ImageID:     r.Image,
		User:        r.Config.User,
		Labels:      r.Config.Labels,
		Privileged:  r.HostConfig.Privileged,
		NetworkMode: r.HostConfig.NetworkMode,
		PidMode:     r.HostConfig.PidMode,
		IpcMode:     r.HostConfig.IpcMode,
		CapAdd:      r.HostConfig.CapAdd,
		SecurityOpt: r.HostConfig.SecurityOpt,
		Devices:     len(r.HostConfig.Devices),
		Memory:      r.HostConfig.Memory,
		ReadOnlyFS:  r.HostConfig.ReadonlyRootfs,
		Pid:         r.State.Pid,
		TTY:         r.Config.Tty,
	}
	for _, n := range r.NetworkSettings.Networks {
		for _, ip := range []string{n.IPAddress, n.GlobalIPv6Address} {
			if ip != "" {
				c.IPs = append(c.IPs, ip)
			}
		}
		if n.Gateway != "" {
			c.Gateways = append(c.Gateways, n.Gateway)
		}
	}
	for _, kv := range r.Config.Env {
		k, v, _ := strings.Cut(kv, "=")
		c.EnvKeys = append(c.EnvKeys, k)
		if versionVars[k] {
			if c.Versions == nil {
				c.Versions = map[string]string{}
			}
			c.Versions[k] = v
		}
	}
	for port, binds := range r.NetworkSettings.Ports {
		for _, b := range binds {
			c.Ports = append(c.Ports, PortBinding{ContainerPort: port, HostIP: b.HostIp, HostPort: b.HostPort})
		}
	}
	for _, m := range r.Mounts {
		c.Mounts = append(c.Mounts, Mount{Type: m.Type, Source: m.Source, Destination: m.Destination, RW: m.RW})
	}
	return c
}
