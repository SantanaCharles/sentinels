package workload

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/SantanaCharles/sentinels/internal/discovery"
	"github.com/SantanaCharles/sentinels/internal/event"
	"github.com/SantanaCharles/sentinels/internal/finding"
)

// Clients learns which containers talk to each database and alerts on a new
// one, or on any connection coming straight from the internet. It reads the
// database container's own TCP table in /proc/<pid>/net, so it works for any
// engine (Postgres, MySQL, Redis, Mongo…) without credentials.
type Clients struct {
	ProcRoot  string        // host /proc ("/host/proc" inside the agent's container)
	StateFile string        // learned baseline, kept across restarts
	Learn     time.Duration // quiet period after a database is first seen

	state    clientState
	loaded   bool
	external map[string]time.Time // db+ip → last alert
}

type clientState struct {
	DBs map[string]*dbBaseline `json:"dbs"`
}

type dbBaseline struct {
	FirstSeen time.Time            `json:"first_seen"`
	Clients   map[string]time.Time `json:"clients"` // label → first seen
}

// Database is a container to watch, with a stable label.
type Database struct {
	Label     string
	Container discovery.Container
}

const externalCooldown = 6 * time.Hour

// Check compares the current connections with the baseline.
func (c *Clients) Check(dbs []Database, all []discovery.Container, now time.Time) ([]event.Event, error) {
	if !c.loaded {
		c.load()
	}
	if c.external == nil {
		c.external = map[string]time.Time{}
	}
	if c.Learn <= 0 {
		c.Learn = 30 * time.Minute
	}
	names, gateways := ipIndex(all)
	var out []event.Event
	changed, readable := false, 0
	for _, db := range dbs {
		if db.Container.Pid <= 0 {
			continue
		}
		peers, err := dbPeers(filepath.Join(c.ProcRoot, strconv.Itoa(db.Container.Pid), "net"))
		if err != nil {
			continue
		}
		readable++
		base := c.state.DBs[db.Label]
		if base == nil {
			base = &dbBaseline{FirstSeen: now, Clients: map[string]time.Time{}}
			c.state.DBs[db.Label] = base
			changed = true
		}
		// An idle database keeps learning until its first client shows up.
		learning := now.Sub(base.FirstSeen) < c.Learn || len(base.Clients) == 0
		for _, ip := range peers {
			if isPublic(ip) {
				k := db.Label + "|" + ip
				if now.Sub(c.external[k]) >= externalCooldown {
					c.external[k] = now
					out = append(out, clientEvent(db.Label, "db-external-client", finding.High, "T1133", now, ip,
						fmt.Sprintf("Banco %s recebendo conexão direta da internet (%s). Bancos não devem ficar expostos: feche a porta ou restrinja ao app.", db.Label, ip)))
				}
				continue
			}
			label := names[ip]
			switch {
			case label == db.Label:
				continue // replicas of the same service
			case label == "" && gateways[ip]:
				label = "host (" + ip + ")"
			case label == "":
				label = ip
			}
			if _, known := base.Clients[label]; known {
				continue
			}
			base.Clients[label] = now
			changed = true
			if !learning {
				out = append(out, clientEvent(db.Label, "db-new-client", finding.Medium, "T1021", now, "",
					fmt.Sprintf("Novo cliente conectando no banco %s: %s. Até agora só conectavam: %s. Se não foi você que subiu esse serviço, investigue.",
						db.Label, label, knownList(base.Clients, label))))
			}
		}
	}
	if len(dbs) > 0 && readable == 0 {
		return out, fmt.Errorf("sem acesso a %s/<pid>/net: monte o /proc do host (veja docs/OPERATIONS.md)", c.ProcRoot)
	}
	if changed {
		c.save()
	}
	return out, nil
}

func knownList(m map[string]time.Time, except string) string {
	var l []string
	for k := range m {
		if k != except {
			l = append(l, k)
		}
	}
	if len(l) == 0 {
		return "ninguém"
	}
	sort.Strings(l)
	if len(l) > 6 {
		l = append(l[:6], "…")
	}
	return strings.Join(l, ", ")
}

func clientEvent(db, rule string, sev finding.Severity, technique string, t time.Time, ip, summary string) event.Event {
	e := event.Event{Source: "dbclients", Rule: rule, Severity: sev, Time: t, Target: db, SourceIP: ip,
		Summary: summary, Technique: technique}
	event.Classify(&e)
	return e
}

// ipIndex maps container IPs to stable labels, and collects network gateways
// (connections from the host itself or published ports).
func ipIndex(all []discovery.Container) (map[string]string, map[string]bool) {
	names, gw := map[string]string{}, map[string]bool{}
	for _, c := range all {
		for _, ip := range c.IPs {
			names[ip] = Label(c)
		}
		for _, g := range c.Gateways {
			gw[g] = true
		}
	}
	return names, gw
}

// Label names a container by its Swarm service or Compose service, which
// survive re-deploys; the container name otherwise.
func Label(c discovery.Container) string {
	if s := c.Labels["com.docker.swarm.service.name"]; s != "" {
		return s
	}
	if s := c.Labels["com.docker.compose.service"]; s != "" {
		if p := c.Labels["com.docker.compose.project"]; p != "" {
			return p + "-" + s
		}
		return s
	}
	return c.Name
}

// dbPeers returns the remote IPs connected to the ports the process listens
// on, from net/tcp and net/tcp6 of its network namespace.
func dbPeers(netDir string) ([]string, error) {
	type conn struct {
		localPort int
		remote    string
	}
	listen := map[int]bool{}
	var established []conn
	opened := 0
	for _, name := range []string{"tcp", "tcp6"} {
		f, err := os.Open(filepath.Join(netDir, name))
		if err != nil {
			continue
		}
		opened++
		sc := bufio.NewScanner(f)
		sc.Scan() // header
		for sc.Scan() {
			fl := strings.Fields(sc.Text())
			if len(fl) < 4 {
				continue
			}
			_, lport, ok1 := hexAddr(fl[1])
			rip, _, ok2 := hexAddr(fl[2])
			if !ok1 || !ok2 {
				continue
			}
			switch fl[3] {
			case "0A":
				listen[lport] = true
			case "01":
				established = append(established, conn{lport, rip})
			}
		}
		f.Close()
	}
	if opened == 0 {
		return nil, os.ErrNotExist
	}
	seen := map[string]bool{}
	var out []string
	for _, c := range established {
		ip := net.ParseIP(c.remote)
		if !listen[c.localPort] || ip == nil || ip.IsLoopback() || seen[c.remote] {
			continue
		}
		seen[c.remote] = true
		out = append(out, c.remote)
	}
	sort.Strings(out)
	return out, nil
}

// hexAddr decodes "0100007F:1538" (IPv4) or the 32-digit IPv6 form; each
// 32-bit word is in host (little-endian) order, the port is big-endian.
func hexAddr(s string) (string, int, bool) {
	a, p, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0, false
	}
	port, err := strconv.ParseInt(p, 16, 32)
	if err != nil {
		return "", 0, false
	}
	raw, err := hex.DecodeString(a)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return "", 0, false
	}
	ip := make(net.IP, len(raw))
	for i := 0; i < len(raw); i += 4 {
		ip[i], ip[i+1], ip[i+2], ip[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String(), int(port), true // also unwraps ::ffff:a.b.c.d
	}
	return ip.String(), int(port), true
}

func (c *Clients) load() {
	c.loaded = true
	c.state = clientState{DBs: map[string]*dbBaseline{}}
	if c.StateFile == "" {
		return
	}
	if b, err := os.ReadFile(c.StateFile); err == nil {
		_ = json.Unmarshal(b, &c.state)
	}
	if c.state.DBs == nil {
		c.state.DBs = map[string]*dbBaseline{}
	}
}

func (c *Clients) save() {
	if c.StateFile == "" {
		return
	}
	b, err := json.MarshalIndent(c.state, "", "  ")
	if err != nil {
		return
	}
	tmp := c.StateFile + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, c.StateFile)
	}
}
