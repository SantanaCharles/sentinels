// Package scan runs a full audit and collects the results for the report.
package scan

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/SantanaCharles/sentinels/internal/checks"
	"github.com/SantanaCharles/sentinels/internal/config"
	"github.com/SantanaCharles/sentinels/internal/discovery"
	"github.com/SantanaCharles/sentinels/internal/finding"
	"github.com/SantanaCharles/sentinels/internal/fingerprint"
	"github.com/SantanaCharles/sentinels/internal/integrations"
	"github.com/SantanaCharles/sentinels/internal/intel"
	"github.com/SantanaCharles/sentinels/internal/version"
)

type Options struct {
	ProcRoot string // "/proc", or "/host/proc" when running in a container
	NoTrivy  bool
	Log      func(format string, args ...any)
}

type Asset struct {
	Name        string            `json:"name"`
	Image       string            `json:"image"`
	Stack       fingerprint.Stack `json:"stack"`
	PublicPorts []string          `json:"public_ports,omitempty"`
	LocalPorts  []string          `json:"local_ports,omitempty"`
	Versions    map[string]string `json:"versions,omitempty"`
}

type IntelStatus struct {
	Advisories int  `json:"advisories"`
	KEV        bool `json:"kev"`
	KEVEntries int  `json:"kev_entries,omitempty"`
	EPSS       bool `json:"epss"`
	Trivy      bool `json:"trivy"`
	// KernelCVEsSkipped counts CVEs of kernel packages inside images, which do
	// not apply to containers (they run on the host kernel).
	KernelCVEsSkipped int `json:"kernel_cves_skipped,omitempty"`
}

type Result struct {
	Version  string            `json:"sentinels_version"`
	Host     string            `json:"host"`
	Started  time.Time         `json:"started"`
	Duration string            `json:"duration"`
	Assets   []Asset           `json:"assets"`
	Findings []finding.Finding `json:"findings"`
	Warnings []string          `json:"warnings,omitempty"`
	Intel    IntelStatus       `json:"intel"`
	History  *History          `json:"history,omitempty"` // nil when the local store is unavailable
	// AISummary is the model's executive summary (already sanitized), if enabled.
	AISummary string `json:"ai_summary,omitempty"`
}

// History compares this scan with the previous one.
type History struct {
	New      int      `json:"new"`
	Resolved []string `json:"resolved,omitempty"`
	First    bool     `json:"first,omitempty"` // baseline scan: findings are not alerted one by one
}

func Run(ctx context.Context, cfg config.Config, opt Options) *Result {
	if opt.Log == nil {
		opt.Log = func(string, ...any) {}
	}
	if opt.ProcRoot == "" {
		opt.ProcRoot = "/proc"
	}
	host, _ := os.Hostname()
	res := &Result{Version: version.Version, Host: host, Started: time.Now()}
	warn := func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		res.Warnings = append(res.Warnings, msg)
		opt.Log("aviso: %s", msg)
	}

	advs, err := intel.LoadAdvisories(ctx, cfg.Scan.CacheDir, cfg.Scan.Offline)
	if err != nil {
		warn("feed de alertas emergenciais indisponível, usando a lista embutida: %v", err)
	}
	res.Intel.Advisories = len(advs)

	web := checks.NewWebChecker()
	publishedPorts := map[int]bool{}

	opt.Log("lendo containers em %s", cfg.Docker.Socket)
	dc := discovery.NewClient(cfg.Docker.Socket)
	containers, err := dc.Containers(ctx)
	if err != nil {
		warn("não foi possível ler os containers (%v); seguindo só com host, URLs e bancos", err)
	}

	// The agent's own container needs the Docker socket by design.
	selfID := discovery.SelfContainerID("/proc")
	for _, c := range containers {
		if discovery.IsSelf(c, selfID) {
			continue
		}
		st := fingerprint.Detect(c)
		asset := Asset{Name: c.Name, Image: c.Image, Versions: c.Versions}
		res.Findings = append(res.Findings, checks.Container(c, st)...)

		var phpVersion, phpSuffix, phpSource string
		if v := c.Versions["PHP_VERSION"]; v != "" {
			phpVersion, phpSource = v, "PHP_VERSION da imagem"
		}
		serverApache := false

		ports := map[string]bool{}
		for _, p := range c.Ports {
			if n, err := strconv.Atoi(p.HostPort); err == nil {
				publishedPorts[n] = true
			}
			label := p.HostPort + "→" + p.ContainerPort
			if p.Public() {
				asset.PublicPorts = appendOnce(asset.PublicPorts, label)
			} else {
				asset.LocalPorts = appendOnce(asset.LocalPorts, label)
			}
			if st.Kind == fingerprint.KindDatabase || st.Kind == fingerprint.KindCache || ports[p.HostPort] ||
				!strings.HasSuffix(p.ContainerPort, "/tcp") {
				continue
			}
			ports[p.HostPort] = true
			for _, scheme := range []string{"http", "https"} {
				r := web.Check(ctx, scheme+"://127.0.0.1:"+p.HostPort, c.Name)
				if !r.Reachable {
					continue
				}
				opt.Log("  %s: HTTP em %s", c.Name, r.URL)
				res.Findings = append(res.Findings, r.Findings...)
				st.Components = mergeSorted(st.Components, r.Components)
				if phpVersion == "" {
					if v, s := phpFromComponents(r.Components); v != "" {
						phpVersion, phpSuffix, phpSource = v, s, "header da resposta HTTP"
					}
				}
				for _, comp := range r.Components {
					if strings.Contains(strings.ToLower(comp), "apache") {
						serverApache = true
					}
				}
				break
			}
		}
		asset.Stack = st
		res.Assets = append(res.Assets, asset)

		if st.IsPHP() {
			pv := checks.ProductVersion{
				Target: c.Name, Product: "php",
				Version: phpVersion, Suffix: phpSuffix, Source: phpSource,
				ModPHP: strings.Contains(strings.ToLower(c.Image), "apache") || serverApache,
			}
			res.Findings = append(res.Findings, checks.Advisories(pv, advs)...)
		}
		opt.Log("  %s: %s %v", c.Name, st.Kind, st.Components)
	}

	for _, u := range cfg.Scan.URLs {
		r := web.Check(ctx, u, u)
		if !r.Reachable {
			warn("URL %s não respondeu", u)
			continue
		}
		res.Findings = append(res.Findings, r.Findings...)
		if v, suffix := phpFromComponents(r.Components); v != "" {
			res.Findings = append(res.Findings, checks.Advisories(checks.ProductVersion{
				Target: u, Product: "php", Version: v, Suffix: suffix, Source: "header da resposta HTTP",
			}, advs)...)
		}
	}
	res.Findings = append(res.Findings, checks.HostListeners(opt.ProcRoot, publishedPorts)...)

	for _, db := range cfg.Databases {
		if db.Driver != "" && db.Driver != "postgres" {
			warn("banco %s: driver %q ainda não suportado", db.Name, db.Driver)
			continue
		}
		dsn := config.Secret(db.DSNEnv)
		if dsn == "" {
			warn("banco %s: variável %s vazia", db.Name, db.DSNEnv)
			continue
		}
		opt.Log("auditando RLS em %s", db.Name)
		fs, err := checks.Postgres(ctx, db.Name, dsn, db.AppRole)
		if err != nil {
			warn("banco %s: %v", db.Name, err)
			continue
		}
		res.Findings = append(res.Findings, fs...)
	}

	res.Findings = append(res.Findings, runTrivy(ctx, cfg, opt, containers, res, warn)...)

	if cves := intel.CVEs(res.Findings); len(cves) > 0 && !cfg.Scan.Offline {
		kev, err := intel.LoadKEV(ctx, cfg.Scan.CacheDir)
		if err != nil {
			warn("catálogo CISA KEV indisponível: %v", err)
		} else {
			res.Intel.KEV, res.Intel.KEVEntries = true, len(kev)
		}
		epss, err := intel.LoadEPSS(ctx, cves)
		if err != nil {
			warn("EPSS indisponível: %v", err)
		} else {
			res.Intel.EPSS = true
		}
		intel.Enrich(res.Findings, kev, epss)
	} else if cfg.Scan.Offline {
		warn("modo offline: CVEs sem enriquecimento CISA KEV/EPSS")
	}

	finding.Sort(res.Findings)
	res.Duration = time.Since(res.Started).Round(time.Second).String()
	return res
}

func runTrivy(ctx context.Context, cfg config.Config, opt Options, cs []discovery.Container, res *Result, warn func(string, ...any)) []finding.Finding {
	mode := strings.ToLower(cfg.Integrations.Trivy.Enabled)
	if opt.NoTrivy || mode == "false" {
		return nil
	}
	if _, ok := integrations.TrivyAvailable(); !ok {
		if mode == "true" {
			warn("trivy habilitado mas não encontrado no PATH")
		} else {
			warn("trivy não instalado: CVEs das imagens não foram verificadas (veja `sentinels doctor`)")
		}
		return nil
	}
	res.Intel.Trivy = true
	byImage := map[string][]string{}
	for _, c := range cs {
		byImage[c.Image] = append(byImage[c.Image], c.Name)
	}
	images := make([]string, 0, len(byImage))
	for img := range byImage {
		images = append(images, img)
	}
	sort.Strings(images)
	var out []finding.Finding
	for _, img := range images {
		opt.Log("trivy: %s", img)
		fs, skipped, err := integrations.TrivyImage(ctx, img, strings.Join(byImage[img], ", "))
		if err != nil {
			warn("%v", err)
			continue
		}
		out = append(out, fs...)
		res.Intel.KernelCVEsSkipped += skipped
	}
	return out
}

func phpFromComponents(comps []string) (string, string) {
	for _, c := range comps {
		if v, s := fingerprint.PHPVersionFromHeaders(map[string][]string{"X-Powered-By": {strings.TrimPrefix(c, "X-Powered-By: ")}}); v != "" {
			return v, s
		}
	}
	return "", ""
}

func appendOnce(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func mergeSorted(a, b []string) []string {
	for _, v := range b {
		a = appendOnce(a, v)
	}
	sort.Strings(a)
	return a
}
