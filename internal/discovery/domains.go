package discovery

import (
	"context"
	"regexp"
	"sort"
	"strings"
)

var (
	hostRuleRe = regexp.MustCompile(`Host\(([^)]*)\)`)
	quotedRe   = regexp.MustCompile("[`\"']([^`\"'\\s]+)[`\"']")
	domainRe   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
)

// DomainsFromLabels extracts public hostnames from reverse-proxy labels:
// Traefik routers (traefik.http.routers.X.rule=Host(`a.com`)) and
// caddy-docker-proxy (caddy=a.com). Wildcards and regex rules are skipped.
func DomainsFromLabels(labels map[string]string) []string {
	set := map[string]bool{}
	add := func(d string) {
		d = strings.ToLower(strings.TrimSpace(d))
		if domainRe.MatchString(d) && !strings.HasSuffix(d, ".localhost") && !strings.HasSuffix(d, ".local") {
			set[d] = true
		}
	}
	for k, v := range labels {
		switch {
		case strings.HasPrefix(k, "traefik.http.routers.") && strings.HasSuffix(k, ".rule"):
			for _, m := range hostRuleRe.FindAllStringSubmatch(v, -1) {
				for _, q := range quotedRe.FindAllStringSubmatch(m[1], -1) {
					add(q[1])
				}
			}
		case k == "caddy" || strings.HasPrefix(k, "caddy_"):
			if strings.Contains(k, ".") { // caddy.reverse_proxy etc. are directives, not sites
				continue
			}
			for _, d := range strings.FieldsFunc(v, func(r rune) bool { return r == ' ' || r == ',' }) {
				add(strings.TrimPrefix(strings.TrimPrefix(d, "https://"), "http://"))
			}
		}
	}
	out := make([]string, 0, len(set))
	for d := range set {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// ServiceLabels returns the labels of Swarm services, where Traefik reads its
// routers in Swarm mode. Outside Swarm (or if the proxy blocks /services)
// it returns nothing and no error.
func (c *Client) ServiceLabels(ctx context.Context) []map[string]string {
	var svcs []struct {
		Spec struct {
			Labels map[string]string
		}
	}
	if err := c.get(ctx, "/services", &svcs); err != nil {
		return nil
	}
	out := make([]map[string]string, 0, len(svcs))
	for _, s := range svcs {
		out = append(out, s.Spec.Labels)
	}
	return out
}
