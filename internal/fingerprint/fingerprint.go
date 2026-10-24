// Package fingerprint guesses what runs inside a container from its image,
// environment variable names, labels and HTTP response headers.
package fingerprint

import (
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/SantanaCharles/sentinels/internal/discovery"
)

type Kind string

const (
	KindDatabase   Kind = "database"
	KindCache      Kind = "cache"
	KindProxy      Kind = "proxy"
	KindApp        Kind = "app"
	KindAutomation Kind = "automation"
	KindAdmin      Kind = "admin"
	KindUnknown    Kind = "unknown"
)

type Stack struct {
	Kind       Kind     `json:"kind"`
	Components []string `json:"components"`
}

type imageRule struct {
	match     string
	component string
	kind      Kind
}

// Ordered: the first rule matching the image repository decides Kind.
var imageRules = []imageRule{
	{"postgres", "PostgreSQL", KindDatabase},
	{"postgis", "PostgreSQL", KindDatabase},
	{"timescale", "PostgreSQL", KindDatabase},
	{"mysql", "MySQL", KindDatabase},
	{"mariadb", "MariaDB", KindDatabase},
	{"mongo", "MongoDB", KindDatabase},
	{"elasticsearch", "Elasticsearch", KindDatabase},
	{"opensearch", "OpenSearch", KindDatabase},
	{"clickhouse", "ClickHouse", KindDatabase},
	{"redis", "Redis", KindCache},
	{"valkey", "Valkey", KindCache},
	{"memcached", "Memcached", KindCache},
	{"rabbitmq", "RabbitMQ", KindCache},
	{"traefik", "Traefik", KindProxy},
	{"nginx-proxy-manager", "Nginx Proxy Manager", KindProxy},
	{"nginx", "Nginx", KindProxy},
	{"caddy", "Caddy", KindProxy},
	{"haproxy", "HAProxy", KindProxy},
	{"httpd", "Apache httpd", KindProxy},
	{"pgadmin", "pgAdmin", KindAdmin},
	{"adminer", "Adminer", KindAdmin},
	{"phpmyadmin", "phpMyAdmin", KindAdmin},
	{"portainer", "Portainer", KindAdmin},
	{"grafana", "Grafana", KindAdmin},
	{"n8n", "n8n", KindAutomation},
	{"evolution-api", "Evolution API", KindAutomation},
	{"wordpress", "WordPress", KindApp},
	{"nextcloud", "Nextcloud", KindApp},
	{"moodle", "Moodle", KindApp},
	{"drupal", "Drupal", KindApp},
	{"joomla", "Joomla", KindApp},
	{"magento", "Magento", KindApp},
	{"prestashop", "PrestaShop", KindApp},
	{"opencart", "OpenCart", KindApp},
	{"matomo", "Matomo", KindApp},
	{"mautic", "Mautic", KindApp},
	{"glpi", "GLPI", KindApp},
	{"ghost", "Ghost", KindApp},
	{"supabase", "Supabase", KindApp},
	{"keycloak", "Keycloak", KindApp},
	{"minio", "MinIO", KindApp},
	{"node", "Node.js", KindApp},
	{"bun", "Bun", KindApp},
	{"python", "Python", KindApp},
	{"php", "PHP", KindApp},
	{"openjdk", "Java", KindApp},
	{"eclipse-temurin", "Java", KindApp},
	{"amazoncorretto", "Java", KindApp},
	{"golang", "Go", KindApp},
	{"ruby", "Ruby", KindApp},
	{"dotnet", ".NET", KindApp},
}

// Environment variable name prefixes/names that reveal a framework.
var envRules = []struct{ prefix, component string }{
	{"NEXT_", "Next.js"},
	{"NEXTAUTH_", "NextAuth"},
	{"CLERK_", "Clerk"},
	{"STRIPE_", "Stripe"},
	{"SUPABASE_", "Supabase"},
	{"SPRING_", "Spring Boot"},
	{"DJANGO_", "Django"},
	{"FLASK_", "Flask"},
	{"RAILS_", "Ruby on Rails"},
	{"LARAVEL", "Laravel"},
	{"APP_KEY", "Laravel"},
	{"ASPNETCORE_", "ASP.NET Core"},
	{"NODE_ENV", "Node.js"},
	{"PRISMA_", "Prisma"},
	{"N8N_", "n8n"},
	{"PHP_", "PHP"},
}

// Components that always run on PHP.
var phpBased = map[string]bool{
	"WordPress": true, "Nextcloud": true, "Moodle": true, "Drupal": true, "Joomla": true,
	"Magento": true, "PrestaShop": true, "OpenCart": true, "Matomo": true, "Mautic": true,
	"GLPI": true, "Laravel": true, "phpMyAdmin": true, "Adminer": true,
}

// IsPHP reports whether the stack runs PHP.
func (s Stack) IsPHP() bool {
	for _, c := range s.Components {
		if c == "PHP" {
			return true
		}
	}
	return false
}

func repo(image string) string {
	image = strings.ToLower(image)
	if i := strings.Index(image, "@"); i >= 0 {
		image = image[:i]
	}
	if i := strings.LastIndex(image, ":"); i > strings.LastIndex(image, "/") {
		image = image[:i]
	}
	return image
}

// Detect fingerprints a container from static metadata.
func Detect(c discovery.Container) Stack {
	set := map[string]bool{}
	kind := KindUnknown
	r := repo(c.Image)
	for _, rule := range imageRules {
		if strings.Contains(r, rule.match) {
			set[rule.component] = true
			if kind == KindUnknown {
				kind = rule.kind
			}
		}
	}
	for _, k := range c.EnvKeys {
		for _, rule := range envRules {
			if strings.HasPrefix(k, rule.prefix) {
				set[rule.component] = true
			}
		}
	}
	for k := range c.Labels {
		if strings.HasPrefix(k, "traefik.") {
			set["exposto via Traefik"] = true
		}
	}
	for comp := range set {
		if phpBased[comp] {
			set["PHP"] = true
			break
		}
	}
	if _, ok := c.Versions["PHP_VERSION"]; ok {
		set["PHP"] = true
	}
	if kind == KindUnknown && len(set) > 0 {
		kind = KindApp
	}
	return Stack{Kind: kind, Components: sorted(set)}
}

var phpHeaderRe = regexp.MustCompile(`(?i)PHP/(\d+\.\d+\.\d+)(\S*)`)

// PHPVersionFromHeaders returns the version in "X-Powered-By: PHP/8.3.12" and
// any distribution suffix such as "-1ubuntu2.3".
func PHPVersionFromHeaders(h http.Header) (version, suffix string) {
	for _, v := range []string{h.Get("X-Powered-By"), h.Get("Server")} {
		if m := phpHeaderRe.FindStringSubmatch(v); m != nil {
			return m[1], m[2]
		}
	}
	return "", ""
}

// FromHeaders extracts components from an HTTP response.
func FromHeaders(h http.Header) []string {
	set := map[string]bool{}
	if v := h.Get("Server"); v != "" {
		set["Server: "+v] = true
	}
	if v := h.Get("X-Powered-By"); v != "" {
		set["X-Powered-By: "+v] = true
		if strings.HasPrefix(strings.ToLower(v), "php") {
			set["PHP"] = true
		}
	}
	for k := range h {
		lk := strings.ToLower(k)
		switch {
		case strings.HasPrefix(lk, "x-nextjs-"):
			set["Next.js"] = true
		case lk == "x-vercel-id":
			set["Vercel"] = true
		case lk == "cf-ray":
			set["Cloudflare"] = true
		}
	}
	return sorted(set)
}

func sorted(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
