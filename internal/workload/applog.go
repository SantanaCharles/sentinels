package workload

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/SantanaCharles/sentinels/internal/event"
	"github.com/SantanaCharles/sentinels/internal/finding"
)

// App analyzes an application container's log: database errors leaking into
// it, and access lines (Apache/Nginx combined format or JSON) to spot a user
// walking through other people's IDs or guessing passwords.
type App struct {
	Target string
	sqlErr *burst
	login  *burst
	actors map[string]*actorWindow
}

func NewApp(target string) *App {
	return &App{Target: target, sqlErr: newBurst(5, 5*time.Minute), login: newBurst(20, 5*time.Minute),
		actors: map[string]*actorWindow{}}
}

const (
	enumWindow    = 5 * time.Minute
	enumRequests  = 30 // denied requests by one actor in the window…
	enumDistinct  = 10 // …to at least this many different paths
	maxActorHits  = 500
	maxActorCount = 5000
)

var sqlErrorRe = regexp.MustCompile(`(?i)SQLSTATE\[|syntax error at or near|unterminated quoted string|You have an error in your SQL syntax|ER_PARSE_ERROR|QueryFailedError|SequelizeDatabaseError|psycopg2?\.errors\.|PG::SyntaxError|Raw query failed|invalid input syntax for type|SQLITE_ERROR`)

// combinedRe: 203.0.113.7 - user [date] "GET /path HTTP/1.1" 403 ...
var combinedRe = regexp.MustCompile(`^(\S+) \S+ (\S+) \[[^\]]+\] "([A-Z]+) ([^" ]+)[^"]*" (\d{3}) `)

type access struct {
	ip, user, path string
	status         int
}

// Line feeds one log line.
func (a *App) Line(text string, t time.Time) []event.Event {
	if sqlErrorRe.MatchString(text) {
		if mk := sqliMarker(text); mk != "" {
			return []event.Event{a.event("app-sqli-attempt", finding.Critical, "T1190", t,
				"Tentativa de SQL injection: erro de SQL com "+mk+" no log da aplicação", text, "")}
		}
		if a.sqlErr.add("sql", t) {
			return []event.Event{a.event("app-sql-error-burst", finding.High, "T1190", t,
				"Rajada de erros de SQL na aplicação: padrão de quem testa SQL injection", text, "")}
		}
		return nil
	}
	acc, ok := parseAccess(text)
	if !ok {
		return nil
	}
	actor, ip := "", ""
	switch {
	case acc.user != "":
		actor = "usuário " + acc.user
		if isPublic(acc.ip) {
			ip = acc.ip
		}
	case isPublic(acc.ip):
		actor, ip = "IP "+acc.ip, acc.ip
	default:
		return nil // behind a proxy without the real IP or user: no way to tell people apart
	}
	switch acc.status {
	case 401:
		if a.login.add(actor, t) {
			e := a.event("app-login-bruteforce", finding.High, "T1110", t,
				fmt.Sprintf("Muitas tentativas de login negadas (%s): possível força bruta", actor), "", actor)
			e.SourceIP = ip
			return []event.Event{e}
		}
	case 403, 404:
		w := a.window(actor)
		if n, distinct := w.add(acc.path, t); n >= enumRequests && distinct >= enumDistinct {
			delete(a.actors, actor)
			sev := finding.Medium
			if acc.user != "" {
				sev = finding.High // a logged-in user going through other records
			}
			e := a.event("app-enumeration", sev, "T1213", t,
				fmt.Sprintf("Possível enumeração de IDs (IDOR) por %s: %d acessos negados em %d endereços diferentes em 5 min", actor, n, distinct),
				"", actor)
			e.SourceIP = ip
			return []event.Event{e}
		}
	}
	return nil
}

func (a *App) window(actor string) *actorWindow {
	if len(a.actors) > maxActorCount {
		a.actors = map[string]*actorWindow{}
	}
	w, ok := a.actors[actor]
	if !ok {
		w = &actorWindow{}
		a.actors[actor] = w
	}
	return w
}

type actorWindow struct {
	hits []struct {
		t    time.Time
		path string
	}
}

func (w *actorWindow) add(path string, t time.Time) (n, distinct int) {
	for len(w.hits) > 0 && t.Sub(w.hits[0].t) > enumWindow {
		w.hits = w.hits[1:]
	}
	if len(w.hits) >= maxActorHits {
		w.hits = w.hits[1:]
	}
	w.hits = append(w.hits, struct {
		t    time.Time
		path string
	}{t, path})
	seen := map[string]bool{}
	for _, h := range w.hits {
		seen[h.path] = true
	}
	return len(w.hits), len(seen)
}

func parseAccess(text string) (access, bool) {
	if m := combinedRe.FindStringSubmatch(text); m != nil {
		st, _ := strconv.Atoi(m[5])
		user := m[2]
		if user == "-" {
			user = ""
		}
		return access{ip: m[1], user: user, path: stripQuery(m[4]), status: st}, true
	}
	if !strings.HasPrefix(strings.TrimSpace(text), "{") {
		return access{}, false
	}
	var doc map[string]any
	if json.Unmarshal([]byte(text), &doc) != nil {
		return access{}, false
	}
	st, _ := strconv.Atoi(pick(doc, "status", "statusCode", "status_code", "DownstreamStatus", "response_status"))
	if st == 0 {
		return access{}, false
	}
	return access{
		ip:     strings.Split(pick(doc, "ip", "client_ip", "clientIp", "remoteAddr", "remote_addr", "remoteAddress", "ClientHost", "x_forwarded_for"), ",")[0],
		user:   pickUser(doc),
		path:   stripQuery(pick(doc, "path", "url", "uri", "RequestPath", "request_uri", "originalUrl")),
		status: st,
	}, true
}

// pick returns the first key present at the top level or one level down
// (pino/winston nest them under req/res/http).
func pick(doc map[string]any, keys ...string) string {
	for _, k := range keys {
		if v := scalar(doc[k]); v != "" {
			return v
		}
	}
	for _, nest := range []string{"req", "res", "request", "response", "http"} {
		if sub, ok := doc[nest].(map[string]any); ok {
			for _, k := range keys {
				if v := scalar(sub[k]); v != "" {
					return v
				}
			}
		}
	}
	return ""
}

// pickUser also accepts {"user": {"id": …}}.
func pickUser(doc map[string]any) string {
	if v := pick(doc, "userId", "user_id", "uid", "user", "username", "sub", "email"); v != "" {
		return v
	}
	if u, ok := doc["user"].(map[string]any); ok {
		return pick(u, "id", "email", "username")
	}
	return ""
}

func scalar(v any) string {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return ""
}

func stripQuery(p string) string {
	p, _, _ = strings.Cut(p, "?")
	return p
}

func (a *App) event(rule string, sev finding.Severity, technique string, t time.Time, title, line, actor string) event.Event {
	summary := "Aplicação " + a.Target + ": " + title
	if line != "" {
		summary += "\nLog: " + excerpt(line, 240)
	}
	target := a.Target
	if actor != "" {
		target += " · " + actor // dedup per actor, not per app
	}
	e := event.Event{Source: "applog", Rule: rule, Severity: sev, Time: t, Target: target,
		Summary: summary, Technique: technique}
	event.Classify(&e)
	return e
}
