package workload

import (
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/SantanaCharles/sentinels/internal/event"
	"github.com/SantanaCharles/sentinels/internal/finding"
)

// Postgres analyzes the log of a PostgreSQL container. With the image
// defaults every failed statement is logged as an ERROR line followed by a
// STATEMENT line with the query; slow queries appear only when
// log_min_duration_statement is set.
type Postgres struct {
	Target  string // container (or service) name
	pending map[string]pgEntry
	syntax  *burst
	auth    *burst
	denied  *burst
}

type pgEntry struct {
	level, msg string
	t          time.Time
}

func NewPostgres(target string) *Postgres {
	return &Postgres{Target: target, pending: map[string]pgEntry{},
		syntax: newBurst(5, 5*time.Minute), auth: newBurst(5, 5*time.Minute), denied: newBurst(10, 5*time.Minute)}
}

var (
	pgLineRe = regexp.MustCompile(`^(.*?)\b(LOG|ERROR|FATAL|PANIC|STATEMENT|DETAIL|HINT|CONTEXT|WARNING|NOTICE):\s+(.*)$`)
	pgPidRe  = regexp.MustCompile(`\[(\d+)\]`)
	pgSlowRe = regexp.MustCompile(`^duration: [\d.]+ ms\s+(?:statement|execute [^:]*):\s+(.*)$`)
	pgStmtRe = regexp.MustCompile(`^statement:\s+(.*)$`)

	pgSyntaxRe = regexp.MustCompile(`(?i)syntax error at or near|unterminated quoted (string|identifier)|invalid input syntax for|each UNION query must have the same number of columns|UNION types .* cannot be matched|operator does not exist|function .* does not exist|zero-length delimited identifier|unterminated dollar-quoted string`)
	pgRLSRe    = regexp.MustCompile(`(?i)violates row-level security policy`)
	pgDeniedRe = regexp.MustCompile(`(?i)permission denied for (table|relation|schema|sequence|view|function|database|large object)|must be (superuser|owner)|only superuser`)
	pgAuthRe   = regexp.MustCompile(`(?i)password authentication failed for user|role ".*" does not exist|database ".*" does not exist|no pg_hba\.conf entry`)
	pgHostRe   = regexp.MustCompile(`no pg_hba\.conf entry for host "([^"]+)"`)
)

// Line feeds one log line and returns the detections it completes.
func (p *Postgres) Line(text string, t time.Time) []event.Event {
	m := pgLineRe.FindStringSubmatch(text)
	if m == nil {
		return nil
	}
	pid := ""
	if pm := pgPidRe.FindStringSubmatch(m[1]); pm != nil {
		pid = pm[1]
	}
	level, msg := m[2], strings.TrimSpace(m[3])
	switch level {
	case "ERROR", "FATAL", "PANIC":
		out := p.flushPid(pid)
		p.pending[pid] = pgEntry{level: level, msg: msg, t: t}
		return out
	case "STATEMENT":
		e, ok := p.pending[pid]
		if !ok {
			return nil
		}
		delete(p.pending, pid)
		return p.evaluate(e.level, e.msg, msg, e.t)
	case "DETAIL", "HINT", "CONTEXT":
		return nil // details of the pending error
	case "LOG":
		out := p.flushPid(pid)
		if sm := pgSlowRe.FindStringSubmatch(msg); sm != nil {
			return append(out, p.statementOnly(sm[1], t, true)...)
		}
		if sm := pgStmtRe.FindStringSubmatch(msg); sm != nil {
			return append(out, p.statementOnly(sm[1], t, false)...)
		}
		return out
	}
	return p.flushPid(pid)
}

// Flush evaluates errors still waiting for a STATEMENT line (end of a batch).
func (p *Postgres) Flush() []event.Event {
	var out []event.Event
	for pid := range p.pending {
		out = append(out, p.flushPid(pid)...)
	}
	return out
}

func (p *Postgres) flushPid(pid string) []event.Event {
	e, ok := p.pending[pid]
	if !ok {
		return nil
	}
	delete(p.pending, pid)
	return p.evaluate(e.level, e.msg, "", e.t)
}

// statementOnly checks statements logged without an error: slow queries
// (time-based injection) and log_statement output (dangerous commands).
func (p *Postgres) statementOnly(stmt string, t time.Time, slow bool) []event.Event {
	if dangerousRe.MatchString(stmt) {
		return []event.Event{p.event("postgres-dangerous-command", finding.Critical, "T1059", t,
			"Comando perigoso executado no banco (lê arquivos, roda programas ou altera o servidor)", "", stmt)}
	}
	if slow {
		if mk := sqliMarker(stmt); strings.Contains(mk, "atraso") {
			return []event.Event{p.event("postgres-sqli-attempt", finding.Critical, "T1190", t,
				"Tentativa de SQL injection por tempo: consulta atrasada de propósito", "", stmt)}
		}
	}
	return nil
}

func (p *Postgres) evaluate(level, msg, stmt string, t time.Time) []event.Event {
	switch {
	case stmt != "" && dangerousRe.MatchString(stmt):
		return []event.Event{p.event("postgres-dangerous-command", finding.Critical, "T1059", t,
			"Tentativa de comando perigoso no banco (ler arquivos, rodar programas)", msg, stmt)}
	case strings.Contains(msg, "COPY to or from an external program") || strings.Contains(msg, "pg_read_server_files") || strings.Contains(msg, "pg_execute_server_program"):
		return []event.Event{p.event("postgres-dangerous-command", finding.Critical, "T1059", t,
			"Tentativa de ler arquivos ou rodar programas pelo banco", msg, stmt)}
	}
	if mk := sqliMarker(stmt); mk != "" && level == "ERROR" {
		return []event.Event{p.event("postgres-sqli-attempt", finding.Critical, "T1190", t,
			"Tentativa de SQL injection: consulta com "+mk+" falhou no banco", msg, stmt)}
	}
	switch {
	case pgRLSRe.MatchString(msg):
		return []event.Event{p.event("postgres-rls-violation", finding.High, "T1213", t,
			"Bloqueado pelo RLS: tentativa de gravar dado de outro cliente/tenant", msg, stmt)}
	case pgDeniedRe.MatchString(msg):
		if p.denied.add("denied", t) {
			return []event.Event{p.event("postgres-permission-denied", finding.High, "T1213", t,
				"Muitos acessos negados no banco: alguém tentando ler o que não pode", msg, stmt)}
		}
		return []event.Event{p.event("postgres-permission-denied", finding.Medium, "T1213", t,
			"Acesso negado no banco", msg, stmt)}
	case pgSyntaxRe.MatchString(msg):
		if p.syntax.add("syntax", t) {
			return []event.Event{p.event("postgres-sql-error-burst", finding.High, "T1190", t,
				"Rajada de erros de SQL: padrão de quem testa SQL injection", msg, stmt)}
		}
	case pgAuthRe.MatchString(msg):
		if hm := pgHostRe.FindStringSubmatch(msg); hm != nil && isPublic(hm[1]) {
			e := p.event("postgres-external-connection", finding.High, "T1133", t,
				"Conexão ao banco vinda da internet (recusada pelo pg_hba)", msg, "")
			e.SourceIP = hm[1]
			return []event.Event{e}
		}
		if p.auth.add("auth", t) {
			return []event.Event{p.event("postgres-auth-bruteforce", finding.High, "T1110", t,
				"Várias senhas erradas no banco: possível força bruta", msg, "")}
		}
	}
	return nil
}

func (p *Postgres) event(rule string, sev finding.Severity, technique string, t time.Time, title, msg, stmt string) event.Event {
	summary := "Banco " + p.Target + ": " + title
	if msg != "" {
		summary += "\nErro: " + excerpt(msg, 160)
	}
	if stmt != "" {
		summary += "\nConsulta: " + excerpt(stmt, 240)
	}
	e := event.Event{Source: "postgres", Rule: rule, Severity: sev, Time: t, Target: p.Target,
		Summary: summary, Technique: technique}
	event.Classify(&e)
	return e
}

// isPublic reports whether ip is routable on the internet.
func isPublic(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified() && !ip.IsMulticast()
}
