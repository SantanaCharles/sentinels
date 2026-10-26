// Package workload watches what happens inside application and database
// containers: database logs, application logs and who connects to each
// database. Everything is read-only (Docker API GET and /proc).
package workload

import (
	"regexp"
	"strings"
	"time"
)

// sqliMarkers are fragments typical of SQL injection payloads. They are only
// looked at in statements that failed (or were slowed on purpose): ORMs and
// migrations produce some of them in successful queries.
var sqliMarkers = []struct {
	re    *regexp.Regexp
	label string
}{
	{regexp.MustCompile(`(?i)\bunion\s+(all\s+)?select\b`), "UNION SELECT"},
	{regexp.MustCompile(`(?i)\binformation_schema\b`), "information_schema"},
	{regexp.MustCompile(`(?i)\bpg_(shadow|authid|user|roles|namespace|settings|stat_activity|file_settings|hba_file_rules)\b`), "catálogo interno do Postgres"},
	{regexp.MustCompile(`(?i)\bpg_sleep\s*\(|\bwaitfor\s+delay\b|\bsleep\s*\(\s*\d|\bbenchmark\s*\(`), "atraso proposital (SQL injection por tempo)"},
	{regexp.MustCompile(`(?i);\s*(drop|delete|truncate|update|insert|create|alter|copy|grant)\s`), "comando empilhado depois de ;"},
	{regexp.MustCompile(`(?i)\b(version|current_database|session_user)\s*\(\s*\)|@@version`), "consulta da versão/usuário do banco"},
	{regexp.MustCompile(`(?i)\b(chr|char)\s*\(\s*\d+\s*\)\s*(\|\||\+)`), "texto ofuscado com CHR()"},
	{regexp.MustCompile(`(?i)\bextractvalue\s*\(|\bupdatexml\s*\(|\bcast\s*\(\s*\(\s*select\b`), "extração de dados pela mensagem de erro"},
}

// tautologyRe finds "OR 1=1" / "' or 'a'='a"; both sides are compared in code
// (RE2 has no backreferences), so "a = 'x' and b = c" is not a match.
var tautologyRe = regexp.MustCompile(`(?i)\b(or|and)\s+'?(\w+)'?\s*=\s*'?(\w+)'?`)

// sqliMarker returns the first payload marker found in stmt, or "".
func sqliMarker(stmt string) string {
	for _, m := range sqliMarkers {
		if m.re.MatchString(stmt) {
			return m.label
		}
	}
	for _, m := range tautologyRe.FindAllStringSubmatch(stmt, -1) {
		if strings.EqualFold(m[2], m[3]) {
			return "condição sempre verdadeira (" + strings.TrimSpace(m[0]) + ")"
		}
	}
	return ""
}

// dangerousRe matches database features that read files, run programs or
// reach other servers: legitimate apps practically never use them.
var dangerousRe = regexp.MustCompile(`(?i)\bcopy\b[^;]*\b(from|to)\s+program\b|\bpg_(read_file|read_binary_file|ls_dir|stat_file)\s*\(|\blo_(import|export)\s*\(|\bdblink(_connect|_exec)?\s*\(|\balter\s+system\b|\bcreate\s+(or\s+replace\s+)?function\b[\s\S]*\blanguage\s+'?(c|plpython3?u|plperlu|pltclu)\b|\bcreate\s+(role|user)\b[\s\S]*\bsuperuser\b|\bload_file\s*\(|\binto\s+(out|dump)file\b`)

// excerpt flattens and shortens a statement for an alert.
func excerpt(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

// burst counts occurrences per key in a sliding window and fires once every
// n hits, so a flood becomes a few alerts instead of thousands.
type burst struct {
	window time.Duration
	n      int
	hits   map[string][]time.Time
}

func newBurst(n int, window time.Duration) *burst {
	return &burst{window: window, n: n, hits: map[string][]time.Time{}}
}

func (b *burst) add(key string, t time.Time) bool {
	if len(b.hits) > 10_000 {
		b.hits = map[string][]time.Time{}
	}
	h := b.hits[key]
	for len(h) > 0 && t.Sub(h[0]) > b.window {
		h = h[1:]
	}
	h = append(h, t)
	if len(h) >= b.n {
		delete(b.hits, key)
		return true
	}
	b.hits[key] = h
	return false
}
