package ai

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// Redactor masks secrets and pseudonymizes personal data before text leaves
// the server. Pseudonyms are stable within one Redactor, so the model can
// still tell that two events came from the same address.
type Redactor struct {
	KeepIPs bool
	seen    map[string]string // original value -> pseudonym
	counts  map[string]int    // pseudonyms issued per kind
}

func NewRedactor(keepIPs bool) *Redactor {
	return &Redactor{KeepIPs: keepIPs, seen: map[string]string{}, counts: map[string]int{}}
}

// secretPatterns are replaced outright: they never help the analysis.
var secretPatterns = []struct {
	re   *regexp.Regexp
	repl string
}{
	{regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`), "[CHAVE-PRIVADA]"},
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`), "[JWT]"},
	{regexp.MustCompile(`\b(AKIA|ASIA)[A-Z0-9]{16}\b`), "[CHAVE-AWS]"},
	{regexp.MustCompile(`\b(sk|pk|rk)_(live|test)_[A-Za-z0-9]{10,}\b`), "[CHAVE-STRIPE]"},
	{regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{16,}\b`), "[CHAVE-API]"},
	{regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`), "[TOKEN-GITHUB]"},
	{regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}\b`), "[TOKEN-SLACK]"},
	{regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{30,}\b`), "[CHAVE-GOOGLE]"},
	{regexp.MustCompile(`\b\d{8,10}:[A-Za-z0-9_-]{30,}\b`), "[TOKEN-TELEGRAM]"},
	// user:password@ in URLs and DSNs
	{regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@]+):[^\s@/]+@`), "$1:[SENHA]@"},
	// Authorization headers and key=value secrets
	{regexp.MustCompile(`(?i)\b(authorization|bearer|basic)([:=\s]+)[A-Za-z0-9._~+/=-]{8,}`), "$1$2[CREDENCIAL]"},
	{regexp.MustCompile(`(?i)\b([a-z0-9_]*(?:password|passwd|senha|secret|token|api[_-]?key|apikey|access[_-]?key)[a-z0-9_]*)(["']?\s*[:=]\s*["']?)[^\s"'&,;]{3,}`), "$1$2[SEGREDO]"},
	// Brazilian CPF
	{regexp.MustCompile(`\b\d{3}\.\d{3}\.\d{3}-\d{2}\b`), "[CPF]"},
}

var (
	ipv4Re  = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6Re  = regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b`)
	emailRe = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)
)

func (r *Redactor) Redact(s string) string {
	for _, p := range secretPatterns {
		s = p.re.ReplaceAllString(s, p.repl)
	}
	s = emailRe.ReplaceAllStringFunc(s, func(m string) string {
		return r.pseudonym(strings.ToLower(m), "EMAIL")
	})
	if !r.KeepIPs {
		s = ipv4Re.ReplaceAllStringFunc(s, r.ip)
		s = ipv6Re.ReplaceAllStringFunc(s, r.ip)
	}
	return s
}

// ip pseudonymizes public addresses and labels private ones, which tells the
// model whether traffic is internal without revealing the network layout.
func (r *Redactor) ip(m string) string {
	ip := net.ParseIP(m)
	if ip == nil {
		return m
	}
	if ip.IsLoopback() {
		return "[IP-LOCAL]"
	}
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return r.pseudonym(ip.String(), "IP-INTERNO")
	}
	return r.pseudonym(ip.String(), "IP")
}

func (r *Redactor) pseudonym(key, kind string) string {
	if v, ok := r.seen[key]; ok {
		return v
	}
	r.counts[kind]++
	v := fmt.Sprintf("[%s-%d]", kind, r.counts[kind])
	r.seen[key] = v
	return v
}
