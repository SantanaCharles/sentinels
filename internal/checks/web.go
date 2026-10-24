package checks

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/SantanaCharles/sentinels/internal/finding"
	"github.com/SantanaCharles/sentinels/internal/fingerprint"
)

const (
	owaspMisconfig = "OWASP Top 10 — Security Misconfiguration"
	owaspHeaders   = "https://owasp.org/www-project-secure-headers/"
	probeOrigin    = "https://sentinels-cors-check.invalid"
	maxBody        = 64 << 10
)

var (
	versionRe = regexp.MustCompile(`\d+\.\d+`)
	envLineRe = regexp.MustCompile(`(?m)^[A-Z][A-Z0-9_]{2,}=`)
	gitHeadRe = regexp.MustCompile(`^(ref: refs/|[0-9a-f]{40}\s*$)`)
)

// WebResult is what a single HTTP target revealed.
type WebResult struct {
	URL        string
	Reachable  bool
	Components []string
	Findings   []finding.Finding
}

type WebChecker struct {
	client *http.Client
}

func NewWebChecker() *WebChecker {
	return &WebChecker{client: &http.Client{
		Timeout: 8 * time.Second,
		// Local ports often redirect to the public HTTPS domain; inspect the
		// first response instead of following it.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			// Local ports usually present the public certificate; a mismatch
			// must not hide header problems.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // audit only, no secrets sent
		},
	}}
}

// Check audits target; label names it in the report (container name or URL).
func (w *WebChecker) Check(ctx context.Context, target, label string) WebResult {
	res := WebResult{URL: target}
	resp, err := w.do(ctx, target, map[string]string{"Origin": probeOrigin})
	if err != nil {
		return res
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody))
	resp.Body.Close()
	res.Reachable = true
	res.Components = fingerprint.FromHeaders(resp.Header)

	add := func(f finding.Finding) {
		f.Target = label
		res.Findings = append(res.Findings, f)
	}
	h := resp.Header
	isHTTPS := strings.HasPrefix(target, "https://")

	if isHTTPS && h.Get("Strict-Transport-Security") == "" {
		add(finding.Finding{
			ID: "web.no_hsts", Severity: finding.Medium, CWE: []string{"CWE-319"},
			Title:       "HSTS ausente",
			Detail:      "Sem Strict-Transport-Security o navegador aceita ser rebaixado para HTTP em redes não confiáveis.",
			Remediation: "Envie `Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
			References:  []string{owaspHeaders},
		})
	}
	csp := h.Get("Content-Security-Policy")
	if csp == "" {
		add(finding.Finding{
			ID: "web.no_csp", Severity: finding.Low, CWE: []string{"CWE-1021"},
			Title:       "Content-Security-Policy ausente",
			Remediation: "Defina uma CSP restritiva; ela reduz muito o impacto de falhas de XSS.",
			References:  []string{owaspHeaders},
		})
	}
	if h.Get("X-Frame-Options") == "" && !strings.Contains(csp, "frame-ancestors") {
		add(finding.Finding{
			ID: "web.no_frame_protection", Severity: finding.Low, CWE: []string{"CWE-1021"},
			Title:       "Proteção contra clickjacking ausente",
			Remediation: "Envie `X-Frame-Options: DENY` ou `Content-Security-Policy: frame-ancestors 'none'`.",
			References:  []string{owaspHeaders},
		})
	}
	if !strings.EqualFold(h.Get("X-Content-Type-Options"), "nosniff") {
		add(finding.Finding{
			ID: "web.no_nosniff", Severity: finding.Low, CWE: []string{"CWE-693"},
			Title:       "X-Content-Type-Options ausente",
			Remediation: "Envie `X-Content-Type-Options: nosniff`.",
			References:  []string{owaspHeaders},
		})
	}
	if s := h.Get("Server"); versionRe.MatchString(s) {
		add(finding.Finding{
			ID: "web.server_version", Severity: finding.Low, CWE: []string{"CWE-200"},
			Title:       "Versão do servidor exposta",
			Detail:      "Server: " + s + ". Facilita encontrar CVEs aplicáveis.",
			Remediation: "Nginx: `server_tokens off;`. Apache: `ServerTokens Prod`.",
			References:  []string{owaspMisconfig},
		})
	}
	if p := h.Get("X-Powered-By"); p != "" {
		add(finding.Finding{
			ID: "web.powered_by", Severity: finding.Low, CWE: []string{"CWE-200"},
			Title:       "Header X-Powered-By exposto",
			Detail:      "X-Powered-By: " + p,
			Remediation: "Next.js: `poweredByHeader: false`. Express: `app.disable('x-powered-by')`. PHP: `expose_php = Off`.",
			References:  []string{owaspMisconfig},
		})
	}
	if h.Get("Access-Control-Allow-Origin") == probeOrigin && strings.EqualFold(h.Get("Access-Control-Allow-Credentials"), "true") {
		add(finding.Finding{
			ID: "web.cors_reflect_credentials", Severity: finding.High, CWE: []string{"CWE-942"},
			Title:       "CORS aceita qualquer origem com credenciais",
			Detail:      "A origem enviada é refletida em Access-Control-Allow-Origin junto com Allow-Credentials: true. Qualquer site pode fazer requisições autenticadas em nome do usuário logado e ler a resposta.",
			Remediation: "Use uma lista fixa de origens permitidas.",
			References:  []string{owaspMisconfig},
		})
	}

	res.Findings = append(res.Findings, w.exposedFiles(ctx, target, label)...)
	return res
}

// exposedFiles looks for deployment files that must never be served.
// Content is validated so catch-all SPA routes do not produce false positives.
func (w *WebChecker) exposedFiles(ctx context.Context, target, label string) []finding.Finding {
	var out []finding.Finding
	if body, ok := w.fetch(ctx, target, "/.env"); ok && envLineRe.MatchString(body) && !looksHTML(body) {
		out = append(out, finding.Finding{
			ID: "web.env_exposed", Severity: finding.Critical, Target: label, CWE: []string{"CWE-538"},
			Title:       "Arquivo .env acessível publicamente",
			Detail:      "O arquivo de variáveis de ambiente é servido pela aplicação. Considere todas as credenciais dele comprometidas. (O Sentinels não armazena o conteúdo.)",
			Remediation: "Bloqueie o arquivo no servidor web, tire-o do diretório público e troque todas as credenciais que estavam nele.",
			References:  []string{owaspMisconfig},
		})
	}
	if body, ok := w.fetch(ctx, target, "/.git/HEAD"); ok && gitHeadRe.MatchString(body) {
		out = append(out, finding.Finding{
			ID: "web.git_exposed", Severity: finding.High, Target: label, CWE: []string{"CWE-538"},
			Title:       "Repositório .git acessível publicamente",
			Detail:      "Permite baixar o código-fonte e o histórico, que costuma conter credenciais antigas.",
			Remediation: "Bloqueie `/.git` no servidor web e não publique o diretório do repositório.",
			References:  []string{owaspMisconfig},
		})
	}
	return out
}

func (w *WebChecker) fetch(ctx context.Context, base, path string) (string, bool) {
	u, err := url.JoinPath(base, path)
	if err != nil {
		return "", false
	}
	resp, err := w.do(ctx, u, nil)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return string(b), true
}

func (w *WebChecker) do(ctx context.Context, u string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Sentinels-Audit/0.1 (+https://github.com/SantanaCharles/sentinels)")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return w.client.Do(req)
}

func looksHTML(body string) bool {
	b := strings.ToLower(strings.TrimSpace(body))
	return strings.HasPrefix(b, "<!doctype") || strings.HasPrefix(b, "<html")
}
