package checks

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/SantanaCharles/sentinels/internal/finding"
)

const tlsRef = "https://letsencrypt.org/docs/"

// TLSCertificate checks the certificate a public HTTPS URL presents:
// expiry, chain/hostname validity and protocol version. Local ports are not
// checked: proxies answer 127.0.0.1 with a default certificate.
func TLSCertificate(ctx context.Context, rawURL string, now time.Time) []finding.Finding {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return nil
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 8 * time.Second},
		Config: &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true, //nolint:gosec // we verify below, to report *why* it fails
			MinVersion:         tls.VersionTLS10,
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil // unreachable: the web check already reports it
	}
	defer conn.Close()
	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil
	}
	return evaluateCert(host, rawURL, state, now)
}

// evaluateCert is separate from the network part so it can be unit tested.
func evaluateCert(host, target string, state tls.ConnectionState, now time.Time) []finding.Finding {
	leaf := state.PeerCertificates[0]
	var out []finding.Finding
	days := int(leaf.NotAfter.Sub(now).Hours() / 24)
	exp := leaf.NotAfter.Format("02/01/2006")
	renew := "Se usa Let's Encrypt (Traefik, Caddy, certbot), confira por que a renovação automática falhou: DNS apontando para o servidor, porta 80/443 aberta e os logs do proxy."

	switch {
	case now.After(leaf.NotAfter):
		out = append(out, finding.Finding{
			ID: "tls.expired", Severity: finding.Critical, Target: target, CWE: []string{"CWE-298"},
			Title:       fmt.Sprintf("Certificado TLS vencido em %s", exp),
			Detail:      "Navegadores bloqueiam o site com aviso de segurança e integrações (APIs, webhooks) param de funcionar.",
			Remediation: renew, References: []string{tlsRef},
		})
	case days < 7:
		out = append(out, finding.Finding{
			ID: "tls.expiring", Severity: finding.High, Target: target,
			Title:       fmt.Sprintf("Certificado TLS vence em %d dia(s) (%s)", days, exp),
			Detail:      "A renovação automática costuma acontecer 30 dias antes; faltando menos de uma semana, ela provavelmente está falhando.",
			Remediation: renew, References: []string{tlsRef},
		})
	case days < 14:
		out = append(out, finding.Finding{
			ID: "tls.expiring", Severity: finding.Medium, Target: target,
			Title:       fmt.Sprintf("Certificado TLS vence em %d dias (%s)", days, exp),
			Remediation: renew, References: []string{tlsRef},
		})
	}

	if !now.After(leaf.NotAfter) {
		pool, _ := x509.SystemCertPool()
		inter := x509.NewCertPool()
		for _, c := range state.PeerCertificates[1:] {
			inter.AddCert(c)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: pool, Intermediates: inter, CurrentTime: now}); err != nil {
			reason := "não é confiável para os navegadores"
			switch e := err.(type) {
			case x509.HostnameError:
				reason = "não vale para " + host + " (emitido para " + strings.Join(e.Certificate.DNSNames, ", ") + ")"
			case x509.UnknownAuthorityError:
				reason = "foi emitido por uma autoridade desconhecida (autoassinado ou certificado padrão do proxy)"
			}
			out = append(out, finding.Finding{
				ID: "tls.invalid", Severity: finding.High, Target: target, CWE: []string{"CWE-295"},
				Title:       "Certificado TLS inválido: " + reason,
				Detail:      "Visitantes veem aviso de segurança, e clientes que validam o certificado recusam a conexão.",
				Remediation: "Emita um certificado válido para o domínio (Let's Encrypt). No Traefik, confira o certresolver do router; um certificado \"TRAEFIK DEFAULT CERT\" indica que a emissão falhou.",
				References:  []string{tlsRef},
			})
		}
	}

	if state.Version < tls.VersionTLS12 {
		out = append(out, finding.Finding{
			ID: "tls.old_protocol", Severity: finding.Medium, Target: target, CWE: []string{"CWE-327"},
			Title:       "Servidor aceita TLS antigo (" + tls.VersionName(state.Version) + ")",
			Detail:      "TLS 1.0 e 1.1 são obsoletos e têm fraquezas conhecidas.",
			Remediation: "Configure o mínimo de TLS 1.2 no proxy (Traefik: tls.options com minVersion VersionTLS12).",
			References:  []string{"https://ssl-config.mozilla.org/"},
		})
	}
	return out
}
