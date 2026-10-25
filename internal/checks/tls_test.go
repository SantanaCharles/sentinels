package checks

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func selfSigned(t *testing.T, names []string, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func TestEvaluateCert(t *testing.T) {
	now := time.Now()
	check := func(cert *x509.Certificate, version uint16) map[string]string {
		got := map[string]string{}
		for _, f := range evaluateCert("loja.exemplo.com.br", "https://loja.exemplo.com.br", tls.ConnectionState{Version: version, PeerCertificates: []*x509.Certificate{cert}}, now) {
			got[f.ID] = f.Severity.String() + ": " + f.Title
		}
		return got
	}
	expired := check(selfSigned(t, []string{"loja.exemplo.com.br"}, now.Add(-24*time.Hour)), tls.VersionTLS13)
	if !strings.HasPrefix(expired["tls.expired"], "critical") || expired["tls.invalid"] != "" {
		t.Errorf("vencido: %v", expired)
	}
	soon := check(selfSigned(t, []string{"loja.exemplo.com.br"}, now.Add(5*24*time.Hour)), tls.VersionTLS13)
	if !strings.HasPrefix(soon["tls.expiring"], "high") || !strings.Contains(soon["tls.invalid"], "autoridade desconhecida") {
		t.Errorf("vence em 5 dias / autoassinado: %v", soon)
	}
	inTwoWeeks := check(selfSigned(t, []string{"loja.exemplo.com.br"}, now.Add(12*24*time.Hour)), tls.VersionTLS13)
	if !strings.HasPrefix(inTwoWeeks["tls.expiring"], "medium") {
		t.Errorf("vence em 12 dias: %v", inTwoWeeks)
	}
	old := check(selfSigned(t, []string{"loja.exemplo.com.br"}, now.Add(90*24*time.Hour)), tls.VersionTLS11)
	if !strings.HasPrefix(old["tls.old_protocol"], "medium") || old["tls.expiring"] != "" {
		t.Errorf("TLS 1.1: %v", old)
	}
}

func TestFreshness(t *testing.T) {
	root := t.TempDir()
	now := time.Now()
	write := func(p string, age time.Duration, content string) {
		full := filepath.Join(root, p)
		os.MkdirAll(filepath.Dir(full), 0o755)
		os.WriteFile(full, []byte(content), 0o644)
		os.Chtimes(full, now.Add(-age), now.Add(-age))
	}
	day := 24 * time.Hour
	write("/cache/advisories.json", 3*day, "[]")
	write("/cache/kev.json", 1*day, "{}") // fresh
	write("/trivy/db/metadata.json", 0, `{"UpdatedAt":"`+now.Add(-5*day).Format(time.RFC3339)+`"}`)
	write("/var/lib/suricata/rules/suricata.rules", 10*day, "")

	got := map[string]bool{}
	for _, f := range Freshness(FreshnessPaths{CacheDir: "/cache", TrivyCacheDir: "/trivy", HostRoot: root}, now) {
		got[f.ID] = true
	}
	for _, want := range []string{"agent.stale_advisories", "agent.stale_trivy_db", "agent.stale_suricata_rules"} {
		if !got[want] {
			t.Errorf("faltou %s (achados: %v)", want, got)
		}
	}
	if got["agent.stale_kev"] || got["agent.stale_crowdsec_hub"] {
		t.Errorf("falso alarme: %v", got)
	}
	offline := Freshness(FreshnessPaths{CacheDir: "/cache", HostRoot: root, Offline: true}, now)
	for _, f := range offline {
		if f.ID == "agent.stale_advisories" {
			t.Error("modo offline não deveria cobrar o feed")
		}
	}
}
