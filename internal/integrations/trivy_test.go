package integrations

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/SantanaCharles/sentinels/internal/finding"
)

func mustReport(t *testing.T, raw []byte) trivyReport {
	t.Helper()
	var rep trivyReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestParseTrivy(t *testing.T) {
	raw := []byte(`{"Results":[{"Target":"debian","Vulnerabilities":[
	  {"VulnerabilityID":"CVE-2024-1111","PkgName":"openssl","InstalledVersion":"3.0.1","FixedVersion":"3.0.9","Severity":"CRITICAL","Title":"t","CweIDs":["CWE-787"]},
	  {"VulnerabilityID":"CVE-2024-1111","PkgName":"openssl","InstalledVersion":"3.0.1","FixedVersion":"3.0.9","Severity":"CRITICAL"},
	  {"VulnerabilityID":"CVE-2024-2222","PkgName":"zlib","InstalledVersion":"1.2","Severity":"HIGH"}
	]},{"Target":"node","Vulnerabilities":null}]}`)
	fs, _, err := parseTrivy(raw, "app:1", "app")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("esperado 2 achados (duplicado removido), veio %d", len(fs))
	}
	if fs[0].Severity != finding.Critical || fs[0].CVE != "CVE-2024-1111" || fs[0].CWE[0] != "CWE-787" {
		t.Errorf("achado 0: %+v", fs[0])
	}
	if fs[1].Severity != finding.High || fs[1].Remediation == "" {
		t.Errorf("achado 1: %+v", fs[1])
	}
}

func TestTrivySkipsKernelPackages(t *testing.T) {
	raw := []byte(`{"Results":[{"Target":"debian","Vulnerabilities":[
	  {"VulnerabilityID":"CVE-2026-0001","PkgName":"linux-libc-dev","InstalledVersion":"6.1","Severity":"HIGH"},
	  {"VulnerabilityID":"CVE-2026-0002","PkgName":"linux-headers-6.1.0-9","InstalledVersion":"6.1","Severity":"CRITICAL"},
	  {"VulnerabilityID":"CVE-2026-0003","PkgName":"libssl3","InstalledVersion":"3.0","Severity":"HIGH"},
	  {"VulnerabilityID":"CVE-2026-0004","PkgName":"linux-tools","InstalledVersion":"1","Severity":"HIGH"}
	]}]}`)
	fs, skipped, err := parseTrivy(raw, "img", "c")
	if err != nil || skipped != 2 || len(fs) != 2 {
		t.Errorf("achados %d, ignorados %d (%v); quer 2 e 2", len(fs), skipped, err)
	}
}

func TestParseTrivyOSKeepsKernel(t *testing.T) {
	raw := []byte(`{"Results":[{"Target":"debian","Class":"os-pkgs","Vulnerabilities":[
	  {"VulnerabilityID":"CVE-2026-1000","PkgName":"linux-image-6.1.0-9","InstalledVersion":"6.1","FixedVersion":"6.1.1","Severity":"CRITICAL"},
	  {"VulnerabilityID":"CVE-2026-1001","PkgName":"openssl","InstalledVersion":"3.0.1","FixedVersion":"3.0.9","Severity":"HIGH"},
	  {"VulnerabilityID":"CVE-2026-1002","PkgName":"libx","InstalledVersion":"1","Severity":"MEDIUM"}
	]}]}`)
	out, _ := vulnFindings(mustReport(t, raw), "host", "sistema operacional do host", false, true)
	if len(out) != 2 { // kernel kept, HIGH/CRITICAL only (MEDIUM dropped)
		t.Fatalf("esperado 2 achados (kernel mantido, média descartada), veio %d: %+v", len(out), out)
	}
	for _, f := range out {
		if f.Target != "host" {
			t.Errorf("alvo deveria ser host: %+v", f)
		}
		if !strings.Contains(f.Detail, "sistema operacional do host") {
			t.Errorf("detalhe deveria citar o SO do host: %q", f.Detail)
		}
	}
	if !strings.Contains(out[0].Remediation, "apt") {
		t.Errorf("remediação do host deveria sugerir atualizar o pacote: %q", out[0].Remediation)
	}
}

func TestTrivySecretsAndMediumCVEs(t *testing.T) {
	raw := []byte(`{"Results":[
	  {"Target":"debian","Vulnerabilities":[{"VulnerabilityID":"CVE-2026-0005","PkgName":"libx","InstalledVersion":"1","Severity":"MEDIUM"}]},
	  {"Target":"/app/.env","Class":"secret","Secrets":[
	    {"RuleID":"aws-access-key-id","Category":"AWS","Severity":"CRITICAL","Title":"AWS Access Key ID","StartLine":3,"Match":"AWS_ACCESS_KEY_ID=AKIA****************"},
	    {"RuleID":"jwt-token","Category":"JWT","Severity":"MEDIUM","Title":"JWT token","StartLine":7,"Match":"TOKEN=eyJ****"}]}
	]}`)
	fs, _, err := parseTrivy(raw, "minha-app:1.0", "app")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("esperado 2 segredos e nenhuma CVE média, veio %d: %+v", len(fs), fs)
	}
	for _, f := range fs {
		if !strings.HasPrefix(f.ID, "secret.") || f.Severity < finding.High || !strings.Contains(f.Title, "/app/.env") {
			t.Errorf("achado de segredo: %+v", f)
		}
		if strings.Contains(f.Detail+f.Title, "AKIA") || strings.Contains(f.Detail+f.Title, "eyJ") {
			t.Error("trecho do segredo foi parar no relatório")
		}
	}
	if fs[0].Severity != finding.Critical {
		t.Errorf("chave AWS deveria ser crítica: %v", fs[0].Severity)
	}
}
