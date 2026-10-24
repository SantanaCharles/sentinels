package integrations

import (
	"testing"

	"github.com/SantanaCharles/sentinels/internal/finding"
)

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
