// Package integrations adapts external open-source security tools.
package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/SantanaCharles/sentinels/internal/finding"
)

// TrivyAvailable reports whether the trivy binary is on PATH.
func TrivyAvailable() (string, bool) {
	p, err := exec.LookPath("trivy")
	return p, err == nil
}

type trivyReport struct {
	Results []struct {
		Target          string
		Vulnerabilities []struct {
			VulnerabilityID  string
			PkgName          string
			InstalledVersion string
			FixedVersion     string
			Severity         string
			Title            string
			PrimaryURL       string
			CweIDs           []string
		}
	}
}

// kernelPackages ship kernel headers or images inside a container image. A
// container runs on the host's kernel, so their CVEs do not apply to it (the
// host kernel is the system's responsibility, patched by the distribution).
var kernelPackages = []string{"linux-libc-dev", "linux-headers-", "linux-image-", "linux-modules-", "kernel-headers", "kernel-devel", "kernel-core"}

func isKernelPackage(name string) bool {
	for _, p := range kernelPackages {
		if name == p || strings.HasSuffix(p, "-") && strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// TrivyImage scans one image for HIGH and CRITICAL CVEs. target names the
// containers using it, for the report. skipped counts kernel-package CVEs
// left out because they do not apply inside a container.
func TrivyImage(ctx context.Context, image, target string) (fs []finding.Finding, skipped int, err error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "trivy", "image",
		"--quiet", "--format", "json", "--scanners", "vuln",
		"--severity", "HIGH,CRITICAL", image)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, 0, fmt.Errorf("trivy %s: %v: %s", image, err, strings.TrimSpace(lastLine(stderr.String())))
	}
	return parseTrivy(stdout.Bytes(), image, target)
}

func parseTrivy(raw []byte, image, target string) ([]finding.Finding, int, error) {
	var rep trivyReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, 0, fmt.Errorf("saída do trivy inválida: %w", err)
	}
	seen := map[string]bool{}
	var out []finding.Finding
	skipped := 0
	for _, r := range rep.Results {
		for _, v := range r.Vulnerabilities {
			key := v.VulnerabilityID + "|" + v.PkgName
			if seen[key] {
				continue
			}
			seen[key] = true
			if isKernelPackage(v.PkgName) {
				skipped++
				continue
			}
			sev, _ := finding.ParseSeverity(v.Severity)
			f := finding.Finding{
				ID:       "cve." + v.VulnerabilityID,
				Severity: sev,
				Target:   target,
				CVE:      v.VulnerabilityID,
				CWE:      v.CweIDs,
				Title:    fmt.Sprintf("%s em %s %s", v.VulnerabilityID, v.PkgName, v.InstalledVersion),
				Detail:   strings.TrimSpace(v.Title + " (imagem " + image + ")"),
			}
			if v.FixedVersion != "" {
				f.Remediation = fmt.Sprintf("Atualize %s para %s ou posterior (normalmente: atualizar a imagem base e reconstruir).", v.PkgName, v.FixedVersion)
			} else {
				f.Remediation = "Ainda sem correção publicada. Avalie se o componente é usado e acompanhe o fornecedor."
			}
			if v.PrimaryURL != "" {
				f.References = []string{v.PrimaryURL}
			}
			out = append(out, f)
		}
	}
	return out, skipped, nil
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, "\n"); i >= 0 {
		return s[i+1:]
	}
	return s
}
