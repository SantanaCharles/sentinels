// Package integrations adapts external open-source security tools.
package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
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
		// Secrets found in image files. Match (the line with the value) is
		// never read: only the rule, file and line go into the report.
		Secrets []struct {
			RuleID    string
			Category  string
			Severity  string
			Title     string
			StartLine int
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

// TrivyImage scans one image for HIGH and CRITICAL CVEs and for secrets
// (API keys, tokens, private keys) baked into its files. target names the
// containers using it, for the report. skipped counts kernel-package CVEs
// left out because they do not apply inside a container.
func TrivyImage(ctx context.Context, image, target string) (fs []finding.Finding, skipped int, err error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	// MEDIUM is requested for secrets; medium CVEs are dropped in parseTrivy.
	cmd := exec.CommandContext(ctx, "trivy", "image",
		"--quiet", "--format", "json", "--scanners", "vuln,secret",
		"--severity", "MEDIUM,HIGH,CRITICAL", image)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, 0, fmt.Errorf("trivy %s: %v: %s", image, err, strings.TrimSpace(lastLine(stderr.String())))
	}
	return parseTrivy(stdout.Bytes(), image, target)
}

// TrivyRootfs scans the host's operating-system packages for HIGH and
// CRITICAL CVEs (Trivy rootfs on the given filesystem root). Unlike the
// image scan, kernel-package CVEs are kept: they apply to the host.
func TrivyRootfs(ctx context.Context, root, target string) ([]finding.Finding, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	args := []string{"rootfs", "--quiet", "--format", "json", "--scanners", "vuln",
		"--severity", "HIGH,CRITICAL"}
	// Virtual filesystems, container layers and our own cache are not the host OS.
	for _, d := range []string{"proc", "sys", "dev", "run", "var/lib/docker", "var/lib/sentinels"} {
		args = append(args, "--skip-dirs", filepath.Join(root, d))
	}
	args = append(args, root)
	cmd := exec.CommandContext(ctx, "trivy", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("trivy rootfs %s: %v: %s", root, err, strings.TrimSpace(lastLine(stderr.String())))
	}
	var rep trivyReport
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		return nil, fmt.Errorf("saída do trivy inválida: %w", err)
	}
	out, _ := vulnFindings(rep, target, "sistema operacional do host", false, true)
	return out, nil
}

// vulnFindings maps Trivy vulnerabilities to findings, deduplicated by
// CVE+package. skipKernel drops kernel-package CVEs (they do not apply inside
// a container; for the host they do, so it is false). source goes into the
// detail ("imagem X" or "sistema operacional do host") and hostUpgrade picks a
// system-package-upgrade remediation instead of a rebuild-the-image one.
func vulnFindings(rep trivyReport, target, source string, skipKernel, hostUpgrade bool) ([]finding.Finding, int) {
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
			if skipKernel && isKernelPackage(v.PkgName) {
				skipped++
				continue
			}
			sev, _ := finding.ParseSeverity(v.Severity)
			if sev < finding.High {
				continue // MEDIUM is only requested for secrets, on the image scan
			}
			f := finding.Finding{
				ID:       "cve." + v.VulnerabilityID,
				Severity: sev,
				Target:   target,
				CVE:      v.VulnerabilityID,
				CWE:      v.CweIDs,
				Title:    fmt.Sprintf("%s em %s %s", v.VulnerabilityID, v.PkgName, v.InstalledVersion),
				Detail:   strings.TrimSpace(v.Title + " (" + source + ")"),
			}
			switch {
			case v.FixedVersion == "":
				f.Remediation = "Ainda sem correção publicada. Avalie se o componente é usado e acompanhe o fornecedor."
			case hostUpgrade:
				f.Remediation = fmt.Sprintf("Atualize o pacote %s para %s ou posterior: `sudo apt update && sudo apt upgrade` (ou `dnf upgrade`). CVEs do kernel exigem reiniciar o servidor.", v.PkgName, v.FixedVersion)
			default:
				f.Remediation = fmt.Sprintf("Atualize %s para %s ou posterior (normalmente: atualizar a imagem base e reconstruir).", v.PkgName, v.FixedVersion)
			}
			if v.PrimaryURL != "" {
				f.References = []string{v.PrimaryURL}
			}
			out = append(out, f)
		}
	}
	return out, skipped
}

func parseTrivy(raw []byte, image, target string) ([]finding.Finding, int, error) {
	var rep trivyReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, 0, fmt.Errorf("saída do trivy inválida: %w", err)
	}
	out, skipped := vulnFindings(rep, target, "imagem "+image, true, false)
	seen := map[string]bool{}
	for _, r := range rep.Results {
		for _, s := range r.Secrets {
			key := "secret|" + s.RuleID + "|" + r.Target
			if seen[key] {
				continue
			}
			seen[key] = true
			sev, _ := finding.ParseSeverity(s.Severity)
			if sev < finding.High {
				sev = finding.High // a credential inside an image is never low risk
			}
			// Trivy reports files by path; anything else is the image
			// config, i.e. a Dockerfile command kept in the build history.
			where := "em " + r.Target
			detail := fmt.Sprintf("O arquivo %s (linha %d) da imagem %s contém %s.", r.Target, s.StartLine, image, s.Category)
			if !strings.HasPrefix(r.Target, "/") {
				where = "no histórico de build (docker history)"
				detail = fmt.Sprintf("Um comando do Dockerfile da imagem %s contém %s; o texto fica gravado nas camadas e aparece em `docker history`.", image, s.Category)
			}
			out = append(out, finding.Finding{
				ID:       "secret." + s.RuleID,
				Severity: sev,
				Target:   target,
				CWE:      []string{"CWE-798"},
				Title:    fmt.Sprintf("Segredo embutido na imagem: %s %s", s.Title, where),
				Detail:   detail + " Qualquer pessoa que consiga baixar a imagem — ou acessar o container — obtém a credencial. (O Sentinels não lê nem guarda o valor.)",
				Remediation: "1) Troque/revogue a credencial agora: apagar o arquivo numa versão nova não a remove das camadas antigas nem de quem já baixou a imagem. " +
					"2) Tire o segredo da imagem: .dockerignore para .env e chaves, build multi-stage, e passe segredos em tempo de execução (variáveis, Docker secrets). " +
					"3) Reconstrua e publique a imagem limpa.",
				References: []string{"https://cwe.mitre.org/data/definitions/798.html"},
			})
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
