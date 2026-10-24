package ai

import (
	"context"
	"strings"
	"testing"
)

const source = `PHP Security Advisory, 21 October 2026. Two vulnerabilities, CVE-2026-109618 and
CVE-2026-109619, allow unauthenticated remote code execution in all PHP versions since 5.4.
Fixed in PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35. See https://www.php.net/archive/2026.php`

const goodDraft = "```json\n" + `{
  "id": "php2shell-2026-10",
  "title": "PHP2Shell — execução remota de código no PHP",
  "cves": ["CVE-2026-109618", "CVE-2026-109619"],
  "product": "php",
  "published": "2026-10-21",
  "severity": "critical",
  "fixed": {"8.5": "8.5.12", "8.4": "8.4.27", "8.3": "8.3.36", "8.2": "8.2.35"},
  "affected_min": "5.4.0",
  "eol_vulnerable": true,
  "summary": "Duas falhas permitem executar código sem login.",
  "remediation": "Atualize para 8.5.12, 8.4.27, 8.3.36 ou 8.2.35.",
  "references": ["https://www.php.net/archive/2026.php"]
}` + "\n```"

func TestDraftAdvisoryValid(t *testing.T) {
	fp := &fakeProvider{reply: goodDraft}
	a, probs, err := DraftAdvisory(context.Background(), fp, source)
	if err != nil || len(probs) != 0 {
		t.Fatalf("rascunho válido rejeitado: %v %v", probs, err)
	}
	if a.Fixed["8.3"] != "8.3.36" || !a.EOLVulnerable {
		t.Errorf("campos: %+v", a)
	}
	if !strings.Contains(fp.reqs[0].User, "<dados>") || !strings.Contains(fp.reqs[0].System, "nunca invente") {
		t.Error("fonte não foi enviada como dado delimitado")
	}
}

func TestDraftAdvisoryCatchesInventions(t *testing.T) {
	bad := strings.NewReplacer(
		`"CVE-2026-109619"`, `"CVE-2026-999999"`, // CVE not in source
		`"8.3.36"`, `"8.3.40"`, // version not in source
		`"php"`, `"nginx"`, // product the agent cannot detect
		`https://www.php.net/archive/2026.php`, `https://atacante.example/x`,
	).Replace(goodDraft)
	_, probs, err := DraftAdvisory(context.Background(), &fakeProvider{reply: bad}, source)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(probs, "\n")
	for _, want := range []string{"CVE-2026-999999 não aparece", "8.3.40 não aparece", `"nginx"`, "atacante.example"} {
		if !strings.Contains(joined, want) {
			t.Errorf("problema não detectado: %s\n%s", want, joined)
		}
	}
	if _, _, err := DraftAdvisory(context.Background(), &fakeProvider{reply: "Claro! Aqui está o alerta."}, source); err == nil {
		t.Error("resposta sem JSON aceita")
	}
	if _, _, err := DraftAdvisory(context.Background(), &fakeProvider{reply: `{"id":"x","campo_extra":1}`}, source); err == nil {
		t.Error("campo desconhecido aceito")
	}
}
