package vault

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SantanaCharles/sentinels/internal/event"
	"github.com/SantanaCharles/sentinels/internal/finding"
	"github.com/SantanaCharles/sentinels/internal/fingerprint"
	"github.com/SantanaCharles/sentinels/internal/scan"
	"github.com/SantanaCharles/sentinels/internal/watch"
)

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestWriteScanPreservesAdminNotes(t *testing.T) {
	root := t.TempDir()
	v, err := New(root, finding.High)
	if err != nil {
		t.Fatal(err)
	}
	res := &scan.Result{Host: "vps-01", Started: time.Date(2026, 10, 23, 22, 10, 0, 0, time.UTC),
		Assets: []scan.Asset{{Name: "lab-php", Image: "php:8.3.10-apache",
			Stack: fingerprint.Stack{Kind: fingerprint.KindApp, Components: []string{"PHP"}}}},
		Findings: []finding.Finding{{ID: "advisory.php2shell-2026-10", Target: "lab-php", Severity: finding.Critical, Title: "PHP2Shell"}},
	}
	if err := v.WriteScan(res, "# Relatório\n"); err != nil {
		t.Fatal(err)
	}
	asset := filepath.Join(root, "Ativos", "lab-php.md")
	content := read(t, asset)
	if !strings.Contains(content, "PHP2Shell") || !strings.Contains(content, "[[Relatórios/Relatório 2026-10-23 2210|") {
		t.Errorf("nota do ativo:\n%s", content)
	}
	// Admin writes below the marker; the next scan must keep it.
	os.WriteFile(asset, []byte(content+"Responsável: equipe de TI da escola.\n"), 0o640)
	res.Findings = nil
	v.WriteScan(res, "# Relatório 2\n")
	content = read(t, asset)
	if !strings.Contains(content, "Responsável: equipe de TI da escola.") || strings.Contains(content, "PHP2Shell") {
		t.Errorf("notas do admin perdidas ou achado antigo mantido:\n%s", content)
	}
	if !strings.Contains(read(t, filepath.Join(root, "Início.md")), "[[Ativos/lab-php|lab-php]]") {
		t.Error("página inicial sem link do ativo")
	}
}

func TestIncidentNoteIsSafe(t *testing.T) {
	root := t.TempDir()
	v, _ := New(root, finding.High)
	hostile := "cmd: curl x ``` fim do bloco ![pixel](https://atacante.example/p.png) [[Início]] <img src=x>"
	e := &event.Event{Source: "falco", Rule: "Terminal shell in container", Technique: "T1059",
		Tactic: "Execution", Time: time.Date(2026, 10, 23, 22, 11, 0, 0, time.UTC)}
	a := watch.Alert{Severity: finding.Critical, Title: "Shell [[x]] ![y](http://a/b.png)", Target: "lab-php",
		Lines: []string{hostile}, Event: e, EventID: 7}
	if err := v.Alert(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(root, "Incidentes", "*.md"))
	if len(files) != 1 || !strings.Contains(filepath.Base(files[0]), "evento 7") {
		t.Fatalf("arquivos: %v", files)
	}
	note := read(t, files[0])
	head, body, _ := strings.Cut(note, "## Dados do evento")
	if strings.Contains(head, "![") || strings.Contains(head, "[[x]]") {
		t.Errorf("título injetou markdown:\n%s", head)
	}
	// The hostile text must sit inside a fence longer than its own ``` run.
	if !strings.Contains(body, "````text\n"+hostile+"\n````") {
		t.Errorf("texto do evento fora do bloco de código:\n%s", body)
	}
	if !strings.Contains(note, "[[Técnicas/T1059 Command and Scripting Interpreter|") {
		t.Error("link da técnica ausente")
	}
	if _, err := os.Stat(filepath.Join(root, "Técnicas", "T1059 Command and Scripting Interpreter.md")); err != nil {
		t.Error("nota da técnica não criada")
	}

	// Admin note + two analyses: the last analysis replaces the first, notes stay.
	os.WriteFile(files[0], []byte(note+"Verificado por Ana.\n"), 0o640)
	v.AppendAnalysis(7, "**Avaliação:** inconclusivo")
	v.AppendAnalysis(7, "**Avaliação:** provável ataque real")
	note = read(t, files[0])
	if strings.Count(note, "## Análise da IA") != 1 || !strings.Contains(note, "provável ataque real") || !strings.Contains(note, "Verificado por Ana.") {
		t.Errorf("análise/nota:\n%s", note)
	}
	ia, notas, ana := strings.Index(note, "## Análise da IA"), strings.Index(note, notesHeading), strings.Index(note, "Verificado por Ana.")
	if strings.Count(note, notesHeading) != 1 || !(ia < notas && notas < ana) {
		t.Errorf("ordem das seções errada (IA %d, notas %d, texto do admin %d):\n%s", ia, notas, ana, note)
	}

	// Below the threshold: no note.
	v.Alert(context.Background(), watch.Alert{Severity: finding.Medium, Event: e, EventID: 8, Title: "x"})
	if files, _ := filepath.Glob(filepath.Join(root, "Incidentes", "*evento 8*")); len(files) != 0 {
		t.Error("nota criada abaixo do limite")
	}
}

func TestFileNamesStayInsideVault(t *testing.T) {
	for _, in := range []string{"../../etc/passwd", `..\..\x`, "a/b:c*d?e\"f<g>h|i#j^k[l]m", "", "....", strings.Repeat("x", 300)} {
		n := fileName(in)
		if strings.ContainsAny(n, `/\:*?"<>|#^[]`) || strings.HasPrefix(n, ".") || len([]rune(n)) > 83 {
			t.Errorf("fileName(%q) = %q", in, n)
		}
	}
	v, _ := New(t.TempDir(), finding.Info)
	if err := v.write("../fora.md", "x"); err == nil {
		t.Error("escrita fora do cofre permitida")
	}
}
