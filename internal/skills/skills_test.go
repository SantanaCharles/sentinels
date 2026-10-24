package skills

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func names(ss []Skill) string {
	var n []string
	for _, s := range ss {
		n = append(n, s.Name)
	}
	return strings.Join(n, ",")
}

func TestBuiltinSkillsAreValid(t *testing.T) {
	lib := Load("")
	if len(lib.Warnings) > 0 {
		t.Fatalf("avisos: %v", lib.Warnings)
	}
	if len(lib.All()) != 8 {
		t.Errorf("esperadas 8 skills embutidas, vieram %d: %s", len(lib.All()), names(lib.All()))
	}
	for _, s := range lib.All() {
		if len(s.AppliesTo) == 0 || len(s.Body) < 200 || strings.HasPrefix(s.Body, "---") {
			t.Errorf("skill %s malformada (applies-to=%v, corpo=%d)", s.Name, s.AppliesTo, len(s.Body))
		}
	}
}

func TestSelect(t *testing.T) {
	lib := Load("")
	got := names(lib.Select([]string{"task:report", "postgres.rls_missing", "stack:postgresql"}, 100000))
	for _, want := range []string{"postgres-rls", "lgpd-incidentes"} {
		if !strings.Contains(got, want) {
			t.Errorf("faltou %s em %s", want, got)
		}
	}
	if strings.Contains(got, "php-seguranca") {
		t.Errorf("php selecionada sem motivo: %s", got)
	}
	if strings.Split(got, ",")[0] != "lgpd-incidentes" && strings.Split(got, ",")[0] != "postgres-rls" {
		t.Errorf("ordem por relevância: %s", got)
	}
	if n := len(lib.Select([]string{"task:report", "postgres.rls_missing"}, 10)); n != 0 {
		t.Errorf("orçamento ignorado: %d skills", n)
	}
	if len(lib.Select([]string{"nada:aqui"}, 100000)) != 0 {
		t.Error("seleção sem correspondência")
	}
}

func TestOverrideAndInvalid(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		os.MkdirAll(filepath.Join(dir, name), 0o755)
		os.WriteFile(filepath.Join(dir, name, "SKILL.md"), []byte(content), 0o644)
	}
	write("postgres-rls", "---\nname: postgres-rls\ndescription: versão da empresa\nmetadata:\n  applies-to: \"postgres.*\"\n---\nRegra interna: usamos schema por tenant.\n")
	write("minha-skill", "---\r\nname: minha-skill\r\ndescription: x\r\nmetadata:\r\n  applies-to: \"stack:php\"\r\n---\r\nCorpo com CRLF.\r\n")
	write("quebrada", "sem frontmatter")
	lib := Load(dir)
	if len(lib.Warnings) != 1 || !strings.Contains(lib.Warnings[0], "quebrada") {
		t.Errorf("avisos: %v", lib.Warnings)
	}
	sel := lib.Select([]string{"postgres.rls_missing"}, 100000)
	for _, s := range sel {
		if s.Name == "postgres-rls" && !strings.Contains(s.Body, "schema por tenant") {
			t.Error("skill do admin não substituiu a embutida")
		}
	}
	if !strings.Contains(names(lib.Select([]string{"stack:php"}, 100000)), "minha-skill") {
		t.Error("skill com CRLF não carregada")
	}
}
