// Package vault writes an Obsidian-compatible folder of Markdown notes:
// reports, incidents, one note per asset and per ATT&CK technique, all
// linked with [[wikilinks]] so the graph view shows what touched what.
//
// The agent only writes. Text that came from logs is always placed inside a
// code fence, so it renders literally: no remote images, links or embeds can
// be smuggled into a note the administrator opens.
package vault

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/SantanaCharles/sentinels/internal/event"
	"github.com/SantanaCharles/sentinels/internal/finding"
	"github.com/SantanaCharles/sentinels/internal/scan"
	"github.com/SantanaCharles/sentinels/internal/watch"
)

const (
	dirReports    = "Relatórios"
	dirIncidents  = "Incidentes"
	dirAssets     = "Ativos"
	dirTechniques = "Técnicas"
	notesHeading  = "## Notas do administrador"
	notesMarker   = "<!-- sentinels:notas — escreva abaixo; o agente preserva este trecho -->"
)

type Vault struct {
	Root string
	// MinSeverity: alerts below it do not create incident notes.
	MinSeverity finding.Severity
	mu          sync.Mutex
}

func New(root string, min finding.Severity) (*Vault, error) {
	for _, d := range []string{dirReports, dirIncidents, dirAssets, dirTechniques} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o750); err != nil {
			return nil, err
		}
	}
	return &Vault{Root: root, MinSeverity: min}, nil
}

// WriteScan stores the report and refreshes asset notes and the home page.
func (v *Vault) WriteScan(res *scan.Result, reportMD string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	stamp := res.Started.Format("2006-01-02 1504")
	reportName := "Relatório " + stamp
	c := finding.Count(res.Findings)

	var b strings.Builder
	fmt.Fprintf(&b, "---\ntipo: relatorio\ndata: %s\ncritico: %d\nalto: %d\nmedio: %d\nbaixo: %d\ntags: [sentinels/relatorio]\n---\n",
		res.Started.Format(time.RFC3339), c[finding.Critical], c[finding.High], c[finding.Medium], c[finding.Low])
	b.WriteString("Ativos: ")
	for i, a := range res.Assets {
		if i > 0 {
			b.WriteString(" · ")
		}
		b.WriteString(link(dirAssets, a.Name))
	}
	b.WriteString("\n\n")
	b.WriteString(reportMD)
	if err := v.write(filepath.Join(dirReports, fileName(reportName)), b.String()); err != nil {
		return err
	}

	byTarget := map[string][]finding.Finding{}
	for _, f := range res.Findings {
		for _, t := range strings.Split(f.Target, ", ") {
			byTarget[t] = append(byTarget[t], f)
		}
	}
	for _, a := range res.Assets {
		if err := v.writeAsset(a, byTarget[a.Name], reportName); err != nil {
			return err
		}
	}
	return v.writeHome(res, reportName)
}

func (v *Vault) writeAsset(a scan.Asset, fs []finding.Finding, reportName string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "---\ntipo: ativo\nimagem: %q\nstack: %q\ntags: [sentinels/ativo, sentinels/%s]\n---\n",
		a.Image, strings.Join(a.Stack.Components, ", "), safeTag(string(a.Stack.Kind)))
	fmt.Fprintf(&b, "# %s\n\n", inline(a.Name))
	fmt.Fprintf(&b, "- **Imagem:** `%s`\n- **Tipo:** %s\n- **Stack:** %s\n", inline(a.Image), a.Stack.Kind, inline(strings.Join(a.Stack.Components, ", ")))
	if len(a.PublicPorts) > 0 {
		fmt.Fprintf(&b, "- **Portas públicas:** %s\n", inline(strings.Join(a.PublicPorts, ", ")))
	}
	fmt.Fprintf(&b, "- **Última varredura:** %s\n\n## Achados abertos\n\n", link(dirReports, reportName))
	open := 0
	for _, f := range fs {
		if f.Accepted != "" {
			continue
		}
		open++
		tag := ""
		if f.KEV {
			tag = " — **explorada ativamente (KEV)**"
		}
		fmt.Fprintf(&b, "- **%s** %s%s\n", f.Severity.Label(), inline(f.Title), tag)
	}
	if open == 0 {
		b.WriteString("Nenhum.\n")
	}
	b.WriteString("\n## Incidentes\n\nVeja os backlinks desta nota (painel de links do Obsidian).\n")
	return v.writeWithNotes(filepath.Join(dirAssets, fileName(a.Name)), b.String())
}

func (v *Vault) writeHome(res *scan.Result, reportName string) error {
	c := finding.Count(res.Findings)
	var b strings.Builder
	b.WriteString("---\ntags: [sentinels/inicio]\n---\n# Sentinels — " + inline(res.Host) + "\n\n")
	fmt.Fprintf(&b, "Última varredura: %s — %s\n\n", res.Started.Format("02/01/2006 15:04"), link(dirReports, reportName))
	fmt.Fprintf(&b, "| Crítico | Alto | Médio | Baixo |\n|---|---|---|---|\n| %d | %d | %d | %d |\n\n",
		c[finding.Critical], c[finding.High], c[finding.Medium], c[finding.Low])
	b.WriteString("## Ativos\n\n")
	names := make([]string, 0, len(res.Assets))
	for _, a := range res.Assets {
		names = append(names, a.Name)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(&b, "- %s\n", link(dirAssets, n))
	}
	b.WriteString("\n## Pastas\n\n- `Incidentes/` — um arquivo por alerta\n- `Técnicas/` — MITRE ATT&CK, ligadas aos incidentes\n- `Relatórios/` — histórico de varreduras\n")
	return v.writeWithNotes("Início.md", b.String())
}

// Alert implements watch.Alerter: one note per real-time alert.
func (v *Vault) Alert(_ context.Context, a watch.Alert) error {
	if a.EventID == 0 || a.Event == nil || a.Severity < v.MinSeverity {
		return nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	e := a.Event
	when := e.Time
	if when.IsZero() {
		when = time.Now()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "---\ntipo: incidente\nevento: %d\nseveridade: %s\nfonte: %s\ntecnica: %q\nalvo: %q\ndata: %s\ntags: [sentinels/incidente, sentinels/%s]\n---\n",
		a.EventID, a.Severity.String(), safeTag(e.Source), inline(e.Technique), inline(a.Target), when.Format(time.RFC3339), a.Severity.String())
	fmt.Fprintf(&b, "# %s — %s\n\n", a.Severity.Label(), inline(a.Title))
	if a.Target != "" {
		fmt.Fprintf(&b, "- **Alvo:** %s\n", link(dirAssets, a.Target))
	}
	if e.Technique != "" {
		tn := techniqueNote(e)
		if err := v.ensureTechnique(e, tn); err != nil {
			return err
		}
		fmt.Fprintf(&b, "- **Técnica:** %s\n", link(dirTechniques, tn))
	}
	fmt.Fprintf(&b, "- **Fonte:** %s · **Regra:** %s\n", inline(e.Source), inline(e.Rule))
	if e.SourceIP != "" {
		fmt.Fprintf(&b, "- **IP de origem:** `%s`\n", inline(e.SourceIP))
	}
	fmt.Fprintf(&b, "- **Feedback:** `sentinels feedback %d fp` ou `sentinels feedback %d confirmed`\n\n", a.EventID, a.EventID)
	b.WriteString("## Dados do evento\n\nTexto original dos logs — pode ter sido escrito pelo atacante.\n\n")
	b.WriteString(fence(strings.Join(a.Lines, "\n")))
	return v.writeWithNotes(filepath.Join(dirIncidents, incidentFile(a.EventID, when, a.Title)), b.String())
}

// AppendAnalysis adds the AI triage to an existing incident note.
func (v *Vault) AppendAnalysis(eventID int64, analysis string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	matches, _ := filepath.Glob(filepath.Join(v.Root, dirIncidents, fmt.Sprintf("* evento %d *.md", eventID)))
	if len(matches) == 0 {
		return nil // below the vault threshold, or created before the vault was enabled
	}
	rel, _ := filepath.Rel(v.Root, matches[0])
	cur, err := os.ReadFile(matches[0])
	if err != nil {
		return err
	}
	head, notes, _ := strings.Cut(string(cur), notesMarker)
	head = strings.TrimSuffix(strings.TrimRight(head, "\n"), notesHeading)
	if i := strings.Index(head, "\n## Análise da IA"); i >= 0 {
		head = head[:i+1] // a newer analysis replaces the previous one
	}
	head = strings.TrimRight(head, "\n") + "\n\n## Análise da IA\n\n> Gerada automaticamente; pode conter erros.\n\n" + analysis + "\n\n"
	return v.write(rel, head+notesHeading+"\n\n"+notesMarker+notes)
}

func (v *Vault) ensureTechnique(e *event.Event, name string) error {
	path := filepath.Join(v.Root, dirTechniques, fileName(name))
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	id := strings.ReplaceAll(e.Technique, ".", "/")
	body := fmt.Sprintf("---\ntipo: tecnica\nid: %s\ntatica: %q\ntags: [sentinels/tecnica]\n---\n# %s\n\n- **Tática:** %s\n- **Referência:** https://attack.mitre.org/techniques/%s/\n\nOs incidentes com esta técnica aparecem nos backlinks.\n\n%s\n",
		safeTag(e.Technique), e.Tactic, inline(name), inline(e.Tactic), id, notesMarker)
	return v.write(filepath.Join(dirTechniques, fileName(name)), body)
}

func techniqueNote(e *event.Event) string {
	if n := e.TechniqueName(); n != "" {
		return e.Technique + " " + n
	}
	return e.Technique
}

// writeWithNotes keeps whatever the admin wrote after the notes marker.
func (v *Vault) writeWithNotes(rel, content string) error {
	notes := "\n"
	if cur, err := os.ReadFile(filepath.Join(v.Root, rel)); err == nil {
		if _, after, ok := strings.Cut(string(cur), notesMarker); ok {
			notes = after
		}
	}
	return v.write(rel, strings.TrimRight(content, "\n")+"\n\n"+notesHeading+"\n\n"+notesMarker+notes)
}

// write replaces a file atomically, refusing paths outside the vault.
func (v *Vault) write(rel, content string) error {
	path := filepath.Join(v.Root, rel)
	if r, err := filepath.Rel(v.Root, path); err != nil || strings.HasPrefix(r, "..") {
		return fmt.Errorf("caminho fora do cofre: %s", rel)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

var (
	badFileChars = regexp.MustCompile(`[\\/:*?"<>|#^\[\]\x00-\x1f]+`)
	backticks    = regexp.MustCompile("`+")
	tagChars     = regexp.MustCompile(`[^a-zA-Z0-9_/-]+`)
)

func fileName(name string) string {
	n := strings.TrimSpace(badFileChars.ReplaceAllString(name, "-"))
	n = strings.Trim(n, ". -")
	if r := []rune(n); len(r) > 80 {
		n = string(r[:80])
	}
	if n == "" {
		n = "sem-nome"
	}
	return n + ".md"
}

func incidentFile(id int64, t time.Time, title string) string {
	return fileName(fmt.Sprintf("%s evento %d %s", t.Format("2006-01-02 1504"), id, title))
}

// link builds a wikilink to a note in dir, displayed by its plain name.
func link(dir, name string) string {
	return "[[" + dir + "/" + strings.TrimSuffix(fileName(name), ".md") + "|" + inline(name) + "]]"
}

// inline makes text safe outside a code block: no wikilinks, embeds,
// HTML, table pipes or line breaks.
func inline(s string) string {
	r := strings.NewReplacer("\n", " ", "\r", " ", "[[", "[ [", "]]", "] ]", "![", "!​[", "<", "‹", ">", "›", "|", "¦", "`", "'")
	s = r.Replace(s)
	if rs := []rune(s); len(rs) > 200 {
		s = string(rs[:200]) + "…"
	}
	return s
}

func safeTag(s string) string {
	return tagChars.ReplaceAllString(strings.ToLower(s), "-")
}

// fence wraps text in a code block longer than any backtick run inside it.
func fence(s string) string {
	n := 3
	for _, m := range backticks.FindAllString(s, -1) {
		if len(m) >= n {
			n = len(m) + 1
		}
	}
	f := strings.Repeat("`", n)
	return f + "text\n" + strings.TrimRight(s, "\n") + "\n" + f + "\n"
}
