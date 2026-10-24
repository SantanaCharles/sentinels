// Package skills loads security knowledge written as Agent Skills
// (a folder with a SKILL.md: YAML frontmatter + Markdown body) and picks the
// ones relevant to each AI task.
//
// Built-in skills ship inside the binary; files in the admin's skills
// directory add new skills or replace a built-in one with the same name.
package skills

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed builtin/*/SKILL.md
var builtin embed.FS

type Skill struct {
	Name        string
	Description string
	AppliesTo   []string // tag patterns; a trailing * matches a prefix
	Body        string
	Source      string // "embutida" or the file path
}

type frontmatter struct {
	Name        string            `yaml:"name"`
	Description string            `yaml:"description"`
	Metadata    map[string]string `yaml:"metadata"`
}

const maxSkillSize = 64 << 10

// Parse reads one SKILL.md.
func Parse(b []byte, source string) (Skill, error) {
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	if !bytes.HasPrefix(b, []byte("---\n")) {
		return Skill{}, errors.New("sem frontmatter (o arquivo deve começar com ---)")
	}
	rest := b[4:]
	end := bytes.Index(rest, []byte("\n---"))
	if end < 0 {
		return Skill{}, errors.New("frontmatter sem fechamento ---")
	}
	var fm frontmatter
	if err := yaml.Unmarshal(rest[:end], &fm); err != nil {
		return Skill{}, fmt.Errorf("frontmatter inválido: %w", err)
	}
	if fm.Name == "" || fm.Description == "" {
		return Skill{}, errors.New("name e description são obrigatórios")
	}
	body := rest[end+4:]
	if i := bytes.IndexByte(body, '\n'); i >= 0 {
		body = body[i+1:]
	}
	s := Skill{Name: fm.Name, Description: fm.Description, Body: strings.TrimSpace(string(body)), Source: source}
	for _, t := range strings.Split(fm.Metadata["applies-to"], ",") {
		if t = strings.ToLower(strings.TrimSpace(t)); t != "" {
			s.AppliesTo = append(s.AppliesTo, t)
		}
	}
	return s, nil
}

type Library struct {
	skills   []Skill
	Warnings []string
}

// Load reads the built-in skills and then dir (may be empty or missing).
func Load(dir string) *Library {
	lib := &Library{}
	byName := map[string]int{}
	add := func(s Skill) {
		if i, ok := byName[s.Name]; ok {
			lib.skills[i] = s
			return
		}
		byName[s.Name] = len(lib.skills)
		lib.skills = append(lib.skills, s)
	}

	entries, _ := fs.Glob(builtin, "builtin/*/SKILL.md")
	for _, p := range entries {
		b, _ := builtin.ReadFile(p)
		s, err := Parse(b, "embutida")
		if err != nil {
			lib.Warnings = append(lib.Warnings, fmt.Sprintf("skill embutida %s: %v", path.Dir(p), err))
			continue
		}
		add(s)
	}

	if dir != "" {
		files, _ := filepath.Glob(filepath.Join(dir, "*", "SKILL.md"))
		sort.Strings(files)
		for _, p := range files {
			st, err := os.Stat(p)
			if err != nil || st.Size() > maxSkillSize {
				lib.Warnings = append(lib.Warnings, fmt.Sprintf("skill %s ignorada (ausente ou maior que 64 KB)", p))
				continue
			}
			b, err := os.ReadFile(p)
			if err == nil {
				var s Skill
				if s, err = Parse(b, p); err == nil {
					add(s)
					continue
				}
			}
			lib.Warnings = append(lib.Warnings, fmt.Sprintf("skill %s: %v", p, err))
		}
	}
	sort.Slice(lib.skills, func(i, j int) bool { return lib.skills[i].Name < lib.skills[j].Name })
	return lib
}

func (l *Library) All() []Skill { return l.skills }

// Select returns the skills matching tags, best match first, within budget
// characters of body text.
func (l *Library) Select(tags []string, budget int) []Skill {
	type scored struct {
		s     Skill
		score int
	}
	var cands []scored
	for _, s := range l.skills {
		n := 0
		for _, pat := range s.AppliesTo {
			for _, t := range tags {
				if match(pat, strings.ToLower(t)) {
					n++
					break
				}
			}
		}
		if n > 0 {
			cands = append(cands, scored{s, n})
		}
	}
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].score != cands[j].score {
			return cands[i].score > cands[j].score
		}
		return cands[i].s.Name < cands[j].s.Name
	})
	var out []Skill
	used := 0
	for _, c := range cands {
		if used+len(c.s.Body) > budget {
			continue
		}
		used += len(c.s.Body)
		out = append(out, c.s)
	}
	return out
}

func match(pattern, tag string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(tag, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == tag
}

// Render formats skills as the reference section of a system prompt.
func Render(ss []Skill) string {
	if len(ss) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n# Conhecimento de referência\n")
	for _, s := range ss {
		fmt.Fprintf(&b, "\n## %s\n%s\n", s.Name, s.Body)
	}
	return b.String()
}
