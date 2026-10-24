package config

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// EnvFile is a KEY=VALUE file (sentinels.env) edited in place: comments,
// blank lines and order are preserved.
type EnvFile struct {
	Path  string
	lines []string
}

var envKeyRe = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// LoadEnvFile reads path; a missing file is an empty EnvFile.
func LoadEnvFile(path string) (*EnvFile, error) {
	f := &EnvFile{Path: path}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return f, nil
	}
	if err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f.lines = append(f.lines, sc.Text())
	}
	return f, sc.Err()
}

func parseLine(l string) (key, val string, ok bool) {
	l = strings.TrimSpace(l)
	if l == "" || strings.HasPrefix(l, "#") {
		return "", "", false
	}
	l = strings.TrimPrefix(l, "export ")
	k, v, found := strings.Cut(l, "=")
	if !found {
		return "", "", false
	}
	v = strings.TrimSpace(v)
	if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
		v = v[1 : len(v)-1]
	}
	return strings.TrimSpace(k), v, true
}

// Get returns the value of key ("" when unset or empty).
func (f *EnvFile) Get(key string) string {
	for _, l := range f.lines {
		if k, v, ok := parseLine(l); ok && k == key {
			return v
		}
	}
	return ""
}

// Set replaces key's value or appends it. Values with newlines are refused:
// systemd's EnvironmentFile and docker's env_file are line based.
func (f *EnvFile) Set(key, val string) error {
	if !envKeyRe.MatchString(key) {
		return fmt.Errorf("nome de variável inválido: %q", key)
	}
	if strings.ContainsAny(val, "\r\n") {
		return fmt.Errorf("o valor de %s não pode ter quebra de linha", key)
	}
	line := key + "=" + val
	for i, l := range f.lines {
		if k, _, ok := parseLine(l); ok && k == key {
			f.lines[i] = line
			return nil
		}
	}
	f.lines = append(f.lines, line)
	return nil
}

// Apply exports every non-empty value into the process environment, so a
// setup session can test what was just typed.
func (f *EnvFile) Apply() {
	for _, l := range f.lines {
		if k, v, ok := parseLine(l); ok && v != "" {
			os.Setenv(k, v)
		}
	}
}

// ApplyMissing exports values that are not already in the environment:
// whatever systemd or Docker injected wins over the file.
func (f *EnvFile) ApplyMissing() {
	for _, l := range f.lines {
		if k, v, ok := parseLine(l); ok && v != "" {
			if _, set := os.LookupEnv(k); !set {
				os.Setenv(k, v)
			}
		}
	}
}

// Save writes atomically with mode 0600, keeping the previous owner.
func (f *EnvFile) Save() error {
	old, statErr := os.Stat(f.Path)
	tmp := f.Path + ".tmp"
	content := ""
	if len(f.lines) > 0 {
		content = strings.Join(f.lines, "\n") + "\n"
	}
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		return err
	}
	if statErr == nil {
		copyOwner(tmp, old)
	}
	return os.Rename(tmp, f.Path)
}
