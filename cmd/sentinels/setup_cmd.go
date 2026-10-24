package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"

	"github.com/SantanaCharles/sentinels/internal/config"
	"github.com/SantanaCharles/sentinels/internal/setup"
)

// sentinels setup [seção] — interactive wizard.
func runSetup(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	path := fs.String("config", defaultConfig, "arquivo de configuração (criado se não existir)")
	envPath := fs.String("env", "", "arquivo de segredos (padrão: sentinels.env ao lado da configuração)")
	plain := fs.Bool("plain", false, "perguntas simples, sem menus (leitores de tela, terminais limitados)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "uso: sentinels setup [opções] [%s]\n", strings.Join(setup.SectionKeys(), "|"))
		fs.PrintDefaults()
	}
	fs.Parse(reorder(args))

	s, err := setup.Open(*path, *envPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	s.Accessible = *plain || os.Getenv("SENTINELS_PLAIN") == "1" || !term.IsTerminal(int(os.Stdin.Fd()))
	// Skip the background-color query: some VPS web consoles never answer it
	// and the menu would stall. The theme reads well on dark and light.
	lipgloss.SetHasDarkBackground(os.Getenv("SENTINELS_LIGHT") != "1")
	s.Doctor = func(ctx context.Context, cfgPath string) { runDoctor(ctx, []string{"-config", cfgPath}) }

	if err := s.Run(ctx, fs.Arg(0)); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			fmt.Println("Cancelado; nada foi alterado.")
			return 0
		}
		fmt.Fprintln(os.Stderr, "erro:", err)
		return 1
	}
	return 0
}

// sentinels config show | get <chave> | set <chave> <valor> | set-secret <VARIÁVEL>
func runConfig(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("config", flag.ExitOnError)
	path := fs.String("config", defaultConfig, "arquivo de configuração")
	envPath := fs.String("env", "", "arquivo de segredos")
	fs.Parse(reorder(args))
	if *envPath == "" {
		*envPath = filepath.Join(filepath.Dir(*path), "sentinels.env")
	}
	usage := func() int {
		fmt.Fprintln(os.Stderr, `uso:
  sentinels config show                       configuração efetiva + segredos definidos (sem valores)
  sentinels config get ai.model
  sentinels config set alerts.min_severity critical
  sentinels config set scan.urls https://a.com,https://b.com
  sentinels config set-secret SENTINELS_AI_KEY   lê o valor sem eco (ou da entrada padrão)`)
		return 2
	}
	if fs.NArg() == 0 {
		return usage()
	}
	cfg, err := config.Load(*path, true)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	tree, err := toTree(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	switch fs.Arg(0) {
	case "show":
		b, _ := yaml.Marshal(cfg)
		fmt.Printf("# %s\n%s", *path, b)
		env, _ := config.LoadEnvFile(*envPath)
		names := envRefs(cfg)
		fmt.Printf("\n# segredos (%s)\n", *envPath)
		for _, n := range names {
			state := "vazio"
			if env.Get(n) != "" || os.Getenv(n) != "" {
				state = "definido"
			}
			fmt.Printf("%-32s %s\n", n, state)
		}
		return 0
	case "get":
		if fs.NArg() != 2 {
			return usage()
		}
		v, ok := getPath(tree, fs.Arg(1))
		if !ok {
			fmt.Fprintf(os.Stderr, "chave %q não existe\n", fs.Arg(1))
			return 1
		}
		b, _ := yaml.Marshal(v)
		fmt.Print(string(b))
		return 0
	case "set":
		if fs.NArg() != 3 {
			return usage()
		}
		if err := setPath(tree, fs.Arg(1), fs.Arg(2)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		next, err := fromTree(tree)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if err := config.Save(next, *path); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Printf("ok: %s = %s\n", fs.Arg(1), fs.Arg(2))
		return 0
	case "set-secret":
		if fs.NArg() != 2 {
			return usage()
		}
		val, err := readSecret("Valor de " + fs.Arg(1) + ": ")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		env, err := config.LoadEnvFile(*envPath)
		if err == nil {
			err = env.Set(fs.Arg(1), val)
		}
		if err == nil {
			err = env.Save()
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Printf("ok: %s gravado em %s\n", fs.Arg(1), *envPath)
		return 0
	}
	return usage()
}

func readSecret(prompt string) (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, prompt)
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return strings.TrimSpace(string(b)), err
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", errors.New("nenhum valor na entrada padrão")
	}
	return strings.TrimSpace(line), nil
}

// envRefs lists every *_env variable name the configuration points to.
func envRefs(cfg config.Config) []string {
	set := map[string]bool{}
	var walk func(v reflect.Value, t reflect.StructField)
	walk = func(v reflect.Value, f reflect.StructField) {
		switch v.Kind() {
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				walk(v.Field(i), v.Type().Field(i))
			}
		case reflect.Slice:
			for i := 0; i < v.Len(); i++ {
				walk(v.Index(i), f)
			}
		case reflect.String:
			if strings.HasSuffix(strings.Split(f.Tag.Get("yaml"), ",")[0], "_env") && v.String() != "" {
				set[v.String()] = true
			}
		}
	}
	walk(reflect.ValueOf(cfg), reflect.StructField{})
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func toTree(cfg config.Config) (map[string]any, error) {
	b, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	return m, yaml.Unmarshal(b, &m)
}

// fromTree decodes strictly, so a mistyped key is an error instead of being ignored.
func fromTree(m map[string]any) (config.Config, error) {
	b, err := yaml.Marshal(m)
	if err != nil {
		return config.Config{}, err
	}
	cfg := config.Default()
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("chave ou valor inválido: %v", err)
	}
	return cfg, nil
}

func getPath(m map[string]any, path string) (any, bool) {
	var cur any = m
	for _, k := range strings.Split(path, ".") {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = mm[k]; !ok {
			return nil, false
		}
	}
	return cur, true
}

// setPath assigns a scalar or a comma-separated list. Only existing keys or
// direct children of existing sections can be set; lists of channels and
// databases are edited with `sentinels setup`.
func setPath(m map[string]any, path, raw string) error {
	keys := strings.Split(path, ".")
	cur := m
	for _, k := range keys[:len(keys)-1] {
		next, ok := cur[k].(map[string]any)
		if !ok {
			if _, exists := cur[k]; !exists {
				next = map[string]any{}
				cur[k] = next
			} else {
				return fmt.Errorf("%s não é uma seção (use sentinels setup para listas de canais e bancos)", k)
			}
		}
		cur = next
	}
	last := keys[len(keys)-1]
	switch existing := cur[last].(type) {
	case []any:
		_ = existing
		var list []any
		for _, p := range strings.Split(raw, ",") {
			if p = strings.TrimSpace(p); p != "" {
				list = append(list, p)
			}
		}
		cur[last] = list
	case map[string]any:
		return fmt.Errorf("%s é uma seção; informe uma chave dentro dela", path)
	default:
		if b, err := strconv.ParseBool(raw); err == nil && raw != "1" && raw != "0" {
			cur[last] = b
		} else if n, err := strconv.Atoi(raw); err == nil {
			cur[last] = n
		} else if strings.HasSuffix(last, "urls") || last == "to" {
			cur[last] = strings.Split(raw, ",")
		} else {
			cur[last] = raw
		}
	}
	return nil
}
