package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/SantanaCharles/sentinels/internal/ai"
	"github.com/SantanaCharles/sentinels/internal/config"
	"github.com/SantanaCharles/sentinels/internal/finding"
	"github.com/SantanaCharles/sentinels/internal/skills"
	"github.com/SantanaCharles/sentinels/internal/store"
	"github.com/SantanaCharles/sentinels/internal/vault"
	"github.com/SantanaCharles/sentinels/internal/watch"
)

// extras are the optional layers: AI analyst and Obsidian vault.
type extras struct {
	analyst *ai.Analyst
	vault   *vault.Vault
}

func buildExtras(cfg config.Config) extras {
	var ex extras
	if p, err := ai.New(cfg.AI); err == nil {
		lib := skills.Load(cfg.AI.SkillsDir)
		for _, w := range lib.Warnings {
			logf("aviso: %s", w)
		}
		ex.analyst = &ai.Analyst{Provider: p, Skills: lib, KeepIPs: cfg.AI.KeepIPs}
	} else if !errors.Is(err, ai.ErrDisabled) {
		logf("aviso: IA não disponível: %v", err)
	}
	if cfg.Vault.Enabled {
		min, _ := finding.ParseSeverity(cfg.Alerts.MinSeverity)
		v, err := vault.New(cfg.Vault.Path, min)
		if err != nil {
			logf("aviso: cofre %s indisponível: %v", cfg.Vault.Path, err)
		} else {
			ex.vault = v
		}
	}
	return ex
}

// sentinels explain <evento> — AI triage of a stored event.
func runExplain(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("explain", flag.ExitOnError)
	cfg, err := loadConfig(fs, args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "uso: sentinels explain <evento>")
		return 2
	}
	id, err := strconv.ParseInt(fs.Arg(0), 10, 64)
	if err != nil {
		fmt.Fprintln(os.Stderr, "número de evento inválido")
		return 2
	}
	ex := buildExtras(cfg)
	if ex.analyst == nil {
		fmt.Fprintln(os.Stderr, "configure a seção ai (ai.enabled: true) — veja `sentinels ai-test`")
		return 1
	}
	st, err := store.Open(cfg.Storage.Path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer st.Close()
	se, err := st.Event(ctx, id)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	e := se.Event
	lines := append([]string{e.Summary}, e.Context...)
	title := e.Rule
	if n := e.TechniqueName(); n != "" {
		title = n + " — " + e.Rule
	}
	actx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	text, err := ex.analyst.ExplainAlert(actx, watch.Alert{
		Severity: e.Severity, Title: title, Target: e.Target, Lines: lines, Event: &e, Count: se.Count, EventID: id,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("Evento #%d — %s\n\n%s\n", id, ex.analyst.Provider.Name(), text)
	if err := st.SetAINote(ctx, id, text); err != nil {
		logf("aviso: análise não gravada: %v", err)
	}
	if ex.vault != nil {
		ex.vault.AppendAnalysis(id, text)
	}
	return 0
}

// sentinels ai-test — checks the provider and lists the skills in use.
func runAITest(ctx context.Context, args []string) int {
	cfg, err := loadConfig(flag.NewFlagSet("ai-test", flag.ExitOnError), args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	lib := skills.Load(cfg.AI.SkillsDir)
	fmt.Printf("Skills carregadas (%d):\n", len(lib.All()))
	for _, s := range lib.All() {
		fmt.Printf("  %-22s %s\n", s.Name, s.Source)
	}
	for _, w := range lib.Warnings {
		fmt.Println("  aviso:", w)
	}
	p, err := ai.New(cfg.AI)
	if err != nil {
		fmt.Fprintln(os.Stderr, "\nIA:", err)
		return 1
	}
	actx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	start := time.Now()
	out, err := p.Complete(actx, ai.Request{
		System: "Responda apenas com a palavra OK.", User: "teste de conexão", MaxTokens: 20,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n[FALHA] %s: %v\n", p.Name(), err)
		return 1
	}
	fmt.Printf("\n[ok] %s respondeu em %s: %s\n", p.Name(), time.Since(start).Round(time.Millisecond), strings.TrimSpace(ai.SafeMarkdown(out)))
	return 0
}
