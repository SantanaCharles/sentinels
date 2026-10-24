package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/SantanaCharles/sentinels/internal/finding"
	"github.com/SantanaCharles/sentinels/internal/store"
)

func runEvents(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("events", flag.ExitOnError)
	since := fs.Duration("since", 24*time.Hour, "período a listar")
	minFlag := fs.String("min", "low", "severidade mínima")
	limit := fs.Int("limit", 50, "quantidade máxima")
	cfg, err := loadConfig(fs, args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	min, err := finding.ParseSeverity(*minFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	st, err := store.Open(cfg.Storage.Path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer st.Close()

	evs, err := st.Events(ctx, time.Now().Add(-*since), min, *limit)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if len(evs) == 0 {
		fmt.Println("nenhum evento no período")
		return 0
	}
	for _, se := range evs {
		e := se.Event
		tech := e.Technique
		if name := e.TechniqueName(); name != "" {
			tech += " " + name
		}
		mark := ""
		switch {
		case se.Verdict == store.VerdictFalsePositive:
			mark = " [falso positivo]"
		case se.Verdict == store.VerdictConfirmed:
			mark = " [confirmado]"
		case se.Suppressed:
			mark = " [silenciado]"
		}
		fmt.Printf("#%-5d %s  %-7s %-8s x%-4d %-15s %-20s %s%s\n",
			se.ID, se.LastSeen.Format("02/01 15:04"), e.Severity.Label(), e.Source, se.Count,
			e.SourceIP, clip(e.Target, 20), clip(tech+" — "+e.Rule, 90), mark)
		for _, c := range e.Context {
			fmt.Printf("%61s↳ %s\n", "", c)
		}
	}
	return 0
}

func clip(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}
