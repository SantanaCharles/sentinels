package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/SantanaCharles/sentinels/internal/finding"
	"github.com/SantanaCharles/sentinels/internal/notify"
	"github.com/SantanaCharles/sentinels/internal/store"
	"github.com/SantanaCharles/sentinels/internal/watch"
)

// openStore loads the config from fs/args and opens the local memory.
func openStore(fs *flag.FlagSet, args []string) (*store.Store, []string, int) {
	cfg, err := loadConfig(fs, args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return nil, nil, 2
	}
	st, err := store.Open(cfg.Storage.Path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return nil, nil, 1
	}
	return st, fs.Args(), 0
}

// sentinels feedback <evento> fp|confirmed [--scope rule|ip|target] [--days N] [--note "..."]
func runFeedback(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("feedback", flag.ExitOnError)
	scope := fs.String("scope", "", "falso positivo vale para: rule (a regra em qualquer lugar), ip (a regra vinda deste IP) ou target (a regra contra este alvo); padrão: o mais restrito disponível")
	days := fs.Int("days", 30, "validade do silenciamento em dias (confirmação de IP vale o triplo)")
	note := fs.String("note", "", "observação")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "uso: sentinels feedback [opções] <evento> fp|confirmed")
		fs.PrintDefaults()
	}
	// Accept options after the positional arguments too.
	args = reorder(args)
	st, pos, code := openStore(fs, args)
	if st == nil {
		return code
	}
	defer st.Close()
	if len(pos) != 2 {
		fs.Usage()
		return 2
	}
	id, err := strconv.ParseInt(pos[0], 10, 64)
	if err != nil {
		fmt.Fprintln(os.Stderr, "número de evento inválido:", pos[0])
		return 2
	}
	verdict := map[string]string{"fp": store.VerdictFalsePositive, "falso-positivo": store.VerdictFalsePositive,
		"confirmed": store.VerdictConfirmed, "confirmado": store.VerdictConfirmed}[pos[1]]
	if verdict == "" {
		fmt.Fprintln(os.Stderr, "veredito deve ser fp ou confirmed")
		return 2
	}
	msg, err := st.AddFeedback(ctx, store.Feedback{
		EventID: id, Verdict: verdict, Scope: *scope, Note: *note, TTL: time.Duration(*days) * 24 * time.Hour,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println("ok:", msg)
	return 0
}

// sentinels suppressions [remove <id>]
func runSuppressions(ctx context.Context, args []string) int {
	st, pos, code := openStore(flag.NewFlagSet("suppressions", flag.ExitOnError), args)
	if st == nil {
		return code
	}
	defer st.Close()
	if len(pos) == 2 && pos[0] == "remove" {
		id, err := strconv.ParseInt(pos[1], 10, 64)
		if err == nil {
			err = st.RemoveSuppression(ctx, id)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Printf("regra #%d removida: os eventos voltam a alertar\n", id)
		return 0
	}
	list, err := st.Suppressions(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if len(list) == 0 {
		fmt.Println("nenhum silenciamento ativo")
		return 0
	}
	for _, s := range list {
		scope := "em qualquer lugar"
		if s.SourceIP != "" {
			scope = "de " + s.SourceIP
		}
		if s.Target != "" {
			scope = "contra " + s.Target
		}
		fmt.Printf("#%-4d %-8s %-50s %-25s até %s  (%d silenciado(s)) %s\n",
			s.ID, s.Source, clip(s.Rule, 50), clip(scope, 25), s.ExpiresAt.Format("02/01/2006"), s.Hits, s.Note)
	}
	return 0
}

// sentinels findings — open findings with the key used by `accept`.
func runFindings(ctx context.Context, args []string) int {
	st, _, code := openStore(flag.NewFlagSet("findings", flag.ExitOnError), args)
	if st == nil {
		return code
	}
	defer st.Close()
	list, err := st.OpenFindings(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if len(list) == 0 {
		fmt.Println("nenhum achado aberto (rode `sentinels scan`)")
		return 0
	}
	for _, f := range list {
		acc := ""
		if f.Accepted != "" {
			acc = "  [aceito: " + f.Accepted + "]"
		}
		fmt.Printf("%-7s %-55s %s%s\n", finding.Severity(f.Severity).Label(), clip(f.Key, 55), clip(f.Title, 70), acc)
	}
	return 0
}

// sentinels accept "<id>|<alvo>" --reason "..." [--days 90]
func runAccept(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("accept", flag.ExitOnError)
	reason := fs.String("reason", "", "justificativa (obrigatória)")
	days := fs.Int("days", 90, "validade em dias; depois o achado volta a contar")
	args = reorder(args)
	st, pos, code := openStore(fs, args)
	if st == nil {
		return code
	}
	defer st.Close()
	if len(pos) != 1 {
		fmt.Fprintln(os.Stderr, `uso: sentinels accept "<id>|<alvo>" --reason "..."   (chaves em: sentinels findings)`)
		return 2
	}
	if err := st.AcceptFinding(ctx, pos[0], *reason, time.Duration(*days)*24*time.Hour); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("ok: risco aceito por %d dias; sai da contagem e dos alertas\n", *days)
	return 0
}

// sentinels notify-test — sends a sample alert to every configured channel.
func runNotifyTest(ctx context.Context, args []string) int {
	cfg, err := loadConfig(flag.NewFlagSet("notify-test", flag.ExitOnError), args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	chans, err := notify.Build(cfg.Alerts)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if len(chans) == 0 {
		fmt.Fprintln(os.Stderr, "nenhum notificador em alerts.notifiers")
		return 1
	}
	host, _ := os.Hostname()
	m := notify.FromAlert(watch.Alert{
		Severity: finding.Critical, Title: "Teste de notificação do Sentinels", Target: "teste",
		Lines: []string{"Se você recebeu esta mensagem, o canal está configurado corretamente."},
	}, host)
	failed := 0
	for _, c := range chans {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := c.Notifier.Send(ctx, m)
		cancel()
		if err != nil {
			failed++
			fmt.Printf("[FALHA] %-12s %v\n", c.Notifier.Name(), err)
		} else {
			fmt.Printf("[ok]    %s\n", c.Notifier.Name())
		}
	}
	if failed > 0 {
		return 1
	}
	return 0
}

// reorder moves flags before positional arguments, since the flag package
// stops at the first positional one ("feedback 12 fp --days 7").
func reorder(args []string) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) > 1 && a[0] == '-' {
			flags = append(flags, a)
			if !containsEq(a) && i+1 < len(args) && len(args[i+1]) > 0 && args[i+1][0] != '-' && takesValue(a) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		pos = append(pos, a)
	}
	return append(flags, pos...)
}

func containsEq(s string) bool {
	for _, c := range s {
		if c == '=' {
			return true
		}
	}
	return false
}

// takesValue lists the non-boolean flags of feedback/accept.
func takesValue(flag string) bool {
	switch flag {
	case "-scope", "--scope", "-days", "--days", "-note", "--note", "-reason", "--reason", "-config", "--config":
		return true
	}
	return false
}
