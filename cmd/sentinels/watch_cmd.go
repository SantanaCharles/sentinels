package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/SantanaCharles/sentinels/internal/ai"
	"github.com/SantanaCharles/sentinels/internal/config"
	"github.com/SantanaCharles/sentinels/internal/finding"
	"github.com/SantanaCharles/sentinels/internal/integrations"
	"github.com/SantanaCharles/sentinels/internal/notify"
	"github.com/SantanaCharles/sentinels/internal/scan"
	"github.com/SantanaCharles/sentinels/internal/store"
	"github.com/SantanaCharles/sentinels/internal/telegram"
	"github.com/SantanaCharles/sentinels/internal/watch"
)

func runWatch(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "alertas em JSON, um por linha")
	noScan := fs.Bool("no-scan", false, "não executar varreduras periódicas")
	procRoot := fs.String("proc", "/proc", "raiz do /proc do host")
	cfg, err := loadConfig(fs, args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	minSev, err := finding.ParseSeverity(cfg.Alerts.MinSeverity)
	if err != nil {
		fmt.Fprintln(os.Stderr, "alerts.min_severity:", err)
		return 2
	}
	st, err := store.Open(cfg.Storage.Path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "memória local (%s): %v\n", cfg.Storage.Path, err)
		return 1
	}
	defer st.Close()

	sources, err := buildSources(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if len(sources) == 0 && *noScan {
		fmt.Fprintln(os.Stderr, "nenhuma fonte de eventos disponível e varreduras desativadas; veja `sentinels doctor`")
		return 1
	}
	for _, s := range sources {
		logf("fonte ativa: %s", s.Name())
	}

	chans, err := notify.Build(cfg.Alerts)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	host, _ := os.Hostname()
	fan := notify.NewFanout(ctx, host, chans, logf)
	defer fan.Wait()
	for _, c := range chans {
		logf("notificador ativo: %s (a partir de %s)", c.Notifier.Name(), c.MinSeverity.Label())
	}
	if len(chans) == 0 {
		logf("nenhum notificador configurado: alertas só no log (configure alerts.notifiers)")
	}

	ex := buildExtras(cfg)
	alerters := watch.Multi{&watch.LogAlerter{W: os.Stdout, JSON: *jsonOut}, fan}
	if ex.vault != nil {
		alerters = append(alerters, ex.vault)
		logf("cofre Obsidian: %s", cfg.Vault.Path)
	}
	if ex.analyst != nil {
		aiMin, err := finding.ParseSeverity(cfg.AI.MinSeverity)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ai.min_severity:", err)
			return 2
		}
		explainer := &ai.Explainer{
			Analyst: ex.analyst, MinSeverity: aiMin, MaxPerHour: cfg.AI.MaxCallsHour, Log: logf,
			OnResult: func(ctx context.Context, a watch.Alert, text string) {
				if err := st.SetAINote(ctx, a.EventID, text); err != nil {
					logf("IA: análise não gravada: %v", err)
				}
				if ex.vault != nil {
					ex.vault.AppendAnalysis(a.EventID, text)
				}
				// Follow-up message: the original alert already went out without waiting.
				fan.Alert(ctx, watch.Alert{
					Severity: a.Severity, Title: "Análise da IA — " + a.Title, Target: a.Target,
					EventID: a.EventID, Lines: strings.Split(text, "\n"),
				})
				logf("IA: evento #%d analisado", a.EventID)
			},
		}
		alerters = append(alerters, explainer)
		defer explainer.Wait()
		logf("IA ativa: %s (análise de alertas a partir de %s, até %d/hora)", ex.analyst.Provider.Name(), aiMin.Label(), cfg.AI.MaxCallsHour)
	}

	for _, bot := range buildBots(cfg, st, ex, host) {
		go func(b *telegram.Bot) {
			if err := b.Run(ctx); err != nil {
				logf("telegram: %v", err)
			}
		}(bot)
	}

	w := &watch.Watcher{
		Store:        st,
		Sources:      sources,
		Alerter:      alerters,
		MinSeverity:  minSev,
		DedupWindow:  config.Duration(cfg.Alerts.DedupWindow, 15*time.Minute),
		ScanInterval: config.Duration(cfg.Scan.Interval, 6*time.Hour),
		Retention:    time.Duration(cfg.Storage.RetentionDays) * 24 * time.Hour,
		Log:          logf,
	}
	if !*noScan {
		opt := scan.Options{ProcRoot: *procRoot, Log: logf}
		w.Scan = func(ctx context.Context) *scan.Result {
			if res := runAndSave(ctx, cfg, opt, st, ex); res != nil {
				return res
			}
			return &scan.Result{}
		}
	}
	if err := w.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	logf("encerrado")
	return 0
}

// buildBots creates one Telegram bot per token among the channels marked
// interactive; each bot obeys only the chat_ids configured for it.
func buildBots(cfg config.Config, st *store.Store, ex extras, host string) []*telegram.Bot {
	byToken := map[string]*telegram.Bot{}
	var out []*telegram.Bot
	for _, n := range cfg.Alerts.Notifiers {
		if n.Type != "telegram" || !n.Interactive || n.ChatID == "" {
			continue
		}
		token := config.Secret(n.TokenEnv)
		if token == "" {
			continue
		}
		b, ok := byToken[token]
		if !ok {
			b = &telegram.Bot{Token: token, AllowedChats: map[string]bool{}, Store: st, ReportDir: cfg.Scan.ReportDir,
				Host: host, Analyst: ex.analyst, MaxAIPerHour: cfg.AI.MaxCallsHour, Log: logf}
			byToken[token] = b
			out = append(out, b)
		}
		b.AllowedChats[n.ChatID] = true
	}
	return out
}

// buildSources turns the integrations section into event sources. "auto"
// enables a source only when its prerequisite is present.
func buildSources(cfg config.Config) ([]integrations.Source, error) {
	var out []integrations.Source
	in := cfg.Integrations

	if m := in.CrowdSec.Mode(); m != "false" {
		key := config.Secret(in.CrowdSec.APIKeyEnv)
		switch {
		case key != "":
			out = append(out, &integrations.CrowdSec{URL: in.CrowdSec.URL, APIKey: key})
		case m == "true":
			return nil, fmt.Errorf("crowdsec habilitado mas %s está vazia (crie com `cscli bouncers add sentinels`)", in.CrowdSec.APIKeyEnv)
		}
	}

	if m := in.Suricata.Mode(); m != "false" {
		_, err := os.Stat(in.Suricata.EveLog)
		switch {
		case err == nil:
			out = append(out, &integrations.Suricata{Path: in.Suricata.EveLog})
		case m == "true":
			return nil, fmt.Errorf("suricata habilitado mas %s não existe", in.Suricata.EveLog)
		}
	}

	if m := in.Falco.Mode(); m != "false" {
		if !integrations.IsLoopback(in.Falco.Listen) {
			return nil, fmt.Errorf("integrations.falco.listen deve ser 127.0.0.1:<porta>, não %q", in.Falco.Listen)
		}
		if m == "true" || falcoInstalled() {
			out = append(out, &integrations.Falco{Listen: in.Falco.Listen})
		}
	}
	return out, nil
}

func falcoInstalled() bool {
	if _, err := exec.LookPath("falco"); err == nil {
		return true
	}
	_, err := os.Stat("/etc/falco")
	return err == nil
}
