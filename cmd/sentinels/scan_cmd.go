package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/SantanaCharles/sentinels/internal/config"
	"github.com/SantanaCharles/sentinels/internal/finding"
	"github.com/SantanaCharles/sentinels/internal/report"
	"github.com/SantanaCharles/sentinels/internal/scan"
	"github.com/SantanaCharles/sentinels/internal/store"
)

func runScan(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	out := fs.String("out", "", "diretório do relatório (padrão: scan.report_dir)")
	offline := fs.Bool("offline", false, "não baixar CISA KEV, EPSS nem o feed de alertas")
	noTrivy := fs.Bool("no-trivy", false, "não executar o Trivy")
	noHostOS := fs.Bool("no-host-os", false, "não buscar CVEs do SO do host")
	procRoot := fs.String("proc", "/proc", "raiz do /proc do host")
	failOn := fs.String("fail-on", "", "sai com código 3 se houver achado desta severidade ou maior (ex.: high)")
	quiet := fs.Bool("quiet", false, "não mostrar o progresso")
	noAI := fs.Bool("no-ai", false, "não pedir o resumo executivo à IA")
	cfg, err := loadConfig(fs, args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if *offline {
		cfg.Scan.Offline = true
	}
	if *out != "" {
		cfg.Scan.ReportDir = *out
	}
	var threshold finding.Severity
	if *failOn != "" {
		if threshold, err = finding.ParseSeverity(*failOn); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	}

	log := logf
	if *quiet {
		log = nil
	}
	opt := scan.Options{ProcRoot: *procRoot, NoTrivy: *noTrivy, NoHostOS: *noHostOS, Log: log}

	st, err := store.Open(cfg.Storage.Path)
	if err != nil {
		logf("aviso: memória local indisponível (%v); relatório sem comparação com a varredura anterior", err)
	} else {
		defer st.Close()
	}
	if *noAI {
		cfg.AI.Enabled = false
	}
	res := runAndSave(ctx, cfg, opt, st, buildExtras(cfg))
	if res == nil {
		return 1
	}

	c := finding.Count(res.Findings)
	fmt.Printf("\nCrítico: %d  Alto: %d  Médio: %d  Baixo: %d\n", c[finding.Critical], c[finding.High], c[finding.Medium], c[finding.Low])
	if res.History != nil {
		fmt.Printf("Novos: %d  Resolvidos: %d\n", res.History.New, len(res.History.Resolved))
	}

	if *failOn != "" {
		for _, f := range res.Findings {
			if f.Accepted == "" && f.Severity >= threshold {
				return 3
			}
		}
	}
	return 0
}

// runAndSave scans, compares with the store (when available), asks the AI
// for a summary, and writes the report and vault notes. Shared by `scan` and
// the periodic scans of `watch`.
func runAndSave(ctx context.Context, cfg config.Config, opt scan.Options, st *store.Store, ex extras) *scan.Result {
	res := scan.Run(ctx, cfg, opt)
	if st != nil {
		if err := scan.Remember(ctx, st, res); err != nil {
			res.Warnings = append(res.Warnings, "memória local: "+err.Error())
		}
	}
	if ex.analyst != nil && cfg.AI.ReportSummary {
		logf("IA: gerando resumo executivo (%s)", ex.analyst.Provider.Name())
		actx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		summary, err := ex.analyst.SummarizeReport(actx, res)
		cancel()
		if err != nil {
			res.Warnings = append(res.Warnings, "resumo da IA indisponível: "+err.Error())
		} else {
			res.AISummary = summary
		}
	}
	md, js, err := report.Write(cfg.Scan.ReportDir, res)
	if err != nil {
		logf("erro ao salvar o relatório: %v", err)
		return nil
	}
	fmt.Printf("Relatório: %s\nJSON:      %s\n", md, js)
	if ex.vault != nil {
		var b strings.Builder
		report.Markdown(&b, res)
		if err := ex.vault.WriteScan(res, b.String()); err != nil {
			logf("cofre: %v", err)
		}
	}
	return res
}
