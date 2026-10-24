package ai

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/SantanaCharles/sentinels/internal/finding"
	"github.com/SantanaCharles/sentinels/internal/scan"
	"github.com/SantanaCharles/sentinels/internal/skills"
	"github.com/SantanaCharles/sentinels/internal/watch"
)

const skillBudget = 14000 // characters of reference knowledge per request

// Analyst turns Sentinels data into prompts and model answers into safe text.
type Analyst struct {
	Provider Provider
	Skills   *skills.Library
	KeepIPs  bool
}

func (a *Analyst) ask(ctx context.Context, tags []string, task, data string, maxTokens int) (string, error) {
	r := NewRedactor(a.KeepIPs)
	system := systemBase
	if a.Skills != nil {
		system += skills.Render(a.Skills.Select(tags, skillBudget))
	}
	out, err := a.Provider.Complete(ctx, Request{
		System:    system,
		User:      task + "\n\n" + Data(r.Redact(data)),
		MaxTokens: maxTokens,
	})
	if err != nil {
		return "", err
	}
	return SafeMarkdown(out), nil
}

// SummarizeReport writes the executive summary placed at the top of a report.
func (a *Analyst) SummarizeReport(ctx context.Context, res *scan.Result) (string, error) {
	tags := []string{"task:report"}
	var b strings.Builder
	fmt.Fprintf(&b, "Servidor com %d container(s).\n\nInventário:\n", len(res.Assets))
	for _, as := range res.Assets {
		fmt.Fprintf(&b, "- %s (%s): %s; portas públicas: %s\n", as.Name, as.Stack.Kind,
			strings.Join(as.Stack.Components, ", "), strings.Join(as.PublicPorts, ", "))
		for _, c := range as.Stack.Components {
			tags = append(tags, "stack:"+strings.ToLower(c))
		}
	}
	c := finding.Count(res.Findings)
	fmt.Fprintf(&b, "\nTotais: crítico %d, alto %d, médio %d, baixo %d.\n\nAchados (mais urgentes primeiro):\n",
		c[finding.Critical], c[finding.High], c[finding.Medium], c[finding.Low])
	n := 0
	for _, f := range res.Findings {
		if f.Accepted != "" || f.Severity < finding.Medium {
			continue
		}
		tags = append(tags, f.ID)
		if n++; n > 40 {
			continue // keep tags from every finding, but cap the listing
		}
		fmt.Fprintf(&b, "- [%s] %s — alvo %s — id %s", f.Severity.Label(), f.Title, f.Target, f.ID)
		if f.CVE != "" {
			fmt.Fprintf(&b, " — %s", f.CVE)
		}
		if f.KEV {
			b.WriteString(" — explorada ativamente (KEV)")
		}
		if f.EPSS > 0 {
			fmt.Fprintf(&b, " — EPSS %.0f%%", f.EPSS*100)
		}
		if f.New {
			b.WriteString(" — NOVO")
		}
		b.WriteString("\n")
	}
	if n > 40 {
		fmt.Fprintf(&b, "… e mais %d achado(s) médios/altos.\n", n-40)
	}
	if h := res.History; h != nil {
		fmt.Fprintf(&b, "\nDesde a varredura anterior: %d novo(s), %d resolvido(s).\n", h.New, len(h.Resolved))
	}

	task := `Escreva o resumo executivo deste relatório de segurança em Markdown, com no máximo 280 palavras:
1. Um parágrafo com a situação geral, em linguagem que o dono do negócio entenda.
2. "### Prioridades" com no máximo 5 ações numeradas, da mais urgente para a menos, cada uma
   citando o alvo. Agrupe achados repetidos da mesma causa numa ação só.
3. Se houver risco a dados pessoais, uma linha sobre LGPD.
Não repita a lista inteira de achados; ela já está no relatório.`
	return a.ask(ctx, tags, task, b.String(), 1200)
}

// ExplainAlert triages one real-time alert.
func (a *Analyst) ExplainAlert(ctx context.Context, al watch.Alert) (string, error) {
	tags := []string{"task:triage", "task:explain", "severity:" + al.Severity.String()}
	var b strings.Builder
	fmt.Fprintf(&b, "Severidade calculada: %s\nTítulo: %s\nAlvo: %s\n", al.Severity.Label(), al.Title, al.Target)
	for _, c := range al.Stack {
		tags = append(tags, "stack:"+strings.ToLower(c))
	}
	if len(al.Stack) > 0 {
		fmt.Fprintf(&b, "Stack do alvo: %s\n", strings.Join(al.Stack, ", "))
	}
	if e := al.Event; e != nil {
		fmt.Fprintf(&b, "Fonte: %s\nRegra: %s\nTécnica ATT&CK: %s %s (%s)\nIP de origem: %s\nOcorrências: %d\n",
			e.Source, e.Rule, e.Technique, e.TechniqueName(), e.Tactic, e.SourceIP, al.Count)
		tags = append(tags, "source:"+e.Source, strings.ToLower(e.Technique))
		if base, _, ok := strings.Cut(e.Technique, "."); ok {
			tags = append(tags, strings.ToLower(base))
		}
		raw := string(e.Raw)
		if len(raw) > 2000 {
			raw = raw[:2000] + "…"
		}
		if raw != "" {
			fmt.Fprintf(&b, "Registro original (truncado): %s\n", raw)
		}
	}
	for _, l := range al.Lines {
		fmt.Fprintf(&b, "- %s\n", l)
		if strings.Contains(l, "CVE-") {
			tags = append(tags, "cve.*")
		}
		if strings.Contains(l, "PHP2Shell") {
			tags = append(tags, "advisory.php2shell-2026-10")
		}
	}
	return a.ask(ctx, tags, "Faça a triagem deste alerta seguindo o formato da skill triagem-alertas.", b.String(), 900)
}

// Explainer asks the model about severe alerts in the background. It never
// delays the original alert, runs at most two requests at a time and stops
// at MaxPerHour to bound cost.
type Explainer struct {
	Analyst     *Analyst
	MinSeverity finding.Severity
	MaxPerHour  int
	OnResult    func(ctx context.Context, a watch.Alert, analysis string)
	Log         func(format string, args ...any)

	once    sync.Once
	sem     chan struct{}
	wg      sync.WaitGroup
	mu      sync.Mutex
	window  time.Time
	calls   int
	skipped int
}

func (x *Explainer) Alert(ctx context.Context, a watch.Alert) error {
	if a.EventID == 0 || a.Severity < x.MinSeverity {
		return nil
	}
	x.once.Do(func() { x.sem = make(chan struct{}, 2) })
	if !x.take(time.Now()) {
		return nil
	}
	x.wg.Add(1)
	go func() {
		defer x.wg.Done()
		select {
		case x.sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		defer func() { <-x.sem }()
		cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		text, err := x.Analyst.ExplainAlert(cctx, a)
		if err != nil {
			x.logf("IA: análise do evento #%d falhou: %v", a.EventID, err)
			return
		}
		if x.OnResult != nil {
			x.OnResult(ctx, a, text)
		}
	}()
	return nil
}

// Wait blocks until pending analyses finish.
func (x *Explainer) Wait() { x.wg.Wait() }

func (x *Explainer) take(now time.Time) bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	if now.Sub(x.window) >= time.Hour {
		if x.skipped > 0 {
			x.logf("IA: %d alerta(s) ficaram sem análise na última hora por limite de custo (ai.max_calls_per_hour)", x.skipped)
		}
		x.window, x.calls, x.skipped = now, 0, 0
	}
	if x.MaxPerHour > 0 && x.calls >= x.MaxPerHour {
		x.skipped++
		return false
	}
	x.calls++
	return true
}

func (x *Explainer) logf(format string, args ...any) {
	if x.Log != nil {
		x.Log(format, args...)
	}
}
