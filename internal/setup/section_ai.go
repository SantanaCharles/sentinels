package setup

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/huh"

	"github.com/SantanaCharles/sentinels/internal/ai"
)

var providers = []huh.Option[string]{
	huh.NewOption("Claude (Anthropic)", "anthropic"),
	huh.NewOption("OpenAI (GPT)", "openai"),
	huh.NewOption("Google Gemini", "gemini"),
	huh.NewOption("OpenRouter — centenas de modelos com uma chave", "openrouter"),
	huh.NewOption("Ollama — local, nada sai do servidor", "ollama"),
	huh.NewOption("LM Studio — local, nada sai do servidor", "lmstudio"),
	huh.NewOption("Outro compatível com a API da OpenAI (Groq, vLLM…)", "openai-compatible"),
	huh.NewOption("Desativar a IA", "off"),
}

var keyHelp = map[string]string{
	"anthropic":  "Crie em console.anthropic.com → API Keys",
	"openai":     "Crie em platform.openai.com → API keys",
	"gemini":     "Crie em aistudio.google.com → Get API key",
	"openrouter": "Crie em openrouter.ai → Keys",
}

func (s *Session) sectionAI(ctx context.Context) error {
	c := &s.Cfg.AI
	provider := c.Provider
	if !c.Enabled {
		provider = "anthropic"
	}
	if err := s.form(huh.NewSelect[string]().Title("Qual IA o Sentinels deve usar?").
		Description("A detecção funciona sem IA; ela só resume relatórios e explica alertas.").
		Options(providers...).Value(&provider)); err != nil {
		return err
	}
	if provider == "off" {
		if c.Enabled {
			c.Enabled, s.dirty = false, true
		}
		fmt.Fprintln(s.Out, "IA desativada.")
		return nil
	}
	if provider != c.Provider {
		c.Model, c.BaseURL = "", ""
	}
	c.Provider, c.Enabled, s.dirty = provider, true, true
	if c.APIKeyEnv == "" {
		c.APIKeyEnv = "SENTINELS_AI_KEY"
	}

	switch provider {
	case "openai-compatible", "ollama", "lmstudio":
		base := c.BaseURL
		if base == "" {
			base = ai.DefaultBaseURL(provider)
		}
		if err := s.form(huh.NewInput().Title("Endereço da API (base URL)").
			Description("Ex.: http://127.0.0.1:11434/v1 (Ollama), http://127.0.0.1:1234/v1 (LM Studio). Use https fora de localhost.").
			Value(&base).Validate(func(v string) error {
			if !strings.HasPrefix(v, "https://") && !strings.HasPrefix(v, "http://127.0.0.1") && !strings.HasPrefix(v, "http://localhost") {
				return errors.New("use https (http só para localhost)")
			}
			return nil
		})); err != nil {
			return err
		}
		c.BaseURL = strings.TrimRight(base, "/")
		if c.BaseURL == ai.DefaultBaseURL(provider) {
			c.BaseURL = ""
		}
	}

	if ai.NeedsKey(provider, c.BaseURL) {
		if err := s.secret("Chave da API — "+keyHelp[provider], c.APIKeyEnv, nil); err != nil {
			return err
		}
	}

	if err := s.pickModel(ctx); err != nil {
		return err
	}

	maxCalls := strconv.Itoa(c.MaxCallsHour)
	if err := s.form(
		huh.NewSelect[string]().Title("Quais alertas recebem análise da IA?").Options(severityOptions...).Value(&c.MinSeverity),
		huh.NewInput().Title("Limite de análises por hora (controle de custo)").Value(&maxCalls).Validate(func(v string) error {
			if n, err := strconv.Atoi(v); err != nil || n < 1 || n > 1000 {
				return errors.New("número entre 1 e 1000")
			}
			return nil
		}),
		huh.NewConfirm().Title("Resumo executivo no topo de cada relatório?").Affirmative("Sim").Negative("Não").Value(&c.ReportSummary),
		huh.NewConfirm().Title("Enviar IPs reais para a IA?").
			Description("Não (recomendado, LGPD): IPs viram [IP-1], [IP-2]…").Affirmative("Sim").Negative("Não").Value(&c.KeepIPs),
	); err != nil {
		return err
	}
	c.MaxCallsHour, _ = strconv.Atoi(maxCalls)

	if s.confirm("Testar a IA agora?", true) {
		s.testAI(ctx)
	}
	return nil
}

// pickModel lists the provider's models when possible, falling back to
// typing the name.
func (s *Session) pickModel(ctx context.Context) error {
	c := &s.Cfg.AI
	fmt.Fprintln(s.Out, "Buscando os modelos disponíveis…")
	lctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	models, err := ai.ListModels(lctx, *c)
	cancel()
	if err == nil && len(models) > 0 {
		if c.Model == "" {
			c.Model = suggestedModel(c.Provider, models)
		}
		opts := make([]huh.Option[string], 0, len(models)+1)
		for _, m := range models {
			opts = append(opts, huh.NewOption(m, m))
		}
		opts = append(opts, huh.NewOption("✎ digitar outro nome", ""))
		sel := c.Model
		if err := s.form(huh.NewSelect[string]().Title(fmt.Sprintf("Modelo (%d disponíveis — digite / para filtrar)", len(models))).
			Options(opts...).Filtering(true).Height(14).Value(&sel)); err != nil {
			return err
		}
		if sel != "" {
			c.Model = sel
			return nil
		}
	} else if err != nil {
		fmt.Fprintf(s.Out, "Não consegui listar os modelos (%v). Digite o nome.\n", err)
	}
	return s.form(huh.NewInput().Title("Nome do modelo").Value(&c.Model).Validate(func(v string) error {
		if strings.TrimSpace(v) == "" {
			return errors.New("obrigatório")
		}
		return nil
	}))
}

// suggestedModel pre-selects a sensible default from the provider's list.
func suggestedModel(provider string, models []string) string {
	prefer := map[string][]string{
		"anthropic":  {"claude-sonnet"},
		"openai":     {"gpt-5-mini", "gpt-5", "gpt-4.1-mini"},
		"gemini":     {"flash", "pro"},
		"openrouter": {"anthropic/claude-sonnet", "openai/gpt-5-mini"},
	}
	for _, p := range prefer[provider] {
		best := ""
		for _, m := range models {
			if strings.Contains(m, p) && m > best { // newest name sorts last
				best = m
			}
		}
		if best != "" {
			return best
		}
	}
	return models[0]
}

func (s *Session) testAI(ctx context.Context) {
	p, err := ai.New(s.Cfg.AI)
	if err != nil {
		fmt.Fprintln(s.Out, "✖", err)
		return
	}
	tctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	start := time.Now()
	out, err := p.Complete(tctx, ai.Request{System: "Responda apenas com a palavra OK.", User: "teste de conexão", MaxTokens: 20})
	if err != nil {
		fmt.Fprintf(s.Out, "✖ %s: %v\n", p.Name(), err)
		return
	}
	fmt.Fprintf(s.Out, "✔ %s respondeu em %s: %s\n", p.Name(), time.Since(start).Round(time.Millisecond), strings.TrimSpace(ai.SafeMarkdown(out)))
}
