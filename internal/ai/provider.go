// Package ai is a single layer over the language-model providers. The model
// only ever receives redacted text and returns text: it has no tools and its
// answer is never executed or treated as an instruction.
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/SantanaCharles/sentinels/internal/config"
)

type Request struct {
	System    string
	User      string
	MaxTokens int
}

type Provider interface {
	Name() string
	Complete(ctx context.Context, r Request) (string, error)
}

// ErrDisabled is returned by New when ai.enabled is false.
var ErrDisabled = errors.New("IA desativada (ai.enabled: false)")

// Defaults for providers that speak the OpenAI chat-completions format.
var compatBase = map[string]string{
	"openai":     "https://api.openai.com/v1",
	"openrouter": "https://openrouter.ai/api/v1",
	"ollama":     "http://127.0.0.1:11434/v1",
	"lmstudio":   "http://127.0.0.1:1234/v1",
}

// New builds the configured provider. Local servers (Ollama, LM Studio) need
// no key; everything else does.
func New(cfg config.AI) (Provider, error) {
	if !cfg.Enabled {
		return nil, ErrDisabled
	}
	if cfg.Model == "" {
		return nil, errors.New("ai.model não informado")
	}
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	client := &http.Client{Timeout: timeout}
	key := config.Secret(cfg.APIKeyEnv)
	p := strings.ToLower(cfg.Provider)
	local := p == "ollama" || p == "lmstudio"
	if key == "" && !local && !(p == "openai-compatible" && isLocalURL(cfg.BaseURL)) {
		return nil, fmt.Errorf("variável %s vazia: defina a chave da API de %s", cfg.APIKeyEnv, cfg.Provider)
	}

	switch p {
	case "anthropic", "claude":
		return &Anthropic{Key: key, Model: cfg.Model, BaseURL: or(cfg.BaseURL, "https://api.anthropic.com"), client: client}, nil
	case "gemini", "google":
		return &Gemini{Key: key, Model: cfg.Model, BaseURL: or(cfg.BaseURL, "https://generativelanguage.googleapis.com"), client: client}, nil
	case "openai", "openrouter", "ollama", "lmstudio", "openai-compatible":
		base := or(cfg.BaseURL, compatBase[p])
		if base == "" {
			return nil, errors.New("openai-compatible exige ai.base_url")
		}
		if !strings.HasPrefix(base, "https://") && !isLocalURL(base) {
			return nil, fmt.Errorf("ai.base_url deve usar https (http só para localhost): %s", base)
		}
		return &OpenAI{Key: key, Model: cfg.Model, BaseURL: base, Label: p,
			// OpenAI's newer models reject max_tokens; compatible servers expect it.
			NewTokenParam: p == "openai", client: client}, nil
	}
	return nil, fmt.Errorf("ai.provider desconhecido: %q", cfg.Provider)
}

func isLocalURL(u string) bool {
	for _, p := range []string{"http://127.0.0.1", "http://localhost", "http://[::1]"} {
		if strings.HasPrefix(u, p) {
			return true
		}
	}
	return false
}

func or(v, def string) string {
	if v != "" {
		return strings.TrimRight(v, "/")
	}
	return def
}

const maxResponse = 1 << 20

// post sends JSON and decodes the reply; error bodies are summarized without
// echoing request headers (which hold the key).
func post(ctx context.Context, c *http.Client, url string, headers map[string]string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Sentinels/0.1")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		msg := string(raw)
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(msg))
	}
	return json.Unmarshal(raw, out)
}

// Anthropic implements the Claude Messages API.
type Anthropic struct {
	Key, Model, BaseURL string
	client              *http.Client
}

func (a *Anthropic) Name() string { return "anthropic/" + a.Model }

func (a *Anthropic) Complete(ctx context.Context, r Request) (string, error) {
	var out struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		StopReason string `json:"stop_reason"`
	}
	err := post(ctx, a.client, a.BaseURL+"/v1/messages",
		map[string]string{"x-api-key": a.Key, "anthropic-version": "2023-06-01"},
		map[string]any{
			"model":      a.Model,
			"max_tokens": r.MaxTokens,
			"system":     r.System,
			"messages":   []map[string]string{{"role": "user", "content": r.User}},
		}, &out)
	if err != nil {
		return "", fmt.Errorf("anthropic: %w", err)
	}
	var sb strings.Builder
	for _, c := range out.Content {
		if c.Type == "text" {
			sb.WriteString(c.Text)
		}
	}
	if sb.Len() == 0 {
		return "", fmt.Errorf("anthropic: resposta vazia (stop_reason=%s)", out.StopReason)
	}
	return sb.String(), nil
}

// OpenAI implements chat completions: OpenAI, OpenRouter, Ollama, LM Studio,
// Groq and any compatible server.
type OpenAI struct {
	Key, Model, BaseURL, Label string
	NewTokenParam              bool
	client                     *http.Client
}

func (o *OpenAI) Name() string { return o.Label + "/" + o.Model }

func (o *OpenAI) Complete(ctx context.Context, r Request) (string, error) {
	body := map[string]any{
		"model": o.Model,
		"messages": []map[string]string{
			{"role": "system", "content": r.System},
			{"role": "user", "content": r.User},
		},
	}
	if o.NewTokenParam {
		body["max_completion_tokens"] = r.MaxTokens
	} else {
		body["max_tokens"] = r.MaxTokens
	}
	headers := map[string]string{}
	if o.Key != "" {
		headers["Authorization"] = "Bearer " + o.Key
	}
	if o.Label == "openrouter" {
		headers["HTTP-Referer"] = "https://github.com/SantanaCharles/sentinels"
		headers["X-Title"] = "Sentinels"
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}
	if err := post(ctx, o.client, o.BaseURL+"/chat/completions", headers, body, &out); err != nil {
		return "", fmt.Errorf("%s: %w", o.Label, err)
	}
	if len(out.Choices) == 0 || out.Choices[0].Message.Content == "" {
		return "", fmt.Errorf("%s: resposta vazia", o.Label)
	}
	return out.Choices[0].Message.Content, nil
}

// Gemini implements generateContent. The key goes in a header, not the URL,
// so it never shows up in logs or errors.
type Gemini struct {
	Key, Model, BaseURL string
	client              *http.Client
}

func (g *Gemini) Name() string { return "gemini/" + g.Model }

func (g *Gemini) Complete(ctx context.Context, r Request) (string, error) {
	var out struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
			FinishReason string `json:"finishReason"`
		} `json:"candidates"`
	}
	err := post(ctx, g.client, g.BaseURL+"/v1beta/models/"+g.Model+":generateContent",
		map[string]string{"x-goog-api-key": g.Key},
		map[string]any{
			"systemInstruction": map[string]any{"parts": []map[string]string{{"text": r.System}}},
			"contents":          []map[string]any{{"role": "user", "parts": []map[string]string{{"text": r.User}}}},
			"generationConfig":  map[string]any{"maxOutputTokens": r.MaxTokens},
		}, &out)
	if err != nil {
		return "", fmt.Errorf("gemini: %w", err)
	}
	var sb strings.Builder
	for _, c := range out.Candidates {
		for _, p := range c.Content.Parts {
			sb.WriteString(p.Text)
		}
		break
	}
	if sb.Len() == 0 {
		return "", errors.New("gemini: resposta vazia ou bloqueada")
	}
	return sb.String(), nil
}
