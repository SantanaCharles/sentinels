package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/SantanaCharles/sentinels/internal/config"
)

// NeedsKey reports whether provider requires an API key.
func NeedsKey(provider, baseURL string) bool {
	switch strings.ToLower(provider) {
	case "ollama", "lmstudio":
		return false
	case "openai-compatible":
		return !isLocalURL(baseURL)
	}
	return true
}

// DefaultBaseURL is the endpoint used when ai.base_url is empty.
func DefaultBaseURL(provider string) string {
	switch strings.ToLower(provider) {
	case "anthropic", "claude":
		return "https://api.anthropic.com"
	case "gemini", "google":
		return "https://generativelanguage.googleapis.com"
	}
	return compatBase[strings.ToLower(provider)]
}

// ListModels asks the provider which models the key can use, so setup can
// offer a real list instead of a guessed name. ai.enabled is not required.
func ListModels(ctx context.Context, cfg config.AI) ([]string, error) {
	p := strings.ToLower(cfg.Provider)
	base := or(cfg.BaseURL, DefaultBaseURL(p))
	if base == "" {
		return nil, fmt.Errorf("informe a URL base")
	}
	key := config.Secret(cfg.APIKeyEnv)
	client := &http.Client{Timeout: 20 * time.Second}

	var url string
	headers := map[string]string{}
	switch p {
	case "anthropic", "claude":
		url = base + "/v1/models?limit=100"
		headers["x-api-key"] = key
		headers["anthropic-version"] = "2023-06-01"
	case "gemini", "google":
		url = base + "/v1beta/models?pageSize=200"
		headers["x-goog-api-key"] = key
	default:
		url = base + "/models"
		if key != "" {
			headers["Authorization"] = "Bearer " + key
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return nil, fmt.Errorf("chave recusada pelo provedor (HTTP %d)", resp.StatusCode)
		}
		return nil, fmt.Errorf("HTTP %d ao listar modelos", resp.StatusCode)
	}

	var doc struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
		Models []struct {
			Name    string   `json:"name"`
			Methods []string `json:"supportedGenerationMethods"`
		} `json:"models"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("resposta inesperada ao listar modelos: %w", err)
	}
	var out []string
	for _, m := range doc.Data {
		if m.ID != "" && !nonChat(m.ID) {
			out = append(out, m.ID)
		}
	}
	for _, m := range doc.Models {
		for _, meth := range m.Methods {
			if meth == "generateContent" {
				out = append(out, strings.TrimPrefix(m.Name, "models/"))
				break
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// nonChat filters OpenAI-style listings that mix in embedding, audio and
// image models the agent cannot use for text.
func nonChat(id string) bool {
	id = strings.ToLower(id)
	for _, w := range []string{"embed", "whisper", "tts", "dall-e", "moderation", "transcribe", "image", "realtime", "audio"} {
		if strings.Contains(id, w) {
			return true
		}
	}
	return false
}
