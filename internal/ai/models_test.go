package ai

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/SantanaCharles/sentinels/internal/config"
)

func TestListModels(t *testing.T) {
	os.Setenv("SENT_LM_KEY", "k")
	defer os.Unsetenv("SENT_LM_KEY")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/models" && r.Header.Get("x-api-key") == "k":
			w.Write([]byte(`{"data":[{"id":"claude-sonnet-5-5"},{"id":"claude-haiku-5-5"}]}`))
		case r.URL.Path == "/v1beta/models" && r.Header.Get("x-goog-api-key") == "k":
			w.Write([]byte(`{"models":[{"name":"models/gemini-x-flash","supportedGenerationMethods":["generateContent"]},{"name":"models/text-embedding","supportedGenerationMethods":["embedContent"]}]}`))
		case r.URL.Path == "/models" && r.Header.Get("Authorization") == "Bearer k":
			w.Write([]byte(`{"data":[{"id":"gpt-x"},{"id":"text-embedding-3"},{"id":"whisper-1"},{"id":"gpt-x-mini"}]}`))
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer srv.Close()
	cases := map[string]string{
		"anthropic": "claude-haiku-5-5,claude-sonnet-5-5",
		"gemini":    "gemini-x-flash",
		"openai":    "gpt-x,gpt-x-mini",
	}
	for prov, want := range cases {
		got, err := ListModels(context.Background(), config.AI{Provider: prov, BaseURL: srv.URL, APIKeyEnv: "SENT_LM_KEY"})
		if err != nil || strings.Join(got, ",") != want {
			t.Errorf("%s: %v %v, quer %s", prov, got, err, want)
		}
	}
	_, err := ListModels(context.Background(), config.AI{Provider: "openai", BaseURL: srv.URL, APIKeyEnv: "SENT_SEM_CHAVE"})
	if err == nil || !strings.Contains(err.Error(), "chave recusada") {
		t.Errorf("chave inválida: %v", err)
	}
}
