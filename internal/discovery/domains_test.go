package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDomainsFromLabels(t *testing.T) {
	got := DomainsFromLabels(map[string]string{
		"traefik.http.routers.loja.rule":  "Host(`loja.exemplo.com.br`) || Host(`www.loja.exemplo.com.br`)",
		"traefik.http.routers.api.rule":   "Host(`api.exemplo.com.br`, `API.exemplo.com.br`) && PathPrefix(`/v1`)",
		"traefik.http.routers.wild.rule":  "HostRegexp(`{sub:[a-z]+}.exemplo.com.br`)",
		"traefik.http.routers.local.rule": "Host(`app.localhost`)",
		"traefik.http.services.loja.port": "80",
		"caddy":                           "blog.exemplo.com.br, https://docs.exemplo.com.br",
		"caddy.reverse_proxy":             "{{upstreams 80}}",
		"com.docker.compose.project":      "x",
	})
	want := "api.exemplo.com.br,blog.exemplo.com.br,docs.exemplo.com.br,loja.exemplo.com.br,www.loja.exemplo.com.br"
	if strings.Join(got, ",") != want {
		t.Errorf("domínios:\n%v\nquer:\n%s", got, want)
	}
}

func TestServiceLabels(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/services" {
			w.WriteHeader(404)
			return
		}
		w.Write([]byte(`[{"Spec":{"Labels":{"traefik.http.routers.n8n.rule":"Host(` + "`n8n.exemplo.com.br`" + `)"}}}]`))
	}))
	defer srv.Close()
	labels := NewClient("tcp://" + strings.TrimPrefix(srv.URL, "http://")).ServiceLabels(context.Background())
	if len(labels) != 1 || DomainsFromLabels(labels[0])[0] != "n8n.exemplo.com.br" {
		t.Errorf("labels de serviço: %v", labels)
	}
	if NewClient("tcp://127.0.0.1:1").ServiceLabels(context.Background()) != nil {
		t.Error("sem Swarm deveria retornar nil")
	}
}
