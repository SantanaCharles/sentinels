package discovery

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeDocker answers the three GET endpoints the agent uses, and fails the
// test on anything else: the agent must stay read-only.
func fakeDocker(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("método %s em %s: o agente deve ser somente leitura", r.Method, r.URL.Path)
		}
		switch {
		case r.URL.Path == "/version":
			w.Write([]byte(`{"Version":"29.0"}`))
		case r.URL.Path == "/containers/json":
			w.Write([]byte(`[{"Id":"abc"}]`))
		case r.URL.Path == "/containers/abc/json":
			w.Write([]byte(`{"Id":"abc","Name":"/web","Config":{"Image":"php:8.3.10-apache","User":"","Env":["PHP_VERSION=8.3.10","DB_PASSWORD=segredo"]},
				"HostConfig":{"NetworkMode":"bridge"},"NetworkSettings":{"Ports":{"80/tcp":[{"HostIp":"0.0.0.0","HostPort":"8080"}]}}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func TestClientOverTCPAndUnix(t *testing.T) {
	tcp := httptest.NewServer(fakeDocker(t))
	defer tcp.Close()

	dir := t.TempDir()
	sock := dir + "/docker.sock"
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip("socket unix indisponível:", err)
	}
	unix := &httptest.Server{Listener: ln, Config: &http.Server{Handler: fakeDocker(t)}}
	unix.Start()
	defer unix.Close()

	for _, addr := range []string{"tcp://" + strings.TrimPrefix(tcp.URL, "http://"), sock, "unix://" + sock} {
		c := NewClient(addr)
		if err := c.Ping(context.Background()); err != nil {
			t.Fatalf("%s: %v", addr, err)
		}
		cs, err := c.Containers(context.Background())
		if err != nil || len(cs) != 1 {
			t.Fatalf("%s: %v %v", addr, cs, err)
		}
		got := cs[0]
		if got.Name != "web" || got.Versions["PHP_VERSION"] != "8.3.10" || len(got.Ports) != 1 || !got.Ports[0].Public() {
			t.Errorf("%s: container %+v", addr, got)
		}
		for _, k := range got.EnvKeys {
			if strings.Contains(k, "segredo") {
				t.Error("valor de variável de ambiente mantido")
			}
		}
		if _, ok := got.Versions["DB_PASSWORD"]; ok {
			t.Error("segredo guardado como versão")
		}
	}
}
