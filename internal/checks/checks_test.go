package checks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SantanaCharles/sentinels/internal/discovery"
	"github.com/SantanaCharles/sentinels/internal/finding"
	"github.com/SantanaCharles/sentinels/internal/fingerprint"
	"github.com/SantanaCharles/sentinels/internal/intel"
)

func ids(fs []finding.Finding) map[string]finding.Severity {
	m := map[string]finding.Severity{}
	for _, f := range fs {
		m[f.ID] = f.Severity
	}
	return m
}

func TestContainerRisky(t *testing.T) {
	c := discovery.Container{
		Name: "db", Image: "postgres:16", Privileged: true, NetworkMode: "bridge",
		CapAdd:  []string{"SYS_ADMIN", "CHOWN"},
		EnvKeys: []string{"POSTGRES_PASSWORD", "POSTGRES_PASSWORD_FILE", "TZ"},
		Ports:   []discovery.PortBinding{{ContainerPort: "5432/tcp", HostIP: "0.0.0.0", HostPort: "5432"}},
		Mounts:  []discovery.Mount{{Source: "/var/run/docker.sock", Destination: "/var/run/docker.sock", RW: true}},
	}
	got := ids(Container(c, fingerprint.Detect(c)))
	want := map[string]finding.Severity{
		"container.privileged":      finding.Critical,
		"container.docker_socket":   finding.Critical,
		"container.dangerous_caps":  finding.High,
		"container.root_user":       finding.Medium,
		"exposure.database_public":  finding.Critical,
		"container.env_secrets":     finding.Low,
		"container.no_memory_limit": finding.Low,
	}
	for id, sev := range want {
		if got[id] != sev {
			t.Errorf("%s: severidade %v, quer %v (achados: %v)", id, got[id], sev, got)
		}
	}
}

func TestContainerHardened(t *testing.T) {
	c := discovery.Container{
		Name: "api", Image: "node:22", User: "node", Memory: 512 << 20,
		SecurityOpt: []string{"no-new-privileges:true"},
		Ports:       []discovery.PortBinding{{ContainerPort: "5432/tcp", HostIP: "127.0.0.1", HostPort: "5432"}},
	}
	if fs := Container(c, fingerprint.Detect(c)); len(fs) != 0 {
		t.Errorf("container endurecido gerou achados: %+v", fs)
	}
}

func TestDatabaseOnLocalhostIsNotExposed(t *testing.T) {
	c := discovery.Container{
		Name: "db", Image: "postgres:16",
		Ports: []discovery.PortBinding{{ContainerPort: "5432/tcp", HostIP: "127.0.0.1", HostPort: "5432"}},
	}
	if _, ok := ids(Container(c, fingerprint.Detect(c)))["exposure.database_public"]; ok {
		t.Error("banco em 127.0.0.1 marcado como exposto")
	}
}

func TestPHPFingerprint(t *testing.T) {
	for _, c := range []discovery.Container{
		{Image: "moodlehq/moodle-php-apache:8.3"},
		{Image: "nextcloud:29-apache"},
		{Image: "wordpress:6.6"},
		{Image: "myapp:latest", Versions: map[string]string{"PHP_VERSION": "8.3.12"}},
	} {
		if !fingerprint.Detect(c).IsPHP() {
			t.Errorf("%s não identificado como PHP", c.Image)
		}
	}
	if fingerprint.Detect(discovery.Container{Image: "node:22"}).IsPHP() {
		t.Error("node identificado como PHP")
	}
}

func TestAdvisoriesPHP(t *testing.T) {
	advs, err := intel.LoadAdvisories(context.Background(), "", true)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		pv   ProductVersion
		want finding.Severity
		none bool
	}{
		{pv: ProductVersion{Target: "site", Product: "php", Version: "8.3.10", Source: "x", ModPHP: true}, want: finding.Critical},
		{pv: ProductVersion{Target: "site", Product: "php", Version: "7.4.33", Source: "x"}, want: finding.Critical},
		{pv: ProductVersion{Target: "site", Product: "php", Version: "8.3.6", Suffix: "-1ubuntu2.5", Source: "x"}, want: finding.High},
		{pv: ProductVersion{Target: "site", Product: "php"}, want: finding.High},
		{pv: ProductVersion{Target: "site", Product: "php", Version: "8.4.27", Source: "x"}, none: true},
	}
	for _, c := range cases {
		fs := Advisories(c.pv, advs)
		if c.none {
			if len(fs) != 0 {
				t.Errorf("%+v: esperado nenhum achado, veio %+v", c.pv, fs)
			}
			continue
		}
		if len(fs) != 1 || fs[0].Severity != c.want {
			t.Errorf("%+v: quer 1 achado %v, veio %+v", c.pv, c.want, fs)
			continue
		}
		if !strings.Contains(fs[0].CVE, "CVE-2026-109618") {
			t.Errorf("CVE ausente: %+v", fs[0])
		}
		if c.pv.ModPHP && !strings.Contains(fs[0].Detail, "mod_php") {
			t.Errorf("risco mod_php não mencionado: %s", fs[0].Detail)
		}
	}
}

func TestRLSFindings(t *testing.T) {
	tables := []tableInfo{
		{schema: "public", name: "Aluno", owner: "app", tenant: true},                                       // sem RLS
		{schema: "public", name: "Turma", owner: "app", tenant: true, rls: true, policies: 2},               // owner sem FORCE
		{schema: "public", name: "Falta", owner: "admin", tenant: true, rls: true, policies: 2},             // ok: app não é owner
		{schema: "public", name: "Escola", owner: "app", tenant: true, rls: true, force: true, policies: 1}, // ok
		{schema: "public", name: "Log", owner: "app", rls: true},                                            // sem política
		{schema: "public", name: "Config", owner: "app"},                                                    // não multitenant
	}
	got := map[string]string{}
	for _, f := range rlsFindings("educare", "app", tables) {
		got[f.Target] = f.ID
	}
	want := map[string]string{
		"educare: public.Aluno": "postgres.rls_missing",
		"educare: public.Turma": "postgres.rls_not_forced",
		"educare: public.Log":   "postgres.rls_no_policy",
	}
	if len(got) != len(want) {
		t.Errorf("achados = %v, quer %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q, quer %q", k, got[k], v)
		}
	}
}

func TestHostListeners(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "net"), 0o755)
	// 5432 em 0.0.0.0 (LISTEN), 6379 em 127.0.0.1 (LISTEN), 3306 em 0.0.0.0 mas ESTABLISHED, 8080 publicado pelo Docker.
	tcp := `  sl  local_address rem_address   st
   0: 00000000:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999
   1: 0100007F:18EB 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999
   2: 00000000:0CEA 0A000001:D431 01 00000000:00000000 00:00000000 00000000   999
   3: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000   0
`
	os.WriteFile(filepath.Join(dir, "net", "tcp"), []byte(tcp), 0o644)
	fs := HostListeners(dir, map[int]bool{8080: true})
	if len(fs) != 1 || fs[0].Target != "host:5432" {
		t.Errorf("esperado só host:5432, veio %+v", fs)
	}
}

func TestWebChecks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.Header().Set("X-Powered-By", "PHP/8.3.10")
		if o := r.Header.Get("Origin"); o != "" {
			w.Header().Set("Access-Control-Allow-Origin", o)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		switch r.URL.Path {
		case "/.env":
			w.Write([]byte("APP_KEY=base64:abc\nDB_PASSWORD=x\n"))
		case "/.git/HEAD":
			w.Write([]byte("<!doctype html><html>SPA</html>")) // catch-all: não é .git
		default:
			w.Write([]byte("<!doctype html><html></html>"))
		}
	}))
	defer srv.Close()

	r := NewWebChecker().Check(context.Background(), srv.URL, "site")
	got := ids(r.Findings)
	for _, id := range []string{"web.env_exposed", "web.cors_reflect_credentials", "web.server_version", "web.powered_by", "web.no_csp"} {
		if _, ok := got[id]; !ok {
			t.Errorf("faltou %s (achados: %v)", id, got)
		}
	}
	if _, ok := got["web.git_exposed"]; ok {
		t.Error("falso positivo de .git em rota catch-all")
	}
	if v, _ := fingerprint.PHPVersionFromHeaders(http.Header{"X-Powered-By": {"PHP/8.3.10"}}); v != "8.3.10" {
		t.Errorf("versão PHP do header = %q", v)
	}
}

func TestRLSRemediationQuotesIdentifiers(t *testing.T) {
	fs := rlsFindings("db", "app", []tableInfo{{schema: "public", name: "Aluno", owner: "app", tenant: true}})
	if len(fs) != 1 || !strings.Contains(fs[0].Remediation, `ALTER TABLE "public"."Aluno" ENABLE`) {
		t.Errorf("identificador sem aspas na correção: %+v", fs)
	}
}

func TestHTTPOnTLSPortIsNotAudited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Client sent an HTTP request to an HTTPS server.\n"))
	}))
	defer srv.Close()
	if r := NewWebChecker().Check(context.Background(), srv.URL, "portainer"); r.Reachable || len(r.Findings) != 0 {
		t.Errorf("página de erro de TLS auditada como site: %+v", r)
	}
}
