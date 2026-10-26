package workload

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SantanaCharles/sentinels/internal/discovery"
	"github.com/SantanaCharles/sentinels/internal/event"
	"github.com/SantanaCharles/sentinels/internal/finding"
)

func rules(evs []event.Event) string {
	var r []string
	for _, e := range evs {
		r = append(r, e.Rule+"/"+e.Severity.String())
	}
	return strings.Join(r, ",")
}

type analyzer interface {
	Line(string, time.Time) []event.Event
}

func feed(p analyzer, t time.Time, lines ...string) []event.Event {
	var out []event.Event
	for i, l := range lines {
		out = append(out, p.Line(l, t.Add(time.Duration(i)*time.Second))...)
	}
	if pg, ok := p.(*Postgres); ok {
		out = append(out, pg.Flush()...)
	}
	return out
}

const pfx = "2026-10-25 11:35:01.123 UTC "

func TestPostgresSQLInjection(t *testing.T) {
	now := time.Now()
	evs := feed(NewPostgres("loja-db"), now,
		pfx+`[812] ERROR:  each UNION query must have the same number of columns at character 41`,
		pfx+`[812] STATEMENT:  SELECT id, nome FROM produtos WHERE id = 1 UNION SELECT usename FROM pg_user--`,
	)
	if rules(evs) != "postgres-sqli-attempt/critical" || evs[0].Technique != "T1190" ||
		!strings.Contains(evs[0].Summary, "UNION SELECT") || !strings.Contains(evs[0].Summary, "Consulta: SELECT id, nome") {
		t.Fatalf("UNION: %s %+v", rules(evs), evs)
	}

	// The tautology needs the same value on both sides.
	evs = feed(NewPostgres("x"), now,
		pfx+`[9] ERROR:  invalid input syntax for type integer: "1' OR '1'='1"`,
		pfx+`[9] STATEMENT:  SELECT * FROM pedidos WHERE id = '1' OR '1'='1'`)
	if rules(evs) != "postgres-sqli-attempt/critical" {
		t.Errorf("tautologia: %s", rules(evs))
	}
	evs = feed(NewPostgres("x"), now,
		pfx+`[9] ERROR:  column "nme" does not exist`,
		pfx+`[9] STATEMENT:  SELECT nme FROM clientes WHERE tenant = 'a' and ativo = true`)
	if len(evs) != 0 {
		t.Errorf("bug comum da aplicação virou alerta: %s", rules(evs))
	}
}

func TestPostgresBurstsAndPolicies(t *testing.T) {
	now := time.Now()
	var lines []string
	for i := 0; i < 5; i++ {
		lines = append(lines, fmt.Sprintf(pfx+`[%d] ERROR:  syntax error at or near "brien" at character 30`, 100+i),
			fmt.Sprintf(pfx+`[%d] STATEMENT:  SELECT * FROM t WHERE nome = 'o'brien'`, 100+i))
	}
	if evs := feed(NewPostgres("db"), now, lines...); rules(evs) != "postgres-sql-error-burst/high" {
		t.Errorf("rajada: %s", rules(evs))
	}

	evs := feed(NewPostgres("db"), now,
		pfx+`[7] ERROR:  new row violates row-level security policy for table "pedidos"`,
		pfx+`[7] STATEMENT:  INSERT INTO pedidos (tenant_id, total) VALUES ($1, $2)`,
		pfx+`[8] ERROR:  permission denied for table usuarios`, // no STATEMENT: flushed at the end
	)
	if rules(evs) != "postgres-rls-violation/high,postgres-permission-denied/medium" || evs[0].Technique != "T1213" {
		t.Errorf("RLS/negado: %s", rules(evs))
	}

	evs = feed(NewPostgres("db"), now,
		pfx+`[5] ERROR:  must be superuser or have privileges of the pg_execute_server_program role to COPY to or from an external program`,
		pfx+`[5] STATEMENT:  COPY saida FROM PROGRAM 'id'`)
	if rules(evs) != "postgres-dangerous-command/critical" || evs[0].Technique != "T1059" {
		t.Errorf("COPY PROGRAM: %s", rules(evs))
	}

	evs = feed(NewPostgres("db"), now,
		pfx+`[6] LOG:  duration: 5004.120 ms  statement: SELECT * FROM produtos WHERE id = 1 AND 1=(SELECT 1 FROM pg_sleep(5))`)
	if rules(evs) != "postgres-sqli-attempt/critical" {
		t.Errorf("por tempo: %s", rules(evs))
	}
	if evs := feed(NewPostgres("db"), now, pfx+`[6] LOG:  duration: 1500.1 ms  statement: SELECT * FROM relatorio`); len(evs) != 0 {
		t.Errorf("consulta só lenta virou alerta: %s", rules(evs))
	}

	var auth []string
	for i := 0; i < 5; i++ {
		auth = append(auth, fmt.Sprintf(pfx+`[%d] FATAL:  password authentication failed for user "postgres"`, 300+i),
			fmt.Sprintf(pfx+`[%d] DETAIL:  Connection matched file "/var/lib/postgresql/data/pg_hba.conf" line 128`, 300+i))
	}
	if evs := feed(NewPostgres("db"), now, auth...); rules(evs) != "postgres-auth-bruteforce/high" {
		t.Errorf("força bruta: %s", rules(evs))
	}
	evs = feed(NewPostgres("db"), now, pfx+`[400] FATAL:  no pg_hba.conf entry for host "203.0.113.50", user "postgres", database "app", no encryption`)
	if rules(evs) != "postgres-external-connection/high" || evs[0].SourceIP != "203.0.113.50" {
		t.Errorf("conexão externa: %s %+v", rules(evs), evs)
	}
}

func TestAppLogs(t *testing.T) {
	now := time.Now()
	evs := feed(NewApp("loja"), now,
		`PHP Fatal error:  Uncaught PDOException: SQLSTATE[42601]: Syntax error: 7 ERROR:  syntax error at or near "UNION" LINE 1: SELECT * FROM p WHERE id=1' UNION SELECT senha FROM usuarios-- in /var/www/html/produto.php:12`)
	if rules(evs) != "app-sqli-attempt/critical" {
		t.Errorf("SQLi no log do PHP: %s", rules(evs))
	}

	// A logged-in user walking through other people's orders (JSON log).
	var lines []string
	for i := 0; i < 30; i++ {
		lines = append(lines, fmt.Sprintf(`{"level":"warn","req":{"method":"GET","url":"/api/pedidos/%d?x=1","remoteAddress":"172.18.0.5"},"res":{"statusCode":403},"userId":"u-77"}`, 1000+i))
	}
	evs = feed(NewApp("educare"), now, lines...)
	if rules(evs) != "app-enumeration/high" || !strings.Contains(evs[0].Summary, "usuário u-77") || evs[0].Target != "educare · usuário u-77" {
		t.Fatalf("IDOR: %s %+v", rules(evs), evs)
	}

	// Same path refreshed many times is not enumeration; private IP without user is ignored.
	lines = lines[:0]
	for i := 0; i < 40; i++ {
		lines = append(lines, `203.0.113.9 - - [25/Oct/2026:11:35:01 +0000] "GET /favicon.ico HTTP/1.1" 404 196 "-" "Mozilla/5.0"`,
			fmt.Sprintf(`172.18.0.2 - - [25/Oct/2026:11:35:01 +0000] "GET /api/x/%d HTTP/1.1" 403 10 "-" "-"`, i))
	}
	if evs := feed(NewApp("site"), now, lines...); len(evs) != 0 {
		t.Errorf("falso positivo: %s", rules(evs))
	}

	lines = lines[:0]
	for i := 0; i < 20; i++ {
		lines = append(lines, `198.51.100.4 - - [25/Oct/2026:11:35:01 +0000] "POST /login HTTP/1.1" 401 52 "-" "python-requests"`)
	}
	if evs := feed(NewApp("site"), now, lines...); rules(evs) != "app-login-bruteforce/high" || evs[0].SourceIP != "198.51.100.4" {
		t.Errorf("login: %s", rules(evs))
	}
}

func TestHexAddr(t *testing.T) {
	for in, want := range map[string]string{
		"020014AC:1538":                         "172.20.0.2:5432",
		"0100007F:9D93":                         "127.0.0.1:40339",
		"0000000000000000FFFF0000320071CB:C350": "203.113.0.50:50000",
		"B80D0120000000000000000001000000:0050": "2001:db8::1:80",
	} {
		ip, port, ok := hexAddr(in)
		if got := fmt.Sprintf("%s:%d", ip, port); !ok || got != want {
			t.Errorf("%s = %s, quer %s", in, got, want)
		}
	}
}

func writeTCP(t *testing.T, dir string, rows ...string) {
	t.Helper()
	os.MkdirAll(dir, 0o755)
	body := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	for i, r := range rows {
		body += fmt.Sprintf("   %d: %s 00000000:00000000 00:00000000 00000000    70        0 1 1\n", i, r)
	}
	os.WriteFile(filepath.Join(dir, "tcp"), []byte(body), 0o644)
}

func TestClientsBaseline(t *testing.T) {
	proc := t.TempDir()
	state := filepath.Join(t.TempDir(), "db-clients.json")
	db := discovery.Container{Name: "erp-db-1", Pid: 42, IPs: []string{"172.20.0.2"},
		Labels: map[string]string{"com.docker.compose.project": "erp", "com.docker.compose.service": "db"}}
	app := discovery.Container{Name: "erp-app-1", IPs: []string{"172.20.0.3"}, Gateways: []string{"172.20.0.1"},
		Labels: map[string]string{"com.docker.compose.project": "erp", "com.docker.compose.service": "app"}}
	other := discovery.Container{Name: "estranho", IPs: []string{"172.20.0.9"}}
	all := []discovery.Container{db, app, other}
	dbs := []Database{{Label: Label(db), Container: db}}
	netDir := filepath.Join(proc, "42", "net")
	listen := "00000000:1538 00000000:0000 0A"

	// Learning: the app is recorded silently; loopback is ignored.
	writeTCP(t, netDir, listen, "020014AC:1538 030014AC:891A 01", "0100007F:1538 0100007F:9000 01")
	c := &Clients{ProcRoot: proc, StateFile: state, Learn: time.Hour}
	now := time.Now()
	if evs, err := c.Check(dbs, all, now); err != nil || len(evs) != 0 {
		t.Fatalf("aprendizado: %v %s", err, rules(evs))
	}

	// After learning, a new container and the host show up; the baseline survives a restart.
	writeTCP(t, netDir, listen, "020014AC:1538 030014AC:891A 01", "020014AC:1538 090014AC:A000 01", "020014AC:1538 010014AC:B000 01")
	c = &Clients{ProcRoot: proc, StateFile: state, Learn: time.Hour}
	evs, _ := c.Check(dbs, all, now.Add(2*time.Hour))
	both := ""
	for _, e := range evs {
		both += e.Summary + "\n"
	}
	if rules(evs) != "db-new-client/medium,db-new-client/medium" || !strings.Contains(both, "estranho") ||
		!strings.Contains(both, "host (172.20.0.1)") || !strings.Contains(both, "só conectavam: erp-app") {
		t.Fatalf("novo cliente: %s\n%s", rules(evs), both)
	}
	if evs, _ := c.Check(dbs, all, now.Add(3*time.Hour)); len(evs) != 0 {
		t.Errorf("repetiu alerta de cliente já visto: %s", rules(evs))
	}

	// Internet → database: always alerted, even while learning, with a cooldown.
	writeTCP(t, netDir, listen, "020014AC:1538 320071CB:C350 01")
	c2 := &Clients{ProcRoot: proc, Learn: time.Hour}
	evs, _ = c2.Check(dbs, all, now)
	if rules(evs) != "db-external-client/high" || evs[0].SourceIP != "203.113.0.50" || evs[0].Severity != finding.High {
		t.Errorf("externo: %s %+v", rules(evs), evs)
	}
	if evs, _ := c2.Check(dbs, all, now.Add(time.Hour)); len(evs) != 0 {
		t.Error("alerta externo deveria respeitar o intervalo")
	}

	if _, err := (&Clients{ProcRoot: filepath.Join(proc, "nada")}).Check(dbs, all, now); err == nil {
		t.Error("sem /proc deveria avisar")
	}
}
