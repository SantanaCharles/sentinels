package integrations

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SantanaCharles/sentinels/internal/event"
	"github.com/SantanaCharles/sentinels/internal/finding"
)

const eveAlert = `{"timestamp":"2026-10-23T21:00:00.123456+0000","event_type":"alert","src_ip":"203.0.113.7","src_port":51515,"dest_ip":"10.0.0.5","dest_port":5432,"proto":"TCP","alert":{"action":"allowed","signature_id":2010937,"signature":"ET SCAN Suspicious inbound to PostgreSQL port 5432","category":"Potentially Bad Traffic","severity":2,"metadata":{"mitre_technique_id":["T1046"]}}}`

func TestParseEveAlert(t *testing.T) {
	e, ok := ParseEveAlert([]byte(eveAlert))
	if !ok {
		t.Fatal("alerta não reconhecido")
	}
	if e.SourceIP != "203.0.113.7" || e.DestPort != 5432 || e.Severity != finding.Medium {
		t.Errorf("campos: %+v", e)
	}
	if e.Technique != "T1046" {
		t.Errorf("técnica da metadata ignorada: %q", e.Technique)
	}
	if _, ok := ParseEveAlert([]byte(`{"event_type":"flow"}`)); ok {
		t.Error("registro flow tratado como alerta")
	}
	if _, ok := ParseEveAlert([]byte(`não é json`)); ok {
		t.Error("linha inválida aceita")
	}
}

func TestParseFalco(t *testing.T) {
	body := `{"output":"Shell aberto no container","priority":"Warning","rule":"Terminal shell in container","time":"2026-10-23T21:00:00.000000000Z","output_fields":{"container.name":"lab-php"},"tags":["container","shell","mitre_execution","T1059"]}`
	e, err := ParseFalco([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if e.Target != "lab-php" || e.Severity != finding.Medium || e.Technique != "T1059" {
		t.Errorf("campos: %+v", e)
	}
	if _, err := ParseFalco([]byte(`{"output":"x"}`)); err == nil {
		t.Error("alerta sem regra aceito")
	}
}

func TestFalcoRejectsNonLoopback(t *testing.T) {
	for addr, want := range map[string]bool{"127.0.0.1:2801": true, "[::1]:2801": true, "localhost:2801": true, "0.0.0.0:2801": false, ":2801": false, "10.0.0.5:2801": false} {
		if got := IsLoopback(addr); got != want {
			t.Errorf("IsLoopback(%q) = %v", addr, got)
		}
	}
	err := (&Falco{Listen: "0.0.0.0:2801"}).Run(context.Background(), make(chan event.Event))
	if err == nil {
		t.Error("listener público aceito")
	}
}

func TestFalcoHandler(t *testing.T) {
	out := make(chan event.Event, 1)
	h := (&Falco{}).Handler(context.Background(), out)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/falco", strings.NewReader(`{"rule":"Write below etc","priority":"Error","output":"x"}`)))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status %d", rec.Code)
	}
	if e := <-out; e.Target != "host" || e.Severity != finding.High {
		t.Errorf("evento: %+v", e)
	}
}

func TestCrowdSecStream(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "k" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		switch calls.Add(1) {
		case 1: // startup: existing decisions are not re-reported
			if r.URL.Query().Get("startup") != "true" {
				t.Errorf("primeira chamada sem startup=true")
			}
			w.Write([]byte(`{"new":[{"id":1,"origin":"crowdsec","type":"ban","scope":"Ip","value":"198.51.100.1","duration":"4h","scenario":"crowdsecurity/ssh-bf"}]}`))
		case 2:
			w.Write([]byte(`{"new":[
				{"id":2,"origin":"CAPI","type":"ban","scope":"Ip","value":"192.0.2.9","duration":"24h","scenario":"http:scan"},
				{"id":3,"origin":"crowdsec","type":"ban","scope":"Ip","value":"203.0.113.7","duration":"4h","scenario":"crowdsecurity/http-cve-2021-41773"}]}`))
		default:
			w.Write([]byte(`{"new":null}`))
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out := make(chan event.Event, 4)
	go (&CrowdSec{URL: srv.URL, APIKey: "k", Interval: 20 * time.Millisecond}).Run(ctx, out)

	select {
	case e := <-out:
		if e.SourceIP != "203.0.113.7" || e.Technique != "T1190" || e.Severity != finding.High {
			t.Errorf("evento: %+v", e)
		}
	case <-ctx.Done():
		t.Fatal("nenhum evento recebido")
	}
	select {
	case e := <-out:
		t.Errorf("evento inesperado (startup ou CAPI vazou): %+v", e)
	case <-time.After(100 * time.Millisecond):
	}

	bad := &CrowdSec{URL: srv.URL, APIKey: "errada"}
	if err := bad.Run(context.Background(), out); err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("chave inválida: %v", err)
	}
}

func TestSuricataTailAndRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")
	os.WriteFile(path, []byte(`{"event_type":"alert","alert":{"signature":"antigo"}}`+"\n"), 0o644)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out := make(chan event.Event, 4)
	go (&Suricata{Path: path, Interval: 20 * time.Millisecond}).Run(ctx, out)
	time.Sleep(100 * time.Millisecond)

	appendLine := func(p, line string) {
		f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		f.WriteString(line)
		f.Close()
	}
	// A line written in two parts must be read once, complete.
	appendLine(path, eveAlert[:40])
	time.Sleep(60 * time.Millisecond)
	appendLine(path, eveAlert[40:]+"\n")

	select {
	case e := <-out:
		if !strings.Contains(e.Rule, "2010937") {
			t.Errorf("evento: %+v", e)
		}
	case <-ctx.Done():
		t.Fatal("linha nova não lida")
	}

	// logrotate: move the file away and create a new one.
	os.Rename(path, path+".1")
	time.Sleep(60 * time.Millisecond)
	appendLine(path, strings.Replace(eveAlert, "2010937", "2999999", 1)+"\n")
	select {
	case e := <-out:
		if !strings.Contains(e.Rule, "2999999") {
			t.Errorf("evento após rotação: %+v", e)
		}
	case <-ctx.Done():
		t.Fatal("arquivo rotacionado não reaberto")
	}
}

func TestCrowdSecTracksActiveDecisions(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch calls.Add(1) {
		case 1: // startup: two local bans, one community entry, one already expired
			w.Write([]byte(`{"new":[
				{"id":1,"origin":"crowdsec","type":"ban","scope":"Ip","value":"203.0.113.7","duration":"3h59m53s","scenario":"crowdsecurity/ssh-slow-bf"},
				{"id":2,"origin":"cscli","type":"ban","scope":"Ip","value":"198.51.100.9","duration":"23h","scenario":"manual"},
				{"id":3,"origin":"CAPI","type":"ban","scope":"Ip","value":"192.0.2.1","duration":"160h","scenario":"http-probing"},
				{"id":4,"origin":"crowdsec","type":"ban","scope":"Ip","value":"192.0.2.50","duration":"-5s","scenario":"x"}]}`))
		case 2: // the manual ban was removed
			w.Write([]byte(`{"new":null,"deleted":[{"id":2,"origin":"cscli","value":"198.51.100.9"}]}`))
		default:
			w.Write([]byte(`{"new":null}`))
		}
	}))
	defer srv.Close()
	cs := &CrowdSec{URL: srv.URL, APIKey: "k", Interval: 10 * time.Millisecond}
	if _, ok := cs.Blocked(time.Now()); ok {
		t.Error("sem leitura ainda, não deveria estar pronto")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go cs.Run(ctx, make(chan event.Event, 8))
	for end := time.Now().Add(2 * time.Second); calls.Load() < 3 && time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
	}
	list, ok := cs.Blocked(time.Now())
	if !ok || len(list) != 1 || list[0].Value != "203.0.113.7" || list[0].Scenario != "crowdsecurity/ssh-slow-bf" {
		t.Fatalf("ativos: ok=%v %+v", ok, list)
	}
	if left := time.Until(list[0].Until); left < 3*time.Hour || left > 4*time.Hour {
		t.Errorf("expira em %v", left)
	}
	if later, _ := cs.Blocked(time.Now().Add(5 * time.Hour)); len(later) != 0 {
		t.Errorf("ban vencido continua na lista: %+v", later)
	}
}
