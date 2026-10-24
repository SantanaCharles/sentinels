package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/SantanaCharles/sentinels/internal/event"
	"github.com/SantanaCharles/sentinels/internal/finding"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func record(t *testing.T, st *Store, e event.Event) int64 {
	t.Helper()
	id, _, _, err := st.Record(context.Background(), e, time.Minute, false)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestFalsePositiveScopes(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	base := event.Event{Source: "falco", Rule: "Terminal shell in container", Severity: finding.Medium,
		Time: time.Now(), SourceIP: "10.0.0.9", Target: "backup"}
	id := record(t, st, base)

	if _, err := st.AddFeedback(ctx, Feedback{EventID: id, Verdict: VerdictFalsePositive}); err != nil {
		t.Fatal(err)
	}
	// Default scope is the target: same rule on the same container is silenced…
	if s, _ := st.Suppressed(ctx, base); !s {
		t.Error("mesmo alvo não silenciado")
	}
	// …but the same rule on another container still alerts.
	other := base
	other.Target = "lab-php"
	if s, _ := st.Suppressed(ctx, other); s {
		t.Error("silenciamento vazou para outro alvo")
	}
	list, _ := st.Suppressions(ctx)
	if len(list) != 1 || list[0].Hits != 1 || list[0].Target != "backup" {
		t.Errorf("regras: %+v", list)
	}
	if err := st.RemoveSuppression(ctx, list[0].ID); err != nil {
		t.Fatal(err)
	}
	if s, _ := st.Suppressed(ctx, base); s {
		t.Error("regra removida continua valendo")
	}
	if _, err := st.AddFeedback(ctx, Feedback{EventID: id, Verdict: VerdictFalsePositive, Scope: "galáxia"}); err == nil {
		t.Error("escopo inválido aceito")
	}
	se, _ := st.Event(ctx, id)
	if se.Verdict != VerdictFalsePositive {
		t.Errorf("veredito não gravado: %q", se.Verdict)
	}
}

func TestSuppressionExpires(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	e := event.Event{Source: "crowdsec", Rule: "crowdsecurity/http-probing", Time: time.Now(), SourceIP: "192.0.2.1"}
	id := record(t, st, e)
	st.AddFeedback(ctx, Feedback{EventID: id, Verdict: VerdictFalsePositive, Scope: ScopeIP, TTL: time.Nanosecond})
	time.Sleep(1100 * time.Millisecond) // expires_at has second resolution
	if s, _ := st.Suppressed(ctx, e); s {
		t.Error("silenciamento vencido continua valendo")
	}
}

func TestConfirmedIP(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	id := record(t, st, event.Event{Source: "suricata", Rule: "r", Time: time.Now(), SourceIP: "203.0.113.7"})
	if _, err := st.AddFeedback(ctx, Feedback{EventID: id, Verdict: VerdictConfirmed}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := st.ConfirmedIP(ctx, "203.0.113.7"); !ok {
		t.Error("IP confirmado não lembrado")
	}
	if ok, _ := st.ConfirmedIP(ctx, "203.0.113.8"); ok {
		t.Error("IP errado marcado")
	}
	if _, err := st.AddFeedback(ctx, Feedback{EventID: 999, Verdict: VerdictConfirmed}); err == nil {
		t.Error("evento inexistente aceito")
	}
}

func TestAcceptFinding(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	f := finding.Finding{ID: "container.root_user", Target: "db", Title: "root", Severity: finding.Medium}
	st.RecordScan(ctx, time.Now(), []finding.Finding{f})
	if err := st.AcceptFinding(ctx, f.Key(), "", time.Hour); err == nil {
		t.Error("aceite sem motivo permitido")
	}
	if err := st.AcceptFinding(ctx, "nao|existe", "x", time.Hour); err == nil {
		t.Error("aceite de achado inexistente permitido")
	}
	if err := st.AcceptFinding(ctx, f.Key(), "imagem oficial do postgres troca de usuário no entrypoint", time.Hour); err != nil {
		t.Fatal(err)
	}
	acc, _ := st.AcceptedFindings(ctx)
	if acc[f.Key()] == "" {
		t.Error("aceite não lembrado")
	}
	open, _ := st.OpenFindings(ctx)
	if len(open) != 1 || open[0].Accepted == "" {
		t.Errorf("achados abertos: %+v", open)
	}
}

// A database created by the step-3 binary (no user_version) must upgrade.
func TestMigrateFromUnversionedDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(migrations[0]); err != nil {
		t.Fatal(err)
	}
	db.Exec(`INSERT INTO events (key, first_seen, last_seen, source, rule, severity) VALUES ('k', 1, 1, 'falco', 'r', 2)`)
	db.Close()

	st, err := Open(path)
	if err != nil {
		t.Fatalf("migração falhou: %v", err)
	}
	defer st.Close()
	se, err := st.Event(context.Background(), 1)
	if err != nil || se.Suppressed || se.Verdict != "" {
		t.Errorf("evento antigo após migração: %+v %v", se, err)
	}
	var v int
	st.db.QueryRow(`PRAGMA user_version`).Scan(&v)
	if v != len(migrations) {
		t.Errorf("user_version = %d", v)
	}
}
