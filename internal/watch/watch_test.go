package watch

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SantanaCharles/sentinels/internal/event"
	"github.com/SantanaCharles/sentinels/internal/finding"
	"github.com/SantanaCharles/sentinels/internal/fingerprint"
	"github.com/SantanaCharles/sentinels/internal/scan"
	"github.com/SantanaCharles/sentinels/internal/store"
)

type memAlerter struct {
	mu     sync.Mutex
	alerts []Alert
}

func (m *memAlerter) Alert(_ context.Context, a Alert) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.alerts = append(m.alerts, a)
	return nil
}

func newWatcher(t *testing.T) (*Watcher, *memAlerter) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	al := &memAlerter{}
	w := &Watcher{Store: st, Alerter: al, MinSeverity: finding.High, DedupWindow: 15 * time.Minute}
	w.UpdateState(&scan.Result{
		Assets: []scan.Asset{
			{Name: "lab-php", Stack: fingerprint.Stack{Kind: fingerprint.KindApp}, PublicPorts: []string{"18080→80/tcp"}},
			{Name: "lab-db", PublicPorts: []string{"15432→5432/tcp"}},
		},
		Findings: []finding.Finding{
			{ID: "advisory.php2shell-2026-10", Target: "lab-php", Severity: finding.Critical,
				Title: "PHP2Shell", CVE: "CVE-2026-109618, CVE-2026-109619"},
			{ID: "web.no_csp", Target: "lab-php", Severity: finding.Low, Title: "CSP"},
		},
	})
	return w, al
}

func TestExploitAgainstVulnerableTargetIsCritical(t *testing.T) {
	w, al := newWatcher(t)
	e := event.Event{Source: "suricata", Rule: "2000001 ET WEB_SPECIFIC_APPS teste", Severity: finding.Medium,
		Time: time.Now(), SourceIP: "203.0.113.7", DestPort: 18080, Technique: "T1190", Summary: "s"}
	if err := w.Handle(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if len(al.alerts) != 1 {
		t.Fatalf("alertas: %d", len(al.alerts))
	}
	a := al.alerts[0]
	if a.Severity != finding.Critical || a.Target != "lab-php" {
		t.Errorf("alerta: %+v", a)
	}
	if !strings.Contains(strings.Join(a.Lines, "\n"), "PHP2Shell") {
		t.Errorf("vulnerabilidade não citada: %v", a.Lines)
	}
}

func TestReconAgainstVulnerableTargetIsNotEscalated(t *testing.T) {
	w, al := newWatcher(t)
	e := event.Event{Source: "suricata", Rule: "r", Severity: finding.Medium, Time: time.Now(),
		DestPort: 18080, Technique: "T1595"}
	w.Handle(context.Background(), e)
	if len(al.alerts) != 0 {
		t.Errorf("reconhecimento escalado: %+v", al.alerts)
	}
}

func TestDedupAndMultiSource(t *testing.T) {
	w, al := newWatcher(t)
	ctx := context.Background()
	now := time.Now()
	ssh := event.Event{Source: "crowdsec", Rule: "crowdsecurity/ssh-bf", Severity: finding.High,
		Time: now, SourceIP: "198.51.100.1", Technique: "T1110"}
	w.Handle(ctx, ssh)
	ssh.Time = now.Add(time.Minute)
	w.Handle(ctx, ssh) // repetition inside the window
	if len(al.alerts) != 1 {
		t.Fatalf("deduplicação falhou: %d alertas", len(al.alerts))
	}

	// Same IP seen by another engine: one level up, with context.
	scanEv := event.Event{Source: "suricata", Rule: "scan", Severity: finding.Medium,
		Time: now.Add(2 * time.Minute), SourceIP: "198.51.100.1", DestPort: 15432, Technique: "T1046"}
	w.Handle(ctx, scanEv)
	if len(al.alerts) != 2 {
		t.Fatalf("evento multi-fonte não alertou: %d", len(al.alerts))
	}
	a := al.alerts[1]
	if a.Severity != finding.High || a.Target != "lab-db" || !strings.Contains(strings.Join(a.Lines, " "), "crowdsec") {
		t.Errorf("alerta multi-fonte: %+v", a)
	}

	evs, err := w.Store.Events(ctx, now.Add(-time.Hour), finding.Info, 10)
	if err != nil || len(evs) != 2 {
		t.Fatalf("eventos guardados: %d (%v)", len(evs), err)
	}
	for _, se := range evs {
		if se.Event.Source == "crowdsec" && se.Count != 2 {
			t.Errorf("contador da repetição = %d", se.Count)
		}
	}
}

func TestLogAlerterKeepsOneLine(t *testing.T) {
	var b strings.Builder
	(&LogAlerter{W: &b}).Alert(context.Background(), Alert{Severity: finding.High, Title: "x\n[CRÍTICO] falso", Lines: []string{"a\rb"}})
	if strings.Count(b.String(), "\n") != 2 {
		t.Errorf("quebra de linha injetada no log: %q", b.String())
	}
}

func TestFalsePositiveSilencesButNotOnVulnerableTarget(t *testing.T) {
	w, al := newWatcher(t)
	ctx := context.Background()
	noisy := event.Event{Source: "falco", Rule: "Read sensitive file untrusted", Severity: finding.High,
		Time: time.Now(), Target: "lab-db"}
	w.Handle(ctx, noisy)
	if len(al.alerts) != 1 {
		t.Fatalf("primeiro evento: %d alertas", len(al.alerts))
	}
	if _, err := w.Store.AddFeedback(ctx, store.Feedback{EventID: al.alerts[0].EventID, Verdict: store.VerdictFalsePositive}); err != nil {
		t.Fatal(err)
	}
	noisy.Time = time.Now().Add(time.Hour) // outside the dedup window
	w.Handle(ctx, noisy)
	if len(al.alerts) != 1 {
		t.Errorf("falso positivo continuou alertando: %d", len(al.alerts))
	}

	// A suppression for an exploit rule on the PHP2Shell target must not hold.
	exploit := event.Event{Source: "suricata", Rule: "regra web", Severity: finding.Medium, Time: time.Now(),
		DestPort: 18080, Technique: "T1190"}
	w.Handle(ctx, exploit)
	id := al.alerts[len(al.alerts)-1].EventID
	w.Store.AddFeedback(ctx, store.Feedback{EventID: id, Verdict: store.VerdictFalsePositive, Scope: store.ScopeRule})
	exploit.Time = time.Now().Add(time.Hour)
	before := len(al.alerts)
	w.Handle(ctx, exploit)
	if len(al.alerts) != before+1 {
		t.Fatal("rede de segurança falhou: exploração contra alvo vulnerável foi silenciada")
	}
	if !strings.Contains(strings.Join(al.alerts[before].Lines, " "), "ignorada") {
		t.Errorf("alerta não explica que o silenciamento foi ignorado: %v", al.alerts[before].Lines)
	}
}

func TestConfirmedIPRaisesSeverity(t *testing.T) {
	w, al := newWatcher(t)
	ctx := context.Background()
	first := event.Event{Source: "crowdsec", Rule: "crowdsecurity/ssh-bf", Severity: finding.High,
		Time: time.Now(), SourceIP: "198.51.100.66"}
	w.Handle(ctx, first)
	w.Store.AddFeedback(ctx, store.Feedback{EventID: al.alerts[0].EventID, Verdict: store.VerdictConfirmed})

	probe := event.Event{Source: "crowdsec", Rule: "crowdsecurity/http-probing", Severity: finding.Medium,
		Time: time.Now(), SourceIP: "198.51.100.66"}
	w.Handle(ctx, probe)
	if len(al.alerts) != 2 || al.alerts[1].Severity != finding.High {
		t.Fatalf("IP confirmado não elevou a severidade: %+v", al.alerts)
	}
}

func TestRequestScanRunsNowAndCallsHooks(t *testing.T) {
	w, _ := newWatcher(t)
	w.ScanInterval = time.Hour // only an on-demand request can trigger the 2nd scan
	var mu sync.Mutex
	scans, hooks := 0, 0
	w.Scan = func(context.Context) *scan.Result {
		mu.Lock()
		scans++
		mu.Unlock()
		return &scan.Result{History: &scan.History{}}
	}
	w.AfterScan = []func(*scan.Result){func(*scan.Result) { mu.Lock(); hooks++; mu.Unlock() }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.scanLoop(ctx)

	wait := func(n int) bool {
		for end := time.Now().Add(3 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
			mu.Lock()
			ok := scans >= n && hooks >= n
			mu.Unlock()
			if ok {
				return true
			}
		}
		return false
	}
	if !wait(1) {
		t.Fatal("primeira varredura não rodou")
	}
	if r := w.RequestScan(); r != ScanStarted {
		t.Fatalf("RequestScan = %v", r)
	}
	if !wait(2) {
		t.Fatal("varredura sob demanda não rodou")
	}
	if (&Watcher{}).RequestScan() != ScanUnavailable {
		t.Error("sem Scan configurado deveria ser indisponível")
	}
}
