package store

import (
	"context"
	"testing"
	"time"

	"github.com/SantanaCharles/sentinels/internal/event"
	"github.com/SantanaCharles/sentinels/internal/finding"
)

func TestMetrics(t *testing.T) {
	st := openTemp(t)
	ctx := context.Background()
	now := time.Now()
	day := 24 * time.Hour

	crit := finding.Finding{ID: "a", Target: "x", Title: "A", Severity: finding.Critical}
	old := finding.Finding{ID: "b", Target: "x", Title: "B", Severity: finding.Critical}
	high := finding.Finding{ID: "c", Target: "x", Title: "C", Severity: finding.High}
	fixed := finding.Finding{ID: "d", Target: "x", Title: "D", Severity: finding.Critical}
	accepted := finding.Finding{ID: "e", Target: "x", Title: "E", Severity: finding.Critical}

	st.RecordScan(ctx, now.Add(-10*day), []finding.Finding{old, fixed, accepted})
	st.RecordScan(ctx, now.Add(-8*day), []finding.Finding{old, accepted})             // "fixed" resolved after 2 days
	st.RecordScan(ctx, now.Add(-2*day), []finding.Finding{old, crit, high, accepted}) // crit and high appear
	st.AcceptFinding(ctx, accepted.Key(), "ok", 30*day)

	for i, e := range []event.Event{
		{Source: "crowdsec", Rule: "ssh-bf", Severity: finding.High, SourceIP: "203.0.113.7", Technique: "T1110"},
		{Source: "crowdsec", Rule: "probe", Severity: finding.Medium, SourceIP: "203.0.113.7", Technique: "T1595"},
		{Source: "suricata", Rule: "scan", Severity: finding.Critical, SourceIP: "198.51.100.1", Technique: "T1595"},
		{Source: "falco", Rule: "shell", Severity: finding.High, Target: "app", Technique: "T1059"},
	} {
		e.Time = now.Add(-time.Duration(i) * time.Hour)
		id, _, _, _ := st.Record(ctx, e, time.Minute, false)
		switch i {
		case 0:
			st.AddFeedback(ctx, Feedback{EventID: id, Verdict: VerdictConfirmed})
		case 1, 2:
			st.AddFeedback(ctx, Feedback{EventID: id, Verdict: VerdictFalsePositive})
		}
	}

	m, err := st.Metrics(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if m.OpenCritical != 2 || m.OpenHigh != 1 || m.CriticalOver7d != 1 || m.OldestCritDays != 10 {
		t.Errorf("abertos: crit=%d high=%d >7d=%d mais antigo=%d (o aceito não pode contar)", m.OpenCritical, m.OpenHigh, m.CriticalOver7d, m.OldestCritDays)
	}
	if m.MTTRCritDays < 1.9 || m.MTTRCritDays > 2.1 || m.MTTRHighDays != -1 {
		t.Errorf("MTTR: crit=%.2f high=%.2f", m.MTTRCritDays, m.MTTRHighDays)
	}
	if m.Events30d != 4 || m.Confirmed30d != 1 || m.FalsePos30d != 2 || m.Unreviewed30d != 1 {
		t.Errorf("eventos: %+v", m)
	}
	if m.FPRate < 0.66 || m.FPRate > 0.67 {
		t.Errorf("taxa de falso positivo = %.2f, quer 2/3", m.FPRate)
	}
	if len(m.TopAttackers) != 2 || m.TopAttackers[0].Key != "203.0.113.7" || m.TopAttackers[0].Count != 2 {
		t.Errorf("top atacantes: %+v", m.TopAttackers)
	}
	if len(m.TopTechniques) == 0 || m.TopTechniques[0].Key != "T1595" {
		t.Errorf("top técnicas: %+v", m.TopTechniques)
	}

	empty, _ := openTemp(t).Metrics(ctx, now)
	if empty.FPRate != -1 || empty.MTTRCritDays != -1 {
		t.Errorf("sem dados deveria ser -1: %+v", empty)
	}
}
