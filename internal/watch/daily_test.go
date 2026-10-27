package watch

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/SantanaCharles/sentinels/internal/event"
	"github.com/SantanaCharles/sentinels/internal/finding"
)

// fakeGeo maps an IP to {ISO code, name}; anything else is unknown.
type fakeGeo map[string][2]string

func (f fakeGeo) Country(ip string) (string, string) {
	v := f[ip]
	return v[0], v[1]
}

func TestNextDailyRun(t *testing.T) {
	loc := time.Local
	// Before the clock today → today.
	if got := nextDailyRun(time.Date(2026, 3, 10, 7, 0, 0, 0, loc), "08:00"); !got.Equal(time.Date(2026, 3, 10, 8, 0, 0, 0, loc)) {
		t.Errorf("mesmo dia: %v", got)
	}
	// After the clock today → tomorrow.
	if got := nextDailyRun(time.Date(2026, 3, 10, 9, 0, 0, 0, loc), "08:00"); !got.Equal(time.Date(2026, 3, 11, 8, 0, 0, 0, loc)) {
		t.Errorf("dia seguinte: %v", got)
	}
	// Malformed clock falls back to 08:00.
	if got := nextDailyRun(time.Date(2026, 3, 10, 7, 0, 0, 0, loc), "nope"); got.Hour() != 8 || got.Minute() != 0 {
		t.Errorf("padrão: %v", got)
	}
}

func TestSeverityBreakdown(t *testing.T) {
	got := severityBreakdown(map[int]int{int(finding.Critical): 2, int(finding.High): 5, int(finding.Low): 1})
	if got != " 2 crítico(s), 5 alto(s), 1 baixo(s)." {
		t.Errorf("quebra: %q", got)
	}
	if severityBreakdown(map[int]int{}) != "" {
		t.Error("vazio deve ser string vazia")
	}
}

func TestDailyReportEmptyDay(t *testing.T) {
	w, _ := newWatcher(t)
	day := time.Date(2026, 3, 10, 0, 0, 0, 0, time.Local)
	a := w.dailyReportAlert(context.Background(), day, day.AddDate(0, 0, 1))
	if !a.Always || len(a.Lines) == 0 || !strings.Contains(a.Lines[0], "Nenhum evento") {
		t.Errorf("dia vazio: %+v", a)
	}
}

func TestDailyReportByCountry(t *testing.T) {
	w, _ := newWatcher(t)
	w.GeoIP = fakeGeo{
		"203.0.113.7":  {"BR", "Brazil"},
		"198.51.100.9": {"RU", "Russia"},
		"192.0.2.5":    {"RU", "Russia"},
	}
	ctx := context.Background()
	day := time.Date(2026, 3, 10, 0, 0, 0, 0, time.Local)
	ts := day.Add(6 * time.Hour)
	rec := func(ip, rule, tech string, times int) {
		for i := 0; i < times; i++ {
			e := event.Event{Source: "crowdsec", Rule: rule, Severity: finding.High, Time: ts, SourceIP: ip, Technique: tech}
			if _, _, _, err := w.Store.Record(ctx, e, time.Hour, false); err != nil {
				t.Fatal(err)
			}
		}
	}
	rec("198.51.100.9", "ssh-bf", "T1110", 5) // RU, 5
	rec("192.0.2.5", "ssh-bf-2", "T1110", 3)  // RU, 3
	rec("203.0.113.7", "web-probe", "T1190", 2) // BR, 2

	a := w.dailyReportAlert(ctx, day, day.AddDate(0, 0, 1))
	joined := strings.Join(a.Lines, "\n")
	for _, want := range []string{"10 evento(s)", "Russia 8", "Brazil 2", "T1110"} {
		if !strings.Contains(joined, want) {
			t.Errorf("faltou %q em:\n%s", want, joined)
		}
	}
}

func TestDailyReportWithoutGeoIP(t *testing.T) {
	w, _ := newWatcher(t)
	ctx := context.Background()
	day := time.Date(2026, 3, 10, 0, 0, 0, 0, time.Local)
	e := event.Event{Source: "crowdsec", Rule: "ssh-bf", Severity: finding.High, Time: day.Add(time.Hour), SourceIP: "198.51.100.9"}
	if _, _, _, err := w.Store.Record(ctx, e, time.Hour, false); err != nil {
		t.Fatal(err)
	}
	a := w.dailyReportAlert(ctx, day, day.AddDate(0, 0, 1))
	joined := strings.Join(a.Lines, "\n")
	if !strings.Contains(joined, "geolocalização indisponível") {
		t.Errorf("sem GeoIP deve avisar: %s", joined)
	}
	if !strings.Contains(joined, "198.51.100.9") {
		t.Errorf("deve listar o IP mesmo sem país: %s", joined)
	}
}
