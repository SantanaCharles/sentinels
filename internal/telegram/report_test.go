package telegram

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/SantanaCharles/sentinels/internal/event"
	"github.com/SantanaCharles/sentinels/internal/finding"
)

type fakeGeo map[string][2]string

func (f fakeGeo) Country(ip string) (string, string) {
	v := f[ip]
	return v[0], v[1]
}

func TestReportCommand(t *testing.T) {
	bot, _, st, _ := setup(t)
	bot.GeoIP = fakeGeo{"198.51.100.9": {"RU", "Russia"}, "203.0.113.7": {"BR", "Brazil"}}
	ctx := context.Background()
	now := time.Now()
	yesterday := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).Add(-6 * time.Hour)
	rec := func(ip, rule, tech string, n int) {
		for i := 0; i < n; i++ {
			e := event.Event{Source: "crowdsec", Rule: rule, Severity: finding.High, Time: yesterday, SourceIP: ip, Technique: tech}
			if _, _, _, err := st.Record(ctx, e, time.Hour, false); err != nil {
				t.Fatal(err)
			}
		}
	}
	rec("198.51.100.9", "ssh-bf", "T1110", 4)
	rec("203.0.113.7", "web", "T1190", 1)

	r := bot.report(ctx, nil) // default: previous day
	for _, want := range []string{"Relatório", "5 evento(s)", "Russia 4", "Brazil 1", "Tipo de ataque", "T1110"} {
		if !strings.Contains(r.text, want) {
			t.Errorf("faltou %q em:\n%s", want, r.text)
		}
	}
}

func TestReportTodayEmpty(t *testing.T) {
	bot, _, _, _ := setup(t)
	r := bot.report(context.Background(), []string{"hoje"})
	if !strings.Contains(r.text, "hoje até agora") || !strings.Contains(r.text, "Nenhum evento") {
		t.Errorf("relatório de hoje vazio inesperado:\n%s", r.text)
	}
}

func TestUpdateCommand(t *testing.T) {
	bot, _, _, _ := setup(t)

	bot.LatestRelease = func(context.Context) (string, error) { return "v99.0.0", nil }
	r := bot.update(context.Background())
	if !strings.Contains(r.text, "Versão nova disponível: v99.0.0") || !strings.Contains(r.text, "docker compose pull") {
		t.Errorf("deveria avisar versão nova:\n%s", r.text)
	}
	if !strings.Contains(r.text, "não atualiza sozinho") {
		t.Errorf("deveria deixar claro que não atualiza sozinho:\n%s", r.text)
	}

	bot.LatestRelease = func(context.Context) (string, error) { return "", context.DeadlineExceeded }
	if r := bot.update(context.Background()); !strings.Contains(r.text, "Não consegui consultar") {
		t.Errorf("deveria tratar erro de rede:\n%s", r.text)
	}
}

func TestSameVersion(t *testing.T) {
	cases := []struct {
		cur, latest string
		want        bool
	}{
		{"0.2.5", "v0.2.5", true},
		{"v0.2.5", "0.2.5", true},
		{"0.2.4", "v0.2.5", false},
		{"0.1.0-dev", "v0.1.0", false}, // dev is never "up to date"
	}
	for _, c := range cases {
		if got := sameVersion(c.cur, c.latest); got != c.want {
			t.Errorf("sameVersion(%q,%q)=%v, quero %v", c.cur, c.latest, got, c.want)
		}
	}
}
