package watch

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/SantanaCharles/sentinels/internal/event"
	"github.com/SantanaCharles/sentinels/internal/finding"
	"github.com/SantanaCharles/sentinels/internal/geoip"
	"github.com/SantanaCharles/sentinels/internal/store"
)

// CountryLookup resolves a source IP to a country for the daily report. A nil
// lookup (no geolocation database) disables the "by country" section; the
// report still goes out grouped by IP.
type CountryLookup interface {
	// Country returns the ISO code and English name, or "", "" when unknown.
	Country(ip string) (code, name string)
}

// dailyReportLoop sends, once a day at the configured local time, a summary of
// the previous full calendar day: total events, where the attacks came from
// (by country), the busiest IPs and the top ATT&CK techniques.
func (w *Watcher) dailyReportLoop(ctx context.Context) {
	for {
		next := nextDailyRun(time.Now(), w.DailyReport)
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Until(next)):
		}
		// The previous calendar day, relative to the firing date.
		end := time.Date(next.Year(), next.Month(), next.Day(), 0, 0, 0, 0, next.Location())
		start := end.AddDate(0, 0, -1)
		if err := w.Alerter.Alert(ctx, w.dailyReportAlert(ctx, start, end)); err != nil {
			w.Log("relatório diário: %v", err)
		}
	}
}

// nextDailyRun returns the next time at the "HH:MM" clock after now.
func nextDailyRun(now time.Time, hhmm string) time.Time {
	h, m := parseClock(hhmm)
	run := time.Date(now.Year(), now.Month(), now.Day(), h, m, 0, 0, now.Location())
	if !run.After(now) {
		run = run.AddDate(0, 0, 1)
	}
	return run
}

// parseClock reads "HH:MM"; it defaults to 08:00 when the value is malformed
// (config.Validate already rejects bad values before the agent starts).
func parseClock(hhmm string) (hour, min int) {
	h, m, ok := strings.Cut(hhmm, ":")
	hv, err1 := strconv.Atoi(h)
	mv, err2 := strconv.Atoi(m)
	if !ok || err1 != nil || err2 != nil || hv < 0 || hv > 23 || mv < 0 || mv > 59 {
		return 8, 0
	}
	return hv, mv
}

func (w *Watcher) dailyReportAlert(ctx context.Context, start, end time.Time) Alert {
	return Alert{
		Severity: finding.Info,
		Title:    "📅 Relatório diário — " + start.Format("02/01/2006"),
		Lines:    DailyReportLines(ctx, w.Store, w.GeoIP, start, end),
		Always:   true,
	}
}

// DailyReportLines builds the body of the report for the window [start, end):
// total and severity, the countries the attacks came from, the busiest IPs and
// the type of attack. It is shared by the scheduled report and the Telegram
// `/report` command. geo may be nil, which drops the country grouping.
func DailyReportLines(ctx context.Context, st *store.Store, geo CountryLookup, start, end time.Time) []string {
	dc, err := st.DayCounts(ctx, start, end)
	if err != nil {
		return []string{"Não foi possível ler os eventos: " + err.Error()}
	}
	var lines []string
	if dc.Total == 0 {
		return []string{"Nenhum evento registrado no período. 🎉"}
	}
	lines = append(lines, fmt.Sprintf("%d evento(s) no total.%s", dc.Total, severityBreakdown(dc.BySeverity)))
	if c := topCountries(geo, dc.ByIP); c != "" {
		lines = append(lines, "Origem dos ataques: "+c)
	} else if geo == nil && len(dc.ByIP) > 0 {
		lines = append(lines, "Origem por país: base de geolocalização indisponível (rode `sentinels setup install` ou configure alerts.geoip_db).")
	}
	if ips := topIPs(geo, dc.ByIP); ips != "" {
		lines = append(lines, "IPs mais ativos: "+ips)
	}
	if t := topTechniques(dc.Techniques); t != "" {
		lines = append(lines, "Tipo de ataque: "+t)
	}
	if m, err := st.Metrics(ctx, end); err == nil && (m.OpenCritical > 0 || m.OpenHigh > 0) {
		lines = append(lines, fmt.Sprintf("Ainda em aberto: %d crítico(s), %d alto(s).", m.OpenCritical, m.OpenHigh))
	}
	return lines
}

// sevNames maps a severity level to its label, highest-interest first order.
var sevOrder = []struct {
	level int
	label string
}{
	{int(finding.Critical), "crítico(s)"},
	{int(finding.High), "alto(s)"},
	{int(finding.Medium), "médio(s)"},
	{int(finding.Low), "baixo(s)"},
	{int(finding.Info), "informativo(s)"},
}

func severityBreakdown(by map[int]int) string {
	var parts []string
	for _, s := range sevOrder {
		if n := by[s.level]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, s.label))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return " " + strings.Join(parts, ", ") + "."
}

// topCountries groups the day's occurrences by country of origin. Returns ""
// when no geolocation database is configured.
func topCountries(geo CountryLookup, byIP map[string]int) string {
	if geo == nil {
		return ""
	}
	type country struct {
		code, name string
		count      int
	}
	agg := map[string]*country{}
	for ip, n := range byIP {
		code, name := geo.Country(ip)
		key := code
		if key == "" {
			key, name = "??", "desconhecido"
		}
		c := agg[key]
		if c == nil {
			if name == "" {
				name = code
			}
			c = &country{code: code, name: name}
			agg[key] = c
		}
		c.count += n
	}
	list := make([]*country, 0, len(agg))
	for _, c := range agg {
		list = append(list, c)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].count != list[j].count {
			return list[i].count > list[j].count
		}
		return list[i].name < list[j].name
	})
	var parts []string
	for i, c := range list {
		if i == 5 {
			break
		}
		parts = append(parts, fmt.Sprintf("%s %s %d", geoip.Flag(c.code), c.name, c.count))
	}
	return strings.Join(parts, ", ")
}

func topIPs(geo CountryLookup, byIP map[string]int) string {
	type ipc struct {
		ip    string
		code  string
		count int
	}
	list := make([]ipc, 0, len(byIP))
	for ip, n := range byIP {
		e := ipc{ip: ip, count: n}
		if geo != nil {
			e.code, _ = geo.Country(ip)
		}
		list = append(list, e)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].count != list[j].count {
			return list[i].count > list[j].count
		}
		return list[i].ip < list[j].ip
	})
	var parts []string
	for i, e := range list {
		if i == 5 {
			break
		}
		if e.code != "" {
			parts = append(parts, fmt.Sprintf("%s (%s) %d", e.ip, e.code, e.count))
		} else {
			parts = append(parts, fmt.Sprintf("%s %d", e.ip, e.count))
		}
	}
	return strings.Join(parts, ", ")
}

func topTechniques(ranked []store.Ranked) string {
	var parts []string
	for _, r := range ranked {
		label := r.Key
		if t, ok := event.Techniques[r.Key]; ok {
			label = r.Key + " " + t.Name
		}
		parts = append(parts, fmt.Sprintf("%s %d", label, r.Count))
	}
	return strings.Join(parts, ", ")
}
