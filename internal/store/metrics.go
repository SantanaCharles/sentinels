package store

import (
	"context"
	"database/sql"
	"time"
)

// Metrics measures whether the agent is helping: how fast problems get
// fixed, how noisy the alerts are, and who is attacking.
type Metrics struct {
	Since time.Time `json:"since"` // start of the event window (30 days)

	// Findings
	OpenCritical    int     `json:"open_critical"`
	OpenHigh        int     `json:"open_high"`
	CriticalOver7d  int     `json:"critical_over_7d"`
	OldestCritDays  int     `json:"oldest_critical_days"`
	AvgOpenDays     float64 `json:"avg_open_days"`      // critical+high still open
	MTTRCritDays    float64 `json:"mttr_critical_days"` // resolved in the last 90 days; -1 = no data
	MTTRHighDays    float64 `json:"mttr_high_days"`
	ResolvedLast30d int     `json:"resolved_last_30d"`

	// Events (30 days)
	Events7d      map[string]int `json:"events_7d"` // by severity name
	Events30d     int            `json:"events_30d"`
	Confirmed30d  int            `json:"confirmed_30d"`
	FalsePos30d   int            `json:"false_positives_30d"`
	FPRate        float64        `json:"false_positive_rate"` // -1 = no feedback yet
	Unreviewed30d int            `json:"unreviewed_high_30d"` // high+ alerts without feedback
	Suppressed30d int            `json:"suppressed_30d"`
	TopAttackers  []Ranked       `json:"top_attackers"`
	TopTechniques []Ranked       `json:"top_techniques"`
}

type Ranked struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// Metrics computes everything from the local store at time now.
func (s *Store) Metrics(ctx context.Context, now time.Time) (*Metrics, error) {
	m := &Metrics{Since: now.AddDate(0, 0, -30), Events7d: map[string]int{}, MTTRCritDays: -1, MTTRHighDays: -1, FPRate: -1}
	day := 86400.0
	nowU := now.Unix()

	// Open findings (accepted risks excluded).
	rows, err := s.db.QueryContext(ctx, `SELECT f.severity, f.first_seen FROM findings f
		LEFT JOIN accepted_findings a ON a.key = f.key AND a.expires_at > ?
		WHERE f.resolved_at IS NULL AND a.key IS NULL AND f.severity >= 3`, nowU)
	if err != nil {
		return nil, err
	}
	var ageSum float64
	n := 0
	for rows.Next() {
		var sev int
		var first int64
		if err := rows.Scan(&sev, &first); err != nil {
			rows.Close()
			return nil, err
		}
		age := float64(nowU-first) / day
		ageSum += age
		n++
		if sev >= 4 {
			m.OpenCritical++
			if age > 7 {
				m.CriticalOver7d++
			}
			if int(age) > m.OldestCritDays {
				m.OldestCritDays = int(age)
			}
		} else {
			m.OpenHigh++
		}
	}
	rows.Close()
	if n > 0 {
		m.AvgOpenDays = ageSum / float64(n)
	}

	// MTTR: findings fixed in the last 90 days.
	mttr := func(sevCond string) (float64, error) {
		var avg sql.NullFloat64
		err := s.db.QueryRowContext(ctx, `SELECT AVG(resolved_at - first_seen) FROM findings
			WHERE resolved_at IS NOT NULL AND resolved_at >= ? AND `+sevCond, nowU-90*86400).Scan(&avg)
		if err != nil || !avg.Valid {
			return -1, err
		}
		return avg.Float64 / day, nil
	}
	if m.MTTRCritDays, err = mttr("severity >= 4"); err != nil {
		return nil, err
	}
	if m.MTTRHighDays, err = mttr("severity = 3"); err != nil {
		return nil, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM findings WHERE resolved_at >= ?`, m.Since.Unix()).Scan(&m.ResolvedLast30d); err != nil {
		return nil, err
	}

	// Events.
	since30, since7 := m.Since.Unix(), now.AddDate(0, 0, -7).Unix()
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(*),
		COALESCE(SUM(verdict = 'confirmed'), 0), COALESCE(SUM(verdict = 'fp'), 0),
		COALESCE(SUM(verdict = '' AND suppressed = 0 AND severity >= 3), 0), COALESCE(SUM(suppressed), 0)
		FROM events WHERE last_seen >= ?`, since30).
		Scan(&m.Events30d, &m.Confirmed30d, &m.FalsePos30d, &m.Unreviewed30d, &m.Suppressed30d)
	if err != nil {
		return nil, err
	}
	if reviewed := m.Confirmed30d + m.FalsePos30d; reviewed > 0 {
		m.FPRate = float64(m.FalsePos30d) / float64(reviewed)
	}
	sevNames := []string{"info", "low", "medium", "high", "critical"}
	rows, err = s.db.QueryContext(ctx, `SELECT severity, COUNT(*) FROM events WHERE last_seen >= ? GROUP BY severity`, since7)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var sev, c int
		if err := rows.Scan(&sev, &c); err != nil {
			rows.Close()
			return nil, err
		}
		if sev >= 0 && sev < len(sevNames) {
			m.Events7d[sevNames[sev]] = c
		}
	}
	rows.Close()

	rank := func(col string) ([]Ranked, error) {
		rows, err := s.db.QueryContext(ctx, `SELECT `+col+`, SUM(count) AS n FROM events
			WHERE last_seen >= ? AND COALESCE(`+col+`, '') <> '' GROUP BY `+col+` ORDER BY n DESC LIMIT 5`, since30)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []Ranked
		for rows.Next() {
			var r Ranked
			if err := rows.Scan(&r.Key, &r.Count); err != nil {
				return nil, err
			}
			out = append(out, r)
		}
		return out, rows.Err()
	}
	if m.TopAttackers, err = rank("source_ip"); err != nil {
		return nil, err
	}
	if m.TopTechniques, err = rank("technique"); err != nil {
		return nil, err
	}
	return m, nil
}

// DayCounts aggregates the events whose last_seen falls in [start, end).
// Totals are occurrence counts (the count column), so a brute force that
// repeated 500 times weighs as 500 — the "how much was thrown at us" view.
type DayCounts struct {
	Total      int            `json:"total"`
	BySeverity map[int]int    `json:"by_severity"` // severity level (0..4) -> occurrences
	ByIP       map[string]int `json:"by_ip"`       // source IP -> occurrences (non-empty IPs only)
	Techniques []Ranked       `json:"techniques"`  // top ATT&CK techniques, most first
}

// DayCounts computes the summary used by the daily report.
func (s *Store) DayCounts(ctx context.Context, start, end time.Time) (*DayCounts, error) {
	dc := &DayCounts{BySeverity: map[int]int{}, ByIP: map[string]int{}}
	a, b := start.Unix(), end.Unix()

	rows, err := s.db.QueryContext(ctx,
		`SELECT severity, SUM(count) FROM events WHERE last_seen >= ? AND last_seen < ? GROUP BY severity`, a, b)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var sev, n int
		if err := rows.Scan(&sev, &n); err != nil {
			rows.Close()
			return nil, err
		}
		dc.BySeverity[sev] += n
		dc.Total += n
	}
	rows.Close()

	rows, err = s.db.QueryContext(ctx,
		`SELECT source_ip, SUM(count) FROM events WHERE last_seen >= ? AND last_seen < ? AND COALESCE(source_ip, '') <> '' GROUP BY source_ip`, a, b)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var ip string
		var n int
		if err := rows.Scan(&ip, &n); err != nil {
			rows.Close()
			return nil, err
		}
		dc.ByIP[ip] = n
	}
	rows.Close()

	rows, err = s.db.QueryContext(ctx,
		`SELECT technique, SUM(count) AS n FROM events WHERE last_seen >= ? AND last_seen < ? AND COALESCE(technique, '') <> ''
			GROUP BY technique ORDER BY n DESC LIMIT 5`, a, b)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r Ranked
		if err := rows.Scan(&r.Key, &r.Count); err != nil {
			return nil, err
		}
		dc.Techniques = append(dc.Techniques, r)
	}
	return dc, rows.Err()
}

// EventsByIP sums the occurrences of each source IP since the given time.
func (s *Store) EventsByIP(ctx context.Context, since time.Time) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT source_ip, SUM(count) FROM events WHERE source_ip != '' AND last_seen >= ? GROUP BY source_ip`, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var ip string
		var n int
		if err := rows.Scan(&ip, &n); err != nil {
			return nil, err
		}
		out[ip] = n
	}
	return out, rows.Err()
}
