package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/SantanaCharles/sentinels/internal/event"
)

const (
	VerdictFalsePositive = "fp"
	VerdictConfirmed     = "confirmed"
)

// Scope of a false-positive suppression.
const (
	ScopeRule   = "rule"   // this rule anywhere
	ScopeIP     = "ip"     // this rule from this source IP
	ScopeTarget = "target" // this rule against this target
)

type Feedback struct {
	EventID int64
	Verdict string
	Scope   string // only for false positives; "" picks the narrowest available
	Note    string
	TTL     time.Duration
}

// AddFeedback records the admin's verdict on an event and teaches the agent:
// a false positive creates an expiring suppression, a confirmation marks the
// source IP as hostile.
func (s *Store) AddFeedback(ctx context.Context, fb Feedback) (string, error) {
	se, err := s.Event(ctx, fb.EventID)
	if err != nil {
		return "", err
	}
	e := se.Event
	now := time.Now()
	if fb.TTL <= 0 {
		fb.TTL = 30 * 24 * time.Hour
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `INSERT INTO feedback (event_id, verdict, note, created_at) VALUES (?, ?, ?, ?)`,
		fb.EventID, fb.Verdict, fb.Note, now.Unix()); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE events SET verdict = ? WHERE id = ?`, fb.Verdict, fb.EventID); err != nil {
		return "", err
	}

	var msg string
	switch fb.Verdict {
	case VerdictFalsePositive:
		scope := fb.Scope
		if scope == "" {
			switch {
			case e.Target != "":
				scope = ScopeTarget
			case e.SourceIP != "":
				scope = ScopeIP
			default:
				scope = ScopeRule
			}
		}
		ip, target := "", ""
		switch scope {
		case ScopeIP:
			if e.SourceIP == "" {
				return "", fmt.Errorf("evento #%d não tem IP de origem; use --scope rule ou target", fb.EventID)
			}
			ip = e.SourceIP
		case ScopeTarget:
			if e.Target == "" {
				return "", fmt.Errorf("evento #%d não tem alvo; use --scope rule ou ip", fb.EventID)
			}
			target = e.Target
		case ScopeRule:
		default:
			return "", fmt.Errorf("escopo inválido %q (use rule, ip ou target)", scope)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO suppressions
			(source, rule, source_ip, target, note, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			e.Source, e.Rule, ip, target, fb.Note, now.Unix(), now.Add(fb.TTL).Unix()); err != nil {
			return "", err
		}
		msg = fmt.Sprintf("silenciado por %d dias: %s %q", int(fb.TTL.Hours()/24), e.Source, e.Rule)
		if ip != "" {
			msg += " vindo de " + ip
		}
		if target != "" {
			msg += " contra " + target
		}
	case VerdictConfirmed:
		if e.SourceIP != "" {
			if _, err := tx.ExecContext(ctx, `INSERT INTO confirmed_ips (ip, event_id, note, created_at, expires_at)
				VALUES (?, ?, ?, ?, ?)
				ON CONFLICT(ip) DO UPDATE SET event_id = excluded.event_id, note = excluded.note, expires_at = excluded.expires_at`,
				e.SourceIP, fb.EventID, fb.Note, now.Unix(), now.Add(3*fb.TTL).Unix()); err != nil {
				return "", err
			}
			msg = fmt.Sprintf("ataque confirmado; eventos futuros de %s sobem um nível de severidade por %d dias", e.SourceIP, int(3*fb.TTL.Hours()/24))
		} else {
			msg = "ataque confirmado"
		}
	default:
		return "", fmt.Errorf("veredito inválido %q (use fp ou confirmed)", fb.Verdict)
	}
	return msg, tx.Commit()
}

// Suppressed reports whether an active admin rule silences e, and counts the hit.
func (s *Store) Suppressed(ctx context.Context, e event.Event) (bool, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `SELECT id FROM suppressions
		WHERE source = ? AND rule = ? AND expires_at > ?
		  AND (source_ip = '' OR source_ip = ?) AND (target = '' OR target = ?)
		LIMIT 1`, e.Source, e.Rule, time.Now().Unix(), e.SourceIP, e.Target).Scan(&id)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE suppressions SET hits = hits + 1 WHERE id = ?`, id)
	return true, err
}

// ConfirmedIP reports whether the admin confirmed an attack from ip.
func (s *Store) ConfirmedIP(ctx context.Context, ip string) (bool, error) {
	if ip == "" {
		return false, nil
	}
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM confirmed_ips WHERE ip = ? AND expires_at > ?`,
		ip, time.Now().Unix()).Scan(&n)
	return n > 0, err
}

type Suppression struct {
	ID        int64
	Source    string
	Rule      string
	SourceIP  string
	Target    string
	Note      string
	ExpiresAt time.Time
	Hits      int
}

// Suppressions lists active rules.
func (s *Store) Suppressions(ctx context.Context) ([]Suppression, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, source, rule, source_ip, target, note, expires_at, hits
		FROM suppressions WHERE expires_at > ? ORDER BY id`, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Suppression
	for rows.Next() {
		var x Suppression
		var exp int64
		if err := rows.Scan(&x.ID, &x.Source, &x.Rule, &x.SourceIP, &x.Target, &x.Note, &exp, &x.Hits); err != nil {
			return nil, err
		}
		x.ExpiresAt = time.Unix(exp, 0)
		out = append(out, x)
	}
	return out, rows.Err()
}

// RemoveSuppression deletes a rule so matching events alert again.
func (s *Store) RemoveSuppression(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM suppressions WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("regra #%d não encontrada", id)
	}
	return nil
}

// AcceptFinding records an accepted risk. key is "<finding id>|<target>".
func (s *Store) AcceptFinding(ctx context.Context, key, reason string, ttl time.Duration) error {
	if reason == "" {
		return fmt.Errorf("informe o motivo (--reason): risco aceito precisa de justificativa")
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM findings WHERE key = ?`, key).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("achado %q não encontrado (veja `sentinels findings`)", key)
	}
	now := time.Now()
	_, err := s.db.ExecContext(ctx, `INSERT INTO accepted_findings (key, reason, created_at, expires_at) VALUES (?, ?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET reason = excluded.reason, created_at = excluded.created_at, expires_at = excluded.expires_at`,
		key, reason, now.Unix(), now.Add(ttl).Unix())
	return err
}

// AcceptedFindings maps keys of accepted risks still in force to their reason.
func (s *Store) AcceptedFindings(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, reason FROM accepted_findings WHERE expires_at > ?`, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, r string
		if err := rows.Scan(&k, &r); err != nil {
			return nil, err
		}
		out[k] = r
	}
	return out, rows.Err()
}

type OpenFinding struct {
	Key       string
	Title     string
	Severity  int
	FirstSeen time.Time
	Accepted  string // reason, when accepted
}

// OpenFindings lists unresolved findings, most severe first.
func (s *Store) OpenFindings(ctx context.Context) ([]OpenFinding, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT f.key, f.title, f.severity, f.first_seen, COALESCE(a.reason, '')
		FROM findings f LEFT JOIN accepted_findings a ON a.key = f.key AND a.expires_at > ?
		WHERE f.resolved_at IS NULL ORDER BY f.severity DESC, f.key`, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OpenFinding
	for rows.Next() {
		var f OpenFinding
		var first int64
		if err := rows.Scan(&f.Key, &f.Title, &f.Severity, &first, &f.Accepted); err != nil {
			return nil, err
		}
		f.FirstSeen = time.Unix(first, 0)
		out = append(out, f)
	}
	return out, rows.Err()
}
