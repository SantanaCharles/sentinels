// Package store is Sentinels' local memory: a single SQLite file holding
// deduplicated events and the state of each finding across scans.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"github.com/SantanaCharles/sentinels/internal/event"
	"github.com/SantanaCharles/sentinels/internal/finding"
)

type Store struct {
	db *sql.DB
}

// migrations are applied in order and tracked with PRAGMA user_version.
// Never edit an entry that has shipped; append a new one.
var migrations = []string{
	`
CREATE TABLE IF NOT EXISTS events (
	id         INTEGER PRIMARY KEY,
	key        TEXT NOT NULL,
	first_seen INTEGER NOT NULL,
	last_seen  INTEGER NOT NULL,
	count      INTEGER NOT NULL DEFAULT 1,
	source     TEXT NOT NULL,
	rule       TEXT NOT NULL,
	severity   INTEGER NOT NULL,
	source_ip  TEXT,
	target     TEXT,
	technique  TEXT,
	tactic     TEXT,
	summary    TEXT,
	context    TEXT,
	raw        TEXT
);
CREATE INDEX IF NOT EXISTS events_key ON events(key, last_seen);
CREATE INDEX IF NOT EXISTS events_ip ON events(source_ip, last_seen);
CREATE INDEX IF NOT EXISTS events_time ON events(last_seen);

CREATE TABLE IF NOT EXISTS findings (
	key         TEXT PRIMARY KEY,
	id          TEXT NOT NULL,
	target      TEXT NOT NULL,
	title       TEXT NOT NULL,
	severity    INTEGER NOT NULL,
	first_seen  INTEGER NOT NULL,
	last_seen   INTEGER NOT NULL,
	resolved_at INTEGER
);

CREATE TABLE IF NOT EXISTS scans (
	id        INTEGER PRIMARY KEY,
	started   INTEGER NOT NULL,
	critical  INTEGER NOT NULL,
	high      INTEGER NOT NULL,
	medium    INTEGER NOT NULL,
	low       INTEGER NOT NULL,
	new       INTEGER NOT NULL,
	resolved  INTEGER NOT NULL
);
`,
	// 2: admin feedback (step 4).
	`
ALTER TABLE events ADD COLUMN suppressed INTEGER NOT NULL DEFAULT 0;
ALTER TABLE events ADD COLUMN verdict TEXT NOT NULL DEFAULT '';

CREATE TABLE feedback (
	id         INTEGER PRIMARY KEY,
	event_id   INTEGER NOT NULL,
	verdict    TEXT NOT NULL,
	note       TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL
);

CREATE TABLE suppressions (
	id         INTEGER PRIMARY KEY,
	source     TEXT NOT NULL,
	rule       TEXT NOT NULL,
	source_ip  TEXT NOT NULL DEFAULT '',
	target     TEXT NOT NULL DEFAULT '',
	note       TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	hits       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX suppressions_rule ON suppressions(source, rule);

CREATE TABLE confirmed_ips (
	ip         TEXT PRIMARY KEY,
	event_id   INTEGER NOT NULL,
	note       TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL
);

CREATE TABLE accepted_findings (
	key        TEXT PRIMARY KEY,
	reason     TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL
);
`,
	// 3: AI analysis of events (step 5).
	`ALTER TABLE events ADD COLUMN ai_note TEXT NOT NULL DEFAULT '';`,
}

// Open creates the database file (mode 0600) and applies the schema.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	if f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600); err == nil {
		f.Close()
	} else {
		return nil, err
	}
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // single writer; avoids SQLITE_BUSY between goroutines
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// OpenReadOnly opens an existing database without creating or migrating it.
// Used by the MCP server, which must never write.
func OpenReadOnly(path string) (*Store, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("memória local %s não encontrada: rode `sentinels scan` ou `sentinels watch` primeiro", path)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		db.Close()
		return nil, err
	}
	if version != len(migrations) {
		db.Close()
		return nil, fmt.Errorf("esquema da memória na versão %d, esperado %d: rode `sentinels scan` para atualizar", version, len(migrations))
	}
	return &Store{db: db}, nil
}

func migrate(db *sql.DB) error {
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if version > len(migrations) {
		return fmt.Errorf("banco criado por uma versão mais nova do Sentinels (esquema %d)", version)
	}
	for i := version; i < len(migrations); i++ {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migração %d: %w", i+1, err)
		}
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Close() error { return s.db.Close() }

// Record stores e, merging it into an existing row with the same key seen
// within window. isNew is false for a repetition (do not alert again).
// suppressed marks events silenced by an admin rule; they are kept for history.
func (s *Store) Record(ctx context.Context, e event.Event, window time.Duration, suppressed bool) (id int64, count int, isNew bool, err error) {
	key := e.Key()
	now := e.Time.Unix()
	err = s.db.QueryRowContext(ctx,
		`SELECT id, count FROM events WHERE key = ? AND last_seen >= ? ORDER BY last_seen DESC LIMIT 1`,
		key, e.Time.Add(-window).Unix()).Scan(&id, &count)
	switch {
	case err == nil:
		count++
		_, err = s.db.ExecContext(ctx,
			`UPDATE events SET count = ?, last_seen = MAX(last_seen, ?), severity = MAX(severity, ?) WHERE id = ?`,
			count, now, int(e.Severity), id)
		return id, count, false, err
	case err != sql.ErrNoRows:
		return 0, 0, false, err
	}
	ctxJSON, _ := json.Marshal(e.Context)
	res, err := s.db.ExecContext(ctx, `INSERT INTO events
		(key, first_seen, last_seen, source, rule, severity, source_ip, target, technique, tactic, summary, context, raw, suppressed)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		key, now, now, e.Source, e.Rule, int(e.Severity), e.SourceIP, e.Target, e.Technique, e.Tactic,
		e.Summary, string(ctxJSON), string(e.Raw), suppressed)
	if err != nil {
		return 0, 0, false, err
	}
	id, err = res.LastInsertId()
	return id, 1, true, err
}

// SourcesForIP returns the distinct engines that reported ip since t.
func (s *Store) SourcesForIP(ctx context.Context, ip string, since time.Time) ([]string, error) {
	if ip == "" {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT source FROM events WHERE source_ip = ? AND last_seen >= ? ORDER BY source`, ip, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var src string
		if err := rows.Scan(&src); err != nil {
			return nil, err
		}
		out = append(out, src)
	}
	return out, rows.Err()
}

type StoredEvent struct {
	ID         int64
	FirstSeen  time.Time
	LastSeen   time.Time
	Count      int
	Suppressed bool
	Verdict    string // "", "fp" or "confirmed"
	AINote     string // model analysis, when one was made
	Event      event.Event
}

const eventColumns = `id, first_seen, last_seen, count, suppressed, verdict, ai_note, source, rule, severity,
	COALESCE(source_ip, ''), COALESCE(target, ''), COALESCE(technique, ''), COALESCE(tactic, ''),
	COALESCE(summary, ''), COALESCE(context, ''), COALESCE(raw, '')`

type scanner interface{ Scan(dest ...any) error }

func scanEvent(r scanner) (StoredEvent, error) {
	var se StoredEvent
	var first, last int64
	var sev int
	var ctxJSON, raw string
	e := &se.Event
	if err := r.Scan(&se.ID, &first, &last, &se.Count, &se.Suppressed, &se.Verdict, &se.AINote, &e.Source, &e.Rule, &sev,
		&e.SourceIP, &e.Target, &e.Technique, &e.Tactic, &e.Summary, &ctxJSON, &raw); err != nil {
		return se, err
	}
	if raw != "" {
		e.Raw = event.TrimRaw([]byte(raw))
	}
	se.FirstSeen, se.LastSeen = time.Unix(first, 0), time.Unix(last, 0)
	e.Severity = finding.Severity(sev)
	e.Time = se.LastSeen
	_ = json.Unmarshal([]byte(ctxJSON), &e.Context)
	return se, nil
}

// SetAINote stores the model's analysis of an event.
func (s *Store) SetAINote(ctx context.Context, id int64, note string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE events SET ai_note = ? WHERE id = ?`, note, id)
	return err
}

// Event returns one stored event by ID.
func (s *Store) Event(ctx context.Context, id int64) (StoredEvent, error) {
	se, err := scanEvent(s.db.QueryRowContext(ctx, `SELECT `+eventColumns+` FROM events WHERE id = ?`, id))
	if err == sql.ErrNoRows {
		return se, fmt.Errorf("evento #%d não encontrado", id)
	}
	return se, err
}

// Events lists events seen since t at or above min severity, newest first.
func (s *Store) Events(ctx context.Context, since time.Time, min finding.Severity, limit int) ([]StoredEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+eventColumns+`
		FROM events WHERE last_seen >= ? AND severity >= ? ORDER BY last_seen DESC LIMIT ?`,
		since.Unix(), int(min), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StoredEvent
	for rows.Next() {
		se, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, se)
	}
	return out, rows.Err()
}

// ScanDiff is how the latest scan compares with what the store remembered.
type ScanDiff struct {
	New      []finding.Finding
	Resolved []string // titles of findings that disappeared
	First    bool     // no scan was recorded before: everything is "new"
}

// RecordScan updates finding state: new findings get first_seen, missing
// ones are marked resolved, and reappearing ones are reopened.
func (s *Store) RecordScan(ctx context.Context, started time.Time, fs []finding.Finding) (ScanDiff, error) {
	var diff ScanDiff
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return diff, err
	}
	defer tx.Rollback()
	now := started.Unix()
	var prior int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM scans`).Scan(&prior); err != nil {
		return diff, err
	}
	diff.First = prior == 0

	current := map[string]bool{}
	for _, f := range fs {
		key := f.ID + "|" + f.Target
		current[key] = true
		var open bool
		err := tx.QueryRowContext(ctx, `SELECT resolved_at IS NULL FROM findings WHERE key = ?`, key).Scan(&open)
		switch {
		case err == sql.ErrNoRows:
			diff.New = append(diff.New, f)
			_, err = tx.ExecContext(ctx, `INSERT INTO findings (key, id, target, title, severity, first_seen, last_seen)
				VALUES (?, ?, ?, ?, ?, ?, ?)`, key, f.ID, f.Target, f.Title, int(f.Severity), now, now)
		case err == nil:
			if !open {
				diff.New = append(diff.New, f) // regression: came back after being fixed
			}
			_, err = tx.ExecContext(ctx, `UPDATE findings SET last_seen = ?, severity = ?, title = ?, resolved_at = NULL
				WHERE key = ?`, now, int(f.Severity), f.Title, key)
		}
		if err != nil {
			return diff, err
		}
	}

	rows, err := tx.QueryContext(ctx, `SELECT key, title, target FROM findings WHERE resolved_at IS NULL`)
	if err != nil {
		return diff, err
	}
	var gone []string
	for rows.Next() {
		var key, title, target string
		if err := rows.Scan(&key, &title, &target); err != nil {
			rows.Close()
			return diff, err
		}
		if !current[key] {
			gone = append(gone, key)
			diff.Resolved = append(diff.Resolved, title+" — "+target)
		}
	}
	rows.Close()
	for _, key := range gone {
		if _, err := tx.ExecContext(ctx, `UPDATE findings SET resolved_at = ? WHERE key = ?`, now, key); err != nil {
			return diff, err
		}
	}

	c := finding.Count(fs)
	if _, err := tx.ExecContext(ctx, `INSERT INTO scans (started, critical, high, medium, low, new, resolved)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, now, c[finding.Critical], c[finding.High], c[finding.Medium], c[finding.Low],
		len(diff.New), len(diff.Resolved)); err != nil {
		return diff, err
	}
	return diff, tx.Commit()
}

// Prune deletes events last seen before t.
func (s *Store) Prune(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM events WHERE last_seen < ?`, before.Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
