// Package store persists events and alerts in SQLite.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/roywenangr/mini-siem/internal/event"
)

// ErrNotFound is returned when a requested row does not exist.
var ErrNotFound = errors.New("not found")

const schema = `
CREATE TABLE IF NOT EXISTS events (
	id      INTEGER PRIMARY KEY AUTOINCREMENT,
	ts      INTEGER NOT NULL,           -- unix milliseconds
	source  TEXT NOT NULL,
	host    TEXT NOT NULL DEFAULT '',
	type    TEXT NOT NULL,
	src_ip  TEXT NOT NULL DEFAULT '',
	user    TEXT NOT NULL DEFAULT '',
	message TEXT NOT NULL DEFAULT '',
	fields  TEXT NOT NULL DEFAULT '{}'  -- JSON object
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS events_src_ip ON events(src_ip, ts);
CREATE INDEX IF NOT EXISTS events_type ON events(type, ts);

CREATE TABLE IF NOT EXISTS alerts (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	rule_id     TEXT NOT NULL,
	rule_name   TEXT NOT NULL,
	severity    TEXT NOT NULL,
	group_key   TEXT NOT NULL DEFAULT '',
	count       INTEGER NOT NULL,
	description TEXT NOT NULL,
	first_seen  INTEGER NOT NULL,
	last_seen   INTEGER NOT NULL,
	event_ids   TEXT NOT NULL DEFAULT '[]',
	status      TEXT NOT NULL,
	created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS alerts_status ON alerts(status, id);
CREATE INDEX IF NOT EXISTS alerts_created ON alerts(created_at);
`

// Store wraps the SQLite database.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the database at path. Use ":memory:" for
// a throwaway database in tests.
func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)"
	if path == ":memory:" {
		// Every pooled connection to :memory: would be a separate empty
		// database, so pin the pool to one connection.
		dsn = "file::memory:?_pragma=busy_timeout(5000)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if path == ":memory:" {
		db.SetMaxOpenConns(1)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: create schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func ms(t time.Time) int64     { return t.UnixMilli() }
func fromMS(v int64) time.Time { return time.UnixMilli(v).UTC() }

// InsertEvents stores events in one transaction and sets their IDs.
func (s *Store) InsertEvents(ctx context.Context, evs []*event.Event) error {
	if len(evs) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `INSERT INTO events (ts, source, host, type, src_ip, user, message, fields) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, ev := range evs {
		fields := ev.Fields
		if fields == nil {
			fields = map[string]string{}
		}
		fj, err := json.Marshal(fields)
		if err != nil {
			return err
		}
		res, err := stmt.ExecContext(ctx, ms(ev.Timestamp), ev.Source, ev.Host, ev.Type, ev.SrcIP, ev.User, ev.Message, string(fj))
		if err != nil {
			return err
		}
		if ev.ID, err = res.LastInsertId(); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// EventFilter narrows ListEvents. Zero values mean "no filter".
type EventFilter struct {
	Type     string
	Source   string
	SrcIP    string
	User     string
	Query    string // substring of message
	Since    time.Time
	Until    time.Time
	BeforeID int64 // for paging: only events with a smaller id
	Limit    int
}

const eventCols = `id, ts, source, host, type, src_ip, user, message, fields`

// ListEvents returns events newest first.
func (s *Store) ListEvents(ctx context.Context, f EventFilter) ([]*event.Event, error) {
	var where []string
	var args []any
	add := func(cond string, v any) {
		where = append(where, cond)
		args = append(args, v)
	}
	if f.Type != "" {
		add("type = ?", f.Type)
	}
	if f.Source != "" {
		add("source = ?", f.Source)
	}
	if f.SrcIP != "" {
		add("src_ip = ?", f.SrcIP)
	}
	if f.User != "" {
		add("user = ?", f.User)
	}
	if f.Query != "" {
		add(`message LIKE ? ESCAPE '\'`, "%"+escapeLike(f.Query)+"%")
	}
	if !f.Since.IsZero() {
		add("ts >= ?", ms(f.Since))
	}
	if !f.Until.IsZero() {
		add("ts < ?", ms(f.Until))
	}
	if f.BeforeID > 0 {
		add("id < ?", f.BeforeID)
	}
	q := "SELECT " + eventCols + " FROM events"
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY id DESC LIMIT ?"
	args = append(args, clampLimit(f.Limit))
	return s.queryEvents(ctx, q, args...)
}

// GetEvents returns the events with the given ids, oldest first. Missing ids
// (for example removed by retention) are skipped.
func (s *Store) GetEvents(ctx context.Context, ids []int64) ([]*event.Event, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	q := "SELECT " + eventCols + " FROM events WHERE id IN (?" + strings.Repeat(",?", len(ids)-1) + ") ORDER BY id"
	return s.queryEvents(ctx, q, args...)
}

func (s *Store) queryEvents(ctx context.Context, q string, args ...any) ([]*event.Event, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*event.Event{}
	for rows.Next() {
		var ev event.Event
		var ts int64
		var fields string
		if err := rows.Scan(&ev.ID, &ts, &ev.Source, &ev.Host, &ev.Type, &ev.SrcIP, &ev.User, &ev.Message, &fields); err != nil {
			return nil, err
		}
		ev.Timestamp = fromMS(ts)
		if err := json.Unmarshal([]byte(fields), &ev.Fields); err != nil {
			return nil, fmt.Errorf("store: event %d fields: %w", ev.ID, err)
		}
		out = append(out, &ev)
	}
	return out, rows.Err()
}

// InsertAlert stores a new alert and sets its ID and CreatedAt.
func (s *Store) InsertAlert(ctx context.Context, a *event.Alert) error {
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC()
	}
	if a.Status == "" {
		a.Status = event.StatusOpen
	}
	ids, err := json.Marshal(a.EventIDs)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO alerts
		(rule_id, rule_name, severity, group_key, count, description, first_seen, last_seen, event_ids, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.RuleID, a.RuleName, a.Severity, a.GroupKey, a.Count, a.Description,
		ms(a.FirstSeen), ms(a.LastSeen), string(ids), a.Status, ms(a.CreatedAt))
	if err != nil {
		return err
	}
	a.ID, err = res.LastInsertId()
	return err
}

// AlertFilter narrows ListAlerts.
type AlertFilter struct {
	Status   string
	Severity string
	RuleID   string
	GroupKey string
	BeforeID int64
	Limit    int
}

const alertCols = `id, rule_id, rule_name, severity, group_key, count, description, first_seen, last_seen, event_ids, status, created_at`

// ListAlerts returns alerts newest first.
func (s *Store) ListAlerts(ctx context.Context, f AlertFilter) ([]*event.Alert, error) {
	var where []string
	var args []any
	add := func(cond string, v any) {
		where = append(where, cond)
		args = append(args, v)
	}
	if f.Status != "" {
		add("status = ?", f.Status)
	}
	if f.Severity != "" {
		add("severity = ?", f.Severity)
	}
	if f.RuleID != "" {
		add("rule_id = ?", f.RuleID)
	}
	if f.GroupKey != "" {
		add("group_key = ?", f.GroupKey)
	}
	if f.BeforeID > 0 {
		add("id < ?", f.BeforeID)
	}
	q := "SELECT " + alertCols + " FROM alerts"
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY id DESC LIMIT ?"
	args = append(args, clampLimit(f.Limit))

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*event.Alert{}
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// GetAlert returns one alert.
func (s *Store) GetAlert(ctx context.Context, id int64) (*event.Alert, error) {
	row := s.db.QueryRowContext(ctx, "SELECT "+alertCols+" FROM alerts WHERE id = ?", id)
	a, err := scanAlert(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

// SetAlertStatus changes an alert's status.
func (s *Store) SetAlertStatus(ctx context.Context, id int64, status string) error {
	if !event.ValidStatus(status) {
		return fmt.Errorf("invalid status %q", status)
	}
	res, err := s.db.ExecContext(ctx, "UPDATE alerts SET status = ? WHERE id = ?", status, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

type scanner interface{ Scan(...any) error }

func scanAlert(r scanner) (*event.Alert, error) {
	var a event.Alert
	var first, last, created int64
	var ids string
	if err := r.Scan(&a.ID, &a.RuleID, &a.RuleName, &a.Severity, &a.GroupKey, &a.Count, &a.Description,
		&first, &last, &ids, &a.Status, &created); err != nil {
		return nil, err
	}
	a.FirstSeen, a.LastSeen, a.CreatedAt = fromMS(first), fromMS(last), fromMS(created)
	if err := json.Unmarshal([]byte(ids), &a.EventIDs); err != nil {
		return nil, fmt.Errorf("store: alert %d event_ids: %w", a.ID, err)
	}
	return &a, nil
}

// Stats is the dashboard summary.
type Stats struct {
	Since          time.Time      `json:"since"`
	TotalEvents    int64          `json:"total_events"`
	WindowEvents   int64          `json:"window_events"`
	EventsByType   map[string]int `json:"events_by_type"`
	OpenBySeverity map[string]int `json:"open_alerts_by_severity"`
	AlertsByStatus map[string]int `json:"alerts_by_status"`
	TopSources     []Count        `json:"top_source_ips"`
	TopAlertedIPs  []Count        `json:"top_alerted_ips"`
	Timeline       []Bucket       `json:"timeline"`
	BucketSeconds  int            `json:"bucket_seconds"`
}

// Count is a label with a count.
type Count struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// Bucket is one point of the event timeline.
type Bucket struct {
	Start  time.Time `json:"start"`
	Events int       `json:"events"`
	Alerts int       `json:"alerts"`
}

// Stats summarizes activity between since and now, with a timeline split
// into buckets of the given size.
func (s *Store) Stats(ctx context.Context, since, now time.Time, bucket time.Duration) (*Stats, error) {
	st := &Stats{
		Since:          since,
		EventsByType:   map[string]int{},
		OpenBySeverity: map[string]int{},
		AlertsByStatus: map[string]int{},
		BucketSeconds:  int(bucket / time.Second),
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM events").Scan(&st.TotalEvents); err != nil {
		return nil, err
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE ts >= ?", ms(since)).Scan(&st.WindowEvents); err != nil {
		return nil, err
	}
	if err := s.countInto(ctx, st.EventsByType, "SELECT type, COUNT(*) FROM events WHERE ts >= ? GROUP BY type", ms(since)); err != nil {
		return nil, err
	}
	if err := s.countInto(ctx, st.OpenBySeverity, "SELECT severity, COUNT(*) FROM alerts WHERE status = 'open' GROUP BY severity"); err != nil {
		return nil, err
	}
	if err := s.countInto(ctx, st.AlertsByStatus, "SELECT status, COUNT(*) FROM alerts GROUP BY status"); err != nil {
		return nil, err
	}
	var err error
	if st.TopSources, err = s.topCounts(ctx, "SELECT src_ip, COUNT(*) AS n FROM events WHERE ts >= ? AND src_ip != '' GROUP BY src_ip ORDER BY n DESC LIMIT 10", ms(since)); err != nil {
		return nil, err
	}
	if st.TopAlertedIPs, err = s.topCounts(ctx, "SELECT group_key, COUNT(*) AS n FROM alerts WHERE created_at >= ? AND group_key != '' GROUP BY group_key ORDER BY n DESC LIMIT 10", ms(since)); err != nil {
		return nil, err
	}
	if st.Timeline, err = s.timeline(ctx, since, now, bucket); err != nil {
		return nil, err
	}
	return st, nil
}

func (s *Store) countInto(ctx context.Context, m map[string]int, q string, args ...any) error {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return err
		}
		m[k] = n
	}
	return rows.Err()
}

func (s *Store) topCounts(ctx context.Context, q string, args ...any) ([]Count, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Count{}
	for rows.Next() {
		var c Count
		if err := rows.Scan(&c.Key, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// timeline counts events and alerts (by the time of their last event) per
// bucket, filling empty buckets with zeros.
func (s *Store) timeline(ctx context.Context, since, now time.Time, bucket time.Duration) ([]Bucket, error) {
	if bucket <= 0 {
		bucket = time.Minute
	}
	bms := bucket.Milliseconds()
	start := since.Truncate(bucket)
	n := int(now.Sub(start)/bucket) + 1
	if n > 1440 {
		return nil, fmt.Errorf("store: timeline of %d buckets is too large", n)
	}
	out := make([]Bucket, n)
	for i := range out {
		out[i].Start = start.Add(time.Duration(i) * bucket).UTC()
	}
	fill := func(q string, set func(*Bucket, int)) error {
		rows, err := s.db.QueryContext(ctx, q, ms(start), bms, ms(start), ms(now))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var idx int64
			var c int
			if err := rows.Scan(&idx, &c); err != nil {
				return err
			}
			if idx >= 0 && int(idx) < len(out) {
				set(&out[idx], c)
			}
		}
		return rows.Err()
	}
	if err := fill(`SELECT (ts - ?) / ?, COUNT(*) FROM events WHERE ts >= ? AND ts <= ? GROUP BY 1`,
		func(b *Bucket, c int) { b.Events = c }); err != nil {
		return nil, err
	}
	if err := fill(`SELECT (last_seen - ?) / ?, COUNT(*) FROM alerts WHERE last_seen >= ? AND last_seen <= ? GROUP BY 1`,
		func(b *Bucket, c int) { b.Alerts = c }); err != nil {
		return nil, err
	}
	return out, nil
}

// DeleteEventsBefore removes events older than t and returns how many were
// deleted. Alerts are kept; their event_ids may then point at nothing.
func (s *Store) DeleteEventsBefore(ctx context.Context, t time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, "DELETE FROM events WHERE ts < ?", ms(t))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func clampLimit(n int) int {
	if n <= 0 {
		return 100
	}
	if n > 1000 {
		return 1000
	}
	return n
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}
