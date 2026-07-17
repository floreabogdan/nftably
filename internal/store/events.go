package store

import (
	"database/sql"
	"fmt"
	"time"
)

// Event kinds recorded on the timeline. M1 is read-only, so the only events are
// operator logins/logouts and settings changes; the apply/revert/drift kinds
// arrive with the milestones that add those actions.
const (
	EventLogin        = "login"
	EventLogout       = "logout"
	EventSettings     = "settings_change"
	EventRulesetError = "ruleset_error" // reading the live ruleset failed
)

// Event is one entry on the timeline, optionally attributed to an operator.
type Event struct {
	ID      int64     `json:"id"`
	Ts      time.Time `json:"ts"`
	Kind    string    `json:"kind"`
	Actor   string    `json:"actor,omitempty"`
	Message string    `json:"message"`
}

// InsertEvent appends one system event to the timeline (no actor).
func (s *Store) InsertEvent(kind, message string) error {
	return s.insertEvent(kind, "", message)
}

// InsertAudit appends one operator action to the timeline, attributed to actor.
func (s *Store) InsertAudit(actor, kind, message string) error {
	return s.insertEvent(kind, actor, message)
}

func (s *Store) insertEvent(kind, actor, message string) error {
	ts := now()
	_, err := s.db.Exec(`INSERT INTO events (ts, kind, actor, message, created_at) VALUES (?, ?, ?, ?, ?)`,
		ts, kind, actor, message, ts)
	if err != nil {
		return fmt.Errorf("store: insert event: %w", err)
	}
	return nil
}

// ListEvents returns up to limit most recent events, optionally only those with
// id strictly less than beforeID (pagination — ids are monotonic, unlike
// timestamps, which can collide within an insert burst). Pass 0 for page one.
func (s *Store) ListEvents(limit int, beforeID int64) ([]Event, error) {
	var rows *sql.Rows
	var err error
	if beforeID == 0 {
		rows, err = s.db.Query(`SELECT id, ts, kind, actor, message FROM events ORDER BY id DESC LIMIT ?`, limit)
	} else {
		rows, err = s.db.Query(`SELECT id, ts, kind, actor, message FROM events WHERE id < ? ORDER BY id DESC LIMIT ?`,
			beforeID, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("store: list events: %w", err)
	}
	defer rows.Close()

	var out []Event
	for rows.Next() {
		var e Event
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.Kind, &e.Actor, &e.Message); err != nil {
			return nil, fmt.Errorf("store: scan event: %w", err)
		}
		e.Ts, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, e)
	}
	return out, rows.Err()
}
