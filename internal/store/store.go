// Package store wraps nftably's SQLite database: settings, local user accounts,
// login sessions and the event timeline. modernc.org/sqlite is pure Go, so the
// whole tool cross-compiles from any host to the router without cgo.
package store

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Store is nftably's SQLite-backed state — settings, users, sessions and the
// event timeline — and the only thing that touches the database. It holds
// nftably's own state, not the firewall: the live ruleset is always read fresh
// from nft, never cached here.
type Store struct {
	db *sql.DB
}

// Open opens (creating if necessary) the SQLite database at path and applies
// the schema. SQLite is single-writer; a small pool is fine since nftably's
// write volume is tiny (settings, sessions, events).
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)")
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: apply schema: %w", err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: migrate: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

// CheckWritable fails when the database can be read but not written — the state
// a root-created file leaves behind when the service then runs as another user.
// SQLite only complains at the first write, so nothing above notices: nftably
// starts, serves a login page, and the login (which inserts a session row) is
// what finally breaks. Probing at startup turns that into one clear error.
func (s *Store) CheckWritable() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS write_probe (ok INTEGER)`); err != nil {
		return fmt.Errorf("store: database is not writable: %w", err)
	}
	if _, err := s.db.Exec(`DROP TABLE write_probe`); err != nil {
		return fmt.Errorf("store: database is not writable: %w", err)
	}
	return nil
}

func now() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

// affectedOne turns a zero-row UPDATE into an error, so a save against a missing
// row is a failure rather than a silent no-op.
func affectedOne(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("store: no row updated")
	}
	return nil
}
