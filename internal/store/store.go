// Package store wraps nftably's SQLite database: settings, local user accounts,
// login sessions and the event timeline. modernc.org/sqlite is pure Go, so the
// whole tool cross-compiles from any host to the router without cgo.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// ErrNotFound is returned by Get/Update/Delete when the row does not exist.
var ErrNotFound = errors.New("not found")

// maxOpenConns bounds the connection pool. SQLite is single-writer, so a large
// pool buys nothing on the write side; WAL still lets these connections read
// concurrently. A small explicit cap keeps a write burst from opening an
// unbounded number of connections (and racing on the write lock past the
// busy_timeout), without pinning to 1 — which would deadlock any code path that
// held a transaction and issued another query on the same goroutine.
const maxOpenConns = 4

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
	db.SetMaxOpenConns(maxOpenConns)
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

// notFoundIfZero turns a zero-row UPDATE/DELETE into ErrNotFound, so a save
// against a missing row is a distinguishable failure rather than a silent no-op.
func notFoundIfZero(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// moveInOrder swaps a row's position with its neighbour in an ordered table, to
// move it up (dir<0) or down. table must be a compile-time constant, never user
// input (it is interpolated into the SQL).
func (s *Store) moveInOrder(table string, id int64, dir int) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var pos int
	if err := tx.QueryRow(fmt.Sprintf(`SELECT position FROM %s WHERE id = ?`, table), id).Scan(&pos); err != nil {
		if err == sql.ErrNoRows {
			return ErrNotFound
		}
		return fmt.Errorf("store: move %s: %w", table, err)
	}

	cmp, ord := ">", "ASC"
	if dir < 0 {
		cmp, ord = "<", "DESC"
	}
	var nid int64
	var npos int
	err = tx.QueryRow(fmt.Sprintf(
		`SELECT id, position FROM %s WHERE position %s ? ORDER BY position %s, id LIMIT 1`, table, cmp, ord),
		pos).Scan(&nid, &npos)
	if err == sql.ErrNoRows {
		return nil // already at the end it is moving towards
	}
	if err != nil {
		return fmt.Errorf("store: move %s: %w", table, err)
	}

	ts := now()
	if _, err := tx.Exec(fmt.Sprintf(`UPDATE %s SET position = ?, updated_at = ? WHERE id = ?`, table), npos, ts, id); err != nil {
		return fmt.Errorf("store: move %s: %w", table, err)
	}
	if _, err := tx.Exec(fmt.Sprintf(`UPDATE %s SET position = ?, updated_at = ? WHERE id = ?`, table), pos, ts, nid); err != nil {
		return fmt.Errorf("store: move %s: %w", table, err)
	}
	return tx.Commit()
}
