package store

import (
	"database/sql"
	"fmt"
	"time"
)

// Config version statuses.
const (
	VersionPending   = "pending"
	VersionConfirmed = "confirmed"
	VersionReverted  = "reverted"
	VersionFailed    = "failed"
)

// ConfigVersion is one recorded apply: the exact text loaded into the kernel
// and what became of it.
type ConfigVersion struct {
	ID     int64
	Ts     time.Time
	Actor  string
	Config string
	Status string
}

// InsertConfigVersion records a new version and returns its id.
func (s *Store) InsertConfigVersion(actor, config, status string) (int64, error) {
	ts := now()
	res, err := s.db.Exec(`
		INSERT INTO config_versions (ts, actor, config, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)`, ts, actor, config, status, ts, ts)
	if err != nil {
		return 0, fmt.Errorf("store: insert config version: %w", err)
	}
	return res.LastInsertId()
}

// SetConfigVersionStatus moves a version through its lifecycle.
func (s *Store) SetConfigVersionStatus(id int64, status string) error {
	res, err := s.db.Exec(`UPDATE config_versions SET status = ?, updated_at = ? WHERE id = ?`, status, now(), id)
	if err != nil {
		return fmt.Errorf("store: set version status: %w", err)
	}
	return notFoundIfZero(res)
}

// GetConfigVersion returns one version (with its full config text).
func (s *Store) GetConfigVersion(id int64) (ConfigVersion, error) {
	var v ConfigVersion
	var ts string
	row := s.db.QueryRow(`SELECT id, ts, actor, config, status FROM config_versions WHERE id = ?`, id)
	err := row.Scan(&v.ID, &ts, &v.Actor, &v.Config, &v.Status)
	if err == sql.ErrNoRows {
		return ConfigVersion{}, ErrNotFound
	}
	if err != nil {
		return ConfigVersion{}, fmt.Errorf("store: get config version: %w", err)
	}
	v.Ts, _ = time.Parse(time.RFC3339Nano, ts)
	return v, nil
}

// ListConfigVersions returns the most recent versions, newest first, without
// their config text (the list view doesn't need the payload).
func (s *Store) ListConfigVersions(limit int) ([]ConfigVersion, error) {
	rows, err := s.db.Query(`SELECT id, ts, actor, status FROM config_versions ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list config versions: %w", err)
	}
	defer rows.Close()

	var out []ConfigVersion
	for rows.Next() {
		var v ConfigVersion
		var ts string
		if err := rows.Scan(&v.ID, &ts, &v.Actor, &v.Status); err != nil {
			return nil, fmt.Errorf("store: scan config version: %w", err)
		}
		v.Ts, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, v)
	}
	return out, rows.Err()
}

// PendingApply is the armed, unconfirmed apply — at most one exists.
type PendingApply struct {
	VersionID  int64
	PrevTable  string
	PrevExists bool
	Deadline   time.Time
}

// SetPendingApply records the armed apply. It refuses to overwrite an existing
// one — the applyMu serialization should make that impossible, and if it
// somehow happens, losing the first revert snapshot would be unrecoverable.
func (s *Store) SetPendingApply(p PendingApply) error {
	_, err := s.db.Exec(`
		INSERT INTO pending_apply (id, version_id, prev_table, prev_exists, deadline, created_at)
		VALUES (1, ?, ?, ?, ?, ?)`,
		p.VersionID, p.PrevTable, p.PrevExists, p.Deadline.UTC().Format(time.RFC3339Nano), now())
	if err != nil {
		return fmt.Errorf("store: set pending apply: %w", err)
	}
	return nil
}

// GetPendingApply returns the armed apply, or ok=false when none is pending.
func (s *Store) GetPendingApply() (PendingApply, bool, error) {
	var p PendingApply
	var deadline string
	row := s.db.QueryRow(`SELECT version_id, prev_table, prev_exists, deadline FROM pending_apply WHERE id = 1`)
	err := row.Scan(&p.VersionID, &p.PrevTable, &p.PrevExists, &deadline)
	if err == sql.ErrNoRows {
		return PendingApply{}, false, nil
	}
	if err != nil {
		return PendingApply{}, false, fmt.Errorf("store: get pending apply: %w", err)
	}
	p.Deadline, err = time.Parse(time.RFC3339Nano, deadline)
	if err != nil {
		return PendingApply{}, false, fmt.Errorf("store: parse pending deadline: %w", err)
	}
	return p, true, nil
}

// ClearPendingApply removes the armed apply (after confirm or revert).
func (s *Store) ClearPendingApply() error {
	if _, err := s.db.Exec(`DELETE FROM pending_apply WHERE id = 1`); err != nil {
		return fmt.Errorf("store: clear pending apply: %w", err)
	}
	return nil
}
