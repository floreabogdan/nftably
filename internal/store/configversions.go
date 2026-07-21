package store

import (
	"database/sql"
	"encoding/json"
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
	// Snapshot is the full object model as a backup JSON document, captured at
	// apply time so a past version can be restored into the model exactly.
	// Empty for versions recorded before snapshots were kept.
	Snapshot string
}

// HasSnapshot reports whether this version can be restored into the model.
func (v ConfigVersion) HasSnapshot() bool { return v.Snapshot != "" }

// InsertConfigVersion records a new version and returns its id. snapshot is the
// backup-JSON of the model being applied (may be empty).
func (s *Store) InsertConfigVersion(actor, config, snapshot, status string) (int64, error) {
	ts := now()
	res, err := s.db.Exec(`
		INSERT INTO config_versions (ts, actor, config, model_snapshot, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, ts, actor, config, snapshot, status, ts, ts)
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
	row := s.db.QueryRow(`SELECT id, ts, actor, config, model_snapshot, status FROM config_versions WHERE id = ?`, id)
	err := row.Scan(&v.ID, &ts, &v.Actor, &v.Config, &v.Snapshot, &v.Status)
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
	// model_snapshot can be large, so the list only carries a presence marker in
	// Snapshot ("1"/"") — enough for HasSnapshot() to gate the Restore button.
	// The full payload is loaded by GetConfigVersion at restore time.
	rows, err := s.db.Query(`
		SELECT id, ts, actor, status, CASE WHEN model_snapshot != '' THEN '1' ELSE '' END
		FROM config_versions ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list config versions: %w", err)
	}
	defer rows.Close()

	var out []ConfigVersion
	for rows.Next() {
		var v ConfigVersion
		var ts string
		if err := rows.Scan(&v.ID, &ts, &v.Actor, &v.Status, &v.Snapshot); err != nil {
			return nil, fmt.Errorf("store: scan config version: %w", err)
		}
		v.Ts, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, v)
	}
	return out, rows.Err()
}

// LatestAppliedConfig returns the config text nftably most recently loaded into
// the kernel — the newest confirmed or pending version — and whether one exists.
// It is how the Firewall page decides its live counters still line up with the
// model: only when the model renders to exactly this text.
func (s *Store) LatestAppliedConfig() (config string, ok bool, err error) {
	row := s.db.QueryRow(`SELECT config FROM config_versions
		WHERE status IN ('confirmed', 'pending') ORDER BY id DESC LIMIT 1`)
	switch err := row.Scan(&config); err {
	case nil:
		return config, true, nil
	case sql.ErrNoRows:
		return "", false, nil
	default:
		return "", false, fmt.Errorf("store: latest applied config: %w", err)
	}
}

// UpdateLatestAppliedConfig rewrites the rendered config text of the newest
// confirmed/pending version — the one LatestAppliedConfig returns. An incremental
// set sync (a block or feed pushed straight to the kernel) uses this to keep the
// applied baseline equal to what the kernel now runs, so the Changes page stays in
// sync without a full apply. The version's model snapshot is left untouched (it
// still restores the model as applied).
func (s *Store) UpdateLatestAppliedConfig(config string) error {
	_, err := s.db.Exec(`UPDATE config_versions SET config = ?
		WHERE id = (SELECT id FROM config_versions
			WHERE status IN ('confirmed', 'pending') ORDER BY id DESC LIMIT 1)`, config)
	if err != nil {
		return fmt.Errorf("store: update latest applied config: %w", err)
	}
	return nil
}

// TableRef identifies one owned table.
type TableRef struct {
	Family string `json:"family"`
	Name   string `json:"name"`
}

// TableSnapshot is one table's pre-apply state, captured so a revert can put it
// back exactly. Text is the `nft list table …` output; Exists is false when the
// table was absent before the apply (so revert simply removes it).
type TableSnapshot struct {
	Family string `json:"family"`
	Name   string `json:"name"`
	Text   string `json:"text"`
	Exists bool   `json:"exists"`
}

// PendingApply is the armed, unconfirmed apply — at most one exists. PrevTables
// is the per-table snapshot the revert restores (the general model manages many
// tables, so a single blob no longer suffices).
type PendingApply struct {
	VersionID  int64
	PrevTables []TableSnapshot
	Deadline   time.Time
}

// SetPendingApply records the armed apply. It refuses to overwrite an existing
// one — the applyMu serialization should make that impossible, and if it
// somehow happens, losing the first revert snapshot would be unrecoverable.
func (s *Store) SetPendingApply(p PendingApply) error {
	blob, err := json.Marshal(p.PrevTables)
	if err != nil {
		return fmt.Errorf("store: encode pending snapshot: %w", err)
	}
	_, err = s.db.Exec(`
		INSERT INTO pending_apply (id, version_id, prev_table, prev_exists, prev_tables, deadline, created_at)
		VALUES (1, ?, '', 0, ?, ?, ?)`,
		p.VersionID, string(blob), p.Deadline.UTC().Format(time.RFC3339Nano), now())
	if err != nil {
		return fmt.Errorf("store: set pending apply: %w", err)
	}
	return nil
}

// GetPendingApply returns the armed apply, or ok=false when none is pending.
func (s *Store) GetPendingApply() (PendingApply, bool, error) {
	var p PendingApply
	var deadline, blob string
	row := s.db.QueryRow(`SELECT version_id, prev_tables, deadline FROM pending_apply WHERE id = 1`)
	err := row.Scan(&p.VersionID, &blob, &deadline)
	if err == sql.ErrNoRows {
		return PendingApply{}, false, nil
	}
	if err != nil {
		return PendingApply{}, false, fmt.Errorf("store: get pending apply: %w", err)
	}
	if blob != "" {
		if err := json.Unmarshal([]byte(blob), &p.PrevTables); err != nil {
			return PendingApply{}, false, fmt.Errorf("store: decode pending snapshot: %w", err)
		}
	}
	p.Deadline, err = time.Parse(time.RFC3339Nano, deadline)
	if err != nil {
		return PendingApply{}, false, fmt.Errorf("store: parse pending deadline: %w", err)
	}
	return p, true, nil
}

// GetAppliedTables returns the set of tables nftably had in the kernel as of the
// last confirmed apply — the ledger the next apply diffs against to know which
// tables the operator has since deleted (and must therefore be removed).
func (s *Store) GetAppliedTables() ([]TableRef, error) {
	var blob string
	err := s.db.QueryRow(`SELECT tables FROM applied_state WHERE id = 1`).Scan(&blob)
	if err == sql.ErrNoRows || blob == "" {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: get applied tables: %w", err)
	}
	var refs []TableRef
	if err := json.Unmarshal([]byte(blob), &refs); err != nil {
		return nil, fmt.Errorf("store: decode applied tables: %w", err)
	}
	return refs, nil
}

// SetAppliedTables records the owned-table set as of a confirmed apply.
func (s *Store) SetAppliedTables(refs []TableRef) error {
	blob, err := json.Marshal(refs)
	if err != nil {
		return fmt.Errorf("store: encode applied tables: %w", err)
	}
	_, err = s.db.Exec(`
		INSERT INTO applied_state (id, tables) VALUES (1, ?)
		ON CONFLICT(id) DO UPDATE SET tables = excluded.tables`, string(blob))
	if err != nil {
		return fmt.Errorf("store: set applied tables: %w", err)
	}
	return nil
}

// ClearPendingApply removes the armed apply (after confirm or revert).
func (s *Store) ClearPendingApply() error {
	if _, err := s.db.Exec(`DELETE FROM pending_apply WHERE id = 1`); err != nil {
		return fmt.Errorf("store: clear pending apply: %w", err)
	}
	return nil
}
