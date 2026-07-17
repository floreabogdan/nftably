package store

import (
	"database/sql"
	"fmt"
)

// schemaVersion is the migration level this build expects. The CREATE TABLE
// statements in schema.go are all IF NOT EXISTS and run unconditionally, so
// migrations here only handle what that cannot express: new columns on tables
// that already exist, and one-time data seeding. Bump this and add a case when
// the shape of an existing database has to change.
//
// nftably's database is a single file the user can snapshot and restore, so
// migrations must be forward-only and safe to re-run.
const schemaVersion = 1

func migrate(db *sql.DB) error {
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("read user_version: %w", err)
	}
	if version >= schemaVersion {
		return nil
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// version < 1: nothing to migrate yet — the base schema is the whole story
	// for M1. Future milestones add their steps here.

	if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, schemaVersion)); err != nil {
		return fmt.Errorf("set user_version: %w", err)
	}
	return tx.Commit()
}
