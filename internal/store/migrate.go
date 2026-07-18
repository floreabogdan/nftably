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
const schemaVersion = 9

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

	// version < 1: nothing to migrate — the base schema was the whole story
	// for M1.

	// Column additions for databases created before a column existed. A fresh
	// database already has each via schema.go, so addColumnIfMissing is a no-op
	// there. (The pre-redesign firewall/fw_rules column adds were dropped along
	// with the flat model — those tables are no longer read.)
	adds := []struct{ table, column, ddl string }{
		{"settings", "geoip_db", `TEXT NOT NULL DEFAULT ''`},
		{"list_entries", "list_id", `INTEGER NOT NULL DEFAULT 0`},
		// version < 5 (the do-over): the general object model replaces the
		// single-table snapshot with a per-table JSON snapshot.
		{"pending_apply", "prev_tables", `TEXT NOT NULL DEFAULT '[]'`},
		// version < 6: opt-in monthly GeoIP auto-update.
		{"settings", "geoip_autoupdate", `INTEGER NOT NULL DEFAULT 0`},
		// version < 8: named-set sources (GeoIP country / remote feed) + refresh.
		{"ip_lists", "source", `TEXT NOT NULL DEFAULT 'manual'`},
		{"ip_lists", "source_arg", `TEXT NOT NULL DEFAULT ''`},
		{"ip_lists", "auto_refresh", `INTEGER NOT NULL DEFAULT 0`},
		{"ip_lists", "last_refresh", `TEXT NOT NULL DEFAULT ''`},
		{"ip_lists", "refresh_note", `TEXT NOT NULL DEFAULT ''`},
		// version < 9: the interface a base ingress/egress chain hooks.
		{"nft_chains", "device", `TEXT NOT NULL DEFAULT ''`},
	}
	for _, a := range adds {
		if err := addColumnIfMissing(tx, a.table, a.column, a.ddl); err != nil {
			return err
		}
	}

	ts := now()

	// Seed a neutral starter object model, but only on a database that predates
	// the object model (version < 5) and still has no owned tables — i.e. a fresh
	// install or a pre-do-over upgrade. Gating on the *starting* version, not just
	// on emptiness, is what stops a later version bump from resurrecting a starter
	// the operator deliberately deleted after the object model was already in
	// place. It shows the structure on a fresh install; the opinionated safe
	// setups live in the presets, not here.
	if version < 5 {
		if _, err := tx.Exec(`
			INSERT INTO nft_tables (family, name, comment, position, created_at, updated_at)
			SELECT 'inet', 'filter', 'Starter table — rename or delete freely', 1, ?, ?
			WHERE NOT EXISTS (SELECT 1 FROM nft_tables)`, ts, ts); err != nil {
			return fmt.Errorf("seed starter table: %w", err)
		}
		for i, ch := range []struct{ name, hook, policy string }{
			{"input", "input", "accept"},
			{"forward", "forward", "accept"},
			{"output", "output", "accept"},
		} {
			if _, err := tx.Exec(`
				INSERT INTO nft_chains (table_id, name, kind, hook, chain_type, priority, policy, position, created_at, updated_at)
				SELECT t.id, ?, 'base', ?, 'filter', 'filter', ?, ?, ?, ?
				FROM nft_tables t
				WHERE t.family = 'inet' AND t.name = 'filter'
				  AND NOT EXISTS (SELECT 1 FROM nft_chains c WHERE c.table_id = t.id AND c.name = ?)`,
				ch.name, ch.hook, ch.policy, i+1, ts, ts, ch.name); err != nil {
				return fmt.Errorf("seed starter chain %s: %w", ch.name, err)
			}
		}
	}

	// The two opinionated default lists, and the adoption of any entries written
	// by the two-fixed-lists era ("mgmt"/"block" in the legacy list column). Only
	// on databases that predate named lists (version < 4): re-running this after
	// the operator has deleted a default list would resurrect it. The legacy
	// column is kept equal to the list id afterwards: on pre-v4 databases the
	// UNIQUE constraint is (list, cidr) and cannot be altered, so keeping the
	// column in lockstep preserves per-list uniqueness there.
	if version < 4 {
		for i, seed := range []struct{ name, role, note string }{
			{"management", "allow", "Accepted before everything — this network can never be locked out."},
			{"blacklist", "block", "Dropped before established connections — blocking also cuts live sessions."},
		} {
			if _, err := tx.Exec(`INSERT OR IGNORE INTO ip_lists (name, role, note, position, created_at, updated_at)
				VALUES (?, ?, ?, ?, ?, ?)`, seed.name, seed.role, seed.note, i+1, ts, ts); err != nil {
				return fmt.Errorf("seed list %s: %w", seed.name, err)
			}
		}
		for legacy, name := range map[string]string{"mgmt": "management", "block": "blacklist"} {
			if _, err := tx.Exec(`UPDATE list_entries SET list_id = (SELECT id FROM ip_lists WHERE name = ?)
				WHERE list = ? AND list_id = 0`, name, legacy); err != nil {
				return fmt.Errorf("adopt %s entries: %w", legacy, err)
			}
		}
		if _, err := tx.Exec(`UPDATE list_entries SET list = CAST(list_id AS TEXT) WHERE list_id != 0`); err != nil {
			return fmt.Errorf("sync legacy list column: %w", err)
		}
	}

	// version < 7: drop the never-used events(ts) index — the timeline paginates
	// by id, so it only ever cost write time.
	if _, err := tx.Exec(`DROP INDEX IF EXISTS idx_events_ts`); err != nil {
		return fmt.Errorf("drop idx_events_ts: %w", err)
	}

	if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, schemaVersion)); err != nil {
		return fmt.Errorf("set user_version: %w", err)
	}
	return tx.Commit()
}

// addColumnIfMissing is ALTER TABLE ADD COLUMN, tolerant of the column already
// existing — which it does on databases created by a build that already had it
// in the base schema.
func addColumnIfMissing(tx *sql.Tx, table, column, ddl string) error {
	rows, err := tx.Query(fmt.Sprintf(`PRAGMA table_info(%q)`, table))
	if err != nil {
		return fmt.Errorf("table_info %s: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return fmt.Errorf("table_info %s: %w", table, err)
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if _, err := tx.Exec(fmt.Sprintf(`ALTER TABLE %q ADD COLUMN %q %s`, table, column, ddl)); err != nil {
		return fmt.Errorf("add %s.%s: %w", table, column, err)
	}
	return nil
}
