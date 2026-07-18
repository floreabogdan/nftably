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
const schemaVersion = 4

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

	// version < 2 (M4): forwarding fields on firewall, the chain column on
	// fw_rules. A fresh database created these via schema.go already, so each
	// column is added only if missing.
	// version < 3 (M6): the optional GeoIP database path on settings.
	// version < 4: named lists — entries move under ip_lists, rules can use
	// a list as their source.
	adds := []struct{ table, column, ddl string }{
		{"firewall", "forward_policy", `TEXT NOT NULL DEFAULT 'drop'`},
		{"firewall", "wan_iface", `TEXT NOT NULL DEFAULT ''`},
		{"firewall", "masquerade", `INTEGER NOT NULL DEFAULT 0`},
		{"fw_rules", "chain", `TEXT NOT NULL DEFAULT 'input'`},
		{"fw_rules", "src_list_id", `INTEGER NOT NULL DEFAULT 0`},
		{"settings", "geoip_db", `TEXT NOT NULL DEFAULT ''`},
		{"list_entries", "list_id", `INTEGER NOT NULL DEFAULT 0`},
	}
	for _, a := range adds {
		if err := addColumnIfMissing(tx, a.table, a.column, a.ddl); err != nil {
			return err
		}
	}

	// The two opinionated default lists, and the adoption of any entries
	// written by the two-fixed-lists era ("mgmt"/"block" in the legacy list
	// column). The legacy column is kept equal to the list id afterwards: on
	// pre-v4 databases the UNIQUE constraint is (list, cidr) and cannot be
	// altered, so keeping the column in lockstep preserves per-list
	// uniqueness there. All idempotent — safe to re-run.
	ts := now()
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
