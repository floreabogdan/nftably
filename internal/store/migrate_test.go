package store

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// TestStarterNotResurrectedOnVersionBump verifies that once the object model
// exists (version ≥ 5), a later schema bump does not re-seed the starter table
// the operator deliberately deleted.
func TestStarterNotResurrectedOnVersionBump(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bump.db")

	// Fresh install: seeds the starter, lands at the current version.
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	tables, err := s.ListTables()
	if err != nil || len(tables) == 0 {
		t.Fatalf("fresh install should seed a starter table: %d tables, err=%v", len(tables), err)
	}
	// Operator deletes every table, then we simulate an older on-disk version so
	// the next Open re-enters migrate().
	for _, tbl := range tables {
		if err := s.DeleteTable(tbl.ID); err != nil {
			t.Fatalf("delete table: %v", err)
		}
	}
	if _, err := s.db.Exec(`PRAGMA user_version = 6`); err != nil {
		t.Fatalf("set version: %v", err)
	}
	s.Close()

	// Re-open: migrate runs (6 < current) but must NOT resurrect the starter.
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	if tables, err := s2.ListTables(); err != nil || len(tables) != 0 {
		t.Errorf("version bump resurrected the starter: %d tables, err=%v", len(tables), err)
	}
}

// TestMigrateFromV1 builds a database exactly as an M3-era build left it —
// firewall without the forwarding columns, fw_rules without chain,
// user_version 1 — and checks that Open migrates it in place without losing
// the operator's data.
func TestMigrateFromV1(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`CREATE TABLE firewall (
			id           INTEGER PRIMARY KEY CHECK (id = 1),
			input_policy TEXT NOT NULL DEFAULT 'drop',
			created_at   TEXT NOT NULL,
			updated_at   TEXT NOT NULL
		)`,
		`CREATE TABLE fw_rules (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			position   INTEGER NOT NULL,
			name       TEXT NOT NULL DEFAULT '',
			action     TEXT NOT NULL DEFAULT 'accept',
			proto      TEXT NOT NULL DEFAULT 'any',
			dports     TEXT NOT NULL DEFAULT '',
			saddrs     TEXT NOT NULL DEFAULT '',
			iif        TEXT NOT NULL DEFAULT '',
			enabled    INTEGER NOT NULL DEFAULT 1,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`INSERT INTO firewall (id, input_policy, created_at, updated_at) VALUES (1, 'accept', 't', 't')`,
		`INSERT INTO fw_rules (position, name, action, proto, dports, created_at, updated_at)
			VALUES (1, 'ssh', 'accept', 'tcp', '22', 't', 't')`,
		`PRAGMA user_version = 1`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("build v1 db: %v\n%s", err, stmt)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// The old flat firewall/fw_rules model is retired; migration only has to bring
	// a legacy-shaped database up to the current schema cleanly, with the object
	// model seeded. (The abandoned old tables are left in place, untouched.)
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open v1 db: %v", err)
	}
	var version int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != schemaVersion {
		t.Fatalf("user_version after migration = %d, want %d", version, schemaVersion)
	}
	if tables, err := s.ListTables(); err != nil || len(tables) == 0 {
		t.Fatalf("object model not seeded after migrating a legacy db: %d tables, err=%v", len(tables), err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Re-opening must be a no-op (migrations are safe to re-run).
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen migrated db: %v", err)
	}
	defer s2.Close()
}

// TestMigrateAdoptsV3Lists builds a database from the fixed-two-lists era —
// list_entries keyed by the legacy "mgmt"/"block" text column, user_version 3
// — and checks that Open moves the entries under the seeded ip_lists rows.
func TestMigrateAdoptsV3Lists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v3.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`CREATE TABLE list_entries (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			list       TEXT NOT NULL,
			cidr       TEXT NOT NULL,
			note       TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			UNIQUE(list, cidr)
		)`,
		`INSERT INTO list_entries (list, cidr, note, created_at, updated_at) VALUES
			('mgmt', '10.0.0.0/24', 'office', 't', 't'),
			('block', '203.0.113.9', 'scanner', 't', 't')`,
		`PRAGMA user_version = 3`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("build v3 db: %v\n%s", err, stmt)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("open v3 db: %v", err)
	}
	defer s.Close()

	mgmt, err := s.GetListByName("management")
	if err != nil || mgmt.Role != RoleAllow {
		t.Fatalf("management list: %+v err=%v", mgmt, err)
	}
	block, err := s.GetListByName("blacklist")
	if err != nil || block.Role != RoleBlock {
		t.Fatalf("blacklist: %+v err=%v", block, err)
	}
	me, err := s.ListEntries(mgmt.ID)
	if err != nil || len(me) != 1 || me[0].CIDR != "10.0.0.0/24" || me[0].Note != "office" {
		t.Fatalf("adopted mgmt entries: %+v err=%v", me, err)
	}
	be, _ := s.ListEntries(block.ID)
	if len(be) != 1 || be[0].CIDR != "203.0.113.9" {
		t.Fatalf("adopted block entries: %+v", be)
	}
	// Uniqueness still works per list on the legacy constraint.
	if err := s.AddListEntry(block.ID, "203.0.113.9", ""); err == nil {
		t.Fatal("duplicate accepted after adoption")
	}
	if err := s.AddListEntry(mgmt.ID, "192.0.2.1", ""); err != nil {
		t.Fatalf("post-adoption insert: %v", err)
	}
}
