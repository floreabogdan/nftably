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

	s, err := Open(path)
	if err != nil {
		t.Fatalf("open v1 db: %v", err)
	}
	defer s.Close()

	fw, err := s.GetFirewall()
	if err != nil {
		t.Fatal(err)
	}
	if fw.InputPolicy != "accept" || fw.ForwardPolicy != "drop" || fw.WANIface != "" || fw.Masquerade {
		t.Fatalf("migrated firewall: %+v", fw)
	}
	rules, err := s.ListRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Name != "ssh" || rules[0].Chain != "input" {
		t.Fatalf("migrated rules: %+v", rules)
	}

	// The new capabilities work on the migrated file.
	fw.WANIface = "eth0"
	fw.Masquerade = true
	if err := s.SaveFirewall(fw); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreatePortForward(PortForward{Proto: "tcp", DPort: "80", Dest: "10.0.0.2", Enabled: true}); err != nil {
		t.Fatal(err)
	}

	// Re-opening must be a no-op (migrations are safe to re-run).
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen migrated db: %v", err)
	}
	defer s2.Close()
	if fw, err = s2.GetFirewall(); err != nil || fw.WANIface != "eth0" {
		t.Fatalf("second open: %+v %v", fw, err)
	}
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
