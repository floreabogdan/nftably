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

// TestMigrateAddsMetricsTokenColumn builds a settings table exactly as a pre-v10
// build left it — every column except metrics_token, user_version 9 — and checks
// that Open adds the column so GetSettings (which SELECTs metrics_token) works
// for a real upgrader. Without the forward ADD COLUMN, every settings read on an
// upgraded database would fail while a fresh install stayed green.
func TestMigrateAddsMetricsTokenColumn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prev10.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	// The v9 settings shape: no metrics_token column.
	for _, stmt := range []string{
		`CREATE TABLE settings (
			id               INTEGER PRIMARY KEY CHECK (id = 1),
			router_label     TEXT NOT NULL DEFAULT '',
			listen_addr      TEXT NOT NULL DEFAULT '127.0.0.1:8080',
			nft_binary       TEXT NOT NULL DEFAULT '',
			access_whitelist TEXT NOT NULL DEFAULT '',
			geoip_db         TEXT NOT NULL DEFAULT '',
			geoip_autoupdate INTEGER NOT NULL DEFAULT 0,
			created_at       TEXT NOT NULL,
			updated_at       TEXT NOT NULL
		)`,
		`INSERT INTO settings (id, router_label, created_at, updated_at) VALUES (1, 'edge-01', 't', 't')`,
		`PRAGMA user_version = 9`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("build v9 db: %v\n%s", err, stmt)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("open v9 db: %v", err)
	}
	defer s.Close()

	// GetSettings SELECTs metrics_token — it must exist and default to "".
	st, ok, err := s.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings after migration: %v", err)
	}
	if !ok {
		t.Fatal("settings row went missing across migration")
	}
	if st.RouterLabel != "edge-01" {
		t.Errorf("existing data lost: router_label = %q, want edge-01", st.RouterLabel)
	}
	if st.MetricsToken != "" {
		t.Errorf("metrics_token default = %q, want empty", st.MetricsToken)
	}
	// And the column must be writable through the normal saver.
	if err := s.SaveMetricsToken("tok"); err != nil {
		t.Fatalf("SaveMetricsToken: %v", err)
	}
	if st, _, _ := s.GetSettings(); st.MetricsToken != "tok" {
		t.Errorf("metrics_token after save = %q, want tok", st.MetricsToken)
	}
}
