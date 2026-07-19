package web

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// TestAutoBackupWriteAndPrune checks a scheduled backup writes a file and that
// old snapshots are pruned to the retention limit.
func TestAutoBackupWriteAndPrune(t *testing.T) {
	srv, _ := newTestServer(t)
	srv.dataDir = t.TempDir()

	if err := srv.writeAutoBackup(); err != nil {
		t.Fatalf("writeAutoBackup: %v", err)
	}
	files := srv.listAutoBackups()
	if len(files) != 1 {
		t.Fatalf("want 1 backup after one write, got %d", len(files))
	}
	if !autoBackupNameRe.MatchString(files[0].Name) {
		t.Errorf("backup name %q doesn't match the expected pattern", files[0].Name)
	}

	// Seed more than the retention limit of pre-existing snapshots, then prune.
	dir := srv.backupDir()
	for i := 0; i < autoBackupKeep+5; i++ {
		// Distinct, pattern-matching names (date fixed, time = counter).
		name := "nftably-20000101-" + pad6(i) + ".json"
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	srv.pruneAutoBackups()
	if got := len(srv.listAutoBackups()); got != autoBackupKeep {
		t.Errorf("after prune: %d files, want %d", got, autoBackupKeep)
	}
	// The newest (highest name) must survive; the oldest must be gone.
	names := map[string]bool{}
	for _, f := range srv.listAutoBackups() {
		names[f.Name] = true
	}
	if !names["nftably-20000101-"+pad6(autoBackupKeep+4)+".json"] {
		t.Error("prune removed a newer snapshot")
	}
	if names["nftably-20000101-000000.json"] {
		t.Error("prune kept the oldest snapshot")
	}
}

func pad6(i int) string {
	s := strconv.Itoa(i)
	for len(s) < 6 {
		s = "0" + s
	}
	return s
}
