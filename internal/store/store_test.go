package store

import (
	"path/filepath"
	"testing"
)

// testStore opens a fresh store in a temp directory, cleaned up after the test.
func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
