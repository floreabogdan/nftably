package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStatusString(t *testing.T) {
	for _, c := range []struct {
		s    Status
		want string
	}{{OK, "OK"}, {Warn, "WARN"}, {Fail, "FAIL"}} {
		if got := c.s.String(); got != c.want {
			t.Errorf("Status(%d).String() = %q, want %q", c.s, got, c.want)
		}
	}
}

func TestFailed(t *testing.T) {
	if Failed([]Result{{Status: OK}, {Status: Warn}}) {
		t.Error("no Fail result should report not-failed")
	}
	if !Failed([]Result{{Status: OK}, {Status: Fail}}) {
		t.Error("a Fail result should report failed")
	}
}

func TestModeSuffix(t *testing.T) {
	if got := modeSuffix(""); got != "" {
		t.Errorf("empty mode should have no suffix, got %q", got)
	}
	if got := modeSuffix("nf_tables"); got != " (nf_tables backend)" {
		t.Errorf("modeSuffix = %q", got)
	}
}

func TestCheckDBDirWritable(t *testing.T) {
	r := checkDBDir(Config{DBPath: filepath.Join(t.TempDir(), "nftably.db")})
	if r.Status != OK {
		t.Fatalf("a fresh temp dir should be writable: %s", r.Detail)
	}
}

func TestCheckDBDirUnwritable(t *testing.T) {
	// Put a regular file where a parent directory would need to be, so MkdirAll
	// cannot create the DB's directory.
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := checkDBDir(Config{DBPath: filepath.Join(blocker, "sub", "nftably.db")})
	if r.Status != Fail {
		t.Fatalf("a DB path under a file should fail, got %s: %s", r.Status, r.Detail)
	}
}

// Run must always return one result per check and never panic, even on a host
// with no nft, no iptables and no systemd (e.g. this test runner).
func TestRunReturnsAllChecks(t *testing.T) {
	results := Run(Config{DBPath: filepath.Join(t.TempDir(), "nftably.db")})
	if len(results) != 5 {
		t.Fatalf("expected 5 checks, got %d", len(results))
	}
	for _, r := range results {
		if strings.TrimSpace(r.Name) == "" {
			t.Errorf("a check has no name: %+v", r)
		}
	}
}
