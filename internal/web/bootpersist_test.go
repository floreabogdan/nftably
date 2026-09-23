package web

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBootPersistWritesRuleset covers the whole point of the feature: turning it
// on writes a loadable ruleset to the configured file, and it is the model's
// tables — not a flush of everything on the box.
func TestBootPersistWritesRuleset(t *testing.T) {
	srv, cookie := newTestServer(t)
	path := filepath.Join(t.TempDir(), "nftables.conf")

	rec := postForm(srv, "/settings/boot-persist", url.Values{
		"enabled": {"on"}, "path": {path},
	}, cookie)
	if rec.Code != 200 {
		t.Fatalf("code=%d, want 200 (settings re-render)", rec.Code)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("boot file not written: %v", err)
	}
	body := string(data)
	if !strings.HasPrefix(body, "#!") || !strings.Contains(body, "Managed by nftably") {
		t.Errorf("boot file is missing its shebang/marker:\n%s", body)
	}
	// The ensure+delete+create triple is what makes it safe to load over a kernel
	// that already has other tables; a flush would take them out.
	if strings.Contains(body, "flush ruleset") {
		t.Error("boot file flushes the whole ruleset — that would wipe tables nftably does not own")
	}
	if !strings.Contains(body, "delete table") || !strings.Contains(body, "table inet") {
		t.Errorf("boot file does not carry the owned tables:\n%s", body)
	}

	// The Posture page should now grade this as covered.
	checks, _, err := srv.posture()
	if err != nil {
		t.Fatal(err)
	}
	if got := statusOf(checks, "boot-persist"); got != posturePass {
		t.Errorf("posture boot-persist = %v, want pass", got)
	}
}

// TestBootPersistBacksUpForeignFile pins the one destructive moment: the file at
// the target path is somebody else's until nftably has written it once.
func TestBootPersistBacksUpForeignFile(t *testing.T) {
	srv, cookie := newTestServer(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "nftables.conf")
	const original = "#!/usr/sbin/nft -f\nflush ruleset\ntable inet handwritten {}\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	postForm(srv, "/settings/boot-persist", url.Values{"enabled": {"on"}, "path": {path}}, cookie)

	backup, err := os.ReadFile(path + bootBackupSuffix)
	if err != nil {
		t.Fatalf("the hand-written ruleset was overwritten with no backup: %v", err)
	}
	if string(backup) != original {
		t.Errorf("backup = %q, want the original file verbatim", backup)
	}

	// A second write must not clobber that backup with nftably's own output.
	postForm(srv, "/settings/boot-persist", url.Values{"enabled": {"on"}, "path": {path}}, cookie)
	backup2, _ := os.ReadFile(path + bootBackupSuffix)
	if string(backup2) != original {
		t.Errorf("a later write replaced the backup: %q", backup2)
	}
}

// TestBootPersistOffWritesNothing — the toggle is the whole consent model, so
// nothing may touch the path while it is off.
func TestBootPersistOffWritesNothing(t *testing.T) {
	srv, cookie := newTestServer(t)
	path := filepath.Join(t.TempDir(), "nftables.conf")

	postForm(srv, "/settings/boot-persist", url.Values{"path": {path}}, cookie) // no "enabled"
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("wrote %s while boot persistence was off", path)
	}
	if note, err := srv.persistForBoot(); err != nil || note != "" {
		t.Errorf("persistForBoot with the toggle off: note=%q err=%v, want a no-op", note, err)
	}
	// A relative path is rejected rather than resolved against nftably's cwd.
	rec := postForm(srv, "/settings/boot-persist", url.Values{"enabled": {"on"}, "path": {"nftables.conf"}}, cookie)
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "/settings?tab=general&err=") {
		t.Errorf("relative path: loc=%q, want an error redirect", loc)
	}
}
