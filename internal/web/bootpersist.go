package web

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	nftconf "github.com/floreabogdan/nftably/internal/render"
)

// bootpersist.go closes the gap between "applied" and "still there tomorrow".
// An apply is `nft -f` into the running kernel and nothing more, so a reboot
// comes up with whatever the system's nftables unit loads from disk — which,
// unless something writes it, is nothing. This writes the confirmed ruleset to
// that file.
//
// Two rules keep it safe:
//
//   - It runs on *confirm*, never on apply. A config that was auto-reverted (or
//     rolled back) never reaches the disk, so the boot file always holds a
//     ruleset the operator proved they could still reach the box through.
//   - It backs up a file it did not write, once, before the first overwrite —
//     the target is /etc/nftables.conf by default, which is nobody's to clobber.
//
// It stays off until the operator turns it on in Settings, for that same reason.

// bootBackupSuffix is appended to the pre-existing file the first time nftably
// takes over the path.
const bootBackupSuffix = ".pre-nftably"

// persistForBoot writes the current owned tables to the configured boot file.
// It reports what happened for the audit log; an error is the caller's to
// surface — a firewall that silently won't come back after a reboot is exactly
// the surprise this feature exists to prevent.
func (s *Server) persistForBoot() (string, error) {
	set, ok, err := s.store.GetSettings()
	if err != nil {
		return "", err
	}
	if !ok || !set.BootPersist {
		return "", nil
	}
	path := set.BootPath()

	m, err := s.loadModel()
	if err != nil {
		return "", err
	}
	stamp := "written " + time.Now().UTC().Format(time.RFC3339)
	content := nftconf.BuildBootFile(m.Tables, strings.TrimSpace(set.NftBinary), stamp)

	if err := backupForeignBootFile(path); err != nil {
		return "", err
	}
	if err := writeFileAtomic(path, []byte(content), 0o600); err != nil {
		return "", err
	}
	return fmt.Sprintf("wrote the boot ruleset to %s (%d tables)", path, len(m.Tables)), nil
}

// handleBootPersist saves the boot-persistence toggle and path. Turning it on
// writes the file straight away rather than waiting for the next confirmed
// apply — the operator asked for the rules to survive a reboot, and the rules
// running right now are the ones they mean.
func (s *Server) handleBootPersist(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	on := r.FormValue("enabled") != ""
	path := strings.TrimSpace(r.FormValue("path"))
	if path != "" && !filepath.IsAbs(path) {
		redirectErr(w, r, "/settings?tab=general", "The boot file needs an absolute path (for example /etc/nftables.conf).")
		return
	}
	if err := s.store.SaveBootPersist(on, path); err != nil {
		s.serverError(w, "save boot persistence", err)
		return
	}
	s.audit(r, fmt.Sprintf("turned boot persistence %s", map[bool]string{true: "on", false: "off"}[on]))
	if on {
		if _, err := s.persistForBoot(); err != nil {
			s.log.Warn("boot persistence failed", "err", err)
			redirectErr(w, r, "/settings?tab=general", "Saved, but writing the boot file failed: "+err.Error())
			return
		}
	}
	s.renderSettings(w, r, "boot", nil, "")
}

// bootFileState reports whether the boot file exists and whether it still holds
// the current model — a stale file is the failure mode worth surfacing, since
// nothing about the running firewall reveals it until a reboot.
func (s *Server) bootFileState(path string) (exists, current bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, false
	}
	m, err := s.loadModel()
	if err != nil {
		return true, false
	}
	// Compare the ruleset body, not the header — that carries a timestamp.
	return true, strings.Contains(string(data), nftconf.BuildApplyFile(m.Tables, nil))
}

// backupForeignBootFile copies an existing file aside the first time nftably
// writes over it, unless nftably wrote it (it carries the marker) or a backup is
// already there — so repeated applies never overwrite the operator's original.
func backupForeignBootFile(path string) error {
	existing, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if strings.Contains(string(existing), nftconf.BootFileMarker) {
		return nil
	}
	backup := path + bootBackupSuffix
	if _, err := os.Stat(backup); err == nil {
		return nil // the original is already saved; don't overwrite it
	}
	if err := writeFileAtomic(backup, existing, 0o600); err != nil {
		return fmt.Errorf("back up %s: %w", path, err)
	}
	return nil
}

// writeFileAtomic writes via a temp file in the same directory and renames, so a
// crash mid-write can never leave the boot file half-written — which would fail
// to load and bring the box up with no firewall at all.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".nftably-boot-*")
	if err != nil {
		return fmt.Errorf("create temp in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("install %s: %w", path, err)
	}
	return nil
}
