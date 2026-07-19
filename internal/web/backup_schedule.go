package web

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// backup_schedule.go writes the config backup to disk on a timer when the
// operator opts in — the automatic side of the manual export. Backups land in a
// backups/ directory under the data dir, newest kept, the rest pruned.

const (
	autoBackupInterval = 24 * time.Hour
	autoBackupKeep     = 14
	autoBackupPrefix   = "nftably-"
)

// autoBackupNameRe is the exact shape of a scheduled-backup filename; used to
// gate the download so no other path can be requested.
var autoBackupNameRe = regexp.MustCompile(`^nftably-\d{8}-\d{6}\.json$`)

// backupDir is where scheduled backups are written ("" when no data dir).
func (s *Server) backupDir() string {
	if s.dataDir == "" {
		return ""
	}
	return filepath.Join(s.dataDir, "backups")
}

// StartBackupScheduler runs the daily local backup when it's enabled in
// settings: an initial backup shortly after start, then one per interval.
func (s *Server) StartBackupScheduler(interval time.Duration) {
	if interval <= 0 {
		interval = autoBackupInterval
	}
	if s.backupDir() == "" {
		return // no writable data dir — auto-backup is unavailable
	}
	go func() {
		time.Sleep(30 * time.Second) // let startup/migration settle
		s.runAutoBackup()
		t := time.NewTicker(interval)
		defer t.Stop()
		for range t.C {
			s.runAutoBackup()
		}
	}()
}

func (s *Server) runAutoBackup() {
	st, ok, err := s.store.GetSettings()
	if err != nil || !ok || !st.BackupAuto {
		return
	}
	if err := s.writeAutoBackup(); err != nil {
		s.log.Warn("scheduled backup failed", "error", err)
	}
}

// writeAutoBackup writes one timestamped backup and prunes old ones.
func (s *Server) writeAutoBackup() error {
	dir := s.backupDir()
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	doc, err := s.buildBackup()
	if err != nil {
		return err
	}
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	name := autoBackupPrefix + time.Now().UTC().Format("20060102-150405") + ".json"
	if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
		return err
	}
	s.pruneAutoBackups()
	return nil
}

// autoBackupFile is one scheduled-backup file for the Settings UI.
type autoBackupFile struct {
	Name string
	Size int64
	Mod  time.Time
}

// listAutoBackups returns the scheduled backup files, newest first.
func (s *Server) listAutoBackups() []autoBackupFile {
	dir := s.backupDir()
	if dir == "" {
		return nil
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []autoBackupFile
	for _, e := range ents {
		if e.IsDir() || !autoBackupNameRe.MatchString(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, autoBackupFile{Name: e.Name(), Size: info.Size(), Mod: info.ModTime()})
	}
	// The filename encodes the timestamp, so a reverse name sort is newest-first.
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	return out
}

// pruneAutoBackups keeps only the newest autoBackupKeep files.
func (s *Server) pruneAutoBackups() {
	files := s.listAutoBackups()
	for i := autoBackupKeep; i < len(files); i++ {
		_ = os.Remove(filepath.Join(s.backupDir(), files[i].Name))
	}
}

// handleBackupAuto turns scheduled backups on or off (and takes one immediately
// when turning on, so the operator sees it work).
func (s *Server) handleBackupAuto(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	on := r.FormValue("auto") == "on"
	if on && s.backupDir() == "" {
		redirectErr(w, r, "/settings?tab=backup", "No writable data directory — scheduled backups need one.")
		return
	}
	if err := s.store.SaveBackupAuto(on); err != nil {
		s.serverError(w, "save backup auto", err)
		return
	}
	if on {
		if err := s.writeAutoBackup(); err != nil {
			s.log.Warn("initial scheduled backup failed", "error", err)
		}
	}
	s.audit(r, "toggled scheduled backups")
	s.renderSettings(w, r, "backup", nil, "")
}

// handleBackupFileDownload serves one scheduled-backup file. The name is matched
// against the strict pattern, so no other path can be reached.
func (s *Server) handleBackupFileDownload(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	dir := s.backupDir()
	if dir == "" || !autoBackupNameRe.MatchString(name) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+strings.ReplaceAll(name, `"`, "")+`"`)
	http.ServeFile(w, r, filepath.Join(dir, name))
}
