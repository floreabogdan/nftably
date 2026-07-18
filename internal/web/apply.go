package web

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	nftconf "github.com/floreabogdan/nftably/internal/render"
	"github.com/floreabogdan/nftably/internal/store"
)

// applier is the slice of the nft client the apply pipeline needs. An
// interface so tests can drive the whole pipeline against a fake instead of a
// kernel.
type applier interface {
	Available() bool
	Table(ctx context.Context, family, name string) (text string, exists bool, err error)
	CheckFile(ctx context.Context, path string) error
	ApplyFile(ctx context.Context, path string) error
}

const (
	defaultApplyTimeout = 60 * time.Second
	minApplyTimeout     = 10 * time.Second
	maxApplyTimeout     = 10 * time.Minute
)

// handleApply renders the model, validates it against the kernel, loads it as
// one atomic transaction, and arms the auto-revert: unless the operator
// confirms within the window, the pre-apply table is restored — even if this
// very apply cut off their connection.
func (s *Server) handleApply(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	timeout := defaultApplyTimeout
	if secs, err := strconv.Atoi(r.FormValue("timeout")); err == nil {
		timeout = min(max(time.Duration(secs)*time.Second, minApplyTimeout), maxApplyTimeout)
	}

	s.applyMu.Lock()
	defer s.applyMu.Unlock()

	if _, pending, err := s.store.GetPendingApply(); err != nil {
		s.serverError(w, "get pending apply", err)
		return
	} else if pending {
		http.Redirect(w, r, "/changes", http.StatusSeeOther) // the page shows the pending panel
		return
	}

	rules, err := s.store.ListRules()
	if err != nil {
		s.serverError(w, "list rules", err)
		return
	}
	fw, err := s.store.GetFirewall()
	if err != nil {
		s.serverError(w, "get firewall", err)
		return
	}
	pfs, err := s.store.ListPortForwards()
	if err != nil {
		s.serverError(w, "list port forwards", err)
		return
	}
	candidate := nftconf.Config(fw, rules, pfs)

	// Snapshot what the kernel runs now — this is what the revert restores.
	prevTable, prevExists, err := s.applier.Table(r.Context(), "inet", nftconf.TableName)
	if err != nil {
		s.renderChangesError(w, r, "Could not snapshot the live table before applying: "+err.Error())
		return
	}

	path, cleanup, err := writeTempScript(nftconf.BuildApplyFile(candidate))
	if err != nil {
		s.serverError(w, "write apply file", err)
		return
	}
	defer cleanup()

	// Kernel-side dry run first: a config nft would reject must never get as
	// far as recording a version.
	if err := s.applier.CheckFile(r.Context(), path); err != nil {
		s.renderChangesError(w, r, "nft rejected the config in the pre-apply check: "+err.Error())
		return
	}

	actor := s.currentUser(r).Username
	versionID, err := s.store.InsertConfigVersion(actor, candidate, store.VersionPending)
	if err != nil {
		s.serverError(w, "record config version", err)
		return
	}
	// Persist the revert snapshot BEFORE touching the kernel: if nftably dies
	// between apply and confirm, startup recovery finds this row and reverts.
	deadline := time.Now().Add(timeout)
	if err := s.store.SetPendingApply(store.PendingApply{
		VersionID: versionID, PrevTable: prevTable, PrevExists: prevExists, Deadline: deadline,
	}); err != nil {
		s.serverError(w, "record pending apply", err)
		return
	}

	if err := s.applier.ApplyFile(r.Context(), path); err != nil {
		_ = s.store.ClearPendingApply()
		_ = s.store.SetConfigVersionStatus(versionID, store.VersionFailed)
		s.renderChangesError(w, r, "nft rejected the config at apply time: "+err.Error())
		return
	}

	s.pendingTimer = time.AfterFunc(timeout, func() { s.autoRevert(versionID) })
	_ = s.store.InsertAudit(actor, store.EventConfigApply,
		fmt.Sprintf("applied config #%d (auto-revert in %s unless confirmed)", versionID, timeout))
	s.log.Info("config applied", "version", versionID, "confirmWithin", timeout)
	http.Redirect(w, r, "/changes", http.StatusSeeOther)
}

// handleApplyConfirm keeps the pending config: the operator proved they still
// have a working connection, so the revert is disarmed.
func (s *Server) handleApplyConfirm(w http.ResponseWriter, r *http.Request) {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()

	p, pending, err := s.store.GetPendingApply()
	if err != nil {
		s.serverError(w, "get pending apply", err)
		return
	}
	if !pending {
		http.Redirect(w, r, "/changes", http.StatusSeeOther)
		return
	}
	s.stopPendingTimer()
	if err := s.store.ClearPendingApply(); err != nil {
		s.serverError(w, "clear pending apply", err)
		return
	}
	if err := s.store.SetConfigVersionStatus(p.VersionID, store.VersionConfirmed); err != nil {
		s.serverError(w, "confirm version", err)
		return
	}
	_ = s.store.InsertAudit(s.currentUser(r).Username, store.EventConfigApply,
		fmt.Sprintf("confirmed config #%d", p.VersionID))
	http.Redirect(w, r, "/changes", http.StatusSeeOther)
}

// handleApplyRollback restores the pre-apply table right now, without waiting
// for the timer.
func (s *Server) handleApplyRollback(w http.ResponseWriter, r *http.Request) {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()

	p, pending, err := s.store.GetPendingApply()
	if err != nil {
		s.serverError(w, "get pending apply", err)
		return
	}
	if !pending {
		http.Redirect(w, r, "/changes", http.StatusSeeOther)
		return
	}
	s.stopPendingTimer()
	if err := s.revert(p, s.currentUser(r).Username, "operator rollback"); err != nil {
		s.renderChangesError(w, r, "Rollback failed: "+err.Error())
		return
	}
	http.Redirect(w, r, "/changes", http.StatusSeeOther)
}

// autoRevert fires when the confirm window elapses. It re-checks the pending
// state under the lock: a confirm or rollback that won the race disarms it.
func (s *Server) autoRevert(versionID int64) {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()

	p, pending, err := s.store.GetPendingApply()
	if err != nil || !pending || p.VersionID != versionID {
		return
	}
	if err := s.revert(p, "", "auto-revert: confirm window elapsed"); err != nil {
		s.log.Error("auto-revert failed", "version", versionID, "error", err)
	}
}

// RecoverPendingApply reverts an apply orphaned by a crash or restart during
// its confirm window. The in-memory timer died with the old process, so the
// only safe resolution is to restore the snapshot — the operator never
// confirmed, and "restart the service" must not become a way to skip the
// confirm step.
func (s *Server) RecoverPendingApply() {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()

	p, pending, err := s.store.GetPendingApply()
	if err != nil {
		s.log.Error("pending-apply recovery check failed", "error", err)
		return
	}
	if !pending {
		return
	}
	s.log.Warn("found an unconfirmed apply from a previous run — reverting it", "version", p.VersionID)
	if err := s.revert(p, "", "auto-revert: nftably restarted during the confirm window"); err != nil {
		s.log.Error("startup revert failed", "version", p.VersionID, "error", err)
	}
}

// revert restores the pre-apply snapshot and settles the version's status.
// Callers hold applyMu. On failure the pending row is kept, so a later startup
// recovery retries rather than leaving the kernel on an unconfirmed config.
func (s *Server) revert(p store.PendingApply, actor, reason string) error {
	path, cleanup, err := writeTempScript(nftconf.BuildRevertFile(p.PrevTable, p.PrevExists))
	if err != nil {
		return err
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.applier.ApplyFile(ctx, path); err != nil {
		return fmt.Errorf("restore previous table: %w", err)
	}

	if err := s.store.ClearPendingApply(); err != nil {
		return err
	}
	if err := s.store.SetConfigVersionStatus(p.VersionID, store.VersionReverted); err != nil {
		return err
	}
	msg := fmt.Sprintf("reverted config #%d (%s)", p.VersionID, reason)
	if actor != "" {
		_ = s.store.InsertAudit(actor, store.EventConfigRevert, msg)
	} else {
		_ = s.store.InsertEvent(store.EventConfigRevert, msg)
	}
	s.log.Info("config reverted", "version", p.VersionID, "reason", reason)
	return nil
}

func (s *Server) stopPendingTimer() {
	if s.pendingTimer != nil {
		s.pendingTimer.Stop()
		s.pendingTimer = nil
	}
}

// writeTempScript writes an nft script where `nft -f` can read it and returns
// the path plus a cleanup func. 0600: the script is not secret, but there is no
// reason for anyone else on the box to read firewall internals either.
func writeTempScript(content string) (string, func(), error) {
	f, err := os.CreateTemp("", "nftably-apply-*.nft")
	if err != nil {
		return "", nil, err
	}
	path := f.Name()
	cleanup := func() { os.Remove(path) }
	if err := os.Chmod(path, 0o600); err != nil {
		f.Close()
		cleanup()
		return "", nil, err
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		cleanup()
		return "", nil, err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", nil, err
	}
	return path, cleanup, nil
}
