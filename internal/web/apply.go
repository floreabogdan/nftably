package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
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
	// kernelOpTimeout bounds a single nft check/apply invocation. It is
	// deliberately generous and, crucially, independent of the browser request:
	// an apply can sever the operator's own connection (that is what the
	// auto-revert exists for), and if that cancellation propagated into the nft
	// process it would SIGKILL `nft -f` mid-transaction. Running the kernel ops
	// on a background context — as the revert path already does — keeps the
	// transaction atomic regardless of what happens to the socket.
	kernelOpTimeout = 60 * time.Second
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

	// The kernel operations below (snapshot, check, apply) run on a context
	// decoupled from the browser request: this apply may cut off the very
	// connection that issued it, and that must not abort the transaction.
	kctx, kcancel := context.WithTimeout(context.Background(), kernelOpTimeout)
	defer kcancel()

	if _, pending, err := s.store.GetPendingApply(); err != nil {
		s.serverError(w, "get pending apply", err)
		return
	} else if pending {
		http.Redirect(w, r, "/changes", http.StatusSeeOther) // the page shows the pending panel
		return
	}

	m, err := s.loadModel()
	if err != nil {
		s.serverError(w, "load model", err)
		return
	}
	candidate := nftconf.Config(m)

	// Which tables must this apply remove? Any nftably had in the kernel at the
	// last confirmed apply that the operator has since deleted from the model.
	current := modelTableRefs(m)
	ledger, err := s.store.GetAppliedTables()
	if err != nil {
		s.serverError(w, "get applied tables", err)
		return
	}
	removed := refsMinus(ledger, current)

	// Snapshot every table this apply touches — the ones it will replace and the
	// ones it will remove — so the revert can restore each exactly.
	snaps, err := s.snapshotTables(kctx, unionRefs(current, ledger))
	if err != nil {
		s.renderChangesError(w, r, "Could not snapshot the live tables before applying: "+err.Error())
		return
	}

	path, cleanup, err := writeTempScript(nftconf.BuildApplyFile(m.Tables, removed))
	if err != nil {
		s.serverError(w, "write apply file", err)
		return
	}
	defer cleanup()

	// Kernel-side dry run first: a config nft would reject must never get as
	// far as recording a version.
	if err := s.applier.CheckFile(kctx, path); err != nil {
		s.renderChangesError(w, r, "nft rejected the config in the pre-apply check: "+err.Error())
		return
	}

	actor := s.currentUser(r).Username
	// Capture the model as a backup document alongside the rendered config, so
	// this version can later be restored into the object model exactly. A
	// snapshot failure must not block the apply — it just means this version
	// won't be restorable.
	var snapshot string
	if doc, berr := s.buildBackup(); berr == nil {
		if b, jerr := json.Marshal(doc); jerr == nil {
			snapshot = string(b)
		}
	}
	versionID, err := s.store.InsertConfigVersion(actor, candidate, snapshot, store.VersionPending)
	if err != nil {
		s.serverError(w, "record config version", err)
		return
	}
	// Persist the revert snapshot BEFORE touching the kernel: if nftably dies
	// between apply and confirm, startup recovery finds this row and reverts.
	deadline := time.Now().Add(timeout)
	if err := s.store.SetPendingApply(store.PendingApply{
		VersionID: versionID, PrevTables: snaps, Deadline: deadline,
	}); err != nil {
		s.serverError(w, "record pending apply", err)
		return
	}

	if err := s.applier.ApplyFile(kctx, path); err != nil {
		_ = s.store.ClearPendingApply()
		_ = s.store.SetConfigVersionStatus(versionID, store.VersionFailed)
		s.renderChangesError(w, r, "nft rejected the config at apply time: "+err.Error())
		return
	}

	s.pendingTimer = time.AfterFunc(timeout, func() { s.autoRevert(versionID) })
	s.pendingAppliedTables = current // the exact owned set the kernel now runs
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
	// The apply is now the kernel's truth: record the owned-table set that was
	// actually applied as the ledger the next apply diffs against for removals.
	// Use the set captured at apply time, not the live model — the model may have
	// been edited during the pending window, and recording that would orphan the
	// running table from future removal diffs.
	applied := s.pendingAppliedTables
	if applied == nil { // defensive: fall back to the live model
		if m, err := s.loadModel(); err == nil {
			applied = modelTableRefs(m)
		}
	}
	_ = s.store.SetAppliedTables(applied)
	// Baseline the live owned tables now that this apply is the kernel's truth,
	// so any out-of-band change from here on registers as drift.
	s.recordAppliedFingerprint(context.Background())
	s.pendingAppliedTables = nil
	_ = s.store.InsertAudit(s.currentUser(r).Username, store.EventConfigApply,
		fmt.Sprintf("confirmed config #%d", p.VersionID))
	s.notifier.Notify(store.AlertApplyConfirmed, "", fmt.Sprintf("Config #%d confirmed and kept.", p.VersionID))
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
	path, cleanup, err := writeTempScript(nftconf.BuildRevertFile(p.PrevTables))
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
	s.pendingAppliedTables = nil // the applied set is no longer the kernel's truth
	if err := s.store.SetConfigVersionStatus(p.VersionID, store.VersionReverted); err != nil {
		return err
	}
	msg := fmt.Sprintf("reverted config #%d (%s)", p.VersionID, reason)
	if actor != "" {
		_ = s.store.InsertAudit(actor, store.EventConfigRevert, msg)
	} else {
		_ = s.store.InsertEvent(store.EventConfigRevert, msg)
	}
	// An operator rollback and an armed auto-revert are different alerts: the
	// latter usually means an apply cut off the operator's own access.
	kind := store.AlertApplyReverted
	if strings.HasPrefix(reason, "operator") {
		kind = store.AlertApplyRolledBack
	}
	s.notifier.Notify(kind, "", "Config #"+fmt.Sprint(p.VersionID)+" "+reason+".")
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
