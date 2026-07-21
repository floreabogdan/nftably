package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	nftconf "github.com/floreabogdan/nftably/internal/render"
	"github.com/floreabogdan/nftably/internal/store"
)

// handleVersionRestore loads a past version's model snapshot back into the
// object model. Model-only: it lands the operator on Changes to review and
// apply behind the armed auto-revert, exactly like a backup restore — nothing
// touches the kernel here.
func (s *Server) handleVersionRestore(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.GetConfigVersion(pathID(r))
	if err != nil {
		s.notFoundOr(w, err)
		return
	}
	if !v.HasSnapshot() {
		redirectErr(w, r, "/changes", fmt.Sprintf("Version #%d has no saved snapshot to restore (it predates snapshots).", v.ID))
		return
	}
	var doc backupDoc
	if err := json.Unmarshal([]byte(v.Snapshot), &doc); err != nil {
		redirectErr(w, r, "/changes", "That version's snapshot is unreadable.")
		return
	}
	if err := s.restoreBackup(doc); err != nil {
		redirectErr(w, r, "/changes", "Restore failed: "+err.Error())
		return
	}
	s.audit(r, fmt.Sprintf("restored the model from version #%d", v.ID))
	http.Redirect(w, r, "/changes?saved=Restored+into+the+model+—+review+and+apply+below.", http.StatusSeeOther)
}

type changesVM struct {
	nav
	// Candidate is the full rendered `table inet nftably` block.
	Candidate string
	// LiveErr is why the live side could not be read (nft missing, no
	// privilege); the candidate still renders without it.
	LiveErr string
	// TableExists reports whether `table inet nftably` exists in the kernel yet.
	// Before the first apply it does not, and the whole candidate is new.
	TableExists bool
	// FirstApply is true when nftably has never applied anything, so there is no
	// prior render to diff against — the whole candidate is new.
	FirstApply bool
	// Drifted is true when the live kernel no longer matches what nftably last
	// applied (someone changed it with nft or a hand-written config). Detected by
	// comparing kernel-readback fingerprints, so it is robust to nft's formatting.
	Drifted bool
	Hunks   []nftconf.Hunk
	Added   int
	Removed int
	// DiffOmitted is how many diff lines were dropped from Hunks to keep a huge
	// set-element change (a big blocklist/GeoIP list) from producing a diff so
	// large it stalls the browser. Added/Removed still count the full change.
	DiffOmitted int
	RuleCount   int // enabled rules in the candidate

	// The M3 apply state.
	CanApply  bool                // nft reachable and no pending apply
	LintWarns []string            // footgun warnings shown next to the apply button
	Summary   []applyTableSummary // a scannable outline of the candidate model
	ApplyErr  string              // why the last apply attempt failed, if it did
	Flash     string              // a success banner carried on a redirect (?saved=)
	// Pending is the armed apply awaiting confirmation; nil when none.
	Pending *pendingVM
	History []store.ConfigVersion
	// SetupDone greets the operator arriving from the guided setup.
	SetupDone bool
}

type pendingVM struct {
	VersionID    int64
	Deadline     time.Time
	DeadlineUnix int64
	SecondsLeft  int
}

// applyTableSummary / applyChainSummary are the scannable outline of the
// candidate model shown above the raw diff: tables, their chains, each chain's
// hook and default policy (drop is the one that can lock you out) and rule count.
type applyTableSummary struct {
	Family    string
	Name      string
	Chains    []applyChainSummary
	NewInKern bool // this table is not in the kernel yet
}

type applyChainSummary struct {
	Name      string
	Kind      string // base | regular
	Hook      string
	Policy    string
	RuleCount int
}

// maxDiffLines caps how many diff lines the Changes page renders. A normal config
// change is a handful; a first apply or a refreshed blocklist / GeoIP list can be
// thousands of set-element lines, which would make the page enormous and stall the
// browser — those are truncated with a pointer to download the full config.
const maxDiffLines = 300

// truncateDiff caps the total number of lines across all hunks at limit, keeping
// whole hunks until the budget runs out and then cutting into the last one.
// Returns the trimmed hunks and how many lines were dropped.
func truncateDiff(hs []nftconf.Hunk, limit int) ([]nftconf.Hunk, int) {
	total := 0
	for _, h := range hs {
		total += len(h.Lines)
	}
	if total <= limit {
		return hs, 0
	}
	out := make([]nftconf.Hunk, 0, len(hs))
	budget := limit
	for _, h := range hs {
		if budget <= 0 {
			break
		}
		if len(h.Lines) > budget {
			h.Lines = h.Lines[:budget]
		}
		budget -= len(h.Lines)
		out = append(out, h)
	}
	return out, total - limit
}

// summarizeModel turns the loaded model into the outline, counting only enabled
// rules (those are what render).
func summarizeModel(m nftconf.Model, existing map[store.TableRef]bool) []applyTableSummary {
	var out []applyTableSummary
	for _, t := range m.Tables {
		ts := applyTableSummary{
			Family:    t.Family,
			Name:      t.Name,
			NewInKern: !existing[store.TableRef{Family: t.Family, Name: t.Name}],
		}
		for _, c := range t.Chains {
			enabled := 0
			for _, r := range c.Rules {
				if r.Enabled {
					enabled++
				}
			}
			ts.Chains = append(ts.Chains, applyChainSummary{
				Name: c.Name, Kind: c.Kind, Hook: c.Hook, Policy: c.Policy, RuleCount: enabled,
			})
		}
		out = append(out, ts)
	}
	return out
}

// handleChanges renders the candidate config, diffs it against the live
// managed table, and carries the apply pipeline's state: the armed pending
// apply if one exists, lint warnings, and recent version history.
func (s *Server) handleChanges(w http.ResponseWriter, r *http.Request) {
	vm, ok := s.buildChangesVM(w, r)
	if !ok {
		return
	}
	render(w, s.log, "changes.html", vm)
}

// handleConfigNftDownload serves the current model rendered as a plain nft
// script, for version control, review, or loading elsewhere with `nft -f`.
func (s *Server) handleConfigNftDownload(w http.ResponseWriter, r *http.Request) {
	m, err := s.loadModel()
	if err != nil {
		s.serverError(w, "load model", err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="nftably.nft"`)
	_, _ = w.Write([]byte(nftconf.Config(m)))
	s.audit(r, "downloaded the rendered nft config")
}

// renderChangesError re-renders the changes page with an apply-failure banner —
// apply errors carry nft's stderr, which is too much for a redirect URL.
func (s *Server) renderChangesError(w http.ResponseWriter, r *http.Request, msg string) {
	vm, ok := s.buildChangesVM(w, r)
	if !ok {
		return
	}
	vm.ApplyErr = msg
	render(w, s.log, "changes.html", vm)
}

func (s *Server) buildChangesVM(w http.ResponseWriter, r *http.Request) (changesVM, bool) {
	m, err := s.loadModel()
	if err != nil {
		s.serverError(w, "load model", err)
		return changesVM{}, false
	}

	vm := changesVM{
		nav:       s.navFor(r, "changes"),
		Candidate: nftconf.Config(m),
		LintWarns: append(nftconf.Lint(m, s.listenAddr), s.simulatedLockoutWarnings(r, m)...),
		SetupDone: r.URL.Query().Get("setup") == "1",
		Flash:     r.URL.Query().Get("saved"),
		ApplyErr:  r.URL.Query().Get("err"),
	}
	for _, t := range m.Tables {
		for _, c := range t.Chains {
			for _, rule := range c.Rules {
				if rule.Enabled {
					vm.RuleCount++
				}
			}
		}
	}

	// "What applying will change": diff the current render against the render of
	// what nftably last loaded into the kernel (LatestAppliedConfig). Both sides go
	// through the same renderer, so the diff is exactly the model delta since the
	// last apply — there is no nft-list reformatting to reconcile, so the page is
	// quiet whenever the model is unchanged, no matter how nft prints the ruleset.
	applied, appliedOK, aerr := s.store.LatestAppliedConfig()
	if aerr != nil {
		s.serverError(w, "latest applied config", aerr)
		return changesVM{}, false
	}
	vm.FirstApply = !appliedOK
	vm.Hunks = nftconf.Diff(applied, vm.Candidate, 3)
	vm.Added, vm.Removed = nftconf.Stat(vm.Hunks) // full counts, before truncation
	vm.Hunks, vm.DiffOmitted = truncateDiff(vm.Hunks, maxDiffLines)

	// The live kernel is still read — for the table-exists status and the adoption
	// warning (a table nftably is about to replace that it did not create).
	snaps, err := s.snapshotTables(r.Context(), modelTableRefs(m))
	if err != nil {
		vm.LiveErr = err.Error()
	} else {
		existing := map[store.TableRef]bool{}
		for _, sn := range snaps {
			if sn.Exists {
				vm.TableExists = true
				existing[store.TableRef{Family: sn.Family, Name: sn.Name}] = true
			}
		}
		vm.Summary = summarizeModel(m, existing)

		// Adoption warning: a table that already exists in the kernel but is absent
		// from the applied ledger was created by someone else — a hand-written
		// /etc/nftables.conf, another tool. The apply replaces it atomically, wiping
		// its current contents; flag it before the operator commits.
		if ledger, lerr := s.store.GetAppliedTables(); lerr == nil {
			owned := make(map[store.TableRef]bool, len(ledger))
			for _, ref := range ledger {
				owned[ref] = true
			}
			for _, sn := range snaps {
				if sn.Exists && !owned[store.TableRef{Family: sn.Family, Name: sn.Name}] {
					vm.LintWarns = append(vm.LintWarns, fmt.Sprintf(
						"The table %s %s already exists in the kernel and was not created by nftably — applying replaces its current contents. If a hand-written config or another tool manages it, review it before you apply and confirm.", sn.Family, sn.Name))
				}
			}
		}
	}
	if vm.Summary == nil {
		// Live tables unreadable — still show the outline of what would apply.
		vm.Summary = summarizeModel(m, nil)
	}

	// Drift: has the live kernel been changed outside nftably since the last apply?
	// This compares kernel-readback fingerprints (both produced by nft, runtime
	// state stripped), so nft's formatting never matters — it fires only on a
	// genuine out-of-band change, and is shown as a warning to re-apply.
	if base, berr := s.store.GetAppliedFingerprint(); berr == nil && base != "" {
		if liveFp, hasOwned, ferr := s.liveOwnedFingerprint(r.Context()); ferr == nil && hasOwned {
			vm.Drifted = liveFp != base
		}
	}

	if p, pending, err := s.store.GetPendingApply(); err != nil {
		s.serverError(w, "get pending apply", err)
		return changesVM{}, false
	} else if pending {
		vm.Pending = &pendingVM{
			VersionID:    p.VersionID,
			Deadline:     p.Deadline,
			DeadlineUnix: p.Deadline.Unix(),
			SecondsLeft:  max(int(time.Until(p.Deadline).Seconds()), 0),
		}
	}
	vm.CanApply = vm.LiveErr == "" && vm.Pending == nil && s.applier.Available()

	if vm.History, err = s.store.ListConfigVersions(10); err != nil {
		s.serverError(w, "list config versions", err)
		return changesVM{}, false
	}
	return vm, true
}
