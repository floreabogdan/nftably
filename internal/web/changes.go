package web

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	nftconf "github.com/floreabogdan/nftably/internal/render"
	"github.com/floreabogdan/nftably/internal/store"
)

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
	Hunks       []nftconf.Hunk
	Added       int
	Removed     int
	RuleCount   int // enabled rules in the candidate

	// The M3 apply state.
	CanApply  bool     // nft reachable and no pending apply
	LintWarns []string // footgun warnings shown next to the apply button
	ApplyErr  string   // why the last apply attempt failed, if it did
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
		LintWarns: nftconf.Lint(m, s.listenAddr),
		SetupDone: r.URL.Query().Get("setup") == "1",
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

	// Build the "live" side from the current kernel text of every owned table,
	// in model order, so it lines up with the candidate for a meaningful diff.
	snaps, err := s.snapshotTables(r.Context(), modelTableRefs(m))
	if err != nil {
		vm.LiveErr = err.Error()
	} else {
		var live strings.Builder
		for _, sn := range snaps {
			if sn.Exists {
				vm.TableExists = true
				live.WriteString(sn.Text)
				if !strings.HasSuffix(sn.Text, "\n") {
					live.WriteString("\n")
				}
			}
		}
		vm.Hunks = nftconf.Diff(live.String(), vm.Candidate, 3)
		vm.Added, vm.Removed = nftconf.Stat(vm.Hunks)

		// Adoption warning: a table nftably is about to replace that already
		// exists in the kernel but is absent from the applied ledger was created
		// by someone else — a hand-written /etc/nftables.conf, another tool. The
		// apply replaces it atomically, wiping its current contents, and a confirm
		// makes that permanent. Flag it before the operator commits (the ordinary
		// diff shows the change, but not that the table was not nftably's).
		if ledger, lerr := s.store.GetAppliedTables(); lerr == nil {
			owned := make(map[store.TableRef]bool, len(ledger))
			for _, ref := range ledger {
				owned[ref] = true
			}
			for _, sn := range snaps {
				if sn.Exists && !owned[store.TableRef{Family: sn.Family, Name: sn.Name}] {
					vm.LintWarns = append(vm.LintWarns, fmt.Sprintf(
						"The table %s %s already exists in the kernel and was not created by nftably — applying replaces its current contents. If a hand-written config or another tool manages it, review the diff carefully before you apply and confirm.", sn.Family, sn.Name))
				}
			}
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
