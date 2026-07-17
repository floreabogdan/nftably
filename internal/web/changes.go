package web

import (
	"net/http"

	nftconf "github.com/floreabogdan/nftably/internal/render"
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
}

// handleChanges renders the candidate config from the model and diffs it
// against the live managed table. M2 stops here: the page shows exactly what
// M3's apply would load, and nothing on it can write to netfilter.
func (s *Server) handleChanges(w http.ResponseWriter, r *http.Request) {
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

	vm := changesVM{
		nav:       s.navFor(r, "changes"),
		Candidate: nftconf.Config(fw, rules),
	}
	for _, rule := range rules {
		if rule.Enabled {
			vm.RuleCount++
		}
	}

	live, exists, err := s.nft.Table(r.Context(), "inet", nftconf.TableName)
	if err != nil {
		vm.LiveErr = err.Error()
	} else {
		vm.TableExists = exists
		vm.Hunks = nftconf.Diff(live, vm.Candidate, 3)
		vm.Added, vm.Removed = nftconf.Stat(vm.Hunks)
	}

	render(w, s.log, "changes.html", vm)
}
