package web

import (
	"context"

	nftconf "github.com/floreabogdan/nftably/internal/render"
	"github.com/floreabogdan/nftably/internal/store"
)

// listsync.go pushes automated changes to a named list — the block API and feed
// refreshes — straight into the live kernel set, so a block or refreshed feed takes
// effect immediately instead of waiting for a manual apply and piling up as pending
// changes. It re-points the applied baseline so the Changes page stays in sync, and
// steps aside — leaving the change to the normal pending flow — whenever it can't
// safely mutate the kernel.

// modelRender renders the current model. Callers capture it BEFORE an automated set
// change, so pushSetElements can tell whether the model was in sync with the kernel.
func (s *Server) modelRender() string {
	m, err := s.loadModel()
	if err != nil {
		return ""
	}
	return nftconf.Config(m)
}

// pushSetElements applies added/removed CIDRs for the list named listName to the
// live kernel set(s) it renders into (in one atomic op per set), then re-points the
// applied baseline. It acts only when the model matched what was applied before the
// change (priorRender) and no apply is armed — so it never partially applies a model
// carrying other pending edits, and never touches the kernel mid apply-window.
// Returns whether it pushed anything to the kernel.
func (s *Server) pushSetElements(ctx context.Context, priorRender, listName string, add, del []string) bool {
	if len(add) == 0 && len(del) == 0 {
		return false
	}
	// Serialise with the apply pipeline: both mutate the live kernel tables, and a
	// push landing mid-apply (during a delete+recreate) would be lost or error.
	s.applyMu.Lock()
	defer s.applyMu.Unlock()

	// Only sync when the model was in sync with the kernel before this change, so
	// the change is the sole delta and the new render is a correct baseline.
	applied, ok, err := s.store.LatestAppliedConfig()
	if err != nil || !ok || applied != priorRender {
		return false
	}
	if _, pending, perr := s.store.GetPendingApply(); perr != nil || pending {
		return false
	}
	m, err := s.loadModel()
	if err != nil {
		return false
	}

	pushed, allOK := false, true
	record := func(err error) {
		if err != nil {
			allOK = false
		} else {
			pushed = true
		}
	}
	for _, t := range m.Tables {
		names := map[string]bool{}
		for _, set := range t.Sets {
			names[set.Name] = true
		}
		for set, els := range groupBySet(names, listName, del) {
			record(s.nft.DeleteSetElements(ctx, t.Family, t.Name, set, els))
		}
		for set, els := range groupBySet(names, listName, add) {
			record(s.nft.AddSetElements(ctx, t.Family, t.Name, set, els))
		}
	}
	if !pushed {
		return false // nothing matched a live set — leave the change to the pending flow
	}
	// The kernel changed, so re-record the drift fingerprint against the new live
	// state — this is nftably's own change, not out-of-band drift.
	defer s.recordAppliedFingerprint(ctx)

	if !allOK {
		// A push partially failed: the live set is somewhere between the old and new
		// model. Do NOT claim in-sync — leave the applied config baseline so the full
		// delta still shows as a pending change for a normal apply to reconcile.
		s.log.Warn("incremental set sync partially failed — leaving the change pending", "list", listName)
		return false
	}
	// Every push landed — re-point the diff baseline so the Changes page reads in sync.
	if err := s.store.UpdateLatestAppliedConfig(nftconf.Config(m)); err != nil {
		s.log.Warn("could not re-point applied config after set sync", "error", err)
		return false
	}
	return true
}

// groupBySet buckets CIDRs by the set they belong to for list listName — "<list>4"
// for IPv4, "<list>6" for IPv6 — keeping only sets that exist among names.
func groupBySet(names map[string]bool, listName string, cidrs []string) map[string][]string {
	out := map[string][]string{}
	for _, c := range cidrs {
		p, err := store.EntryPrefix(c)
		if err != nil {
			continue
		}
		suffix := "6"
		if p.Addr().Is4() {
			suffix = "4"
		}
		if set := listName + suffix; names[set] {
			out[set] = append(out[set], c)
		}
	}
	return out
}

// listEntryDelta returns the CIDRs added and removed between two entry snapshots,
// comparing their normalized forms so a feed refresh syncs only what changed.
func listEntryDelta(before, after []store.ListEntry) (add, del []string) {
	beforeSet := map[string]bool{}
	for _, e := range before {
		beforeSet[e.CIDR] = true
	}
	afterSet := map[string]bool{}
	for _, e := range after {
		afterSet[e.CIDR] = true
		if !beforeSet[e.CIDR] {
			add = append(add, e.CIDR)
		}
	}
	for _, e := range before {
		if !afterSet[e.CIDR] {
			del = append(del, e.CIDR)
		}
	}
	return add, del
}
