package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"

	nftconf "github.com/floreabogdan/nftably/internal/render"
	"github.com/floreabogdan/nftably/internal/store"
)

// drift.go detects when the live kernel firewall no longer matches what nftably
// last applied — someone edited rules with `nft` directly, or loaded a
// hand-written nftables.conf. nftably fingerprints its owned tables at confirm
// time, and the alert poller compares the live fingerprint against it.

// normalizeTableText reduces one `nft list table` dump to the stable, comparable
// form shared with the Changes diff — see render.CanonicalizeNftText, which drops
// volatile counters, kernel handles and dynamic-set runtime, and collapses and
// sorts set elements. Two dumps of the same ruleset then compare equal, so the
// drift poller never cries wolf on a counter that merely ticked up.
func normalizeTableText(s string) string {
	return nftconf.CanonicalizeNftText(s)
}

// liveOwnedFingerprint reads every table nftably's ledger says it applied and
// returns a stable hash of their live content (counters/handles removed).
// hasOwned is false when the ledger is empty (nothing applied yet), in which
// case drift is not meaningful.
func (s *Server) liveOwnedFingerprint(ctx context.Context) (fp string, hasOwned bool, err error) {
	owned, err := s.store.GetAppliedTables()
	if err != nil {
		return "", false, err
	}
	if len(owned) == 0 {
		return "", false, nil
	}
	// Stable order so the hash doesn't depend on ledger ordering.
	refs := append([]store.TableRef(nil), owned...)
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Family != refs[j].Family {
			return refs[i].Family < refs[j].Family
		}
		return refs[i].Name < refs[j].Name
	})
	h := sha256.New()
	for _, ref := range refs {
		text, exists, terr := s.nft.Table(ctx, ref.Family, ref.Name)
		if terr != nil {
			return "", true, terr
		}
		h.Write([]byte(ref.Family + " " + ref.Name + "\n"))
		if exists {
			h.Write([]byte(normalizeTableText(text)))
		} else {
			// A table nftably applied was deleted out of band — that is drift too.
			h.Write([]byte("<missing>\n"))
		}
	}
	return hex.EncodeToString(h.Sum(nil)), true, nil
}

// recordAppliedFingerprint captures the live fingerprint as the drift baseline —
// called after a confirmed apply, once the kernel holds the intended state.
func (s *Server) recordAppliedFingerprint(ctx context.Context) {
	fp, ok, err := s.liveOwnedFingerprint(ctx)
	if err != nil || !ok {
		return
	}
	if err := s.store.SaveAppliedFingerprint(fp); err != nil {
		s.log.Warn("could not record applied fingerprint", "error", err)
		return
	}
	s.setDrifted(false)
}

// checkDrift compares the live fingerprint to the recorded baseline and updates
// the cached drift flag. It alerts only on a transition into drift, so the
// operator hears about it once rather than every poll tick.
func (s *Server) checkDrift(ctx context.Context, st *alertPollState) {
	baseline, err := s.store.GetAppliedFingerprint()
	if err != nil || baseline == "" {
		return // nothing applied yet — drift is not meaningful
	}
	live, ok, err := s.liveOwnedFingerprint(ctx)
	if err != nil || !ok {
		return
	}
	drifted := live != baseline
	s.setDrifted(drifted)
	if drifted && !st.drifted {
		s.notifier.Notify(store.AlertConfigDrift, "",
			"The live firewall no longer matches what nftably last applied — it was changed outside nftably.")
	}
	st.drifted = drifted
}
