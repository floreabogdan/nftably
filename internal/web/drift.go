package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"

	"github.com/floreabogdan/nftably/internal/store"
)

// drift.go detects when the live kernel firewall no longer matches what nftably
// last applied — someone edited rules with `nft` directly, or loaded a
// hand-written nftables.conf. nftably fingerprints its owned tables at confirm
// time, and the alert poller compares the live fingerprint against it.

// Volatile parts of `nft list table` output that change without the ruleset
// itself changing: per-rule counters and kernel handle numbers.
var (
	reCounter = regexp.MustCompile(`counter packets \d+ bytes \d+`)
	reHandle  = regexp.MustCompile(`# handle \d+`)
)

// normalizeTableText strips the volatile parts of one `nft list table` dump so
// two dumps of the same ruleset compare equal.
func normalizeTableText(s string) string {
	s = reCounter.ReplaceAllString(s, "counter")
	s = reHandle.ReplaceAllString(s, "")
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimRight(line, " \t")
		if strings.TrimSpace(line) == "" {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
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
