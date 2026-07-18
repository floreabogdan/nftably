package web

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/floreabogdan/nftably/internal/store"
)

// One-click country block: from a country you see in the Connections view, build
// a GeoIP-sourced set of its CIDRs and drop it early on the input chain. It only
// touches the model — the armed apply still gates the kernel.

var blockISORe = regexp.MustCompile(`^[A-Za-z]{2}$`)

func (s *Server) handleBlockCountry(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	back := "/connections"
	iso := strings.ToUpper(strings.TrimSpace(r.FormValue("iso")))
	if !blockISORe.MatchString(iso) {
		redirectMsg(w, r, back, "err", "That doesn't look like a country to block.")
		return
	}
	if s.effectiveGeoIPPath() == "" {
		redirectMsg(w, r, back, "err", "Blocking a country needs a GeoIP database — set one under Settings → GeoIP first.")
		return
	}
	chainID, ok := s.primaryInputChainID()
	if !ok {
		redirectMsg(w, r, back, "err", "There's no input chain to add a drop rule to — apply a preset first.")
		return
	}

	// Ensure the GeoIP-sourced set for this country. It is a plain address group
	// (not a block-role list): the drop rule below does the blocking, and a
	// role-block list of a whole country would slow the Connections view's
	// per-row "is this blocked?" check to a crawl.
	name := "blk_" + strings.ToLower(iso)
	list, err := s.store.GetListByName(name)
	if err == store.ErrNotFound {
		id, cerr := s.store.CreateList(store.IPList{
			Name: name, Source: store.SourceGeoIP, SourceArg: iso, AutoRefresh: true,
			Note: "Country " + iso + ", blocked from the Connections view (GeoIP).",
		})
		if cerr != nil {
			redirectMsg(w, r, back, "err", "Could not create the country set: "+cerr.Error())
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
		n, rerr := s.doRefresh(ctx, id)
		cancel()
		if rerr != nil || n == 0 {
			msg := fmt.Sprintf("The GeoIP database has no addresses for %s — nothing was blocked.", iso)
			if rerr != nil {
				msg = "Could not build the set for " + iso + ": " + rerr.Error()
			}
			redirectMsg(w, r, back, "err", msg)
			return
		}
		list, _ = s.store.GetList(id)
	} else if err != nil {
		s.serverError(w, "get country list", err)
		return
	}

	added, err := s.ensureCountryDropRules(chainID, name)
	if err != nil {
		redirectMsg(w, r, back, "err", "Could not add the drop rules: "+err.Error())
		return
	}
	if added == 0 {
		redirectMsg(w, r, back, "err", fmt.Sprintf("%s (@%s) is already blocked on the input chain.", iso, name))
		return
	}
	s.audit(r, fmt.Sprintf("blocked country %s via set @%s (%d entries)", iso, name, s.entryCount(list.ID)))
	http.Redirect(w, r, "/changes", http.StatusSeeOther)
}

// ensureCountryDropRules adds early "ip[6] saddr @<name>N drop" rules for the two
// families to the chain, skipping either that already exists. Returns how many
// it added (0 = already fully blocked).
func (s *Server) ensureCountryDropRules(chainID int64, name string) (int, error) {
	existing, err := s.store.ListChainRules(chainID)
	if err != nil {
		return 0, err
	}
	added := 0
	for _, fam := range []struct{ key, set string }{
		{"ip.saddr", "@" + name + "4"},
		{"ip6.saddr", "@" + name + "6"},
	} {
		if dropRuleExists(existing, fam.key, fam.set) {
			continue
		}
		rule := store.ChainRule{
			ChainID:    chainID,
			Enabled:    true,
			Comment:    "block " + name,
			Matches:    []store.RuleMatch{{Key: fam.key, Op: "==", Value: fam.set}},
			Statements: []store.RuleStatement{{Key: "drop", Params: "{}"}},
		}
		if _, err := s.store.CreateChainRuleAtStart(rule); err != nil {
			return added, err
		}
		added++
	}
	return added, nil
}

// dropRuleExists reports whether a rule already drops setRef via matchKey.
func dropRuleExists(rules []store.ChainRule, matchKey, setRef string) bool {
	for _, r := range rules {
		hasMatch, hasDrop := false, false
		for _, m := range r.Matches {
			if m.Key == matchKey && strings.TrimSpace(m.Value) == setRef {
				hasMatch = true
			}
		}
		for _, st := range r.Statements {
			if st.Key == "drop" {
				hasDrop = true
			}
		}
		if hasMatch && hasDrop {
			return true
		}
	}
	return false
}

// entryCount is a best-effort count of a list's entries, for the audit line.
func (s *Server) entryCount(listID int64) int {
	if e, err := s.store.ListEntries(listID); err == nil {
		return len(e)
	}
	return 0
}
