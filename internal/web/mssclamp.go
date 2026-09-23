package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/floreabogdan/nftably/internal/store"
)

// mssclamp.go is the MSS-clamp wizard: it turns "the path is 1448 bytes" into
// the connection-opening rules that lower TCP's advertised segment size to fit,
// which is the cure for a link where big packets vanish — a VPN, PPPoE, or a
// tunnel on the return path. Model-only, like every other wizard: the operator
// reviews it on /changes and applies it behind the armed auto-revert.
//
// Two details this gets right that a hand-written rule usually doesn't:
//
//   - The flag match is `tcp flags & syn == syn`, not `tcp flags syn`. The latter
//     compares the whole flags byte, so it matches a bare SYN and misses the
//     SYN+ACK — and the MSS in the SYN+ACK is what constrains the far end when a
//     connection was opened *towards* this box.
//   - The size differs by family: an IPv6 header is 20 bytes larger than an IPv4
//     one, so the same path MTU yields two different MSS values. Given the path
//     MTU, the wizard does that arithmetic and splits the rule on `meta nfproto`.

// MSS clamping arithmetic and the bounds we accept. The IPv4 overhead is a
// 20-byte IP header plus a 20-byte TCP header; IPv6's base header is 40.
const (
	mssOverhead4 = 40
	mssOverhead6 = 60
	// Below the IPv6 minimum MTU there is nothing sensible to clamp to, and a
	// jumbo path tops out around 9216 on real hardware.
	minPathMTU = 1280
	maxPathMTU = 9216
	// A clamp far below the TCP default of 536 is a mistake, not a tuning.
	minMSS = 536
	maxMSS = maxPathMTU - mssOverhead4
)

// clampTag marks every rule the wizard writes, so they can be found with the
// rule filter (and told apart from hand-authored clamps).
const clampTag = "mss-clamp"

func (s *Server) handleMSSClamp(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	hooks := r.Form["hook"]
	if len(hooks) == 0 {
		redirectErr(w, r, "/firewall", "Pick at least one chain to clamp in (forward, output, or both).")
		return
	}
	for _, h := range hooks {
		if h != "forward" && h != "output" {
			redirectErr(w, r, "/firewall", "MSS clamping applies to the forward and output chains only.")
			return
		}
	}

	iface := strings.TrimSpace(r.FormValue("iface"))
	if iface != "" && !pfIfaceRe.MatchString(iface) {
		redirectErr(w, r, "/firewall", "Interface name has invalid characters.")
		return
	}

	sizes, label, err := clampSizes(r.FormValue("mode"), r.FormValue("pmtu"), r.FormValue("mss"))
	if err != nil {
		redirectErr(w, r, "/firewall", err.Error())
		return
	}

	var built []string
	for _, hook := range hooks {
		chain, family, err := s.clampChain(hook)
		if err != nil {
			redirectErr(w, r, "/firewall", "Could not prepare the "+hook+" chain: "+err.Error())
			return
		}
		// Re-running the wizard reconfigures the clamp rather than stacking a second
		// one on top: its own previous rules (the ones it tagged) come out first.
		if err := s.dropExistingClamps(chain); err != nil {
			redirectErr(w, r, "/firewall", "Could not replace the existing clamp: "+err.Error())
			return
		}
		n, err := s.addClampRules(chain, family, iface, sizes)
		if err != nil {
			redirectErr(w, r, "/firewall", "Could not add the clamp rule: "+err.Error())
			return
		}
		built = append(built, fmt.Sprintf("%d in %s", n, hook))
	}

	s.audit(r, "added MSS clamping ("+label+"): "+strings.Join(built, ", "))
	http.Redirect(w, r, "/changes", http.StatusSeeOther)
}

// clampSize is one rule's worth of clamp: the family to restrict it to (empty
// for both) and the MSS to set (or "rt mtu").
type clampSize struct {
	nfproto string // "ipv4" | "ipv6" | "" for a family-agnostic rule
	size    string // an MSS in bytes, or "rt mtu"
	note    string // what goes in the rule's comment
}

// clampSizes turns the wizard's mode into the rules to write, plus a one-line
// description for the audit log.
func clampSizes(mode, pmtu, mss string) ([]clampSize, string, error) {
	switch mode {
	case "auto":
		// `rt mtu` is the route's TCP MSS — the kernel subtracts the right header
		// size for the packet's own family, so one rule covers both. It only works
		// when the constrained link is the one the route points down.
		return []clampSize{{size: "rt mtu", note: "follow the route MTU"}}, "route MTU", nil

	case "pmtu":
		n, err := strconv.Atoi(strings.TrimSpace(pmtu))
		if err != nil || n < minPathMTU || n > maxPathMTU {
			return nil, "", fmt.Errorf("Path MTU must be a whole number between %d (the IPv6 minimum) and %d.", minPathMTU, maxPathMTU)
		}
		return []clampSize{
			{nfproto: "ipv4", size: strconv.Itoa(n - mssOverhead4), note: fmt.Sprintf("IPv4, path MTU %d", n)},
			{nfproto: "ipv6", size: strconv.Itoa(n - mssOverhead6), note: fmt.Sprintf("IPv6, path MTU %d", n)},
		}, fmt.Sprintf("path MTU %d", n), nil

	case "mss":
		n, err := strconv.Atoi(strings.TrimSpace(mss))
		if err != nil || n < minMSS || n > maxMSS {
			return nil, "", fmt.Errorf("MSS must be a whole number between %d and %d.", minMSS, maxMSS)
		}
		return []clampSize{{size: strconv.Itoa(n), note: fmt.Sprintf("MSS %d", n)}}, fmt.Sprintf("MSS %d", n), nil
	}
	return nil, "", fmt.Errorf("Pick how the segment size should be decided.")
}

// addClampRules writes one clamp rule per size into the chain, at the top —
// a clamp below an `accept` never runs, because the accept ends the hook first.
// They go in reverse so they end up in the listed order. A family-specific size
// is skipped in a single-family table, where it would be dead weight.
func (s *Server) addClampRules(chainID int64, family, iface string, sizes []clampSize) (int, error) {
	n := 0
	for i := len(sizes) - 1; i >= 0; i-- {
		sz := sizes[i]
		if !familyCarries(family, sz.nfproto) {
			continue
		}
		var matches []store.RuleMatch
		// A single-family table already gates the family; the qualifier would be
		// redundant there, so only an inet table gets one.
		if sz.nfproto != "" && family == "inet" {
			matches = append(matches, mt("meta.nfproto", sz.nfproto))
		}
		if iface != "" {
			matches = append(matches, mt("meta.oifname", iface))
		}
		// `has` (a masked compare) rather than `==`: this must catch the SYN+ACK of
		// a connection opened towards us, and an ECN-negotiating SYN, not just a
		// bare SYN.
		matches = append(matches, store.RuleMatch{Key: "tcp.flags", Op: "has", Value: "syn"})

		if _, err := s.store.CreateChainRuleAtStart(store.ChainRule{
			ChainID: chainID, Enabled: true, Tags: clampTag,
			Comment:    "MSS clamp — " + sz.note,
			Matches:    matches,
			Statements: []store.RuleStatement{stmtP("tcp.mss.clamp", map[string]string{"size": sz.size})},
		}); err != nil {
			return n, err
		}
		n++
	}
	if n == 0 {
		return 0, fmt.Errorf("nothing to clamp: the chain's table is %s only", family)
	}
	return n, nil
}

// dropExistingClamps removes the wizard's own rules from a chain, so running it
// again replaces the clamp instead of adding a second one below the first (where
// it would be dead — the first clamp has already rewritten the option).
func (s *Server) dropExistingClamps(chainID int64) error {
	rules, err := s.store.ListChainRules(chainID)
	if err != nil {
		return err
	}
	for _, r := range rules {
		if r.Tags != clampTag {
			continue
		}
		if err := s.store.DeleteChainRule(r.ID); err != nil {
			return err
		}
	}
	return nil
}

// familyCarries reports whether a table family can carry traffic of the given
// nfproto ("" meaning both).
func familyCarries(family, nfproto string) bool {
	switch family {
	case "ip":
		return nfproto != "ipv6"
	case "ip6":
		return nfproto != "ipv4"
	}
	return true
}

// clampChain returns a base filter chain on the given hook and its table's
// family, creating an inet filter table and/or an accept-policy chain if the
// model has none. An accept policy is the neutral one: a chain that only clamps
// must not change what gets through.
func (s *Server) clampChain(hook string) (int64, string, error) {
	m, err := s.loadModel()
	if err != nil {
		return 0, "", err
	}
	// Prefer an existing base filter chain on this hook, inet first so the clamp
	// covers both families where it can.
	var fallbackID int64
	var fallbackFamily string
	for _, t := range m.Tables {
		if t.Family != "inet" && t.Family != "ip" && t.Family != "ip6" {
			continue
		}
		for _, c := range t.Chains {
			if !c.IsBase() || c.Hook != hook || c.ChainType != "filter" {
				continue
			}
			if t.Family == "inet" {
				return c.ID, t.Family, nil
			}
			if fallbackID == 0 {
				fallbackID, fallbackFamily = c.ID, t.Family
			}
		}
	}
	if fallbackID != 0 {
		return fallbackID, fallbackFamily, nil
	}

	// No chain on this hook — put one in an existing inet filter table, or make
	// the table too.
	var tableID int64
	taken := map[string]bool{}
	for _, t := range m.Tables {
		if t.Family == "inet" && t.Name == "filter" {
			tableID = t.ID
			for _, c := range t.Chains {
				taken[c.Name] = true
			}
		}
	}
	if tableID == 0 {
		id, err := s.store.CreateTable(store.Table{Family: "inet", Name: "filter", Comment: "Filtering (IPv4 + IPv6)"})
		if err != nil {
			return 0, "", err
		}
		tableID = id
	}
	name := hook
	if taken[name] {
		name = hook + "-mss"
	}
	id, err := s.store.CreateChain(store.Chain{
		TableID: tableID, Name: name, Kind: "base",
		Hook: hook, ChainType: "filter", Priority: "filter", Policy: "accept",
	})
	if err != nil {
		return 0, "", err
	}
	return id, "inet", nil
}
