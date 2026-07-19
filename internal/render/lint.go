package render

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/floreabogdan/nftably/internal/nftcat"
	"github.com/floreabogdan/nftably/internal/store"
)

// Lint returns self-lockout warnings for a candidate model — never errors. The
// armed auto-revert is the hard safety net; these are the friendly heads-up
// before it has to fire. The checks are deliberately conservative: they warn
// when a drop-policy input chain has no plausible way in for the operator's own
// SSH or the nftably UI, and when a rule references something that will not
// render.
func Lint(m Model, listenAddr string) []string {
	var warns []string

	uiPort := listenPort(listenAddr)

	// Gather every base chain that filters inbound traffic to this host with a
	// default-drop policy — those are the ones that can lock you out.
	var dropInputs []ChainTree
	for _, t := range m.Tables {
		for _, c := range t.Chains {
			if c.IsBase() && c.Hook == "input" && c.ChainType != "nat" && c.Policy == "drop" {
				dropInputs = append(dropInputs, c)
			}
		}
	}

	if len(dropInputs) > 0 {
		// If nothing anywhere in the drop-policy input chains plausibly lets the
		// management connection back in, warn. We look across all such chains
		// together — one may accept SSH, another the UI.
		var allRules []store.ChainRule
		for _, c := range dropInputs {
			allRules = append(allRules, c.Rules...)
		}
		if uiPort > 0 && !acceptsPort(allRules, uiPort) && !acceptsEstablished(allRules) {
			warns = append(warns, fmt.Sprintf(
				"An input chain drops by default and nothing accepts the nftably UI port (%d) — applying this could cut off this web session. The auto-revert would bring it back, but add an allow rule to be safe.", uiPort))
		}
		if !acceptsPort(allRules, 22) && !acceptsEstablished(allRules) {
			warns = append(warns,
				"An input chain drops by default and nothing accepts TCP 22 (SSH) — if you manage this box over SSH, add an allow rule so you don't get locked out.")
		}
	}

	// The reply path: a base output chain that drops by default cuts off the
	// return traffic of the operator's own SSH/UI session unless something lets
	// established/related connections back out. This is just as much of a lockout
	// as a drop-policy input chain, and easy to miss.
	if rules, hit := dropChainRules(m, "output"); hit && !acceptsEstablished(rules) {
		warns = append(warns,
			"An output chain drops by default and nothing accepts established/related traffic — this would drop the replies to your own SSH/UI session and cut you off. Add an `established, related accept` rule to the output chain.")
	}

	// A forward chain that drops by default only reaches the operator if they
	// manage this box through it (a routed management network). Warn softly.
	if rules, hit := dropChainRules(m, "forward"); hit && !acceptsEstablished(rules) {
		warns = append(warns,
			"A forward chain drops by default and nothing accepts established/related traffic — if you reach this box through a routed network, that path could be cut. Add an allow rule if so.")
	}

	// Rules that reference an unknown knob will silently not render.
	for _, t := range m.Tables {
		for _, c := range t.Chains {
			for _, r := range c.Rules {
				if !r.Enabled {
					continue
				}
				for _, mt := range r.Matches {
					if _, ok := nftcat.MatchByKey(mt.Key); !ok && strings.TrimSpace(mt.Key) != "" {
						warns = append(warns, fmt.Sprintf("A rule in chain %q uses an unknown condition (%s) and will not be applied.", c.Name, mt.Key))
					}
				}
				for _, st := range r.Statements {
					if _, ok := nftcat.StatementByKey(st.Key); !ok && strings.TrimSpace(st.Key) != "" {
						warns = append(warns, fmt.Sprintf("A rule in chain %q uses an unknown action (%s) and will not be applied.", c.Name, st.Key))
					}
				}
				// A NAT action that maps to a port needs the rule to have matched a
				// transport protocol first; nft rejects the port otherwise, with a
				// cryptic "transport protocol mapping is only valid after transport
				// protocol match". Easy to miss when hand-building a port-forward.
				if natMapsPort(r) && !hasTransportMatch(r) {
					warns = append(warns, fmt.Sprintf(
						"A rule in chain %q forwards to a port (DNAT/SNAT/redirect) but doesn't match a transport protocol first — add a TCP or UDP port condition (e.g. tcp dport 443) on the same rule, or nft will reject the config.", c.Name))
				}
			}
		}
	}

	return warns
}

// natMapsPort reports whether a rule carries a dnat/snat/redirect action that
// maps to a specific port (an empty port needs no transport match).
func natMapsPort(r store.ChainRule) bool {
	for _, st := range r.Statements {
		switch st.Key {
		case "dnat", "snat", "redirect":
			if strings.TrimSpace(DecodeParams(st.Params)["port"]) != "" {
				return true
			}
		}
	}
	return false
}

// hasTransportMatch reports whether a rule matches a transport protocol — either
// a tcp/udp field, or meta l4proto tcp/udp — which nft needs before a port map.
func hasTransportMatch(r store.ChainRule) bool {
	for _, m := range r.Matches {
		if strings.HasPrefix(m.Key, "tcp.") || strings.HasPrefix(m.Key, "udp.") {
			return true
		}
		if m.Key == "meta.l4proto" && (strings.Contains(m.Value, "tcp") || strings.Contains(m.Value, "udp")) {
			return true
		}
	}
	return false
}

// dropChainRules gathers the rules of every base chain on the given hook that
// filters with a default-drop policy, and reports whether any such chain exists.
func dropChainRules(m Model, hook string) ([]store.ChainRule, bool) {
	var rules []store.ChainRule
	found := false
	for _, t := range m.Tables {
		for _, c := range t.Chains {
			if c.IsBase() && c.Hook == hook && c.ChainType != "nat" && c.Policy == "drop" {
				found = true
				rules = append(rules, c.Rules...)
			}
		}
	}
	return rules, found
}

// acceptsEstablished reports whether some enabled rule accepts established/
// related connections — the classic "keep my own sessions alive" allow that, on
// its own, keeps an in-progress SSH/UI connection working under a drop policy.
func acceptsEstablished(rules []store.ChainRule) bool {
	for _, r := range rules {
		if !r.Enabled || !hasAccept(r) {
			continue
		}
		for _, m := range r.Matches {
			if m.Key == "ct.state" && strings.Contains(m.Value, "established") {
				return true
			}
		}
	}
	return false
}

// acceptsPort reports whether some enabled rule accepts TCP traffic to port —
// either unconditionally (an accept with no port condition) or with a tcp.dport
// condition that covers it.
func acceptsPort(rules []store.ChainRule, port int) bool {
	for _, r := range rules {
		if !r.Enabled || !hasAccept(r) {
			continue
		}
		portMatched, portMentioned := false, false
		blockedByOtherProto := false
		for _, m := range r.Matches {
			switch m.Key {
			case "tcp.dport":
				portMentioned = true
				if m.Op == "==" && portInValue(m.Value, port) {
					portMatched = true
				}
			case "udp.dport":
				// A rule pinned to a UDP port can't be the one that lets TCP
				// SSH/UI in.
				blockedByOtherProto = true
			case "meta.l4proto":
				if m.Op == "==" && !strings.Contains(m.Value, "tcp") {
					blockedByOtherProto = true
				}
			}
		}
		if blockedByOtherProto {
			continue
		}
		if portMatched || !portMentioned {
			return true
		}
	}
	return false
}

// hasAccept reports whether a rule's actions include a plain accept.
func hasAccept(r store.ChainRule) bool {
	for _, st := range r.Statements {
		if st.Key == "accept" {
			return true
		}
	}
	return false
}

// portInValue reports whether port falls inside a stored port value — a comma
// list of single ports and a-b ranges.
func portInValue(value string, port int) bool {
	for _, tok := range strings.Split(value, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(tok, "-"); ok {
			a, err1 := strconv.Atoi(strings.TrimSpace(lo))
			b, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 == nil && err2 == nil && port >= a && port <= b {
				return true
			}
			continue
		}
		if n, err := strconv.Atoi(tok); err == nil && n == port {
			return true
		}
	}
	return false
}

// listenPort extracts the TCP port from a listen address like ":8080" or
// "0.0.0.0:8080"; 0 when it cannot be determined.
func listenPort(addr string) int {
	_, portStr, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(portStr)
	if err != nil {
		return 0
	}
	return n
}
