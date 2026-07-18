package simulate

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/floreabogdan/nftably/internal/nftcat"
	nftconf "github.com/floreabogdan/nftably/internal/render"
	"github.com/floreabogdan/nftably/internal/store"
)

// priorityValue maps a base-chain priority (a keyword, a keyword±offset, or a
// signed integer) to nft's numeric value, so chains run in the right order.
// Unknown input sorts as 0 (the filter default).
func priorityValue(p string) int {
	keywords := map[string]int{
		"raw": -300, "mangle": -150, "dstnat": -100, "filter": 0,
		"security": 50, "srcnat": 100, "out": 100,
	}
	p = strings.TrimSpace(p)
	if n, err := strconv.Atoi(p); err == nil {
		return n
	}
	// "filter + 10" / "srcnat - 5"
	for _, sign := range []string{"+", "-"} {
		if kw, rest, ok := strings.Cut(p, sign); ok {
			base, known := keywords[strings.TrimSpace(kw)]
			if off, err := strconv.Atoi(strings.TrimSpace(rest)); known && err == nil {
				if sign == "-" {
					return base - off
				}
				return base + off
			}
		}
	}
	if v, ok := keywords[p]; ok {
		return v
	}
	return 0
}

// findChain returns a chain by name within a table.
func findChain(t nftconf.TableTree, name string) (nftconf.ChainTree, bool) {
	for _, c := range t.Chains {
		if c.Name == name {
			return c, true
		}
	}
	return nftconf.ChainTree{}, false
}

// ruleVerdict returns the verdict a matched rule takes: a terminal verdict
// (accept/drop/reject/return), a jump/goto with its target, or "" with a note
// when the rule only has non-deciding actions (log/counter/mark/nat) so
// evaluation should continue.
func ruleVerdict(r store.ChainRule) (verdict, target, note string) {
	var notes []string
	for _, st := range r.Statements {
		switch st.Key {
		case "accept", "drop", "reject", "return", "continue":
			return st.Key, "", ""
		case "jump", "goto":
			return st.Key, jumpTarget(st.Params), ""
		default:
			notes = append(notes, st.Key)
		}
	}
	return "", "", "non-deciding: " + strings.Join(notes, ", ")
}

// jumpTarget pulls the target chain name out of a jump/goto statement's params.
func jumpTarget(params string) string {
	return strings.TrimSpace(nftconf.DecodeParams(params)["target"])
}

// matchOne evaluates a single condition against the packet, three-valued.
func (e *eval) matchOne(m store.RuleMatch) matchResult {
	p := e.pkt
	neg := m.Op == "!="
	// affirm turns a raw "does the value contain this" into the match result,
	// honouring negation.
	affirm := func(hit matchResult) matchResult {
		if hit == unknown || !neg {
			return hit
		}
		if hit == yes {
			return no
		}
		return yes
	}

	switch m.Key {
	case "meta.iifname":
		if p.Iif == "" {
			return unknown
		}
		return affirm(ifaceIn(p.Iif, m.Value))
	case "meta.oifname":
		if p.Oif == "" {
			return unknown
		}
		return affirm(ifaceIn(p.Oif, m.Value))
	case "ip.saddr":
		return affirm(addrIn(p.Src, false, m.Value, e.table))
	case "ip.daddr":
		return affirm(addrIn(p.Dst, false, m.Value, e.table))
	case "ip6.saddr":
		return affirm(addrIn(p.Src, true, m.Value, e.table))
	case "ip6.daddr":
		return affirm(addrIn(p.Dst, true, m.Value, e.table))
	case "meta.l4proto":
		if p.Proto == "" {
			return unknown
		}
		return affirm(tokenIn(p.Proto, m.Value))
	case "tcp.dport":
		return affirm(portMatch(p.Proto, "tcp", p.DPort, m))
	case "tcp.sport":
		return affirm(portMatch(p.Proto, "tcp", p.SPort, m))
	case "udp.dport":
		return affirm(portMatch(p.Proto, "udp", p.DPort, m))
	case "udp.sport":
		return affirm(portMatch(p.Proto, "udp", p.SPort, m))
	case "ct.state":
		if p.CtState == "" {
			return unknown
		}
		return affirm(tokenIn(p.CtState, m.Value))
	default:
		return unknown // a condition the simulator does not model
	}
}

// portMatch checks a port against a rule, first requiring the packet's protocol
// to be the one the match implies (a tcp.dport can't match a udp packet).
func portMatch(pktProto, matchProto string, port int, m store.RuleMatch) matchResult {
	if pktProto == "" || port == 0 {
		return unknown
	}
	if pktProto != matchProto {
		return no
	}
	// Comparison operators on a single numeric value.
	switch m.Op {
	case "<", ">", "<=", ">=":
		n, err := strconv.Atoi(strings.TrimSpace(m.Value))
		if err != nil {
			return unknown
		}
		switch m.Op {
		case "<":
			return boolMR(port < n)
		case ">":
			return boolMR(port > n)
		case "<=":
			return boolMR(port <= n)
		default:
			return boolMR(port >= n)
		}
	}
	// == / != membership; the caller's affirm() applies any negation, so report
	// the plain "is the port in the value" result here.
	return portInValue(m.Value, port)
}

// addrIn reports whether addr is in a value that is a single address, a CIDR, a
// range, a comma list, or an @set reference resolved from the table's sets. want6
// selects the family the match applies to (an ip match never matches a v6
// packet, and vice-versa).
func addrIn(addr netip.Addr, want6 bool, value string, table nftconf.TableTree) matchResult {
	if !addr.IsValid() {
		return unknown
	}
	if addr.Is6() != want6 {
		return no // family mismatch: an ip match on a v6 packet cannot hold
	}
	for _, tok := range splitTokens(value) {
		if name, ok := strings.CutPrefix(tok, "@"); ok {
			switch setContains(table, name, addr) {
			case yes:
				return yes
			case unknown:
				return unknown
			}
			continue
		}
		if r := addrTokenContains(tok, addr); r == yes || r == unknown {
			return r
		}
	}
	return no
}

// addrTokenContains matches a single non-set token: an address, a CIDR, or an
// a-b range.
func addrTokenContains(tok string, addr netip.Addr) matchResult {
	if lo, hi, ok := strings.Cut(tok, "-"); ok && strings.Contains(tok, "-") && !strings.Contains(tok, "/") {
		a, err1 := netip.ParseAddr(strings.TrimSpace(lo))
		b, err2 := netip.ParseAddr(strings.TrimSpace(hi))
		if err1 != nil || err2 != nil {
			return unknown
		}
		if addr.Compare(a) >= 0 && addr.Compare(b) <= 0 {
			return yes
		}
		return no
	}
	if pfx, err := netip.ParsePrefix(tok); err == nil {
		return boolMR(pfx.Contains(addr))
	}
	if a, err := netip.ParseAddr(tok); err == nil {
		return boolMR(a == addr)
	}
	return unknown
}

// setContains resolves a named set on the table and tests membership. The set
// name carries a family suffix (office4 / office6); its elements are the list's
// entries for that family.
func setContains(table nftconf.TableTree, setName string, addr netip.Addr) matchResult {
	for _, s := range table.Sets {
		if s.Name != setName {
			continue
		}
		for _, el := range s.Elements {
			if r := addrTokenContains(el, addr); r == yes {
				return yes
			}
		}
		return no // the set exists but does not contain the address
	}
	return unknown // the set is not resolved (dangling or empty) — can't decide
}

// ifaceIn reports whether name is one of the (possibly quoted) interface tokens.
func ifaceIn(name, value string) matchResult {
	for _, tok := range splitTokens(value) {
		if strings.Trim(tok, `"`) == name {
			return yes
		}
	}
	return no
}

// tokenIn reports whether tok appears in a comma/space list value.
func tokenIn(tok, value string) matchResult {
	for _, t := range splitTokens(value) {
		if t == tok {
			return yes
		}
	}
	return no
}

// portInValue reports whether port is in a value: a comma list of single ports
// and a-b ranges.
func portInValue(value string, port int) matchResult {
	for _, tok := range splitTokens(value) {
		if lo, hi, ok := strings.Cut(tok, "-"); ok {
			a, err1 := strconv.Atoi(strings.TrimSpace(lo))
			b, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 == nil && err2 == nil && port >= a && port <= b {
				return yes
			}
			continue
		}
		if n, err := strconv.Atoi(tok); err == nil && n == port {
			return yes
		}
	}
	return no
}

// splitTokens splits a stored value into its element tokens (comma/space
// separated, set braces stripped).
func splitTokens(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '{' || r == '}'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// describeMiss explains, in plain terms, why a condition did not hold.
func describeMiss(m store.RuleMatch) string {
	label := m.Key
	if k, ok := nftcat.MatchByKey(m.Key); ok {
		label = k.Label
	}
	op := "requires"
	if m.Op == "!=" {
		op = "excludes"
	}
	return label + " " + op + " " + m.Value + " — the packet does not qualify"
}

func boolMR(b bool) matchResult {
	if b {
		return yes
	}
	return no
}
