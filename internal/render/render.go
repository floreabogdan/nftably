// Package render turns nftably's rule model into nftables config text — the
// `table inet nftably` block that M3's apply pipeline will load with `nft -f`
// and that the /changes page previews and diffs today.
//
// The output is deliberately written in `nft list` output style (tabs, one rule
// per line, bare values for single-element sets) so that diffing it against the
// live table is quiet when nothing changed.
package render

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/floreabogdan/nftably/internal/store"
)

// TableName is the one table nftably owns. Everything nftably renders lives in
// `table inet nftably`; tables it does not own are never touched.
const TableName = "nftably"

// Config renders the full managed table: chain declaration, the always-on
// baseline rules, then the operator's enabled rules in order.
//
// The baseline encodes the footgun protection this milestone can already give:
// loopback and established/related always accepted (a policy-drop table that
// drops the operator's own SSH return traffic would lock them out on apply, the
// classic mistake M3's lint will refuse outright), and the ICMPv6 that IPv6
// needs to function (ND, RA, PMTUD) always allowed.
func Config(fw store.Firewall, rules []store.Rule) string {
	policy := fw.InputPolicy
	if policy != "accept" {
		policy = "drop"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n", TableName)
	b.WriteString("\tchain input {\n")
	fmt.Fprintf(&b, "\t\ttype filter hook input priority filter; policy %s;\n", policy)

	// Baseline: order matters — invalid is dropped before established/related
	// is accepted, and both come before any operator rule.
	b.WriteString("\t\tiif \"lo\" accept comment \"nftably:baseline loopback\"\n")
	b.WriteString("\t\tct state invalid drop comment \"nftably:baseline invalid\"\n")
	b.WriteString("\t\tct state established,related accept comment \"nftably:baseline conntrack\"\n")
	b.WriteString("\t\ticmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, echo-request, echo-reply, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept comment \"nftably:baseline icmpv6\"\n")
	b.WriteString("\t\ticmp type { destination-unreachable, echo-request, echo-reply, time-exceeded, parameter-problem } accept comment \"nftably:baseline icmp\"\n")

	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		for _, line := range RuleLines(r) {
			b.WriteString("\t\t")
			b.WriteString(line)
			b.WriteString("\n")
		}
	}

	b.WriteString("\t}\n")
	b.WriteString("}\n")
	return b.String()
}

// RuleLines renders one model rule to nft rule syntax (without indentation).
// A rule whose sources mix address families becomes two lines, because in the
// inet family `ip saddr` matches only IPv4 packets and `ip6 saddr` only IPv6 —
// a single line could not match both.
func RuleLines(r store.Rule) []string {
	prefixes, _ := store.ParseSources(r.SAddrs)
	var v4, v6 []string
	for _, p := range prefixes {
		if p.Addr().Is4() {
			v4 = append(v4, prefixStr(p))
		} else {
			v6 = append(v6, prefixStr(p))
		}
	}

	var out []string
	switch {
	case len(v4) == 0 && len(v6) == 0:
		out = append(out, ruleLine(r, "", nil))
	default:
		if len(v4) > 0 {
			out = append(out, ruleLine(r, "ip saddr", v4))
		}
		if len(v6) > 0 {
			out = append(out, ruleLine(r, "ip6 saddr", v6))
		}
	}
	return out
}

// prefixStr prints a host prefix as a bare address (10.0.0.5, not 10.0.0.5/32),
// matching how `nft list` echoes it back.
func prefixStr(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return p.String()
}

func ruleLine(r store.Rule, saddrKey string, saddrs []string) string {
	var parts []string
	if r.IIf != "" {
		parts = append(parts, fmt.Sprintf("iifname %q", r.IIf))
	}
	if saddrKey != "" {
		parts = append(parts, saddrKey+" "+setExpr(saddrs))
	}

	ports, _ := store.ParsePorts(r.DPorts)
	switch {
	case (r.Proto == "tcp" || r.Proto == "udp") && len(ports) > 0:
		parts = append(parts, r.Proto+" dport "+setExpr(ports))
	case r.Proto == "tcp" || r.Proto == "udp":
		parts = append(parts, "meta l4proto "+r.Proto)
	}

	parts = append(parts, r.Action)
	if r.Name != "" {
		parts = append(parts, fmt.Sprintf("comment %q", "nftably: "+r.Name))
	}
	return strings.Join(parts, " ")
}

// setExpr prints one value bare and several as an anonymous set, the way
// `nft list` does.
func setExpr(vals []string) string {
	if len(vals) == 1 {
		return vals[0]
	}
	return "{ " + strings.Join(vals, ", ") + " }"
}
