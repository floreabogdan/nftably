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
	"sort"
	"strconv"
	"strings"

	"github.com/floreabogdan/nftably/internal/store"
)

// TableName is the one table nftably owns. Everything nftably renders lives in
// `table inet nftably`; tables it does not own are never touched.
const TableName = "nftably"

// Config renders the full managed table: chain declarations, the always-on
// baseline rules, then the operator's enabled rules in order.
//
// The input baseline encodes the footgun protection: loopback and
// established/related always accepted (a policy-drop table that drops the
// operator's own SSH return traffic would lock them out on apply), and the
// ICMPv6 that IPv6 needs to function (ND, RA, PMTUD) always allowed.
//
// Forwarding — the forward chain, port-forward DNAT and masquerade — renders
// only once fw.WANIface names the upstream interface. On a plain host nothing
// changes: an unasked-for policy-drop forward chain would silently break
// Docker/Incus/VM networking, so its absence is the feature.
func Config(fw store.Firewall, rules []store.Rule, pfs []store.PortForward) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n", TableName)

	b.WriteString("\tchain input {\n")
	fmt.Fprintf(&b, "\t\ttype filter hook input priority filter; policy %s;\n", policyOrDrop(fw.InputPolicy))

	// Baseline: order matters — invalid is dropped before established/related
	// is accepted, and both come before any operator rule.
	b.WriteString("\t\tiif \"lo\" accept comment \"nftably:baseline loopback\"\n")
	b.WriteString("\t\tct state invalid drop comment \"nftably:baseline invalid\"\n")
	b.WriteString("\t\tct state established,related accept comment \"nftably:baseline conntrack\"\n")
	b.WriteString("\t\ticmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, echo-request, echo-reply, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept comment \"nftably:baseline icmpv6\"\n")
	b.WriteString("\t\ticmp type { echo-reply, destination-unreachable, echo-request, time-exceeded, parameter-problem } accept comment \"nftably:baseline icmp\"\n")

	writeRules(&b, rules, "input")
	b.WriteString("\t}\n")

	if fw.WANIface != "" {
		wan := fmt.Sprintf("%q", fw.WANIface)

		// nft list separates chains with a blank line; matching it keeps the
		// post-apply diff quiet.
		b.WriteString("\n\tchain forward {\n")
		fmt.Fprintf(&b, "\t\ttype filter hook forward priority filter; policy %s;\n", policyOrDrop(fw.ForwardPolicy))
		// The forward baseline mirrors the input one, plus the two lines that
		// make a drop policy usable on a router: DNAT'ed flows (port-forwards,
		// whether ours or e.g. Docker's) pass, and inside→outside is open. The
		// lan-wan accept comes AFTER operator rules so a drop rule above it
		// can still cut a specific LAN host or port off from the internet.
		b.WriteString("\t\tct state invalid drop comment \"nftably:baseline invalid\"\n")
		b.WriteString("\t\tct state established,related accept comment \"nftably:baseline conntrack\"\n")
		b.WriteString("\t\tct status dnat accept comment \"nftably:baseline port-forwards\"\n")
		writeRules(&b, rules, "forward")
		fmt.Fprintf(&b, "\t\tiifname != %s oifname %s accept comment \"nftably:baseline lan-wan\"\n", wan, wan)
		b.WriteString("\t}\n")

		var enabled []store.PortForward
		for _, p := range pfs {
			if p.Enabled {
				enabled = append(enabled, p)
			}
		}
		if len(enabled) > 0 {
			b.WriteString("\n\tchain prerouting {\n")
			b.WriteString("\t\ttype nat hook prerouting priority dstnat; policy accept;\n")
			for _, p := range enabled {
				b.WriteString("\t\t")
				b.WriteString(PortForwardLine(fw.WANIface, p))
				b.WriteString("\n")
			}
			b.WriteString("\t}\n")
		}

		if fw.Masquerade {
			b.WriteString("\n\tchain postrouting {\n")
			b.WriteString("\t\ttype nat hook postrouting priority srcnat; policy accept;\n")
			fmt.Fprintf(&b, "\t\toifname %s masquerade comment \"nftably:baseline masquerade\"\n", wan)
			b.WriteString("\t}\n")
		}
	}

	b.WriteString("}\n")
	return b.String()
}

func policyOrDrop(p string) string {
	if p != "accept" {
		p = "drop"
	}
	return p
}

// writeRules emits the enabled rules belonging to chain, in model order. Rows
// written before M4 have an empty chain and belong to input.
func writeRules(b *strings.Builder, rules []store.Rule, chain string) {
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		rc := r.Chain
		if rc == "" {
			rc = "input"
		}
		if rc != chain {
			continue
		}
		for _, line := range RuleLines(r) {
			b.WriteString("\t\t")
			b.WriteString(line)
			b.WriteString("\n")
		}
	}
}

// PortForwardLine renders one port-forward to its DNAT rule (without
// indentation). The address family suffix on dnat is what makes it legal in
// the inet family — `dnat ip to` only ever sees IPv4 packets, `dnat ip6 to`
// only IPv6 (nft adds the family dependency itself).
func PortForwardLine(wanIface string, p store.PortForward) string {
	dest := p.Dest
	family := "ip"
	if addr, err := netip.ParseAddr(p.Dest); err == nil && addr.Is6() {
		family = "ip6"
		if p.DestPort != "" {
			dest = "[" + dest + "]"
		}
	}
	if p.DestPort != "" {
		dest += ":" + p.DestPort
	}
	line := fmt.Sprintf("iifname %q %s dport %s dnat %s to %s", wanIface, p.Proto, p.DPort, family, dest)
	if p.Name != "" {
		line += fmt.Sprintf(" comment %q", "nftably: "+p.Name)
	}
	return line
}

// RuleLines renders one model rule to nft rule syntax (without indentation).
// A rule whose sources mix address families becomes two lines, because in the
// inet family `ip saddr` matches only IPv4 packets and `ip6 saddr` only IPv6 —
// a single line could not match both.
//
// Set elements are emitted in nft's own canonical order (numeric, ascending):
// the kernel stores sets unordered and `nft list` prints them sorted, so
// rendering any other order would make every post-apply diff noisy.
func RuleLines(r store.Rule) []string {
	prefixes, _ := store.ParseSources(r.SAddrs)
	sort.Slice(prefixes, func(i, j int) bool {
		if c := prefixes[i].Addr().Compare(prefixes[j].Addr()); c != 0 {
			return c < 0
		}
		return prefixes[i].Bits() < prefixes[j].Bits()
	})
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
	sort.Slice(ports, func(i, j int) bool { return portLow(ports[i]) < portLow(ports[j]) })
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

// portLow is a normalized port token's sort key: the low end of a range, the
// port itself otherwise.
func portLow(tok string) int {
	lo, _, _ := strings.Cut(tok, "-")
	n, _ := strconv.Atoi(lo)
	return n
}
