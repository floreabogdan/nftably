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

// Model is everything Config renders: the chain-wide settings, the ordered
// rules, the port-forwards and the two lists.
type Model struct {
	FW       store.Firewall
	Rules    []store.Rule
	Forwards []store.PortForward
	// Lists are the named address lists in position order. Allow-role lists
	// are accepted before everything, even before block-role lists; block-
	// role lists are dropped before established/related, so a block also
	// cuts already-open connections. Plain lists render only when a rule
	// uses them as its source.
	Lists []ListWithEntries
}

// ListWithEntries pairs a list with its entries for rendering.
type ListWithEntries struct {
	store.IPList
	Entries []store.ListEntry
}

// list looks a list up by id; nil when absent.
func (m Model) list(id int64) *ListWithEntries {
	for i := range m.Lists {
		if m.Lists[i].ID == id {
			return &m.Lists[i]
		}
	}
	return nil
}

// Config renders the full managed table: named sets for the lists, chain
// declarations, the always-on baseline rules, then the operator's enabled
// rules in order.
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
func Config(m Model) string {
	fw := m.FW
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n", TableName)

	// Sets first: one per rendered list and family. A role list renders when
	// it has entries; a plain list when an enabled rule sources from it (an
	// empty referenced set is declared and matches nothing — the honest
	// rendering of "list has no members yet", and lint says so).
	for _, l := range m.renderedLists() {
		v4, v6 := splitFamilies(l.Entries)
		if len(v4) > 0 || l.referencedByRule(m) {
			writeSet(&b, l.Name+"4", "ipv4_addr", v4)
		}
		if len(v6) > 0 || l.referencedByRule(m) {
			writeSet(&b, l.Name+"6", "ipv6_addr", v6)
		}
	}

	b.WriteString("\tchain input {\n")
	fmt.Fprintf(&b, "\t\ttype filter hook input priority filter; policy %s;\n", policyOrDrop(fw.InputPolicy))

	// Baseline: order matters — invalid is dropped first; allow lists are
	// accepted before block lists (management wins); block lists are dropped
	// before established/related, so blocking an address also cuts its
	// connections that are already open; everything precedes operator rules.
	b.WriteString("\t\tiif \"lo\" accept comment \"nftably:baseline loopback\"\n")
	b.WriteString("\t\tct state invalid drop comment \"nftably:baseline invalid\"\n")
	m.writeRoleLines(&b)
	b.WriteString("\t\tct state established,related accept comment \"nftably:baseline conntrack\"\n")
	b.WriteString("\t\ticmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, echo-request, echo-reply, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept comment \"nftably:baseline icmpv6\"\n")
	b.WriteString("\t\ticmp type { echo-reply, destination-unreachable, echo-request, time-exceeded, parameter-problem } accept comment \"nftably:baseline icmp\"\n")

	m.writeRules(&b, "input")
	b.WriteString("\t}\n")

	if fw.WANIface != "" {
		wan := fmt.Sprintf("%q", fw.WANIface)

		// nft list separates chains with a blank line; matching it keeps the
		// post-apply diff quiet.
		b.WriteString("\n\tchain forward {\n")
		fmt.Fprintf(&b, "\t\ttype filter hook forward priority filter; policy %s;\n", policyOrDrop(fw.ForwardPolicy))
		// The forward baseline mirrors the input one — the lists apply to
		// routed traffic too (management reaches the LAN through the router,
		// blocked sources do not) — plus the two lines that make a drop
		// policy usable on a router: DNAT'ed flows (port-forwards, whether
		// ours or e.g. Docker's) pass, and inside→outside is open. The
		// lan-wan accept comes AFTER operator rules so a drop rule above it
		// can still cut a specific LAN host or port off from the internet.
		b.WriteString("\t\tct state invalid drop comment \"nftably:baseline invalid\"\n")
		m.writeRoleLines(&b)
		b.WriteString("\t\tct state established,related accept comment \"nftably:baseline conntrack\"\n")
		b.WriteString("\t\tct status dnat accept comment \"nftably:baseline port-forwards\"\n")
		m.writeRules(&b, "forward")
		fmt.Fprintf(&b, "\t\tiifname != %s oifname %s accept comment \"nftably:baseline lan-wan\"\n", wan, wan)
		b.WriteString("\t}\n")

		var enabled []store.PortForward
		for _, p := range m.Forwards {
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

// splitFamilies sorts a list's entries into v4 and v6 element strings, each
// in nft's listing order (ascending by address). Unparsable rows are skipped
// — they cannot render into anything nft would accept.
func splitFamilies(entries []store.ListEntry) (v4, v6 []string) {
	type el struct {
		addr netip.Addr
		s    string
	}
	var e4, e6 []el
	for _, e := range entries {
		p, err := store.EntryPrefix(e.CIDR)
		if err != nil {
			continue
		}
		if p.Addr().Is4() {
			e4 = append(e4, el{p.Addr(), e.CIDR})
		} else {
			e6 = append(e6, el{p.Addr(), e.CIDR})
		}
	}
	for _, s := range [][]el{e4, e6} {
		sort.Slice(s, func(i, j int) bool { return s[i].addr.Compare(s[j].addr) < 0 })
	}
	for _, e := range e4 {
		v4 = append(v4, e.s)
	}
	for _, e := range e6 {
		v6 = append(v6, e.s)
	}
	return v4, v6
}

// writeSet emits one named set followed by a blank line, in nft's canonical
// listing format: elements two per line, continuations aligned under the
// opening brace; an empty set has no elements line at all, exactly as nft
// lists one.
func writeSet(b *strings.Builder, name, typ string, elements []string) {
	fmt.Fprintf(b, "\tset %s {\n", name)
	fmt.Fprintf(b, "\t\ttype %s\n", typ)
	b.WriteString("\t\tflags interval\n")
	if len(elements) > 0 {
		b.WriteString("\t\telements = { ")
		for i, e := range elements {
			if i > 0 {
				if i%2 == 0 {
					b.WriteString(",\n\t\t\t     ")
				} else {
					b.WriteString(", ")
				}
			}
			b.WriteString(e)
		}
		b.WriteString(" }\n")
	}
	b.WriteString("\t}\n\n")
}

// renderedLists returns the lists that appear in the config: role lists with
// entries, and any list an enabled, rendered rule sources from.
func (m Model) renderedLists() []ListWithEntries {
	var out []ListWithEntries
	for _, l := range m.Lists {
		if (l.Role != store.RoleNone && len(l.Entries) > 0) || l.referencedByRule(m) {
			out = append(out, l)
		}
	}
	return out
}

// referencedByRule reports whether an enabled rule in a rendered chain
// sources from this list.
func (l ListWithEntries) referencedByRule(m Model) bool {
	for _, r := range m.Rules {
		if !r.Enabled || r.SrcListID != l.ID {
			continue
		}
		if chainOf(r) == "forward" && m.FW.WANIface == "" {
			continue // the forward chain is not rendered
		}
		return true
	}
	return false
}

func chainOf(r store.Rule) string {
	if r.Chain == "" {
		return "input"
	}
	return r.Chain
}

// writeRoleLines emits the allow-accept lines, then the block-drop lines, in
// list order — allow wins over block by coming first.
func (m Model) writeRoleLines(b *strings.Builder) {
	for _, role := range []string{store.RoleAllow, store.RoleBlock} {
		verdict := "accept"
		if role == store.RoleBlock {
			verdict = "drop"
		}
		for _, l := range m.Lists {
			if l.Role != role || len(l.Entries) == 0 {
				continue
			}
			v4, v6 := splitFamilies(l.Entries)
			if len(v4) > 0 {
				fmt.Fprintf(b, "\t\tip saddr @%s4 %s comment \"nftably:list %s\"\n", l.Name, verdict, l.Name)
			}
			if len(v6) > 0 {
				fmt.Fprintf(b, "\t\tip6 saddr @%s6 %s comment \"nftably:list %s\"\n", l.Name, verdict, l.Name)
			}
		}
	}
}

func policyOrDrop(p string) string {
	if p != "accept" {
		p = "drop"
	}
	return p
}

// writeRules emits the enabled rules belonging to chain, in model order. Rows
// written before M4 have an empty chain and belong to input.
func (m Model) writeRules(b *strings.Builder, chain string) {
	for _, r := range m.Rules {
		if !r.Enabled || chainOf(r) != chain {
			continue
		}
		for _, line := range m.RuleLines(r) {
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
// a single line could not match both. A rule sourcing from a named list
// references the list's sets the same way; a dangling list reference renders
// nothing (and lint says so).
//
// Set elements are emitted in nft's own canonical order (numeric, ascending):
// the kernel stores sets unordered and `nft list` prints them sorted, so
// rendering any other order would make every post-apply diff noisy.
func (m Model) RuleLines(r store.Rule) []string {
	if r.SrcListID != 0 {
		l := m.list(r.SrcListID)
		if l == nil {
			return nil
		}
		return []string{
			ruleLine(r, "ip saddr @"+l.Name+"4"),
			ruleLine(r, "ip6 saddr @"+l.Name+"6"),
		}
	}
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
		out = append(out, ruleLine(r, ""))
	default:
		if len(v4) > 0 {
			out = append(out, ruleLine(r, "ip saddr "+setExpr(v4)))
		}
		if len(v6) > 0 {
			out = append(out, ruleLine(r, "ip6 saddr "+setExpr(v6)))
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

// ruleLine assembles one rule line; srcExpr is the ready-made source match
// ("ip saddr 10.0.0.0/8", "ip6 saddr @office6") or empty for any source.
func ruleLine(r store.Rule, srcExpr string) string {
	var parts []string
	if r.IIf != "" {
		parts = append(parts, fmt.Sprintf("iifname %q", r.IIf))
	}
	if srcExpr != "" {
		parts = append(parts, srcExpr)
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
