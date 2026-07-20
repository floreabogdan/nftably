// Package nftcat is the knob catalogue: the single source of truth for every
// match condition and action statement nftably's rule editor offers. Each knob
// carries a plain-language label, a one-line explanation, an example and a safe
// default, so the UI can render an exhaustive-yet-explained form directly from
// this data, and the renderer can turn a stored knob back into nft config text.
//
// The package is deliberately dependency-free (it does not import store): it
// works on plain (key, op, value) matches and (key, params) statements, so both
// the store model and the render layer can share it without an import cycle.
package nftcat

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Kind is how a knob's value is entered in the UI (and validated).
type Kind int

const (
	KindNone  Kind = iota // no value
	KindText              // free text: address, CIDR, range, or @set reference
	KindInt               // a whole number
	KindPort              // a port, a-b range, or comma list
	KindEnum              // exactly one Option
	KindFlags             // one or more Options (comma-joined)
	KindIface             // an interface name (rendered quoted)
)

// Option is one choice for an enum/flags knob, explained.
type Option struct {
	Value string `json:"value"`
	Label string `json:"label"`
	Help  string `json:"help"`
}

// Ctx is the rendering context a few knobs need — chiefly the table family,
// which decides whether a NAT statement needs an `ip`/`ip6` qualifier.
type Ctx struct {
	Family string // inet | ip | ip6 | arp | bridge | netdev
}

// Match describes one match condition.
type Match struct {
	Key      string
	Label    string
	Group    string
	Help     string
	Example  string
	Expr     string // nft left-hand expression, e.g. "ip saddr", "tcp dport"
	Kind     Kind
	Quote    bool     // wrap each value token in double quotes (interfaces/strings)
	Options  []Option // for KindEnum / KindFlags
	Ops      []string // operators offered; defaults to {"=="} then {"!="}
	Families []string // families where valid; empty = all
	NeedsL4  string   // informational: the L4 protocol this implies (tcp/udp/…)
}

// Param is one typed field of a statement.
type Param struct {
	Key         string
	Label       string
	Help        string
	Kind        Kind
	Options     []Option
	Optional    bool
	Placeholder string
}

// Statement describes one action statement.
type Statement struct {
	Key      string
	Label    string
	Group    string
	Help     string
	Example  string
	Params   []Param
	Families []string
	render   func(p map[string]string, ctx Ctx) (string, error)
}

// ── the catalogue data ─────────────────────────────────────────────────────

var matches = []Match{
	// Interface
	{Key: "meta.iifname", Label: "Incoming interface", Group: "Interface", Expr: "iifname", Kind: KindIface, Quote: true, Ops: []string{"==", "!="},
		Help: "The interface the packet arrived on (by name). Use this to allow traffic only from your LAN side.", Example: "eth0"},
	{Key: "meta.oifname", Label: "Outgoing interface", Group: "Interface", Expr: "oifname", Kind: KindIface, Quote: true, Ops: []string{"==", "!="},
		Help: "The interface the packet will leave on. Meaningful in forward/output/postrouting chains.", Example: "wan0"},

	// IPv4
	{Key: "ip.saddr", Label: "Source address (IPv4)", Group: "IPv4", Expr: "ip saddr", Kind: KindText, Ops: []string{"==", "!="}, Families: []string{"inet", "ip"},
		Help: "Where the packet came from: a single IPv4 (10.0.0.5), a CIDR (10.0.0.0/8), a range, a comma list, or @set.", Example: "192.168.1.0/24"},
	{Key: "ip.daddr", Label: "Destination address (IPv4)", Group: "IPv4", Expr: "ip daddr", Kind: KindText, Ops: []string{"==", "!="}, Families: []string{"inet", "ip"},
		Help: "Where the packet is headed (IPv4). Same value forms as the source.", Example: "203.0.113.10"},
	{Key: "ip.ttl", Label: "TTL (IPv4)", Group: "IPv4", Expr: "ip ttl", Kind: KindInt, Ops: []string{"==", "!=", "<", ">", "<=", ">="}, Families: []string{"inet", "ip"},
		Help: "IPv4 time-to-live. For BGP GTSM, directly-connected peers send TTL 255 — accepting only ttl 255 rejects spoofed BGP from farther away.", Example: "255"},
	{Key: "ip.dscp", Label: "DSCP / QoS class (IPv4)", Group: "IPv4", Expr: "ip dscp", Kind: KindText, Ops: []string{"==", "!="}, Families: []string{"inet", "ip"},
		Help: "The IPv4 Differentiated Services (QoS) class — a keyword like ef, af11, cs0, or a number 0-63. Match it to prioritise or police traffic marked by an upstream device.", Example: "ef"},

	// IPv6
	{Key: "ip6.saddr", Label: "Source address (IPv6)", Group: "IPv6", Expr: "ip6 saddr", Kind: KindText, Ops: []string{"==", "!="}, Families: []string{"inet", "ip6"},
		Help: "Where the packet came from, IPv6. A single address, a prefix (2001:db8::/32), a comma list, or @set.", Example: "2001:db8::/32"},
	{Key: "ip6.daddr", Label: "Destination address (IPv6)", Group: "IPv6", Expr: "ip6 daddr", Kind: KindText, Ops: []string{"==", "!="}, Families: []string{"inet", "ip6"},
		Help: "Where the packet is headed, IPv6.", Example: "2001:db8::1"},
	{Key: "ip6.hoplimit", Label: "Hop limit (IPv6)", Group: "IPv6", Expr: "ip6 hoplimit", Kind: KindInt, Ops: []string{"==", "!=", "<", ">", "<=", ">="}, Families: []string{"inet", "ip6"},
		Help: "IPv6 hop limit (the v6 equivalent of TTL). For BGP GTSM over IPv6, accept only hoplimit 255 from directly-connected peers.", Example: "255"},
	{Key: "ip6.dscp", Label: "DSCP / QoS class (IPv6)", Group: "IPv6", Expr: "ip6 dscp", Kind: KindText, Ops: []string{"==", "!="}, Families: []string{"inet", "ip6"},
		Help: "The IPv6 Differentiated Services (QoS) class — a keyword like ef, af11, cs0, or a number 0-63.", Example: "ef"},

	// Ports
	{Key: "tcp.dport", Label: "Destination port (TCP)", Group: "Ports", Expr: "tcp dport", Kind: KindPort, Ops: []string{"==", "!=", "<", ">", "<=", ">="}, NeedsL4: "tcp",
		Help: "The TCP port being connected to. One port (22), a range (8000-8100), or a comma list (80,443). This is how you allow a service.", Example: "22"},
	{Key: "tcp.sport", Label: "Source port (TCP)", Group: "Ports", Expr: "tcp sport", Kind: KindPort, Ops: []string{"==", "!=", "<", ">", "<=", ">="}, NeedsL4: "tcp",
		Help: "The TCP port the packet came from. Rarely needed for allow rules.", Example: "1024-65535"},
	{Key: "udp.dport", Label: "Destination port (UDP)", Group: "Ports", Expr: "udp dport", Kind: KindPort, Ops: []string{"==", "!=", "<", ">", "<=", ">="}, NeedsL4: "udp",
		Help: "The UDP port being connected to (e.g. 51820 for WireGuard, 53 for DNS).", Example: "51820"},
	{Key: "udp.sport", Label: "Source port (UDP)", Group: "Ports", Expr: "udp sport", Kind: KindPort, Ops: []string{"==", "!=", "<", ">", "<=", ">="}, NeedsL4: "udp",
		Help: "The UDP port the packet came from.", Example: "53"},

	// Protocol
	{Key: "meta.l4proto", Label: "Layer-4 protocol", Group: "Protocol", Expr: "meta l4proto", Kind: KindEnum, Ops: []string{"==", "!="},
		Help: "Match the transport protocol itself, with no port condition — e.g. allow all ICMP, or match any TCP.", Example: "tcp",
		Options: []Option{
			{"tcp", "TCP", "Connection-oriented (web, SSH, most services)."},
			{"udp", "UDP", "Connectionless (DNS, VPNs, games)."},
			{"icmp", "ICMP", "IPv4 control messages (ping, errors)."},
			{"icmpv6", "ICMPv6", "IPv6 control messages — needed for IPv6 to work at all."},
			{"sctp", "SCTP", "Less common transport protocol."},
		}},

	// Connection tracking
	{Key: "ct.state", Label: "Connection state", Group: "Connection", Expr: "ct state", Kind: KindFlags, Ops: []string{"==", "!="},
		Help: "Where a packet sits in a connection's life. 'established, related' is the classic 'allow replies' rule that keeps your own outbound traffic working under a drop policy.", Example: "established, related",
		Options: []Option{
			{"new", "new", "The first packet of a connection."},
			{"established", "established", "Part of a connection that's already been allowed."},
			{"related", "related", "A new connection spawned by an allowed one (e.g. FTP data)."},
			{"invalid", "invalid", "Doesn't match any known connection — usually dropped."},
			{"untracked", "untracked", "Deliberately exempted from connection tracking."},
		}},
	{Key: "ct.mark", Label: "Connection mark", Group: "Connection", Expr: "ct mark", Kind: KindInt, Ops: []string{"==", "!="},
		Help: "A number attached to the whole connection by an earlier rule — match it to treat a flow's packets consistently.", Example: "0x1"},
	{Key: "ct.status", Label: "Connection status", Group: "Connection", Expr: "ct status", Kind: KindFlags, Ops: []string{"==", "!="},
		Help: "Extra flags conntrack sets on a connection. 'dnat' matches flows that were port-forwarded — handy to accept them in a forward chain.", Example: "dnat",
		Options: []Option{
			{"dnat", "dnat", "The destination address was rewritten (a port-forward)."},
			{"snat", "snat", "The source address was rewritten (masquerade/SNAT)."},
		}},
	{Key: "ct.helper", Label: "Connection helper", Group: "Connection", Expr: "ct helper", Kind: KindText, Quote: true, Ops: []string{"==", "!="},
		Help: "Match a connection being tracked by a named conntrack helper (e.g. \"ftp\", \"sip\") — the assistants that follow protocols which open extra data channels. Use it to accept the related channels a helper predicts.", Example: "ftp"},

	// ICMP
	{Key: "icmp.type", Label: "ICMP type (IPv4)", Group: "ICMP", Expr: "icmp type", Kind: KindFlags, Ops: []string{"==", "!="}, NeedsL4: "icmp",
		Help: "Which kind of IPv4 ICMP message. Allowing echo-request lets others ping you; the error types keep path-MTU and diagnostics working.", Example: "echo-request",
		Options: []Option{
			{"echo-request", "echo-request", "An incoming ping."},
			{"echo-reply", "echo-reply", "A reply to a ping you sent."},
			{"destination-unreachable", "destination-unreachable", "Delivery failed — needed for error reporting."},
			{"time-exceeded", "time-exceeded", "TTL hit zero — needed for traceroute/PMTU."},
			{"parameter-problem", "parameter-problem", "Malformed header report."},
		}},
	{Key: "icmpv6.type", Label: "ICMPv6 type", Group: "ICMP", Expr: "icmpv6 type", Kind: KindFlags, Ops: []string{"==", "!="}, NeedsL4: "icmpv6",
		Help: "Which kind of IPv6 ICMP message. The neighbour-discovery and router types are mandatory for IPv6 — block them and IPv6 stops working.", Example: "nd-neighbor-solicit",
		Options: []Option{
			{"echo-request", "echo-request", "An incoming ping."},
			{"echo-reply", "echo-reply", "A reply to a ping you sent."},
			{"nd-router-solicit", "nd-router-solicit", "Neighbour discovery — mandatory."},
			{"nd-router-advert", "nd-router-advert", "Neighbour discovery — mandatory."},
			{"nd-neighbor-solicit", "nd-neighbor-solicit", "Neighbour discovery — mandatory."},
			{"nd-neighbor-advert", "nd-neighbor-advert", "Neighbour discovery — mandatory."},
			{"destination-unreachable", "destination-unreachable", "Delivery failed — needed for error reporting."},
			{"packet-too-big", "packet-too-big", "Path-MTU discovery — needed or connections stall."},
			{"time-exceeded", "time-exceeded", "Hop limit exceeded."},
			{"parameter-problem", "parameter-problem", "Malformed header report."},
		}},

	// TCP flags
	{Key: "tcp.flags", Label: "TCP flags", Group: "TCP flags", Expr: "tcp flags", Kind: KindFlags, Ops: []string{"==", "!="}, NeedsL4: "tcp",
		Help: "Match packets carrying particular TCP control flags set — e.g. 'syn' for connection openers.", Example: "syn",
		Options: []Option{
			{"fin", "fin", "Sender is finished."},
			{"syn", "syn", "Opening a connection."},
			{"rst", "rst", "Reset the connection."},
			{"psh", "psh", "Push buffered data."},
			{"ack", "ack", "Acknowledgement."},
			{"urg", "urg", "Urgent data."},
		}},

	// Packet meta
	{Key: "meta.mark", Label: "Packet mark", Group: "Meta", Expr: "meta mark", Kind: KindInt, Ops: []string{"==", "!="},
		Help: "A number attached to a packet by an earlier rule (or by policy routing). Match it here to act on marked traffic.", Example: "0x1"},
	{Key: "meta.pkttype", Label: "Packet type", Group: "Meta", Expr: "meta pkttype", Kind: KindEnum, Ops: []string{"==", "!="},
		Help: "Whether the packet is addressed to this host, or is a broadcast/multicast.", Example: "host",
		Options: []Option{
			{"host", "host (unicast)", "Addressed specifically to this machine."},
			{"broadcast", "broadcast", "Sent to everyone on the segment."},
			{"multicast", "multicast", "Sent to a multicast group."},
		}},

	// Owner — for traffic this box itself sends (output/postrouting): the local
	// user/group that owns the socket. Real egress control most firewalls skip.
	{Key: "meta.skuid", Label: "Owning user (this box's own traffic)", Group: "Owner", Expr: "meta skuid", Kind: KindInt, Ops: []string{"==", "!="},
		Help: "For traffic THIS box sends, the numeric user-id that owns the sending socket. Only meaningful in an output/postrouting chain — genuine egress control: e.g. only the backup user's traffic may leave, or root may not.", Example: "0"},
	{Key: "meta.skgid", Label: "Owning group (this box's own traffic)", Group: "Owner", Expr: "meta skgid", Kind: KindInt, Ops: []string{"==", "!="},
		Help: "Like the owning user, but the group-id of the socket that sent the packet. Match this box's outbound traffic by owning group.", Example: "0"},

	// Routing (FIB) — ask the routing table about a packet. No value to type.
	{Key: "fib.rpf", Label: "Fails reverse-path check (spoofed source)", Group: "Routing", Expr: "fib saddr . iif oif missing", Kind: KindNone,
		Help: "Matches a packet whose source address would NOT route back out the interface it arrived on — the classic sign of a spoofed source. Pair it with drop near the top of an input or prerouting chain for anti-spoofing (nftables' answer to rp_filter). No value needed.", Example: "fib saddr . iif oif missing"},
}

var statements = []Statement{
	// Verdicts
	{Key: "accept", Label: "Accept", Group: "Verdict", Help: "Let the packet through. Stops evaluating this chain.", Example: "accept",
		render: func(_ map[string]string, _ Ctx) (string, error) { return "accept", nil }},
	{Key: "drop", Label: "Drop", Group: "Verdict", Help: "Silently discard the packet — the sender gets no reply at all.", Example: "drop",
		render: func(_ map[string]string, _ Ctx) (string, error) { return "drop", nil }},
	{Key: "reject", Label: "Reject", Group: "Verdict", Example: "reject with icmpx type admin-prohibited",
		Help: "Discard the packet but tell the sender — a bit friendlier (and more visible) than drop.",
		Params: []Param{{Key: "with", Label: "Send back", Kind: KindEnum, Optional: true,
			Options: []Option{
				{"", "Default", "An ICMP/ICMPv6 port- or admin-unreachable, chosen automatically."},
				{"tcp reset", "TCP reset", "For TCP, send an RST so the connection fails fast."},
				{"icmpx admin", "Admin prohibited (any family)", "Say the connection is administratively blocked."},
				{"icmpx port", "Port unreachable (any family)", "Say nothing is listening on that port."},
				{"icmpx host", "Host unreachable (any family)", "Say the host can't be reached."},
				{"icmp admin", "Admin prohibited (IPv4)", "IPv4-only admin-prohibited."},
				{"icmp port", "Port unreachable (IPv4)", "IPv4-only port-unreachable."},
				{"icmp host", "Host unreachable (IPv4)", "IPv4-only host-unreachable."},
				{"icmp net", "Net unreachable (IPv4)", "IPv4-only network-unreachable."},
				{"icmpv6 admin", "Admin prohibited (IPv6)", "IPv6-only admin-prohibited."},
				{"icmpv6 port", "Port unreachable (IPv6)", "IPv6-only port-unreachable."},
				{"icmpv6 noroute", "No route (IPv6)", "IPv6-only no-route-to-destination."},
			}}},
		render: func(p map[string]string, _ Ctx) (string, error) {
			// value -> full nft "reject with ..." clause. icmpx works in any
			// family; icmp/icmpv6 forms are family-specific (the pre-apply check
			// catches a mismatch).
			rejects := map[string]string{
				"":               "reject",
				"default":        "reject",
				"tcp reset":      "reject with tcp reset",
				"icmpx admin":    "reject with icmpx type admin-prohibited",
				"icmpx port":     "reject with icmpx type port-unreachable",
				"icmpx host":     "reject with icmpx type host-unreachable",
				"icmp admin":     "reject with icmp type admin-prohibited",
				"icmp port":      "reject with icmp type port-unreachable",
				"icmp host":      "reject with icmp type host-unreachable",
				"icmp net":       "reject with icmp type net-unreachable",
				"icmpv6 admin":   "reject with icmpv6 type admin-prohibited",
				"icmpv6 port":    "reject with icmpv6 type port-unreachable",
				"icmpv6 noroute": "reject with icmpv6 type no-route",
			}
			if out, ok := rejects[p["with"]]; ok {
				return out, nil
			}
			return "", fmt.Errorf("reject: unknown response %q", p["with"])
		}},
	{Key: "continue", Label: "Continue", Group: "Verdict", Help: "Keep evaluating the next rule (an explicit no-op verdict).", Example: "continue",
		render: func(_ map[string]string, _ Ctx) (string, error) { return "continue", nil }},
	{Key: "return", Label: "Return", Group: "Verdict", Help: "Stop this chain and go back to the one that jumped here (in a base chain, applies the policy).", Example: "return",
		render: func(_ map[string]string, _ Ctx) (string, error) { return "return", nil }},
	{Key: "jump", Label: "Jump to chain", Group: "Verdict", Example: "jump my_checks",
		Help:   "Hand the packet to another (regular) chain, then come back here if that chain returns.",
		Params: []Param{{Key: "target", Label: "Chain", Kind: KindText, Placeholder: "chain name", Help: "The regular chain to jump into."}},
		render: func(p map[string]string, _ Ctx) (string, error) {
			t := strings.TrimSpace(p["target"])
			if t == "" {
				return "", fmt.Errorf("jump needs a target chain")
			}
			if !identRe.MatchString(t) {
				return "", fmt.Errorf("jump target must be a chain name (letters, digits, underscores)")
			}
			return "jump " + t, nil
		}},
	{Key: "goto", Label: "Go to chain", Group: "Verdict", Example: "goto my_checks",
		Help:   "Like jump, but does not come back — evaluation continues in the target chain and returns to the caller of this one.",
		Params: []Param{{Key: "target", Label: "Chain", Kind: KindText, Placeholder: "chain name", Help: "The regular chain to go to."}},
		render: func(p map[string]string, _ Ctx) (string, error) {
			t := strings.TrimSpace(p["target"])
			if t == "" {
				return "", fmt.Errorf("goto needs a target chain")
			}
			if !identRe.MatchString(t) {
				return "", fmt.Errorf("goto target must be a chain name (letters, digits, underscores)")
			}
			return "goto " + t, nil
		}},
	{Key: "vmap", Label: "Verdict map (vmap)", Group: "Verdict", Example: "tcp dport vmap { 22 : accept, 80 : drop, 443 : accept }",
		Help: "One O(1) lookup instead of a long list of rules: map a field's value straight to a verdict. Ideal for a big 'port → accept/drop' table or 'source → jump chain'. The whole rule becomes this map — put any pre-conditions in the matches above.",
		Params: []Param{
			{Key: "vmapkey", Label: "Map on", Kind: KindEnum, Help: "The field whose value picks the verdict.",
				Options: []Option{
					{"tcp dport", "TCP destination port", ""}, {"tcp sport", "TCP source port", ""},
					{"udp dport", "UDP destination port", ""}, {"udp sport", "UDP source port", ""},
					{"ip saddr", "Source address (IPv4)", ""}, {"ip daddr", "Destination address (IPv4)", ""},
					{"ip6 saddr", "Source address (IPv6)", ""}, {"ip6 daddr", "Destination address (IPv6)", ""},
					{"meta mark", "Packet mark", ""}, {"ct mark", "Connection mark", ""},
					{"meta l4proto", "L4 protocol", ""}, {"meta iifname", "Inbound interface", ""},
				}},
			{Key: "vmapentries", Label: "Entries (value : verdict, …)", Kind: KindText, Placeholder: "22 : accept, 80 : drop, 443 : accept",
				Help: "Comma-separated value : verdict pairs. Verdicts: accept, drop, continue, return, or jump/goto <chain>."},
		},
		render: func(p map[string]string, _ Ctx) (string, error) {
			key := strings.TrimSpace(p["vmapkey"])
			if !vmapKeys[key] {
				return "", fmt.Errorf("a verdict map's 'map on' must be one of the supported fields")
			}
			body, err := parseVmapEntries(strings.TrimSpace(p["vmapentries"]), key)
			if err != nil {
				return "", err
			}
			return key + " vmap { " + body + " }", nil
		}},

	// Logging / accounting
	{Key: "log", Label: "Log", Group: "Observe", Example: `log prefix "drop " level info`,
		Help: "Write a line to the kernel log for matching packets. Add it above a drop to see what's being blocked.",
		Params: []Param{
			{Key: "prefix", Label: "Prefix", Kind: KindText, Optional: true, Placeholder: "blocked ", Help: "A tag prepended to each log line so you can grep for it."},
			{Key: "level", Label: "Level", Kind: KindEnum, Optional: true, Help: "Syslog severity.", Options: []Option{
				{"", "info (default)", ""}, {"debug", "debug", ""}, {"info", "info", ""}, {"notice", "notice", ""},
				{"warn", "warn", ""}, {"err", "err", ""}, {"crit", "crit", ""},
			}},
			{Key: "group", Label: "nflog group", Kind: KindInt, Optional: true, Placeholder: "0", Help: "Send to an nflog netlink group instead of the kernel log — a userspace collector (ulogd, a packet logger) reads it by this group number."},
		},
		render: func(p map[string]string, _ Ctx) (string, error) {
			var b strings.Builder
			b.WriteString("log")
			// The prefix is used verbatim (a trailing space to separate it from
			// the logged packet is common and intentional), only guarding the
			// characters that would break out of the quoted string.
			if pre := p["prefix"]; strings.TrimSpace(pre) != "" {
				if strings.ContainsAny(pre, "\"\\\n\r") {
					return "", fmt.Errorf("log prefix must not contain quotes or line breaks")
				}
				fmt.Fprintf(&b, " prefix %q", pre)
			}
			if lvl := strings.TrimSpace(p["level"]); lvl != "" {
				if !logLevels[lvl] {
					return "", fmt.Errorf("log level %q is not a syslog level", lvl)
				}
				b.WriteString(" level " + lvl)
			}
			if grp := strings.TrimSpace(p["group"]); grp != "" {
				if _, err := strconv.Atoi(grp); err != nil {
					return "", fmt.Errorf("nflog group must be a whole number")
				}
				b.WriteString(" group " + grp)
			}
			return b.String(), nil
		}},
	{Key: "counter", Label: "Count", Group: "Observe", Example: "counter",
		Help: "Tally the packets and bytes that match this rule; the total shows next to the rule on the Firewall page once applied. Give it a name to share one counter across several rules (a named counter also keeps its value across ruleset reloads).",
		Params: []Param{{Key: "cname", Label: "Named counter (optional)", Kind: KindText, Optional: true, Placeholder: "web_hits",
			Help: "Name it to aggregate the count across every rule that uses the same name. Blank = a per-rule anonymous counter."}},
		render: func(p map[string]string, _ Ctx) (string, error) {
			name := strings.TrimSpace(p["cname"])
			if name == "" {
				return "counter", nil
			}
			if !identRe.MatchString(name) {
				return "", fmt.Errorf("counter name must be letters, digits and underscores")
			}
			return "counter name " + name, nil
		}},
	{Key: "flow", Label: "Offload to flowtable (flow add)", Group: "Observe", Example: "flow add @ft",
		Help:   "Hand established connections to a flowtable's fast path — later packets of the flow skip the rest of the ruleset for a big throughput win on a router. Put it in a forward chain (e.g. after 'ct state established related'); the flowtable must exist on the table.",
		Params: []Param{{Key: "ft", Label: "Flowtable", Kind: KindText, Placeholder: "ft", Help: "The flowtable to offload into (its name, without the @)."}},
		render: func(p map[string]string, _ Ctx) (string, error) {
			ft := strings.TrimSpace(strings.TrimPrefix(p["ft"], "@"))
			if ft == "" {
				return "", fmt.Errorf("flow offload needs a flowtable name")
			}
			if !identRe.MatchString(ft) {
				return "", fmt.Errorf("flowtable name must be letters, digits and underscores")
			}
			return "flow add @" + ft, nil
		}},
	{Key: "meta.nftrace.set", Label: "Trace (for nft monitor trace)", Group: "Observe", Example: "meta nftrace set 1",
		Help:   "Flag matching packets for tracing, so `nft monitor trace` prints every rule they hit as they cross the ruleset — a powerful last-resort debugging aid. Match it to the traffic you're chasing, apply, then watch the trace. Remove it when you're done; it's noisy.",
		render: func(_ map[string]string, _ Ctx) (string, error) { return "meta nftrace set 1", nil }},

	// Rate limiting
	{Key: "limit", Label: "Rate limit", Group: "Rate limiting", Example: "limit rate 10/minute burst 5 packets",
		Help: "Cap matching traffic to a rate. In 'under' mode (default) matching packets up to the rate pass to the next statement (pair with accept to throttle, e.g. new SSH); in 'over' mode the ones ABOVE the rate match (pair with drop to police a flood). Choose packets or a byte rate.",
		Params: []Param{
			{Key: "lmode", Label: "Mode", Kind: KindEnum, Optional: true, Help: "under = the traffic within the rate matches; over = the excess matches (pair with drop).", Options: []Option{
				{"", "under (throttle — pair with accept)", ""}, {"over", "over (police — pair with drop)", ""},
			}},
			{Key: "rate", Label: "Rate", Kind: KindInt, Placeholder: "10", Help: "How much per unit of time."},
			{Key: "lunit", Label: "Unit", Kind: KindEnum, Optional: true, Help: "Count packets, or a data rate.", Options: []Option{
				{"", "packets", ""}, {"bytes", "bytes", ""}, {"kbytes", "kbytes", ""}, {"mbytes", "mbytes", ""},
			}},
			{Key: "per", Label: "Per", Kind: KindEnum, Options: []Option{
				{"second", "second", ""}, {"minute", "minute", ""}, {"hour", "hour", ""}, {"day", "day", ""}, {"week", "week", ""},
			}, Help: "The time unit."},
			{Key: "burst", Label: "Burst", Kind: KindInt, Optional: true, Placeholder: "5", Help: "Allow a short burst above the rate before limiting kicks in."},
		},
		render: func(p map[string]string, _ Ctx) (string, error) {
			rate := strings.TrimSpace(p["rate"])
			per := strings.TrimSpace(p["per"])
			if _, err := strconv.Atoi(rate); err != nil {
				return "", fmt.Errorf("rate limit needs a whole number rate")
			}
			if per == "" {
				per = "second"
			}
			if !rateUnits[per] {
				return "", fmt.Errorf("rate limit unit %q is not second/minute/hour/day/week", per)
			}
			out := "limit rate"
			if dir := strings.TrimSpace(p["lmode"]); dir == "over" {
				out += " over"
			} else if dir != "" {
				return "", fmt.Errorf("rate limit mode %q must be over or blank", dir)
			}
			byteUnits := map[string]bool{"bytes": true, "kbytes": true, "mbytes": true}
			if unit := strings.TrimSpace(p["lunit"]); unit != "" && byteUnits[unit] {
				// Byte rate: burst (if any) is a byte quantity, not packets.
				out += fmt.Sprintf(" %s %s/%s", rate, unit, per)
				if burst := strings.TrimSpace(p["burst"]); burst != "" {
					if _, err := strconv.Atoi(burst); err != nil {
						return "", fmt.Errorf("rate limit burst must be a whole number")
					}
					out += " burst " + burst + " " + unit
				}
				return out, nil
			}
			out += fmt.Sprintf(" %s/%s", rate, per)
			if burst := strings.TrimSpace(p["burst"]); burst != "" {
				if _, err := strconv.Atoi(burst); err != nil {
					return "", fmt.Errorf("rate limit burst must be a whole number")
				}
				out += " burst " + burst + " packets"
			}
			return out, nil
		}},

	// Marking
	{Key: "meta.mark.set", Label: "Set packet mark", Group: "Marking", Example: "meta mark set 0x1",
		Help:   "Attach a number to the packet — later rules or policy routing can match it.",
		Params: []Param{{Key: "value", Label: "Mark", Kind: KindText, Placeholder: "0x1", Help: "A number (decimal or 0x-hex)."}},
		render: func(p map[string]string, _ Ctx) (string, error) {
			v := strings.TrimSpace(p["value"])
			if v == "" {
				return "", fmt.Errorf("set packet mark needs a value")
			}
			if err := checkNumberOrHex("packet mark", v); err != nil {
				return "", err
			}
			return "meta mark set " + v, nil
		}},
	{Key: "ct.mark.set", Label: "Set connection mark", Group: "Marking", Example: "ct mark set 0x1",
		Help:   "Attach a number to the whole connection (persists across its packets).",
		Params: []Param{{Key: "value", Label: "Mark", Kind: KindText, Placeholder: "0x1", Help: "A number (decimal or 0x-hex)."}},
		render: func(p map[string]string, _ Ctx) (string, error) {
			v := strings.TrimSpace(p["value"])
			if v == "" {
				return "", fmt.Errorf("set connection mark needs a value")
			}
			if err := checkNumberOrHex("connection mark", v); err != nil {
				return "", err
			}
			return "ct mark set " + v, nil
		}},
	{Key: "ct.helper.set", Label: "Assign connection helper", Group: "Marking", Example: `ct helper set "ftp"`,
		Help:   "Attach a conntrack helper (ALG) to the connection so a matching protocol's dynamic data ports are tracked as 'related' — e.g. active FTP, SIP, TFTP. The named helper must exist (declared with `ct helper` on the table).",
		Params: []Param{{Key: "name", Label: "Helper name", Kind: KindText, Placeholder: "ftp", Help: "The conntrack helper to assign (letters, digits, dash, underscore)."}},
		render: func(p map[string]string, _ Ctx) (string, error) {
			v := strings.TrimSpace(p["name"])
			if v == "" {
				return "", fmt.Errorf("assign helper needs a helper name")
			}
			if !helperNameRe.MatchString(v) {
				return "", fmt.Errorf("helper name must be letters, digits, dash or underscore")
			}
			return fmt.Sprintf("ct helper set %q", v), nil
		}},
	{Key: "dscp.set", Label: "Set DSCP / QoS class", Group: "Marking", Example: "ip dscp set ef",
		Help: "Stamp a Differentiated Services (QoS) class on the packet so downstream devices can prioritise it — e.g. mark VoIP as 'ef' (expedited forwarding). DSCP lives in the IP header, so pick the family.",
		Params: []Param{
			{Key: "family", Label: "Family", Kind: KindEnum, Help: "Which IP header to stamp.",
				Options: []Option{{"ip", "IPv4", ""}, {"ip6", "IPv6", ""}}},
			{Key: "value", Label: "Class", Kind: KindText, Placeholder: "ef", Help: "A DSCP keyword (ef, af11, cs0…) or a number 0-63."},
		},
		render: func(p map[string]string, _ Ctx) (string, error) {
			fam := strings.TrimSpace(p["family"])
			if fam == "" {
				fam = "ip"
			}
			if fam != "ip" && fam != "ip6" {
				return "", fmt.Errorf("DSCP family must be ip or ip6")
			}
			v := strings.TrimSpace(p["value"])
			if v == "" {
				return "", fmt.Errorf("DSCP needs a class (a keyword or 0-63)")
			}
			if err := checkSafe("DSCP class", v); err != nil {
				return "", err
			}
			return fam + " dscp set " + v, nil
		}},

	// NAT (only meaningful in nat-type chains)
	{Key: "dnat", Label: "Destination NAT (port forward)", Group: "NAT", Example: "dnat to 192.168.1.10:80",
		Help: "Rewrite where a packet is going — the core of a port-forward. Use in a prerouting nat chain.",
		Params: []Param{
			{Key: "addr", Label: "To address", Kind: KindText, Placeholder: "192.168.1.10", Help: "The internal host to send matching traffic to."},
			{Key: "port", Label: "To port", Kind: KindPort, Optional: true, Placeholder: "80", Help: "Optional — the internal port; blank keeps the original."},
		},
		render: func(p map[string]string, ctx Ctx) (string, error) { return renderNatTo("dnat", p, ctx) }},
	{Key: "snat", Label: "Source NAT", Group: "NAT", Example: "snat to 203.0.113.1",
		Help: "Rewrite where a packet appears to come from, to a fixed address. Use in a postrouting nat chain when you have a static external IP.",
		Params: []Param{
			{Key: "addr", Label: "To address", Kind: KindText, Placeholder: "203.0.113.1", Help: "The external source address to use."},
			{Key: "port", Label: "To port", Kind: KindPort, Optional: true, Help: "Optional source port to map to."},
		},
		render: func(p map[string]string, ctx Ctx) (string, error) { return renderNatTo("snat", p, ctx) }},
	{Key: "masquerade", Label: "Masquerade", Group: "NAT", Example: "masquerade",
		Help:   "Source-NAT to whatever address the outgoing interface currently has — the standard 'share one internet connection' setting for a router. Use in a postrouting nat chain.",
		render: func(_ map[string]string, _ Ctx) (string, error) { return "masquerade", nil }},
	{Key: "redirect", Label: "Redirect (to this host)", Group: "NAT", Example: "redirect to :3128",
		Help:   "Send traffic to a port on this same machine — e.g. transparently to a local proxy. Use in a prerouting nat chain.",
		Params: []Param{{Key: "port", Label: "To port", Kind: KindPort, Optional: true, Placeholder: "3128", Help: "The local port to redirect to (blank keeps the original)."}},
		render: func(p map[string]string, _ Ctx) (string, error) {
			if port := strings.TrimSpace(p["port"]); port != "" {
				if err := checkPort("redirect port", port); err != nil {
					return "", err
				}
				return "redirect to :" + port, nil
			}
			return "redirect", nil
		}},

	// Defense — kernel-side attack mitigation most people never discover.
	{Key: "synproxy", Label: "SYN-proxy (SYN-flood protection)", Group: "Defense", Example: "synproxy mss 1460 wscale 7",
		Help: "Complete the TCP handshake in the kernel and only open a real connection once the client answers — so a SYN flood never reaches the service. Put it on new TCP SYN packets to the port you're protecting; leave the numbers blank for sane defaults.",
		Params: []Param{
			{Key: "mss", Label: "MSS", Kind: KindInt, Optional: true, Placeholder: "1460", Help: "Maximum segment size to advertise; 1460 suits standard Ethernet."},
			{Key: "wscale", Label: "Window scale", Kind: KindInt, Optional: true, Placeholder: "7", Help: "TCP window-scale factor to advertise."},
		},
		render: func(p map[string]string, _ Ctx) (string, error) {
			var b strings.Builder
			b.WriteString("synproxy")
			if mss := strings.TrimSpace(p["mss"]); mss != "" {
				if _, err := strconv.Atoi(mss); err != nil {
					return "", fmt.Errorf("synproxy MSS must be a whole number")
				}
				b.WriteString(" mss " + mss)
			}
			if ws := strings.TrimSpace(p["wscale"]); ws != "" {
				if _, err := strconv.Atoi(ws); err != nil {
					return "", fmt.Errorf("synproxy window scale must be a whole number")
				}
				b.WriteString(" wscale " + ws)
			}
			return b.String(), nil
		}},
	{Key: "tcp.mss.clamp", Label: "Clamp TCP MSS (fix VPN/PPPoE 'some sites hang')", Group: "Defense", Example: "tcp option maxseg size set rt mtu",
		Help:   "Lower the TCP maximum segment size on connection-opening packets so they fit a smaller path — the classic cure when pages stall over a VPN or PPPoE link. Pair it with a match on TCP SYN packets in a forward chain. 'rt mtu' tracks the route's MTU automatically.",
		Params: []Param{{Key: "size", Label: "Size", Kind: KindText, Optional: true, Placeholder: "rt mtu", Help: "'rt mtu' to follow the route automatically, or a number like 1400."}},
		render: func(p map[string]string, _ Ctx) (string, error) {
			size := strings.TrimSpace(p["size"])
			if size == "" {
				size = "rt mtu"
			}
			if size != "rt mtu" {
				if _, err := strconv.Atoi(size); err != nil {
					return "", fmt.Errorf("MSS size must be 'rt mtu' or a whole number")
				}
			}
			return "tcp option maxseg size set " + size, nil
		}},

	{Key: "ban.rate", Label: "Rate-ban the source (brute-force auto-ban)", Group: "Defense",
		Example: `meter ssh_abusers_m4 { ip saddr limit rate over 10/minute burst 5 packets } add @ssh_abusers { ip saddr timeout 1h } drop`,
		Help:    "Fail2ban in the kernel: a source that opens new connections faster than the allowed rate is added to a timeout set and dropped for the ban period — no userspace daemon, no log parsing. Put it on new connections to the port you're protecting (match `tcp dport 22` and connection state `new`), and add a companion rule higher up that drops the same set. nftably declares the dynamic set for you.",
		Params: []Param{
			{Key: "set", Label: "Ban set", Kind: KindText, Placeholder: "ssh_abusers", Help: "Name of the dynamic set offenders are added to. A companion `saddr @<set> drop` rule does the blocking; nftably emits the set declaration automatically."},
			{Key: "family", Label: "Address family", Kind: KindEnum, Help: "A dynamic set holds one family. Ban IPv4 and IPv6 with a rule (and set) each.",
				Options: []Option{{"ip", "IPv4", "Bans by IPv4 source (ipv4_addr set)."}, {"ip6", "IPv6", "Bans by IPv6 source (ipv6_addr set)."}}},
			{Key: "rate", Label: "Rate", Kind: KindInt, Placeholder: "10", Help: "New connections a source may open per time unit before it's banned."},
			{Key: "per", Label: "Per", Kind: KindEnum, Help: "The time unit for the rate.",
				Options: []Option{{"second", "second", ""}, {"minute", "minute", ""}, {"hour", "hour", ""}}},
			{Key: "burst", Label: "Burst", Kind: KindInt, Optional: true, Placeholder: "5", Help: "Short burst tolerated before the ban kicks in."},
			{Key: "timeout", Label: "Ban for", Kind: KindText, Optional: true, Placeholder: "1h", Help: "How long a banned source stays blocked — an nft duration like 30s, 10m, 1h, 1d."},
		},
		render: renderBanRate},

	// Byte quota — accounting with a cut-off.
	{Key: "quota", Label: "Byte quota", Group: "Rate limiting", Example: "quota over 500 mbytes",
		Help: "Match against a running byte total — cut a service off after it has served so much, or allow only up to a cap. 'over' fires once the total is exceeded (then drop); 'until' fires while still under it (then accept).",
		Params: []Param{
			{Key: "dir", Label: "When", Kind: KindEnum, Options: []Option{
				{"over", "over — once exceeded", "Matches after the total passes the limit (pair with drop)."},
				{"until", "until — while under", "Matches while still below the limit (pair with accept)."},
			}, Help: "Match before or after the limit."},
			{Key: "amount", Label: "Amount", Kind: KindInt, Placeholder: "500", Help: "How much data."},
			{Key: "unit", Label: "Unit", Kind: KindEnum, Options: []Option{
				{"bytes", "bytes", ""}, {"kbytes", "kbytes", ""}, {"mbytes", "mbytes", ""},
			}, Help: "Byte unit."},
		},
		render: func(p map[string]string, _ Ctx) (string, error) {
			dir := strings.TrimSpace(p["dir"])
			if dir == "" {
				dir = "over"
			}
			if dir != "over" && dir != "until" {
				return "", fmt.Errorf("quota direction must be over or until")
			}
			amt := strings.TrimSpace(p["amount"])
			if _, err := strconv.Atoi(amt); err != nil {
				return "", fmt.Errorf("quota needs a whole-number amount")
			}
			unit := strings.TrimSpace(p["unit"])
			if unit == "" {
				unit = "mbytes"
			}
			if !quotaUnits[unit] {
				return "", fmt.Errorf("quota unit must be bytes, kbytes or mbytes")
			}
			return fmt.Sprintf("quota %s %s %s", dir, amt, unit), nil
		}},

	// Advanced — hand-offs and tuning.
	{Key: "queue", Label: "Send to userspace program (NFQUEUE)", Group: "Advanced", Example: "queue num 0",
		Help: "Hand the packet to a userspace program reading an nfqueue — the standard way to feed traffic to an inline IDS/IPS such as Suricata or Snort. 'Fail open' lets traffic pass if no program is attached (safer for availability).",
		Params: []Param{
			{Key: "num", Label: "Queue number", Kind: KindInt, Optional: true, Placeholder: "0", Help: "The nfqueue the program reads from."},
			{Key: "bypass", Label: "If no program is listening", Kind: KindEnum, Optional: true, Options: []Option{
				{"", "drop the traffic", "Fail closed — no inspection, no pass."},
				{"bypass", "let it pass (fail open)", "Keep working if the inspector is down."},
			}, Help: "What happens when nothing is attached to the queue."},
		},
		render: func(p map[string]string, _ Ctx) (string, error) {
			num := strings.TrimSpace(p["num"])
			bypass := strings.TrimSpace(p["bypass"]) == "bypass"
			if num == "" && bypass {
				num = "0" // 'bypass' needs an explicit queue number
			}
			var b strings.Builder
			b.WriteString("queue")
			if num != "" {
				if _, err := strconv.Atoi(num); err != nil {
					return "", fmt.Errorf("queue number must be a whole number")
				}
				b.WriteString(" num " + num)
			}
			if bypass {
				b.WriteString(" bypass")
			}
			return b.String(), nil
		}},
	{Key: "notrack", Label: "Don't track (skip connection tracking)", Group: "Advanced", Example: "notrack",
		Help:   "Exempt matching packets from connection tracking — a performance win for high-volume stateless traffic (e.g. an authoritative DNS server). Only works in a chain at 'raw' priority (prerouting or output).",
		render: func(_ map[string]string, _ Ctx) (string, error) { return "notrack", nil }},
	{Key: "tproxy", Label: "Transparent proxy (TPROXY)", Group: "Advanced", Example: "tproxy ip to :50080",
		Help: "Hand the packet to a local transparent proxy without rewriting its destination — the proxy sees the original target. Belongs in a prerouting chain at mangle priority, matched on the transport/port you're intercepting; the proxy listens on the port here with IP_TRANSPARENT. Needs the kernel's TPROXY support.",
		Params: []Param{
			{Key: "family", Label: "Family", Kind: KindEnum, Optional: true, Help: "In an inet table TPROXY must name the family; ignored in ip/ip6 tables.",
				Options: []Option{{"ip", "IPv4", ""}, {"ip6", "IPv6", ""}}},
			{Key: "port", Label: "To local port", Kind: KindPort, Placeholder: "50080", Help: "The port your transparent proxy listens on."},
		},
		render: func(p map[string]string, ctx Ctx) (string, error) {
			port := strings.TrimSpace(p["port"])
			if port == "" {
				return "", fmt.Errorf("tproxy needs a local port")
			}
			if err := checkPort("tproxy port", port); err != nil {
				return "", err
			}
			qual := ""
			if ctx.Family == "inet" {
				fam := strings.TrimSpace(p["family"])
				if fam == "" {
					fam = "ip"
				}
				if fam != "ip" && fam != "ip6" {
					return "", fmt.Errorf("tproxy family must be ip or ip6")
				}
				qual = fam + " "
			}
			return fmt.Sprintf("tproxy %sto :%s", qual, port), nil
		}},
}

// ── lookups ─────────────────────────────────────────────────────────────────

var matchByKey = func() map[string]Match {
	m := make(map[string]Match, len(matches))
	for _, x := range matches {
		m[x.Key] = x
	}
	return m
}()

var statementByKey = func() map[string]Statement {
	m := make(map[string]Statement, len(statements))
	for _, x := range statements {
		m[x.Key] = x
	}
	return m
}()

// Matches returns every match knob (catalogue order).
func Matches() []Match { return matches }

// Statements returns every statement knob (catalogue order).
func Statements() []Statement { return statements }

// MatchByKey looks up a match knob.
func MatchByKey(key string) (Match, bool) { m, ok := matchByKey[key]; return m, ok }

// StatementByKey looks up a statement knob.
func StatementByKey(key string) (Statement, bool) { s, ok := statementByKey[key]; return s, ok }

// MatchGroups returns the match knobs grouped for the UI, groups in first-seen
// order and knobs within a group in catalogue order.
func MatchGroups() []MatchGroup { return groupMatches(matches) }

// MatchGroup is a named set of match knobs.
type MatchGroup struct {
	Name    string
	Matches []Match
}

func groupMatches(ms []Match) []MatchGroup {
	var order []string
	byName := map[string][]Match{}
	for _, m := range ms {
		if _, seen := byName[m.Group]; !seen {
			order = append(order, m.Group)
		}
		byName[m.Group] = append(byName[m.Group], m)
	}
	out := make([]MatchGroup, 0, len(order))
	for _, n := range order {
		out = append(out, MatchGroup{Name: n, Matches: byName[n]})
	}
	return out
}

// StatementGroup is a named set of statement knobs.
type StatementGroup struct {
	Name       string
	Statements []Statement
}

// StatementGroups returns the statement knobs grouped for the UI.
func StatementGroups() []StatementGroup {
	var order []string
	byName := map[string][]Statement{}
	for _, s := range statements {
		if _, seen := byName[s.Group]; !seen {
			order = append(order, s.Group)
		}
		byName[s.Group] = append(byName[s.Group], s)
	}
	out := make([]StatementGroup, 0, len(order))
	for _, n := range order {
		out = append(out, StatementGroup{Name: n, Statements: byName[n]})
	}
	return out
}

// ── value validation ─────────────────────────────────────────────────────────
//
// Match values and statement params are free-form text (addresses, ports,
// ranges, comma lists, @set references) that the renderer emits into a rule
// line — a line that lives inside a `table <fam> <name> { chain { … } }` block.
// nft's structural characters (newlines, the `{}` and `;` that delimit chains
// and tables, the `#` comment marker) must therefore never survive into that
// text: a value containing them could close the enclosing chain and table and
// declare new nft objects, escaping the model nftably tracks — and so escaping
// the pre-apply snapshot and the armed auto-revert. `nft -c` accepts such input
// because it is syntactically valid; only rejecting the characters here does.
// This is a deny-list of structural characters, not a grammar: the many valid
// value forms stay free-form.

const nftStructuralChars = "\n\r\t{}();#\\\"'`"

// The closed vocabularies a couple of statement params draw from — emitted into
// config bare, so validated against the exact keyword set rather than only the
// structural deny-list.
var (
	logLevels  = map[string]bool{"debug": true, "info": true, "notice": true, "warn": true, "err": true, "crit": true, "alert": true, "emerg": true}
	rateUnits  = map[string]bool{"second": true, "minute": true, "hour": true, "day": true, "week": true}
	quotaUnits = map[string]bool{"bytes": true, "kbytes": true, "mbytes": true}
)

// identRe matches an nft identifier (a chain or set name) — emittable bare with
// no way to break out of the token.
var identRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)

// helperNameRe validates a conntrack helper name (e.g. "ftp", "sip-5060").
var helperNameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,31}$`)

// vmapKeys are the fields a verdict map may key on. meta iifname values are
// quoted (interface names); the rest are emitted bare.
var vmapKeys = map[string]bool{
	"tcp dport": true, "tcp sport": true, "udp dport": true, "udp sport": true,
	"ip saddr": true, "ip daddr": true, "ip6 saddr": true, "ip6 daddr": true,
	"meta mark": true, "ct mark": true, "meta l4proto": true, "meta iifname": true,
}

// parseVmapEntries validates and renders the "value : verdict" pairs of a vmap.
// The commas and colons are consumed here, so each value is checked with the
// same structural deny-list as any other value.
func parseVmapEntries(entries, key string) (string, error) {
	if entries == "" {
		return "", fmt.Errorf("a verdict map needs at least one value : verdict entry")
	}
	quote := key == "meta iifname"
	var out []string
	for _, raw := range strings.Split(entries, ",") {
		lhs, rhs, ok := strings.Cut(raw, ":")
		if !ok {
			return "", fmt.Errorf("each entry must be value : verdict (got %q)", strings.TrimSpace(raw))
		}
		val := strings.TrimSpace(lhs)
		if val == "" {
			return "", fmt.Errorf("a verdict-map entry is missing its value")
		}
		if err := checkSafe("verdict-map value", val); err != nil {
			return "", err
		}
		verdict, err := vmapVerdict(strings.TrimSpace(rhs))
		if err != nil {
			return "", err
		}
		if quote {
			val = fmt.Sprintf("%q", val)
		}
		out = append(out, val+" : "+verdict)
	}
	return strings.Join(out, ", "), nil
}

// vmapVerdict validates one verdict on the right of a vmap entry.
func vmapVerdict(v string) (string, error) {
	switch v {
	case "accept", "drop", "continue", "return":
		return v, nil
	}
	if kw, target, ok := strings.Cut(v, " "); ok {
		kw, target = strings.TrimSpace(kw), strings.TrimSpace(target)
		if (kw == "jump" || kw == "goto") && identRe.MatchString(target) {
			return kw + " " + target, nil
		}
	}
	return "", fmt.Errorf("verdict %q must be accept, drop, continue, return, or jump/goto <chain>", v)
}

// checkSafe rejects a value carrying nft structural characters. label names the
// field for the message.
func checkSafe(label, value string) error {
	if i := strings.IndexAny(value, nftStructuralChars); i >= 0 {
		return fmt.Errorf("%s must not contain %q", label, string(value[i]))
	}
	return nil
}

// checkNumberOrHex accepts a decimal or 0x-hex whole number (nft mark/number).
func checkNumberOrHex(label, value string) error {
	v := strings.TrimSpace(value)
	if strings.HasPrefix(v, "0x") || strings.HasPrefix(v, "0X") {
		if _, err := strconv.ParseUint(v[2:], 16, 64); err == nil {
			return nil
		}
	} else if _, err := strconv.ParseUint(v, 10, 64); err == nil {
		return nil
	}
	return fmt.Errorf("%s must be a whole number (decimal or 0x-hex)", label)
}

// durationRe matches an nft time value: one or more number+unit segments, e.g.
// "30s", "10m", "1h", "1d", "1h30m". Emitted bare, so validated against the
// exact shape rather than only the structural deny-list.
var durationRe = regexp.MustCompile(`^([0-9]+[smhdw])+$`)

// checkDuration accepts an nft duration like 30s, 10m, 1h, 1d, 1h30m.
func checkDuration(label, value string) error {
	if !durationRe.MatchString(strings.TrimSpace(value)) {
		return fmt.Errorf("%s must be a duration like 30s, 10m, 1h or 1d", label)
	}
	return nil
}

// checkPort accepts a single port, an a-b range, or a comma list of those.
func checkPort(label, value string) error {
	for _, tok := range strings.Split(value, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(tok, "-")
		if _, err := strconv.Atoi(strings.TrimSpace(lo)); err != nil {
			return fmt.Errorf("%s must be a port number or range", label)
		}
		if isRange {
			if _, err := strconv.Atoi(strings.TrimSpace(hi)); err != nil {
				return fmt.Errorf("%s must be a port number or range", label)
			}
		}
	}
	return nil
}

// ── rendering ───────────────────────────────────────────────────────────────

// matchOps is the operator set this match offers, applying the documented
// default (== then !=) when a knob does not name its own. It is the single
// source both the editor (to present only sensible operators) and RenderMatch
// (to reject the rest) read.
func (m Match) matchOps() []string {
	if len(m.Ops) > 0 {
		return m.Ops
	}
	return []string{"==", "!="}
}

// RenderMatch turns a stored match into an nft expression fragment.
func RenderMatch(key, op, value string, _ Ctx) (string, error) {
	m, ok := matchByKey[key]
	if !ok {
		return "", fmt.Errorf("unknown match %q", key)
	}
	// A valueless match (e.g. the reverse-path check) is its expression alone —
	// no operator, no value.
	if m.Kind == KindNone {
		return m.Expr, nil
	}
	if err := checkSafe(m.Label, value); err != nil {
		return "", err
	}
	val := renderValue(value, m.Quote)
	if val == "" && m.Kind != KindNone {
		return "", fmt.Errorf("%s needs a value", m.Label)
	}
	op = strings.TrimSpace(op)
	if op == "" {
		op = "=="
	}
	// Reject an operator this field does not support (e.g. ip saddr > …) at the
	// model boundary, so it never reaches nft --check as a broken candidate.
	if !slices.Contains(m.matchOps(), op) {
		return "", fmt.Errorf("%s: operator %q not allowed here", m.Label, op)
	}
	switch op {
	case "==":
		return m.Expr + " " + val, nil
	case "!=":
		return m.Expr + " != " + val, nil
	default: // <, >, <=, >= — already checked against the field's allowed set
		return m.Expr + " " + op + " " + val, nil
	}
}

// renderValue formats a stored value: a single token is emitted bare, a comma
// list as an anonymous set { a, b }, matching how `nft list` prints them. A
// leading @ (a named-set reference) is always passed through untouched.
func renderValue(value string, quote bool) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "@") {
		return value
	}
	var toks []string
	for _, t := range strings.Split(value, ",") {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if quote && !strings.HasPrefix(t, "\"") {
			t = fmt.Sprintf("%q", t)
		}
		toks = append(toks, t)
	}
	if len(toks) == 0 {
		return ""
	}
	if len(toks) == 1 {
		return toks[0]
	}
	return "{ " + strings.Join(toks, ", ") + " }"
}

// RenderStatement turns a stored statement into an nft statement fragment.
func RenderStatement(key string, params map[string]string, ctx Ctx) (string, error) {
	s, ok := statementByKey[key]
	if !ok {
		return "", fmt.Errorf("unknown action %q", key)
	}
	return s.render(params, ctx)
}

// renderBanRate renders the kernel fail2ban statement: a per-source rate meter
// that, once a source exceeds the rate, adds it to a dynamic timeout set and
// drops the packet. A companion `saddr @<set> drop` rule (higher in the chain)
// blocks everything the set holds for the ban duration. The dynamic set itself
// is declared by the render layer via DynamicSet, so this only emits the rule.
func renderBanRate(p map[string]string, _ Ctx) (string, error) {
	set := strings.TrimSpace(p["set"])
	if !identRe.MatchString(set) {
		return "", fmt.Errorf("ban set name must be letters, digits and underscores")
	}
	saddr, suffix, err := banSaddr(p["family"])
	if err != nil {
		return "", err
	}
	rate := strings.TrimSpace(p["rate"])
	if _, err := strconv.Atoi(rate); err != nil {
		return "", fmt.Errorf("ban rate must be a whole number")
	}
	per := strings.TrimSpace(p["per"])
	if per == "" {
		per = "minute"
	}
	if !rateUnits[per] {
		return "", fmt.Errorf("ban rate unit %q is not second/minute/hour/day/week", per)
	}
	timeout := strings.TrimSpace(p["timeout"])
	if timeout == "" {
		timeout = "1h"
	}
	if err := checkDuration("ban timeout", timeout); err != nil {
		return "", err
	}
	// The meter name must be unique per table; deriving it from the set and family
	// keeps the v4 and v6 rules from colliding.
	var b strings.Builder
	fmt.Fprintf(&b, "meter %s_m%s { %s limit rate over %s/%s", set, suffix, saddr, rate, per)
	if burst := strings.TrimSpace(p["burst"]); burst != "" {
		if _, err := strconv.Atoi(burst); err != nil {
			return "", fmt.Errorf("ban burst must be a whole number")
		}
		b.WriteString(" burst " + burst + " packets")
	}
	fmt.Fprintf(&b, " } add @%s { %s timeout %s } drop", set, saddr, timeout)
	return b.String(), nil
}

// banSaddr maps the family param to its source-address expression and a family
// suffix (used to keep meter names unique).
func banSaddr(family string) (saddr, suffix string, err error) {
	switch strings.TrimSpace(family) {
	case "", "ip":
		return "ip saddr", "4", nil
	case "ip6":
		return "ip6 saddr", "6", nil
	default:
		return "", "", fmt.Errorf("ban family must be ip or ip6")
	}
}

// DynamicSet reports the dynamic timeout set a statement declares — its nft name
// and element type — so the render layer can emit the `set … { flags dynamic,
// timeout }` block. ok is false for every statement that declares no set.
func DynamicSet(key string, params map[string]string) (name, elemType string, ok bool) {
	if key != "ban.rate" {
		return "", "", false
	}
	name = strings.TrimSpace(params["set"])
	if !identRe.MatchString(name) {
		return "", "", false
	}
	elemType = "ipv4_addr"
	if strings.TrimSpace(params["family"]) == "ip6" {
		elemType = "ipv6_addr"
	}
	return name, elemType, true
}

// renderNatTo renders a dnat/snat `... to <addr>[:port]`, adding the family
// qualifier nft requires in the inet family (where a rule can carry either v4
// or v6 packets, so the NAT target's family must be stated).
func renderNatTo(verb string, p map[string]string, ctx Ctx) (string, error) {
	addr := strings.TrimSpace(p["addr"])
	if addr == "" {
		return "", fmt.Errorf("%s needs a target address", verb)
	}
	port := strings.TrimSpace(p["port"])
	if port != "" {
		if err := checkPort(verb+" port", port); err != nil {
			return "", err
		}
	}

	// The target must be a literal IP address: it is emitted bare into the rule
	// line, so anything else (a hostname, an expression, injected text) is
	// rejected rather than passed through.
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return "", fmt.Errorf("%s target must be an IP address", verb)
	}

	// Decide the family qualifier and address bracketing.
	qualifier := ""
	bracket := false
	if a.Is6() {
		bracket = true
		if ctx.Family == "inet" {
			qualifier = "ip6 "
		}
	} else if ctx.Family == "inet" {
		qualifier = "ip "
	}
	target := addr
	if bracket && port != "" {
		target = "[" + addr + "]"
	}
	if port != "" {
		target += ":" + port
	}
	return fmt.Sprintf("%s %sto %s", verb, qualifier, target), nil
}

// knobInfo is the per-knob metadata the rule-editor JS uses to annotate the
// form (help text, an example, and — for enum/flags — the explained choices).
type knobInfo struct {
	Help    string   `json:"help"`
	Example string   `json:"example"`
	Kind    string   `json:"kind,omitempty"`
	Options []Option `json:"options,omitempty"`
	// Ops are the operators this match offers, so the editor can present only the
	// ones that make sense for the field (== / != for an address; the full
	// ordered set for a port or TTL) instead of a fixed list that lets an operator
	// build a rule nft then rejects. Empty for statements.
	Ops []string `json:"ops,omitempty"`
}

// CatalogueJSON is the whole catalogue as compact JSON, keyed by knob id, for
// embedding in the rule-editor page.
func CatalogueJSON() string {
	ms := map[string]knobInfo{}
	for _, m := range matches {
		ms[m.Key] = knobInfo{Help: m.Help, Example: m.Example, Kind: kindName(m.Kind), Options: m.Options, Ops: m.matchOps()}
	}
	ss := map[string]knobInfo{}
	for _, s := range statements {
		ss[s.Key] = knobInfo{Help: s.Help, Example: s.Example}
	}
	b, err := json.Marshal(map[string]any{"matches": ms, "statements": ss})
	if err != nil {
		return "{}"
	}
	return string(b)
}

func kindName(k Kind) string {
	switch k {
	case KindEnum:
		return "enum"
	case KindFlags:
		return "flags"
	case KindInt:
		return "int"
	case KindPort:
		return "port"
	case KindIface:
		return "iface"
	case KindNone:
		return "none"
	default:
		return "text"
	}
}
