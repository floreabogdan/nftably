package render

import (
	"strings"
	"testing"

	"github.com/floreabogdan/nftably/internal/store"
)

func TestConfigBaselineAndPolicy(t *testing.T) {
	out := Config(Model{FW: store.Firewall{InputPolicy: "drop"}})

	for _, want := range []string{
		"table inet nftably {",
		"type filter hook input priority filter; policy drop;",
		`iif "lo" accept`,
		"ct state invalid drop",
		"ct state established,related accept",
		"nd-neighbor-solicit",
		"icmp type {",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("config missing %q:\n%s", want, out)
		}
	}

	// An unknown policy falls back to drop; accept is honoured.
	if out := Config(Model{FW: store.Firewall{InputPolicy: "accept"}}); !strings.Contains(out, "policy accept;") {
		t.Errorf("accept policy not rendered:\n%s", out)
	}
	if out := Config(Model{}); !strings.Contains(out, "policy drop;") {
		t.Errorf("empty policy should render as drop:\n%s", out)
	}
}

func TestRuleLines(t *testing.T) {
	cases := []struct {
		name string
		r    store.Rule
		want []string
	}{
		{
			"single port, bare set",
			store.Rule{Name: "ssh", Action: "accept", Proto: "tcp", DPorts: "22", Enabled: true},
			[]string{`tcp dport 22 accept comment "nftably: ssh"`},
		},
		{
			"multiple ports and range",
			store.Rule{Action: "accept", Proto: "udp", DPorts: "53, 5000-5100", Enabled: true},
			[]string{`udp dport { 53, 5000-5100 } accept`},
		},
		{
			"proto without ports",
			store.Rule{Action: "drop", Proto: "tcp", Enabled: true},
			[]string{`meta l4proto tcp drop`},
		},
		{
			"interface and v4 source, host address bare",
			store.Rule{Action: "accept", Proto: "any", SAddrs: "192.0.2.7", IIf: "eth0", Enabled: true},
			[]string{`iifname "eth0" ip saddr 192.0.2.7 accept`},
		},
		{
			"mixed families split into two lines",
			store.Rule{Name: "mgmt", Action: "accept", Proto: "tcp", DPorts: "22", SAddrs: "10.0.0.0/8, 2001:db8::/32", Enabled: true},
			[]string{
				`ip saddr 10.0.0.0/8 tcp dport 22 accept comment "nftably: mgmt"`,
				`ip6 saddr 2001:db8::/32 tcp dport 22 accept comment "nftably: mgmt"`,
			},
		},
		{
			"reject with no matches at all",
			store.Rule{Action: "reject", Proto: "any", Enabled: true},
			[]string{`reject`},
		},
	}
	for _, c := range cases {
		got := Model{}.RuleLines(c.r)
		if len(got) != len(c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: line %d = %q, want %q", c.name, i, got[i], c.want[i])
			}
		}
	}
}

func TestConfigSkipsDisabledRules(t *testing.T) {
	rules := []store.Rule{
		{Name: "on", Action: "accept", Proto: "tcp", DPorts: "22", Enabled: true},
		{Name: "off", Action: "accept", Proto: "tcp", DPorts: "23", Enabled: false},
	}
	out := Config(Model{FW: store.Firewall{InputPolicy: "drop"}, Rules: rules})
	if !strings.Contains(out, "nftably: on") {
		t.Error("enabled rule missing")
	}
	if strings.Contains(out, "nftably: off") {
		t.Error("disabled rule should not render")
	}
}

func TestConfigForwarding(t *testing.T) {
	// No WAN interface: no forward, no nat — the M3 output, byte for byte.
	out := Config(Model{FW: store.Firewall{InputPolicy: "drop", Masquerade: false}, Forwards: []store.PortForward{
		{Proto: "tcp", DPort: "80", Dest: "10.0.0.2", Enabled: true},
	}})
	for _, absent := range []string{"chain forward", "chain prerouting", "chain postrouting", "dnat"} {
		if strings.Contains(out, absent) {
			t.Errorf("forwarding rendered without a WAN interface (%q):\n%s", absent, out)
		}
	}

	fw := store.Firewall{InputPolicy: "drop", ForwardPolicy: "drop", WANIface: "eth0", Masquerade: true}
	rules := []store.Rule{
		{Name: "no-iot-internet", Chain: "forward", Action: "drop", Proto: "any", SAddrs: "192.168.66.0/24", Enabled: true},
		{Name: "ssh", Chain: "input", Action: "accept", Proto: "tcp", DPorts: "22", Enabled: true},
	}
	pfs := []store.PortForward{
		{Name: "web", Proto: "tcp", DPort: "80", Dest: "10.0.0.2", DestPort: "8080", Enabled: true},
		{Name: "off", Proto: "tcp", DPort: "81", Dest: "10.0.0.3", Enabled: false},
		{Name: "game", Proto: "udp", DPort: "27000-27100", Dest: "10.0.0.4", Enabled: true},
		{Name: "v6", Proto: "tcp", DPort: "443", Dest: "2001:db8::10", DestPort: "8443", Enabled: true},
	}
	out = Config(Model{FW: fw, Rules: rules, Forwards: pfs})

	for _, want := range []string{
		"type filter hook forward priority filter; policy drop;",
		"ct status dnat accept comment \"nftably:baseline port-forwards\"",
		`ip saddr 192.168.66.0/24 drop comment "nftably: no-iot-internet"`,
		`iifname != "eth0" oifname "eth0" accept comment "nftably:baseline lan-wan"`,
		"type nat hook prerouting priority dstnat; policy accept;",
		`iifname "eth0" tcp dport 80 dnat ip to 10.0.0.2:8080 comment "nftably: web"`,
		`iifname "eth0" udp dport 27000-27100 dnat ip to 10.0.0.4 comment "nftably: game"`,
		`iifname "eth0" tcp dport 443 dnat ip6 to [2001:db8::10]:8443 comment "nftably: v6"`,
		"type nat hook postrouting priority srcnat; policy accept;",
		`oifname "eth0" masquerade comment "nftably:baseline masquerade"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("forwarding config missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "dport 81") {
		t.Error("disabled port-forward rendered")
	}

	// The forward drop rule must land in the forward chain, not input, and
	// before the lan-wan accept so it can actually cut that subnet off.
	fwdChain := out[strings.Index(out, "chain forward"):strings.Index(out, "chain prerouting")]
	if !strings.Contains(fwdChain, "no-iot-internet") {
		t.Errorf("forward rule not in forward chain:\n%s", out)
	}
	if strings.Index(fwdChain, "no-iot-internet") > strings.Index(fwdChain, "lan-wan") {
		t.Errorf("forward rule rendered after the lan-wan accept:\n%s", fwdChain)
	}
	inputChain := out[strings.Index(out, "chain input"):strings.Index(out, "chain forward")]
	if strings.Contains(inputChain, "no-iot-internet") {
		t.Errorf("forward rule leaked into input chain:\n%s", inputChain)
	}

	// No enabled forwards and no masquerade: forward chain only.
	out = Config(Model{FW: store.Firewall{WANIface: "eth0"}})
	if !strings.Contains(out, "chain forward") {
		t.Error("forward chain missing with WAN set")
	}
	if strings.Contains(out, "chain prerouting") || strings.Contains(out, "chain postrouting") {
		t.Errorf("nat chains rendered with nothing to put in them:\n%s", out)
	}
}

func TestConfigLists(t *testing.T) {
	// Role lists without entries and unreferenced plain lists render nothing
	// — a fresh install's seeded (empty) lists leave the config untouched.
	out := Config(Model{FW: store.Firewall{InputPolicy: "drop"}, Lists: []ListWithEntries{
		{IPList: store.IPList{ID: 1, Name: "management", Role: store.RoleAllow}},
		{IPList: store.IPList{ID: 2, Name: "blacklist", Role: store.RoleBlock}},
		{IPList: store.IPList{ID: 3, Name: "office"}, Entries: []store.ListEntry{{CIDR: "10.9.0.0/24"}}},
	}})
	if strings.Contains(out, "set ") || strings.Contains(out, "@") {
		t.Errorf("empty/unreferenced lists rendered:\n%s", out)
	}

	m := Model{
		FW: store.Firewall{InputPolicy: "drop", WANIface: "eth0"},
		Lists: []ListWithEntries{
			{IPList: store.IPList{ID: 1, Name: "mgmt", Role: store.RoleAllow},
				Entries: []store.ListEntry{{CIDR: "10.0.0.0/24"}, {CIDR: "2001:db8::5"}}},
			{IPList: store.IPList{ID: 2, Name: "badguys", Role: store.RoleBlock},
				// Added out of order: the set must print numerically
				// ascending, the way nft lists it back.
				Entries: []store.ListEntry{{CIDR: "203.0.113.9"}, {CIDR: "198.51.100.0/24"}, {CIDR: "203.0.113.1"}}},
			{IPList: store.IPList{ID: 3, Name: "office"},
				Entries: []store.ListEntry{{CIDR: "10.9.0.0/24"}}},
		},
		Rules: []store.Rule{
			{Name: "ssh office", Action: "accept", Proto: "tcp", DPorts: "22", SrcListID: 3, Enabled: true},
		},
	}
	out = Config(m)

	// Exact canonical set block, verified against nft 1.0.9 output: elements
	// two per line, continuations aligned under the opening brace.
	wantBlock4 := "\tset badguys4 {\n" +
		"\t\ttype ipv4_addr\n" +
		"\t\tflags interval\n" +
		"\t\telements = { 198.51.100.0/24, 203.0.113.1,\n" +
		"\t\t\t     203.0.113.9 }\n" +
		"\t}\n\n"
	if !strings.Contains(out, wantBlock4) {
		t.Errorf("badguys4 set not canonical:\n%s", out)
	}
	for _, want := range []string{
		"\tset mgmt4 {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\telements = { 10.0.0.0/24 }\n\t}\n",
		"\tset mgmt6 {\n\t\ttype ipv6_addr\n\t\tflags interval\n\t\telements = { 2001:db8::5 }\n\t}\n",
		`ip saddr @mgmt4 accept comment "nftably:list mgmt"`,
		`ip6 saddr @mgmt6 accept comment "nftably:list mgmt"`,
		`ip saddr @badguys4 drop comment "nftably:list badguys"`,
		// The plain list renders through the rule that uses it — both
		// families, referencing its sets.
		`ip saddr @office4 tcp dport 22 accept comment "nftably: ssh office"`,
		`ip6 saddr @office6 tcp dport 22 accept comment "nftably: ssh office"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("lists config missing %q:\n%s", want, out)
		}
	}
	// A referenced list declares both family sets, even the empty one.
	if !strings.Contains(out, "\tset office6 {\n\t\ttype ipv6_addr\n\t\tflags interval\n\t}\n") {
		t.Errorf("office6 empty set not declared:\n%s", out)
	}
	// A block list with no v6 entries and no referencing rule has no v6 set.
	if strings.Contains(out, "set badguys6") || strings.Contains(out, "@badguys6") {
		t.Error("badguys6 rendered with no v6 entries")
	}

	// Ordering inside input: allow accept before block drop, block drop
	// before the established accept (so blocking cuts live connections).
	input := out[strings.Index(out, "chain input"):strings.Index(out, "chain forward")]
	iMgmt := strings.Index(input, "@mgmt4 accept")
	iBlock := strings.Index(input, "@badguys4 drop")
	iEst := strings.Index(input, "established,related accept")
	if iMgmt >= iBlock || iBlock >= iEst {
		t.Errorf("list rule order wrong (mgmt=%d block=%d est=%d):\n%s", iMgmt, iBlock, iEst, input)
	}
	// And the forward chain carries the same role lines.
	forward := out[strings.Index(out, "chain forward"):]
	if !strings.Contains(forward, "@mgmt4 accept") || !strings.Contains(forward, "@badguys4 drop") {
		t.Errorf("forward chain missing list rules:\n%s", forward)
	}

	// A dangling source list renders nothing (lint reports it).
	dangling := Model{Rules: []store.Rule{{Name: "ghost", Action: "accept", Proto: "tcp", DPorts: "1", SrcListID: 99, Enabled: true}}}
	if got := Config(dangling); strings.Contains(got, "ghost") {
		t.Errorf("dangling list reference rendered:\n%s", got)
	}
}

func TestDiff(t *testing.T) {
	oldText := "a\nb\nc\nd\n"
	newText := "a\nB\nc\nd\ne\n"
	hs := Diff(oldText, newText, 1)
	if len(hs) == 0 {
		t.Fatal("expected hunks")
	}
	added, removed := Stat(hs)
	if added != 2 || removed != 1 {
		t.Fatalf("stat = +%d -%d, want +2 -1", added, removed)
	}
	if Diff("same\n", "same\n", 3) != nil {
		t.Fatal("identical texts should produce no hunks")
	}
	// Everything-new: the whole candidate is one added hunk.
	hs = Diff("", "x\ny\n", 3)
	if len(hs) != 1 || hs[0].NewCount != 2 || hs[0].OldCount != 0 {
		t.Fatalf("all-new diff: %+v", hs)
	}
}
