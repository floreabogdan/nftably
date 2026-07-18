package render

import (
	"strings"
	"testing"

	"github.com/floreabogdan/nftably/internal/store"
)

func TestConfigBaselineAndPolicy(t *testing.T) {
	out := Config(store.Firewall{InputPolicy: "drop"}, nil, nil)

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
	if out := Config(store.Firewall{InputPolicy: "accept"}, nil, nil); !strings.Contains(out, "policy accept;") {
		t.Errorf("accept policy not rendered:\n%s", out)
	}
	if out := Config(store.Firewall{}, nil, nil); !strings.Contains(out, "policy drop;") {
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
		got := RuleLines(c.r)
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
	out := Config(store.Firewall{InputPolicy: "drop"}, rules, nil)
	if !strings.Contains(out, "nftably: on") {
		t.Error("enabled rule missing")
	}
	if strings.Contains(out, "nftably: off") {
		t.Error("disabled rule should not render")
	}
}

func TestConfigForwarding(t *testing.T) {
	// No WAN interface: no forward, no nat — the M3 output, byte for byte.
	out := Config(store.Firewall{InputPolicy: "drop", Masquerade: false}, nil, []store.PortForward{
		{Proto: "tcp", DPort: "80", Dest: "10.0.0.2", Enabled: true},
	})
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
	out = Config(fw, rules, pfs)

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
	out = Config(store.Firewall{WANIface: "eth0"}, nil, nil)
	if !strings.Contains(out, "chain forward") {
		t.Error("forward chain missing with WAN set")
	}
	if strings.Contains(out, "chain prerouting") || strings.Contains(out, "chain postrouting") {
		t.Errorf("nat chains rendered with nothing to put in them:\n%s", out)
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
