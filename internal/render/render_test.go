package render

import (
	"strings"
	"testing"

	"github.com/floreabogdan/nftably/internal/store"
)

func TestConfigBaselineAndPolicy(t *testing.T) {
	out := Config(store.Firewall{InputPolicy: "drop"}, nil)

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
	if out := Config(store.Firewall{InputPolicy: "accept"}, nil); !strings.Contains(out, "policy accept;") {
		t.Errorf("accept policy not rendered:\n%s", out)
	}
	if out := Config(store.Firewall{}, nil); !strings.Contains(out, "policy drop;") {
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
	out := Config(store.Firewall{InputPolicy: "drop"}, rules)
	if !strings.Contains(out, "nftably: on") {
		t.Error("enabled rule missing")
	}
	if strings.Contains(out, "nftably: off") {
		t.Error("disabled rule should not render")
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
