package render

import (
	"strings"
	"testing"

	"github.com/floreabogdan/nftably/internal/store"
)

// model builds a one-table model with a single input base chain carrying rules.
func model(policy string, rules ...store.ChainRule) Model {
	return Model{Tables: []TableTree{{
		Table: store.Table{Family: "inet", Name: "filter"},
		Chains: []ChainTree{{
			Chain: store.Chain{Name: "input", Kind: "base", Hook: "input", ChainType: "filter", Priority: "filter", Policy: policy},
			Rules: rules,
		}},
	}}}
}

func rule(comment string, matches []store.RuleMatch, stmts []store.RuleStatement) store.ChainRule {
	return store.ChainRule{Enabled: true, Comment: comment, Matches: matches, Statements: stmts}
}

func TestConfigRendersTableChainRule(t *testing.T) {
	m := model("drop", rule("ssh",
		[]store.RuleMatch{{Key: "tcp.dport", Op: "==", Value: "22"}},
		[]store.RuleStatement{{Key: "accept", Params: "{}"}},
	))
	out := Config(m)
	for _, want := range []string{
		"table inet filter {",
		"\tchain input {",
		"type filter hook input priority filter; policy drop;",
		`tcp dport 22 accept comment "nftably: ssh"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("config missing %q:\n%s", want, out)
		}
	}
}

func TestRenderRuleNegationAndSet(t *testing.T) {
	r := rule("block ranges",
		[]store.RuleMatch{{Key: "ip.saddr", Op: "!=", Value: "10.0.0.0/8, 192.168.0.0/16"}},
		[]store.RuleStatement{{Key: "drop", Params: "{}"}},
	)
	got, err := RenderRule("inet", r)
	if err != nil {
		t.Fatal(err)
	}
	want := `ip saddr != { 10.0.0.0/8, 192.168.0.0/16 } drop comment "nftably: block ranges"`
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestRenderRawRule(t *testing.T) {
	// A raw rule renders verbatim, with the comment appended, and its
	// matches/statements ignored.
	r := store.ChainRule{
		Enabled: true, Comment: "connlimit",
		Raw:        "ip saddr 10.0.0.0/8 ct count over 20 drop",
		Statements: []store.RuleStatement{{Key: "accept"}}, // ignored
	}
	got, err := RenderRule("inet", r)
	if err != nil {
		t.Fatal(err)
	}
	want := `ip saddr 10.0.0.0/8 ct count over 20 drop comment "nftably: connlimit"`
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestValidateRawRuleRejectsBreakouts(t *testing.T) {
	ok := []string{
		"ip saddr 1.2.3.4 drop",
		"tcp dport { 22, 80, 443 } accept",
	}
	for _, s := range ok {
		if _, err := ValidateRawRule(s); err != nil {
			t.Errorf("ValidateRawRule(%q) = %v, want ok", s, err)
		}
	}
	bad := []string{
		"",                              // empty
		"accept\ndrop",                  // line break
		"accept ; drop",                 // rule separator
		"drop # sneaky",                 // comment marker
		"accept } chain evil {",         // unbalanced brace (breakout attempt)
	}
	for _, s := range bad {
		if _, err := ValidateRawRule(s); err == nil {
			t.Errorf("ValidateRawRule(%q) accepted an unsafe line", s)
		}
	}
}

func TestRenderRuleDisabledSkipped(t *testing.T) {
	m := model("accept")
	m.Tables[0].Chains[0].Rules = []store.ChainRule{{
		Enabled: false, Comment: "off",
		Statements: []store.RuleStatement{{Key: "drop"}},
	}}
	if strings.Contains(Config(m), "drop") {
		t.Error("a disabled rule must not render")
	}
}

func TestBuildApplyFileMultiTable(t *testing.T) {
	tables := []TableTree{
		{Table: store.Table{Family: "inet", Name: "filter"}, Chains: []ChainTree{{Chain: store.Chain{Name: "input", Kind: "base", Hook: "input", ChainType: "filter", Priority: "filter", Policy: "accept"}}}},
	}
	remove := []store.TableRef{{Family: "ip", Name: "old"}}
	out := BuildApplyFile(tables, remove)
	for _, want := range []string{
		"table inet filter {}\n",
		"delete table inet filter\n",
		"table inet filter {\n",
		"table ip old {}\n",
		"delete table ip old\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("apply file missing %q:\n%s", want, out)
		}
	}
	// The removed table must NOT be recreated with a body.
	if strings.Contains(out, "table ip old {\n") {
		t.Error("removed table should only be deleted, not recreated")
	}
}

func TestBanRateRendersDynamicSet(t *testing.T) {
	// A drop-banned companion rule plus a detect-and-ban rule, as the SSH auto-ban
	// recipe builds them.
	m := model("drop",
		rule("drop banned",
			[]store.RuleMatch{{Key: "ip.saddr", Op: "==", Value: "@ssh_abusers"}},
			[]store.RuleStatement{{Key: "drop"}},
		),
		rule("rate-ban ssh",
			[]store.RuleMatch{{Key: "tcp.dport", Op: "==", Value: "22"}, {Key: "ct.state", Op: "==", Value: "new"}},
			[]store.RuleStatement{{Key: "ban.rate", Params: `{"set":"ssh_abusers","family":"ip","rate":"10","per":"minute","burst":"5","timeout":"1h"}`}},
		),
	)
	ResolveDynSets(&m)
	out := Config(m)
	for _, want := range []string{
		"\tset ssh_abusers {",
		"\t\ttype ipv4_addr",
		"\t\tflags dynamic, timeout",
		"ip saddr @ssh_abusers drop",
		"meter ssh_abusers_m4 { ip saddr limit rate over 10/minute burst 5 packets } add @ssh_abusers { ip saddr timeout 1h } drop",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// The dynamic set must be declared exactly once, even though two rules name it.
	if n := strings.Count(out, "set ssh_abusers {"); n != 1 {
		t.Errorf("dynamic set declared %d times, want 1:\n%s", n, out)
	}
}

func TestResolveAndRenderSets(t *testing.T) {
	m := model("accept", rule("from office",
		[]store.RuleMatch{{Key: "ip.saddr", Op: "==", Value: "@office4"}},
		[]store.RuleStatement{{Key: "accept"}},
	))
	lists := []ListWithEntries{{
		IPList:  store.IPList{Name: "office"},
		Entries: []store.ListEntry{{CIDR: "10.9.0.0/24"}, {CIDR: "10.1.0.0/16"}},
	}}
	ResolveSets(&m, lists)
	out := Config(m)
	for _, want := range []string{
		"\tset office4 {",
		"\t\ttype ipv4_addr",
		"\t\tflags interval",
		"elements = { 10.1.0.0/16, 10.9.0.0/24 }", // sorted ascending
		"ip saddr @office4 accept",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// A set referenced but never defined by a list must not crash or render.
	if strings.Contains(out, "office6") {
		t.Error("only the referenced v4 set should render")
	}
}

func TestBuildRevertFileRestoresAndDrops(t *testing.T) {
	snaps := []store.TableSnapshot{
		{Family: "inet", Name: "filter", Text: "table inet filter {\n\tchain input {\n\t}\n}\n", Exists: true},
		{Family: "inet", Name: "gone", Exists: false},
	}
	out := BuildRevertFile(snaps)
	if !strings.Contains(out, "table inet filter {\n\tchain input") {
		t.Error("revert must restore an existing table's captured text")
	}
	if strings.Contains(out, "table inet gone {\n\t") {
		t.Error("a table absent before must stay deleted on revert")
	}
}

func TestIngressChainRendersDevice(t *testing.T) {
	m := Model{Tables: []TableTree{{
		Table: store.Table{Family: "netdev", Name: "nd"},
		Chains: []ChainTree{{
			Chain: store.Chain{Name: "ingress", Kind: "base", Hook: "ingress", ChainType: "filter", Priority: "0", Policy: "drop", Device: "eth0"},
		}},
	}}}
	out := Config(m)
	if want := `type filter hook ingress device "eth0" priority 0;`; !strings.Contains(out, want) {
		t.Fatalf("ingress chain missing device clause:\n%s", out)
	}
}
