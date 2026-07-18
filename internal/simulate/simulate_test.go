package simulate

import (
	"net/netip"
	"testing"

	nftconf "github.com/floreabogdan/nftably/internal/render"
	"github.com/floreabogdan/nftably/internal/store"
)

// build a one-table, one-input-chain model with the given policy and rules.
func inputModel(policy string, rules ...store.ChainRule) nftconf.Model {
	return nftconf.Model{Tables: []nftconf.TableTree{{
		Table: store.Table{Family: "inet", Name: "filter"},
		Chains: []nftconf.ChainTree{{
			Chain: store.Chain{Name: "input", Kind: "base", Hook: "input", ChainType: "filter", Priority: "filter", Policy: policy},
			Rules: rules,
		}},
	}}}
}

func rule(matches []store.RuleMatch, verdict string) store.ChainRule {
	return store.ChainRule{Enabled: true, Matches: matches, Statements: []store.RuleStatement{{Key: verdict, Params: "{}"}}}
}

func addr(s string) netip.Addr { a, _ := netip.ParseAddr(s); return a }

func TestPolicyDropNoRules(t *testing.T) {
	tr := Simulate(inputModel("drop"), "input", Packet{Proto: "tcp", Dst: addr("10.0.0.1"), DPort: 22, Iif: "eth0"})
	if tr.Final != "DROP" {
		t.Fatalf("empty drop chain should DROP, got %s (%s)", tr.Final, tr.DecidedBy)
	}
}

func TestAcceptedByPortRule(t *testing.T) {
	m := inputModel("drop", rule([]store.RuleMatch{{Key: "tcp.dport", Op: "==", Value: "22"}}, "accept"))
	tr := Simulate(m, "input", Packet{Proto: "tcp", Src: addr("1.2.3.4"), Dst: addr("10.0.0.1"), DPort: 22})
	if tr.Final != "ACCEPT" {
		t.Fatalf("SSH should be accepted, got %s (%s)", tr.Final, tr.DecidedBy)
	}
}

func TestWrongProtoDoesNotMatchPortRule(t *testing.T) {
	// A tcp.dport 22 accept must not let a UDP packet to port 22 through a drop.
	m := inputModel("drop", rule([]store.RuleMatch{{Key: "tcp.dport", Op: "==", Value: "22"}}, "accept"))
	tr := Simulate(m, "input", Packet{Proto: "udp", Dst: addr("10.0.0.1"), DPort: 22})
	if tr.Final != "DROP" {
		t.Fatalf("UDP/22 should hit the drop policy, got %s (%s)", tr.Final, tr.DecidedBy)
	}
}

func TestSourceCidrMatch(t *testing.T) {
	m := inputModel("drop", rule([]store.RuleMatch{
		{Key: "ip.saddr", Op: "==", Value: "10.0.0.0/8"},
	}, "accept"))
	in := Simulate(m, "input", Packet{Proto: "tcp", Src: addr("10.9.9.9"), Dst: addr("10.0.0.1"), DPort: 22})
	if in.Final != "ACCEPT" {
		t.Fatalf("10.9.9.9 is in 10.0.0.0/8, expected ACCEPT, got %s", in.Final)
	}
	out := Simulate(m, "input", Packet{Proto: "tcp", Src: addr("192.168.1.1"), Dst: addr("10.0.0.1"), DPort: 22})
	if out.Final != "DROP" {
		t.Fatalf("192.168.1.1 is outside 10.0.0.0/8, expected DROP, got %s", out.Final)
	}
}

func TestNegationOperator(t *testing.T) {
	// Accept anything whose source is NOT 10.0.0.0/8.
	m := inputModel("drop", rule([]store.RuleMatch{
		{Key: "ip.saddr", Op: "!=", Value: "10.0.0.0/8"},
	}, "accept"))
	if tr := Simulate(m, "input", Packet{Proto: "tcp", Src: addr("8.8.8.8"), Dst: addr("10.0.0.1"), DPort: 1}); tr.Final != "ACCEPT" {
		t.Fatalf("8.8.8.8 != 10/8 should ACCEPT, got %s", tr.Final)
	}
	if tr := Simulate(m, "input", Packet{Proto: "tcp", Src: addr("10.0.0.5"), Dst: addr("10.0.0.1"), DPort: 1}); tr.Final != "DROP" {
		t.Fatalf("10.0.0.5 is 10/8, the != rule should not match → DROP, got %s", tr.Final)
	}
}

func TestFamilyMismatchDoesNotMatch(t *testing.T) {
	// An ip (v4) source match must not match a v6 packet.
	m := inputModel("drop", rule([]store.RuleMatch{{Key: "ip.saddr", Op: "==", Value: "10.0.0.0/8"}}, "accept"))
	tr := Simulate(m, "input", Packet{Proto: "tcp", Src: addr("2001:db8::1"), Dst: addr("2001:db8::2"), DPort: 22})
	if tr.Final != "DROP" {
		t.Fatalf("v6 packet vs v4 match should not accept, got %s", tr.Final)
	}
}

func TestEstablishedRelatedAccept(t *testing.T) {
	m := inputModel("drop", rule([]store.RuleMatch{{Key: "ct.state", Op: "==", Value: "established, related"}}, "accept"))
	tr := Simulate(m, "input", Packet{Proto: "tcp", Src: addr("8.8.8.8"), Dst: addr("10.0.0.1"), DPort: 443, CtState: "established"})
	if tr.Final != "ACCEPT" {
		t.Fatalf("established reply should ACCEPT, got %s (%s)", tr.Final, tr.DecidedBy)
	}
}

func TestRuleOrderFirstMatchWins(t *testing.T) {
	// An early blanket drop beats a later accept.
	m := inputModel("accept",
		rule([]store.RuleMatch{{Key: "ip.saddr", Op: "==", Value: "6.6.6.6"}}, "drop"),
		rule([]store.RuleMatch{{Key: "tcp.dport", Op: "==", Value: "22"}}, "accept"),
	)
	tr := Simulate(m, "input", Packet{Proto: "tcp", Src: addr("6.6.6.6"), Dst: addr("10.0.0.1"), DPort: 22})
	if tr.Final != "DROP" || tr.Chains[0].Rules[0].Outcome != "matched" {
		t.Fatalf("early drop should win, got %s (%s)", tr.Final, tr.DecidedBy)
	}
}

func TestIndeterminateMatchIsFlagged(t *testing.T) {
	// A rule keyed on something we don't simulate (tcp flags) → indeterminate,
	// and the trace is marked uncertain.
	m := inputModel("drop", rule([]store.RuleMatch{{Key: "tcp.flags", Op: "==", Value: "syn"}}, "accept"))
	tr := Simulate(m, "input", Packet{Proto: "tcp", Dst: addr("10.0.0.1"), DPort: 22})
	if !tr.Uncertain {
		t.Fatalf("a rule with an unmodelled match should mark the trace uncertain")
	}
	if tr.Chains[0].Rules[0].Outcome != "indeterminate" {
		t.Fatalf("expected indeterminate outcome, got %q", tr.Chains[0].Rules[0].Outcome)
	}
}

func TestJumpAndReturn(t *testing.T) {
	// input jumps to "checks"; checks drops 6.6.6.6, otherwise returns; input
	// then accepts SSH.
	m := nftconf.Model{Tables: []nftconf.TableTree{{
		Table: store.Table{Family: "inet", Name: "filter"},
		Chains: []nftconf.ChainTree{
			{
				Chain: store.Chain{Name: "input", Kind: "base", Hook: "input", ChainType: "filter", Priority: "filter", Policy: "drop"},
				Rules: []store.ChainRule{
					{Enabled: true, Statements: []store.RuleStatement{{Key: "jump", Params: `{"target":"checks"}`}}},
					rule([]store.RuleMatch{{Key: "tcp.dport", Op: "==", Value: "22"}}, "accept"),
				},
			},
			{
				Chain: store.Chain{Name: "checks", Kind: "regular"},
				Rules: []store.ChainRule{
					rule([]store.RuleMatch{{Key: "ip.saddr", Op: "==", Value: "6.6.6.6"}}, "drop"),
				},
			},
		},
	}}}
	// Bad source → the jumped chain drops it.
	if tr := Simulate(m, "input", Packet{Proto: "tcp", Src: addr("6.6.6.6"), Dst: addr("10.0.0.1"), DPort: 22}); tr.Final != "DROP" {
		t.Fatalf("6.6.6.6 should be dropped in the jumped chain, got %s (%s)", tr.Final, tr.DecidedBy)
	}
	// Good source → checks returns, input accepts SSH.
	if tr := Simulate(m, "input", Packet{Proto: "tcp", Src: addr("1.2.3.4"), Dst: addr("10.0.0.1"), DPort: 22}); tr.Final != "ACCEPT" {
		t.Fatalf("clean SSH should be accepted after the jump returns, got %s (%s)", tr.Final, tr.DecidedBy)
	}
}

func TestNamedSetMembership(t *testing.T) {
	// A rule accepting @mgmt4; resolve the set with one member.
	m := nftconf.Model{Tables: []nftconf.TableTree{{
		Table: store.Table{Family: "inet", Name: "filter"},
		Sets:  []nftconf.SetDef{{Name: "mgmt4", Type: "ipv4_addr", Elements: []string{"203.0.113.0/24"}}},
		Chains: []nftconf.ChainTree{{
			Chain: store.Chain{Name: "input", Kind: "base", Hook: "input", ChainType: "filter", Priority: "filter", Policy: "drop"},
			Rules: []store.ChainRule{rule([]store.RuleMatch{{Key: "ip.saddr", Op: "==", Value: "@mgmt4"}}, "accept")},
		}},
	}}}
	if tr := Simulate(m, "input", Packet{Proto: "tcp", Src: addr("203.0.113.9"), Dst: addr("10.0.0.1"), DPort: 22}); tr.Final != "ACCEPT" {
		t.Fatalf("address in @mgmt4 should ACCEPT, got %s (%s)", tr.Final, tr.DecidedBy)
	}
	if tr := Simulate(m, "input", Packet{Proto: "tcp", Src: addr("198.51.100.1"), Dst: addr("10.0.0.1"), DPort: 22}); tr.Final != "DROP" {
		t.Fatalf("address outside @mgmt4 should DROP, got %s (%s)", tr.Final, tr.DecidedBy)
	}
}

func TestNoChainOnHookAcceptsByDefault(t *testing.T) {
	tr := Simulate(inputModel("drop"), "output", Packet{Proto: "tcp", Dst: addr("8.8.8.8"), DPort: 53})
	if tr.Final != "accept" && tr.Final != "ACCEPT" {
		t.Fatalf("a hook with no base chain should default-accept, got %s", tr.Final)
	}
}
