// Command nftcheck renders every knob in the catalogue (and a set of tweak
// variations) into a minimal, appropriately-scoped nftables ruleset and prints
// each as a delimited block on stdout. scripts/validate-catalogue.sh pipes these
// into a disposable, network-isolated nftables container and applies each, so a
// real kernel — not just `nft -c` — validates what nftably emits.
//
// Output format, one block per candidate:
//
//	@@@<name>
//	<ruleset text>
//	@@@END
//
// This is a developer tool, not part of the shipped binary. Run the whole check
// with: scripts/validate-catalogue.sh
package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/floreabogdan/nftably/internal/nftcat"
	nftconf "github.com/floreabogdan/nftably/internal/render"
	"github.com/floreabogdan/nftably/internal/store"
)

// firstToken returns the first value of a range/list example ("1024-65535" →
// "1024"), for testing ordered operators that need a single value.
func firstToken(s string) string {
	if i := strings.IndexAny(s, "-, "); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

// ctx is the table/chain a knob is rendered into. Each knob needs a context nft
// accepts — NAT statements need a nat chain at the right hook, owner matches need
// an output chain, and so on.
type ctx struct {
	family, hook, ctype, prio, policy string
	extra                             []store.RuleMatch
	regular                           bool // also declare a regular chain "t" (jump/goto target)
}

func mt(k, op, v string) store.RuleMatch { return store.RuleMatch{Key: k, Op: op, Value: v} }

func stmt(k string, p map[string]string) store.RuleStatement {
	b, _ := json.Marshal(p)
	return store.RuleStatement{Key: k, Params: string(b)}
}

func base() ctx {
	return ctx{family: "inet", hook: "input", ctype: "filter", prio: "filter", policy: "drop"}
}

func matchCtx(m nftcat.Match) ctx {
	c := base()
	switch m.Key {
	case "meta.skuid", "meta.skgid": // socket owner: locally-generated traffic
		c.hook, c.policy = "output", "accept"
	case "meta.oifname": // outgoing interface: meaningful past routing
		c.hook = "forward"
	}
	return c
}

func stmtCtx(key string) ctx {
	c := base()
	switch key {
	case "dnat", "redirect":
		return ctx{family: "inet", hook: "prerouting", ctype: "nat", prio: "dstnat", policy: "accept",
			extra: []store.RuleMatch{mt("tcp.dport", "==", "443")}} // a port map needs a transport match
	case "snat", "masquerade":
		return ctx{family: "inet", hook: "postrouting", ctype: "nat", prio: "srcnat", policy: "accept"}
	case "notrack":
		return ctx{family: "inet", hook: "prerouting", ctype: "filter", prio: "raw", policy: "accept"}
	case "synproxy":
		c.extra = []store.RuleMatch{mt("tcp.dport", "==", "80"), mt("ct.state", "==", "new")}
	case "tcp.mss.clamp":
		c.hook = "forward"
		c.extra = []store.RuleMatch{mt("tcp.flags", "==", "syn")}
	case "ban.rate":
		c.extra = []store.RuleMatch{mt("tcp.dport", "==", "22"), mt("ct.state", "==", "new")}
	case "jump", "goto":
		c.regular = true
	}
	return c
}

// stmtParams supplies representative params per statement.
func stmtParams(key string) map[string]string {
	switch key {
	case "reject":
		return map[string]string{"with": "tcp reset"}
	case "jump", "goto":
		return map[string]string{"target": "t"}
	case "log":
		return map[string]string{"prefix": "x ", "level": "info"}
	case "limit":
		return map[string]string{"rate": "10", "per": "minute", "burst": "5"}
	case "meta.mark.set", "ct.mark.set":
		return map[string]string{"value": "0x1"}
	case "dnat":
		return map[string]string{"addr": "192.168.1.10", "port": "80"}
	case "snat":
		return map[string]string{"addr": "203.0.113.1"}
	case "redirect":
		return map[string]string{"port": "3128"}
	case "synproxy":
		return map[string]string{"mss": "1460", "wscale": "7"}
	case "tcp.mss.clamp":
		return map[string]string{"size": "rt mtu"}
	case "quota":
		return map[string]string{"dir": "over", "amount": "500", "unit": "mbytes"}
	case "queue":
		return map[string]string{"num": "0", "bypass": "bypass"}
	case "ban.rate":
		return map[string]string{"set": "abusers", "family": "ip", "rate": "10", "per": "minute", "burst": "5", "timeout": "1h"}
	}
	return map[string]string{}
}

func render(c ctx, rule store.ChainRule) string {
	if c.policy == "" {
		c.policy = "accept"
	}
	chains := []nftconf.ChainTree{{
		Chain: store.Chain{Name: "c", Kind: "base", Hook: c.hook, ChainType: c.ctype, Priority: c.prio, Policy: c.policy},
		Rules: []store.ChainRule{rule},
	}}
	if c.regular {
		chains = append(chains, nftconf.ChainTree{
			Chain: store.Chain{Name: "t", Kind: "regular"},
			Rules: []store.ChainRule{{Enabled: true, Statements: []store.RuleStatement{{Key: "return", Params: "{}"}}}},
		})
	}
	m := nftconf.Model{Tables: []nftconf.TableTree{{Table: store.Table{Family: c.family, Name: "t1"}, Chains: chains}}}
	nftconf.ResolveDynSets(&m)
	nftconf.ResolveSets(&m, nil)
	return nftconf.Config(m)
}

func emit(name, cfg string) { fmt.Printf("@@@%s\n%s@@@END\n", name, cfg) }

func main() {
	acc := []store.RuleStatement{{Key: "accept", Params: "{}"}}

	// Every match knob, with each operator it offers.
	for _, m := range nftcat.Matches() {
		ops := m.Ops
		if len(ops) == 0 {
			ops = []string{"=="}
		}
		for _, op := range ops {
			c := matchCtx(m)
			// An ordered comparison (< > <= >=) is only meaningful against a single
			// value — the field's example may be a range or list (fine for ==), so
			// use its first token for the ordered operators.
			val := m.Example
			if op != "==" && op != "!=" {
				val = firstToken(m.Example)
			}
			matches := append(append([]store.RuleMatch{}, c.extra...), mt(m.Key, op, val))
			label := "match:" + m.Key
			if op != "==" {
				label = "match(" + op + "):" + m.Key
			}
			emit(label, render(c, store.ChainRule{Enabled: true, Matches: matches, Statements: acc}))
		}
	}

	// Every statement knob.
	for _, s := range nftcat.Statements() {
		c := stmtCtx(s.Key)
		emit("stmt:"+s.Key, render(c, store.ChainRule{Enabled: true, Matches: c.extra,
			Statements: []store.RuleStatement{stmt(s.Key, stmtParams(s.Key))}}))
	}

	// Tweak dimensions: multiport lists, flag sets, non-default families, a
	// named-set reference, and realistic combined rules.
	emit("tweak:multiport", render(base(), store.ChainRule{Enabled: true,
		Matches: []store.RuleMatch{mt("tcp.dport", "==", "22, 80, 443")}, Statements: acc}))
	emit("tweak:flagset", render(base(), store.ChainRule{Enabled: true,
		Matches: []store.RuleMatch{mt("ct.state", "==", "new, established, related")}, Statements: acc}))
	emit("tweak:ip-family", render(ctx{family: "ip", hook: "input", ctype: "filter", prio: "filter", policy: "drop"},
		store.ChainRule{Enabled: true, Matches: []store.RuleMatch{mt("ip.saddr", "==", "10.0.0.0/8")}, Statements: acc}))
	emit("tweak:ip6-family", render(ctx{family: "ip6", hook: "input", ctype: "filter", prio: "filter", policy: "drop"},
		store.ChainRule{Enabled: true, Matches: []store.RuleMatch{mt("ip6.saddr", "==", "2001:db8::/32")}, Statements: acc}))
	emit("tweak:combo-ssh", render(base(), store.ChainRule{Enabled: true,
		Matches: []store.RuleMatch{mt("ip.saddr", "==", "192.168.0.0/16"), mt("tcp.dport", "==", "22"), mt("ct.state", "==", "new")},
		Statements: []store.RuleStatement{stmt("limit", map[string]string{"rate": "10", "per": "minute", "burst": "5"}), stmt("log", map[string]string{"prefix": "ssh "}), {Key: "accept", Params: "{}"}}}))

	// A named-set reference needs a backing list to render its set block.
	{
		m := nftconf.Model{Tables: []nftconf.TableTree{{Table: store.Table{Family: "inet", Name: "t1"},
			Chains: []nftconf.ChainTree{{Chain: store.Chain{Name: "c", Kind: "base", Hook: "input", ChainType: "filter", Priority: "filter", Policy: "drop"},
				Rules: []store.ChainRule{{Enabled: true, Matches: []store.RuleMatch{mt("ip.saddr", "==", "@office4")}, Statements: acc}}}}}}}
		nftconf.ResolveDynSets(&m)
		nftconf.ResolveSets(&m, []nftconf.ListWithEntries{{IPList: store.IPList{Name: "office"}, Entries: []store.ListEntry{{CIDR: "10.9.0.0/24"}, {CIDR: "10.1.0.0/16"}}}})
		emit("tweak:namedset", nftconf.Config(m))
	}
}
