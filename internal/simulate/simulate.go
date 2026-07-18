// Package simulate answers the question a firewall editor should be able to
// answer before you apply anything: "if this packet arrives, what happens to
// it?" It walks a candidate model the same way netfilter walks the live
// ruleset — base chains on a hook in priority order, rules top to bottom,
// following jump/goto — and returns a step-by-step trace ending in a verdict.
//
// It is deliberately honest about its limits. Matches it does not model (marks,
// tcp flags, icmp types, ttl…) make a rule *indeterminate* rather than silently
// matching or not, and the trace flags when such a rule could have changed the
// outcome. The evaluation is pure Go over the model — no kernel, no nft — so it
// runs on any host and needs no privilege.
package simulate

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	nftconf "github.com/floreabogdan/nftably/internal/render"
	"github.com/floreabogdan/nftably/internal/store"
)

// Packet is the synthetic packet to trace. Zero-value fields are treated as
// "unspecified": a match that needs an unspecified field is indeterminate.
type Packet struct {
	Proto   string     // tcp | udp | icmp | icmpv6 | "" (unspecified)
	Src     netip.Addr // source address (may be invalid = unspecified)
	Dst     netip.Addr // destination address
	SPort   int        // source port (0 = unspecified)
	DPort   int        // destination port
	Iif     string     // ingress interface name
	Oif     string     // egress interface name
	CtState string     // new | established | related | invalid | untracked | ""
}

// verdict values a rule or chain can reach.
const (
	Accept   = "accept"
	Drop     = "drop"
	Reject   = "reject"
	Continue = "continue"
	Return   = "return"
)

// RuleTrace is one rule as the packet saw it.
type RuleTrace struct {
	Index   int    // 1-based position within its chain
	Preview string // the rendered nft line
	Comment string
	// Outcome: "matched" (all conditions held), "skipped" (a condition failed),
	// or "indeterminate" (a condition could not be simulated).
	Outcome string
	Verdict string // the verdict taken, when matched (may be a jump/goto note)
	Reason  string // why it was skipped, or which knob was indeterminate
}

// ChainTrace is the evaluation of one base chain (plus any chains it jumped to).
type ChainTrace struct {
	Table    string
	Chain    string
	Hook     string
	Priority string
	Policy   string
	Rules    []RuleTrace
	Result   string // human summary of how this chain resolved
}

// Trace is the whole simulation.
type Trace struct {
	Hook      string
	Chains    []ChainTrace
	Final     string   // ACCEPT | DROP | REJECT
	DecidedBy string   // which rule or policy decided it
	Uncertain bool     // an indeterminate rule could have changed the outcome
	Notes     []string // scope caveats worth showing the operator
}

// matchResult is the three-valued outcome of one condition.
type matchResult int

const (
	no matchResult = iota
	yes
	unknown
)

// Simulate traces pkt through every filter base chain on hook, in priority
// order, and returns the verdict. It treats accept as "delivered" (it does not
// model a packet continuing to a lower-priority base chain after an accept) —
// which is exactly the question an operator asks of a single host's input
// filter. drop/reject are final.
func Simulate(m nftconf.Model, hook string, pkt Packet) Trace {
	tr := Trace{Hook: hook}

	chains := baseChainsOnHook(m, hook, pkt)
	if len(chains) == 0 {
		tr.Final = "ACCEPT"
		tr.DecidedBy = "no base chain hooks " + hook + " — nftables lets the packet through by default"
		return tr
	}
	tr.Notes = append(tr.Notes,
		"Simulates filter base chains on this hook, in priority order; accept is treated as delivered and drop/reject as final.")

	for _, bc := range chains {
		ct := ChainTrace{
			Table: bc.table.Name, Chain: bc.chain.Name, Hook: bc.chain.Hook,
			Priority: bc.chain.Priority, Policy: bc.chain.Policy,
		}
		ev := &eval{model: m, table: bc.table, pkt: pkt}
		verdict, decidedBy := ev.walk(bc.chain, &ct.Rules, 0)
		if verdict == "" || verdict == Continue || verdict == Return {
			// Fell through to the chain's policy.
			policy := bc.chain.Policy
			if policy == "" {
				policy = Accept
			}
			verdict = policy
			ct.Result = "no rule decided — chain policy is " + policy
			decidedBy = fmt.Sprintf("policy %s on chain %s", policy, bc.chain.Name)
		} else {
			ct.Result = "decided: " + verdict
		}
		tr.Chains = append(tr.Chains, ct)
		if ev.uncertain {
			tr.Uncertain = true
		}

		switch verdict {
		case Drop:
			tr.Final, tr.DecidedBy = "DROP", decidedBy
			return tr
		case Reject:
			tr.Final, tr.DecidedBy = "REJECT", decidedBy
			return tr
		case Accept:
			tr.Final, tr.DecidedBy = "ACCEPT", decidedBy
			return tr
		}
	}

	// Every chain fell through to an accept policy.
	tr.Final = "ACCEPT"
	tr.DecidedBy = "all base chains fell through to an accept policy"
	return tr
}

// baseChain pairs a chain with its owning table, for priority sorting.
type baseChain struct {
	table nftconf.TableTree
	chain nftconf.ChainTree
}

// baseChainsOnHook returns the filter base chains on a hook, lowest priority
// first (the order netfilter runs them) — skipping tables whose family can't
// carry the packet (an ip6 table never sees an IPv4 packet, and vice-versa).
func baseChainsOnHook(m nftconf.Model, hook string, pkt Packet) []baseChain {
	var out []baseChain
	for _, t := range m.Tables {
		if !tableHandlesPacket(t.Family, pkt) {
			continue
		}
		for _, c := range t.Chains {
			if c.IsBase() && c.Hook == hook && c.ChainType != "nat" {
				out = append(out, baseChain{table: t, chain: c})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return priorityValue(out[i].chain.Priority) < priorityValue(out[j].chain.Priority)
	})
	return out
}

// tableHandlesPacket reports whether a table of the given family would ever see
// this packet: an ip table only IPv4, ip6 only IPv6, inet/bridge/netdev both,
// arp never (the simulator models IP packets). When the packet's family is
// unspecified (no addresses given), every IP-capable family is kept.
func tableHandlesPacket(family string, pkt Packet) bool {
	is6, known := packetIsV6(pkt)
	switch family {
	case "ip":
		return !known || !is6
	case "ip6":
		return !known || is6
	case "arp":
		return false
	default: // inet, bridge, netdev
		return true
	}
}

// packetIsV6 reports the packet's address family, preferring the destination.
// known is false when neither address is set.
func packetIsV6(pkt Packet) (is6, known bool) {
	if pkt.Dst.IsValid() {
		return pkt.Dst.Is6(), true
	}
	if pkt.Src.IsValid() {
		return pkt.Src.Is6(), true
	}
	return false, false
}

// eval carries the per-simulation state as chains are walked (jump/goto recurse).
type eval struct {
	model     nftconf.Model
	table     nftconf.TableTree
	pkt       Packet
	uncertain bool
	depth     int
}

// walk evaluates a chain's rules in order, appending a RuleTrace for each, and
// returns the verdict the chain reached (or "" to fall through) plus a
// human description of what decided it.
func (e *eval) walk(chain nftconf.ChainTree, out *[]RuleTrace, depth int) (verdict, decidedBy string) {
	if depth > 16 {
		e.uncertain = true
		return "", "" // jump/goto nesting too deep to follow — bail safely
	}
	rules := chain.Rules
	for i, r := range rules {
		if !r.Enabled {
			continue
		}
		rt := RuleTrace{Index: i + 1, Comment: strings.TrimSpace(r.Comment)}
		if line, err := nftconf.RenderRule(e.table.Family, r); err == nil {
			rt.Preview = line
		}

		res, why := e.matchRule(r)
		switch res {
		case no:
			rt.Outcome, rt.Reason = "skipped", why
			*out = append(*out, rt)
			continue
		case unknown:
			rt.Outcome, rt.Reason = "indeterminate", why
			e.uncertain = true
			*out = append(*out, rt)
			continue
		}

		// All conditions held — take the rule's verdict.
		v, target, note := ruleVerdict(r)
		rt.Outcome = "matched"
		switch v {
		case Accept, Drop, Reject:
			rt.Verdict = v
			*out = append(*out, rt)
			return v, fmt.Sprintf("rule %d in chain %s (%s)", i+1, chain.Name, v)
		case "jump":
			rt.Verdict = "jump " + target
			*out = append(*out, rt)
			if tc, ok := findChain(e.table, target); ok {
				sub, by := e.walk(tc, out, depth+1)
				if sub == Accept || sub == Drop || sub == Reject {
					return sub, by
				}
				// The jumped chain returned/fell through — keep going here.
				continue
			}
			e.uncertain = true
			rt.Reason = "jump target not found"
			continue
		case "goto":
			rt.Verdict = "goto " + target
			*out = append(*out, rt)
			if tc, ok := findChain(e.table, target); ok {
				sub, by := e.walk(tc, out, depth+1)
				return sub, by // goto does not return to this chain
			}
			e.uncertain = true
			rt.Reason = "goto target not found"
			return "", ""
		case Return:
			rt.Verdict = "return"
			*out = append(*out, rt)
			return Return, ""
		default:
			// A non-verdict action (log, counter, mark, nat…): the rule matched
			// but does not decide the packet — evaluation continues.
			rt.Verdict = note
			*out = append(*out, rt)
			continue
		}
	}
	return "", ""
}

// matchRule reports whether every condition on a rule holds for the packet.
// A definitive failure short-circuits to no; an unmodelled condition (with all
// others holding) yields unknown.
func (e *eval) matchRule(r store.ChainRule) (matchResult, string) {
	anyUnknown, unknownWhy := false, ""
	for _, m := range r.Matches {
		switch e.matchOne(m) {
		case no:
			return no, describeMiss(m)
		case unknown:
			anyUnknown, unknownWhy = true, "condition not simulated: "+m.Key
		}
	}
	if anyUnknown {
		return unknown, unknownWhy
	}
	return yes, ""
}
