package nft

import (
	"context"
	"encoding/json"
	"strings"
)

// RuleCounter is the packet/byte tally a rule accumulates while it carries a
// `counter` statement. Present is false for a rule that has no counter, so the
// UI can tell "0 packets" apart from "not counting".
type RuleCounter struct {
	Packets uint64
	Bytes   uint64
	Present bool
}

// TableCounters reads the live per-rule counters for one table, ordered per
// chain: the value for a chain name is that chain's rule counters in kernel
// order (index i = the i-th rule). exists is false, with a nil error, when the
// table is not in the kernel (the normal state before the first apply).
//
// The order matters: nftably owns the table and applies its rules in model
// order, so the kernel lists them in that same order — the caller lines these up
// with the model's enabled rules by position.
func (c *Client) TableCounters(ctx context.Context, family, name string) (counters map[string][]RuleCounter, exists bool, err error) {
	out, err := c.run(ctx, "-j", "list", "table", family, name)
	if err != nil {
		if strings.Contains(err.Error(), "No such file or directory") {
			return nil, false, nil
		}
		return nil, false, err
	}
	rs, err := parseRuleset([]byte(out), "")
	if err != nil {
		return nil, false, err
	}
	counters = map[string][]RuleCounter{}
	for _, t := range rs.Tables {
		if string(t.Family) != family || t.Name != name {
			continue
		}
		for _, ch := range t.Chains {
			list := make([]RuleCounter, 0, len(ch.Rules))
			for _, rule := range ch.Rules {
				list = append(list, counterFromExpr(rule.Expr))
			}
			counters[ch.Name] = list
		}
	}
	return counters, true, nil
}

// CounterOf returns the inline packet/byte counter carried by a rule, if it has
// a `counter` statement (Present is false otherwise). It reads the rule's raw
// nft expression, so it works on any rule from a parsed Ruleset without a second
// nft call.
func CounterOf(r *Rule) RuleCounter {
	if r == nil {
		return RuleCounter{}
	}
	return counterFromExpr(r.Expr)
}

// counterFromExpr pulls the inline counter out of a rule's expression array, if
// it has one: nft renders a `counter` statement as {"counter":{"packets":N,
// "bytes":M}} among the rule's expr elements.
func counterFromExpr(expr json.RawMessage) RuleCounter {
	if len(expr) == 0 {
		return RuleCounter{}
	}
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(expr, &items); err != nil {
		return RuleCounter{}
	}
	for _, it := range items {
		raw, ok := it["counter"]
		if !ok {
			continue
		}
		var cnt struct {
			Packets uint64 `json:"packets"`
			Bytes   uint64 `json:"bytes"`
		}
		if err := json.Unmarshal(raw, &cnt); err == nil {
			return RuleCounter{Packets: cnt.Packets, Bytes: cnt.Bytes, Present: true}
		}
	}
	return RuleCounter{}
}
