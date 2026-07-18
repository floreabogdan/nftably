package nft

import (
	"encoding/json"
	"testing"
)

// Real `nft -j list table` output shape (captured from nft v1.0.9): a chain with
// three rules, the first two carrying counters, the third none.
const sampleTableJSON = `{"nftables":[
  {"metainfo":{"version":"1.0.9","json_schema_version":1}},
  {"table":{"family":"inet","name":"filter","handle":1}},
  {"chain":{"family":"inet","table":"filter","name":"input","handle":1,"type":"filter","hook":"input","prio":0,"policy":"drop"}},
  {"rule":{"family":"inet","table":"filter","chain":"input","handle":2,"expr":[
     {"match":{"op":"in","left":{"ct":{"key":"state"}},"right":["established","related"]}},
     {"counter":{"packets":3,"bytes":252}},
     {"accept":null}]}},
  {"rule":{"family":"inet","table":"filter","chain":"input","handle":3,"expr":[
     {"match":{"op":"==","left":{"meta":{"key":"iif"}},"right":"lo"}},
     {"counter":{"packets":6,"bytes":504}},
     {"accept":null}]}},
  {"rule":{"family":"inet","table":"filter","chain":"input","handle":4,"expr":[
     {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":22}},
     {"accept":null}]}}
]}`

func TestCounterFromExpr(t *testing.T) {
	rs, err := parseRuleset([]byte(sampleTableJSON), "")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rs.Tables) != 1 || len(rs.Tables[0].Chains) != 1 {
		t.Fatalf("unexpected structure: %d tables", len(rs.Tables))
	}
	rules := rs.Tables[0].Chains[0].Rules
	if len(rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(rules))
	}

	c0 := counterFromExpr(rules[0].Expr)
	if !c0.Present || c0.Packets != 3 || c0.Bytes != 252 {
		t.Errorf("rule 0 counter = %+v, want {3,252,present}", c0)
	}
	c1 := counterFromExpr(rules[1].Expr)
	if !c1.Present || c1.Packets != 6 || c1.Bytes != 504 {
		t.Errorf("rule 1 counter = %+v, want {6,504,present}", c1)
	}
	// The third rule has no counter statement.
	if c2 := counterFromExpr(rules[2].Expr); c2.Present {
		t.Errorf("rule 2 should have no counter, got %+v", c2)
	}
}

func TestCounterFromExprEmpty(t *testing.T) {
	if c := counterFromExpr(nil); c.Present {
		t.Error("nil expr should yield no counter")
	}
	if c := counterFromExpr(json.RawMessage(`[]`)); c.Present {
		t.Error("empty expr should yield no counter")
	}
}
