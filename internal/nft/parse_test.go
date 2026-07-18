package nft

import "testing"

// A trimmed but realistic `nft -j list ruleset` for an inet filter table with a
// base input chain (two rules) and a base forward chain (no rules).
const sampleJSON = `{
  "nftables": [
    {"metainfo": {"version": "1.0.6", "release_name": "Lester Gooch", "json_schema_version": 1}},
    {"table": {"family": "inet", "name": "filter", "handle": 1}},
    {"chain": {"family": "inet", "table": "filter", "name": "input", "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}},
    {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 4, "expr": [{"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["established", "related"]}}, {"accept": null}]}},
    {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 5, "comment": "ssh", "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 22}}, {"accept": null}]}},
    {"chain": {"family": "inet", "table": "filter", "name": "forward", "handle": 2, "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}}
  ]
}`

// The matching `nft -a list ruleset` text — the source of the per-rule wording.
// The table and chain openers carry a "# handle N" comment, exactly as real nft
// emits them (that annotation is what the opener detection must tolerate).
const sampleText = `table inet filter { # handle 1
	chain input { # handle 1
		type filter hook input priority filter; policy drop;
		ct state established,related accept # handle 4
		tcp dport 22 accept comment "ssh" # handle 5
	}

	chain forward { # handle 2
		type filter hook forward priority filter; policy drop;
	}
}`

func TestParseRuleset(t *testing.T) {
	rs, err := parseRuleset([]byte(sampleJSON), sampleText)
	if err != nil {
		t.Fatalf("parseRuleset: %v", err)
	}

	if rs.NftVersion != "1.0.6" {
		t.Errorf("NftVersion = %q, want 1.0.6", rs.NftVersion)
	}
	if len(rs.Tables) != 1 {
		t.Fatalf("got %d tables, want 1", len(rs.Tables))
	}
	tbl := rs.Tables[0]
	if tbl.Family != FamilyInet || tbl.Name != "filter" {
		t.Errorf("table = %s/%s, want inet/filter", tbl.Family, tbl.Name)
	}
	if len(tbl.Chains) != 2 {
		t.Fatalf("got %d chains, want 2", len(tbl.Chains))
	}

	input := tbl.Chains[0]
	if !input.IsBase() || input.Hook != "input" || input.Policy != "drop" {
		t.Errorf("input chain = base:%v hook:%q policy:%q, want base hook input policy drop",
			input.IsBase(), input.Hook, input.Policy)
	}
	if len(input.Rules) != 2 {
		t.Fatalf("input has %d rules, want 2", len(input.Rules))
	}

	if got, want := input.Rules[0].Text, "ct state established,related accept"; got != want {
		t.Errorf("rule[0].Text = %q, want %q", got, want)
	}
	if got, want := input.Rules[1].Text, `tcp dport 22 accept comment "ssh"`; got != want {
		t.Errorf("rule[1].Text = %q, want %q", got, want)
	}
	if input.Rules[1].Comment != "ssh" {
		t.Errorf("rule[1].Comment = %q, want ssh", input.Rules[1].Comment)
	}

	if rs.TotalRules() != 2 {
		t.Errorf("TotalRules = %d, want 2", rs.TotalRules())
	}
	if rs.TotalChains() != 2 {
		t.Errorf("TotalChains = %d, want 2", rs.TotalChains())
	}
	if fams := rs.Families(); len(fams) != 1 || fams[0] != FamilyInet {
		t.Errorf("Families = %v, want [inet]", fams)
	}
}

func TestParseHandleText(t *testing.T) {
	m := parseHandleText(sampleText)
	if got := m[handleKey("inet", "filter", 4)]; got != "ct state established,related accept" {
		t.Errorf("handle 4 = %q", got)
	}
	// A set element's handle must never be captured as a rule.
	withSet := `table inet filter {
	set blocked {
		type ipv4_addr
		elements = { 10.0.0.1 } # handle 9
	}
	chain input {
		ip saddr @blocked drop # handle 7
	}
}`
	m2 := parseHandleText(withSet)
	if _, ok := m2[handleKey("inet", "filter", 9)]; ok {
		t.Error("captured a set-element handle as a rule")
	}
	if got := m2[handleKey("inet", "filter", 7)]; got != "ip saddr @blocked drop" {
		t.Errorf("handle 7 = %q", got)
	}
}

func TestParseEmptyRuleset(t *testing.T) {
	rs, err := parseRuleset([]byte(`{"nftables": [{"metainfo": {"version": "1.0.6"}}]}`), "")
	if err != nil {
		t.Fatalf("parseRuleset: %v", err)
	}
	if !rs.IsEmpty() {
		t.Error("expected empty ruleset")
	}
}
