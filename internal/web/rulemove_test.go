package web

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/floreabogdan/nftably/internal/store"
)

// seedTwoChains builds a table with two regular chains and returns their ids.
func seedTwoChains(t *testing.T, srv *Server) (tableID, chainA, chainB int64) {
	t.Helper()
	// A distinct name — the test server already seeds an inet/filter table.
	tid, err := srv.store.CreateTable(store.Table{Family: "inet", Name: "movetest"})
	if err != nil {
		t.Fatal(err)
	}
	a, err := srv.store.CreateChain(store.Chain{TableID: tid, Name: "input", Kind: "base", Hook: "input", ChainType: "filter", Priority: "filter", Policy: "drop"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := srv.store.CreateChain(store.Chain{TableID: tid, Name: "extras", Kind: "regular"})
	if err != nil {
		t.Fatal(err)
	}
	return tid, a, b
}

// TestRuleEditMovesAcrossChains checks the editor's chain selector relocates an
// existing rule into another chain of the same table (landing at the bottom),
// which is the whole point of the selector.
func TestRuleEditMovesAcrossChains(t *testing.T) {
	srv, cookie := newTestServer(t)
	_, chainA, chainB := seedTwoChains(t, srv)

	// A rule authored in chain A.
	rid, err := srv.store.CreateChainRule(store.ChainRule{ChainID: chainA, Enabled: true, Comment: "ssh",
		Matches:    []store.RuleMatch{{Key: "tcp.dport", Op: "==", Value: "22"}},
		Statements: []store.RuleStatement{{Key: "accept", Params: "{}"}}})
	if err != nil {
		t.Fatal(err)
	}
	// A rule already sitting in chain B, so we can prove the moved rule lands after it.
	if _, err := srv.store.CreateChainRule(store.ChainRule{ChainID: chainB, Enabled: true, Comment: "first",
		Statements: []store.RuleStatement{{Key: "drop", Params: "{}"}}}); err != nil {
		t.Fatal(err)
	}

	form := url.Values{
		"chain_id":  {itoa(chainB)},
		"comment":   {"ssh"},
		"enabled":   {"on"},
		"c_field_0": {"tcp.dport"}, "c_op_0": {"=="}, "c_val_0": {"22"},
		"a_key_0": {"accept"},
	}
	rec := postForm(srv, "/firewall/rules/"+itoa(rid)+"/edit", form, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("edit save: status %d, want 303", rec.Code)
	}

	moved, err := srv.store.GetChainRule(rid)
	if err != nil {
		t.Fatal(err)
	}
	if moved.ChainID != chainB {
		t.Fatalf("rule chain = %d, want %d (should have moved to chain B)", moved.ChainID, chainB)
	}
	// It must be last in chain B (after the pre-existing rule).
	rules, _ := srv.store.ListChainRules(chainB)
	if len(rules) != 2 || rules[len(rules)-1].ID != rid {
		t.Errorf("moved rule should be last in chain B; got %d rules, last id %d", len(rules), rules[len(rules)-1].ID)
	}
	// Chain A must now be empty.
	if a, _ := srv.store.ListChainRules(chainA); len(a) != 0 {
		t.Errorf("chain A should be empty after the move, has %d", len(a))
	}
}

// TestRuleDuplicateCarriesRawAndTags guards the regression where duplicate
// silently dropped a rule's raw text (yielding an empty rule) and its tags.
func TestRuleDuplicateCarriesRawAndTags(t *testing.T) {
	srv, cookie := newTestServer(t)
	_, chainA, _ := seedTwoChains(t, srv)
	rid, err := srv.store.CreateChainRule(store.ChainRule{ChainID: chainA, Enabled: true, Comment: "connlimit",
		Raw: "ip saddr 10.0.0.0/8 ct count over 20 drop", Tags: "handwritten,edge"})
	if err != nil {
		t.Fatal(err)
	}
	if rec := postForm(srv, "/firewall/rules/"+itoa(rid)+"/duplicate", url.Values{}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("duplicate: status %d", rec.Code)
	}
	rules, _ := srv.store.ListChainRules(chainA)
	if len(rules) != 2 {
		t.Fatalf("want 2 rules after duplicate, got %d", len(rules))
	}
	dup := rules[1]
	if dup.Raw != "ip saddr 10.0.0.0/8 ct count over 20 drop" {
		t.Errorf("duplicate lost the raw text: %q", dup.Raw)
	}
	if dup.Tags != "handwritten,edge" {
		t.Errorf("duplicate lost the tags: %q", dup.Tags)
	}
}
