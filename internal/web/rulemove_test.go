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

// TestRuleReorderPersistsNewOrder checks the drag-and-drop reorder endpoint
// rewrites a chain's rule order, and that the store method is defensive: a rule
// omitted from the posted list is kept (appended), not dropped.
func TestRuleReorderPersistsNewOrder(t *testing.T) {
	srv, cookie := newTestServer(t)
	_, chainA, _ := seedTwoChains(t, srv)
	var ids []int64
	for _, name := range []string{"r1", "r2", "r3"} {
		id, err := srv.store.CreateChainRule(store.ChainRule{ChainID: chainA, Enabled: true, Comment: name,
			Statements: []store.RuleStatement{{Key: "drop", Params: "{}"}}})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	// Drag r3 to the front, r1 next; deliberately omit r2 to prove it's retained.
	form := url.Values{"ids": {itoa(ids[2]) + "," + itoa(ids[0])}}
	rec := postForm(srv, "/firewall/chains/"+itoa(chainA)+"/rules/reorder", form, cookie)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("reorder: status %d, want 204", rec.Code)
	}
	rules, _ := srv.store.ListChainRules(chainA)
	got := []int64{rules[0].ID, rules[1].ID, rules[2].ID}
	want := []int64{ids[2], ids[0], ids[1]} // r3, r1, then the omitted r2 appended
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v (omitted rule must be kept, not dropped)", got, want)
		}
	}
}

// TestChainAndTableReorder checks the drag-and-drop reorder endpoints for chains
// (scoped to a table) and tables (page-wide) both persist the new order.
func TestChainAndTableReorder(t *testing.T) {
	srv, cookie := newTestServer(t)
	tid, chainA, chainB := seedTwoChains(t, srv)
	chainC, err := srv.store.CreateChain(store.Chain{TableID: tid, Name: "more", Kind: "regular"})
	if err != nil {
		t.Fatal(err)
	}

	// Reverse the chain order: C, B, A.
	form := url.Values{"ids": {itoa(chainC) + "," + itoa(chainB) + "," + itoa(chainA)}}
	if rec := postForm(srv, "/firewall/tables/"+itoa(tid)+"/chains/reorder", form, cookie); rec.Code != http.StatusNoContent {
		t.Fatalf("chain reorder: status %d, want 204", rec.Code)
	}
	chains, _ := srv.store.ListChains(tid)
	if len(chains) != 3 || chains[0].ID != chainC || chains[1].ID != chainB || chains[2].ID != chainA {
		t.Fatalf("chain order not applied: got %d %d %d", chains[0].ID, chains[1].ID, chains[2].ID)
	}

	// A second table, then reorder the two page-wide (the test server also seeds
	// an inet/filter table, so we assert on relative order of ours).
	tid2, err := srv.store.CreateTable(store.Table{Family: "inet", Name: "movetest2"})
	if err != nil {
		t.Fatal(err)
	}
	if rec := postForm(srv, "/firewall/tables/reorder", url.Values{"ids": {itoa(tid2) + "," + itoa(tid)}}, cookie); rec.Code != http.StatusNoContent {
		t.Fatalf("table reorder: status %d, want 204", rec.Code)
	}
	tables, _ := srv.store.ListTables()
	var posOurs, pos2 = -1, -1
	for i, tb := range tables {
		if tb.ID == tid {
			posOurs = i
		}
		if tb.ID == tid2 {
			pos2 = i
		}
	}
	if pos2 == -1 || posOurs == -1 || pos2 > posOurs {
		t.Fatalf("table reorder not applied: movetest2 at %d should precede movetest at %d", pos2, posOurs)
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
