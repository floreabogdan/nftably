package web

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/floreabogdan/nftably/internal/store"
)

// statusOf returns a check's status by id, or "" if absent.
func statusOf(checks []postureCheck, id string) postureStatus {
	for _, c := range checks {
		if c.ID == id {
			return c.Status
		}
	}
	return ""
}

func TestPostureEmptyModel(t *testing.T) {
	srv, _ := newTestServer(t)
	if err := srv.resetTables(); err != nil { // clear the seeded starter table
		t.Fatal(err)
	}
	checks, v, err := srv.posture()
	if err != nil {
		t.Fatal(err)
	}
	if v.haveInput {
		t.Error("empty model should have no input chain")
	}
	if statusOf(checks, "default-deny") != postureFail {
		t.Errorf("empty model: default-deny = %q, want fail", statusOf(checks, "default-deny"))
	}
}

func TestPostureGradesDropInput(t *testing.T) {
	srv, _ := newTestServer(t)
	if err := srv.resetTables(); err != nil {
		t.Fatal(err)
	}

	tableID, err := srv.store.CreateTable(store.Table{Family: "inet", Name: "filter"})
	if err != nil {
		t.Fatal(err)
	}
	input, err := srv.store.CreateChain(store.Chain{TableID: tableID, Name: "input", Kind: "base", Hook: "input", ChainType: "filter", Priority: "filter", Policy: "drop"})
	if err != nil {
		t.Fatal(err)
	}
	// A partial base: loopback + established, but no invalid-drop and no v6 ICMP.
	if err := srv.addRule(input, "loopback", []store.RuleMatch{mt("meta.iifname", "lo")}, []store.RuleStatement{stmt("accept")}); err != nil {
		t.Fatal(err)
	}
	if err := srv.addRule(input, "established", []store.RuleMatch{mt("ct.state", "established, related")}, []store.RuleStatement{stmt("accept")}); err != nil {
		t.Fatal(err)
	}
	// SSH open to the world (no source scope).
	if err := srv.addRule(input, "ssh", []store.RuleMatch{mt("tcp.dport", "22")}, []store.RuleStatement{stmt("accept")}); err != nil {
		t.Fatal(err)
	}

	checks, v, err := srv.posture()
	if err != nil {
		t.Fatal(err)
	}
	if !v.haveInput || !v.dropPolicy || v.chainID != input {
		t.Fatalf("view: haveInput=%v dropPolicy=%v chainID=%d (want input=%d)", v.haveInput, v.dropPolicy, v.chainID, input)
	}
	want := map[string]postureStatus{
		"default-deny": posturePass,
		"loopback":     posturePass,
		"established":  posturePass,
		"invalid":      postureWarn, // missing
		"v6icmp":       postureWarn, // missing
		"rpf":          postureInfo, // advisory, missing
		"ssh":          postureWarn, // open to the world
	}
	for id, exp := range want {
		if got := statusOf(checks, id); got != exp {
			t.Errorf("check %q = %q, want %q", id, got, exp)
		}
	}
	// The missing base rules carry a one-click fix into the input chain.
	for _, id := range []string{"invalid", "v6icmp", "rpf"} {
		if fix, ok := hardenFixes[id]; !ok || len(fix.stmts) == 0 {
			t.Errorf("fix %q not registered", id)
		}
	}
}

// dropInputServer returns a test server whose model is a single inet filter
// table with a drop-policy input chain and no rules — the minimal shape the
// one-click fixes inject into.
func dropInputServer(t *testing.T) (*Server, *http.Cookie, int64) {
	t.Helper()
	srv, cookie := newTestServer(t)
	if err := srv.resetTables(); err != nil {
		t.Fatal(err)
	}
	tableID, err := srv.store.CreateTable(store.Table{Family: "inet", Name: "filter"})
	if err != nil {
		t.Fatal(err)
	}
	input, err := srv.store.CreateChain(store.Chain{TableID: tableID, Name: "input", Kind: "base", Hook: "input", ChainType: "filter", Priority: "filter", Policy: "drop"})
	if err != nil {
		t.Fatal(err)
	}
	return srv, cookie, input
}

// TestHardenFixAddsRule drives POST /harden/fix/{id}: a known fix injects its
// rule into the input chain and redirects to Review, an unknown id is a 400, and
// a model with no input chain is turned away without adding anything. This is a
// security control (it writes firewall rules), so the actual injection — not just
// the fix registration — needs coverage.
func TestHardenFixAddsRule(t *testing.T) {
	srv, cookie, _ := dropInputServer(t)

	// Before: the invalid-drop check is missing.
	if checks, _, _ := srv.posture(); statusOf(checks, "invalid") != postureWarn {
		t.Fatalf("precondition: invalid check = %q, want warn", statusOf(checks, "invalid"))
	}

	rec := postForm(srv, "/harden/fix/invalid", url.Values{}, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("fix: status %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/changes" {
		t.Errorf("fix redirect = %q, want /changes", loc)
	}
	// After: the rule landed, so the check now passes.
	if checks, _, _ := srv.posture(); statusOf(checks, "invalid") != posturePass {
		t.Errorf("after fix: invalid check = %q, want pass", statusOf(checks, "invalid"))
	}

	// An unknown fix id is a 400 — no rule invented.
	if rec := postForm(srv, "/harden/fix/bogus", url.Values{}, cookie); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown fix: status %d, want 400", rec.Code)
	}
}

// TestHardenFixNoInputChain checks the guard: with no input chain to inject into,
// the fix is refused (redirect back to /harden) rather than writing a rule into a
// zero/absent chain.
func TestHardenFixNoInputChain(t *testing.T) {
	srv, cookie := newTestServer(t)
	if err := srv.resetTables(); err != nil {
		t.Fatal(err)
	}
	rec := postForm(srv, "/harden/fix/invalid", url.Values{}, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("no-chain fix: status %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc == "/changes" {
		t.Errorf("no-chain fix redirected to /changes; expected back to /harden")
	}
}

func TestPostureScoreExcludesInfo(t *testing.T) {
	checks := []postureCheck{
		{Status: posturePass}, {Status: posturePass}, {Status: postureWarn}, {Status: postureInfo},
	}
	pass, total := postureScore(checks)
	if pass != 2 || total != 3 {
		t.Errorf("score = %d/%d, want 2/3 (info excluded)", pass, total)
	}
}
