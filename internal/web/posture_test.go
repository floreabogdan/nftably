package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

// TestHardenSSHBanRecipe drives POST /harden/ssh-ban: it installs the four
// auto-ban rules at the top of the input chain, reports itself active, and is
// idempotent (a second click adds nothing). This is a security control that
// writes firewall rules, so the injection and the guard both need coverage.
func TestHardenSSHBanRecipe(t *testing.T) {
	srv, cookie, _ := dropInputServer(t)

	if v, _ := srv.postureView(); v.any(hasBanRule) {
		t.Fatal("precondition: a fresh chain must have no ban rule")
	}

	rec := postForm(srv, "/harden/ssh-ban", url.Values{}, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("ssh-ban: status %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/changes" {
		t.Errorf("ssh-ban redirect = %q, want /changes", loc)
	}

	v, err := srv.postureView()
	if err != nil {
		t.Fatal(err)
	}
	if len(v.rules) != 4 {
		t.Errorf("installed %d rules, want 4", len(v.rules))
	}
	if !v.any(hasBanRule) {
		t.Error("no ban.rate rule after applying the recipe")
	}
	// The two ban rules must reference distinct per-family sets, and the drop rules
	// must reference the same sets — otherwise the ban never takes effect.
	var haveDrop4, haveDrop6, haveBan bool
	for _, r := range v.rules {
		if matchHas(r, "ip.saddr", "@ssh_abusers") && stmtHas(r, "drop") {
			haveDrop4 = true
		}
		if matchHas(r, "ip6.saddr", "@ssh_abusers6") && stmtHas(r, "drop") {
			haveDrop6 = true
		}
		if hasBanRule(r) {
			haveBan = true
		}
	}
	if !haveDrop4 || !haveDrop6 || !haveBan {
		t.Errorf("recipe wiring incomplete: drop4=%v drop6=%v ban=%v", haveDrop4, haveDrop6, haveBan)
	}

	// The Posture page still renders after the recipe adds its rules.
	req := httptest.NewRequest(http.MethodGet, "/harden", nil)
	req.AddCookie(cookie)
	rec2 := httptest.NewRecorder()
	srv.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusOK {
		t.Fatalf("GET /harden after recipe: status %d, want 200", rec2.Code)
	}

	// Idempotent: clicking again adds nothing.
	if rec := postForm(srv, "/harden/ssh-ban", url.Values{}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("second ssh-ban: status %d, want 303", rec.Code)
	}
	if v, _ := srv.postureView(); len(v.rules) != 4 {
		t.Errorf("second apply changed rule count to %d, want 4", len(v.rules))
	}
}

// TestHardenIDSRecipe drives POST /harden/ids: with a forward chain it inserts a
// single fail-open queue rule at the top and is idempotent; with no forward chain
// it's refused rather than writing nowhere. The fail-open placement is a safety
// property, so the wiring needs coverage.
func TestHardenIDSRecipe(t *testing.T) {
	srv, cookie := newTestServer(t)

	// A BGP preset gives us a forward base chain to inspect.
	if rec := postForm(srv, "/presets/apply", url.Values{"preset": {"bgp-router"}}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("apply preset: %d", rec.Code)
	}

	rec := postForm(srv, "/harden/ids", url.Values{}, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("ids: status %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/changes" {
		t.Errorf("ids redirect = %q, want /changes", loc)
	}
	_, rules, ok := srv.forwardChain()
	if !ok {
		t.Fatal("forward chain vanished")
	}
	var queued int
	for _, r := range rules {
		if stmtHas(r, "queue") {
			queued++
		}
	}
	if queued != 1 {
		t.Errorf("forward chain has %d queue rules, want 1", queued)
	}

	// The Posture page renders the IDS card (HaveForward) with its setup modal.
	req := httptest.NewRequest(http.MethodGet, "/harden", nil)
	req.AddCookie(cookie)
	prec := httptest.NewRecorder()
	srv.ServeHTTP(prec, req)
	body := prec.Body.String()
	for _, want := range []string{"Inspect transit with an IDS", "modal-ids-setup", "suricata -q 0", "--daq nfq"} {
		if !strings.Contains(body, want) {
			t.Errorf("Posture page missing IDS setup content %q", want)
		}
	}

	// Idempotent: a second click adds no further queue rule.
	if rec := postForm(srv, "/harden/ids", url.Values{}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("second ids: status %d, want 303", rec.Code)
	}
	_, rules2, _ := srv.forwardChain()
	queued = 0
	for _, r := range rules2 {
		if stmtHas(r, "queue") {
			queued++
		}
	}
	if queued != 1 {
		t.Errorf("second apply left %d queue rules, want 1", queued)
	}
}

// TestHardenIDSNoForwardChain checks the guard: a host with only an input chain
// can't send transit to an IDS, so the recipe is refused.
func TestHardenIDSNoForwardChain(t *testing.T) {
	srv, cookie, _ := dropInputServer(t) // input-only model, no forward chain
	rec := postForm(srv, "/harden/ids", url.Values{}, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("no-forward ids: status %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc == "/changes" {
		t.Error("no-forward ids redirected to /changes; expected refusal")
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
