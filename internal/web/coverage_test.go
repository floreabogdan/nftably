package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/floreabogdan/nftably/internal/store"
)

// TestRuleSaveCreatesAndRejects covers the core state-changing authoring path:
// a valid rule POST persists and redirects, while a rule that can't be expressed
// re-renders the form with an error and creates nothing. Every other test
// inserts rules via the store directly, so this is the only coverage of the
// handler's validation gate.
func TestRuleSaveCreatesAndRejects(t *testing.T) {
	srv, cookie := newTestServer(t)
	chainID := seededInputChain(t, srv)
	path := "/firewall/chains/" + strconv.FormatInt(chainID, 10) + "/rules/new"

	// Valid: accept tcp/22.
	rec := postForm(srv, path, url.Values{
		"c_field_0": {"tcp.dport"}, "c_op_0": {"=="}, "c_val_0": {"22"},
		"a_key_0": {"accept"}, "enabled": {"on"},
	}, cookie)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/firewall?saved=1" {
		t.Fatalf("valid rule: code=%d loc=%q, want 303 /firewall?saved=1", rec.Code, rec.Header().Get("Location"))
	}
	rules, err := srv.store.ListChainRules(chainID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("want 1 rule after valid save, got %d", len(rules))
	}
	if len(rules[0].Matches) != 1 || rules[0].Matches[0].Key != "tcp.dport" || len(rules[0].Statements) != 1 {
		t.Errorf("saved rule lost its match/statement: %+v", rules[0])
	}

	// Invalid: a jump with no target can't render. Must re-render (200), not
	// redirect, and must not create a second rule.
	rec = postForm(srv, path, url.Values{"a_key_0": {"jump"}, "enabled": {"on"}}, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("invalid rule: code=%d, want 200 (form re-render)", rec.Code)
	}
	if rules, _ := srv.store.ListChainRules(chainID); len(rules) != 1 {
		t.Errorf("an invalid rule was persisted: chain now has %d rules", len(rules))
	}
}

// TestAccessWhitelistEnforcement checks the outermost security boundary: with a
// whitelist set, an in-range peer is served and an out-of-range peer is denied.
// httptest's recorder is not a Hijacker, so denial surfaces as the 403 fallback.
func TestAccessWhitelistEnforcement(t *testing.T) {
	srv, _ := newTestServer(t)
	if err := srv.store.SaveAccessWhitelist("192.0.2.0/24"); err != nil {
		t.Fatal(err)
	}
	srv.reloadAccess()

	do := func(remote string) int {
		req := httptest.NewRequest(http.MethodGet, "/login", nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := do("192.0.2.5:1234"); code == http.StatusForbidden {
		t.Errorf("in-range peer was denied (code %d)", code)
	}
	if code := do("203.0.113.9:1234"); code != http.StatusForbidden {
		t.Errorf("out-of-range peer: code=%d, want 403", code)
	}
}

// TestSettingsAccessRejectsBadCIDR checks the self-lockout guard: a malformed
// whitelist is refused up front, leaving the stored value and the open state
// untouched; a valid CIDR saves and restricts.
func TestSettingsAccessRejectsBadCIDR(t *testing.T) {
	srv, cookie := newTestServer(t)
	if !srv.WideOpen() {
		t.Fatal("fresh install should be wide open")
	}

	rec := postForm(srv, "/settings/access", url.Values{"access_whitelist": {"not-a-cidr"}}, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("bad CIDR: code=%d, want 200 (re-render with error)", rec.Code)
	}
	if st, _, _ := srv.store.GetSettings(); strings.TrimSpace(st.AccessWhitelist) != "" {
		t.Errorf("a bad CIDR was saved: %q", st.AccessWhitelist)
	}
	if !srv.WideOpen() {
		t.Error("a rejected whitelist changed the access state")
	}

	rec = postForm(srv, "/settings/access", url.Values{"access_whitelist": {"192.0.2.0/24"}}, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid CIDR: code=%d, want 200", rec.Code)
	}
	if st, _, _ := srv.store.GetSettings(); strings.TrimSpace(st.AccessWhitelist) != "192.0.2.0/24" {
		t.Errorf("valid whitelist not saved: %q", st.AccessWhitelist)
	}
	if srv.WideOpen() {
		t.Error("a valid whitelist should have restricted access")
	}
}

// TestLogoutClearsSession checks that logout deletes the server-side session and
// a request with the old cookie is no longer authenticated.
func TestLogoutClearsSession(t *testing.T) {
	srv, cookie := newTestServer(t)

	rec := postForm(srv, "/logout", nil, cookie)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("logout: code=%d loc=%q, want 303 /login", rec.Code, rec.Header().Get("Location"))
	}
	if _, ok, _ := srv.store.GetSession(cookie.Value); ok {
		t.Error("session still exists after logout")
	}
	// The old cookie no longer authenticates: an authed page redirects to login.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther && rec.Code != http.StatusFound {
		t.Errorf("stale cookie: code=%d, want a redirect to /login", rec.Code)
	}
}

// TestRuleToggleAndDelete covers the two cheapest state-changing rule handlers:
// toggle flips Enabled, delete removes the row.
func TestRuleToggleAndDelete(t *testing.T) {
	srv, cookie := newTestServer(t)
	chainID := seededInputChain(t, srv)
	rid, err := srv.store.CreateChainRule(store.ChainRule{
		ChainID: chainID, Enabled: true,
		Statements: []store.RuleStatement{{Key: "accept", Params: "{}"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	base := "/firewall/rules/" + strconv.FormatInt(rid, 10)

	if rec := postForm(srv, base+"/toggle", nil, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("toggle: code=%d, want 303", rec.Code)
	}
	if got, _ := srv.store.GetChainRule(rid); got.Enabled {
		t.Error("rule should be disabled after one toggle")
	}
	if rec := postForm(srv, base+"/toggle", nil, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("second toggle: code=%d, want 303", rec.Code)
	}
	if got, _ := srv.store.GetChainRule(rid); !got.Enabled {
		t.Error("rule should be re-enabled after a second toggle")
	}

	if rec := postForm(srv, base+"/delete", nil, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("delete: code=%d, want 303", rec.Code)
	}
	if rules, _ := srv.store.ListChainRules(chainID); len(rules) != 0 {
		t.Errorf("rule not deleted: chain still has %d rules", len(rules))
	}
}
