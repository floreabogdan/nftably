package web

import (
	"encoding/json"
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

// TestVersionRestoreRoundTrip checks that a stored version snapshot can be
// restored back into the model after the model has been wiped.
func TestVersionRestoreRoundTrip(t *testing.T) {
	srv, cookie := newTestServer(t)
	// Build a model, snapshot it into a config version, then wipe the model.
	if rec := postForm(srv, "/presets/apply", url.Values{"preset": {"secure-server"}}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("apply preset: %d", rec.Code)
	}
	doc, err := srv.buildBackup()
	if err != nil {
		t.Fatal(err)
	}
	snap, _ := json.Marshal(doc)
	vid, err := srv.store.InsertConfigVersion("admin", "config-text", string(snap), store.VersionConfirmed)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.resetTables(); err != nil {
		t.Fatal(err)
	}
	if tbls, _ := srv.store.ListTables(); len(tbls) != 0 {
		t.Fatalf("expected wiped model, got %d tables", len(tbls))
	}

	rec := postForm(srv, "/changes/restore/"+strconv.FormatInt(vid, 10), nil, cookie)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") == "" {
		t.Fatalf("restore: code=%d, want 303 redirect", rec.Code)
	}
	if tbls, _ := srv.store.ListTables(); len(tbls) == 0 {
		t.Error("restore did not bring the model back")
	}

	// A version with no snapshot cannot be restored.
	vid2, _ := srv.store.InsertConfigVersion("admin", "config-text", "", store.VersionConfirmed)
	rec = postForm(srv, "/changes/restore/"+strconv.FormatInt(vid2, 10), nil, cookie)
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "err=") {
		t.Errorf("restoring a snapshot-less version should error, got loc=%q", loc)
	}
}

// TestRuleTags checks tag normalization and that tags persist through a save.
func TestRuleTags(t *testing.T) {
	// normalization: trim, de-dupe, strip junk.
	if got := normalizeTags("  ssh , mgmt ,ssh, bad!char "); got != "ssh, mgmt, badchar" {
		t.Errorf("normalizeTags = %q", got)
	}

	srv, cookie := newTestServer(t)
	chainID := seededInputChain(t, srv)
	path := "/firewall/chains/" + strconv.FormatInt(chainID, 10) + "/rules/new"
	rec := postForm(srv, path, url.Values{
		"c_field_0": {"tcp.dport"}, "c_op_0": {"=="}, "c_val_0": {"22"},
		"a_key_0": {"accept"}, "enabled": {"on"}, "tags": {"ssh, mgmt"},
	}, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("save with tags: %d", rec.Code)
	}
	rules, _ := srv.store.ListChainRules(chainID)
	if len(rules) != 1 || rules[0].Tags != "ssh, mgmt" {
		t.Errorf("tags not persisted: %+v", rules)
	}
	if tl := rules[0].TagList(); len(tl) != 2 || tl[0] != "ssh" {
		t.Errorf("TagList = %v", tl)
	}
}

// TestPortForwardWizard checks the wizard builds a DNAT rule in a nat
// prerouting chain and a matching forward-accept, and validates input.
func TestPortForwardWizard(t *testing.T) {
	srv, cookie := newTestServer(t)
	// secure-server gives a drop-policy forward chain to accept the forward into.
	if rec := postForm(srv, "/presets/apply", url.Values{"preset": {"secure-server"}}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("apply preset: %d", rec.Code)
	}
	rec := postForm(srv, "/firewall/port-forward", url.Values{
		"proto": {"tcp"}, "ext_port": {"443"}, "dest_host": {"192.168.1.10"}, "dest_port": {"8443"},
	}, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("port-forward: code=%d, want 303", rec.Code)
	}
	m, _ := srv.loadModel()
	var haveDNAT, haveNatChain, haveForwardAccept bool
	for _, tbl := range m.Tables {
		for _, c := range tbl.Chains {
			if c.IsBase() && c.Hook == "prerouting" && c.ChainType == "nat" {
				haveNatChain = true
			}
			for _, rl := range c.Rules {
				if stmtHas(rl, "dnat") && matchHas(rl, "tcp.dport", "443") {
					haveDNAT = true
				}
				if c.Hook == "forward" && matchHas(rl, "ip.daddr", "192.168.1.10") && stmtHas(rl, "accept") {
					haveForwardAccept = true
				}
			}
		}
	}
	if !haveNatChain || !haveDNAT {
		t.Errorf("missing nat chain (%v) or dnat rule (%v)", haveNatChain, haveDNAT)
	}
	if !haveForwardAccept {
		t.Error("no forward-accept for the internal host")
	}

	// A non-IP destination is rejected.
	rec = postForm(srv, "/firewall/port-forward", url.Values{
		"proto": {"tcp"}, "ext_port": {"80"}, "dest_host": {"example.com"},
	}, cookie)
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "err=") {
		t.Errorf("non-IP destination should error, got %q", loc)
	}
}

// TestUnbanValidation checks canonicalAddr canonicalizes real addresses and
// rejects anything that could inject nft tokens, and that the unban handler
// refuses a malformed reference.
func TestUnbanValidation(t *testing.T) {
	if got := canonicalAddr("1.2.3.4"); got != "1.2.3.4" {
		t.Errorf("canonicalAddr(1.2.3.4) = %q", got)
	}
	if got := canonicalAddr("10.0.0.0/8"); got != "10.0.0.0/8" {
		t.Errorf("canonicalAddr(prefix) = %q", got)
	}
	for _, bad := range []string{"", "not-an-ip", "1.2.3.4 } add element x", "1.2.3.4; drop"} {
		if got := canonicalAddr(bad); got != "" {
			t.Errorf("canonicalAddr(%q) = %q, want rejected", bad, got)
		}
	}

	srv, cookie := newTestServer(t)
	// A bad family / table must be refused before nft is touched.
	rec := postForm(srv, "/harden/unban", url.Values{
		"family": {"inet"}, "table": {"bad table"}, "set": {"ssh_abusers"}, "ip": {"1.2.3.4"},
	}, cookie)
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "err=") {
		t.Errorf("unban with a bad table name should error, got %q", loc)
	}
}

// TestGenericAutoBan checks the generic auto-ban builds detect-and-drop rules
// for an arbitrary service on a per-service ban set.
func TestGenericAutoBan(t *testing.T) {
	srv, cookie := newTestServer(t)
	if rec := postForm(srv, "/presets/apply", url.Values{"preset": {"secure-server"}}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("apply preset: %d", rec.Code)
	}
	rec := postForm(srv, "/harden/ban", url.Values{
		"service": {"http"}, "proto": {"tcp"}, "port": {"80,443"},
		"rate": {"20"}, "per": {"minute"}, "burst": {"5"}, "timeout": {"30m"},
	}, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("auto-ban: code=%d, want 303", rec.Code)
	}
	m, _ := srv.loadModel()
	var haveDrop4, haveBan bool
	for _, tbl := range m.Tables {
		for _, c := range tbl.Chains {
			for _, rl := range c.Rules {
				if matchHas(rl, "ip.saddr", "@http_abusers") && stmtHas(rl, "drop") {
					haveDrop4 = true
				}
				if hasBanRule(rl) && matchHas(rl, "tcp.dport", "80,443") {
					haveBan = true
				}
			}
		}
	}
	if !haveDrop4 {
		t.Error("no drop rule referencing @http_abusers")
	}
	if !haveBan {
		t.Error("no rate-ban detector on tcp/80,443")
	}

	// A bad service name is rejected without adding rules.
	count := func() int {
		mm, _ := srv.loadModel()
		n := 0
		for _, tbl := range mm.Tables {
			for _, c := range tbl.Chains {
				n += len(c.Rules)
			}
		}
		return n
	}
	before := count()
	rec = postForm(srv, "/harden/ban", url.Values{"service": {"Bad Name!"}, "proto": {"tcp"}, "port": {"22"}, "rate": {"10"}, "timeout": {"1h"}}, cookie)
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "err=") {
		t.Errorf("bad service name should error, got %q", loc)
	}
	if after := count(); after != before {
		t.Errorf("a rejected auto-ban changed the model: %d -> %d rules", before, after)
	}
}

// TestRuleDuplicate checks a rule clones into its chain with matches/statements
// intact and a distinguishing comment.
func TestRuleDuplicate(t *testing.T) {
	srv, cookie := newTestServer(t)
	chainID := seededInputChain(t, srv)
	rid, err := srv.store.CreateChainRule(store.ChainRule{
		ChainID: chainID, Enabled: true, Comment: "ssh",
		Matches:    []store.RuleMatch{{Key: "tcp.dport", Op: "==", Value: "22"}},
		Statements: []store.RuleStatement{{Key: "accept", Params: "{}"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rec := postForm(srv, "/firewall/rules/"+strconv.FormatInt(rid, 10)+"/duplicate", nil, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("duplicate: code=%d, want 303", rec.Code)
	}
	rules, _ := srv.store.ListChainRules(chainID)
	if len(rules) != 2 {
		t.Fatalf("want 2 rules after duplicate, got %d", len(rules))
	}
	copyRule := rules[1]
	if len(copyRule.Matches) != 1 || copyRule.Matches[0].Value != "22" || len(copyRule.Statements) != 1 {
		t.Errorf("duplicate lost its match/statement: %+v", copyRule)
	}
	if !strings.Contains(copyRule.Comment, "copy") {
		t.Errorf("duplicate comment = %q, want it to mark a copy", copyRule.Comment)
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
