package web

import (
	"net/http"
	"net/url"
	"testing"
)

// inputRuleCount returns how many rules sit in the model's input chain(s).
func inputRuleCount(t *testing.T, srv *Server) int {
	t.Helper()
	v, err := srv.postureView()
	if err != nil {
		t.Fatalf("postureView: %v", err)
	}
	return len(v.rules)
}

// hasAcceptPort reports whether an input rule accepts the given proto/port.
func hasAcceptPort(t *testing.T, srv *Server, proto, port string) bool {
	t.Helper()
	v, err := srv.postureView()
	if err != nil {
		t.Fatalf("postureView: %v", err)
	}
	for _, r := range v.rules {
		if matchHas(r, proto+".dport", port) && stmtHas(r, "accept") {
			return true
		}
	}
	return false
}

// TestAdvisorAllowAddsRule drives POST /advisor/allow — the exposed-service
// one-click "allow". A valid proto/port injects a scoped accept rule and lands on
// Review; a bad proto/port is rejected without opening the box. Since a
// mishandled value here could add an overly-broad or malformed accept rule, the
// validation and injection need coverage, not just the redirect.
func TestAdvisorAllowAddsRule(t *testing.T) {
	srv, cookie, _ := dropInputServer(t)

	before := inputRuleCount(t, srv)

	// Valid: tcp/8443 → an accept rule appears and we go to Review.
	rec := postForm(srv, "/advisor/allow", url.Values{"proto": {"tcp"}, "port": {"8443"}}, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("valid allow: status %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/changes" {
		t.Errorf("valid allow redirect = %q, want /changes", loc)
	}
	if !hasAcceptPort(t, srv, "tcp", "8443") {
		t.Error("valid allow did not add an accept rule for tcp/8443")
	}
	if got := inputRuleCount(t, srv); got != before+1 {
		t.Errorf("rule count = %d, want %d", got, before+1)
	}

	// Out-of-range port and bad proto are refused — no rule added, back to /harden.
	for _, bad := range []url.Values{
		{"proto": {"tcp"}, "port": {"99999"}},
		{"proto": {"tcp"}, "port": {"0"}},
		{"proto": {"icmp"}, "port": {"80"}},
	} {
		countBefore := inputRuleCount(t, srv)
		rec := postForm(srv, "/advisor/allow", bad, cookie)
		if rec.Code != http.StatusSeeOther {
			t.Errorf("bad allow %v: status %d, want 303", bad, rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc == "/changes" {
			t.Errorf("bad allow %v redirected to /changes; expected refusal", bad)
		}
		if got := inputRuleCount(t, srv); got != countBefore {
			t.Errorf("bad allow %v changed rule count %d → %d", bad, countBefore, got)
		}
	}
}

// TestAdvisorAllowNoInputChain checks the guard: with no input chain, a valid
// allow is refused rather than silently dropped or written nowhere.
func TestAdvisorAllowNoInputChain(t *testing.T) {
	srv, cookie := newTestServer(t)
	if err := srv.resetTables(); err != nil {
		t.Fatal(err)
	}
	rec := postForm(srv, "/advisor/allow", url.Values{"proto": {"tcp"}, "port": {"8443"}}, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("no-chain allow: status %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc == "/changes" {
		t.Errorf("no-chain allow redirected to /changes; expected refusal back to /harden")
	}
}
