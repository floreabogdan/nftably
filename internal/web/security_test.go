package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// postForm sends an urlencoded POST through the full ServeHTTP stack.
func postForm(srv *Server, path string, form url.Values, cookie *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

// Every response — even the unauthenticated login page — carries the hardening
// headers, since they are set before the mux runs.
func TestSecurityHeaders(t *testing.T) {
	srv, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	h := rec.Header()
	if got := h.Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", got)
	}
	if got := h.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := h.Get("Cross-Origin-Opener-Policy"); got != "same-origin" {
		t.Errorf("Cross-Origin-Opener-Policy = %q, want same-origin", got)
	}
	if got := h.Get("Cross-Origin-Resource-Policy"); got != "same-origin" {
		t.Errorf("Cross-Origin-Resource-Policy = %q, want same-origin", got)
	}
	if got := h.Get("Permissions-Policy"); !strings.Contains(got, "camera=()") {
		t.Errorf("Permissions-Policy = %q", got)
	}
	csp := h.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'self'", "frame-ancestors 'none'", "form-action 'self'", "object-src 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP missing %q; got %q", want, csp)
		}
	}
	if strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
		t.Errorf("CSP still permits inline scripts: %q", csp)
	}
	// The templates carry no inline style attributes, so the policy must not
	// permit them either — a regression that reintroduces style="…" should fail.
	if strings.Contains(csp, "'unsafe-inline'") {
		t.Errorf("CSP still permits inline styles: %q", csp)
	}
}

// Authenticated pages carry them too.
func TestSecurityHeadersOnAuthedPage(t *testing.T) {
	srv, cookie := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("dashboard: %d", rec.Code)
	}
	if rec.Header().Get("Content-Security-Policy") == "" {
		t.Error("authenticated pages should also carry a CSP")
	}
}

func TestCrossOriginPostRejected(t *testing.T) {
	srv, cookie := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.Header.Set("Origin", "https://attacker.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-origin POST code=%d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestSameOriginWriteRequiresMatchingScheme(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://nftably.example/logout", nil)
	req.Header.Set("Origin", "http://nftably.example")
	if sameOriginWrite(req) {
		t.Fatal("HTTP origin should not be accepted for an HTTPS request")
	}

	req.Header.Set("Origin", "https://nftably.example")
	if !sameOriginWrite(req) {
		t.Fatal("matching HTTPS origin should be accepted")
	}
}

func TestLoginLockoutAfterRepeatedFailures(t *testing.T) {
	srv, _ := newTestServer(t)
	bad := url.Values{"username": {"admin"}, "password": {"wrong"}}

	// The limiter allows 5 failures, then locks out.
	for i := 0; i < 5; i++ {
		rec := postForm(srv, "/login", bad, nil)
		if loc := rec.Header().Get("Location"); loc != "/login?error=1" {
			t.Fatalf("attempt %d: location=%q", i, loc)
		}
	}
	// The 6th is locked out — even the CORRECT password is refused now.
	good := url.Values{"username": {"admin"}, "password": {"password123"}}
	rec := postForm(srv, "/login", good, nil)
	if loc := rec.Header().Get("Location"); loc != "/login?error=locked" {
		t.Fatalf("a locked-out IP should be refused, location=%q", loc)
	}

	// The login page shows the lockout message.
	req := httptest.NewRequest(http.MethodGet, "/login?error=locked", nil)
	lrec := httptest.NewRecorder()
	srv.ServeHTTP(lrec, req)
	if !strings.Contains(lrec.Body.String(), "Too many failed attempts") {
		t.Error("the lockout message should be shown")
	}
}

// A successful login clears the failure count.
func TestLoginResetsOnSuccess(t *testing.T) {
	srv, _ := newTestServer(t)
	bad := url.Values{"username": {"admin"}, "password": {"wrong"}}
	for i := 0; i < 4; i++ { // one short of the limit
		postForm(srv, "/login", bad, nil)
	}
	good := url.Values{"username": {"admin"}, "password": {"password123"}}
	if rec := postForm(srv, "/login", good, nil); rec.Header().Get("Location") != "/" {
		t.Fatalf("a good login should succeed before lockout")
	}
	// The counter is cleared, so four more failures do not lock out.
	for i := 0; i < 4; i++ {
		postForm(srv, "/login", bad, nil)
	}
	if srv.login.blocked("192.0.2.1") {
		t.Error("the failure count should have reset after the successful login")
	}
}

func TestLoginLimiterStateIsBounded(t *testing.T) {
	l := newLoginLimiter()
	for i := 0; i < maxLoginLimiterEntries+500; i++ {
		l.fail(fmt.Sprintf("192.0.2.%d", i))
	}
	if got := len(l.byIP); got > maxLoginLimiterEntries {
		t.Fatalf("limiter retained %d entries, limit is %d", got, maxLoginLimiterEntries)
	}
}

// A peer whose address cannot be parsed must be denied, not treated as exempt
// from the allow-list. httptest's recorder is not a Hijacker, so the denial
// surfaces as the bare-403 fallback.
func TestInvalidPeerAddressDenied(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.RemoteAddr = "not-an-address"
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("invalid peer address: code=%d, want %d", rec.Code, http.StatusForbidden)
	}
}
