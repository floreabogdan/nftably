package web

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/floreabogdan/nftably/internal/nft"
	"github.com/floreabogdan/nftably/internal/store"
)

// newTestServer builds a Server backed by a temp database with one admin user,
// and returns it alongside a valid session cookie. nft is pointed at a name
// that does not exist, so every handler exercises its "nft unavailable" path —
// which still renders the full template, the point of this test.
func newTestServer(t *testing.T) (*Server, *http.Cookie) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "nftably.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	hash, err := HashPassword("password123")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	uid, err := st.CreateUser("admin", hash)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := st.SaveSettings(store.Settings{RouterLabel: "test-router", ListenAddr: "0.0.0.0:8080"}); err != nil {
		t.Fatalf("save settings: %v", err)
	}

	token := "test-token"
	if err := st.CreateSession(token, uid, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("create session: %v", err)
	}

	srv := New(Config{
		Store:      st,
		Nft:        nft.New("nft-does-not-exist-on-this-box"),
		ListenAddr: "0.0.0.0:8080",
	})
	return srv, &http.Cookie{Name: sessionCookieName, Value: token}
}

// TestPagesRender walks every authenticated GET page and asserts it renders a
// 200 with no server-error marker. It is the guard that catches template parse
// and execution errors, which build and vet cannot see.
func TestPagesRender(t *testing.T) {
	srv, cookie := newTestServer(t)

	pages := []string{"/", "/ruleset", "/ruleset/raw", "/timeline", "/connections", "/firewall", "/presets", "/lists", "/changes", "/harden", "/learn", "/settings", "/settings?tab=import", "/profile", "/api/status"}
	for _, p := range pages {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("GET %s: status %d, want 200\nbody: %s", p, rec.Code, rec.Body.String())
			continue
		}
		if strings.Contains(rec.Body.String(), "internal error") {
			t.Errorf("GET %s: body contains \"internal error\" — a handler or template failed", p)
		}
	}
}

// TestAdvisorRedirectsToSecurity confirms the retired /advisor page now
// permanently redirects to the merged Security check.
func TestAdvisorRedirectsToSecurity(t *testing.T) {
	srv, cookie := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/advisor", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusMovedPermanently {
		t.Fatalf("GET /advisor: status %d, want 301", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/harden" {
		t.Errorf("redirect to %q, want /harden", loc)
	}
}

// TestLoginPageRenders checks the unauthenticated login template.
func TestLoginPageRenders(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /login: status %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Sign in") {
		t.Errorf("login page missing the sign-in form")
	}
}

// TestAuthRequired confirms an unauthenticated request to a protected page is
// redirected to /login rather than served.
func TestAuthRequired(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/settings", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Errorf("unauthenticated /settings: status %d, want 303 redirect", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("redirect to %q, want /login", loc)
	}
}
