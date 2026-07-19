package web

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestSettingsMetricsGenerateAndDisable drives the whole /settings/metrics flow —
// the only way the metrics bearer credential is minted and revoked. A regression
// that stored an empty token on "generate" (leaving /metrics disabled while the
// operator thinks it's protected) or failed to clear it on "disable" would be
// invisible to the store-level tests, which never touch the handler.
func TestSettingsMetricsGenerateAndDisable(t *testing.T) {
	srv, cookie := newTestServer(t)

	// Off by default: /metrics 404s.
	if rec := getMetrics(t, srv, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("before generate: /metrics = %d, want 404", rec.Code)
	}

	// Generate: mints a random token and enables the endpoint.
	if rec := postForm(srv, "/settings/metrics", url.Values{"generate": {"1"}}, cookie); rec.Code != http.StatusOK && rec.Code/100 != 3 {
		t.Fatalf("generate: status %d, want 200 or redirect", rec.Code)
	}
	st, ok, err := srv.store.GetSettings()
	if err != nil || !ok {
		t.Fatalf("GetSettings: ok=%v err=%v", ok, err)
	}
	tok := st.MetricsToken
	if tok == "" {
		t.Fatal("generate did not set a token")
	}
	// The freshly-minted token actually authorizes a scrape.
	if rec := getMetrics(t, srv, tok); rec.Code != http.StatusOK {
		t.Errorf("scrape with generated token: %d, want 200", rec.Code)
	}
	// A stale/empty bearer is now rejected, not accepted.
	if rec := getMetrics(t, srv, ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token after enable: %d, want 401", rec.Code)
	}

	// Disable: an empty metrics_token turns the endpoint back off.
	if rec := postForm(srv, "/settings/metrics", url.Values{"metrics_token": {""}}, cookie); rec.Code != http.StatusOK && rec.Code/100 != 3 {
		t.Fatalf("disable: status %d, want 200 or redirect", rec.Code)
	}
	if st, _, _ := srv.store.GetSettings(); st.MetricsToken != "" {
		t.Errorf("disable left token = %q, want empty", st.MetricsToken)
	}
	if rec := getMetrics(t, srv, tok); rec.Code != http.StatusNotFound {
		t.Errorf("after disable: old token = %d, want 404", rec.Code)
	}
}

// TestRandomToken asserts the metrics credential is long, URL-safe and distinct
// across calls — a regression to a short or static token would silently weaken
// the sole gate on a network-reachable endpoint.
func TestRandomToken(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		tok, err := randomToken()
		if err != nil {
			t.Fatalf("randomToken: %v", err)
		}
		raw, err := base64.RawURLEncoding.DecodeString(tok)
		if err != nil {
			t.Errorf("token %q is not raw-url base64: %v", tok, err)
		}
		if len(raw) != 24 {
			t.Errorf("token decodes to %d bytes, want 24 (192 bits)", len(raw))
		}
		if seen[tok] {
			t.Fatalf("randomToken produced a duplicate: %q", tok)
		}
		seen[tok] = true
	}
}

// TestGeoIPDownloadFailureStaysOnTab verifies a failed "download database" click
// re-renders on the GeoIP tab (showing the error) instead of dropping the user
// back to the default General tab — a click shouldn't move you off your tab.
func TestGeoIPDownloadFailureStaysOnTab(t *testing.T) {
	srv, cookie := newTestServer(t) // no data dir → download fails fast

	rec := postForm(srv, "/settings/geoip/download", url.Values{}, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("download: status %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Download failed") {
		t.Error("expected the download error to be shown")
	}
	// The GeoIP tab must be the selected one, not General.
	if !strings.Contains(body, `aria-controls="panel-geoip" aria-selected="true"`) {
		t.Error("after a failed download the GeoIP tab should stay active")
	}
	if strings.Contains(body, `aria-controls="panel-general" aria-selected="true"`) {
		t.Error("the General tab should not be active after a GeoIP action")
	}
}

// TestThemeTabRenders checks the Settings → Theme panel ships the density picker
// the client-side theme.js wires up.
func TestThemeTabRenders(t *testing.T) {
	srv, cookie := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/settings?tab=theme", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("theme tab: status %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{`data-theme-choice`, `value="comfortable"`, `value="compact"`, "Layout density"} {
		if !strings.Contains(body, want) {
			t.Errorf("theme tab missing %q", want)
		}
	}
}

// TestTabParam checks the settings tab selector: a known tab is honoured, an
// unknown or absent one falls back to the first (default) tab. A regression here
// lands the operator on a blank/wrong panel.
func TestTabParam(t *testing.T) {
	tabs := []string{"general", "access", "geoip"}
	cases := map[string]string{
		"/settings?tab=access": "access",
		"/settings?tab=geoip":  "geoip",
		"/settings?tab=bogus":  "general",
		"/settings":            "general",
		"/settings?tab=":       "general",
	}
	for target, want := range cases {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		if got := tabParam(req, tabs...); got != want {
			t.Errorf("tabParam(%q) = %q, want %q", target, got, want)
		}
	}
}
