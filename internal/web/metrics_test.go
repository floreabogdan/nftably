package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/floreabogdan/nftably/internal/nft"
)

// getMetrics issues a GET /metrics with the given bearer token ("" = no header).
func getMetrics(t *testing.T, srv *Server, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func TestMetricsDisabledByDefault(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := getMetrics(t, srv, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("no token set: status %d, want 404", rec.Code)
	}
}

func TestMetricsRequiresToken(t *testing.T) {
	srv, _ := newTestServer(t)
	if err := srv.store.SaveMetricsToken("s3cret"); err != nil {
		t.Fatal(err)
	}

	// No Authorization header → 401.
	if rec := getMetrics(t, srv, ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("missing token: status %d, want 401", rec.Code)
	}
	// Wrong token → 401.
	if rec := getMetrics(t, srv, "nope"); rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong token: status %d, want 401", rec.Code)
	}
	// Correct token → 200 with the base series.
	rec := getMetrics(t, srv, "s3cret")
	if rec.Code != http.StatusOK {
		t.Fatalf("correct token: status %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"nftably_build_info", "nftably_up ", "nftably_apply_pending "} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics body missing %q\n%s", want, body)
		}
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("content-type = %q, want text/plain…", ct)
	}
}

func TestWriteRuleCounters(t *testing.T) {
	// A rule with a counter and a comment; and one without a counter (skipped).
	counted := &nft.Rule{Comment: "drop invalid", Expr: json.RawMessage(
		`[{"match":{}},{"counter":{"packets":7,"bytes":420}},{"drop":null}]`)}
	uncounted := &nft.Rule{Comment: "accept ssh", Expr: json.RawMessage(`[{"accept":null}]`)}
	rs := &nft.Ruleset{Tables: []*nft.Table{{
		Family: nft.FamilyInet, Name: "filter",
		Chains: []*nft.Chain{{Name: "input", Hook: "input", Rules: []*nft.Rule{counted, uncounted}}},
	}}}

	var b strings.Builder
	writeRuleCounters(&b, rs)
	out := b.String()

	if !strings.Contains(out, `nftably_rule_packets_total{family="inet",table="filter",chain="input",rule="drop invalid",index="0"} 7`) {
		t.Errorf("missing/incorrect packets series:\n%s", out)
	}
	if !strings.Contains(out, `nftably_rule_bytes_total{family="inet",table="filter",chain="input",rule="drop invalid",index="0"} 420`) {
		t.Errorf("missing/incorrect bytes series:\n%s", out)
	}
	if strings.Contains(out, "accept ssh") {
		t.Errorf("a rule without a counter should not appear:\n%s", out)
	}
}

func TestMetricLabelEscaping(t *testing.T) {
	got := metricLabel(`a"b\c` + "\n")
	want := `a\"b\\c\n`
	if got != want {
		t.Errorf("metricLabel = %q, want %q", got, want)
	}
}
