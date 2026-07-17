package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestSuggestionsPageAndDismissFlow(t *testing.T) {
	srv, cookie := newTestServer(t)

	get := func() string {
		req := httptest.NewRequest(http.MethodGet, "/suggestions", nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("suggestions: %d", rec.Code)
		}
		return rec.Body.String()
	}

	// Scan results differ per platform; what matters here is that the page
	// renders and the dismiss/restore flow round-trips.
	get()

	t.Run("dismiss and restore", func(t *testing.T) {
		if err := srv.store.DismissSuggestion("policy-drop"); err != nil {
			t.Fatal(err)
		}
		dismissed, _ := srv.store.DismissedSuggestions()
		if !dismissed["policy-drop"] {
			t.Fatal("dismissal not stored")
		}
		if rec := postForm(srv, "/suggestions/restore", url.Values{"key": {"policy-drop"}}, cookie); rec.Code != http.StatusSeeOther {
			t.Fatalf("restore: %d", rec.Code)
		}
		dismissed, _ = srv.store.DismissedSuggestions()
		if dismissed["policy-drop"] {
			t.Fatal("restore did not clear the dismissal")
		}
	})

	// Dismiss via the handler.
	if rec := postForm(srv, "/suggestions/dismiss", url.Values{"key": {"docker-note"}}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("dismiss: %d", rec.Code)
	}
	if dismissed, _ := srv.store.DismissedSuggestions(); !dismissed["docker-note"] {
		t.Fatal("dismiss handler did not store")
	}
	if rec := postForm(srv, "/suggestions/dismiss", url.Values{"key": {""}}, cookie); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty key accepted: %d", rec.Code)
	}
}

func TestRuleNewPrefill(t *testing.T) {
	srv, cookie := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/rules/new?name=web&proto=tcp&dports=80,+443&action=accept", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("prefill form: %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `value="web"`) || !strings.Contains(body, `value="80, 443"`) {
		t.Error("prefill values missing from the form")
	}
}
