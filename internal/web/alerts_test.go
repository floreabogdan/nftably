package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestAlertDestinationCRUD covers creating, listing, filtering and deleting an
// alert destination through the HTTP handlers.
func TestAlertDestinationCRUD(t *testing.T) {
	srv, cookie := newTestServer(t)

	// Create a Slack destination, filtered to two event kinds.
	form := url.Values{
		"name": {"ops-slack"}, "type": {"slack"}, "enabled": {"on"},
		"url":                  {"https://hooks.slack.com/services/T/B/xxxx"},
		"event_apply.reverted": {"on"}, "event_ban.new": {"on"},
	}
	if rec := postForm(srv, "/alerts/save", form, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("save: status %d, want 303\n%s", rec.Code, rec.Body.String())
	}
	dests, err := srv.store.ListAlertDestinations()
	if err != nil || len(dests) != 1 {
		t.Fatalf("expected 1 destination, got %d (err %v)", len(dests), err)
	}
	d := dests[0]
	if d.Type != "slack" || !d.Enabled || d.URL == "" {
		t.Errorf("destination not saved right: %+v", d)
	}
	if !d.Wants("apply.reverted") || d.Wants("apply.confirmed") {
		t.Errorf("event filter wrong: events=%q", d.Events)
	}

	// It shows on the Alerts tab.
	if body := getBody(t, srv, cookie, "/settings?tab=alerts"); !strings.Contains(body, "ops-slack") {
		t.Error("destination not listed on the Alerts tab")
	}

	// Delete it.
	if rec := postForm(srv, "/alerts/"+itoa(d.ID)+"/delete", url.Values{}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("delete: status %d, want 303", rec.Code)
	}
	if dests, _ := srv.store.ListAlertDestinations(); len(dests) != 0 {
		t.Errorf("destination survived delete: %d left", len(dests))
	}
}

// TestAlertValidationRejects checks bad input re-renders the form with an error
// instead of saving.
func TestAlertValidationRejects(t *testing.T) {
	srv, cookie := newTestServer(t)

	// A webhook with a non-URL.
	rec := postForm(srv, "/alerts/save", url.Values{"name": {"bad"}, "type": {"webhook"}, "url": {"not a url"}}, cookie)
	if rec.Code != http.StatusOK { // form re-rendered, not a redirect
		t.Fatalf("bad webhook: status %d, want 200 (re-render)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "webhook URL") {
		t.Error("expected a URL validation error on the form")
	}

	// An email missing its host.
	rec = postForm(srv, "/alerts/save", url.Values{"name": {"mail"}, "type": {"email"}, "smtp_from": {"a@b.com"}, "smtp_to": {"c@d.com"}, "smtp_port": {"587"}, "smtp_security": {"starttls"}}, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("bad email: status %d, want 200 (re-render)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "SMTP server host") {
		t.Error("expected an SMTP host validation error")
	}

	if dests, _ := srv.store.ListAlertDestinations(); len(dests) != 0 {
		t.Errorf("invalid destinations were saved: %d", len(dests))
	}
}

func getBody(t *testing.T, srv *Server, cookie *http.Cookie, path string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: status %d", path, rec.Code)
	}
	return rec.Body.String()
}
