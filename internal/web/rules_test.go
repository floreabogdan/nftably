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

// TestRuleLifecycle drives the M2 flow end to end through the handlers:
// create, list, edit with a validation error, toggle, delete.
func TestRuleLifecycle(t *testing.T) {
	srv, cookie := newTestServer(t)

	// Create.
	rec := postForm(srv, "/rules/new", url.Values{
		"name": {"ssh"}, "action": {"accept"}, "proto": {"tcp"},
		"dports": {"22"}, "saddrs": {"10.0.0.0/8"}, "enabled": {"on"},
	}, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}

	// It shows up on the list.
	req := httptest.NewRequest(http.MethodGet, "/rules", nil)
	req.AddCookie(cookie)
	lrec := httptest.NewRecorder()
	srv.ServeHTTP(lrec, req)
	if lrec.Code != http.StatusOK || !strings.Contains(lrec.Body.String(), "ssh") {
		t.Fatalf("list after create: %d", lrec.Code)
	}

	rules, err := srv.store.ListRules()
	if err != nil || len(rules) != 1 {
		t.Fatalf("stored rules: %v %v", rules, err)
	}
	id := strconv.FormatInt(rules[0].ID, 10)

	// A validation error re-renders the form with the message, saving nothing.
	rec = postForm(srv, "/rules/"+id+"/edit", url.Values{
		"name": {"ssh"}, "action": {"accept"}, "proto": {"any"}, "dports": {"22"},
	}, cookie)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "protocol of tcp or udp") {
		t.Fatalf("validation error not surfaced: %d", rec.Code)
	}
	if got, _ := srv.store.GetRule(rules[0].ID); got.Proto != "tcp" {
		t.Fatalf("invalid edit was saved: %+v", got)
	}

	// Toggle off.
	if rec := postForm(srv, "/rules/"+id+"/toggle", url.Values{}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("toggle: %d", rec.Code)
	}
	if got, _ := srv.store.GetRule(rules[0].ID); got.Enabled {
		t.Fatal("toggle did not disable")
	}

	// Delete.
	if rec := postForm(srv, "/rules/"+id+"/delete", url.Values{}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("delete: %d", rec.Code)
	}
	if rules, _ := srv.store.ListRules(); len(rules) != 0 {
		t.Fatalf("rule not deleted: %v", rules)
	}

	// Unknown id 404s rather than 500s.
	if rec := postForm(srv, "/rules/9999/delete", url.Values{}, cookie); rec.Code != http.StatusNotFound {
		t.Fatalf("missing rule: %d, want 404", rec.Code)
	}
}

func TestChangesPageShowsCandidate(t *testing.T) {
	srv, cookie := newTestServer(t)
	_, err := srv.store.CreateRule(store.Rule{Name: "web", Action: "accept", Proto: "tcp", DPorts: "80, 443", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/changes", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("changes: %d", rec.Code)
	}
	body := rec.Body.String()
	// The candidate always renders, even though the test host has no nft.
	for _, want := range []string{"table inet nftably", "policy drop;", "nftably: web"} {
		if !strings.Contains(body, want) {
			t.Errorf("changes page missing %q", want)
		}
	}
	if !strings.Contains(body, "Could not read the live table") {
		t.Error("nft-unavailable notice missing")
	}
}

func TestRulesPolicySave(t *testing.T) {
	srv, cookie := newTestServer(t)
	if rec := postForm(srv, "/rules/policy", url.Values{"input_policy": {"accept"}}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("policy save: %d", rec.Code)
	}
	if fw, _ := srv.store.GetFirewall(); fw.InputPolicy != "accept" {
		t.Fatalf("policy not saved: %+v", fw)
	}
	if rec := postForm(srv, "/rules/policy", url.Values{"input_policy": {"reject"}}, cookie); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad policy accepted: %d", rec.Code)
	}
}
