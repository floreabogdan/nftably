package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestLibraryEntriesValidate(t *testing.T) {
	// Every catalogue rule must pass the same validation a hand-written rule
	// does — the library must never inject something the form would refuse.
	seen := map[string]bool{}
	for _, g := range library {
		for _, e := range g.Entries {
			if e.Key == "" || e.Why == "" || len(e.Rules) == 0 {
				t.Errorf("entry %+v incomplete", e)
			}
			if seen[e.Key] {
				t.Errorf("duplicate key %q", e.Key)
			}
			seen[e.Key] = true
			for _, rule := range e.Rules {
				r := rule
				if errs := r.Validate(); len(errs) > 0 {
					t.Errorf("library rule %q invalid: %v", r.Name, errs)
				}
			}
		}
	}
}

func TestLibraryAdd(t *testing.T) {
	srv, cookie := newTestServer(t)

	if rec := postForm(srv, "/library/add", url.Values{"key": {"dns"}}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("add: %d", rec.Code)
	}
	rules, _ := srv.store.ListRules()
	if len(rules) != 2 || rules[0].Name != "dns" || rules[1].Name != "dns tcp" {
		t.Fatalf("dns bundle: %+v", rules)
	}
	// Adding again duplicates nothing.
	postForm(srv, "/library/add", url.Values{"key": {"dns"}}, cookie)
	if rules, _ = srv.store.ListRules(); len(rules) != 2 {
		t.Fatalf("duplicate add: %+v", rules)
	}
	if rec := postForm(srv, "/library/add", url.Values{"key": {"nope"}}, cookie); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown key: %d", rec.Code)
	}

	// The page marks it as present now.
	req := httptest.NewRequest(http.MethodGet, "/library", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "in your rules") {
		t.Error("added entry not marked on the page")
	}
}

func TestLibraryHarden(t *testing.T) {
	srv, cookie := newTestServer(t)

	// Start from accept — the un-hardened state.
	fw, _ := srv.store.GetFirewall()
	fw.InputPolicy = "accept"
	if err := srv.store.SaveFirewall(fw); err != nil {
		t.Fatal(err)
	}

	if rec := postForm(srv, "/library/harden", url.Values{}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("harden: %d", rec.Code)
	}
	fw, _ = srv.store.GetFirewall()
	if fw.InputPolicy != "drop" {
		t.Fatalf("policy: %+v", fw)
	}
	rules, _ := srv.store.ListRules()
	var names []string
	for _, r := range rules {
		names = append(names, r.Name)
	}
	// The test server listens beyond loopback, so both accepts are created.
	if len(rules) != 2 || rules[0].Name != "ssh" {
		t.Fatalf("hardening rules: %v", names)
	}

	// Hardening twice adds nothing new.
	postForm(srv, "/library/harden", url.Values{}, cookie)
	if rules, _ = srv.store.ListRules(); len(rules) != 2 {
		t.Fatalf("second harden duplicated rules: %d", len(rules))
	}
}
