package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/floreabogdan/nftably/internal/store"
)

func TestListsAddDeleteFlow(t *testing.T) {
	srv, cookie := newTestServer(t)

	rec := postForm(srv, "/lists/add", url.Values{
		"list": {"mgmt"}, "cidr": {"10.0.0.0/24"}, "note": {"office vpn"},
	}, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("mgmt add: %d", rec.Code)
	}
	rec = postForm(srv, "/lists/add", url.Values{
		"list": {"block"}, "cidr": {"203.0.113.0/24"},
	}, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("block add: %d", rec.Code)
	}

	// A bad address round-trips to the page as an error, storing nothing.
	rec = postForm(srv, "/lists/add", url.Values{"list": {"block"}, "cidr": {"nope"}}, cookie)
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "err=") {
		t.Fatalf("bad cidr: %d %s", rec.Code, rec.Header().Get("Location"))
	}

	// The rendered config now carries the sets and the changes page linted
	// with the mgmt list present has no lockout warnings.
	m, err := srv.loadModel()
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Mgmt) != 1 || len(m.Block) != 1 {
		t.Fatalf("model lists: %+v", m)
	}

	block, _ := srv.store.ListEntries(store.ListBlock)
	if rec := postForm(srv, "/lists/"+itoa(block[0].ID)+"/delete", url.Values{}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("delete: %d", rec.Code)
	}
	if block, _ = srv.store.ListEntries(store.ListBlock); len(block) != 0 {
		t.Fatalf("still there: %+v", block)
	}
}

func TestQuickBlockAndSelfGuard(t *testing.T) {
	srv, cookie := newTestServer(t)

	rec := postForm(srv, "/lists/block", url.Values{"ip": {"203.0.113.9"}}, cookie)
	if rec.Code != http.StatusSeeOther || strings.Contains(rec.Header().Get("Location"), "err=") {
		t.Fatalf("quick block: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	block, _ := srv.store.ListEntries(store.ListBlock)
	if len(block) != 1 || block[0].CIDR != "203.0.113.9" {
		t.Fatalf("block list: %+v", block)
	}

	// Blocking again: friendly overlap message, no duplicate.
	rec = postForm(srv, "/lists/block", url.Values{"ip": {"203.0.113.9"}}, cookie)
	if !strings.Contains(rec.Header().Get("Location"), "err=") {
		t.Fatal("duplicate block did not error")
	}

	// httptest requests come from 192.0.2.1 — blocking your own address (or a
	// range containing it) is refused.
	for _, self := range []string{"192.0.2.1", "192.0.2.0/24"} {
		rec = postForm(srv, "/lists/block", url.Values{"ip": {self}}, cookie)
		loc := rec.Header().Get("Location")
		if !strings.Contains(loc, "err=") {
			t.Fatalf("self-block %s accepted: %s", self, loc)
		}
	}
	if block, _ = srv.store.ListEntries(store.ListBlock); len(block) != 1 {
		t.Fatalf("self-block stored: %+v", block)
	}
	// The same guard protects the plain add form.
	rec = postForm(srv, "/lists/add", url.Values{"list": {"block"}, "cidr": {"192.0.2.1"}}, cookie)
	if !strings.Contains(rec.Header().Get("Location"), "err=") {
		t.Fatal("self-block via add form accepted")
	}
}
