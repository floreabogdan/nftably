package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	nftconf "github.com/floreabogdan/nftably/internal/render"
	"github.com/floreabogdan/nftably/internal/store"
)

func TestListsCreateEntriesDeleteFlow(t *testing.T) {
	srv, cookie := newTestServer(t)

	// Create a plain group and land on its page.
	rec := postForm(srv, "/lists/create", url.Values{
		"name": {"office"}, "role": {""}, "note": {"the office"},
	}, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create: %d", rec.Code)
	}
	office, err := srv.store.GetListByName("office")
	if err != nil {
		t.Fatal(err)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "/lists/") {
		t.Fatalf("create redirect: %s", loc)
	}

	// Bad name → error round-trip, nothing created.
	rec = postForm(srv, "/lists/create", url.Values{"name": {"Not Valid"}}, cookie)
	if !strings.Contains(rec.Header().Get("Location"), "err=") {
		t.Fatal("bad name accepted")
	}

	// Entries on the office list.
	base := "/lists/" + itoa(office.ID)
	rec = postForm(srv, base+"/entries", url.Values{"cidr": {"10.9.0.0/24"}, "note": {"lan"}}, cookie)
	if rec.Code != http.StatusSeeOther || strings.Contains(rec.Header().Get("Location"), "err=") {
		t.Fatalf("entry add: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	entries, _ := srv.store.ListEntries(office.ID)
	if len(entries) != 1 || entries[0].CIDR != "10.9.0.0/24" {
		t.Fatalf("entries: %+v", entries)
	}

	// A rule sourcing the list appears on its page; deleting the list is
	// refused while the rule exists.
	if _, err := srv.store.CreateRule(store.Rule{Name: "ssh office", Action: "accept", Proto: "tcp", DPorts: "22", SrcListID: office.ID, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, base, nil)
	req.AddCookie(cookie)
	page := httptest.NewRecorder()
	srv.ServeHTTP(page, req)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "ssh office") {
		t.Fatalf("list page: %d", page.Code)
	}
	rec = postForm(srv, base+"/delete", url.Values{}, cookie)
	if !strings.Contains(rec.Header().Get("Location"), "err=") {
		t.Fatal("delete accepted while a rule uses the list")
	}

	// Entry delete round-trips back to the list page.
	rec = postForm(srv, "/lists/entries/"+itoa(entries[0].ID)+"/delete", url.Values{}, cookie)
	if loc := rec.Header().Get("Location"); loc != base {
		t.Fatalf("entry delete redirect: %s", loc)
	}
}

func TestListUpdateRole(t *testing.T) {
	srv, cookie := newTestServer(t)
	office, err := srv.store.CreateList(store.IPList{Name: "office"})
	if err != nil {
		t.Fatal(err)
	}
	rec := postForm(srv, "/lists/"+itoa(office)+"/update", url.Values{
		"name": {"office"}, "role": {"allow"}, "note": {"now management"},
	}, cookie)
	if rec.Code != http.StatusSeeOther || strings.Contains(rec.Header().Get("Location"), "err=") {
		t.Fatalf("update: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	l, _ := srv.store.GetList(office)
	if l.Role != store.RoleAllow || l.Note != "now management" {
		t.Fatalf("update lost: %+v", l)
	}
}

func TestQuickBlockAndSelfGuard(t *testing.T) {
	srv, cookie := newTestServer(t)

	rec := postForm(srv, "/lists/block", url.Values{"ip": {"203.0.113.9"}}, cookie)
	if rec.Code != http.StatusSeeOther || strings.Contains(rec.Header().Get("Location"), "err=") {
		t.Fatalf("quick block: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	// It landed on the seeded block-role list.
	bl, err := srv.store.GetListByName("blacklist")
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := srv.store.ListEntries(bl.ID)
	if len(entries) != 1 || entries[0].CIDR != "203.0.113.9" {
		t.Fatalf("block entries: %+v", entries)
	}

	// Blocking again: friendly overlap message, no duplicate.
	rec = postForm(srv, "/lists/block", url.Values{"ip": {"203.0.113.9"}}, cookie)
	if !strings.Contains(rec.Header().Get("Location"), "err=") {
		t.Fatal("duplicate block did not error")
	}

	// httptest requests come from 192.0.2.1 — blocking your own address (or
	// a range containing it) is refused, on quick block and on the list page.
	for _, self := range []string{"192.0.2.1", "192.0.2.0/24"} {
		rec = postForm(srv, "/lists/block", url.Values{"ip": {self}}, cookie)
		if !strings.Contains(rec.Header().Get("Location"), "err=") {
			t.Fatalf("self-block %s accepted", self)
		}
	}
	rec = postForm(srv, "/lists/"+itoa(bl.ID)+"/entries", url.Values{"cidr": {"192.0.2.1"}}, cookie)
	if !strings.Contains(rec.Header().Get("Location"), "err=") {
		t.Fatal("self-block via list page accepted")
	}
	if entries, _ = srv.store.ListEntries(bl.ID); len(entries) != 1 {
		t.Fatalf("self-block stored: %+v", entries)
	}

	// Even with the seeded lists deleted, quick block recreates a blacklist.
	if err := srv.store.DeleteListEntry(entries[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.DeleteList(bl.ID); err != nil {
		t.Fatal(err)
	}
	rec = postForm(srv, "/lists/block", url.Values{"ip": {"198.51.100.9"}, "back": {"/connections"}}, cookie)
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "/connections?saved=") {
		t.Fatalf("recreate+back redirect: %s", loc)
	}
	nb, err := srv.store.GetListByName("blacklist")
	if err != nil {
		t.Fatal(err)
	}
	if entries, _ = srv.store.ListEntries(nb.ID); len(entries) != 1 {
		t.Fatalf("recreated blacklist entries: %+v", entries)
	}
}

func TestRuleWithSourceList(t *testing.T) {
	srv, cookie := newTestServer(t)
	office, err := srv.store.CreateList(store.IPList{Name: "office"})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.store.AddListEntry(office, "10.9.0.0/24", ""); err != nil {
		t.Fatal(err)
	}

	rec := postForm(srv, "/rules/new", url.Values{
		"name": {"ssh office"}, "chain": {"input"}, "action": {"accept"}, "proto": {"tcp"},
		"dports": {"22"}, "src_list": {itoa(office)}, "enabled": {"on"},
	}, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	rules, _ := srv.store.ListRules()
	if len(rules) != 1 || rules[0].SrcListID != office {
		t.Fatalf("rule: %+v", rules)
	}

	// The rendered config references the list's sets.
	m, err := srv.loadModel()
	if err != nil {
		t.Fatal(err)
	}
	out := nftconf.Config(m)
	for _, want := range []string{"set office4", "ip saddr @office4 tcp dport 22 accept"} {
		if !strings.Contains(out, want) {
			t.Fatalf("config missing %q:\n%s", want, out)
		}
	}

	// List + literal addresses together is a validation error.
	rec = postForm(srv, "/rules/new", url.Values{
		"name": {"both"}, "action": {"accept"}, "proto": {"tcp"}, "dports": {"23"},
		"src_list": {itoa(office)}, "saddrs": {"10.0.0.1"},
	}, cookie)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "either a source list") {
		t.Fatalf("both sources accepted: %d", rec.Code)
	}
}
