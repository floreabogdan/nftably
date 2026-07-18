package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestSetupCatalogueValid(t *testing.T) {
	// Every catalogue rule must pass the same validation a hand-written rule
	// does — setup must never inject something the form would refuse.
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
					t.Errorf("catalogue rule %q invalid: %v", r.Name, errs)
				}
			}
		}
	}
}

func TestSetupPageAndPreview(t *testing.T) {
	srv, cookie := newTestServer(t)

	// The page renders with a first-paint preview and the client's network
	// prefilled (httptest requests come from 192.0.2.1).
	req := httptest.NewRequest(http.MethodGet, "/setup", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("setup page: %d", rec.Code)
	}
	if !strings.Contains(body, "192.0.2.0/24") {
		t.Error("client network not prefilled")
	}
	if !strings.Contains(body, "table inet nftably") {
		t.Error("first-paint preview missing")
	}

	// The live preview reflects the posted choices without persisting.
	rec = postForm(srv, "/setup/preview", url.Values{
		"mgmt_cidr": {"10.0.0.0/24"}, "svc": {"ssh", "web"}, "input_policy": {"drop"},
	}, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("preview: %d", rec.Code)
	}
	prev := rec.Body.String()
	for _, want := range []string{"@management4 accept", "tcp dport 22 accept", "tcp dport { 80, 443 } accept"} {
		if !strings.Contains(prev, want) {
			t.Errorf("preview missing %q:\n%s", want, prev)
		}
	}
	if rules, _ := srv.store.ListRules(); len(rules) != 0 {
		t.Fatalf("preview persisted rules: %+v", rules)
	}
}

func TestSetupApply(t *testing.T) {
	srv, cookie := newTestServer(t)

	rec := postForm(srv, "/setup", url.Values{
		"mgmt_cidr":    {"10.0.0.0/24"},
		"svc":          {"ssh", "dns"},
		"input_policy": {"drop"},
		"wan_iface":    {""},
	}, cookie)
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "/changes?setup=1") {
		t.Fatalf("setup apply: %d %s", rec.Code, rec.Header().Get("Location"))
	}

	rules, _ := srv.store.ListRules()
	var names []string
	for _, r := range rules {
		names = append(names, r.Name)
	}
	if len(rules) != 3 { // ssh + the two dns rules
		t.Fatalf("rules after setup: %v", names)
	}
	fw, _ := srv.store.GetFirewall()
	if fw.InputPolicy != "drop" {
		t.Fatalf("policy: %+v", fw)
	}
	mgmt, err := srv.store.GetListByName("management")
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := srv.store.ListEntries(mgmt.ID)
	if len(entries) != 1 || entries[0].CIDR != "10.0.0.0/24" {
		t.Fatalf("mgmt entries: %+v", entries)
	}

	// Running setup again with the same choices duplicates nothing.
	postForm(srv, "/setup", url.Values{
		"mgmt_cidr": {"10.0.0.0/24"}, "svc": {"ssh", "dns"}, "input_policy": {"drop"},
	}, cookie)
	if rules, _ = srv.store.ListRules(); len(rules) != 3 {
		t.Fatalf("setup re-run duplicated rules: %d", len(rules))
	}
	if entries, _ = srv.store.ListEntries(mgmt.ID); len(entries) != 1 {
		t.Fatalf("setup re-run duplicated mgmt entry: %+v", entries)
	}

	// The dashboard nudge disappears once rules exist.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	rec2 := httptest.NewRecorder()
	srv.ServeHTTP(rec2, req)
	if strings.Contains(rec2.Body.String(), "no rules yet") {
		t.Error("setup nudge still shown after setup")
	}
}

func TestSetupRouterSettings(t *testing.T) {
	srv, cookie := newTestServer(t)
	rec := postForm(srv, "/setup", url.Values{
		"input_policy": {"drop"}, "wan_iface": {"eth0"}, "masquerade": {"on"},
	}, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("setup: %d", rec.Code)
	}
	fw, _ := srv.store.GetFirewall()
	if fw.WANIface != "eth0" || !fw.Masquerade {
		t.Fatalf("router settings: %+v", fw)
	}
}
