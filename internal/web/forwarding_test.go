package web

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/floreabogdan/nftably/internal/store"
)

func itoa(id int64) string { return strconv.FormatInt(id, 10) }

func TestForwardingSettingsSave(t *testing.T) {
	srv, cookie := newTestServer(t)

	rec := postForm(srv, "/forwarding/settings", url.Values{
		"wan_iface": {"eth0"}, "forward_policy": {"drop"}, "masquerade": {"on"},
	}, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("save settings: %d %s", rec.Code, rec.Body.String())
	}
	fw, err := srv.store.GetFirewall()
	if err != nil {
		t.Fatal(err)
	}
	if fw.WANIface != "eth0" || !fw.Masquerade || fw.ForwardPolicy != "drop" {
		t.Fatalf("settings not saved: %+v", fw)
	}
	// The rules-page policy form must not clobber the forwarding fields.
	if rec := postForm(srv, "/rules/policy", url.Values{"input_policy": {"accept"}}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("save policy: %d", rec.Code)
	}
	fw, _ = srv.store.GetFirewall()
	if fw.InputPolicy != "accept" || fw.WANIface != "eth0" || !fw.Masquerade {
		t.Fatalf("policy save clobbered forwarding: %+v", fw)
	}

	// Masquerade without a WAN interface is rejected with a readable message.
	rec = postForm(srv, "/forwarding/settings", url.Values{
		"wan_iface": {""}, "forward_policy": {"drop"}, "masquerade": {"on"},
	}, cookie)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "WAN") {
		t.Fatalf("masquerade without wan: %d %s", rec.Code, rec.Body.String())
	}
}

func TestPortForwardCRUDFlow(t *testing.T) {
	srv, cookie := newTestServer(t)

	// Create.
	rec := postForm(srv, "/forwarding/new", url.Values{
		"name": {"web"}, "proto": {"tcp"}, "dport": {"443"}, "dest": {"10.0.0.2"}, "dest_port": {"8443"}, "enabled": {"on"},
	}, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	pfs, err := srv.store.ListPortForwards()
	if err != nil || len(pfs) != 1 {
		t.Fatalf("pfs=%v err=%v", pfs, err)
	}
	id := pfs[0].ID

	// An invalid submit re-renders the form with the error, stores nothing.
	rec = postForm(srv, "/forwarding/new", url.Values{
		"name": {"bad"}, "proto": {"tcp"}, "dport": {"80-90"}, "dest": {"10.0.0.2"}, "dest_port": {"80"},
	}, cookie)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "range") {
		t.Fatalf("invalid create: %d", rec.Code)
	}
	if pfs, _ = srv.store.ListPortForwards(); len(pfs) != 1 {
		t.Fatalf("invalid forward stored: %v", pfs)
	}

	// Toggle, edit, delete round-trip.
	if rec := postForm(srv, "/forwarding/"+itoa(id)+"/toggle", url.Values{}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("toggle: %d", rec.Code)
	}
	if p, _ := srv.store.GetPortForward(id); p.Enabled {
		t.Fatal("toggle did not disable")
	}
	rec = postForm(srv, "/forwarding/"+itoa(id)+"/edit", url.Values{
		"name": {"web"}, "proto": {"udp"}, "dport": {"443"}, "dest": {"10.0.0.3"}, "enabled": {"on"},
	}, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("edit: %d %s", rec.Code, rec.Body.String())
	}
	if p, _ := srv.store.GetPortForward(id); p.Proto != "udp" || p.Dest != "10.0.0.3" || p.DestPort != "" {
		t.Fatalf("edit lost: %+v", p)
	}
	if rec := postForm(srv, "/forwarding/"+itoa(id)+"/delete", url.Values{}, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("delete: %d", rec.Code)
	}
	if _, err := srv.store.GetPortForward(id); err != store.ErrNotFound {
		t.Fatalf("still there: %v", err)
	}
	// Unknown id → 404.
	if rec := postForm(srv, "/forwarding/9999/toggle", url.Values{}, cookie); rec.Code != http.StatusNotFound {
		t.Fatalf("missing id: %d", rec.Code)
	}
}

func TestRuleSaveChain(t *testing.T) {
	srv, cookie := newTestServer(t)

	rec := postForm(srv, "/rules/new", url.Values{
		"name": {"no-guests"}, "chain": {"forward"}, "action": {"drop"}, "proto": {"any"},
		"saddrs": {"192.168.9.0/24"}, "enabled": {"on"},
	}, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	rules, err := srv.store.ListRules()
	if err != nil || len(rules) != 1 {
		t.Fatalf("rules=%v err=%v", rules, err)
	}
	if rules[0].Chain != "forward" {
		t.Fatalf("chain not saved: %+v", rules[0])
	}

	// A bad chain value is a validation error, and a missing one means input.
	rec = postForm(srv, "/rules/new", url.Values{
		"name": {"x"}, "chain": {"output"}, "action": {"accept"}, "proto": {"any"},
	}, cookie)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Chain") {
		t.Fatalf("bad chain accepted: %d", rec.Code)
	}
	rec = postForm(srv, "/rules/new", url.Values{
		"name": {"plain"}, "action": {"accept"}, "proto": {"any"}, "enabled": {"on"},
	}, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("chainless create: %d", rec.Code)
	}
	rules, _ = srv.store.ListRules()
	if rules[len(rules)-1].Chain != "input" {
		t.Fatalf("missing chain should default to input: %+v", rules[len(rules)-1])
	}
}
