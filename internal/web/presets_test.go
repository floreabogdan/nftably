package web

import (
	"net/url"
	"strings"
	"testing"

	nftconf "github.com/floreabogdan/nftably/internal/render"
)

func TestBGPPresetBuildsValidConfig(t *testing.T) {
	srv, cookie := newTestServer(t)

	rec := postForm(srv, "/presets/apply", url.Values{"preset": {"bgp-router"}}, cookie)
	if rec.Code != 303 {
		t.Fatalf("apply preset: %d %s", rec.Code, rec.Body.String())
	}

	m, err := srv.loadModel()
	if err != nil {
		t.Fatal(err)
	}
	out := nftconf.Config(m)

	// The control-plane hardening we promised must all be present and render.
	for _, want := range []string{
		"table inet filter {",
		"chain input {",
		"policy drop;",
		`iifname "lo" accept`,
		"ct state invalid drop",
		"ct state { established, related } accept",
		"ip saddr @mgmt4 tcp dport 22 accept",
		"ip saddr @peers4 tcp dport 179 accept",
		"udp dport { 3784, 3785, 4784 }",
		"ip saddr @blacklist4 drop", // Connections "block" bites
		"chain output {",
		"udp dport 5353 drop", // output hygiene: no mDNS leak
		"chain forward {",
		"policy accept;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("preset config missing %q:\n%s", want, out)
		}
	}

	// The mgmt set was seeded with the caller's address, so lint must not warn
	// about SSH lockout.
	warns := nftconf.Lint(m, "0.0.0.0:8080")
	for _, w := range warns {
		if strings.Contains(w, "SSH") || strings.Contains(w, "UI port") {
			t.Errorf("preset should not trigger a lockout warning: %q", w)
		}
	}

	// mgmt seeded with the httptest client address (192.0.2.1).
	mgmt, err := srv.store.GetListByName("mgmt")
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := srv.store.ListEntries(mgmt.ID)
	if len(entries) == 0 {
		t.Error("mgmt should be seeded with the caller's address")
	}
}

func TestWireGuardPresetBuildsValidConfig(t *testing.T) {
	srv, cookie := newTestServer(t)

	rec := postForm(srv, "/presets/apply", url.Values{"preset": {"wireguard"}}, cookie)
	if rec.Code != 303 {
		t.Fatalf("apply preset: %d %s", rec.Code, rec.Body.String())
	}

	m, err := srv.loadModel()
	if err != nil {
		t.Fatal(err)
	}
	out := nftconf.Config(m)

	for _, want := range []string{
		"table inet filter {",
		"chain input {",
		`iifname "lo" accept`,
		"ct state { established, related } accept",
		"ip saddr @mgmt4 tcp dport 22 accept",
		"udp dport 51820 accept", // WireGuard listen port
		`iifname "wg0" accept`,   // trust the tunnel (input)
		"chain forward {",
		"policy drop;",         // the forward chain routes deliberately
		`oifname "wg0" accept`, // traffic back to clients
	} {
		if !strings.Contains(out, want) {
			t.Errorf("wireguard preset config missing %q:\n%s", want, out)
		}
	}

	// Seeded mgmt means no SSH/UI lockout warning.
	for _, w := range nftconf.Lint(m, "0.0.0.0:8080") {
		if strings.Contains(w, "SSH") || strings.Contains(w, "UI port") {
			t.Errorf("wireguard preset should not trigger a lockout warning: %q", w)
		}
	}
}

func TestHomeRouterPresetBuildsValidConfig(t *testing.T) {
	srv, cookie := newTestServer(t)

	rec := postForm(srv, "/presets/apply", url.Values{"preset": {"home-router"}}, cookie)
	if rec.Code != 303 {
		t.Fatalf("apply preset: %d %s", rec.Code, rec.Body.String())
	}

	m, err := srv.loadModel()
	if err != nil {
		t.Fatal(err)
	}
	out := nftconf.Config(m)

	for _, want := range []string{
		"table inet filter {",
		"table inet nat {",
		`iifname "lan" tcp dport 22 accept`,          // LAN-side management
		`iifname "lan" oifname "wan" accept`,         // LAN out to the internet
		"type nat hook prerouting priority dstnat;",  // empty dstnat chain for port-forwards
		"type nat hook postrouting priority srcnat;", // the masquerade chain
		`oifname "wan" masquerade`,                   // share one connection
	} {
		if !strings.Contains(out, want) {
			t.Errorf("home-router preset config missing %q:\n%s", want, out)
		}
	}

	// Seeded mgmt keeps lint from warning about SSH/UI lockout.
	for _, w := range nftconf.Lint(m, "0.0.0.0:8080") {
		if strings.Contains(w, "SSH") || strings.Contains(w, "UI port") {
			t.Errorf("home-router preset should not trigger a lockout warning: %q", w)
		}
	}
}
