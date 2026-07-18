package web

import (
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/floreabogdan/nftably/internal/conntrack"
)

func TestClassify(t *testing.T) {
	a := func(s string) netip.Addr { return netip.MustParseAddr(s) }
	cases := []struct {
		f          conntrack.Flow
		srcL, dstL bool
		dir        string
		remote     string
	}{
		// Inbound to this box: the remote is the source.
		{conntrack.Flow{Src: a("203.0.113.9"), Dst: a("10.0.0.1")}, false, true, "in", "203.0.113.9"},
		// Outbound from this box: the remote is the destination.
		{conntrack.Flow{Src: a("10.0.0.1"), Dst: a("1.1.1.1")}, true, false, "out", "1.1.1.1"},
		// Routed LAN->internet: prefer the public side over the LAN host.
		{conntrack.Flow{Src: a("192.168.1.50"), Dst: a("142.250.0.1")}, false, false, "routed", "142.250.0.1"},
		// Routed internet->LAN (port-forward): the public side is the source.
		{conntrack.Flow{Src: a("203.0.113.9"), Dst: a("192.168.1.50")}, false, false, "routed", "203.0.113.9"},
	}
	for i, c := range cases {
		dir, remote := classify(c.f, c.srcL, c.dstL)
		if dir != c.dir || remote.String() != c.remote {
			t.Errorf("case %d: got %s/%s want %s/%s", i, dir, remote, c.dir, c.remote)
		}
	}
}

func TestFlagEmoji(t *testing.T) {
	if got := flagEmoji("DE"); got != "\U0001F1E9\U0001F1EA" {
		t.Errorf("DE flag: %q", got)
	}
	for _, bad := range []string{"", "D", "DEU", "d e", "12"} {
		if flagEmoji(bad) != "" {
			t.Errorf("%q produced a flag", bad)
		}
	}
}

func TestQuickBlockBackRedirect(t *testing.T) {
	srv, cookie := newTestServer(t)

	rec := postForm(srv, "/lists/block", url.Values{"ip": {"203.0.113.9"}, "back": {"/connections"}}, cookie)
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "/connections?saved=") {
		t.Fatalf("back redirect: %s", loc)
	}
	// A non-local back target falls back to /lists — no open redirects.
	rec = postForm(srv, "/lists/block", url.Values{"ip": {"203.0.113.10"}, "back": {"//evil.example"}}, cookie)
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "/lists?") {
		t.Fatalf("external back accepted: %s", loc)
	}
}

func TestSettingsGeoIPSave(t *testing.T) {
	srv, cookie := newTestServer(t)
	rec := postForm(srv, "/settings/geoip", url.Values{"geoip_db": {"/var/lib/GeoIP/GeoLite2-Country.mmdb"}}, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("save geoip: %d", rec.Code)
	}
	st, _, err := srv.store.GetSettings()
	if err != nil || st.GeoIPDB != "/var/lib/GeoIP/GeoLite2-Country.mmdb" {
		t.Fatalf("geoip not saved: %+v err=%v", st, err)
	}
}
