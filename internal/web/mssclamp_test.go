package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	nftconf "github.com/floreabogdan/nftably/internal/render"
)

// TestClampSizes pins the arithmetic: one path MTU becomes two MSS values,
// because an IPv6 header is 20 bytes larger than an IPv4 one. Getting this
// backwards is the whole reason the wizard exists.
func TestClampSizes(t *testing.T) {
	sizes, label, err := clampSizes("pmtu", "1448", "")
	if err != nil {
		t.Fatalf("pmtu 1448: %v", err)
	}
	if label != "path MTU 1448" {
		t.Errorf("label = %q", label)
	}
	if len(sizes) != 2 || sizes[0].nfproto != "ipv4" || sizes[0].size != "1408" || sizes[1].nfproto != "ipv6" || sizes[1].size != "1388" {
		t.Fatalf("pmtu 1448 gave %+v, want ipv4/1408 + ipv6/1388", sizes)
	}

	sizes, _, err = clampSizes("auto", "", "")
	if err != nil || len(sizes) != 1 || sizes[0].size != "rt mtu" || sizes[0].nfproto != "" {
		t.Fatalf("auto gave %+v, %v; want a single family-agnostic 'rt mtu'", sizes, err)
	}

	sizes, _, err = clampSizes("mss", "", "1388")
	if err != nil || len(sizes) != 1 || sizes[0].size != "1388" {
		t.Fatalf("fixed mss gave %+v, %v", sizes, err)
	}

	bad := []struct{ mode, pmtu, mss string }{
		{"pmtu", "1279", ""},  // below the IPv6 minimum MTU
		{"pmtu", "99999", ""}, // beyond any real link
		{"pmtu", "big", ""},
		{"pmtu", "", ""},
		{"mss", "", "12"},    // absurdly small
		{"mss", "", "70000"}, //
		{"mss", "", "x"},
		{"", "1448", ""}, // no mode at all
		{"nonsense", "1448", ""},
	}
	for _, c := range bad {
		if _, _, err := clampSizes(c.mode, c.pmtu, c.mss); err == nil {
			t.Errorf("clampSizes(%q, %q, %q) accepted a value it should reject", c.mode, c.pmtu, c.mss)
		}
	}
}

// TestMSSClampBuildsRules drives the wizard end to end and checks what it wrote:
// the per-family split, the masked SYN test (a bare `tcp flags syn` would miss
// the SYN+ACK of an inbound connection), and the position — a clamp under an
// accept never runs.
func TestMSSClampBuildsRules(t *testing.T) {
	srv, cookie := newTestServer(t)

	rec := postForm(srv, "/firewall/mss-clamp", url.Values{
		"mode": {"pmtu"}, "pmtu": {"1448"}, "hook": {"forward", "output"},
	}, cookie)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/changes" {
		t.Fatalf("code=%d loc=%q, want 303 /changes", rec.Code, rec.Header().Get("Location"))
	}

	want := map[string][]string{
		"forward": {
			"meta nfproto ipv4 tcp flags & syn == syn tcp option maxseg size set 1408",
			"meta nfproto ipv6 tcp flags & syn == syn tcp option maxseg size set 1388",
		},
		"output": {
			"meta nfproto ipv4 tcp flags & syn == syn tcp option maxseg size set 1408",
			"meta nfproto ipv6 tcp flags & syn == syn tcp option maxseg size set 1388",
		},
	}
	got := clampRulesByHook(t, srv)
	for hook, lines := range want {
		if len(got[hook]) < len(lines) {
			t.Fatalf("%s chain: got %d rules, want at least %d: %v", hook, len(got[hook]), len(lines), got[hook])
		}
		// The clamp rules go in at the top, in family order.
		for i, w := range lines {
			if !strings.HasPrefix(got[hook][i], w) {
				t.Errorf("%s rule %d = %q, want prefix %q", hook, i, got[hook][i], w)
			}
		}
	}
}

// TestMSSClampAutoModeIsFamilyAgnostic checks the `rt mtu` path writes a single
// rule with no nfproto split — the kernel derives the size per family itself —
// and that a second run replaces the first clamp instead of stacking on it.
func TestMSSClampAutoModeIsFamilyAgnostic(t *testing.T) {
	srv, cookie := newTestServer(t)

	postForm(srv, "/firewall/mss-clamp", url.Values{
		"mode": {"pmtu"}, "pmtu": {"1400"}, "hook": {"forward"},
	}, cookie)
	rec := postForm(srv, "/firewall/mss-clamp", url.Values{
		"mode": {"auto"}, "hook": {"forward"}, "iface": {"ppp0"},
	}, cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("code=%d, want 303", rec.Code)
	}
	lines := clampRulesByHook(t, srv)["forward"]
	if len(lines) != 1 {
		t.Fatalf("want the earlier clamp replaced by exactly 1 rule, got %d: %v", len(lines), lines)
	}
	const want = `oifname "ppp0" tcp flags & syn == syn tcp option maxseg size set rt mtu`
	if !strings.HasPrefix(lines[0], want) {
		t.Errorf("rule = %q, want prefix %q", lines[0], want)
	}
}

func TestMSSClampRejectsBadInput(t *testing.T) {
	srv, cookie := newTestServer(t)

	bad := []url.Values{
		{"mode": {"pmtu"}, "pmtu": {"1448"}},                                // no chain picked
		{"mode": {"pmtu"}, "pmtu": {"1448"}, "hook": {"input"}},             // clamping input is meaningless
		{"mode": {"pmtu"}, "pmtu": {"900"}, "hook": {"forward"}},            // below the IPv6 minimum
		{"mode": {"auto"}, "hook": {"forward"}, "iface": {"eth0; drop"}},    // injection in the interface
		{"mode": {"mss"}, "mss": {"1388 drop"}, "hook": {"forward"}},        // injection in the size
		{"mode": {"nope"}, "pmtu": {"1448"}, "hook": {"forward", "output"}}, // unknown mode
	}
	for _, form := range bad {
		rec := postForm(srv, "/firewall/mss-clamp", form, cookie)
		loc := rec.Header().Get("Location")
		if rec.Code != http.StatusSeeOther || !strings.HasPrefix(loc, "/firewall?err=") {
			t.Errorf("%v: code=%d loc=%q, want a 303 back to /firewall with an error", form, rec.Code, loc)
		}
	}
	// Nothing was written by any of them.
	for hook, lines := range clampRulesByHook(t, srv) {
		if len(lines) > 0 {
			t.Errorf("a rejected form still wrote %d rule(s) to %s: %v", len(lines), hook, lines)
		}
	}
}

// clampRulesByHook renders every rule tagged as a clamp, keyed by the hook of
// the chain holding it and in chain order.
func clampRulesByHook(t *testing.T, srv *Server) map[string][]string {
	t.Helper()
	m, err := srv.loadModel()
	if err != nil {
		t.Fatalf("load model: %v", err)
	}
	out := map[string][]string{}
	for _, tbl := range m.Tables {
		for _, c := range tbl.Chains {
			for _, r := range c.Rules {
				if r.Tags != clampTag {
					continue
				}
				line, err := nftconf.RenderRule(tbl.Family, r)
				if err != nil {
					t.Fatalf("clamp rule does not render: %v", err)
				}
				out[c.Hook] = append(out[c.Hook], line)
			}
		}
	}
	return out
}
