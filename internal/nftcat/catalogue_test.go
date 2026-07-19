package nftcat

import (
	"strings"
	"testing"
)

func TestRenderMatch(t *testing.T) {
	cases := []struct {
		key, op, value string
		want           string
	}{
		{"tcp.dport", "==", "22", "tcp dport 22"},
		{"tcp.dport", "==", "80, 443", "tcp dport { 80, 443 }"},
		{"ip.saddr", "!=", "10.0.0.0/8", "ip saddr != 10.0.0.0/8"},
		{"ip.saddr", "==", "@office", "ip saddr @office"},
		{"meta.iifname", "==", "eth0", `iifname "eth0"`},
		{"ct.state", "==", "established, related", "ct state { established, related }"},
		{"tcp.dport", ">", "1024", "tcp dport > 1024"},
	}
	for _, c := range cases {
		got, err := RenderMatch(c.key, c.op, c.value, Ctx{Family: "inet"})
		if err != nil {
			t.Errorf("%s %s %q: %v", c.key, c.op, c.value, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s %s %q: got %q, want %q", c.key, c.op, c.value, got, c.want)
		}
	}
}

func TestRenderStatement(t *testing.T) {
	cases := []struct {
		key    string
		params map[string]string
		family string
		want   string
	}{
		{"accept", nil, "inet", "accept"},
		{"reject", map[string]string{"with": "tcp reset"}, "inet", "reject with tcp reset"},
		{"jump", map[string]string{"target": "checks"}, "inet", "jump checks"},
		{"log", map[string]string{"prefix": "drop ", "level": "info"}, "inet", `log prefix "drop " level info`},
		{"limit", map[string]string{"rate": "10", "per": "minute", "burst": "5"}, "inet", "limit rate 10/minute burst 5 packets"},
		// inet family needs the ip/ip6 qualifier on NAT targets.
		{"dnat", map[string]string{"addr": "192.168.1.10", "port": "80"}, "inet", "dnat ip to 192.168.1.10:80"},
		{"dnat", map[string]string{"addr": "2001:db8::1", "port": "80"}, "inet", "dnat ip6 to [2001:db8::1]:80"},
		// ip family: no qualifier.
		{"dnat", map[string]string{"addr": "192.168.1.10"}, "ip", "dnat to 192.168.1.10"},
		{"masquerade", nil, "inet", "masquerade"},
	}
	for _, c := range cases {
		got, err := RenderStatement(c.key, c.params, Ctx{Family: c.family})
		if err != nil {
			t.Errorf("%s %v: %v", c.key, c.params, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s %v: got %q, want %q", c.key, c.params, got, c.want)
		}
	}
}

// TestRejectsInjection verifies that structural nft characters and out-of-grammar
// values cannot survive into rendered config — the defence against a stored value
// closing its chain/table and injecting foreign nft objects.
func TestRejectsInjection(t *testing.T) {
	matchCases := []struct{ key, value string }{
		{"ip.saddr", "1.1.1.1\n\t}\n}\ntable inet evil {"}, // newline + brace escape
		{"tcp.dport", "22; drop"},                          // statement separator
		{"ip.saddr", "1.1.1.1 # comment out the rest"},     // comment marker
		{"ct.mark", "0x1}"},                                // brace
	}
	for _, c := range matchCases {
		if _, err := RenderMatch(c.key, "==", c.value, Ctx{Family: "inet"}); err == nil {
			t.Errorf("RenderMatch(%s, %q) accepted an unsafe value", c.key, c.value)
		}
	}

	stmtCases := []struct {
		key    string
		params map[string]string
	}{
		{"jump", map[string]string{"target": "evil\n\t}\n}"}},       // non-identifier target
		{"jump", map[string]string{"target": "a; drop"}},            // separator in target
		{"meta.mark.set", map[string]string{"value": "0x1\n drop"}}, // non-number mark
		{"ct.mark.set", map[string]string{"value": "}"}},            // brace mark
		{"log", map[string]string{"level": "info\n drop"}},          // bogus level
		{"limit", map[string]string{"rate": "10", "per": "minute\n drop"}},
		{"dnat", map[string]string{"addr": "1.1.1.1\n drop"}}, // non-address target
		{"redirect", map[string]string{"port": "80\n drop"}},  // non-port
	}
	for _, c := range stmtCases {
		if _, err := RenderStatement(c.key, c.params, Ctx{Family: "inet"}); err == nil {
			t.Errorf("RenderStatement(%s, %v) accepted an unsafe param", c.key, c.params)
		}
	}
}

// TestRejectsBadOperator verifies a match only accepts the operators its field
// offers — so an ordered comparison on an address (which nft rejects) is caught
// at the model boundary, not left to nft --check.
func TestRejectsBadOperator(t *testing.T) {
	rejected := []struct{ key, op string }{
		{"ip.saddr", ">"},      // addresses aren't ordered
		{"ip.saddr", "<="},     //
		{"meta.iifname", "<"},  // interfaces aren't ordered
		{"ct.mark", ">"},       // marks are bitmasks, == / != only
		{"ct.state", ">="},     // flag sets, == / != only
		{"tcp.dport", "badop"}, // not an operator at all
	}
	for _, c := range rejected {
		if _, err := RenderMatch(c.key, c.op, "1", Ctx{Family: "inet"}); err == nil {
			t.Errorf("RenderMatch(%s, %q) accepted an operator the field does not offer", c.key, c.op)
		}
	}
	// The ordered operators are still fine on a numeric field.
	for _, op := range []string{"==", "!=", "<", ">", "<=", ">="} {
		if _, err := RenderMatch("tcp.dport", op, "22", Ctx{Family: "inet"}); err != nil {
			t.Errorf("RenderMatch(tcp.dport, %q): unexpected error %v", op, err)
		}
	}
}

func TestCatalogueJSONValid(t *testing.T) {
	if s := CatalogueJSON(); len(s) < 2 || s[0] != '{' {
		t.Fatalf("catalogue JSON looks wrong: %q", s)
	}
	// The editor needs each match's operator set to present only sensible
	// operators; assert it is carried in the JSON.
	if !strings.Contains(CatalogueJSON(), `"ops"`) {
		t.Error("catalogue JSON is missing per-match operator sets")
	}
}
