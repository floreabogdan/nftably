package nftcat

import "testing"

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

func TestCatalogueJSONValid(t *testing.T) {
	if s := CatalogueJSON(); len(s) < 2 || s[0] != '{' {
		t.Fatalf("catalogue JSON looks wrong: %q", s)
	}
}
