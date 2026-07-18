package web

import (
	"net/http/httptest"
	"strings"
	"testing"

	nftconf "github.com/floreabogdan/nftably/internal/render"
	"github.com/floreabogdan/nftably/internal/store"
)

func TestSimulatedLockoutWarnings(t *testing.T) {
	srv, _ := newTestServer(t)

	// A drop-policy input chain that accepts SSH only from @mgmt (= 203.0.113.5).
	// The heuristic lint sees "SSH is accepted" and stays quiet; the simulator
	// knows an operator outside @mgmt would be dropped.
	m := nftconf.Model{Tables: []nftconf.TableTree{{
		Table: store.Table{Family: "inet", Name: "filter"},
		Sets:  []nftconf.SetDef{{Name: "mgmt4", Type: "ipv4_addr", Elements: []string{"203.0.113.5"}}},
		Chains: []nftconf.ChainTree{{
			Chain: store.Chain{Name: "input", Kind: "base", Hook: "input", ChainType: "filter", Priority: "filter", Policy: "drop"},
			Rules: []store.ChainRule{{Enabled: true,
				Matches:    []store.RuleMatch{{Key: "ip.saddr", Op: "==", Value: "@mgmt4"}, {Key: "tcp.dport", Op: "==", Value: "22"}},
				Statements: []store.RuleStatement{{Key: "accept"}}}},
		}},
	}}}

	// Operator NOT in @mgmt → an SSH lockout warning.
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	warns := srv.simulatedLockoutWarnings(req, m)
	if !strings.Contains(strings.Join(warns, " "), "SSH") {
		t.Fatalf("expected an SSH lockout warning for an out-of-mgmt operator, got %v", warns)
	}

	// Operator IN @mgmt → no SSH warning.
	req.RemoteAddr = "203.0.113.5:1234"
	for _, w := range srv.simulatedLockoutWarnings(req, m) {
		if strings.Contains(w, "SSH") {
			t.Fatalf("in-mgmt operator should not get an SSH warning: %q", w)
		}
	}

	// Loopback operator (SSH tunnel) → skipped entirely.
	req.RemoteAddr = "127.0.0.1:1234"
	if w := srv.simulatedLockoutWarnings(req, m); len(w) != 0 {
		t.Fatalf("loopback operator should get no warnings, got %v", w)
	}
}
