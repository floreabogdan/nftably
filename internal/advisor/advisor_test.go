package advisor

import (
	"strings"
	"testing"

	nftconf "github.com/floreabogdan/nftably/internal/render"
	"github.com/floreabogdan/nftably/internal/store"
)

func keyed(fs []Finding) map[string]Finding {
	m := map[string]Finding{}
	for _, f := range fs {
		m[f.Key] = f
	}
	return m
}

// inputModel builds a one-table model with an input base chain of the given
// policy plus the supplied rules.
func inputModel(policy string, rules ...store.ChainRule) nftconf.Model {
	return nftconf.Model{Tables: []nftconf.TableTree{{
		Table: store.Table{Family: "inet", Name: "filter"},
		Chains: []nftconf.ChainTree{{
			Chain: store.Chain{Name: "input", Kind: "base", Hook: "input", ChainType: "filter", Priority: "filter", Policy: policy},
			Rules: rules,
		}},
	}}}
}

func acceptPort(proto string, port string) store.ChainRule {
	key := "tcp.dport"
	if proto == "udp" {
		key = "udp.dport"
	}
	return store.ChainRule{Enabled: true,
		Matches:    []store.RuleMatch{{Key: key, Op: "==", Value: port}},
		Statements: []store.RuleStatement{{Key: "accept"}},
	}
}

func TestAnalyzeBlockedListenerOffersAllow(t *testing.T) {
	// sshd listens on :22, drop-policy input with no rule for it → blocked, with
	// a one-click allow.
	scan := Scan{Listeners: []Listener{{Proto: "tcp", Port: 22, Addr: "0.0.0.0", Wild: true, Process: "sshd"}}}
	got := keyed(Analyze(scan, inputModel("drop"), Options{ListenPort: 8080}))
	f, ok := got["listener-tcp-22-blocked"]
	if !ok {
		t.Fatalf("expected a blocked-listener finding, got %v", got)
	}
	if f.Verdict != "DROP" || f.Allow == nil || f.Allow.Port != 22 || f.Sim == "" {
		t.Fatalf("blocked finding is incomplete: %+v", f)
	}
}

func TestAnalyzeExposedDatabaseWarns(t *testing.T) {
	// postgres reachable from anywhere (accept rule for 5432) → exposure warning,
	// severity warn, no allow action.
	scan := Scan{Listeners: []Listener{{Proto: "tcp", Port: 5432, Addr: "0.0.0.0", Wild: true, Process: "postgres"}}}
	got := keyed(Analyze(scan, inputModel("drop", acceptPort("tcp", "5432")), Options{ListenPort: 8080}))
	f, ok := got["listener-tcp-5432-exposed"]
	if !ok {
		t.Fatalf("expected an exposed-database warning, got %v", got)
	}
	if f.Severity != "warn" || f.Verdict != "ACCEPT" || f.Allow != nil {
		t.Fatalf("exposed finding wrong: %+v", f)
	}
}

func TestAnalyzeOpenNonSensitiveIsInfo(t *testing.T) {
	// A web server reachable from anywhere is fine — info, not warn.
	scan := Scan{Listeners: []Listener{{Proto: "tcp", Port: 443, Addr: "0.0.0.0", Wild: true, Process: "nginx"}}}
	got := keyed(Analyze(scan, inputModel("drop", acceptPort("tcp", "443")), Options{ListenPort: 8080}))
	f, ok := got["listener-tcp-443-open"]
	if !ok || f.Severity != "info" || f.Verdict != "ACCEPT" {
		t.Fatalf("expected an info 'reachable from anywhere' finding, got %+v (%v)", f, got)
	}
}

func TestAnalyzeSkipsOwnPortAndLoopback(t *testing.T) {
	scan := Scan{Listeners: []Listener{
		{Proto: "tcp", Port: 8080, Addr: "0.0.0.0", Wild: true, Process: "nftably"},
		{Proto: "tcp", Port: 631, Addr: "127.0.0.1", Wild: false, Process: "cupsd"},
	}}
	for k := range keyed(Analyze(scan, inputModel("drop"), Options{ListenPort: 8080})) {
		if strings.Contains(k, "8080") || strings.Contains(k, "631") {
			t.Fatalf("own port / loopback listener should not produce a finding: %q", k)
		}
	}
}

func TestAnalyzePosture(t *testing.T) {
	// Accept-policy input → the "accepts by default" warning.
	if _, ok := keyed(Analyze(Scan{}, inputModel("accept"), Options{}))["input-accept-policy"]; !ok {
		t.Fatal("accept-policy input should warn")
	}
	// Drop-policy input → no posture warning.
	if _, ok := keyed(Analyze(Scan{}, inputModel("drop"), Options{}))["input-accept-policy"]; ok {
		t.Fatal("drop-policy input should not warn about posture")
	}
	// No input chain at all → the strongest posture warning.
	empty := nftconf.Model{Tables: []nftconf.TableTree{{Table: store.Table{Family: "inet", Name: "filter"}}}}
	if _, ok := keyed(Analyze(Scan{}, empty, Options{}))["no-input-chain"]; !ok {
		t.Fatal("a model with no input chain should warn that nothing filters input")
	}
}

func TestAnalyzeForwarding(t *testing.T) {
	// Routing box, no drop-policy forward chain → forwarding-open.
	if _, ok := keyed(Analyze(Scan{IPForward: true}, inputModel("drop"), Options{}))["forwarding-open"]; !ok {
		t.Fatal("a routing box without a filtering forward chain should be flagged")
	}
	// Add a drop-policy forward chain → retired.
	m := inputModel("drop")
	m.Tables[0].Chains = append(m.Tables[0].Chains, nftconf.ChainTree{
		Chain: store.Chain{Name: "forward", Kind: "base", Hook: "forward", ChainType: "filter", Priority: "filter", Policy: "drop"},
	})
	if _, ok := keyed(Analyze(Scan{IPForward: true}, m, Options{}))["forwarding-open"]; ok {
		t.Fatal("a drop-policy forward chain should retire the forwarding finding")
	}
	// Non-routing box → nothing.
	if _, ok := keyed(Analyze(Scan{IPForward: false}, inputModel("drop"), Options{}))["forwarding-open"]; ok {
		t.Fatal("a non-routing box should not be flagged for forwarding")
	}
}

func TestFilterDismissed(t *testing.T) {
	fs := []Finding{{Key: "a"}, {Key: "b"}, {Key: "c"}}
	vis, hid := Filter(fs, map[string]bool{"b": true})
	if len(vis) != 2 || len(hid) != 1 || hid[0].Key != "b" {
		t.Fatalf("filter split wrong: vis=%v hid=%v", vis, hid)
	}
}

func TestParseProcNet(t *testing.T) {
	tcp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 100 0 0 10 0
   2: 00000000:0016 0100007F:1234 01 00000000:00000000 00:00000000 00000000     0        0 12347 1 0000000000000000 100 0 0 10 0
`
	ls := parseProcNet(strings.NewReader(tcp), "tcp")
	if len(ls) != 2 {
		t.Fatalf("listeners: %+v", ls)
	}
	if ls[0].Port != 8080 || !ls[0].Wild || ls[0].Addr != "0.0.0.0" || ls[0].Process != "12345" {
		t.Fatalf("wildcard listener: %+v", ls[0])
	}
	if ls[1].Port != 631 || ls[1].Wild || ls[1].Addr != "127.0.0.1" {
		t.Fatalf("loopback listener: %+v", ls[1])
	}

	tcp6 := ` sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode
   0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 222 1 0000000000000000 100 0 0 10 0
   1: 0000000000000000FFFF00000100007F:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 223 1 0000000000000000 100 0 0 10 0
`
	ls = parseProcNet(strings.NewReader(tcp6), "tcp")
	if len(ls) != 2 {
		t.Fatalf("v6 listeners: %+v", ls)
	}
	if ls[0].Port != 80 || !ls[0].Wild || ls[0].Addr != "::" {
		t.Fatalf("v6 wildcard: %+v", ls[0])
	}
	if ls[1].Port != 443 || ls[1].Addr != "127.0.0.1" {
		t.Fatalf("v4-mapped: %+v", ls[1])
	}
}
