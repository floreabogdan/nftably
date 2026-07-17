package advisor

import (
	"strings"
	"testing"

	"github.com/floreabogdan/nftably/internal/store"
)

func keys(sugs []Suggestion) map[string]Suggestion {
	m := map[string]Suggestion{}
	for _, s := range sugs {
		m[s.Key] = s
	}
	return m
}

func TestSuggestUncoveredAndExposed(t *testing.T) {
	scan := Scan{
		Listeners: []Listener{
			{Proto: "tcp", Port: 80, Addr: "0.0.0.0", Wild: true, Process: "nginx"},
			{Proto: "tcp", Port: 5432, Addr: "0.0.0.0", Wild: true, Process: "postgres"},
			{Proto: "tcp", Port: 8080, Addr: "0.0.0.0", Wild: true, Process: "nftably"},
			{Proto: "tcp", Port: 631, Addr: "127.0.0.1", Wild: false, Process: "cupsd"},
		},
	}
	fw := store.Firewall{InputPolicy: "drop"}
	rules := []store.Rule{{Action: "accept", Proto: "tcp", DPorts: "5432", Enabled: true}}

	got := keys(Suggest(scan, fw, rules, 8080))

	// nginx on 80: uncovered under drop → prefilled suggestion.
	s, ok := got["uncovered-tcp-80"]
	if !ok || s.Prefill == nil || s.Prefill.DPorts != "80" {
		t.Fatalf("missing/incomplete port-80 suggestion: %+v", s)
	}
	// postgres covered by an accept rule → exposure warning, not "uncovered".
	if _, ok := got["exposed-tcp-5432"]; !ok {
		t.Fatalf("missing postgres exposure warning: %v", got)
	}
	// A sensitive port that the drop policy shields must NOT get an accept
	// prefill — it gets the bind-localhost advice instead.
	scan.Listeners = append(scan.Listeners, Listener{Proto: "tcp", Port: 6379, Addr: "0.0.0.0", Wild: true, Process: "redis-server"})
	got = keys(Suggest(scan, fw, rules, 8080))
	if _, ok := got["uncovered-tcp-6379"]; ok {
		t.Fatal("redis under drop must not be suggested for opening")
	}
	if s, ok := got["shielded-tcp-6379"]; !ok || s.Prefill != nil {
		t.Fatalf("redis should get the shielded/bind-localhost advice: %+v", s)
	}
	// nftably's own port and loopback-bound cups draw nothing.
	for k := range got {
		if strings.Contains(k, "8080") || strings.Contains(k, "631") {
			t.Fatalf("unexpected suggestion %q", k)
		}
	}
}

func TestSuggestPolicyAndSoftwareNotes(t *testing.T) {
	scan := Scan{Software: []Software{
		{Key: "docker"}, {Key: "bird"}, {Key: "sshd"}, {Key: "nginx"},
	}}
	fw := store.Firewall{InputPolicy: "accept"}
	rules := []store.Rule{{Action: "accept", Proto: "tcp", DPorts: "22", Enabled: true}}

	got := keys(Suggest(scan, fw, rules, 0))
	for _, want := range []string{"policy-drop", "docker-note", "ssh-narrow"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %q; got %v", want, got)
		}
	}
	// bird-bgp and web-server only fire under a drop policy — under accept
	// everything is already reachable.
	if _, ok := got["bird-bgp"]; ok {
		t.Error("bird-bgp should not fire under an accept policy")
	}

	// Under drop, they do.
	fw.InputPolicy = "drop"
	got = keys(Suggest(scan, fw, rules, 0))
	if _, ok := got["bird-bgp"]; !ok {
		t.Errorf("bird-bgp missing under drop: %v", got)
	}
	if _, ok := got["web-server"]; !ok {
		t.Errorf("web-server missing under drop: %v", got)
	}
	// Warnings sort before infos.
	all := Suggest(scan, fw, rules, 0)
	sawInfo := false
	for _, s := range all {
		if s.Severity == "info" {
			sawInfo = true
		} else if sawInfo {
			t.Fatal("warn suggestion sorted after an info one")
		}
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
	// A v4-mapped socket unmaps to its real v4 address.
	if ls[1].Port != 443 || ls[1].Addr != "127.0.0.1" {
		t.Fatalf("v4-mapped: %+v", ls[1])
	}
}
