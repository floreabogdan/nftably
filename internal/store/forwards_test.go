package store

import (
	"strings"
	"testing"
)

func TestPortForwardValidate(t *testing.T) {
	ok := PortForward{Name: "web", Proto: "tcp", DPort: "80", Dest: "10.0.0.2", DestPort: "8080"}
	if errs := ok.Validate(); len(errs) != 0 {
		t.Fatalf("valid forward rejected: %v", errs)
	}

	// Normalization: padded range, v6 canonical form.
	norm := PortForward{Proto: "udp", DPort: " 27000-27100 ", Dest: "2001:DB8::0010"}
	if errs := norm.Validate(); len(errs) != 0 {
		t.Fatalf("errs: %v", errs)
	}
	if norm.DPort != "27000-27100" || norm.Dest != "2001:db8::10" {
		t.Fatalf("not normalized: %+v", norm)
	}

	bad := []PortForward{
		{Proto: "icmp", DPort: "80", Dest: "10.0.0.2"}, // bad proto
		{Proto: "tcp", DPort: "0", Dest: "10.0.0.2"},   // bad port
		{Proto: "tcp", DPort: "80", Dest: "not-an-ip"}, // bad dest
		{Proto: "tcp", DPort: "80", Dest: "127.0.0.1"}, // loopback dest
		{Proto: "tcp", DPort: "80", Dest: "224.0.0.1"}, // multicast dest
		{Proto: "tcp", DPort: "80", Dest: "10.0.0.2", DestPort: "x"},
		{Proto: "tcp", DPort: "80", Dest: "10.0.0.2", DestPort: "1-9"},   // dest range
		{Proto: "tcp", DPort: "80-90", Dest: "10.0.0.2", DestPort: "80"}, // range + dest port
		{Proto: "tcp", DPort: "80", Dest: "10.0.0.2", Name: `a"b`},       // quote in name
	}
	for i, p := range bad {
		if errs := p.Validate(); len(errs) == 0 {
			t.Errorf("case %d accepted: %+v", i, p)
		}
	}
}

func TestPortForwardCRUDAndMove(t *testing.T) {
	s := testStore(t)

	mk := func(name, port string) int64 {
		id, err := s.CreatePortForward(PortForward{Name: name, Proto: "tcp", DPort: port, Dest: "10.0.0.2", Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	a, b, c := mk("a", "80"), mk("b", "81"), mk("c", "82")

	names := func() string {
		pfs, err := s.ListPortForwards()
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, p := range pfs {
			out = append(out, p.Name)
		}
		return strings.Join(out, ",")
	}
	if got := names(); got != "a,b,c" {
		t.Fatalf("order: %s", got)
	}

	if err := s.MovePortForward(c, -1); err != nil {
		t.Fatal(err)
	}
	if got := names(); got != "a,c,b" {
		t.Fatalf("after move: %s", got)
	}
	// Moving past the top is a no-op.
	if err := s.MovePortForward(a, -1); err != nil {
		t.Fatal(err)
	}
	if got := names(); got != "a,c,b" {
		t.Fatalf("no-op move changed order: %s", got)
	}

	p, err := s.GetPortForward(b)
	if err != nil {
		t.Fatal(err)
	}
	p.DestPort = "8081"
	if err := s.UpdatePortForward(p); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPortForwardEnabled(b, false); err != nil {
		t.Fatal(err)
	}
	p, _ = s.GetPortForward(b)
	if p.DestPort != "8081" || p.Enabled {
		t.Fatalf("update lost: %+v", p)
	}

	if err := s.DeletePortForward(a); err != nil {
		t.Fatal(err)
	}
	if err := s.DeletePortForward(a); err != ErrNotFound {
		t.Fatalf("double delete: %v", err)
	}
	if _, err := s.GetPortForward(a); err != ErrNotFound {
		t.Fatalf("get deleted: %v", err)
	}
}

func TestFirewallForwardingRoundTrip(t *testing.T) {
	s := testStore(t)

	// Defaults before any save.
	fw, err := s.GetFirewall()
	if err != nil {
		t.Fatal(err)
	}
	if fw.InputPolicy != "drop" || fw.ForwardPolicy != "drop" || fw.WANIface != "" || fw.Masquerade {
		t.Fatalf("defaults: %+v", fw)
	}

	fw = Firewall{InputPolicy: "drop", ForwardPolicy: "accept", WANIface: "eth0", Masquerade: true}
	if err := s.SaveFirewall(fw); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetFirewall()
	if err != nil {
		t.Fatal(err)
	}
	if got != fw {
		t.Fatalf("round trip: %+v != %+v", got, fw)
	}

	for _, bad := range []Firewall{
		{InputPolicy: "drop", ForwardPolicy: "reject"},
		{InputPolicy: "drop", WANIface: `e"th0`},
		{InputPolicy: "drop", Masquerade: true}, // masquerade without WAN
	} {
		if err := s.SaveFirewall(bad); err == nil {
			t.Errorf("bad firewall accepted: %+v", bad)
		}
	}
}
