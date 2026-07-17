package store

import (
	"path/filepath"
	"testing"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestRuleCRUDAndOrder(t *testing.T) {
	s := testStore(t)

	id1, err := s.CreateRule(Rule{Name: "ssh", Action: "accept", Proto: "tcp", DPorts: "22", Enabled: true})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	id2, err := s.CreateRule(Rule{Name: "web", Action: "accept", Proto: "tcp", DPorts: "80, 443", Enabled: true})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	rules, err := s.ListRules()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rules) != 2 || rules[0].ID != id1 || rules[1].ID != id2 {
		t.Fatalf("order after create: %+v", rules)
	}

	// Move the second rule up; the order flips.
	if err := s.MoveRule(id2, -1); err != nil {
		t.Fatalf("move: %v", err)
	}
	rules, _ = s.ListRules()
	if rules[0].ID != id2 || rules[1].ID != id1 {
		t.Fatalf("order after move: %+v", rules)
	}

	// Moving past the top is a no-op.
	if err := s.MoveRule(id2, -1); err != nil {
		t.Fatalf("move past top: %v", err)
	}
	rules, _ = s.ListRules()
	if rules[0].ID != id2 {
		t.Fatalf("order changed moving past the top: %+v", rules)
	}

	// Update and read back.
	r := rules[1]
	r.DPorts = "2222"
	if err := s.UpdateRule(r); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, err := s.GetRule(id1)
	if err != nil || got.DPorts != "2222" {
		t.Fatalf("get after update: %+v, %v", got, err)
	}

	if err := s.SetRuleEnabled(id1, false); err != nil {
		t.Fatalf("toggle: %v", err)
	}
	if got, _ := s.GetRule(id1); got.Enabled {
		t.Fatal("rule should be disabled")
	}

	if err := s.DeleteRule(id1); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.GetRule(id1); err != ErrNotFound {
		t.Fatalf("get deleted: %v, want ErrNotFound", err)
	}
	if err := s.DeleteRule(id1); err != ErrNotFound {
		t.Fatalf("double delete: %v, want ErrNotFound", err)
	}
}

func TestRuleValidate(t *testing.T) {
	valid := Rule{Name: "ssh from mgmt", Action: "accept", Proto: "tcp", DPorts: "22, 8000-8100", SAddrs: "10.0.0.0/8, 2001:db8::/32", IIf: "eth0"}
	if errs := valid.Validate(); len(errs) != 0 {
		t.Fatalf("valid rule rejected: %v", errs)
	}

	cases := []struct {
		name string
		r    Rule
	}{
		{"bad action", Rule{Action: "log", Proto: "any"}},
		{"bad proto", Rule{Action: "accept", Proto: "icmp"}},
		{"ports without proto", Rule{Action: "accept", Proto: "any", DPorts: "22"}},
		{"bad port", Rule{Action: "accept", Proto: "tcp", DPorts: "70000"}},
		{"inverted range", Rule{Action: "accept", Proto: "tcp", DPorts: "100-22"}},
		{"bad source", Rule{Action: "accept", Proto: "any", SAddrs: "not-an-ip"}},
		{"bad iface", Rule{Action: "accept", Proto: "any", IIf: `eth0"; drop`}},
		{"quote in name", Rule{Name: `a"b`, Action: "accept", Proto: "any"}},
	}
	for _, c := range cases {
		if errs := c.r.Validate(); len(errs) == 0 {
			t.Errorf("%s: expected a validation error", c.name)
		}
	}
}

func TestParsePorts(t *testing.T) {
	toks, errs := ParsePorts(" 22, 80 443\n8000-8100 ")
	if len(errs) != 0 {
		t.Fatalf("errs: %v", errs)
	}
	want := []string{"22", "80", "443", "8000-8100"}
	if len(toks) != len(want) {
		t.Fatalf("toks: %v", toks)
	}
	for i := range want {
		if toks[i] != want[i] {
			t.Fatalf("toks: %v, want %v", toks, want)
		}
	}
}

func TestFirewallDefaultsAndSave(t *testing.T) {
	s := testStore(t)
	f, err := s.GetFirewall()
	if err != nil || f.InputPolicy != "drop" {
		t.Fatalf("default firewall: %+v, %v", f, err)
	}
	if err := s.SaveFirewall(Firewall{InputPolicy: "accept"}); err != nil {
		t.Fatalf("save: %v", err)
	}
	if f, _ := s.GetFirewall(); f.InputPolicy != "accept" {
		t.Fatalf("read back: %+v", f)
	}
	if err := s.SaveFirewall(Firewall{InputPolicy: "reject"}); err == nil {
		t.Fatal("bad policy should be rejected")
	}
}
