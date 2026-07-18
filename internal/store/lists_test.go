package store

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeCIDR(t *testing.T) {
	cases := map[string]string{
		"192.0.2.7":       "192.0.2.7",
		" 192.0.2.7 ":     "192.0.2.7",
		"10.0.0.5/24":     "10.0.0.0/24", // host bits masked off
		"2001:DB8::10":    "2001:db8::10",
		"2001:db8::/32":   "2001:db8::/32",
		"192.0.2.7/32":    "192.0.2.7", // /32 collapses to the bare IP
		"2001:db8::1/128": "2001:db8::1",
	}
	for in, want := range cases {
		got, msg := NormalizeCIDR(in)
		if msg != "" || got != want {
			t.Errorf("NormalizeCIDR(%q) = %q, %q; want %q", in, got, msg, want)
		}
	}
	for _, bad := range []string{"", "not-an-ip", "127.0.0.1", "0.0.0.0", "224.0.0.1", "::1", "10.0.0.0/33"} {
		if got, msg := NormalizeCIDR(bad); msg == "" {
			t.Errorf("NormalizeCIDR(%q) accepted as %q", bad, got)
		}
	}
}

func TestListEntriesCRUDAndOverlap(t *testing.T) {
	s := testStore(t)

	if err := s.AddListEntry(ListBlock, "203.0.113.0/24", "scanner net"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddListEntry(ListMgmt, "203.0.113.7", "office"); err != nil {
		t.Fatal(err) // same address on the OTHER list is fine — mgmt wins by rule order
	}

	// Overlapping the same list is refused, both directions.
	if err := s.AddListEntry(ListBlock, "203.0.113.7", ""); !errors.Is(err, ErrOverlap) {
		t.Fatalf("narrow-in-wide accepted: %v", err)
	}
	if err := s.AddListEntry(ListBlock, "203.0.0.0/16", ""); !errors.Is(err, ErrOverlap) {
		t.Fatalf("wide-over-narrow accepted: %v", err)
	}
	// Exact duplicate is an overlap too.
	if err := s.AddListEntry(ListBlock, "203.0.113.0/24", ""); err == nil {
		t.Fatal("duplicate accepted")
	}
	// Unknown list, bad note.
	if err := s.AddListEntry("badlist", "192.0.2.1", ""); err == nil {
		t.Fatal("unknown list accepted")
	}
	if err := s.AddListEntry(ListBlock, "192.0.2.1", strings.Repeat("x", 121)); err == nil {
		t.Fatal("oversized note accepted")
	}

	block, err := s.ListEntries(ListBlock)
	if err != nil || len(block) != 1 || block[0].CIDR != "203.0.113.0/24" || block[0].Note != "scanner net" {
		t.Fatalf("block list: %+v err=%v", block, err)
	}
	e, err := s.GetListEntry(block[0].ID)
	if err != nil || e.List != ListBlock {
		t.Fatalf("get: %+v err=%v", e, err)
	}
	if err := s.DeleteListEntry(block[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteListEntry(block[0].ID); err != ErrNotFound {
		t.Fatalf("double delete: %v", err)
	}
	// The mgmt entry is untouched.
	if mgmt, _ := s.ListEntries(ListMgmt); len(mgmt) != 1 {
		t.Fatalf("mgmt list: %+v", mgmt)
	}
}
