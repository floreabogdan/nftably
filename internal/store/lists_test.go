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

func TestSeededListsAndCRUD(t *testing.T) {
	s := testStore(t)

	// A fresh database ships the two opinionated lists.
	lists, err := s.ListLists()
	if err != nil || len(lists) != 2 {
		t.Fatalf("seeded lists: %+v err=%v", lists, err)
	}
	if lists[0].Name != "management" || lists[0].Role != RoleAllow ||
		lists[1].Name != "blacklist" || lists[1].Role != RoleBlock {
		t.Fatalf("seeds: %+v", lists)
	}

	// Create a plain group; names are set-safe and unique.
	id, err := s.CreateList(IPList{Name: "office", Note: "the office network"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateList(IPList{Name: "office"}); err == nil {
		t.Fatal("duplicate name accepted")
	}
	for _, bad := range []IPList{
		{Name: "Office"}, {Name: "1st"}, {Name: "has space"}, {Name: ""},
		{Name: strings.Repeat("x", 30)}, {Name: "ok", Role: "reject"},
	} {
		if _, err := s.CreateList(bad); err == nil {
			t.Errorf("bad list accepted: %+v", bad)
		}
	}

	l, err := s.GetList(id)
	if err != nil || l.Name != "office" || l.Role != RoleNone {
		t.Fatalf("get: %+v err=%v", l, err)
	}
	l.Role = RoleAllow
	l.Note = "promoted"
	if err := s.UpdateList(l); err != nil {
		t.Fatal(err)
	}
	if l, _ = s.GetList(id); l.Role != RoleAllow || l.Note != "promoted" {
		t.Fatalf("update lost: %+v", l)
	}
	if _, err := s.GetListByName("office"); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteList(id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetList(id); err != ErrNotFound {
		t.Fatalf("deleted list still there: %v", err)
	}
}

func TestListDeleteRefusedWhileRulesUseIt(t *testing.T) {
	s := testStore(t)
	id, err := s.CreateList(IPList{Name: "office"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateRule(Rule{Name: "ssh from office", Action: "accept", Proto: "tcp", DPorts: "22", SrcListID: id, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteList(id); err == nil {
		t.Fatal("list deleted while a rule uses it")
	}
	rules, err := s.RulesUsingList(id)
	if err != nil || len(rules) != 1 || rules[0].Name != "ssh from office" {
		t.Fatalf("rules using list: %+v err=%v", rules, err)
	}
}

func TestListEntriesCRUDAndOverlap(t *testing.T) {
	s := testStore(t)
	block, err := s.GetListByName("blacklist")
	if err != nil {
		t.Fatal(err)
	}
	mgmt, err := s.GetListByName("management")
	if err != nil {
		t.Fatal(err)
	}

	if err := s.AddListEntry(block.ID, "203.0.113.0/24", "scanner net"); err != nil {
		t.Fatal(err)
	}
	// The same address on ANOTHER list is fine — behaviour order decides.
	if err := s.AddListEntry(mgmt.ID, "203.0.113.7", "office"); err != nil {
		t.Fatal(err)
	}

	// Overlapping the same list is refused, both directions.
	if err := s.AddListEntry(block.ID, "203.0.113.7", ""); !errors.Is(err, ErrOverlap) {
		t.Fatalf("narrow-in-wide accepted: %v", err)
	}
	if err := s.AddListEntry(block.ID, "203.0.0.0/16", ""); !errors.Is(err, ErrOverlap) {
		t.Fatalf("wide-over-narrow accepted: %v", err)
	}
	if err := s.AddListEntry(block.ID, "203.0.113.0/24", ""); err == nil {
		t.Fatal("duplicate accepted")
	}
	// Unknown list, oversized note.
	if err := s.AddListEntry(9999, "192.0.2.1", ""); err != ErrNotFound {
		t.Fatalf("unknown list: %v", err)
	}
	if err := s.AddListEntry(block.ID, "192.0.2.1", strings.Repeat("x", 121)); err == nil {
		t.Fatal("oversized note accepted")
	}

	entries, err := s.ListEntries(block.ID)
	if err != nil || len(entries) != 1 || entries[0].CIDR != "203.0.113.0/24" || entries[0].Note != "scanner net" {
		t.Fatalf("block entries: %+v err=%v", entries, err)
	}
	all, err := s.AllEntries()
	if err != nil || len(all[block.ID]) != 1 || len(all[mgmt.ID]) != 1 {
		t.Fatalf("all entries: %+v err=%v", all, err)
	}
	e, err := s.GetListEntry(entries[0].ID)
	if err != nil || e.ListID != block.ID {
		t.Fatalf("get: %+v err=%v", e, err)
	}
	if err := s.DeleteListEntry(e.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteListEntry(e.ID); err != ErrNotFound {
		t.Fatalf("double delete: %v", err)
	}
	if mgmtEntries, _ := s.ListEntries(mgmt.ID); len(mgmtEntries) != 1 {
		t.Fatalf("mgmt entries: %+v", mgmtEntries)
	}
}

func TestDedupePrefixes(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"exact duplicate", []string{"10.0.0.0/8", "10.0.0.0/8"}, []string{"10.0.0.0/8"}},
		{"containment drops child", []string{"10.0.0.0/8", "10.5.0.0/16"}, []string{"10.0.0.0/8"}},
		{"disjoint siblings kept", []string{"10.128.0.0/9", "10.0.0.0/9"}, []string{"10.0.0.0/9", "10.128.0.0/9"}},
		{"single host to bare", []string{"1.2.3.4/32"}, []string{"1.2.3.4"}},
		{"invalid skipped", []string{"nonsense", "1.1.1.0/24"}, []string{"1.1.1.0/24"}},
		{"v4 and v6 both kept", []string{"2001:db8::/32", "10.0.0.0/8"}, []string{"10.0.0.0/8", "2001:db8::/32"}},
		{"nested three levels", []string{"10.0.0.0/24", "10.0.0.0/8", "10.0.0.0/16"}, []string{"10.0.0.0/8"}},
	}
	for _, c := range cases {
		got := dedupePrefixes(c.in)
		if len(got) != len(c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: got %v, want %v", c.name, got, c.want)
				break
			}
		}
	}
}

func TestReplaceListEntries(t *testing.T) {
	s := testStore(t)
	id, err := s.CreateList(IPList{Name: "feedset", Source: SourceURL, SourceArg: "https://example.com/f.txt"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	n, err := s.ReplaceListEntries(id, []string{"1.1.1.0/24", "2.2.2.2", "1.1.1.0/24"}) // one dup
	if err != nil || n != 2 {
		t.Fatalf("first replace: n=%d err=%v", n, err)
	}
	// A second replace fully supersedes the first.
	n, err = s.ReplaceListEntries(id, []string{"9.9.9.0/24"})
	if err != nil || n != 1 {
		t.Fatalf("second replace: n=%d err=%v", n, err)
	}
	entries, _ := s.ListEntries(id)
	if len(entries) != 1 || entries[0].CIDR != "9.9.9.0/24" {
		t.Fatalf("entries after replace = %+v", entries)
	}
}

func TestSetReferencesObjectModel(t *testing.T) {
	s := testStore(t)
	lid, err := s.CreateList(IPList{Name: "office"})
	if err != nil {
		t.Fatal(err)
	}
	// Build an object-model rule that references @office4.
	tid, _ := s.CreateTable(Table{Family: "inet", Name: "t1"})
	cid, _ := s.CreateChain(Chain{TableID: tid, Name: "input", Kind: "base", Hook: "input", ChainType: "filter", Priority: "filter", Policy: "drop"})
	if _, err := s.CreateChainRule(ChainRule{ChainID: cid, Enabled: true,
		Matches:    []RuleMatch{{Key: "ip.saddr", Op: "==", Value: "@office4"}},
		Statements: []RuleStatement{{Key: "accept"}},
	}); err != nil {
		t.Fatal(err)
	}

	uses, err := s.RulesReferencingSet("office")
	if err != nil || len(uses) != 1 || uses[0].ChainName != "input" || uses[0].TableName != "t1" {
		t.Fatalf("RulesReferencingSet = %+v err=%v", uses, err)
	}
	if counts, _ := s.SetReferenceCounts(); counts["office"] != 1 {
		t.Fatalf("SetReferenceCounts[office] = %d, want 1", counts["office"])
	}
	// Delete must be refused while the object-model rule references it.
	if err := s.DeleteList(lid); err == nil {
		t.Fatal("deleted a list still referenced by an object-model rule")
	}
}
