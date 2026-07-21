package web

import (
	"sort"
	"testing"

	"github.com/floreabogdan/nftably/internal/store"
)

func TestListEntryDelta(t *testing.T) {
	before := []store.ListEntry{{CIDR: "1.1.1.0/24"}, {CIDR: "2.2.2.2"}, {CIDR: "2001:db8::/32"}}
	after := []store.ListEntry{{CIDR: "1.1.1.0/24"}, {CIDR: "3.3.3.3"}, {CIDR: "2001:db8::/32"}}
	add, del := listEntryDelta(before, after)
	if len(add) != 1 || add[0] != "3.3.3.3" {
		t.Errorf("add = %v, want [3.3.3.3]", add)
	}
	if len(del) != 1 || del[0] != "2.2.2.2" {
		t.Errorf("del = %v, want [2.2.2.2]", del)
	}
}

func TestGroupBySet(t *testing.T) {
	names := map[string]bool{"blacklist4": true, "blacklist6": true}
	got := groupBySet(names, "blacklist", []string{"1.2.3.4", "2001:db8::1", "10.0.0.0/8", "bogus"})

	v4 := got["blacklist4"]
	sort.Strings(v4)
	if len(v4) != 2 || v4[0] != "1.2.3.4" || v4[1] != "10.0.0.0/8" {
		t.Errorf("blacklist4 = %v, want [1.2.3.4 10.0.0.0/8]", v4)
	}
	if v6 := got["blacklist6"]; len(v6) != 1 || v6[0] != "2001:db8::1" {
		t.Errorf("blacklist6 = %v, want [2001:db8::1]", v6)
	}

	// A set the model doesn't have is skipped entirely.
	if len(groupBySet(map[string]bool{}, "blacklist", []string{"1.2.3.4"})) != 0 {
		t.Error("elements for an absent set should be dropped")
	}
}
