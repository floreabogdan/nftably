package nft

import (
	"encoding/json"
	"testing"
)

// TestBanElement covers the element forms a live ban set can hold: a plain address
// with a remaining timeout, a prefix (CIDR) with a timeout, a permanent
// (timeout-less) entry, and an un-re-creatable range. A CIDR or permanent ban must
// be preserved, not silently dropped.
func TestBanElement(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
		ok   bool
	}{
		{"addr with timeout", `{"elem":{"val":"1.2.3.4","expires":3540}}`, "1.2.3.4 timeout 3540s", true},
		{"prefix with timeout", `{"elem":{"val":{"prefix":{"addr":"1.2.3.0","len":24}},"expires":90}}`, "1.2.3.0/24 timeout 90s", true},
		{"permanent addr", `{"elem":{"val":"1.2.3.4"}}`, "1.2.3.4", true},
		{"bare addr", `"1.2.3.4"`, "1.2.3.4", true},
		{"range dropped", `{"elem":{"val":{"range":["1.2.3.4","1.2.3.8"]},"expires":90}}`, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			frag, ok := banElement(json.RawMessage(c.raw))
			if ok != c.ok || frag != c.want {
				t.Errorf("banElement(%s) = (%q, %v), want (%q, %v)", c.raw, frag, ok, c.want, c.ok)
			}
		})
	}
}

// TestBuildPreservedElements: only dynamic TIMEOUT sets that are still in the
// model (keep) yield `add element` statements, each element carrying its remaining
// expiry in seconds — including a CIDR ban. Rate-meter sets (dynamic, no timeout)
// and static sets are skipped.
func TestBuildPreservedElements(t *testing.T) {
	js := `{"nftables":[
		{"set":{"family":"inet","table":"filter","name":"ssh_abusers","flags":["timeout","dynamic"],"elem":[
			{"elem":{"val":"203.0.113.5","timeout":3600,"expires":3540}},
			{"elem":{"val":"203.0.113.6","timeout":3600,"expires":10}},
			{"elem":{"val":{"prefix":{"addr":"192.0.2.0","len":24}},"timeout":3600,"expires":120}}
		]}},
		{"set":{"family":"inet","table":"filter","name":"ssh_abusers_m4","flags":["dynamic"],"elem":[
			{"elem":{"val":"198.51.100.1"}}
		]}},
		{"set":{"family":"inet","table":"filter","name":"office","flags":["interval"],"elem":["10.0.0.0/24"]}}
	]}`

	keep := map[string]bool{"inet/filter/ssh_abusers": true}
	got := buildPreservedElements([]byte(js), keep)
	want := "add element inet filter ssh_abusers { 203.0.113.5 timeout 3540s, 203.0.113.6 timeout 10s, 192.0.2.0/24 timeout 120s }\n"
	if got != want {
		t.Errorf("preserved elements:\n got: %q\nwant: %q", got, want)
	}

	if buildPreservedElements([]byte(js), map[string]bool{}) != "" {
		t.Error("a set absent from the model (empty keep) must not be preserved")
	}
}
