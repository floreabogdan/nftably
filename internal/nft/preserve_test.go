package nft

import "testing"

// TestBuildPreservedElements: only dynamic TIMEOUT sets that are still in the
// model (keep) yield `add element` statements, each element carrying its remaining
// expiry in seconds. Rate-meter sets (dynamic, no timeout) and static sets are
// skipped, as are elements about to expire.
func TestBuildPreservedElements(t *testing.T) {
	js := `{"nftables":[
		{"set":{"family":"inet","table":"filter","name":"ssh_abusers","flags":["timeout","dynamic"],"elem":[
			{"elem":{"val":"203.0.113.5","timeout":3600,"expires":3540}},
			{"elem":{"val":"203.0.113.6","timeout":3600,"expires":10}}
		]}},
		{"set":{"family":"inet","table":"filter","name":"ssh_abusers_m4","flags":["dynamic"],"elem":[
			{"elem":{"val":"198.51.100.1"}}
		]}},
		{"set":{"family":"inet","table":"filter","name":"office","flags":["interval"],"elem":["10.0.0.0/24"]}}
	]}`

	keep := map[string]bool{"inet/filter/ssh_abusers": true}
	got := buildPreservedElements([]byte(js), keep)
	want := "add element inet filter ssh_abusers { 203.0.113.5 timeout 3540s, 203.0.113.6 timeout 10s }\n"
	if got != want {
		t.Errorf("preserved elements:\n got: %q\nwant: %q", got, want)
	}

	if buildPreservedElements([]byte(js), map[string]bool{}) != "" {
		t.Error("a set absent from the model (empty keep) must not be preserved")
	}
}
