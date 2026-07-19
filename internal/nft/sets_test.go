package nft

import "testing"

func TestParseDynamicSets(t *testing.T) {
	// A dynamic timeout set (elements wrapped with val/expires), a static set
	// (must be ignored), and a rule (ignored).
	js := `{"nftables":[
		{"metainfo":{"version":"1.0.9"}},
		{"set":{"family":"inet","table":"filter","name":"ssh_abusers","type":"ipv4_addr","flags":["dynamic","timeout"],
			"elem":[{"elem":{"val":"1.2.3.4","timeout":3600,"expires":3500}},{"elem":{"val":"5.6.7.8","timeout":3600,"expires":3400}}]}},
		{"set":{"family":"inet","table":"filter","name":"office","type":"ipv4_addr","flags":["interval"],
			"elem":["10.0.0.0/8"]}},
		{"rule":{"family":"inet","table":"filter","chain":"input"}}
	]}`
	got, err := parseDynamicSets([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	// Only the dynamic set is returned.
	if len(got) != 1 {
		t.Fatalf("expected 1 dynamic set, got %d: %v", len(got), got)
	}
	members := got["inet/filter/ssh_abusers"]
	if len(members) != 2 || members[0] != "1.2.3.4" || members[1] != "5.6.7.8" {
		t.Errorf("members = %v, want [1.2.3.4 5.6.7.8]", members)
	}
	if _, ok := got["inet/filter/office"]; ok {
		t.Error("a static (interval) set must not be reported as dynamic")
	}
}

func TestParseDynamicSetsBareElements(t *testing.T) {
	// A dynamic set whose elements nft printed as bare strings (no timeout).
	js := `{"nftables":[{"set":{"family":"ip","table":"t","name":"s","flags":["dynamic"],"elem":["9.9.9.9"]}}]}`
	got, err := parseDynamicSets([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	if m := got["ip/t/s"]; len(m) != 1 || m[0] != "9.9.9.9" {
		t.Errorf("members = %v, want [9.9.9.9]", m)
	}
}
