package web

import "testing"

// TestNormalizeTableTextIgnoresVolatileBits is the crux of drift detection: two
// dumps of the SAME ruleset that differ only in packet counters and kernel
// handle numbers must normalize equal, or the poller would cry drift on every
// packet. A genuine rule change must normalize differently.
func TestNormalizeTableTextIgnoresVolatileBits(t *testing.T) {
	a := `table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related counter packets 10 bytes 800 accept # handle 4
		tcp dport 22 counter packets 3 bytes 180 accept # handle 5
	}
}`
	// Same ruleset, traffic has since flowed (counters up) and handles renumbered.
	b := `table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related counter packets 999 bytes 71234 accept # handle 7
		tcp dport 22 counter packets 42 bytes 2520 accept # handle 8
	}
}`
	if normalizeTableText(a) != normalizeTableText(b) {
		t.Error("same ruleset with different counters/handles should normalize equal")
	}

	// A real change (port 22 -> 2222) must normalize differently.
	c := `table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related counter packets 10 bytes 800 accept # handle 4
		tcp dport 2222 counter packets 3 bytes 180 accept # handle 5
	}
}`
	if normalizeTableText(a) == normalizeTableText(c) {
		t.Error("a real rule change (dport 22 -> 2222) should normalize differently")
	}
}
