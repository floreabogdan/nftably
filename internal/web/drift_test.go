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

// TestNormalizeTableTextIgnoresDynamicSetContents guards the auto-ban feature:
// nftably applies an EMPTY dynamic set, and the kernel fills it with offender
// addresses whose `expires` counts down every second. That runtime state must
// not read as drift, or every banned IP would trip a false "changed outside
// nftably" alarm — and the countdown would make the fingerprint unstable.
func TestNormalizeTableTextIgnoresDynamicSetContents(t *testing.T) {
	// What nftably applied: the set is declared empty.
	applied := `table inet filter {
	set ssh_abusers {
		type ipv4_addr
		flags dynamic,timeout
		timeout 1h
	}
}`
	// Live, after the kernel banned two sources — an elements block appeared,
	// each with a per-second-decrementing expires.
	live := `table inet filter {
	set ssh_abusers {
		type ipv4_addr
		flags dynamic,timeout
		timeout 1h
		elements = { 1.2.3.4 timeout 1h expires 59m58s,
			     5.6.7.8 timeout 1h expires 12m3s }
	}
}`
	if normalizeTableText(applied) != normalizeTableText(live) {
		t.Errorf("kernel-populated dynamic set should not count as drift:\napplied=%q\nlive=%q",
			normalizeTableText(applied), normalizeTableText(live))
	}

	// A STATIC set's elements have no `expires` and must still be compared — a
	// changed member is genuine drift, not runtime noise.
	s1 := `table inet filter {
	set office {
		type ipv4_addr
		flags interval
		elements = { 10.0.0.0/24 }
	}
}`
	s2 := `table inet filter {
	set office {
		type ipv4_addr
		flags interval
		elements = { 10.0.0.0/24, 192.168.0.0/16 }
	}
}`
	if normalizeTableText(s1) == normalizeTableText(s2) {
		t.Error("an edited static set (added member) should normalize differently")
	}
}
