package render

import "testing"

// TestCanonicalizeMatchesKernelReadback is the crux of a quiet Changes page:
// what nftably renders and what `nft list` prints back for the SAME applied
// ruleset must canonicalize equal, despite the kernel filling in counter totals,
// wrapping set elements one-per-line, reordering anonymous-set members, and
// quoting the counter name. Built from a real router's diff.
func TestCanonicalizeMatchesKernelReadback(t *testing.T) {
	// What nftably renders: empty counter object, elements packed two-per-line,
	// catalogue-order ICMP types, bare `counter name denied`.
	rendered := "table inet filter {\n" +
		"\tcounter denied {\n" +
		"\t}\n" +
		"\tset peers6 {\n" +
		"\t\ttype ipv6_addr\n" +
		"\t\tflags interval\n" +
		"\t\telements = { 2602:fa7e:21::1, fd00:210:622::2,\n" +
		"\t\t\t     fd00:210:622::4 }\n" +
		"\t}\n" +
		"\tchain input {\n" +
		"\t\ticmpv6 type { echo-request, echo-reply, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, destination-unreachable, packet-too-big, time-exceeded, parameter-problem } accept comment \"nftably: ICMPv6\"\n" +
		"\t\tct state new counter name denied limit rate 5/second burst 10 packets log prefix \"in-drop \" comment \"nftably: denied\"\n" +
		"\t}\n" +
		"}\n"

	// What the kernel lists back: counter carries live totals, elements one-per-line,
	// ICMP types reordered by numeric value, `counter name "denied"` quoted, handles.
	live := "table inet filter {\n" +
		"\tcounter denied {\n" +
		"\t\tpackets 6 bytes 395\n" +
		"\t}\n" +
		"\tset peers6 {\n" +
		"\t\ttype ipv6_addr\n" +
		"\t\tflags interval\n" +
		"\t\telements = { 2602:fa7e:21::1,\n" +
		"\t\t\t     fd00:210:622::2,\n" +
		"\t\t\t     fd00:210:622::4 }\n" +
		"\t}\n" +
		"\tchain input {\n" +
		"\t\ticmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, echo-request, echo-reply, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept comment \"nftably: ICMPv6\" # handle 12\n" +
		"\t\tct state new counter name \"denied\" limit rate 5/second burst 10 packets log prefix \"in-drop \" comment \"nftably: denied\" # handle 13\n" +
		"\t}\n" +
		"}\n"

	if got, want := CanonicalizeNftText(live), CanonicalizeNftText(rendered); got != want {
		t.Errorf("kernel readback and render should canonicalize equal\n--- canonical(live) ---\n%s\n--- canonical(rendered) ---\n%s", got, want)
	}
}

// TestCanonicalizeSurfacesRealChanges makes sure the normalization is not so
// aggressive that it hides an actual edit: a changed set member and a changed
// port must still canonicalize differently.
func TestCanonicalizeSurfacesRealChanges(t *testing.T) {
	base := "table inet filter {\n\tset office {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\telements = { 10.0.0.0/24 }\n\t}\n\tchain input {\n\t\ttcp dport 22 accept\n\t}\n}\n"
	memberAdded := "table inet filter {\n\tset office {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\telements = { 10.0.0.0/24, 192.168.0.0/16 }\n\t}\n\tchain input {\n\t\ttcp dport 22 accept\n\t}\n}\n"
	portChanged := "table inet filter {\n\tset office {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\telements = { 10.0.0.0/24 }\n\t}\n\tchain input {\n\t\ttcp dport 2222 accept\n\t}\n}\n"

	if CanonicalizeNftText(base) == CanonicalizeNftText(memberAdded) {
		t.Error("adding a set member should canonicalize differently")
	}
	if CanonicalizeNftText(base) == CanonicalizeNftText(portChanged) {
		t.Error("changing a port should canonicalize differently")
	}
}

// TestCanonicalizeAutoBanReadback covers the rate-limit auto-ban feature, whose
// dynamic sets and detector the kernel reformats on readback: it stamps a default
// `size` on the sets, drops the space in `flags dynamic, timeout`, and prints the
// detector in one of several version-dependent spellings — `meter m { … }` (what
// nftably renders), `meter m size N { … }` (older nft), or `add @m { … }` (newer
// nft). All must canonicalize to the same thing. Spellings from real routers.
func TestCanonicalizeAutoBanReadback(t *testing.T) {
	// table(sizeLine, flags, detector): one inet filter table with a dynamic set
	// and a rate-limit detector, parameterized by the version-dependent bits.
	table := func(sizeLine, flags, detector string) string {
		return "table inet filter {\n" +
			"\tset ssh_abusers_m4 {\n" +
			"\t\ttype ipv4_addr\n" +
			sizeLine +
			"\t\tflags " + flags + "\n" +
			"\t}\n" +
			"\tchain input {\n" +
			"\t\ttype filter hook input priority filter; policy drop;\n" +
			"\t\ttcp dport 22 ct state new " + detector + " add @ssh_abusers { ip saddr timeout 1h } drop comment \"nftably: SSH auto-ban: detect floods (IPv4)\"\n" +
			"\t}\n" +
			"}\n"
	}

	rendered := table("", "dynamic, timeout", "meter ssh_abusers_m4 { ip saddr limit rate over 10/minute burst 5 packets }")
	liveOlder := table("\t\tsize 65535\n", "dynamic,timeout", "meter ssh_abusers_m4 size 65535 { ip saddr limit rate over 10/minute burst 5 packets } # handle 9")
	liveNewer := table("\t\tsize 65535\n", "dynamic,timeout", "add @ssh_abusers_m4 { ip saddr limit rate over 10/minute burst 5 packets } # handle 9")

	want := CanonicalizeNftText(rendered)
	for name, live := range map[string]string{"older-nft (meter … size N)": liveOlder, "newer-nft (add @m)": liveNewer} {
		if got := CanonicalizeNftText(live); got != want {
			t.Errorf("%s readback should canonicalize equal to the render\n--- canonical(live) ---\n%s\n--- canonical(rendered) ---\n%s", name, got, want)
		}
	}
}

// TestCanonicalizeQueueReadback: nftably renders an NFQUEUE fail-open detector as
// `queue num N bypass`, but some nft versions list it back as `queue flags bypass
// to N`. Same rule, so they must canonicalize equal.
func TestCanonicalizeQueueReadback(t *testing.T) {
	rendered := "\t\tqueue num 0 bypass comment \"nftably: inspect transit with an IDS/IPS (fail-open)\"\n"
	live := "\t\tqueue flags bypass to 0 comment \"nftably: inspect transit with an IDS/IPS (fail-open)\" # handle 7\n"
	if got, want := CanonicalizeNftText(live), CanonicalizeNftText(rendered); got != want {
		t.Errorf("queue-bypass readback should canonicalize equal to the render\nlive:     %q\nrendered: %q", got, want)
	}
}

// TestCanonicalizeMeterRuntimeElements: nftably applies a rate-meter set empty;
// the kernel fills it with the sources it is currently rate-limiting, each
// carrying `limit rate over …`. Like the timeout ban set's `expires` members,
// that is kernel runtime and must not read as drift. From a real router.
func TestCanonicalizeMeterRuntimeElements(t *testing.T) {
	applied := "table inet filter {\n" +
		"\tset ssh_abusers_m4 {\n" +
		"\t\ttype ipv4_addr\n" +
		"\t\tflags dynamic\n" +
		"\t}\n" +
		"}\n"
	live := "table inet filter {\n" +
		"\tset ssh_abusers_m4 {\n" +
		"\t\ttype ipv4_addr\n" +
		"\t\tflags dynamic\n" +
		"\t\telements = { 120.48.178.72 limit rate over 10/minute burst 5 packets, 14.103.127.23 limit rate over 10/minute burst 5 packets, 91.196.152.118 limit rate over 10/minute burst 5 packets }\n" +
		"\t}\n" +
		"}\n"
	if got, want := CanonicalizeNftText(live), CanonicalizeNftText(applied); got != want {
		t.Errorf("a kernel-populated rate-meter set should not read as drift\n--- canonical(live) ---\n%s\n--- canonical(applied) ---\n%s", got, want)
	}
}
