// Package conntrack reads the kernel's connection-tracking table — the live
// view of every flow netfilter knows about: connections to this box, from it,
// and (on a router) through it.
package conntrack

import (
	"bufio"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// Flow is one tracked connection, original direction.
type Flow struct {
	Proto string // tcp | udp | icmp | ...
	// State is the tracker's state for stateful protocols (ESTABLISHED,
	// TIME_WAIT, SYN_SENT ...); empty for protocols without one. UNREPLIED
	// marks flows that never saw an answer — scans look like this.
	State   string
	Src     netip.Addr
	Dst     netip.Addr
	SPort   int
	DPort   int
	Assured bool
}

// parse reads /proc/net/nf_conntrack lines. The format is token-based:
//
//	ipv4 2 tcp 6 431999 ESTABLISHED src=10.0.0.5 dst=10.0.0.1 sport=51000
//	  dport=22 src=10.0.0.1 dst=10.0.0.5 sport=22 dport=51000 [ASSURED] ...
//
// Only the first (original-direction) src/dst/ports are taken; the second set
// is the reply direction, interesting only to NAT internals.
func parse(r io.Reader) []Flow {
	var out []Flow
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 64*1024)
	for sc.Scan() {
		if f, ok := parseLine(sc.Text()); ok {
			out = append(out, f)
		}
	}
	return out
}

// parseLine handles both line dialects: /proc/net/nf_conntrack prefixes each
// line with the l3 family ("ipv4 2 tcp 6 ..."), the conntrack(8) tool starts
// straight at the protocol ("tcp 6 431999 ESTABLISHED src=...").
func parseLine(line string) (Flow, bool) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return Flow{}, false
	}
	proto, rest := fields[0], fields[1:]
	if proto == "ipv4" || proto == "ipv6" {
		proto, rest = fields[2], fields[3:]
	}
	f := Flow{Proto: proto}
	for _, tok := range rest {
		switch {
		case strings.HasPrefix(tok, "src=") && !f.Src.IsValid():
			f.Src, _ = netip.ParseAddr(tok[4:])
		case strings.HasPrefix(tok, "dst=") && !f.Dst.IsValid():
			f.Dst, _ = netip.ParseAddr(tok[4:])
		case strings.HasPrefix(tok, "sport=") && f.SPort == 0:
			f.SPort, _ = strconv.Atoi(tok[6:])
		case strings.HasPrefix(tok, "dport=") && f.DPort == 0:
			f.DPort, _ = strconv.Atoi(tok[6:])
		case tok == "[ASSURED]":
			f.Assured = true
		case tok == "[UNREPLIED]":
			if f.State == "" {
				f.State = "UNREPLIED"
			}
		case f.State == "" && !f.Src.IsValid() && isStateToken(tok):
			// The state comes before the first src= and is ALL_CAPS.
			f.State = tok
		}
	}
	if !f.Src.IsValid() || !f.Dst.IsValid() {
		return Flow{}, false
	}
	f.Src = f.Src.Unmap()
	f.Dst = f.Dst.Unmap()
	return f, true
}

func isStateToken(tok string) bool {
	if tok == "" {
		return false
	}
	for _, r := range tok {
		if (r < 'A' || r > 'Z') && r != '_' {
			return false
		}
	}
	return true
}
