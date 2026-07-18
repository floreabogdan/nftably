package render

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/floreabogdan/nftably/internal/store"
)

// Lint checks the model for the classic self-lockout footguns before an apply.
// It returns warnings, not errors: the auto-revert is the hard safety net, and
// an operator reaching this box over a serial console may be doing exactly what
// the warning describes on purpose.
//
// The baseline rules already guarantee loopback, established/related and
// essential ICMP — so the checks here are about what a drop policy does to NEW
// connections the operator depends on. A populated allow-role list is treated
// as a way in: those sources are accepted before everything, so the lockout
// warnings stand down.
func Lint(m Model, listenAddr string) []string {
	fw, rules, pfs := m.FW, m.Rules, m.Forwards
	var warns []string

	hasAllowList := false
	for _, l := range m.Lists {
		if l.Role == store.RoleAllow && len(l.Entries) > 0 {
			hasAllowList = true
		}
	}

	if (fw.InputPolicy == "drop" || fw.InputPolicy == "") && !hasAllowList {
		if port := listenPort(listenAddr); port > 0 && !InputAccepts(rules, port) {
			warns = append(warns, fmt.Sprintf(
				"No rule accepts new connections to nftably's own port (tcp %d). Your current session survives on established/related, but a reconnect would be dropped — the auto-revert would save you, and then you'd add this rule anyway.", port))
		}
		if !InputAccepts(rules, 22) {
			warns = append(warns,
				"No rule accepts new SSH connections (tcp 22). Existing sessions survive, new ones will be dropped. Skip this warning only if you reach the box another way.")
		}
	}

	// Forwarding configuration that will not render is a silent surprise, not
	// a lockout — still worth a warning before the operator hunts for why a
	// port-forward does nothing.
	if fw.WANIface == "" {
		if n := enabledForwards(pfs); n > 0 {
			warns = append(warns, fmt.Sprintf(
				"%d port-forward(s) are enabled but no WAN interface is set, so they are not in the rendered config. Name the WAN interface on the Forwarding page to activate them.", n))
		}
		if n := enabledChainRules(rules, "forward"); n > 0 {
			warns = append(warns, fmt.Sprintf(
				"%d forward-chain rule(s) are enabled but no WAN interface is set, so the forward chain is not rendered. Name the WAN interface on the Forwarding page to activate it.", n))
		}
	}

	// A rule sourcing from a missing or empty list matches nothing — legal,
	// but almost certainly not what the operator meant.
	for _, r := range rules {
		if !r.Enabled || r.SrcListID == 0 {
			continue
		}
		l := m.list(r.SrcListID)
		switch {
		case l == nil:
			warns = append(warns, fmt.Sprintf(
				"Rule %q sources from a list that no longer exists — it matches nothing and is not rendered.", r.Name))
		case len(l.Entries) == 0:
			warns = append(warns, fmt.Sprintf(
				"Rule %q sources from list %q, which has no entries yet — it matches nothing until the list does.", r.Name, l.Name))
		}
	}
	return warns
}

func enabledForwards(pfs []store.PortForward) int {
	n := 0
	for _, p := range pfs {
		if p.Enabled {
			n++
		}
	}
	return n
}

func enabledChainRules(rules []store.Rule, chain string) int {
	n := 0
	for _, r := range rules {
		if r.Enabled && r.Chain == chain {
			n++
		}
	}
	return n
}

// InputAccepts reports whether any enabled input-chain accept rule matches a
// new TCP connection to port. Source or interface restrictions still count — the
// operator knows their management network; what matters is that some path to
// the port exists.
func InputAccepts(rules []store.Rule, port int) bool {
	for _, r := range rules {
		if !r.Enabled || r.Action != "accept" || (r.Chain != "" && r.Chain != "input") {
			continue
		}
		switch r.Proto {
		case "any":
			return true
		case "tcp":
			ports, _ := store.ParsePorts(r.DPorts)
			if len(ports) == 0 {
				return true // whole protocol accepted
			}
			for _, tok := range ports {
				if portInToken(port, tok) {
					return true
				}
			}
		}
	}
	return false
}

func portInToken(port int, tok string) bool {
	if lo, hi, found := strings.Cut(tok, "-"); found {
		l, _ := strconv.Atoi(lo)
		h, _ := strconv.Atoi(hi)
		return port >= l && port <= h
	}
	n, _ := strconv.Atoi(tok)
	return n == port
}

// listenPort extracts the TCP port nftably itself is bound to; 0 when it
// cannot be determined. A loopback bind returns 0 too — off-box traffic cannot
// reach it, so the input chain is irrelevant to it.
func listenPort(addr string) int {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return 0
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0
	}
	return port
}
