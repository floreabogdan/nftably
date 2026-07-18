// Package advisor looks at what actually runs on this box — its listening
// sockets and whether it routes traffic — and reports how the current firewall
// model treats each exposure. It answers a concrete question per finding
// ("sshd listens on :22 — a connection from the internet would be DROPPED by
// your rules") rather than offering generic advice, by running each observed
// listener through the packet simulator. Findings are advice, never actions:
// each can be dismissed, taken to a one-click rule, or opened in the simulator.
package advisor

import (
	"os/exec"
	"sort"
)

// Software is one detected daemon, used only for the caveats about tools that
// manage their own netfilter rules (Docker, Incus) — not as a source of "you
// should open port X" advice, which the listener analysis derives precisely.
type Software struct {
	Key  string // stable id, e.g. "docker"
	Name string // display name
}

// Listener is one bound socket read from the kernel.
type Listener struct {
	Proto   string // "tcp" | "udp"
	Addr    string // local address; "0.0.0.0" / "::" when listening everywhere
	Port    int
	Wild    bool   // bound to every address (reachable from outside)
	Process string // best-effort process name; "" when unknown
}

// Scan is everything detection found.
type Scan struct {
	Software  []Software
	Listeners []Listener
	// IPForward reports whether the kernel routes between interfaces
	// (net.ipv4.ip_forward=1) — the box acts as a router.
	IPForward bool
	// Note explains a detection limitation (e.g. listener scanning needs
	// Linux); empty when the scan is complete.
	Note string
}

// softwareCatalog maps well-known binaries to the software they indicate. Kept
// small and used only for the "manages its own netfilter" caveats.
var softwareCatalog = []struct {
	key, name string
	bins      []string
}{
	{"docker", "Docker", []string{"dockerd", "docker"}},
	{"incus", "Incus / LXD", []string{"incusd", "incus", "lxd"}},
}

// Detect scans the host. Binary detection works everywhere; listener scanning
// is Linux-only (it reads /proc/net) and degrades to a note elsewhere.
func Detect() Scan {
	var s Scan
	for _, entry := range softwareCatalog {
		for _, bin := range entry.bins {
			if _, err := exec.LookPath(bin); err == nil {
				s.Software = append(s.Software, Software{Key: entry.key, Name: entry.name})
				break
			}
		}
	}
	s.Listeners, s.Note = listeners()
	s.IPForward = ipForwarding()
	sort.Slice(s.Listeners, func(i, j int) bool {
		if s.Listeners[i].Port != s.Listeners[j].Port {
			return s.Listeners[i].Port < s.Listeners[j].Port
		}
		return s.Listeners[i].Proto < s.Listeners[j].Proto
	})
	return s
}

// HasSoftware reports whether a detected-software key is present.
func (s Scan) HasSoftware(key string) bool {
	for _, sw := range s.Software {
		if sw.Key == key {
			return true
		}
	}
	return false
}
