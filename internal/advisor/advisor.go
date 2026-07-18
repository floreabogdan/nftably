// Package advisor looks at what actually runs on this box — installed
// software, listening sockets — and suggests firewall rules and best
// practices for it. Suggestions are advice, never actions: each one can be
// dismissed, or taken to a prefilled rule form.
package advisor

import (
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/floreabogdan/nftably/internal/store"
)

// Software is one detected package/daemon.
type Software struct {
	Key  string // stable id, e.g. "docker"
	Name string // display name
	Bin  string // the binary that gave it away
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

// softwareCatalog maps well-known binaries to the software they indicate.
var softwareCatalog = []struct {
	key, name string
	bins      []string
}{
	{"sshd", "OpenSSH server", []string{"sshd"}},
	{"docker", "Docker", []string{"dockerd", "docker"}},
	{"incus", "Incus / LXD", []string{"incusd", "incus", "lxd"}},
	{"bird", "BIRD routing daemon", []string{"bird", "birdc"}},
	{"nginx", "nginx", []string{"nginx"}},
	{"apache", "Apache httpd", []string{"apache2", "httpd"}},
	{"caddy", "Caddy", []string{"caddy"}},
	{"haproxy", "HAProxy", []string{"haproxy"}},
	{"dns", "DNS server (bind/unbound/dnsmasq)", []string{"named", "unbound", "dnsmasq"}},
	{"wireguard", "WireGuard", []string{"wg"}},
	{"mysql", "MySQL / MariaDB", []string{"mysqld", "mariadbd"}},
	{"postgres", "PostgreSQL", []string{"postgres"}},
	{"redis", "Redis", []string{"redis-server"}},
	{"mongodb", "MongoDB", []string{"mongod"}},
	{"samba", "Samba", []string{"smbd"}},
}

// Detect scans the host. Binary detection works everywhere; listener scanning
// is Linux-only (it reads /proc/net) and degrades to a note elsewhere.
func Detect() Scan {
	var s Scan
	for _, entry := range softwareCatalog {
		for _, bin := range entry.bins {
			if path, err := exec.LookPath(bin); err == nil {
				s.Software = append(s.Software, Software{Key: entry.key, Name: entry.name, Bin: path})
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

// Prefill is the rule form pre-population an accepted suggestion offers.
type Prefill struct {
	Name   string
	Action string
	Proto  string
	DPorts string
}

// Suggestion is one piece of advice. Key is stable across scans, so a
// dismissal sticks until the operator restores it.
type Suggestion struct {
	Key      string
	Severity string // "warn" | "info"
	Title    string
	Body     string
	// Prefill, when non-nil, links to /rules/new prefilled with a starting
	// point — the operator still reviews, narrows sources, and applies.
	Prefill *Prefill
}

// wellKnownPorts names the ports the engine talks about.
var wellKnownPorts = map[int]string{
	22: "SSH", 53: "DNS", 80: "HTTP", 111: "rpcbind", 179: "BGP", 443: "HTTPS",
	445: "SMB", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
	51820: "WireGuard",
}

// exposedPorts are services that generally should NOT face the open internet.
var exposedPorts = map[int]bool{111: true, 445: true, 3306: true, 5432: true, 6379: true, 27017: true}

// Suggest turns a scan plus the current model into advice. listenPort is
// nftably's own port (0 when loopback-bound).
func Suggest(scan Scan, fw store.Firewall, rules []store.Rule, listenPort int) []Suggestion {
	var out []Suggestion
	drop := fw.InputPolicy != "accept"
	has := map[string]bool{}
	for _, sw := range scan.Software {
		has[sw.Key] = true
	}

	// Default policy first: everything else assumes it.
	if !drop {
		out = append(out, Suggestion{
			Key: "policy-drop", Severity: "warn",
			Title: "Default policy is accept",
			Body:  "Everything not explicitly dropped is let in. Add accept rules for the services below, then switch the default policy to drop on the Rules page — the baseline keeps loopback, established connections and essential ICMP working.",
		})
	}

	// Wildcard listeners against the model: reachable services with no rule
	// (under drop they silently break; either way they deserve a decision).
	// A service bound to both 0.0.0.0 and :: appears as two listeners with the
	// same port — seenPort keeps that one suggestion, not two.
	seenPort := map[string]bool{}
	for _, l := range scan.Listeners {
		if !l.Wild || l.Proto != "tcp" {
			continue
		}
		pk := fmt.Sprintf("%s/%d", l.Proto, l.Port)
		if seenPort[pk] {
			continue
		}
		seenPort[pk] = true
		if l.Port == listenPort {
			continue // nftably's own port is handled by lint and access control
		}
		covered := ruleAccepts(rules, l.Proto, l.Port)
		service := l.Process
		if service == "" {
			service = wellKnownPorts[l.Port]
		}
		if service == "" {
			service = "a service"
		}
		switch {
		case exposedPorts[l.Port] && (!drop || covered):
			out = append(out, Suggestion{
				Key: fmt.Sprintf("exposed-%s-%d", l.Proto, l.Port), Severity: "warn",
				Title: fmt.Sprintf("%s is reachable on %s port %d", service, l.Proto, l.Port),
				Body:  "Databases and RPC services on a wildcard bind are a classic exposure. Prefer binding it to localhost or an internal interface; if it must be remote, restrict the rule to the clients' source addresses.",
			})
		case exposedPorts[l.Port]:
			// The drop policy already shields it — do NOT suggest opening it;
			// suggest removing the wildcard bind, the deeper fix.
			out = append(out, Suggestion{
				Key: fmt.Sprintf("shielded-%s-%d", l.Proto, l.Port), Severity: "info",
				Title: fmt.Sprintf("%s listens on every address, shielded only by the firewall", service),
				Body:  fmt.Sprintf("The drop policy is the only thing keeping %s port %d private right now. Defence in depth: bind the service to 127.0.0.1 or an internal interface too, so a firewall mistake can never expose it.", l.Proto, l.Port),
			})
		case drop && !covered:
			out = append(out, Suggestion{
				Key: fmt.Sprintf("uncovered-%s-%d", l.Proto, l.Port), Severity: "info",
				Title: fmt.Sprintf("%s listens on %s port %d, but no rule accepts it", service, l.Proto, l.Port),
				Body:  "Under the drop policy this service is unreachable from outside. If that is intended, dismiss this; otherwise add a rule — ideally restricted to the sources that need it.",
				Prefill: &Prefill{
					Name: strings.TrimSpace(service + " " + l.Proto + " " + fmt.Sprint(l.Port)), Action: "accept", Proto: l.Proto, DPorts: fmt.Sprint(l.Port),
				},
			})
		}
	}

	// SSH deserves its own look even without a detected listener.
	if has["sshd"] || listenerOn(scan, "tcp", 22) {
		if r, ok := acceptRule(rules, "tcp", 22); ok && strings.TrimSpace(r.SAddrs) == "" {
			out = append(out, Suggestion{
				Key: "ssh-narrow", Severity: "info",
				Title: "SSH is accepted from anywhere",
				Body:  "The rule accepting tcp 22 has no source restriction. If you always come from a management network or VPN, list those sources on the rule — brute-force noise disappears with it.",
			})
		}
	}

	// A routing box with forwarding unconfigured: the forward chain is where
	// its real traffic flows, and nftably is not filtering it yet.
	if scan.IPForward && fw.WANIface == "" {
		out = append(out, Suggestion{
			Key: "forwarding-unmanaged", Severity: "info",
			Title: "This box routes traffic, but forwarding is not configured",
			Body:  "The kernel forwards packets between interfaces (net.ipv4.ip_forward=1), and that routed traffic bypasses the input chain entirely. Name the WAN interface on the Forwarding page to filter it: replies and port-forwards keep working, LAN to WAN stays open, and unsolicited traffic from outside follows the forward policy.",
		})
	}

	// Software-specific notes.
	if has["docker"] {
		body := "Published container ports (-p) are DNAT'd before this input chain runs, so input rules do not gate them — Docker inserts its own accept rules. Audit exposure with `docker ps` and prefer publishing on 127.0.0.1 where a container is not meant to be public."
		if fw.WANIface != "" {
			body += " Note: with forwarding on, nftably's forward chain also sees traffic between Docker networks — cross-network container traffic may need a forward accept rule."
		} else {
			body += " Container traffic can be filtered on the Forwarding page once a WAN interface is set."
		}
		out = append(out, Suggestion{
			Key: "docker-note", Severity: "info",
			Title: "Docker manages its own netfilter rules",
			Body:  body,
		})
	}
	if has["incus"] {
		out = append(out, Suggestion{
			Key: "incus-note", Severity: "info",
			Title: "Incus/LXD instance traffic bypasses the input chain",
			Body:  "Bridged instances are forwarded, not delivered to this host, so the input chain does not filter them. Filter instance exposure with forward-chain rules (Rules page, chain: forward) once forwarding is on, alongside Incus's own network ACLs.",
		})
	}
	if has["bird"] && !ruleAccepts(rules, "tcp", 179) && drop {
		out = append(out, Suggestion{
			Key: "bird-bgp", Severity: "info",
			Title:   "BIRD is installed, but BGP (tcp 179) is not accepted",
			Body:    "If this box speaks BGP, its peers must reach tcp 179. Add the rule and restrict it to your peers' addresses — nobody else has business on that port.",
			Prefill: &Prefill{Name: "bgp peers", Action: "accept", Proto: "tcp", DPorts: "179"},
		})
	}
	if (has["nginx"] || has["apache"] || has["caddy"] || has["haproxy"]) && drop &&
		(!ruleAccepts(rules, "tcp", 80) || !ruleAccepts(rules, "tcp", 443)) {
		out = append(out, Suggestion{
			Key: "web-server", Severity: "info",
			Title:   "A web server is installed, but HTTP/HTTPS are not (fully) accepted",
			Body:    "If it serves the outside world, allow tcp 80 and 443. A redirect-only port 80 still needs to be open for the redirect to happen.",
			Prefill: &Prefill{Name: "web", Action: "accept", Proto: "tcp", DPorts: "80, 443"},
		})
	}
	if has["wireguard"] && drop && !ruleAccepts(rules, "udp", 51820) {
		out = append(out, Suggestion{
			Key: "wireguard", Severity: "info",
			Title:   "WireGuard is installed, but its port is not accepted",
			Body:    "Handshakes arrive on udp 51820 (unless configured otherwise). WireGuard is silent to unauthenticated probes, so accepting it from anywhere is normal practice.",
			Prefill: &Prefill{Name: "wireguard", Action: "accept", Proto: "udp", DPorts: "51820"},
		})
	}
	if has["dns"] && drop && (!ruleAccepts(rules, "udp", 53) || !ruleAccepts(rules, "tcp", 53)) {
		out = append(out, Suggestion{
			Key: "dns", Severity: "info",
			Title:   "A DNS server is installed, but port 53 is not (fully) accepted",
			Body:    "Resolvers need udp 53 and tcp 53 (TCP carries large answers and zone transfers). If it only serves your LAN, restrict the sources — an open resolver is an amplification-attack tool.",
			Prefill: &Prefill{Name: "dns", Action: "accept", Proto: "udp", DPorts: "53"},
		})
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].Severity == "warn" && out[j].Severity != "warn" })
	return out
}

// ruleAccepts reports whether an enabled accept rule covers proto/port.
func ruleAccepts(rules []store.Rule, proto string, port int) bool {
	_, ok := acceptRule(rules, proto, port)
	return ok
}

func acceptRule(rules []store.Rule, proto string, port int) (store.Rule, bool) {
	for _, r := range rules {
		// Only input-chain rules make a host service reachable — a forward
		// accept covers routed traffic, not this box's listeners.
		if !r.Enabled || r.Action != "accept" || (r.Chain != "" && r.Chain != "input") {
			continue
		}
		if r.Proto != "any" && r.Proto != proto {
			continue
		}
		if r.Proto == "any" {
			return r, true
		}
		ports, _ := store.ParsePorts(r.DPorts)
		if len(ports) == 0 {
			return r, true
		}
		for _, tok := range ports {
			if portTokenContains(tok, port) {
				return r, true
			}
		}
	}
	return store.Rule{}, false
}

func portTokenContains(tok string, port int) bool {
	if lo, hi, found := strings.Cut(tok, "-"); found {
		l, err1 := strconv.Atoi(lo)
		h, err2 := strconv.Atoi(hi)
		return err1 == nil && err2 == nil && l <= port && port <= h
	}
	n, err := strconv.Atoi(tok)
	return err == nil && n == port
}

func listenerOn(scan Scan, proto string, port int) bool {
	for _, l := range scan.Listeners {
		if l.Proto == proto && l.Port == port && l.Wild {
			return true
		}
	}
	return false
}
