package web

import (
	"fmt"
	"net/http"

	nftconf "github.com/floreabogdan/nftably/internal/render"
	"github.com/floreabogdan/nftably/internal/store"
)

// libEntry is one curated, explained rule (or small bundle of rules) the
// operator can add with a click. The library teaches while it configures:
// Why says what the service is and how tightly to hold it.
type libEntry struct {
	Key   string
	Name  string
	Why   string
	Rules []store.Rule
	// Restrict marks services that should usually be limited to known
	// sources; the UI nudges the operator to edit the rule after adding.
	Restrict bool
}

type libGroup struct {
	Name    string
	Entries []libEntry
}

// library is the curated catalogue. Deliberately absent: databases, Redis,
// SMB-to-the-internet and friends — the advisor warns about exposing those,
// so the library will not hand out a rule that does.
var library = []libGroup{
	{"Remote access", []libEntry{
		{
			Key: "ssh", Name: "SSH",
			Why: "Remote administration on tcp 22. The internet knocks on this port all day; restricting the rule to your management addresses (or using the management list) makes the brute-force noise disappear without changing how you work.",
			Rules: []store.Rule{{Name: "ssh", Action: "accept", Proto: "tcp", DPorts: "22", Enabled: true}}, Restrict: true,
		},
		{
			Key: "mosh", Name: "Mosh",
			Why: "Mosh keeps shell sessions alive across roaming and flaky links. It authenticates over SSH first, then moves to UDP in this range — so it needs SSH open too.",
			Rules: []store.Rule{{Name: "mosh", Action: "accept", Proto: "udp", DPorts: "60000-61000", Enabled: true}}, Restrict: true,
		},
	}},
	{"VPN", []libEntry{
		{
			Key: "wireguard", Name: "WireGuard",
			Why: "Handshakes arrive on udp 51820 (unless configured otherwise). WireGuard does not answer unauthenticated packets, so accepting it from anywhere is normal practice — a scanner cannot even tell it is there.",
			Rules: []store.Rule{{Name: "wireguard", Action: "accept", Proto: "udp", DPorts: "51820", Enabled: true}},
		},
		{
			Key: "openvpn", Name: "OpenVPN",
			Why: "The default port is udp 1194. Unlike WireGuard, OpenVPN answers probes unless tls-auth/tls-crypt is configured — worth setting up alongside the firewall rule.",
			Rules: []store.Rule{{Name: "openvpn", Action: "accept", Proto: "udp", DPorts: "1194", Enabled: true}},
		},
		{
			Key: "tailscale", Name: "Tailscale",
			Why: "Tailscale works without any open port (it relays through DERP), but accepting udp 41641 lets peers connect directly — lower latency, less relay traffic.",
			Rules: []store.Rule{{Name: "tailscale", Action: "accept", Proto: "udp", DPorts: "41641", Enabled: true}},
		},
	}},
	{"Web serving", []libEntry{
		{
			Key: "web", Name: "HTTP + HTTPS",
			Why: "A public web server needs tcp 80 and 443. Port 80 stays necessary even for HTTPS-only sites — the redirect to https and ACME http-01 certificate renewal both arrive there.",
			Rules: []store.Rule{{Name: "web", Action: "accept", Proto: "tcp", DPorts: "80, 443", Enabled: true}},
		},
		{
			Key: "http3", Name: "HTTP/3 (QUIC)",
			Why: "HTTP/3 runs over UDP on 443. Browsers fall back to TCP without it, so add this only if your web server actually speaks QUIC — an open port nothing listens on is just noise in your ruleset.",
			Rules: []store.Rule{{Name: "http3", Action: "accept", Proto: "udp", DPorts: "443", Enabled: true}},
		},
	}},
	{"Core services", []libEntry{
		{
			Key: "dns", Name: "DNS server",
			Why: "Resolvers need udp 53 and tcp 53 — TCP carries large answers and zone transfers. If it serves only your own networks, restrict the sources: an open resolver on the internet becomes an amplification-attack tool within hours.",
			Rules: []store.Rule{
				{Name: "dns", Action: "accept", Proto: "udp", DPorts: "53", Enabled: true},
				{Name: "dns tcp", Action: "accept", Proto: "tcp", DPorts: "53", Enabled: true},
			}, Restrict: true,
		},
		{
			Key: "ntp", Name: "NTP server",
			Why: "Time service on udp 123. Same story as DNS: fine for your LAN, an amplification vector when open to the world — restrict the sources unless you are deliberately running a public pool server.",
			Rules: []store.Rule{{Name: "ntp", Action: "accept", Proto: "udp", DPorts: "123", Enabled: true}}, Restrict: true,
		},
		{
			Key: "dhcp", Name: "DHCP server",
			Why: "Lease requests arrive as broadcasts on udp 67. Only needed when this box hands out addresses; consider limiting it to the LAN interface (edit the rule and set the ingress interface).",
			Rules: []store.Rule{{Name: "dhcp", Action: "accept", Proto: "udp", DPorts: "67", Enabled: true}},
		},
		{
			Key: "bgp", Name: "BGP (BIRD)",
			Why: "BGP peers connect on tcp 179. Nobody but your configured peers has business on this port — list their addresses on the rule. (nftably's brother project birdy manages the BIRD side.)",
			Rules: []store.Rule{{Name: "bgp peers", Action: "accept", Proto: "tcp", DPorts: "179", Enabled: true}}, Restrict: true,
		},
	}},
	{"Mail", []libEntry{
		{
			Key: "smtp", Name: "SMTP (receiving mail)",
			Why: "Other mail servers deliver to tcp 25. It must be open to the world for mail to arrive — spam filtering belongs in the mail server, not the firewall.",
			Rules: []store.Rule{{Name: "smtp", Action: "accept", Proto: "tcp", DPorts: "25", Enabled: true}},
		},
		{
			Key: "mail-clients", Name: "Mail clients (submission + IMAP)",
			Why: "Your own users submit mail on tcp 465/587 and read it over IMAPS on 993. If all users come from known networks or a VPN, restrict the sources.",
			Rules: []store.Rule{{Name: "mail clients", Action: "accept", Proto: "tcp", DPorts: "465, 587, 993", Enabled: true}}, Restrict: true,
		},
	}},
	{"File sharing & monitoring", []libEntry{
		{
			Key: "samba", Name: "Samba / SMB",
			Why: "Windows file sharing on tcp 445. This should never face the internet — it is one of the most attacked ports in existence. Add it only with sources restricted to your LAN.",
			Rules: []store.Rule{{Name: "samba", Action: "accept", Proto: "tcp", DPorts: "445", Enabled: true}}, Restrict: true,
		},
		{
			Key: "nfs", Name: "NFS",
			Why: "NFSv4 on tcp 2049. Like SMB, strictly a LAN protocol — restrict the sources to the machines that mount from here.",
			Rules: []store.Rule{{Name: "nfs", Action: "accept", Proto: "tcp", DPorts: "2049", Enabled: true}}, Restrict: true,
		},
		{
			Key: "node-exporter", Name: "Prometheus node_exporter",
			Why: "Metrics on tcp 9100. Metrics leak a surprising amount about a box (kernel, mounts, network peers) — restrict to your Prometheus server's address.",
			Rules: []store.Rule{{Name: "node exporter", Action: "accept", Proto: "tcp", DPorts: "9100", Enabled: true}}, Restrict: true,
		},
	}},
}

// libraryVM is the /library page: the catalogue, plus which entries already
// have a matching rule and the hardening card's state.
type libraryVM struct {
	nav
	Groups   []libGroup
	Have     map[string]bool // entry key -> a rule with its name exists
	PolicyOK bool            // input policy is already drop
	SSHOK    bool
	UIOK     bool
	UIPort   int
	Added    string
	Hardened bool
}

func (s *Server) handleLibrary(w http.ResponseWriter, r *http.Request) {
	rules, err := s.store.ListRules()
	if err != nil {
		s.serverError(w, "list rules", err)
		return
	}
	fw, err := s.store.GetFirewall()
	if err != nil {
		s.serverError(w, "get firewall", err)
		return
	}

	names := map[string]bool{}
	for _, rule := range rules {
		names[rule.Name] = true
	}
	have := map[string]bool{}
	for _, g := range library {
		for _, e := range g.Entries {
			have[e.Key] = names[e.Rules[0].Name]
		}
	}

	uiPort := s.ownListenPort()
	render(w, s.log, "library.html", libraryVM{
		nav:      s.navFor(r, "library"),
		Groups:   library,
		Have:     have,
		PolicyOK: fw.InputPolicy == "drop",
		SSHOK:    nftconf.InputAccepts(rules, 22),
		UIOK:     uiPort == 0 || nftconf.InputAccepts(rules, uiPort),
		UIPort:   uiPort,
		Added:    r.URL.Query().Get("added"),
		Hardened: r.URL.Query().Get("hardened") == "1",
	})
}

func (s *Server) handleLibraryAdd(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	key := r.FormValue("key")
	var entry *libEntry
	for gi := range library {
		for ei := range library[gi].Entries {
			if library[gi].Entries[ei].Key == key {
				entry = &library[gi].Entries[ei]
			}
		}
	}
	if entry == nil {
		http.Error(w, "unknown library entry", http.StatusBadRequest)
		return
	}

	existing, err := s.store.ListRules()
	if err != nil {
		s.serverError(w, "list rules", err)
		return
	}
	names := map[string]bool{}
	for _, rule := range existing {
		names[rule.Name] = true
	}
	for _, rule := range entry.Rules {
		if names[rule.Name] {
			continue // added before; do not duplicate
		}
		if _, err := s.store.CreateRule(rule); err != nil {
			s.serverError(w, "create rule", err)
			return
		}
	}
	s.audit(r, fmt.Sprintf("added %q from the rule library", entry.Name))
	http.Redirect(w, r, "/library?added="+entry.Key, http.StatusSeeOther)
}

// handleLibraryHarden is the one-click hardening: make sure a way in exists
// (SSH, and nftably's own port when it listens beyond loopback), then switch
// the input policy to drop. The order matters — the accepts are created
// before the policy flips, and nothing touches the kernel until the operator
// applies, where lint and the auto-revert stand guard anyway.
func (s *Server) handleLibraryHarden(w http.ResponseWriter, r *http.Request) {
	rules, err := s.store.ListRules()
	if err != nil {
		s.serverError(w, "list rules", err)
		return
	}
	fw, err := s.store.GetFirewall()
	if err != nil {
		s.serverError(w, "get firewall", err)
		return
	}

	if !nftconf.InputAccepts(rules, 22) {
		if _, err := s.store.CreateRule(store.Rule{Name: "ssh", Action: "accept", Proto: "tcp", DPorts: "22", Enabled: true}); err != nil {
			s.serverError(w, "create ssh rule", err)
			return
		}
	}
	if port := s.ownListenPort(); port > 0 && !nftconf.InputAccepts(rules, port) {
		if _, err := s.store.CreateRule(store.Rule{Name: "nftably ui", Action: "accept", Proto: "tcp", DPorts: fmt.Sprint(port), Enabled: true}); err != nil {
			s.serverError(w, "create ui rule", err)
			return
		}
	}
	fw.InputPolicy = "drop"
	if err := s.store.SaveFirewall(fw); err != nil {
		s.serverError(w, "save firewall", err)
		return
	}
	s.audit(r, "hardened: input policy drop, SSH + UI accepts ensured")
	http.Redirect(w, r, "/library?hardened=1", http.StatusSeeOther)
}
