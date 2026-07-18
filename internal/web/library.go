package web

import "github.com/floreabogdan/nftably/internal/store"

// The rule catalogue behind the guided setup: the services people actually
// run, each with the reasoning attached. Deliberately absent: databases,
// Redis, SMB-to-the-internet and friends — the advisor warns about exposing
// those, so setup will not hand out a rule that does.

// libEntry is one curated, explained rule (or small bundle of rules).
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

var library = []libGroup{
	{"Remote access", []libEntry{
		{
			Key: "ssh", Name: "SSH",
			Why: "Remote administration on tcp 22. The internet knocks on this port all day; restricting the rule to your management addresses (or a management list) makes the brute-force noise disappear without changing how you work.",
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
