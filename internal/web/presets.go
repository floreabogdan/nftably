package web

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/floreabogdan/nftably/internal/store"
)

// Presets are one-click, best-practice starting points. Applying one replaces
// the current firewall tables with a recommended layout (named sets are kept and
// created as needed, so the operator only edits addresses). Everything is still
// model-only — /changes applies it with the armed auto-revert — so a preset can
// never surprise the kernel.

type presetDef struct {
	Key     string
	Name    string
	Tagline string
	// What lists a preset expects you to fill in, and why.
	Sets []presetSet
	// Bullet points shown on the card: what it adds and the reasoning.
	Adds  []string
	build func(s *Server, r *http.Request) error
}

type presetSet struct {
	Name string
	Why  string
}

func (s *Server) presets() []presetDef {
	return []presetDef{
		{
			Key: "bgp-router", Name: "BGP edge router", Tagline: "Harden a BIRD/FRR router's control plane while transit keeps flowing.",
			Sets: []presetSet{
				{"mgmt", "Your management networks. SSH and the nftably UI are accepted only from here — seeded with the address you're connecting from so you don't lock yourself out."},
				{"peers", "Your BGP peers. TCP 179 (BGP) and BFD are accepted only from these addresses. Add each peer's IPv4 and IPv6."},
				{"blacklist", "Addresses dropped before anything else (even established sessions). The Connections page's Block button appends here, so a block takes effect the moment you apply."},
			},
			Adds: []string{
				"An inet filter table with input (drop), forward (accept, invalid dropped) and output (accept, cleaned up) chains.",
				"Loopback, established/related, connection-invalid handling, and an early @blacklist drop — the survivable base for a drop policy.",
				"The ICMP/ICMPv6 a router must answer (echo, unreachable, time-exceeded, and IPv6 neighbour discovery / PMTU — block these and IPv6 breaks).",
				"SSH (22) and the nftably UI accepted only from @mgmt; BGP (179) and BFD (3784/3785/4784) only from @peers — everything else to the box is dropped.",
				"Output hygiene: the router still originates whatever it needs (BGP, ND, DNS…), but LAN-only chatter (mDNS, LLMNR, NetBIOS, SMB, SSDP, DHCP) is stopped from ever leaking to peers.",
				"Denied inbound is tallied into a named “denied” counter (visible on the rule) and logged rate-limited, so you can see how much is being turned away without flooding the log.",
				"Tip: for line-rate transit, add a flowtable on the Firewall page bound to your real interfaces and a flow-add rule in the forward chain — established flows then take the kernel fast path.",
			},
			build: (*Server).buildBGPPreset,
		},
		{
			Key: "secure-server", Name: "Basic secure server", Tagline: "A sensible default-deny host firewall: replies, ping, and SSH from your network.",
			Sets: []presetSet{
				{"mgmt", "Where SSH is allowed from — seeded with your current address. Widen it to your admin network."},
			},
			Adds: []string{
				"An inet filter table with input (drop), forward (drop) and output (accept) chains.",
				"Loopback, established/related, invalid-dropped, and the essential ICMP/ICMPv6.",
				"SSH (22) and the nftably UI accepted only from @mgmt.",
			},
			build: (*Server).buildSecureServerPreset,
		},
		{
			Key: "wireguard", Name: "WireGuard VPN server", Tagline: "A secure host that also terminates a WireGuard tunnel and routes its clients.",
			Sets: []presetSet{
				{"mgmt", "Where SSH and the nftably UI are allowed from — seeded with your current address. Widen it to your admin network (the tunnel side is trusted separately)."},
			},
			Adds: []string{
				"Everything the basic secure server sets up (default-deny input, the survivable base, essential ICMP/ICMPv6, SSH + UI from @mgmt).",
				"The WireGuard listen port UDP 51820 accepted from anywhere — the tunnel is authenticated by keys, so the port is safe to expose.",
				"Traffic arriving on the wg0 interface accepted to this box, so services reachable over the tunnel work.",
				"A default-drop forward chain that routes the tunnel: established/related, plus traffic in and out of wg0 — so clients reach what's behind this host.",
				"Note: if clients need the internet through this host, add a postrouting nat chain with masquerade on the Firewall page — the uplink interface is yours to name.",
				"Tip: to route a lot of tunnel traffic fast, add a flowtable (bound to wg0 and your uplink) and a flow-add rule in the forward chain to offload established flows.",
			},
			build: (*Server).buildWireGuardPreset,
		},
		{
			Key: "home-router", Name: "Home router / gateway", Tagline: "Share one internet connection: NAT the LAN out, keep the internet from reaching in.",
			Sets: []presetSet{
				{"mgmt", "Extra networks allowed to manage the router (on top of the LAN side) — seeded with your current address so applying it can't lock you out."},
			},
			Adds: []string{
				"Two interfaces by convention: rename wan (your uplink to the ISP) and lan (your internal network) to match this box on the Firewall page.",
				"An inet filter table: input drops by default; the LAN side reaches SSH, this UI, DHCP and DNS on the router, and @mgmt may too; the internet side reaches nothing.",
				"A default-drop forward chain that lets the LAN reach the internet and lets replies back — but stops the internet from opening connections into your LAN.",
				"An inet nat table that masquerades LAN traffic out the wan interface (the 'share one connection' setting), with an empty prerouting chain ready for port-forwards.",
				"Two one-click boosts on the Firewall page: the Port-forward wizard builds the DNAT to expose an inside service, and a flowtable (bound to your real wan/lan interfaces) + a flow-add rule offloads established traffic to the fast path for a big throughput win.",
			},
			build: (*Server).buildHomeRouterPreset,
		},
		{
			Key: "web-server", Name: "Web server", Tagline: "A public web host: HTTP/HTTPS open to the world, SSH kept to your network.",
			Sets: []presetSet{
				{"mgmt", "Where SSH and the nftably UI are allowed from — seeded with your current address."},
			},
			Adds: []string{
				"The basic secure-server base: default-deny input, loopback, established/related, invalid-dropped and the essential ICMP/ICMPv6.",
				"HTTP (80) and HTTPS (443) accepted from anywhere — the service you're publishing.",
				"SSH (22) and the nftably UI accepted only from @mgmt; everything else to the box is dropped.",
			},
			build: (*Server).buildWebServerPreset,
		},
		{
			Key: "database-server", Name: "Database server", Tagline: "Reachable only by your app tier: the DB port scoped to @app, never the internet.",
			Sets: []presetSet{
				{"mgmt", "Where SSH and the nftably UI are allowed from — seeded with your current address."},
				{"app", "Your application tier — the only hosts allowed to reach the database. Add your app servers' addresses (v4 and v6)."},
			},
			Adds: []string{
				"The basic secure-server base: default-deny input, the survivable rules and essential ICMP/ICMPv6.",
				"PostgreSQL (5432) and MySQL (3306) accepted only from @app — keep the port you use and delete the other.",
				"SSH (22) and the nftably UI accepted only from @mgmt. The database is never exposed to the internet.",
			},
			build: (*Server).buildDatabaseServerPreset,
		},
		{
			Key: "container-host", Name: "Docker / container host", Tagline: "Harden the host without touching container networking — Docker keeps its own rules.",
			Sets: []presetSet{
				{"mgmt", "Where SSH and the nftably UI are allowed from — seeded with your current address."},
			},
			Adds: []string{
				"A default-deny input chain that protects the host: loopback, established/related, invalid-dropped, essential ICMP/ICMPv6, and SSH + the UI from @mgmt.",
				"No forward chain — Docker manages container forwarding and NAT in its own tables, and a drop-policy forward chain here would break container traffic. nftably only hardens the host's own input.",
				"Publish container ports the way you already do (Docker's -p handles the DNAT); this preset just keeps the host itself locked down.",
			},
			build: (*Server).buildContainerHostPreset,
		},
	}
}

func (s *Server) presetByKey(key string) (presetDef, bool) {
	for _, p := range s.presets() {
		if p.Key == key {
			return p, true
		}
	}
	return presetDef{}, false
}

// ── handlers ────────────────────────────────────────────────────────────────

type presetsVM struct {
	nav
	Presets []presetDef
}

func (s *Server) handlePresets(w http.ResponseWriter, r *http.Request) {
	render(w, s.log, "presets.html", presetsVM{nav: s.navFor(r, "presets"), Presets: s.presets()})
}

func (s *Server) handlePresetApply(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	p, ok := s.presetByKey(r.FormValue("preset"))
	if !ok {
		http.Error(w, "unknown preset", http.StatusBadRequest)
		return
	}
	if err := p.build(s, r); err != nil {
		redirectErr(w, r, "/firewall", "Could not apply the preset: "+err.Error())
		return
	}
	s.audit(r, "applied the "+p.Name+" preset")
	// The preset gates SSH/UI behind @mgmt and seeds it with the operator's
	// address — but that can't be detected over an SSH tunnel (loopback is not a
	// listable address). If @mgmt came out empty, warn before they apply into a
	// drop policy that admits no new management traffic.
	if l, err := s.store.GetListByName("mgmt"); err == nil {
		if entries, _ := s.store.ListEntries(l.ID); len(entries) == 0 {
			http.Redirect(w, r, "/firewall?preset="+p.Key+"&err="+urlEscape(
				"The preset couldn't detect your address (an SSH tunnel hides it), so the management set @mgmt is empty. Add your admin network under Named sets before you apply — otherwise new SSH/UI connections would be dropped."),
				http.StatusSeeOther)
			return
		}
	}
	http.Redirect(w, r, "/firewall?preset="+p.Key, http.StatusSeeOther)
}

// ── build helpers ───────────────────────────────────────────────────────────

// resetTables removes every owned table so a preset installs a clean layout.
// Named sets are left untouched.
func (s *Server) resetTables() error {
	tables, err := s.store.ListTables()
	if err != nil {
		return err
	}
	for _, t := range tables {
		if err := s.store.DeleteTable(t.ID); err != nil {
			return err
		}
	}
	return nil
}

// ensureList returns a named list by name, creating it (with a note) if missing.
func (s *Server) ensureList(name, note string) (int64, error) {
	if l, err := s.store.GetListByName(name); err == nil {
		return l.ID, nil
	}
	return s.store.CreateList(store.IPList{Name: name, Note: note})
}

// seedMgmtWithClient adds the operator's current address to an empty mgmt list,
// so a drop-policy preset never locks out the person applying it.
func (s *Server) seedMgmtWithClient(listID int64, r *http.Request) {
	entries, err := s.store.ListEntries(listID)
	if err != nil || len(entries) > 0 {
		return
	}
	if ip := clientAddr(r); ip.IsValid() {
		_ = s.store.AddListEntry(listID, ip.String(), "your current connection — widen to your management network")
	}
}

// rule builders — concise constructors for the preset chains.
func mt(key, value string) store.RuleMatch { return store.RuleMatch{Key: key, Op: "==", Value: value} }

func stmt(key string) store.RuleStatement { return store.RuleStatement{Key: key, Params: "{}"} }

func stmtP(key string, params map[string]string) store.RuleStatement {
	b, _ := json.Marshal(params)
	return store.RuleStatement{Key: key, Params: string(b)}
}

func (s *Server) addRule(chainID int64, comment string, matches []store.RuleMatch, stmts []store.RuleStatement) error {
	_, err := s.store.CreateChainRule(store.ChainRule{
		ChainID: chainID, Enabled: true, Comment: comment, Matches: matches, Statements: stmts,
	})
	return err
}

// baseInputRules writes the survivable base every input chain needs: loopback,
// invalid, an early @blacklist drop (so the Connections "block" button cuts even
// established sessions), established/related, and the essential ICMP/ICMPv6.
func (s *Server) baseInputRules(input int64) error {
	steps := []struct {
		comment string
		matches []store.RuleMatch
		stmts   []store.RuleStatement
	}{
		{"loopback", []store.RuleMatch{mt("meta.iifname", "lo")}, []store.RuleStatement{stmt("accept")}},
		{"drop invalid", []store.RuleMatch{mt("ct.state", "invalid")}, []store.RuleStatement{stmt("drop")}},
		{"drop blacklisted (IPv4)", []store.RuleMatch{mt("ip.saddr", "@blacklist4")}, []store.RuleStatement{stmt("drop")}},
		{"drop blacklisted (IPv6)", []store.RuleMatch{mt("ip6.saddr", "@blacklist6")}, []store.RuleStatement{stmt("drop")}},
		{"established/related", []store.RuleMatch{mt("ct.state", "established, related")}, []store.RuleStatement{stmt("accept")}},
		{"ICMPv6 — required for IPv6 to work", []store.RuleMatch{mt("icmpv6.type", "echo-request, echo-reply, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, destination-unreachable, packet-too-big, time-exceeded, parameter-problem")}, []store.RuleStatement{stmt("accept")}},
		{"ICMPv4", []store.RuleMatch{mt("icmp.type", "echo-request, echo-reply, destination-unreachable, time-exceeded, parameter-problem")}, []store.RuleStatement{stmt("accept")}},
	}
	for _, st := range steps {
		if err := s.addRule(input, st.comment, st.matches, st.stmts); err != nil {
			return err
		}
	}
	return nil
}

// outputHygieneRules keeps a router's own traffic clean: drop invalid, and stop
// LAN-only discovery/chatter from ever leaking out to transit or peers. It does
// NOT touch ND/ICMPv6 or routing protocols — the router legitimately originates
// those (and needs ND to reach its IPv6 peers). The policy stays accept, so
// everything the router needs to send still goes out.
func (s *Server) outputHygieneRules(output int64) error {
	steps := []struct {
		comment string
		matches []store.RuleMatch
	}{
		{"drop invalid outbound", []store.RuleMatch{mt("ct.state", "invalid")}},
		{"don't leak mDNS to the internet", []store.RuleMatch{mt("udp.dport", "5353")}},
		{"don't leak LLMNR", []store.RuleMatch{mt("udp.dport", "5355")}},
		{"don't leak NetBIOS (UDP)", []store.RuleMatch{mt("udp.dport", "137, 138")}},
		{"don't leak NetBIOS (TCP)", []store.RuleMatch{mt("tcp.dport", "139")}},
		{"don't leak SMB", []store.RuleMatch{mt("tcp.dport", "445")}},
		{"don't leak SSDP / UPnP", []store.RuleMatch{mt("udp.dport", "1900")}},
		{"don't send DHCP to peers (disable if this router is a DHCP client)", []store.RuleMatch{mt("udp.dport", "67, 68")}},
	}
	for _, st := range steps {
		if err := s.addRule(output, st.comment, st.matches, []store.RuleStatement{stmt("drop")}); err != nil {
			return err
		}
	}
	return nil
}

// mgmtAccessRules accepts SSH and the nftably UI from @mgmt, both families.
func (s *Server) mgmtAccessRules(input int64, uiPort int) error {
	type accessRule struct {
		comment      string
		saddr, dport string
	}
	rules := []accessRule{
		{"SSH from management (IPv4)", "@mgmt4", "22"},
		{"SSH from management (IPv6)", "@mgmt6", "22"},
	}
	if uiPort > 0 {
		port := fmt.Sprintf("%d", uiPort)
		rules = append(rules,
			accessRule{"nftably UI from management (IPv4)", "@mgmt4", port},
			accessRule{"nftably UI from management (IPv6)", "@mgmt6", port},
		)
	}
	for _, r := range rules {
		saddrKey := "ip.saddr"
		if r.saddr == "@mgmt6" {
			saddrKey = "ip6.saddr"
		}
		if err := s.addRule(input, r.comment,
			[]store.RuleMatch{mt(saddrKey, r.saddr), mt("tcp.dport", r.dport)},
			[]store.RuleStatement{stmt("accept")}); err != nil {
			return err
		}
	}
	return nil
}

// dropLogRule adds a rate-limited log of denied inbound (falls through to the
// chain's drop policy — no verdict of its own).
func (s *Server) dropLogRule(input int64) error {
	// The counter (unlimited) tallies every denied new connection into a named
	// "denied" counter for at-a-glance accounting; the log is rate-limited so a
	// scan can't flood it. Order matters: count first, then sample the log.
	return s.addRule(input, "count + log denied inbound",
		[]store.RuleMatch{mt("ct.state", "new")},
		[]store.RuleStatement{
			stmtP("counter", map[string]string{"cname": "denied"}),
			stmtP("limit", map[string]string{"rate": "5", "per": "second", "burst": "10"}),
			stmtP("log", map[string]string{"prefix": "in-drop "}),
		})
}

func (s *Server) buildSecureServerPreset(r *http.Request) error {
	if err := s.resetTables(); err != nil {
		return err
	}
	mgmt, err := s.ensureList("mgmt", "Management networks — SSH and the nftably UI are allowed only from here.")
	if err != nil {
		return err
	}
	s.seedMgmtWithClient(mgmt, r)
	if _, err := s.ensureList("blacklist", "Addresses to drop outright, before anything else. The Connections page's Block button appends here."); err != nil {
		return err
	}

	tableID, err := s.store.CreateTable(store.Table{Family: "inet", Name: "filter", Comment: "Basic secure server (nftably preset)"})
	if err != nil {
		return err
	}
	input, err := s.store.CreateChain(store.Chain{TableID: tableID, Name: "input", Kind: "base", Hook: "input", ChainType: "filter", Priority: "filter", Policy: "drop"})
	if err != nil {
		return err
	}
	if _, err := s.store.CreateChain(store.Chain{TableID: tableID, Name: "forward", Kind: "base", Hook: "forward", ChainType: "filter", Priority: "filter", Policy: "drop"}); err != nil {
		return err
	}
	if _, err := s.store.CreateChain(store.Chain{TableID: tableID, Name: "output", Kind: "base", Hook: "output", ChainType: "filter", Priority: "filter", Policy: "accept"}); err != nil {
		return err
	}
	if err := s.baseInputRules(input); err != nil {
		return err
	}
	if err := s.mgmtAccessRules(input, s.ownListenPort()); err != nil {
		return err
	}
	return s.dropLogRule(input)
}

// wgIface / wgPort are the WireGuard preset's conventional interface and listen
// port — the common defaults, editable afterwards on the Firewall page.
const (
	wgIface = "wg0"
	wgPort  = "51820"
)

func (s *Server) buildWireGuardPreset(r *http.Request) error {
	if err := s.resetTables(); err != nil {
		return err
	}
	mgmt, err := s.ensureList("mgmt", "Management networks — SSH and the nftably UI are allowed only from here.")
	if err != nil {
		return err
	}
	s.seedMgmtWithClient(mgmt, r)
	if _, err := s.ensureList("blacklist", "Addresses to drop outright, before anything else. The Connections page's Block button appends here."); err != nil {
		return err
	}

	tableID, err := s.store.CreateTable(store.Table{Family: "inet", Name: "filter", Comment: "WireGuard VPN server (nftably preset)"})
	if err != nil {
		return err
	}
	input, err := s.store.CreateChain(store.Chain{TableID: tableID, Name: "input", Kind: "base", Hook: "input", ChainType: "filter", Priority: "filter", Policy: "drop"})
	if err != nil {
		return err
	}
	forward, err := s.store.CreateChain(store.Chain{TableID: tableID, Name: "forward", Kind: "base", Hook: "forward", ChainType: "filter", Priority: "filter", Policy: "drop"})
	if err != nil {
		return err
	}
	if _, err := s.store.CreateChain(store.Chain{TableID: tableID, Name: "output", Kind: "base", Hook: "output", ChainType: "filter", Priority: "filter", Policy: "accept"}); err != nil {
		return err
	}

	if err := s.baseInputRules(input); err != nil {
		return err
	}
	if err := s.mgmtAccessRules(input, s.ownListenPort()); err != nil {
		return err
	}
	// The WireGuard handshake/data port, and full trust of the tunnel interface for
	// traffic addressed to this box.
	if err := s.addRule(input, "WireGuard listen port", []store.RuleMatch{mt("udp.dport", wgPort)}, []store.RuleStatement{stmt("accept")}); err != nil {
		return err
	}
	if err := s.addRule(input, "trust the WireGuard tunnel", []store.RuleMatch{mt("meta.iifname", wgIface)}, []store.RuleStatement{stmt("accept")}); err != nil {
		return err
	}
	if err := s.dropLogRule(input); err != nil {
		return err
	}

	// Route the tunnel: replies, clients heading out, and traffic back to clients.
	fwd := []struct {
		comment string
		matches []store.RuleMatch
	}{
		{"established/related transit", []store.RuleMatch{mt("ct.state", "established, related")}},
		{"from WireGuard clients", []store.RuleMatch{mt("meta.iifname", wgIface)}},
		{"to WireGuard clients", []store.RuleMatch{mt("meta.oifname", wgIface)}},
	}
	for _, f := range fwd {
		if err := s.addRule(forward, f.comment, f.matches, []store.RuleStatement{stmt("accept")}); err != nil {
			return err
		}
	}
	return nil
}

// homeWAN / homeLAN are the home-router preset's conventional uplink and internal
// interface names — placeholders the operator renames to their real interfaces.
const (
	homeWAN = "wan"
	homeLAN = "lan"
)

func (s *Server) buildHomeRouterPreset(r *http.Request) error {
	if err := s.resetTables(); err != nil {
		return err
	}
	mgmt, err := s.ensureList("mgmt", "Networks allowed to manage the router, in addition to the LAN side.")
	if err != nil {
		return err
	}
	s.seedMgmtWithClient(mgmt, r)
	if _, err := s.ensureList("blacklist", "Addresses to drop outright, before anything else. The Connections page's Block button appends here."); err != nil {
		return err
	}

	// ── filter table ────────────────────────────────────────────────────────
	filterID, err := s.store.CreateTable(store.Table{Family: "inet", Name: "filter", Comment: "Home router / gateway (nftably preset)"})
	if err != nil {
		return err
	}
	input, err := s.store.CreateChain(store.Chain{TableID: filterID, Name: "input", Kind: "base", Hook: "input", ChainType: "filter", Priority: "filter", Policy: "drop"})
	if err != nil {
		return err
	}
	forward, err := s.store.CreateChain(store.Chain{TableID: filterID, Name: "forward", Kind: "base", Hook: "forward", ChainType: "filter", Priority: "filter", Policy: "drop"})
	if err != nil {
		return err
	}
	if _, err := s.store.CreateChain(store.Chain{TableID: filterID, Name: "output", Kind: "base", Hook: "output", ChainType: "filter", Priority: "filter", Policy: "accept"}); err != nil {
		return err
	}

	if err := s.baseInputRules(input); err != nil {
		return err
	}
	if err := s.mgmtAccessRules(input, s.ownListenPort()); err != nil {
		return err
	}
	// LAN-side management and the services a home router hands out (DHCP, DNS).
	lan := []struct {
		comment string
		matches []store.RuleMatch
	}{
		{"SSH from the LAN", []store.RuleMatch{mt("meta.iifname", homeLAN), mt("tcp.dport", "22")}},
		{"DHCP requests from the LAN", []store.RuleMatch{mt("meta.iifname", homeLAN), mt("udp.dport", "67")}},
		{"DNS from the LAN (router as resolver)", []store.RuleMatch{mt("meta.iifname", homeLAN), mt("udp.dport", "53")}},
		{"DNS over TCP from the LAN", []store.RuleMatch{mt("meta.iifname", homeLAN), mt("tcp.dport", "53")}},
	}
	if port := s.ownListenPort(); port > 0 {
		lan = append(lan, struct {
			comment string
			matches []store.RuleMatch
		}{"this UI from the LAN", []store.RuleMatch{mt("meta.iifname", homeLAN), mt("tcp.dport", fmt.Sprintf("%d", port))}})
	}
	for _, l := range lan {
		if err := s.addRule(input, l.comment, l.matches, []store.RuleStatement{stmt("accept")}); err != nil {
			return err
		}
	}
	if err := s.dropLogRule(input); err != nil {
		return err
	}

	// Forward: let the LAN out and replies back; the internet can't start anything.
	fwd := []struct {
		comment string
		matches []store.RuleMatch
	}{
		{"drop invalid transit", []store.RuleMatch{mt("ct.state", "invalid")}},
		{"established/related back to the LAN", []store.RuleMatch{mt("ct.state", "established, related")}},
		{"LAN out to the internet", []store.RuleMatch{mt("meta.iifname", homeLAN), mt("meta.oifname", homeWAN)}},
	}
	for i, f := range fwd {
		verdict := stmt("accept")
		if i == 0 {
			verdict = stmt("drop")
		}
		if err := s.addRule(forward, f.comment, f.matches, []store.RuleStatement{verdict}); err != nil {
			return err
		}
	}

	// ── nat table ───────────────────────────────────────────────────────────
	natID, err := s.store.CreateTable(store.Table{Family: "inet", Name: "nat", Comment: "Home router NAT (nftably preset)"})
	if err != nil {
		return err
	}
	// An empty prerouting dstnat chain, ready for port-forwards the operator adds.
	if _, err := s.store.CreateChain(store.Chain{TableID: natID, Name: "prerouting", Kind: "base", Hook: "prerouting", ChainType: "nat", Priority: "dstnat"}); err != nil {
		return err
	}
	post, err := s.store.CreateChain(store.Chain{TableID: natID, Name: "postrouting", Kind: "base", Hook: "postrouting", ChainType: "nat", Priority: "srcnat"})
	if err != nil {
		return err
	}
	return s.addRule(post, "masquerade LAN traffic out the WAN", []store.RuleMatch{mt("meta.oifname", homeWAN)}, []store.RuleStatement{stmt("masquerade")})
}

// secureBase builds the common single-host filter table used by the server-style
// presets: an inet filter table, a default-deny input with the survivable base +
// SSH/UI from @mgmt, a drop forward and an accept output. It returns the input
// chain id so the caller can add its service-specific accepts before the log.
func (s *Server) secureBase(r *http.Request, comment string, forward bool) (int64, error) {
	if err := s.resetTables(); err != nil {
		return 0, err
	}
	mgmt, err := s.ensureList("mgmt", "Management networks — SSH and the nftably UI are allowed only from here.")
	if err != nil {
		return 0, err
	}
	s.seedMgmtWithClient(mgmt, r)
	if _, err := s.ensureList("blacklist", "Addresses to drop outright, before anything else. The Connections page's Block button appends here."); err != nil {
		return 0, err
	}
	tableID, err := s.store.CreateTable(store.Table{Family: "inet", Name: "filter", Comment: comment})
	if err != nil {
		return 0, err
	}
	input, err := s.store.CreateChain(store.Chain{TableID: tableID, Name: "input", Kind: "base", Hook: "input", ChainType: "filter", Priority: "filter", Policy: "drop"})
	if err != nil {
		return 0, err
	}
	// A container host deliberately has no forward chain — Docker owns that hook.
	if forward {
		if _, err := s.store.CreateChain(store.Chain{TableID: tableID, Name: "forward", Kind: "base", Hook: "forward", ChainType: "filter", Priority: "filter", Policy: "drop"}); err != nil {
			return 0, err
		}
	}
	if _, err := s.store.CreateChain(store.Chain{TableID: tableID, Name: "output", Kind: "base", Hook: "output", ChainType: "filter", Priority: "filter", Policy: "accept"}); err != nil {
		return 0, err
	}
	if err := s.baseInputRules(input); err != nil {
		return 0, err
	}
	if err := s.mgmtAccessRules(input, s.ownListenPort()); err != nil {
		return 0, err
	}
	return input, nil
}

func (s *Server) buildWebServerPreset(r *http.Request) error {
	input, err := s.secureBase(r, "Web server (nftably preset)", true)
	if err != nil {
		return err
	}
	if err := s.addRule(input, "HTTP and HTTPS from anywhere", []store.RuleMatch{mt("tcp.dport", "80, 443")}, []store.RuleStatement{stmt("accept")}); err != nil {
		return err
	}
	return s.dropLogRule(input)
}

func (s *Server) buildDatabaseServerPreset(r *http.Request) error {
	input, err := s.secureBase(r, "Database server (nftably preset)", true)
	if err != nil {
		return err
	}
	if _, err := s.ensureList("app", "Your application tier — the only hosts allowed to reach the database."); err != nil {
		return err
	}
	// PostgreSQL + MySQL from @app only, both families. Keep the one you use.
	db := []struct {
		comment, saddrKey, saddr string
	}{
		{"database from the app tier (IPv4)", "ip.saddr", "@app4"},
		{"database from the app tier (IPv6)", "ip6.saddr", "@app6"},
	}
	for _, d := range db {
		if err := s.addRule(input, d.comment,
			[]store.RuleMatch{mt(d.saddrKey, d.saddr), mt("tcp.dport", "5432, 3306")},
			[]store.RuleStatement{stmt("accept")}); err != nil {
			return err
		}
	}
	return s.dropLogRule(input)
}

func (s *Server) buildContainerHostPreset(r *http.Request) error {
	// No forward chain: Docker manages the forward hook and container NAT itself,
	// and a drop-policy forward here would break container traffic.
	input, err := s.secureBase(r, "Docker / container host (nftably preset)", false)
	if err != nil {
		return err
	}
	return s.dropLogRule(input)
}

func (s *Server) buildBGPPreset(r *http.Request) error {
	if err := s.resetTables(); err != nil {
		return err
	}
	mgmt, err := s.ensureList("mgmt", "Management networks — SSH and the nftably UI are allowed only from here.")
	if err != nil {
		return err
	}
	s.seedMgmtWithClient(mgmt, r)
	if _, err := s.ensureList("peers", "Your BGP peers — BGP (TCP 179) and BFD are accepted only from these addresses. Add each peer's IPv4 and IPv6."); err != nil {
		return err
	}
	if _, err := s.ensureList("blacklist", "Addresses to drop outright, before anything else. The Connections page's Block button appends here."); err != nil {
		return err
	}

	tableID, err := s.store.CreateTable(store.Table{Family: "inet", Name: "filter", Comment: "BGP edge router (nftably preset)"})
	if err != nil {
		return err
	}
	input, err := s.store.CreateChain(store.Chain{TableID: tableID, Name: "input", Kind: "base", Hook: "input", ChainType: "filter", Priority: "filter", Policy: "drop"})
	if err != nil {
		return err
	}
	forward, err := s.store.CreateChain(store.Chain{TableID: tableID, Name: "forward", Kind: "base", Hook: "forward", ChainType: "filter", Priority: "filter", Policy: "accept"})
	if err != nil {
		return err
	}
	output, err := s.store.CreateChain(store.Chain{TableID: tableID, Name: "output", Kind: "base", Hook: "output", ChainType: "filter", Priority: "filter", Policy: "accept"})
	if err != nil {
		return err
	}

	if err := s.baseInputRules(input); err != nil {
		return err
	}
	if err := s.mgmtAccessRules(input, s.ownListenPort()); err != nil {
		return err
	}
	// BGP + BFD from peers, both families.
	bgp := []struct {
		comment string
		matches []store.RuleMatch
	}{
		{"BGP from peers (IPv4)", []store.RuleMatch{mt("ip.saddr", "@peers4"), mt("tcp.dport", "179")}},
		{"BGP from peers (IPv6)", []store.RuleMatch{mt("ip6.saddr", "@peers6"), mt("tcp.dport", "179")}},
		{"BFD from peers (IPv4)", []store.RuleMatch{mt("ip.saddr", "@peers4"), mt("udp.dport", "3784, 3785, 4784")}},
		{"BFD from peers (IPv6)", []store.RuleMatch{mt("ip6.saddr", "@peers6"), mt("udp.dport", "3784, 3785, 4784")}},
	}
	for _, b := range bgp {
		if err := s.addRule(input, b.comment, b.matches, []store.RuleStatement{stmt("accept")}); err != nil {
			return err
		}
	}
	if err := s.dropLogRule(input); err != nil {
		return err
	}
	// Transit hygiene: drop obviously-invalid forwarded traffic; the accept
	// policy routes the rest.
	if err := s.addRule(forward, "drop invalid transit", []store.RuleMatch{mt("ct.state", "invalid")}, []store.RuleStatement{stmt("drop")}); err != nil {
		return err
	}
	// Output hygiene: keep the router's own noise off the wire.
	return s.outputHygieneRules(output)
}
