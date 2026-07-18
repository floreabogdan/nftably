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
				"A rate-limited log of denied inbound, so scans are visible without flooding the log.",
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
	return s.addRule(input, "log denied inbound (rate-limited)",
		[]store.RuleMatch{mt("ct.state", "new")},
		[]store.RuleStatement{
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
