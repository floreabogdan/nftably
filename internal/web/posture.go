package web

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/floreabogdan/nftably/internal/advisor"
	nftconf "github.com/floreabogdan/nftably/internal/render"
	"github.com/floreabogdan/nftably/internal/store"
)

// posture.go is the security self-check: it reads the owned model and grades it
// against the things a solid host firewall should have — default-deny, the
// survivable base (loopback, established/related, invalid), IPv6's mandatory
// ICMP, anti-spoofing, and a scoped SSH — explaining each in plain language and,
// where it's safe, offering a one-click fix. The fixes only ever ADD accept
// rules or drop clearly-bad traffic (invalid, spoofed); they never flip a policy
// or remove access, so a check can't lock you out. Everything stays model-only —
// a fix drops you on the Changes page, behind the armed auto-revert.

type postureStatus string

const (
	posturePass postureStatus = "pass"
	postureWarn postureStatus = "warn"
	postureFail postureStatus = "fail"
	postureInfo postureStatus = "info" // advisory; not counted in the score
)

// postureCheck is one graded item shown on the Posture page.
type postureCheck struct {
	ID       string
	Title    string
	Status   postureStatus
	Detail   string // plain-language why-it-matters and the current finding
	FixID    string // non-empty ⇒ a one-click fix (POST /harden/fix/{FixID})
	FixLabel string
	FixHref  string // for a non-inline remedy (e.g. a link to Presets)
}

// inputView flattens the input-filtering picture the checks read.
type inputView struct {
	haveInput  bool
	dropPolicy bool
	chainID    int64 // an input chain to inject fixes into (0 if none)
	rules      []store.ChainRule
}

// postureView collects every base input chain across the owned inet/ip tables.
// Those are where host filtering happens; a router's forward chain is out of
// scope here.
func (s *Server) postureView() (inputView, error) {
	m, err := s.loadModel()
	if err != nil {
		return inputView{}, err
	}
	return postureViewFrom(m), nil
}

// postureViewFrom derives the input-chain view from an already-loaded model, so
// a caller that needs several model-derived views (the Posture page) can load
// once instead of once per view.
func postureViewFrom(m nftconf.Model) inputView {
	var v inputView
	for _, t := range m.Tables {
		if t.Family != "inet" && t.Family != "ip" && t.Family != "ip6" {
			continue
		}
		for _, c := range t.Chains {
			if !c.IsBase() || c.Hook != "input" {
				continue
			}
			v.haveInput = true
			if v.chainID == 0 || (c.Policy == "drop" && !v.dropPolicy) {
				v.chainID = c.ID // prefer a drop-policy chain to inject into
			}
			if c.Policy == "drop" {
				v.dropPolicy = true
			}
			v.rules = append(v.rules, c.Rules...)
		}
	}
	return v
}

func (v inputView) any(pred func(store.ChainRule) bool) bool {
	for _, r := range v.rules {
		if r.Enabled && pred(r) {
			return true
		}
	}
	return false
}

// has is like any but ignores the enabled flag — used for idempotency, so a
// recipe rule the operator disabled (rather than deleted) isn't re-added.
func (v inputView) has(pred func(store.ChainRule) bool) bool {
	for _, r := range v.rules {
		if pred(r) {
			return true
		}
	}
	return false
}

// matchHas reports whether a rule carries a match on key whose value contains
// sub (sub "" matches the key regardless of value).
func matchHas(r store.ChainRule, key, sub string) bool {
	for _, m := range r.Matches {
		if m.Key == key && (sub == "" || strings.Contains(m.Value, sub)) {
			return true
		}
	}
	return false
}

func stmtHas(r store.ChainRule, key string) bool {
	for _, st := range r.Statements {
		if st.Key == key {
			return true
		}
	}
	return false
}

// posture runs the checks and returns them with the view (the view carries the
// chain id the fix handler injects into).
func (s *Server) posture() ([]postureCheck, inputView, error) {
	m, err := s.loadModel()
	if err != nil {
		return nil, inputView{}, err
	}
	checks, v := s.postureFrom(m)
	return checks, v, nil
}

// postureFrom runs the posture checks against an already-loaded model. The
// Posture page loads the model once and calls this plus forwardChainFrom /
// advisorFindingsFrom, instead of each re-loading the whole graph.
func (s *Server) postureFrom(m nftconf.Model) ([]postureCheck, inputView) {
	v := postureViewFrom(m)

	loopback := v.any(func(r store.ChainRule) bool { return matchHas(r, "meta.iifname", "lo") && stmtHas(r, "accept") })
	estab := v.any(func(r store.ChainRule) bool { return matchHas(r, "ct.state", "established") && stmtHas(r, "accept") })
	invalid := v.any(func(r store.ChainRule) bool { return matchHas(r, "ct.state", "invalid") && stmtHas(r, "drop") })
	v6icmp := v.any(func(r store.ChainRule) bool { return matchHas(r, "icmpv6.type", "") && stmtHas(r, "accept") })
	rpf := v.any(func(r store.ChainRule) bool { return matchHas(r, "fib.rpf", "") && stmtHas(r, "drop") })

	// SSH: any accept of tcp/22, and whether it's scoped by a source address.
	sshOpen := false
	sshScoped := false
	for _, r := range v.rules {
		if r.Enabled && matchHas(r, "tcp.dport", "22") && stmtHas(r, "accept") {
			if matchHas(r, "ip.saddr", "") || matchHas(r, "ip6.saddr", "") {
				sshScoped = true
			} else {
				sshOpen = true
			}
		}
	}

	var checks []postureCheck

	// 1. Default-deny — advisory only; flipping a policy is never one-click.
	switch {
	case !v.haveInput:
		checks = append(checks, postureCheck{ID: "default-deny", Title: "Default-deny on inbound traffic", Status: postureFail,
			Detail:  "There's no input chain, so nothing filters traffic addressed to this box — everything the kernel allows gets in. Start from a preset for a safe default-deny base.",
			FixHref: "/presets", FixLabel: "Use a preset"})
	case !v.dropPolicy:
		checks = append(checks, postureCheck{ID: "default-deny", Title: "Default-deny on inbound traffic", Status: postureWarn,
			Detail:  "Your input chain's policy is accept, so anything no rule dropped is allowed — the opposite of a secure default. A drop policy (with the base rules below in place) only lets in what you've explicitly allowed.",
			FixHref: "/presets", FixLabel: "Use a preset"})
	default:
		checks = append(checks, postureCheck{ID: "default-deny", Title: "Default-deny on inbound traffic", Status: posturePass,
			Detail: "Your input chain drops by default — only what you explicitly allow gets in."})
	}

	// The base rules matter under a drop policy; if the input already accepts by
	// default they're informational.
	baseFail := postureFail
	if v.haveInput && !v.dropPolicy {
		baseFail = postureWarn
	}

	// 2. Loopback.
	checks = append(checks, boolCheck(loopback, "loopback", "Loopback traffic allowed", baseFail,
		"Local services (databases, health checks, this UI over an SSH tunnel) talk over 127.0.0.1. Under a drop policy, without an early `iifname lo accept` they break.",
		"Allow loopback", v.chainID))

	// 3. Established/related.
	checks = append(checks, boolCheck(estab, "established", "Replies to your own connections allowed", baseFail,
		"`ct state established,related accept` is what lets the answers to traffic you started back in. Without it, a drop policy blocks the replies and nothing works.",
		"Accept established/related", v.chainID))

	// 4. Invalid dropped.
	checks = append(checks, boolCheck(invalid, "invalid", "Invalid packets dropped", postureWarn,
		"Packets conntrack can't place in any connection are a common tool of scans and attacks. Dropping `ct state invalid` early is cheap and standard.",
		"Drop invalid", v.chainID))

	// 5. IPv6's mandatory ICMP.
	checks = append(checks, boolCheck(v6icmp, "v6icmp", "IPv6 neighbour discovery allowed", postureWarn,
		"IPv6 relies on ICMPv6 (neighbour discovery, packet-too-big). Block it under a drop policy and IPv6 quietly stops working. If you don't run IPv6 at all you can ignore this.",
		"Allow essential ICMPv6", v.chainID))

	// 6. Anti-spoofing — advisory (rpf can bite on asymmetric routing).
	if rpf {
		checks = append(checks, postureCheck{ID: "rpf", Title: "Anti-spoofing (reverse-path filter)", Status: posturePass,
			Detail: "You drop packets whose source couldn't route back the way they came — spoofed traffic is rejected."})
	} else {
		checks = append(checks, postureCheck{ID: "rpf", Title: "Anti-spoofing (reverse-path filter)", Status: postureInfo,
			Detail: "A reverse-path check (`fib saddr . iif oif missing drop`) rejects spoofed source addresses — nftables' answer to rp_filter. Skip it if this box does asymmetric routing (multi-homed / policy routing), where legitimate traffic can arrive the 'wrong' way.",
			FixID:  "rpf", FixLabel: "Add anti-spoofing"})
	}

	// 7. SSH scoping — advisory; the right source set is yours to choose.
	switch {
	case sshOpen:
		checks = append(checks, postureCheck{ID: "ssh", Title: "SSH restricted to your networks", Status: postureWarn,
			Detail:  "SSH (port 22) is accepted from any address. That's the internet's most-scanned port. Scope it to a management set (@mgmt) or your admin network on the Firewall page, or put it behind a VPN.",
			FixHref: "/firewall", FixLabel: "Edit on Firewall"})
	case sshScoped:
		checks = append(checks, postureCheck{ID: "ssh", Title: "SSH restricted to your networks", Status: posturePass,
			Detail: "Your SSH accept is scoped to a source address/set, not open to the whole internet."})
	default:
		checks = append(checks, postureCheck{ID: "ssh", Title: "SSH restricted to your networks", Status: postureInfo,
			Detail: "No rule accepts SSH (port 22) here. If you administer this box over SSH, allow it from your management network only; if you don't, nothing to do."})
	}

	// 8. IPv6 parity — the classic footgun: rules that scope traffic by IPv4
	// address, with nothing scoping it by IPv6 address, so IPv6 clients bypass the
	// restriction. Only surfaced when there's a clear v4-only asymmetry.
	v4scope := v.any(func(r store.ChainRule) bool { return matchHas(r, "ip.saddr", "") || matchHas(r, "ip.daddr", "") })
	v6scope := v.any(func(r store.ChainRule) bool { return matchHas(r, "ip6.saddr", "") || matchHas(r, "ip6.daddr", "") })
	switch {
	case v4scope && !v6scope:
		checks = append(checks, postureCheck{ID: "v6-parity", Title: "IPv6 covered like IPv4", Status: postureWarn,
			Detail:  "Some rules restrict traffic by IPv4 address, but nothing restricts it by IPv6 address. If this box has IPv6, clients can reach those services over IPv6 and slip past the IPv4 scoping. Add the ip6 equivalents — or, if you don't use IPv6 here, drop it at the input chain.",
			FixHref: "/firewall", FixLabel: "Review rules"})
	case v4scope && v6scope:
		checks = append(checks, postureCheck{ID: "v6-parity", Title: "IPv6 covered like IPv4", Status: posturePass,
			Detail: "Your address-scoped rules cover both IPv4 and IPv6, so IPv6 clients can't bypass the restrictions."})
	default:
		checks = append(checks, postureCheck{ID: "v6-parity", Title: "IPv6 covered like IPv4", Status: postureInfo,
			Detail: "No rules scope traffic by address, so there's no IPv4/IPv6 asymmetry to worry about here."})
	}

	return checks, v
}

// boolCheck builds a pass/needs-attention check with an inline fix when it fails.
func boolCheck(ok bool, id, title string, failStatus postureStatus, detail, fixLabel string, chainID int64) postureCheck {
	c := postureCheck{ID: id, Title: title, Detail: detail}
	if ok {
		c.Status = posturePass
		return c
	}
	c.Status = failStatus
	if chainID != 0 {
		c.FixID = id
		c.FixLabel = fixLabel
	}
	return c
}

// score counts passes over the non-advisory checks.
func postureScore(checks []postureCheck) (pass, total int) {
	for _, c := range checks {
		if c.Status == postureInfo {
			continue
		}
		total++
		if c.Status == posturePass {
			pass++
		}
	}
	return pass, total
}

// ── page + fixes ────────────────────────────────────────────────────────────

type hardenVM struct {
	nav
	Checks    []postureCheck
	Pass      int
	Total     int
	HaveModel bool
	LoadErr   string
	// SSHBanActive is true once the brute-force auto-ban rules are in the input
	// chain, so the recipe card shows "on" instead of offering to add them.
	SSHBanActive bool
	// HaveForward gates the IDS recipe (it only makes sense for a routing/IPS
	// setup); IDSAdded is true once the forward chain carries a queue rule (added
	// disabled, so it can't break an apply on a kernel without NFQUEUE).
	HaveForward bool
	IDSAdded    bool
	// Exposed-services section (the merged-in advisor): every live listener run
	// through the simulator against the model.
	Findings []advisor.Finding
	Hidden   []advisor.Finding
	ScanNote string
	Warns    int
	Infos    int
	// Bans are the sources the kernel's auto-ban timeout sets are currently
	// blocking — live runtime state, each liftable early.
	Bans []banEntry
}

func (s *Server) handleHarden(w http.ResponseWriter, r *http.Request) {
	vm := hardenVM{nav: s.navFor(r, "harden")}
	// Load the owned model once and derive every view from it — posture, the
	// forward-chain probe and the exposure findings all read the same graph, so
	// one load replaces the three this page used to do.
	m, err := s.loadModel()
	if err != nil {
		vm.LoadErr = err.Error()
	} else {
		checks, v := s.postureFrom(m)
		vm.Checks = checks
		vm.Pass, vm.Total = postureScore(checks)
		vm.HaveModel = v.haveInput
		vm.SSHBanActive = v.has(hasBanRule)
		if _, fwRules, ok := forwardChainFrom(m); ok {
			vm.HaveForward = true
			for _, r := range fwRules {
				if stmtHas(r, "queue") {
					vm.IDSAdded = true
				}
			}
		}
	}
	// The exposed-services scan is independent of the posture read; a failure
	// there shouldn't blank the whole page, so it's best-effort. When the model
	// failed to load, fall back to a fresh load inside advisorFindings.
	findings := func() (visible, hidden []advisor.Finding, note string, e error) {
		if err != nil {
			return s.advisorFindings()
		}
		return s.advisorFindingsFrom(m)
	}
	if visible, hidden, note, ferr := findings(); ferr == nil {
		vm.Findings, vm.Hidden, vm.ScanNote = visible, hidden, note
		for _, f := range visible {
			if f.Severity == "warn" {
				vm.Warns++
			} else {
				vm.Infos++
			}
		}
	} else {
		// Best-effort: a failure here shouldn't blank the whole page, but log it so
		// a silently-empty section is diagnosable rather than a mystery.
		s.log.Warn("exposed-services scan failed", "error", ferr)
	}
	// Live auto-ban members, so the operator can see who's blocked and lift a ban.
	banCtx, banCancel := reqCtx(r)
	vm.Bans = s.currentBans(banCtx)
	banCancel()
	render(w, s.log, "harden.html", vm)
}

// hardenFixes maps a fix id to the rule(s) it appends to the input chain. Each
// only adds an accept or drops clearly-bad traffic, so applying one can't lock
// anyone out.
var hardenFixes = map[string]struct {
	comment string
	matches []store.RuleMatch
	stmts   []store.RuleStatement
}{
	"loopback":    {"loopback", []store.RuleMatch{mt("meta.iifname", "lo")}, []store.RuleStatement{stmt("accept")}},
	"established": {"established/related", []store.RuleMatch{mt("ct.state", "established, related")}, []store.RuleStatement{stmt("accept")}},
	"invalid":     {"drop invalid", []store.RuleMatch{mt("ct.state", "invalid")}, []store.RuleStatement{stmt("drop")}},
	"v6icmp": {"ICMPv6 — required for IPv6 to work", []store.RuleMatch{mt("icmpv6.type",
		"echo-request, echo-reply, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, destination-unreachable, packet-too-big, time-exceeded, parameter-problem")}, []store.RuleStatement{stmt("accept")}},
	"rpf": {"drop spoofed source (reverse-path)", []store.RuleMatch{mt("fib.rpf", "")}, []store.RuleStatement{stmt("drop")}},
}

func (s *Server) handleHardenFix(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	fix, ok := hardenFixes[id]
	if !ok {
		http.Error(w, "unknown fix", http.StatusBadRequest)
		return
	}
	v, err := s.postureView()
	if err != nil {
		redirectErr(w, r, "/harden", "Could not read the firewall: "+err.Error())
		return
	}
	if v.chainID == 0 {
		redirectErr(w, r, "/harden", "There's no input chain to add this to yet — start from a preset.")
		return
	}
	if err := s.addRule(v.chainID, fix.comment, fix.matches, fix.stmts); err != nil {
		redirectErr(w, r, "/harden", "Could not add the rule: "+err.Error())
		return
	}
	s.audit(r, "applied hardening fix: "+id)
	// Land on the Changes page so the armed auto-revert covers the change.
	http.Redirect(w, r, "/changes", http.StatusSeeOther)
}

// hasBanRule reports whether a rule carries a rate-ban (auto-ban) statement.
func hasBanRule(r store.ChainRule) bool { return stmtHas(r, "ban.rate") }

// sshBanSets are the two dynamic sets the SSH auto-ban recipe drops on and bans
// into — one per family.
// Validation for the generic auto-ban form.
var (
	banServiceRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)
	banPortRe    = regexp.MustCompile(`^[0-9]{1,5}(,[0-9]{1,5})*$`)
	banTimeoutRe = regexp.MustCompile(`^[0-9]{1,4}[smhd]$`)
	banRateUnits = map[string]bool{"second": true, "minute": true, "hour": true, "day": true}
)

// handleHardenSSHBan installs the kernel brute-force auto-ban for SSH: a rule
// that adds a source opening SSH connections too fast to a dynamic timeout set,
// and an early drop of everything in that set. It inserts at the top of the input
// chain — before any SSH accept, so an open accept can't shadow the detector —
// and the dynamic sets are declared by the renderer. Model-only; the armed apply
// still gates the kernel.
func (s *Server) handleHardenSSHBan(w http.ResponseWriter, r *http.Request) {
	v, err := s.postureView()
	if err != nil {
		redirectErr(w, r, "/harden", "Could not read the firewall: "+err.Error())
		return
	}
	if v.chainID == 0 {
		redirectErr(w, r, "/harden", "There's no input chain to protect yet — start from a preset.")
		return
	}
	if v.has(hasBanRule) {
		http.Redirect(w, r, "/harden", http.StatusSeeOther)
		return
	}
	rules := banRules("ssh", "tcp", "22", "10", "minute", "5", "1h")
	if err := s.insertBanRules(v.chainID, rules); err != nil {
		redirectErr(w, r, "/harden", "Could not add the auto-ban rules: "+err.Error())
		return
	}
	s.audit(r, "enabled SSH brute-force auto-ban")
	http.Redirect(w, r, "/changes", http.StatusSeeOther)
}

// banRules builds the four rules of a rate-based auto-ban for one service: an
// early drop of every source already in the abusers set (v4 + v6), and a
// detector that adds a source exceeding the rate to that set (v4 + v6). setBase
// names the dynamic sets (<base>_abusers / <base>_abusers6). proto is tcp or
// udp; port is the watched destination port (or a comma list, or "" to watch
// every new connection of that proto). The returned order is drops first, then
// detectors, so inserting each at the chain start lands them top-of-chain as
// drop(v4,v6) then detect(v4,v6).
func banRules(setBase, proto, port, rate, per, burst, timeout string) []store.ChainRule {
	set4, set6 := setBase+"_abusers", setBase+"_abusers6"
	banP := func(set, family string) map[string]string {
		return map[string]string{"set": set, "family": family, "rate": rate, "per": per, "burst": burst, "timeout": timeout}
	}
	// The detector's traffic match is the same for v4 and v6 (only the ban set
	// and family differ); an empty port watches all new connections of the proto.
	detect := func() []store.RuleMatch {
		var ms []store.RuleMatch
		if strings.TrimSpace(port) != "" {
			ms = append(ms, mt(proto+".dport", port))
		}
		return append(ms, mt("ct.state", "new"))
	}
	svc := strings.ToUpper(setBase)
	return []store.ChainRule{
		{Comment: svc + " auto-ban: drop banned sources (IPv4)", Matches: []store.RuleMatch{mt("ip.saddr", "@"+set4)}, Statements: []store.RuleStatement{stmt("drop")}},
		{Comment: svc + " auto-ban: drop banned sources (IPv6)", Matches: []store.RuleMatch{mt("ip6.saddr", "@"+set6)}, Statements: []store.RuleStatement{stmt("drop")}},
		{Comment: svc + " auto-ban: detect floods (IPv4)", Matches: detect(), Statements: []store.RuleStatement{stmtP("ban.rate", banP(set4, "ip"))}},
		{Comment: svc + " auto-ban: detect floods (IPv6)", Matches: detect(), Statements: []store.RuleStatement{stmtP("ban.rate", banP(set6, "ip6"))}},
	}
}

// insertBanRules inserts the ban rules at the top of the chain, in reverse so
// they keep their intended top-of-chain order.
func (s *Server) insertBanRules(chainID int64, rules []store.ChainRule) error {
	for i := len(rules) - 1; i >= 0; i-- {
		rl := rules[i]
		rl.ChainID = chainID
		rl.Enabled = true
		if _, err := s.store.CreateChainRuleAtStart(rl); err != nil {
			return err
		}
	}
	return nil
}

// handleHardenBan installs a rate-based auto-ban for an arbitrary service — the
// generic form of the SSH recipe. The operator names the service and gives the
// protocol/port and rate; nftably builds the same detect-and-drop rules keyed on
// a per-service dynamic set. Model-only; the armed apply gates the kernel.
func (s *Server) handleHardenBan(w http.ResponseWriter, r *http.Request) {
	v, err := s.postureView()
	if err != nil {
		redirectErr(w, r, "/harden", "Could not read the firewall: "+err.Error())
		return
	}
	if v.chainID == 0 {
		redirectErr(w, r, "/harden", "There's no input chain to protect yet — start from a preset.")
		return
	}
	name := strings.ToLower(strings.TrimSpace(r.FormValue("service")))
	proto := strings.TrimSpace(r.FormValue("proto"))
	port := strings.TrimSpace(r.FormValue("port"))
	rate := strings.TrimSpace(r.FormValue("rate"))
	per := strings.TrimSpace(r.FormValue("per"))
	burst := strings.TrimSpace(r.FormValue("burst"))
	timeout := strings.TrimSpace(r.FormValue("timeout"))

	if !banServiceRe.MatchString(name) {
		redirectErr(w, r, "/harden", "The service name must be letters, digits or underscore (it names the ban set).")
		return
	}
	if proto != "tcp" && proto != "udp" {
		redirectErr(w, r, "/harden", "Protocol must be tcp or udp.")
		return
	}
	if port != "" {
		if !banPortRe.MatchString(port) {
			redirectErr(w, r, "/harden", "Port must be a number, a comma list, or blank for any.")
			return
		}
		for _, p := range strings.Split(port, ",") {
			if !validPort(p) {
				redirectErr(w, r, "/harden", "Each port must be between 1 and 65535.")
				return
			}
		}
	}
	if _, e := strconv.Atoi(rate); e != nil {
		redirectErr(w, r, "/harden", "Rate must be a whole number.")
		return
	}
	if burst != "" {
		if _, e := strconv.Atoi(burst); e != nil {
			redirectErr(w, r, "/harden", "Burst must be a whole number.")
			return
		}
	}
	if !banTimeoutRe.MatchString(timeout) {
		redirectErr(w, r, "/harden", "Ban duration must look like 30s, 10m, 1h or 2d.")
		return
	}
	if !banRateUnits[per] {
		per = "minute"
	}
	// Refuse a duplicate: a ban already keyed on this service's set.
	for _, rl := range v.rules {
		if matchHas(rl, "ip.saddr", "@"+name+"_abusers") || matchHas(rl, "ip6.saddr", "@"+name+"_abusers6") {
			redirectErr(w, r, "/harden", "An auto-ban named "+name+" already exists.")
			return
		}
	}
	if err := s.insertBanRules(v.chainID, banRules(name, proto, port, rate, per, burst, timeout)); err != nil {
		redirectErr(w, r, "/harden", "Could not add the auto-ban rules: "+err.Error())
		return
	}
	s.audit(r, "enabled auto-ban for "+name)
	http.Redirect(w, r, "/changes", http.StatusSeeOther)
}

// forwardChain returns the first base forward filter chain with its rules — where
// an inline IDS/IPS inspects transit traffic.
func (s *Server) forwardChain() (int64, []store.ChainRule, bool) {
	m, err := s.loadModel()
	if err != nil {
		return 0, nil, false
	}
	return forwardChainFrom(m)
}

// forwardChainFrom finds the forward base chain in an already-loaded model.
func forwardChainFrom(m nftconf.Model) (int64, []store.ChainRule, bool) {
	for _, t := range m.Tables {
		for _, c := range t.Chains {
			if c.IsBase() && c.Hook == "forward" && c.ChainType != "nat" {
				return c.ID, c.Rules, true
			}
		}
	}
	return 0, nil, false
}

// handleHardenIDS sends transit traffic to an NFQUEUE for inspection by an inline
// IDS/IPS (Suricata, Snort). It inserts one `queue num 0 bypass` rule at the top
// of the forward chain: fail-open, so if no inspector is attached traffic simply
// continues through the rest of the chain — the box never blackholes transit
// because Suricata is down. It deliberately never touches the input chain, so the
// operator's own session is never queued. Model-only; the armed apply still gates
// the kernel.
func (s *Server) handleHardenIDS(w http.ResponseWriter, r *http.Request) {
	fwID, rules, ok := s.forwardChain()
	if !ok {
		redirectErr(w, r, "/harden", "There's no forward chain to inspect — this is for a routing/IPS setup. Start from a preset that routes (BGP or WireGuard).")
		return
	}
	for _, rl := range rules {
		if stmtHas(rl, "queue") {
			http.Redirect(w, r, "/harden", http.StatusSeeOther)
			return
		}
	}
	// Added DISABLED on purpose: the queue target needs kernel NFQUEUE support
	// (nfnetlink_queue), which many hosts don't have loaded — and because a whole
	// apply is one atomic transaction, an unsupported rule would reject everything.
	// The operator enables it on the Firewall page once the inspector is attached.
	rule := store.ChainRule{
		ChainID: fwID, Enabled: false,
		Comment:    "inspect transit with an IDS/IPS (fail-open)",
		Statements: []store.RuleStatement{stmtP("queue", map[string]string{"num": "0", "bypass": "bypass"})},
	}
	if _, err := s.store.CreateChainRuleAtStart(rule); err != nil {
		redirectErr(w, r, "/harden", "Could not add the inspection rule: "+err.Error())
		return
	}
	s.audit(r, "added IDS/IPS traffic inspection (NFQUEUE), disabled")
	http.Redirect(w, r, "/changes", http.StatusSeeOther)
}
