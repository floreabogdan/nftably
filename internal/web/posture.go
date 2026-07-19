package web

import (
	"net/http"
	"strings"

	"github.com/floreabogdan/nftably/internal/advisor"
	"github.com/floreabogdan/nftably/internal/store"
)

// posture.go is the security self-check: it reads the owned model and grades it
// against the things a solid host firewall should have — default-deny, the
// survivable base (loopback, established/related, invalid), IPv6's mandatory
// ICMP, anti-spoofing, and a scoped SSH — explaining each in plain language and,
// where it's safe, offering a one-click fix. The fixes only ever ADD accept
// rules or drop clearly-bad traffic (invalid, spoofed); they never flip a policy
// or remove access, so a check can't lock you out. Everything stays model-only —
// a fix drops you on the Review page, behind the armed auto-revert.

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
	return v, nil
}

func (v inputView) any(pred func(store.ChainRule) bool) bool {
	for _, r := range v.rules {
		if r.Enabled && pred(r) {
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
	v, err := s.postureView()
	if err != nil {
		return nil, v, err
	}

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

	return checks, v, nil
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
	// setup); IDSActive is true once a forward rule sends traffic to NFQUEUE.
	HaveForward bool
	IDSActive   bool
	// Exposed-services section (the merged-in advisor): every live listener run
	// through the simulator against the model.
	Findings []advisor.Finding
	Hidden   []advisor.Finding
	ScanNote string
	Warns    int
	Infos    int
}

func (s *Server) handleHarden(w http.ResponseWriter, r *http.Request) {
	vm := hardenVM{nav: s.navFor(r, "harden")}
	checks, v, err := s.posture()
	if err != nil {
		vm.LoadErr = err.Error()
	} else {
		vm.Checks = checks
		vm.Pass, vm.Total = postureScore(checks)
		vm.HaveModel = v.haveInput
		vm.SSHBanActive = v.any(hasBanRule)
		if fwID, fwRules, ok := s.forwardChain(); ok {
			vm.HaveForward = true
			for _, r := range fwRules {
				if r.Enabled && stmtHas(r, "queue") {
					vm.IDSActive = true
				}
			}
			_ = fwID
		}
	}
	// The exposed-services scan is independent of the posture read; a failure
	// there shouldn't blank the whole page, so it's best-effort.
	if visible, hidden, note, ferr := s.advisorFindings(); ferr == nil {
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
	// Land on the Review page so the armed auto-revert covers the change.
	http.Redirect(w, r, "/changes", http.StatusSeeOther)
}

// hasBanRule reports whether a rule carries a rate-ban (auto-ban) statement.
func hasBanRule(r store.ChainRule) bool { return stmtHas(r, "ban.rate") }

// sshBanSets are the two dynamic sets the SSH auto-ban recipe drops on and bans
// into — one per family.
const (
	sshBanSet4 = "ssh_abusers"
	sshBanSet6 = "ssh_abusers6"
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
	if v.any(hasBanRule) {
		http.Redirect(w, r, "/harden", http.StatusSeeOther)
		return
	}
	// Built in display order; inserted in reverse so they land top-of-chain as:
	// drop-banned (v4, v6) then detect-and-ban (v4, v6), above every existing rule.
	banParams := func(set, family string) map[string]string {
		return map[string]string{"set": set, "family": family, "rate": "10", "per": "minute", "burst": "5", "timeout": "1h"}
	}
	rules := []store.ChainRule{
		{Comment: "drop brute-force-banned sources (IPv4)", Matches: []store.RuleMatch{mt("ip.saddr", "@"+sshBanSet4)}, Statements: []store.RuleStatement{stmt("drop")}},
		{Comment: "drop brute-force-banned sources (IPv6)", Matches: []store.RuleMatch{mt("ip6.saddr", "@"+sshBanSet6)}, Statements: []store.RuleStatement{stmt("drop")}},
		{Comment: "ban sources hammering SSH (IPv4)", Matches: []store.RuleMatch{mt("tcp.dport", "22"), mt("ct.state", "new")}, Statements: []store.RuleStatement{stmtP("ban.rate", banParams(sshBanSet4, "ip"))}},
		{Comment: "ban sources hammering SSH (IPv6)", Matches: []store.RuleMatch{mt("tcp.dport", "22"), mt("ct.state", "new")}, Statements: []store.RuleStatement{stmtP("ban.rate", banParams(sshBanSet6, "ip6"))}},
	}
	for i := len(rules) - 1; i >= 0; i-- {
		rl := rules[i]
		rl.ChainID = v.chainID
		rl.Enabled = true
		if _, err := s.store.CreateChainRuleAtStart(rl); err != nil {
			redirectErr(w, r, "/harden", "Could not add the auto-ban rules: "+err.Error())
			return
		}
	}
	s.audit(r, "enabled SSH brute-force auto-ban")
	http.Redirect(w, r, "/changes", http.StatusSeeOther)
}

// forwardChain returns the first base forward filter chain with its rules — where
// an inline IDS/IPS inspects transit traffic.
func (s *Server) forwardChain() (int64, []store.ChainRule, bool) {
	m, err := s.loadModel()
	if err != nil {
		return 0, nil, false
	}
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
		if rl.Enabled && stmtHas(rl, "queue") {
			http.Redirect(w, r, "/harden", http.StatusSeeOther)
			return
		}
	}
	rule := store.ChainRule{
		ChainID: fwID, Enabled: true,
		Comment:    "inspect transit with an IDS/IPS (fail-open)",
		Statements: []store.RuleStatement{stmtP("queue", map[string]string{"num": "0", "bypass": "bypass"})},
	}
	if _, err := s.store.CreateChainRuleAtStart(rule); err != nil {
		redirectErr(w, r, "/harden", "Could not add the inspection rule: "+err.Error())
		return
	}
	s.audit(r, "enabled IDS/IPS traffic inspection (NFQUEUE)")
	http.Redirect(w, r, "/changes", http.StatusSeeOther)
}
