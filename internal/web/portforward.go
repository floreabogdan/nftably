package web

import (
	"net/http"
	"net/netip"
	"regexp"
	"strings"

	"github.com/floreabogdan/nftably/internal/store"
)

// portforward.go is the port-forward wizard: it turns "expose external tcp/443
// to 192.168.1.10:8443" into the DNAT rule in a nat prerouting chain (creating
// an inet nat table + chain if there isn't one), plus a matching forward-accept
// so the redirected traffic passes a drop-policy forward chain. Model-only —
// the operator reviews and applies it behind the armed auto-revert.

var (
	pfPortRe  = regexp.MustCompile(`^[0-9]{1,5}$`)
	pfIfaceRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
)

func (s *Server) handlePortForward(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	proto := strings.TrimSpace(r.FormValue("proto"))
	extPort := strings.TrimSpace(r.FormValue("ext_port"))
	destHost := strings.TrimSpace(r.FormValue("dest_host"))
	destPort := strings.TrimSpace(r.FormValue("dest_port"))
	iface := strings.TrimSpace(r.FormValue("iface"))

	if proto != "tcp" && proto != "udp" {
		redirectErr(w, r, "/firewall", "Protocol must be tcp or udp.")
		return
	}
	if !pfPortRe.MatchString(extPort) {
		redirectErr(w, r, "/firewall", "External port must be a number.")
		return
	}
	dest, err := netip.ParseAddr(destHost)
	if err != nil {
		redirectErr(w, r, "/firewall", "Destination must be a single internal IP address.")
		return
	}
	if destPort == "" {
		destPort = extPort
	}
	if !pfPortRe.MatchString(destPort) {
		redirectErr(w, r, "/firewall", "Destination port must be a number.")
		return
	}
	if iface != "" && !pfIfaceRe.MatchString(iface) {
		redirectErr(w, r, "/firewall", "Interface name has invalid characters.")
		return
	}

	pre, err := s.natPreroutingChain()
	if err != nil {
		redirectErr(w, r, "/firewall", "Could not prepare the NAT chain: "+err.Error())
		return
	}

	// The DNAT rule: match the incoming port (optionally on one interface) and
	// rewrite the destination to the internal host:port.
	var matches []store.RuleMatch
	if iface != "" {
		matches = append(matches, mt("meta.iifname", iface))
	}
	matches = append(matches, mt(proto+".dport", extPort))
	dnat := stmtP("dnat", map[string]string{"addr": dest.String(), "port": destPort})
	label := "port-forward " + proto + "/" + extPort + " → " + dest.String() + ":" + destPort
	if err := s.addRule(pre, label, matches, []store.RuleStatement{dnat}); err != nil {
		redirectErr(w, r, "/firewall", "Could not add the port-forward rule: "+err.Error())
		return
	}

	// If there's a drop-policy forward filter chain, the redirected packet (now
	// addressed to the internal host) must be accepted there too, or it's dropped
	// after the DNAT. Best-effort: skip silently if there's no such chain.
	if fwd, ok := s.forwardFilterChain(); ok {
		daddrKey := "ip.daddr"
		if dest.Is6() {
			daddrKey = "ip6.daddr"
		}
		_ = s.addRule(fwd, "allow forwarded "+dest.String()+":"+destPort,
			[]store.RuleMatch{mt(daddrKey, dest.String()), mt(proto+".dport", destPort), mt("ct.state", "new")},
			[]store.RuleStatement{stmt("accept")})
	}

	s.audit(r, "added a port forward: "+label)
	http.Redirect(w, r, "/changes", http.StatusSeeOther)
}

// natPreroutingChain returns the id of a base nat prerouting chain, creating an
// inet nat table and chain if the model has none.
func (s *Server) natPreroutingChain() (int64, error) {
	m, err := s.loadModel()
	if err != nil {
		return 0, err
	}
	for _, t := range m.Tables {
		for _, c := range t.Chains {
			if c.IsBase() && c.Hook == "prerouting" && c.ChainType == "nat" {
				return c.ID, nil
			}
		}
	}
	// None — create inet nat / prerouting (reusing an existing inet nat table if
	// one is there without the chain).
	var tableID int64
	for _, t := range m.Tables {
		if t.Family == "inet" && t.Name == "nat" {
			tableID = t.ID
		}
	}
	if tableID == 0 {
		id, err := s.store.CreateTable(store.Table{Family: "inet", Name: "nat", Comment: "NAT (port-forwards / masquerade)"})
		if err != nil {
			return 0, err
		}
		tableID = id
	}
	return s.store.CreateChain(store.Chain{
		TableID: tableID, Name: "prerouting", Kind: "base",
		Hook: "prerouting", ChainType: "nat", Priority: "dstnat", Policy: "accept",
	})
}

// forwardFilterChain returns a base forward filter chain with a drop policy —
// where a forwarded packet needs an explicit accept. false when there's none
// (so an accept-policy or router-less setup doesn't get a redundant rule).
func (s *Server) forwardFilterChain() (int64, bool) {
	m, err := s.loadModel()
	if err != nil {
		return 0, false
	}
	for _, t := range m.Tables {
		for _, c := range t.Chains {
			if c.IsBase() && c.Hook == "forward" && c.ChainType == "filter" && c.Policy == "drop" {
				return c.ID, true
			}
		}
	}
	return 0, false
}
