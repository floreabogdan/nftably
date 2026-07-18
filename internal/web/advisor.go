package web

import (
	"fmt"
	"net"
	"net/http"
	"strconv"

	"github.com/floreabogdan/nftably/internal/advisor"
	"github.com/floreabogdan/nftably/internal/store"
)

// This file is the /advisor surface: it scans the box's listening sockets and
// routing, runs each exposure through the packet simulator against the current
// model, and reports what the firewall actually does about it — with a one-click
// fix or a link into the simulator. Findings are advice; nothing changes the
// kernel here (a one-click "allow" only adds a rule to the model, for review).

type advisorVM struct {
	nav
	Findings []advisor.Finding
	Hidden   []advisor.Finding
	Note     string // scan limitation (e.g. listener scanning needs Linux)
	Warns    int
	Infos    int
}

func (s *Server) handleAdvisor(w http.ResponseWriter, r *http.Request) {
	m, err := s.loadModel()
	if err != nil {
		s.serverError(w, "load model", err)
		return
	}
	scan := advisor.Detect()
	findings := advisor.Analyze(scan, m, advisor.Options{
		ListenPort: listenPortOf(s.listenAddr),
		ExternalIf: firstNonLoopbackIface(),
	})
	dismissed, err := s.store.DismissedSuggestions()
	if err != nil {
		s.serverError(w, "list dismissed", err)
		return
	}
	visible, hidden := advisor.Filter(findings, dismissed)

	vm := advisorVM{nav: s.navFor(r, "advisor"), Findings: visible, Hidden: hidden, Note: scan.Note}
	for _, f := range visible {
		if f.Severity == "warn" {
			vm.Warns++
		} else {
			vm.Infos++
		}
	}
	render(w, s.log, "advisor.html", vm)
}

// handleAdvisorAllow takes a blocked-listener finding's one-click fix: it adds an
// accept rule for that port to the primary input chain and sends the operator to
// Review & apply. It only touches the model — the armed apply still gates the
// kernel.
func (s *Server) handleAdvisorAllow(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	proto := r.FormValue("proto")
	port, _ := strconv.Atoi(r.FormValue("port"))
	if (proto != "tcp" && proto != "udp") || port < 1 || port > 65535 {
		redirectErr(w, r, "/advisor", "That service can't be allowed automatically.")
		return
	}
	chainID, ok := s.primaryInputChainID()
	if !ok {
		redirectErr(w, r, "/advisor", "There's no input chain to add a rule to — apply a preset first, then try again.")
		return
	}
	rule := store.ChainRule{
		ChainID:    chainID,
		Enabled:    true,
		Comment:    fmt.Sprintf("allow %s/%d (added by advisor)", proto, port),
		Matches:    []store.RuleMatch{{Key: proto + ".dport", Op: "==", Value: strconv.Itoa(port)}},
		Statements: []store.RuleStatement{{Key: "accept", Params: "{}"}},
	}
	if _, err := s.store.CreateChainRule(rule); err != nil {
		redirectErr(w, r, "/advisor", "Could not add the rule: "+err.Error())
		return
	}
	s.audit(r, fmt.Sprintf("advisor: added accept rule for %s/%d", proto, port))
	http.Redirect(w, r, "/changes", http.StatusSeeOther)
}

func (s *Server) handleAdvisorDismiss(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if key := r.FormValue("key"); key != "" {
		if err := s.store.DismissSuggestion(key); err != nil {
			s.log.Warn("dismiss finding failed", "error", err)
		}
	}
	http.Redirect(w, r, "/advisor", http.StatusSeeOther)
}

func (s *Server) handleAdvisorRestore(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if key := r.FormValue("key"); key != "" {
		if err := s.store.RestoreSuggestion(key); err != nil {
			s.log.Warn("restore finding failed", "error", err)
		}
	}
	http.Redirect(w, r, "/advisor", http.StatusSeeOther)
}

// primaryInputChainID returns the id of the first base input filter chain, the
// natural place to add an inbound accept rule.
func (s *Server) primaryInputChainID() (int64, bool) {
	m, err := s.loadModel()
	if err != nil {
		return 0, false
	}
	for _, t := range m.Tables {
		for _, c := range t.Chains {
			if c.IsBase() && c.Hook == "input" && c.ChainType != "nat" {
				return c.ID, true
			}
		}
	}
	return 0, false
}

// listenPortOf extracts the TCP port from a listen address like ":8080" or
// "0.0.0.0:8080"; 0 when it cannot be determined.
func listenPortOf(addr string) int {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(portStr)
	return n
}

// firstNonLoopbackIface returns a non-loopback interface name to trace an
// "arriving from outside" packet on, or "" when none is found (the simulator
// then treats the interface as unspecified).
func firstNonLoopbackIface() string {
	ifs, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback == 0 && i.Flags&net.FlagUp != 0 {
			return i.Name
		}
	}
	return ""
}
