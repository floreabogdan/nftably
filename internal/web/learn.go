package web

import "net/http"

// learn.go serves the Concepts page: a plain-language guide to how nftables
// actually works — the packet's journey through the hooks, base vs regular
// chains, priority, connection tracking, address families and sets — so someone
// who has never written a firewall rule can understand what the editor is
// building and why the Security check asks for what it does. It's static prose;
// the value is in tying each concept to where you act on it in nftably
// (Simulate, Security check, Firewall, Presets).

type learnVM struct {
	nav
	// HaveModel nudges the closing call-to-action: build-from-preset for a fresh
	// install, review-and-apply once there's a model.
	HaveModel bool
}

func (s *Server) handleLearn(w http.ResponseWriter, r *http.Request) {
	vm := learnVM{nav: s.navFor(r, "learn")}
	if tables, err := s.store.ListTables(); err == nil {
		vm.HaveModel = len(tables) > 0
	}
	render(w, s.log, "learn.html", vm)
}
