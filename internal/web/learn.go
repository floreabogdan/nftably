package web

import "net/http"

// learn.go serves the Learn section: a set of plain-language lessons that teach
// nftables and how to apply it in nftably. Concepts covers the fundamentals (the
// packet's journey, chains, connection tracking, sets); the sibling lessons go
// wider (NAT & port-forwarding) and more task-oriented (a recipe cookbook,
// troubleshooting, and a guide for people arriving from iptables). All static
// prose; the value is tying each idea to where you act on it (Simulate, Firewall,
// Presets, the importer).

type learnVM struct {
	nav
	// HaveModel nudges the closing call-to-action: build-from-preset for a fresh
	// install, review-and-apply once there's a model.
	HaveModel bool
}

// renderLearn builds the shared lesson view (nav highlight + model-aware CTA) and
// renders one lesson template.
func (s *Server) renderLearn(w http.ResponseWriter, r *http.Request, active, tmpl string) {
	vm := learnVM{nav: s.navFor(r, active)}
	if tables, err := s.store.ListTables(); err == nil {
		vm.HaveModel = len(tables) > 0
	}
	render(w, s.log, tmpl, vm)
}

func (s *Server) handleLearn(w http.ResponseWriter, r *http.Request) {
	s.renderLearn(w, r, "learn", "learn.html")
}

func (s *Server) handleLearnNAT(w http.ResponseWriter, r *http.Request) {
	s.renderLearn(w, r, "learn-nat", "learn_nat.html")
}

func (s *Server) handleLearnRecipes(w http.ResponseWriter, r *http.Request) {
	s.renderLearn(w, r, "learn-recipes", "learn_recipes.html")
}

func (s *Server) handleLearnTroubleshoot(w http.ResponseWriter, r *http.Request) {
	s.renderLearn(w, r, "learn-troubleshoot", "learn_troubleshoot.html")
}

func (s *Server) handleLearnIptables(w http.ResponseWriter, r *http.Request) {
	s.renderLearn(w, r, "learn-iptables", "learn_iptables.html")
}
