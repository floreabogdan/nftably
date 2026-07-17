package web

import (
	"net"
	"net/http"
	"strconv"

	"github.com/floreabogdan/nftably/internal/advisor"
)

type suggestionsVM struct {
	nav
	Scan advisor.Scan
	// Current are the live suggestions; Dismissed the ones waved away (still
	// re-derived each scan, so restoring one brings it back with fresh facts).
	Current   []advisor.Suggestion
	Dismissed []advisor.Suggestion
}

// handleSuggestions scans the host and derives advice, fresh on every load —
// the Rescan button is just this page again.
func (s *Server) handleSuggestions(w http.ResponseWriter, r *http.Request) {
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
	dismissed, err := s.store.DismissedSuggestions()
	if err != nil {
		s.serverError(w, "list dismissed", err)
		return
	}

	scan := advisor.Detect()
	vm := suggestionsVM{nav: s.navFor(r, "suggestions"), Scan: scan}
	for _, sug := range advisor.Suggest(scan, fw, rules, s.ownListenPort()) {
		if dismissed[sug.Key] {
			vm.Dismissed = append(vm.Dismissed, sug)
		} else {
			vm.Current = append(vm.Current, sug)
		}
	}
	render(w, s.log, "suggestions.html", vm)
}

func (s *Server) handleSuggestionDismiss(w http.ResponseWriter, r *http.Request) {
	s.suggestionMark(w, r, s.store.DismissSuggestion)
}

func (s *Server) handleSuggestionRestore(w http.ResponseWriter, r *http.Request) {
	s.suggestionMark(w, r, s.store.RestoreSuggestion)
}

func (s *Server) suggestionMark(w http.ResponseWriter, r *http.Request, op func(string) error) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	key := r.FormValue("key")
	if key == "" || len(key) > 128 {
		http.Error(w, "bad key", http.StatusBadRequest)
		return
	}
	if err := op(key); err != nil {
		s.serverError(w, "update suggestion", err)
		return
	}
	http.Redirect(w, r, "/suggestions", http.StatusSeeOther)
}

// ownListenPort is nftably's port for the advisor: its own listener should not
// be reported as an unknown service. 0 when loopback-bound or unparsable.
func (s *Server) ownListenPort() int {
	host, portStr, err := net.SplitHostPort(s.listenAddr)
	if err != nil {
		return 0
	}
	_ = host
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0
	}
	return port
}
