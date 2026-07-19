package web

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/floreabogdan/nftably/internal/nft"
)

// reqCtx bounds a handler's nft calls so a wedged nft never hangs a page.
func reqCtx(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), 20*time.Second)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

// apiStatus backs the top bar's nft connection dot: is nft installed and can we
// read netfilter (i.e. do we have CAP_NET_ADMIN).
func (s *Server) apiStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()
	available := s.nft.Available()
	rulesetOK := available && s.nft.Ping(ctx) == nil
	writeJSON(w, map[string]any{"nftAvailable": available, "rulesetOK": rulesetOK})
}

// ---- dashboard ----

type dashboardVM struct {
	nav
	Backend  nft.Backend
	Iptables nft.IptablesReport
	WideOpen bool
	// NeedsSetup nudges a fresh install towards the guided setup: no rules
	// modelled yet means nftably is not managing anything.
	NeedsSetup bool
	// Posture summary — a compact score linking to the full Posture page.
	PostureShow  bool
	PosturePass  int
	PostureTotal int
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()
	tables, err := s.store.ListTables()
	if err != nil {
		s.serverError(w, "list tables", err)
		return
	}
	vm := dashboardVM{
		nav:        s.navFor(r, "dashboard"),
		Backend:    nft.Detect(ctx, s.nft),
		Iptables:   nft.ProbeIptables(ctx, s.iptablesSave, s.ip6tablesSave, s.iptablesBin),
		WideOpen:   s.WideOpen(),
		NeedsSetup: len(tables) == 0,
	}
	// A compact posture score, when there's a model to grade.
	if len(tables) > 0 {
		if checks, _, err := s.posture(); err == nil {
			vm.PostureShow = true
			vm.PosturePass, vm.PostureTotal = postureScore(checks)
		}
	}
	render(w, s.log, "dashboard.html", vm)
}

// ---- ruleset viewer ----

type rulesetVM struct {
	nav
	NftAvailable bool
	Ruleset      *nft.Ruleset
	Err          string
	// Managed keys ("<family> <name>") the tables nftably owns, so the live view
	// can flag which tables are ours versus loaded by something else.
	Managed map[string]bool
}

func (s *Server) handleRuleset(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()
	vm := rulesetVM{nav: s.navFor(r, "ruleset"), NftAvailable: s.nft.Available()}
	if vm.NftAvailable {
		rs, err := s.nft.Ruleset(ctx)
		if err != nil {
			vm.Err = err.Error()
		} else {
			vm.Ruleset = rs
		}
	}
	// Which live tables are nftably's own (best-effort — a read failure just means
	// nothing is flagged as managed).
	vm.Managed = map[string]bool{}
	if tables, err := s.store.ListTables(); err == nil {
		for _, t := range tables {
			vm.Managed[t.Family+" "+t.Name] = true
		}
	}
	render(w, s.log, "ruleset.html", vm)
}

type rawVM struct {
	nav
	Raw string
	Err string
}

func (s *Server) handleRawRuleset(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()
	vm := rawVM{nav: s.navFor(r, "ruleset")}
	if !s.nft.Available() {
		vm.Err = "nft is not installed on this host"
	} else if raw, err := s.nft.RawRuleset(ctx); err != nil {
		vm.Err = err.Error()
	} else {
		vm.Raw = raw
	}
	render(w, s.log, "raw.html", vm)
}

// ---- iptables import preview ----

type translateBlock struct {
	Family string
	Text   string
	Err    string
}

// handleImport redirects the retired standalone /import page to its new home, a
// tab on the Settings page.
func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/settings?tab=import", http.StatusMovedPermanently)
}

// ---- timeline ----

type timelineVM struct {
	nav
	Events []timelineEvent
}

type timelineEvent struct {
	Ts      time.Time
	Kind    string
	Actor   string
	Message string
}

func (s *Server) handleTimeline(w http.ResponseWriter, r *http.Request) {
	events, err := s.store.ListEvents(200, 0)
	if err != nil {
		s.serverError(w, "list events", err)
		return
	}
	vm := timelineVM{nav: s.navFor(r, "timeline")}
	for _, e := range events {
		vm.Events = append(vm.Events, timelineEvent{Ts: e.Ts, Kind: e.Kind, Actor: e.Actor, Message: e.Message})
	}
	render(w, s.log, "timeline.html", vm)
}
