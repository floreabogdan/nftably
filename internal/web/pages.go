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
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()
	rules, err := s.store.ListRules()
	if err != nil {
		s.serverError(w, "list rules", err)
		return
	}
	vm := dashboardVM{
		nav:        s.navFor(r, "dashboard"),
		Backend:    nft.Detect(ctx, s.nft),
		Iptables:   nft.ProbeIptables(ctx, s.iptablesSave, s.ip6tablesSave, s.iptablesBin),
		WideOpen:   s.WideOpen(),
		NeedsSetup: len(rules) == 0,
	}
	render(w, s.log, "dashboard.html", vm)
}

// ---- ruleset viewer ----

type rulesetVM struct {
	nav
	NftAvailable bool
	Ruleset      *nft.Ruleset
	Err          string
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

type importVM struct {
	nav
	Report nft.IptablesReport
	Blocks []translateBlock
}

func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := reqCtx(r)
	defer cancel()
	vm := importVM{
		nav:    s.navFor(r, "import"),
		Report: nft.ProbeIptables(ctx, s.iptablesSave, s.ip6tablesSave, s.iptablesBin),
	}
	// Only bother translating when there is actually something to import.
	if vm.Report.V4Rules > 0 {
		b := translateBlock{Family: "IPv4"}
		if txt, err := nft.TranslateIptables(ctx, s.iptablesSave, s.iptablesTranslate); err != nil {
			b.Err = err.Error()
		} else {
			b.Text = txt
		}
		vm.Blocks = append(vm.Blocks, b)
	}
	if vm.Report.V6Rules > 0 {
		b := translateBlock{Family: "IPv6"}
		if txt, err := nft.TranslateIptables(ctx, s.ip6tablesSave, s.ip6tablesTranslate); err != nil {
			b.Err = err.Error()
		} else {
			b.Text = txt
		}
		vm.Blocks = append(vm.Blocks, b)
	}
	render(w, s.log, "import.html", vm)
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
