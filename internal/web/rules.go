package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	nftconf "github.com/floreabogdan/nftably/internal/render"
	"github.com/floreabogdan/nftably/internal/store"
)

type rulesVM struct {
	nav
	Rules    []store.Rule
	Firewall store.Firewall
	Saved    bool
}

func (s *Server) handleRulesList(w http.ResponseWriter, r *http.Request) {
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
	render(w, s.log, "rules.html", rulesVM{
		nav:      s.navFor(r, "rules"),
		Rules:    rules,
		Firewall: fw,
		Saved:    r.URL.Query().Get("saved") == "1",
	})
}

type ruleFormVM struct {
	nav
	Rule   store.Rule
	IsNew  bool
	Errors []string
	// Preview is the nft syntax the rule renders to, shown under the form after
	// a failed submit and on edit — the operator sees exactly what M3 will load.
	Preview []string
}

func (s *Server) handleRuleNew(w http.ResponseWriter, r *http.Request) {
	render(w, s.log, "rule_form.html", ruleFormVM{
		nav:   s.navFor(r, "rules"),
		Rule:  store.Rule{Action: "accept", Proto: "tcp", Enabled: true},
		IsNew: true,
	})
}

func (s *Server) handleRuleEdit(w http.ResponseWriter, r *http.Request) {
	rule, ok := s.ruleFromPath(w, r)
	if !ok {
		return
	}
	render(w, s.log, "rule_form.html", ruleFormVM{
		nav:     s.navFor(r, "rules"),
		Rule:    rule,
		Preview: nftconf.RuleLines(rule),
	})
}

// handleRuleSave backs both the new form and the edit form: the path with an
// {id} updates, the one without creates.
func (s *Server) handleRuleSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	isNew := r.PathValue("id") == ""
	rule := store.Rule{
		Name:    strings.TrimSpace(r.FormValue("name")),
		Action:  r.FormValue("action"),
		Proto:   r.FormValue("proto"),
		DPorts:  strings.TrimSpace(r.FormValue("dports")),
		SAddrs:  strings.TrimSpace(r.FormValue("saddrs")),
		IIf:     strings.TrimSpace(r.FormValue("iif")),
		Enabled: r.FormValue("enabled") == "on",
	}
	if !isNew {
		existing, ok := s.ruleFromPath(w, r)
		if !ok {
			return
		}
		rule.ID = existing.ID
		rule.Position = existing.Position
	}

	if errs := rule.Validate(); len(errs) > 0 {
		render(w, s.log, "rule_form.html", ruleFormVM{
			nav:    s.navFor(r, "rules"),
			Rule:   rule,
			IsNew:  isNew,
			Errors: errs,
		})
		return
	}

	if isNew {
		if _, err := s.store.CreateRule(rule); err != nil {
			s.serverError(w, "create rule", err)
			return
		}
		s.audit(r, fmt.Sprintf("added rule %q", rule.Name))
	} else {
		if err := s.store.UpdateRule(rule); err != nil {
			s.serverError(w, "update rule", err)
			return
		}
		s.audit(r, fmt.Sprintf("edited rule %q", rule.Name))
	}
	http.Redirect(w, r, "/rules?saved=1", http.StatusSeeOther)
}

func (s *Server) handleRuleDelete(w http.ResponseWriter, r *http.Request) {
	rule, ok := s.ruleFromPath(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteRule(rule.ID); err != nil {
		s.serverError(w, "delete rule", err)
		return
	}
	s.audit(r, fmt.Sprintf("deleted rule %q", rule.Name))
	http.Redirect(w, r, "/rules", http.StatusSeeOther)
}

func (s *Server) handleRuleToggle(w http.ResponseWriter, r *http.Request) {
	rule, ok := s.ruleFromPath(w, r)
	if !ok {
		return
	}
	if err := s.store.SetRuleEnabled(rule.ID, !rule.Enabled); err != nil {
		s.serverError(w, "toggle rule", err)
		return
	}
	verb := "enabled"
	if rule.Enabled {
		verb = "disabled"
	}
	s.audit(r, fmt.Sprintf("%s rule %q", verb, rule.Name))
	http.Redirect(w, r, "/rules", http.StatusSeeOther)
}

func (s *Server) handleRuleMove(w http.ResponseWriter, r *http.Request) {
	rule, ok := s.ruleFromPath(w, r)
	if !ok {
		return
	}
	dir := 1
	if r.FormValue("dir") == "up" {
		dir = -1
	}
	if err := s.store.MoveRule(rule.ID, dir); err != nil {
		s.serverError(w, "move rule", err)
		return
	}
	http.Redirect(w, r, "/rules", http.StatusSeeOther)
}

func (s *Server) handleRulesPolicy(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	policy := r.FormValue("input_policy")
	if err := s.store.SaveFirewall(store.Firewall{InputPolicy: policy}); err != nil {
		http.Error(w, "input policy must be drop or accept", http.StatusBadRequest)
		return
	}
	s.audit(r, "set input policy to "+policy)
	http.Redirect(w, r, "/rules?saved=1", http.StatusSeeOther)
}

// ruleFromPath resolves the {id} path value to a rule, writing the right
// response and returning ok=false when the handler must stop.
func (s *Server) ruleFromPath(w http.ResponseWriter, r *http.Request) (store.Rule, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return store.Rule{}, false
	}
	rule, err := s.store.GetRule(id)
	if err == store.ErrNotFound {
		http.NotFound(w, r)
		return store.Rule{}, false
	}
	if err != nil {
		s.serverError(w, "get rule", err)
		return store.Rule{}, false
	}
	return rule, true
}

// audit records an operator's model change on the timeline. Best-effort: a
// failed audit write is logged, never surfaced to the operator.
func (s *Server) audit(r *http.Request, message string) {
	if err := s.store.InsertAudit(s.currentUser(r).Username, store.EventModelChange, message); err != nil {
		s.log.Warn("audit write failed", "error", err)
	}
}
