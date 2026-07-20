package web

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/floreabogdan/nftably/internal/nft"
	"github.com/floreabogdan/nftably/internal/nftcat"
	nftconf "github.com/floreabogdan/nftably/internal/render"
	"github.com/floreabogdan/nftably/internal/store"
)

// This file is the /firewall surface: the owned object graph (tables → chains →
// rules) and the catalogue-driven, explained rule editor. Everything here is
// model-only — /changes renders it, diffs it and applies it with the armed
// auto-revert. Nothing writes to netfilter directly.

const (
	maxConds = 8 // condition rows a rule form offers
	maxActs  = 6 // action rows a rule form offers
)

// paramKeys is the union of every statement parameter, so one fixed set of
// inputs on the action row can feed any statement; RenderStatement reads only
// the keys its statement needs and ignores the rest.
var paramKeys = []string{
	"target", "addr", "port", "with", "prefix", "level", "rate", "per", "burst", "value",
	"mss", "wscale", "size", "dir", "amount", "unit", "num", "bypass", "name", "group",
	"lmode", "lunit", "vmapkey", "vmapentries", "cname", "ft",
}

// ── overview ────────────────────────────────────────────────────────────────

type fwVM struct {
	nav
	Tables    []fwTable
	Families  []string
	Saved     bool
	Err       string
	Preset    string   // name of a just-applied preset, for the confirmation banner
	LintWarns []string // lockout/footgun warnings, surfaced here as well as on /changes
}

type fwTable struct {
	store.Table
	Chains     []fwChain
	Flowtables []store.Flowtable
}

type fwChain struct {
	store.Chain
	HookLine string
	Rules    []fwRule
}

type fwRule struct {
	store.ChainRule
	Preview   string
	RenderErr string
	// Live counters, present when the rule carries a `counter` action, nft is
	// reachable, and the applied ruleset lines up with the model.
	HasCounter bool
	Packets    string
	Bytes      string
}

func (s *Server) handleFirewall(w http.ResponseWriter, r *http.Request) {
	m, err := s.loadModel()
	if err != nil {
		s.serverError(w, "load model", err)
		return
	}
	vm := fwVM{
		nav:       s.navFor(r, "firewall"),
		Families:  []string{"inet", "ip", "ip6", "arp", "bridge", "netdev"},
		Saved:     r.URL.Query().Get("saved") == "1",
		Err:       r.URL.Query().Get("err"),
		LintWarns: append(nftconf.Lint(m, s.listenAddr), s.simulatedLockoutWarnings(r, m)...),
	}
	if key := r.URL.Query().Get("preset"); key != "" {
		if p, ok := s.presetByKey(key); ok {
			vm.Preset = p.Name
		}
	}
	// Live counters come from the kernel and line up with the model by position —
	// which only holds when the model still renders to exactly what's applied.
	// Reading them for a model with unapplied edits (a reorder in particular)
	// would attach the running config's counts to the wrong rows, so gate on sync.
	var counters map[string]map[string][]nft.RuleCounter
	if s.modelInSyncWithApplied(m) {
		counters = s.readCounters(r.Context(), m)
	}
	for _, t := range m.Tables {
		ft := fwTable{Table: t.Table, Flowtables: t.Flowtables}
		tblCounters := counters[t.Family+"/"+t.Name]
		for _, c := range t.Chains {
			fc := fwChain{Chain: c.Chain, HookLine: hookLine(c.Chain)}
			// The kernel holds only enabled rules, in model order, so counters
			// line up with the enabled model rules by position — but only when the
			// counts match (i.e. the model has not drifted from what's applied).
			chainCounters := tblCounters[c.Name]
			enabled := 0
			for _, rr := range c.Rules {
				if rr.Enabled {
					enabled++
				}
			}
			aligned := chainCounters != nil && len(chainCounters) == enabled
			ei := 0
			for _, rule := range c.Rules {
				fr := fwRule{ChainRule: rule}
				if line, err := nftconf.RenderRule(t.Family, rule); err != nil {
					fr.RenderErr = err.Error()
				} else {
					fr.Preview = line
				}
				if rule.Enabled {
					if aligned && ei < len(chainCounters) && chainCounters[ei].Present {
						rc := chainCounters[ei]
						fr.HasCounter = true
						fr.Packets = humanCount(rc.Packets)
						fr.Bytes = humanBytes(rc.Bytes)
					}
					ei++
				}
				fc.Rules = append(fc.Rules, fr)
			}
			ft.Chains = append(ft.Chains, fc)
		}
		vm.Tables = append(vm.Tables, ft)
	}
	render(w, s.log, "firewall.html", vm)
}

// modelInSyncWithApplied reports whether the current model renders to exactly the
// config nftably last loaded into the kernel — the condition under which the live
// per-rule counters line up with the model by position.
func (s *Server) modelInSyncWithApplied(m nftconf.Model) bool {
	applied, ok, err := s.store.LatestAppliedConfig()
	if err != nil || !ok {
		return false
	}
	return applied == nftconf.Config(m)
}

// readCounters reads the live per-rule counters for every owned table, keyed by
// "family/name" → chain → ordered counters. It is best-effort: no nft, a table
// not yet applied, or a read error simply yields no counters for that table, and
// the page renders without them.
func (s *Server) readCounters(ctx context.Context, m nftconf.Model) map[string]map[string][]nft.RuleCounter {
	if !s.nft.Available() {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out := map[string]map[string][]nft.RuleCounter{}
	for _, t := range m.Tables {
		if cc, exists, err := s.nft.TableCounters(ctx, t.Family, t.Name); err == nil && exists {
			out[t.Family+"/"+t.Name] = cc
		}
	}
	return out
}

// humanCount formats a packet count with thousands separators.
func humanCount(n uint64) string {
	s := strconv.FormatUint(n, 10)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	pre := len(s) % 3
	if pre > 0 {
		b.WriteString(s[:pre])
	}
	for i := pre; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s[i : i+3])
	}
	return b.String()
}

// humanBytes formats a byte count in binary units (B, KiB→"KB", …).
func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// hookLine is the human summary shown under a base chain's name.
func hookLine(c store.Chain) string {
	if !c.IsBase() {
		return "regular chain — reached only by jump/goto"
	}
	line := "hook " + c.Hook + " · " + c.ChainType + " · priority " + c.Priority
	if c.Device != "" {
		line += " · device " + c.Device
	}
	if c.Policy != "" {
		line += " · policy " + c.Policy
	}
	return line
}

// ── table CRUD ──────────────────────────────────────────────────────────────

func (s *Server) handleTableCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	t := store.Table{
		Family:  strings.TrimSpace(r.FormValue("family")),
		Name:    strings.TrimSpace(r.FormValue("name")),
		Comment: strings.TrimSpace(r.FormValue("comment")),
	}
	if errs := t.Validate(); len(errs) > 0 {
		redirectErr(w, r, "/firewall", errs[0])
		return
	}
	if _, err := s.store.CreateTable(t); err != nil {
		redirectErr(w, r, "/firewall", "Could not create table: "+err.Error())
		return
	}
	s.audit(r, "created table "+t.Family+" "+t.Name)
	http.Redirect(w, r, "/firewall?saved=1", http.StatusSeeOther)
}

func (s *Server) handleTableDelete(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	if err := s.store.DeleteTable(id); err != nil {
		redirectErr(w, r, "/firewall", "Could not delete table: "+err.Error())
		return
	}
	s.audit(r, "deleted a table")
	http.Redirect(w, r, "/firewall?saved=1", http.StatusSeeOther)
}

func (s *Server) handleTableMove(w http.ResponseWriter, r *http.Request) {
	_ = s.store.MoveTable(pathID(r), moveDir(r))
	http.Redirect(w, r, "/firewall", http.StatusSeeOther)
}

// ── chain CRUD ──────────────────────────────────────────────────────────────

type chainFormVM struct {
	nav
	Chain  store.Chain
	Table  store.Table
	IsNew  bool
	Errors []string
	Hooks  []string
	Types  []string
}

func (s *Server) handleChainNew(w http.ResponseWriter, r *http.Request) {
	t, err := s.store.GetTable(pathID(r))
	if err != nil {
		s.notFoundOr(w, err)
		return
	}
	s.chainForm(w, r, chainFormVM{
		Table: t,
		Chain: store.Chain{TableID: t.ID, Kind: "base", ChainType: "filter", Priority: "filter", Policy: "accept"},
		IsNew: true,
	})
}

func (s *Server) handleChainEdit(w http.ResponseWriter, r *http.Request) {
	c, err := s.store.GetChain(pathID(r))
	if err != nil {
		s.notFoundOr(w, err)
		return
	}
	t, err := s.store.GetTable(c.TableID)
	if err != nil {
		s.serverError(w, "get table", err)
		return
	}
	s.chainForm(w, r, chainFormVM{Table: t, Chain: c})
}

func (s *Server) chainForm(w http.ResponseWriter, r *http.Request, vm chainFormVM) {
	vm.nav = s.navFor(r, "firewall")
	vm.Hooks = []string{"input", "output", "forward", "prerouting", "postrouting", "ingress", "egress"}
	vm.Types = []string{"filter", "nat", "route"}
	render(w, s.log, "chain_form.html", vm)
}

func (s *Server) handleChainSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	isNew := r.PathValue("id") == "" || r.URL.Query().Get("new") == "1"

	var c store.Chain
	var table store.Table
	if isNew {
		tid, _ := strconv.ParseInt(r.FormValue("table_id"), 10, 64)
		t, err := s.store.GetTable(tid)
		if err != nil {
			s.notFoundOr(w, err)
			return
		}
		table = t
		c.TableID = t.ID
	} else {
		existing, err := s.store.GetChain(pathID(r))
		if err != nil {
			s.notFoundOr(w, err)
			return
		}
		c = existing
		if t, err := s.store.GetTable(c.TableID); err == nil {
			table = t
		}
	}

	c.Name = strings.TrimSpace(r.FormValue("name"))
	c.Kind = r.FormValue("kind")
	c.Hook = r.FormValue("hook")
	c.ChainType = r.FormValue("chain_type")
	c.Priority = strings.TrimSpace(r.FormValue("priority"))
	c.Policy = r.FormValue("policy")
	c.Device = strings.TrimSpace(r.FormValue("device"))

	if errs := c.Validate(); len(errs) > 0 {
		s.chainForm(w, r, chainFormVM{Table: table, Chain: c, IsNew: isNew, Errors: errs})
		return
	}
	var err error
	if isNew {
		_, err = s.store.CreateChain(c)
	} else {
		err = s.store.UpdateChain(c)
	}
	if err != nil {
		s.chainForm(w, r, chainFormVM{Table: table, Chain: c, IsNew: isNew, Errors: []string{err.Error()}})
		return
	}
	s.audit(r, "saved chain "+c.Name)
	http.Redirect(w, r, "/firewall?saved=1", http.StatusSeeOther)
}

func (s *Server) handleChainDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteChain(pathID(r)); err != nil {
		redirectErr(w, r, "/firewall", "Could not delete chain: "+err.Error())
		return
	}
	s.audit(r, "deleted a chain")
	http.Redirect(w, r, "/firewall?saved=1", http.StatusSeeOther)
}

func (s *Server) handleChainMove(w http.ResponseWriter, r *http.Request) {
	_ = s.store.MoveChain(pathID(r), moveDir(r))
	http.Redirect(w, r, "/firewall", http.StatusSeeOther)
}

// ── rule editor ─────────────────────────────────────────────────────────────

type condRow struct {
	Field string
	Op    string
	Value string
}

type actRow struct {
	Key    string
	Params map[string]string
}

type ruleFormVM struct {
	nav
	Chain           store.Chain
	Chains          []store.Chain // sibling chains in the same table, for the "move to chain" selector
	Table           store.Table
	RuleID          int64
	Comment         string
	Enabled         bool
	Raw             string // verbatim nft line (advanced escape hatch); empty for a structured rule
	Tags            string // comma-separated freeform labels
	IsNew           bool
	Errors          []string
	Preview         string
	Conds           []condRow
	Acts            []actRow
	MatchGroups     []nftcat.MatchGroup
	StatementGroups []nftcat.StatementGroup
	ParamKeys       []string
	Ops             []string
	// CatalogueJSON is the per-knob help/example/options metadata, embedded in
	// the page for firewall.js to annotate the form as the operator builds a rule.
	CatalogueJSON template.JS
	// PageDataJSON carries the box's real interfaces, this table's named sets and
	// its chain names, so the editor can offer them as choices instead of asking
	// the operator to type identifiers blind.
	PageDataJSON template.JS
}

func (s *Server) handleRuleNew(w http.ResponseWriter, r *http.Request) {
	c, err := s.store.GetChain(pathID(r))
	if err != nil {
		s.notFoundOr(w, err)
		return
	}
	vm := ruleFormVM{Chain: c, IsNew: true, Enabled: true}
	// Seed one empty condition and one accept action so the form is inviting.
	vm.Conds = padConds(nil)
	vm.Acts = padActs([]actRow{{Key: "accept", Params: map[string]string{}}})
	s.ruleForm(w, r, vm)
}

func (s *Server) handleRuleEditGet(w http.ResponseWriter, r *http.Request) {
	rule, err := s.store.GetChainRule(pathID(r))
	if err != nil {
		s.notFoundOr(w, err)
		return
	}
	c, err := s.store.GetChain(rule.ChainID)
	if err != nil {
		s.serverError(w, "get chain", err)
		return
	}
	vm := ruleFormVM{
		Chain:   c,
		RuleID:  rule.ID,
		Comment: rule.Comment,
		Enabled: rule.Enabled,
		Raw:     rule.Raw,
		Tags:    rule.Tags,
	}
	for _, m := range rule.Matches {
		vm.Conds = append(vm.Conds, condRow{Field: m.Key, Op: m.Op, Value: m.Value})
	}
	vm.Conds = padConds(vm.Conds)
	for _, st := range rule.Statements {
		vm.Acts = append(vm.Acts, actRow{Key: st.Key, Params: nftconf.DecodeParams(st.Params)})
	}
	vm.Acts = padActs(vm.Acts)
	s.ruleForm(w, r, vm)
}

func (s *Server) ruleForm(w http.ResponseWriter, r *http.Request, vm ruleFormVM) {
	vm.nav = s.navFor(r, "firewall")
	if t, err := s.store.GetTable(vm.Chain.TableID); err == nil {
		vm.Table = t
	}
	// Sibling chains in this table power the editor's chain selector — a rule can
	// be moved (or, when new, placed) into any chain of the same table, keeping
	// the rendered family compatible.
	if chains, err := s.store.ListChains(vm.Chain.TableID); err == nil {
		vm.Chains = chains
	}
	vm.MatchGroups = nftcat.MatchGroups()
	vm.StatementGroups = nftcat.StatementGroups()
	vm.ParamKeys = paramKeys
	vm.Ops = []string{"==", "!=", "<", ">", "<=", ">="}
	vm.CatalogueJSON = template.JS(nftcat.CatalogueJSON())
	vm.PageDataJSON = template.JS(s.rulePageData(vm.Chain))

	// A live preview of what the rule renders to, best-effort.
	rule := ruleFromForm(vm)
	if line, err := nftconf.RenderRule(vm.Table.Family, rule); err == nil {
		vm.Preview = line
	}
	render(w, s.log, "rule_form.html", vm)
}

// rulePageData is the JSON the editor uses to offer real choices: the box's
// interfaces (for iifname/oifname), the named sets a rule can reference, the
// sibling chains a jump/goto can target, and the flowtables in this table a
// `flow add` can offload into.
func (s *Server) rulePageData(chain store.Chain) string {
	var setNames []string
	if lists, err := s.store.ListLists(); err == nil {
		for _, l := range lists {
			setNames = append(setNames, l.Name)
		}
	}
	var chainNames []string
	var flowtableNames []string
	if chain.TableID != 0 {
		if chains, err := s.store.ListChains(chain.TableID); err == nil {
			for _, c := range chains {
				if c.ID != chain.ID { // a chain cannot jump to itself
					chainNames = append(chainNames, c.Name)
				}
			}
		}
		// A flow action can only offload into a flowtable in its own table.
		if fts, err := s.store.AllFlowtables(); err == nil {
			for _, f := range fts[chain.TableID] {
				flowtableNames = append(flowtableNames, f.Name)
			}
		}
	}
	b, err := json.Marshal(map[string]any{
		"interfaces": hostInterfaces(),
		"sets":       setNames,
		"chains":     chainNames,
		"flowtables": flowtableNames,
	})
	if err != nil {
		return "{}"
	}
	return string(b)
}

// hostInterfaces lists the network interface names on the box, so the editor can
// offer them for iifname/oifname instead of a blind text field. In production
// (host network namespace) these are the router's real interfaces; in a bridged
// container they are the container's — either way, the ones nft will see.
func hostInterfaces() []string {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(ifs))
	for _, i := range ifs {
		out = append(out, i.Name)
	}
	sort.Strings(out)
	return out
}

// ruleFromForm builds a ChainRule from the form view-model's rows (dropping
// empty ones), for both preview and save.
// tagCleanRe strips anything but letters, digits, space, dash and underscore
// from a tag, so tags stay display-safe.
var tagCleanRe = regexp.MustCompile(`[^a-zA-Z0-9 _-]`)

// normalizeTags trims, de-dupes and bounds a comma-separated tag string.
func normalizeTags(raw string) string {
	seen := map[string]bool{}
	var out []string
	for _, t := range strings.Split(raw, ",") {
		t = tagCleanRe.ReplaceAllString(strings.TrimSpace(t), "")
		if len(t) > 32 {
			t = strings.TrimSpace(t[:32])
		}
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
		if len(out) >= 12 {
			break
		}
	}
	return strings.Join(out, ", ")
}

func ruleFromForm(vm ruleFormVM) store.ChainRule {
	rule := store.ChainRule{ID: vm.RuleID, ChainID: vm.Chain.ID, Comment: vm.Comment, Enabled: vm.Enabled, Tags: normalizeTags(vm.Tags)}
	// A raw rule is verbatim: its structured conditions/actions are ignored.
	if raw := strings.TrimSpace(vm.Raw); raw != "" {
		rule.Raw = raw
		return rule
	}
	for _, c := range vm.Conds {
		if strings.TrimSpace(c.Field) == "" {
			continue
		}
		op := c.Op
		if op == "" {
			op = "=="
		}
		rule.Matches = append(rule.Matches, store.RuleMatch{Key: c.Field, Op: op, Value: strings.TrimSpace(c.Value)})
	}
	for _, a := range vm.Acts {
		if strings.TrimSpace(a.Key) == "" {
			continue
		}
		rule.Statements = append(rule.Statements, store.RuleStatement{Key: a.Key, Params: nftconf.EncodeParams(a.Params)})
	}
	return rule
}

func (s *Server) handleRuleSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	isNew := r.URL.Query().Get("new") == "1" || strings.Contains(r.URL.Path, "/rules/new")

	var chain store.Chain
	var ruleID int64
	if isNew {
		c, err := s.store.GetChain(pathID(r))
		if err != nil {
			s.notFoundOr(w, err)
			return
		}
		chain = c
	} else {
		ruleID = pathID(r)
		existing, err := s.store.GetChainRule(ruleID)
		if err != nil {
			s.notFoundOr(w, err)
			return
		}
		c, err := s.store.GetChain(existing.ChainID)
		if err != nil {
			s.serverError(w, "get chain", err)
			return
		}
		chain = c
	}

	vm := ruleFormVM{
		Chain:   chain,
		RuleID:  ruleID,
		IsNew:   isNew,
		Comment: strings.TrimSpace(r.FormValue("comment")),
		Enabled: r.FormValue("enabled") == "on",
		Raw:     strings.TrimSpace(r.FormValue("raw")),
		Tags:    r.FormValue("tags"),
		Conds:   readConds(r),
		Acts:    readActs(r),
	}

	rule := ruleFromForm(vm)
	if errs := rule.Validate(); len(errs) > 0 {
		vm.Errors = errs
		vm.Conds = padConds(vm.Conds)
		vm.Acts = padActs(vm.Acts)
		s.ruleForm(w, r, vm)
		return
	}
	// Reject anything nft would — the render itself is the check here.
	table, _ := s.store.GetTable(chain.TableID)
	if _, err := nftconf.RenderRule(table.Family, rule); err != nil {
		vm.Errors = []string{"This rule can't be expressed: " + err.Error()}
		vm.Conds = padConds(vm.Conds)
		vm.Acts = padActs(vm.Acts)
		s.ruleForm(w, r, vm)
		return
	}

	// The editor's chain selector can retarget the rule to another chain in the
	// same table. The render check above used this table's family, and the target
	// shares it, so a move can't turn a valid rule invalid. A different-table (and
	// thus different-family) selection is ignored — it would need re-authoring.
	target := chain
	if selID, _ := strconv.ParseInt(r.FormValue("chain_id"), 10, 64); selID != 0 && selID != chain.ID {
		if tc, err := s.store.GetChain(selID); err == nil && tc.TableID == chain.TableID {
			target = tc
		}
	}

	var err error
	if isNew {
		rule.ChainID = target.ID
		_, err = s.store.CreateChainRule(rule)
	} else {
		err = s.store.UpdateChainRule(rule)
		if err == nil && target.ID != rule.ChainID {
			err = s.store.ReassignChainRule(rule.ID, target.ID)
		}
	}
	if err != nil {
		vm.Errors = []string{err.Error()}
		vm.Conds = padConds(vm.Conds)
		vm.Acts = padActs(vm.Acts)
		s.ruleForm(w, r, vm)
		return
	}
	s.audit(r, "saved a rule in chain "+target.Name)
	http.Redirect(w, r, "/firewall?saved=1", http.StatusSeeOther)
}

// handleRulePreview renders the rule the form currently describes and returns it
// as JSON, so the editor's "renders as" panel updates live as you fill it in. It
// uses the same Go renderer the apply path uses, so the preview can never drift
// from what would actually be applied.
func (s *Server) handleRulePreview(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, map[string]any{"error": "bad form"})
		return
	}
	chainID, _ := strconv.ParseInt(r.FormValue("chain_id"), 10, 64)
	chain, err := s.store.GetChain(chainID)
	if err != nil {
		writeJSON(w, map[string]any{"error": "unknown chain"})
		return
	}
	table, _ := s.store.GetTable(chain.TableID)

	vm := ruleFormVM{Chain: chain, Comment: strings.TrimSpace(r.FormValue("comment")), Raw: strings.TrimSpace(r.FormValue("raw")), Tags: r.FormValue("tags"), Conds: readConds(r), Acts: readActs(r)}
	rule := ruleFromForm(vm)

	resp := map[string]any{"chain": chain.Name, "family": table.Family, "table": table.Name}
	if line, rerr := nftconf.RenderRule(table.Family, rule); rerr != nil {
		resp["error"] = rerr.Error()
	} else {
		resp["line"] = line
	}
	writeJSON(w, resp)
}

func (s *Server) handleRuleDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteChainRule(pathID(r)); err != nil {
		redirectErr(w, r, "/firewall", "Could not delete rule: "+err.Error())
		return
	}
	s.audit(r, "deleted a rule")
	http.Redirect(w, r, "/firewall?saved=1", http.StatusSeeOther)
}

func (s *Server) handleRuleToggle(w http.ResponseWriter, r *http.Request) {
	rule, err := s.store.GetChainRule(pathID(r))
	if err != nil {
		s.notFoundOr(w, err)
		return
	}
	_ = s.store.SetChainRuleEnabled(rule.ID, !rule.Enabled)
	http.Redirect(w, r, "/firewall", http.StatusSeeOther)
}

func (s *Server) handleRuleMove(w http.ResponseWriter, r *http.Request) {
	_ = s.store.MoveChainRule(pathID(r), moveDir(r))
	http.Redirect(w, r, "/firewall", http.StatusSeeOther)
}

// handleRuleReorder persists a drag-and-drop reordering of one chain's rules.
// The body carries `ids` as a comma-separated list of rule ids in the new order;
// the store method is defensive, so a stale list can't drop a rule. It answers
// 204 (the page already reflects the new order in the DOM) and is same-origin
// only, like the live preview — the up/down buttons remain the no-JS fallback.
func (s *Server) handleRuleReorder(w http.ResponseWriter, r *http.Request) {
	chainID := pathID(r)
	ids, ok := reorderIDs(w, r)
	if !ok {
		return
	}
	if err := s.store.SetChainRuleOrder(chainID, ids); err != nil {
		s.serverError(w, "reorder rules", err)
		return
	}
	s.audit(r, "reordered rules in a chain")
	w.WriteHeader(http.StatusNoContent)
}

// handleChainReorder and handleTableReorder are the drag-and-drop counterparts of
// the chain/table up-down move buttons — same defensive store logic as rules.
func (s *Server) handleChainReorder(w http.ResponseWriter, r *http.Request) {
	tableID := pathID(r)
	ids, ok := reorderIDs(w, r)
	if !ok {
		return
	}
	if err := s.store.SetChainOrder(tableID, ids); err != nil {
		s.serverError(w, "reorder chains", err)
		return
	}
	s.audit(r, "reordered chains in a table")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleTableReorder(w http.ResponseWriter, r *http.Request) {
	ids, ok := reorderIDs(w, r)
	if !ok {
		return
	}
	if err := s.store.SetTableOrder(ids); err != nil {
		s.serverError(w, "reorder tables", err)
		return
	}
	s.audit(r, "reordered tables")
	w.WriteHeader(http.StatusNoContent)
}

// reorderIDs parses the `ids` form field (a comma-separated id list) shared by
// the three drag-and-drop reorder endpoints. It writes a 400 and returns ok=false
// on a malformed form.
func reorderIDs(w http.ResponseWriter, r *http.Request) ([]int64, bool) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return nil, false
	}
	return splitIDs(r.FormValue("ids")), true
}

// splitIDs parses a comma-separated list of decimal ids, skipping blanks and
// non-numbers.
func splitIDs(s string) []int64 {
	var ids []int64
	for _, tok := range strings.Split(s, ",") {
		if tok = strings.TrimSpace(tok); tok != "" {
			if id, err := strconv.ParseInt(tok, 10, 64); err == nil {
				ids = append(ids, id)
			}
		}
	}
	return ids
}

// handleRuleBulk applies one action to a set of selected rules at once
// (enable/disable/delete, or move into another chain of the same table). The
// per-chain checkbox bar on the Firewall page posts here; it answers 204 and the
// page reloads. Each id is validated independently, so an id that has since been
// deleted is skipped rather than failing the batch.
func (s *Server) handleRuleBulk(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	action := r.FormValue("action")
	ids := splitIDs(r.FormValue("ids"))
	if len(ids) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var targetChain int64
	if action == "move" {
		if targetChain, _ = strconv.ParseInt(r.FormValue("chain_id"), 10, 64); targetChain == 0 {
			http.Error(w, "move needs a target chain", http.StatusBadRequest)
			return
		}
	}
	done := 0
	for _, id := range ids {
		switch action {
		case "enable":
			if s.store.SetChainRuleEnabled(id, true) == nil {
				done++
			}
		case "disable":
			if s.store.SetChainRuleEnabled(id, false) == nil {
				done++
			}
		case "delete":
			if s.store.DeleteChainRule(id) == nil {
				done++
			}
		case "move":
			// Only move within the same table, so the rendered family stays valid.
			rule, err := s.store.GetChainRule(id)
			if err != nil {
				continue
			}
			src, err := s.store.GetChain(rule.ChainID)
			if err != nil {
				continue
			}
			tc, err := s.store.GetChain(targetChain)
			if err != nil || tc.TableID != src.TableID {
				continue
			}
			if s.store.ReassignChainRule(id, targetChain) == nil {
				done++
			}
		default:
			http.Error(w, "unknown bulk action", http.StatusBadRequest)
			return
		}
	}
	s.audit(r, fmt.Sprintf("bulk %s on %d rule(s)", action, done))
	w.WriteHeader(http.StatusNoContent)
}

// handleRuleDuplicate clones a rule to the end of a chain, so authoring a batch
// of similar rules doesn't mean re-entering every match by hand. The copy keeps
// the enabled state and carries a "(copy)" comment so it's easy to spot. With no
// chain_id it lands in the rule's own chain; with a chain_id for another chain in
// the same table (the row's "copy to…" picker) it lands there instead — keeping
// the rendered family compatible, like the editor's move selector.
func (s *Server) handleRuleDuplicate(w http.ResponseWriter, r *http.Request) {
	src, err := s.store.GetChainRule(pathID(r))
	if err != nil {
		s.notFoundOr(w, err)
		return
	}
	targetChain := src.ChainID
	if selID, _ := strconv.ParseInt(r.FormValue("chain_id"), 10, 64); selID != 0 && selID != src.ChainID {
		srcChain, err := s.store.GetChain(src.ChainID)
		if err == nil {
			if tc, err := s.store.GetChain(selID); err == nil && tc.TableID == srcChain.TableID {
				targetChain = tc.ID
			}
		}
	}
	dup := store.ChainRule{
		ChainID:    targetChain,
		Comment:    strings.TrimSpace(src.Comment + " (copy)"),
		Enabled:    src.Enabled,
		Raw:        src.Raw,
		Tags:       src.Tags,
		Matches:    append([]store.RuleMatch(nil), src.Matches...),
		Statements: append([]store.RuleStatement(nil), src.Statements...),
	}
	if _, err := s.store.CreateChainRule(dup); err != nil {
		redirectErr(w, r, "/firewall", "Could not duplicate rule: "+err.Error())
		return
	}
	s.audit(r, "duplicated a rule")
	http.Redirect(w, r, "/firewall?saved=1", http.StatusSeeOther)
}

// ── form row parsing ────────────────────────────────────────────────────────

func readConds(r *http.Request) []condRow {
	var out []condRow
	for i := range maxConds {
		field := strings.TrimSpace(r.FormValue("c_field_" + strconv.Itoa(i)))
		if field == "" {
			continue
		}
		out = append(out, condRow{
			Field: field,
			Op:    r.FormValue("c_op_" + strconv.Itoa(i)),
			Value: r.FormValue("c_val_" + strconv.Itoa(i)),
		})
	}
	return out
}

func readActs(r *http.Request) []actRow {
	var out []actRow
	for i := range maxActs {
		key := strings.TrimSpace(r.FormValue("a_key_" + strconv.Itoa(i)))
		if key == "" {
			continue
		}
		params := map[string]string{}
		for _, pk := range paramKeys {
			if v := strings.TrimSpace(r.FormValue("a_" + pk + "_" + strconv.Itoa(i))); v != "" {
				params[pk] = v
			}
		}
		out = append(out, actRow{Key: key, Params: params})
	}
	return out
}

// padConds/padActs top the rows up to the form's slot count so the template can
// always render a fixed grid (extra rows are empty and ignored on save).
func padConds(in []condRow) []condRow {
	for len(in) < maxConds {
		in = append(in, condRow{Op: "=="})
	}
	return in[:maxConds]
}

func padActs(in []actRow) []actRow {
	for len(in) < maxActs {
		in = append(in, actRow{Params: map[string]string{}})
	}
	for i := range in {
		if in[i].Params == nil {
			in[i].Params = map[string]string{}
		}
	}
	return in[:maxActs]
}

// ── small shared helpers ────────────────────────────────────────────────────

func pathID(r *http.Request) int64 {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id
}

func moveDir(r *http.Request) int {
	if r.FormValue("dir") == "up" || r.URL.Query().Get("dir") == "up" {
		return -1
	}
	return 1
}

func redirectErr(w http.ResponseWriter, r *http.Request, base, msg string) {
	http.Redirect(w, r, base+"?err="+urlEscape(msg), http.StatusSeeOther)
}

func (s *Server) notFoundOr(w http.ResponseWriter, err error) {
	if err == store.ErrNotFound {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	s.serverError(w, "lookup", err)
}
