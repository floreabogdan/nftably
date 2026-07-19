package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/floreabogdan/nftably/internal/store"
)

// backup.go exports and restores the whole owned configuration — every table,
// chain and rule, plus the named sets and their entries — as a single portable
// JSON document. It's the model, not the database: no login hashes, no settings,
// so it's safe to share and keep in version control. A restore replaces the
// current model wholesale and is model-only, so nothing reaches the kernel until
// you review and apply it (behind the armed auto-revert).

const backupVersion = 1

type backupDoc struct {
	Version int           `json:"version"`
	Tables  []backupTable `json:"tables"`
	Lists   []backupList  `json:"lists,omitempty"`
}

type backupTable struct {
	Family  string        `json:"family"`
	Name    string        `json:"name"`
	Comment string        `json:"comment,omitempty"`
	Chains  []backupChain `json:"chains,omitempty"`
}

type backupChain struct {
	Name      string       `json:"name"`
	Kind      string       `json:"kind"`
	Hook      string       `json:"hook,omitempty"`
	ChainType string       `json:"chain_type,omitempty"`
	Priority  string       `json:"priority,omitempty"`
	Policy    string       `json:"policy,omitempty"`
	Device    string       `json:"device,omitempty"`
	Rules     []backupRule `json:"rules,omitempty"`
}

type backupRule struct {
	Comment    string            `json:"comment,omitempty"`
	Enabled    bool              `json:"enabled"`
	Matches    []backupMatch     `json:"matches,omitempty"`
	Statements []backupStatement `json:"statements,omitempty"`
}

type backupMatch struct {
	Key   string `json:"key"`
	Op    string `json:"op"`
	Value string `json:"value"`
}

type backupStatement struct {
	Key    string          `json:"key"`
	Params json.RawMessage `json:"params,omitempty"`
}

type backupList struct {
	Name        string        `json:"name"`
	Note        string        `json:"note,omitempty"`
	Source      string        `json:"source,omitempty"`
	SourceArg   string        `json:"source_arg,omitempty"`
	AutoRefresh bool          `json:"auto_refresh,omitempty"`
	Entries     []backupEntry `json:"entries,omitempty"`
}

type backupEntry struct {
	CIDR string `json:"cidr"`
	Note string `json:"note,omitempty"`
}

// buildBackup reads the owned model and named sets into a portable document.
func (s *Server) buildBackup() (backupDoc, error) {
	doc := backupDoc{Version: backupVersion}
	tables, err := s.store.ListTables()
	if err != nil {
		return doc, err
	}
	for _, t := range tables {
		bt := backupTable{Family: t.Family, Name: t.Name, Comment: t.Comment}
		chains, err := s.store.ListChains(t.ID)
		if err != nil {
			return doc, err
		}
		for _, c := range chains {
			bc := backupChain{Name: c.Name, Kind: c.Kind, Hook: c.Hook, ChainType: c.ChainType, Priority: c.Priority, Policy: c.Policy, Device: c.Device}
			rules, err := s.store.ListChainRules(c.ID)
			if err != nil {
				return doc, err
			}
			for _, r := range rules {
				br := backupRule{Comment: r.Comment, Enabled: r.Enabled}
				for _, m := range r.Matches {
					br.Matches = append(br.Matches, backupMatch{Key: m.Key, Op: m.Op, Value: m.Value})
				}
				for _, st := range r.Statements {
					params := st.Params
					if params == "" {
						params = "{}"
					}
					br.Statements = append(br.Statements, backupStatement{Key: st.Key, Params: json.RawMessage(params)})
				}
				bc.Rules = append(bc.Rules, br)
			}
			bt.Chains = append(bt.Chains, bc)
		}
		doc.Tables = append(doc.Tables, bt)
	}
	lists, err := s.store.ListLists()
	if err != nil {
		return doc, err
	}
	for _, l := range lists {
		bl := backupList{Name: l.Name, Note: l.Note, Source: l.Source, SourceArg: l.SourceArg, AutoRefresh: l.AutoRefresh}
		entries, err := s.store.ListEntries(l.ID)
		if err != nil {
			return doc, err
		}
		for _, e := range entries {
			bl.Entries = append(bl.Entries, backupEntry{CIDR: e.CIDR, Note: e.Note})
		}
		doc.Lists = append(doc.Lists, bl)
	}
	return doc, nil
}

// handleConfigExport streams the backup document as a downloadable JSON file.
func (s *Server) handleConfigExport(w http.ResponseWriter, r *http.Request) {
	doc, err := s.buildBackup()
	if err != nil {
		s.serverError(w, "build backup", err)
		return
	}
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		s.serverError(w, "encode backup", err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="nftably-config.json"`)
	_, _ = w.Write(body)
	s.audit(r, "exported the configuration")
}

// handleConfigRestore replaces the owned model and named sets from an uploaded
// backup. Model-only: the operator reviews and applies afterwards.
func (s *Server) handleConfigRestore(w http.ResponseWriter, r *http.Request) {
	f, _, err := r.FormFile("backup")
	if err != nil {
		redirectErr(w, r, "/settings?tab=backup", "Choose a backup file to restore.")
		return
	}
	defer f.Close()
	// Cap the read — a config document is small; anything huge is a mistake.
	data, err := io.ReadAll(io.LimitReader(f, 8<<20))
	if err != nil {
		redirectErr(w, r, "/settings?tab=backup", "Could not read the file: "+err.Error())
		return
	}
	var doc backupDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		redirectErr(w, r, "/settings?tab=backup", "That doesn't look like an nftably backup (invalid JSON).")
		return
	}
	if err := s.restoreBackup(doc); err != nil {
		redirectErr(w, r, "/settings?tab=backup", "Restore failed: "+err.Error())
		return
	}
	s.audit(r, "restored the configuration from a backup")
	// Land on Changes so the restored model is reviewed and applied behind the
	// armed auto-revert.
	http.Redirect(w, r, "/changes", http.StatusSeeOther)
}

// restoreBackup validates the whole document, then replaces the model and named
// sets. It validates before mutating so a bad file is rejected without leaving a
// half-restored model.
func (s *Server) restoreBackup(doc backupDoc) error {
	if doc.Version != backupVersion {
		return fmt.Errorf("unsupported backup version %d (this build reads version %d)", doc.Version, backupVersion)
	}
	// Validate shape up front.
	for _, t := range doc.Tables {
		tbl := store.Table{Family: t.Family, Name: t.Name, Comment: t.Comment}
		if errs := tbl.Validate(); len(errs) > 0 {
			return fmt.Errorf("table %s %s: %s", t.Family, t.Name, errs[0])
		}
		for _, c := range t.Chains {
			ch := store.Chain{Name: c.Name, Kind: c.Kind, Hook: c.Hook, ChainType: c.ChainType, Priority: c.Priority, Policy: c.Policy, Device: c.Device}
			if errs := ch.Validate(); len(errs) > 0 {
				return fmt.Errorf("chain %s: %s", c.Name, errs[0])
			}
		}
	}

	// Replace: clear the current model and lists, then rebuild.
	if err := s.resetTables(); err != nil {
		return err
	}
	lists, err := s.store.ListLists()
	if err != nil {
		return err
	}
	for _, l := range lists {
		if err := s.store.DeleteList(l.ID); err != nil {
			return err
		}
	}
	for _, l := range doc.Lists {
		source := l.Source
		if source == "" {
			source = store.SourceManual
		}
		id, err := s.store.CreateList(store.IPList{Name: l.Name, Note: l.Note, Source: source, SourceArg: l.SourceArg, AutoRefresh: l.AutoRefresh})
		if err != nil {
			return fmt.Errorf("named set %q: %w", l.Name, err)
		}
		for _, e := range l.Entries {
			// A bad entry shouldn't abort the whole restore; skip it.
			_ = s.store.AddListEntry(id, e.CIDR, e.Note)
		}
	}
	for _, t := range doc.Tables {
		tid, err := s.store.CreateTable(store.Table{Family: t.Family, Name: t.Name, Comment: t.Comment})
		if err != nil {
			return err
		}
		for _, c := range t.Chains {
			cid, err := s.store.CreateChain(store.Chain{TableID: tid, Name: c.Name, Kind: c.Kind, Hook: c.Hook, ChainType: c.ChainType, Priority: c.Priority, Policy: c.Policy, Device: c.Device})
			if err != nil {
				return err
			}
			for _, r := range c.Rules {
				rule := store.ChainRule{ChainID: cid, Comment: r.Comment, Enabled: r.Enabled}
				for _, m := range r.Matches {
					rule.Matches = append(rule.Matches, store.RuleMatch{Key: m.Key, Op: m.Op, Value: m.Value})
				}
				for _, st := range r.Statements {
					params := string(st.Params)
					if params == "" {
						params = "{}"
					}
					rule.Statements = append(rule.Statements, store.RuleStatement{Key: st.Key, Params: params})
				}
				if _, err := s.store.CreateChainRule(rule); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
