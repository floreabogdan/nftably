package web

import (
	"context"

	nftconf "github.com/floreabogdan/nftably/internal/render"
	"github.com/floreabogdan/nftably/internal/store"
)

// loadModel assembles the whole owned object graph — tables, their chains, and
// each chain's rules (with matches and statements) — into the render.Model that
// every render/lint/apply path consumes, so they can never disagree about what
// nftably is managing.
func (s *Server) loadModel() (nftconf.Model, error) {
	var m nftconf.Model

	tables, err := s.store.ListTables()
	if err != nil {
		return m, err
	}
	chainsByTable, err := s.store.AllChains()
	if err != nil {
		return m, err
	}
	rulesByChain, err := s.store.AllChainRules()
	if err != nil {
		return m, err
	}

	for _, t := range tables {
		tt := nftconf.TableTree{Table: t}
		for _, c := range chainsByTable[t.ID] {
			tt.Chains = append(tt.Chains, nftconf.ChainTree{Chain: c, Rules: rulesByChain[c.ID]})
		}
		m.Tables = append(m.Tables, tt)
	}

	// Resolve named-set references: emit each list a rule points at (@name4 /
	// @name6) into the table that uses it.
	lists, err := s.loadLists()
	if err != nil {
		return m, err
	}
	nftconf.ResolveSets(&m, lists)
	return m, nil
}

// loadLists reads every named address list with its entries.
func (s *Server) loadLists() ([]nftconf.ListWithEntries, error) {
	lists, err := s.store.ListLists()
	if err != nil {
		return nil, err
	}
	entries, err := s.store.AllEntries()
	if err != nil {
		return nil, err
	}
	out := make([]nftconf.ListWithEntries, 0, len(lists))
	for _, l := range lists {
		out = append(out, nftconf.ListWithEntries{IPList: l, Entries: entries[l.ID]})
	}
	return out, nil
}

// modelTableRefs is the current owned-table set, for the apply ledger and the
// removed-table diff.
func modelTableRefs(m nftconf.Model) []store.TableRef {
	refs := make([]store.TableRef, 0, len(m.Tables))
	for _, t := range m.Tables {
		refs = append(refs, store.TableRef{Family: t.Family, Name: t.Name})
	}
	return refs
}

// snapshotTables reads each table's current kernel text — the state a revert
// restores. A table that does not exist yet is captured with Exists=false.
func (s *Server) snapshotTables(ctx context.Context, refs []store.TableRef) ([]store.TableSnapshot, error) {
	out := make([]store.TableSnapshot, 0, len(refs))
	for _, ref := range refs {
		text, exists, err := s.applier.Table(ctx, ref.Family, ref.Name)
		if err != nil {
			return nil, err
		}
		out = append(out, store.TableSnapshot{Family: ref.Family, Name: ref.Name, Text: text, Exists: exists})
	}
	return out, nil
}

// unionRefs returns the distinct union of two ref slices (order: a then new b's).
func unionRefs(a, b []store.TableRef) []store.TableRef {
	seen := map[store.TableRef]bool{}
	var out []store.TableRef
	for _, r := range append(append([]store.TableRef{}, a...), b...) {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}

// refsMinus returns the refs in a that are not in b.
func refsMinus(a, b []store.TableRef) []store.TableRef {
	inB := map[store.TableRef]bool{}
	for _, r := range b {
		inB[r] = true
	}
	var out []store.TableRef
	for _, r := range a {
		if !inB[r] {
			out = append(out, r)
		}
	}
	return out
}
