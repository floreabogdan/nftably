package render

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/floreabogdan/nftably/internal/nftcat"
	"github.com/floreabogdan/nftably/internal/store"
)

// ResolveSets fills each table's Sets from the named address lists, driven by
// which sets the table's enabled rules actually reference (via @name4 / @name6).
// A set lives in the table that uses it — nft set references are table-scoped —
// so the same list referenced from two tables is emitted into both. This keeps
// the model simple (lists stay global, no table binding) while producing config
// nft accepts.
func ResolveSets(m *Model, lists []ListWithEntries) {
	byName := map[string]ListWithEntries{}
	for _, l := range lists {
		byName[l.Name] = l
	}
	for ti := range m.Tables {
		refs := referencedSetNames(m.Tables[ti])
		// A dynamic set (ban target) owns its name — never also resolve it as a
		// list-backed set, or the table would declare the same set name twice.
		dyn := map[string]bool{}
		for _, d := range m.Tables[ti].DynSets {
			dyn[d.Name] = true
		}
		var defs []SetDef
		// Deterministic order: sort the referenced set names.
		names := make([]string, 0, len(refs))
		for n := range refs {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, setName := range names {
			if dyn[setName] {
				continue
			}
			list, family, ok := listForSet(byName, setName)
			if !ok {
				continue // dangling reference — lint warns, render just skips it
			}
			v4, v6 := splitFamilies(list.Entries)
			typ, elems := "ipv4_addr", v4
			if family == "6" {
				typ, elems = "ipv6_addr", v6
			}
			defs = append(defs, SetDef{Name: setName, Type: typ, Elements: elems})
		}
		m.Tables[ti].Sets = defs
	}
}

// ResolveDynSets fills each table's DynSets from the ban statements its enabled
// rules carry: an `add @set` ban action declares a dynamic timeout set, which
// nft must see declared (empty) in the table. Deduplicated by name, in
// first-seen order, so two rules banning into the same set emit one declaration.
func ResolveDynSets(m *Model) {
	for ti := range m.Tables {
		var defs []DynSetDef
		seen := map[string]bool{}
		for _, c := range m.Tables[ti].Chains {
			for _, r := range c.Rules {
				if !r.Enabled {
					continue
				}
				for _, st := range r.Statements {
					name, typ, ok := nftcat.DynamicSet(st.Key, DecodeParams(st.Params))
					if !ok || seen[name] {
						continue
					}
					seen[name] = true
					defs = append(defs, DynSetDef{Name: name, Type: typ})
				}
			}
		}
		m.Tables[ti].DynSets = defs
	}
}

// referencedSetNames collects the @-prefixed set names used by a table's enabled
// rules (the leading @ stripped).
func referencedSetNames(t TableTree) map[string]bool {
	out := map[string]bool{}
	for _, c := range t.Chains {
		for _, r := range c.Rules {
			if !r.Enabled {
				continue
			}
			for _, mt := range r.Matches {
				for _, tok := range strings.FieldsFunc(mt.Value, func(r rune) bool {
					return r == ',' || r == ' ' || r == '\t' || r == '{' || r == '}'
				}) {
					if name, ok := strings.CutPrefix(tok, "@"); ok {
						out[name] = true
					}
				}
			}
		}
	}
	return out
}

// listForSet maps a set name (e.g. "office4") back to its list and family suffix.
func listForSet(byName map[string]ListWithEntries, setName string) (ListWithEntries, string, bool) {
	for _, suffix := range []string{"4", "6"} {
		if base, ok := strings.CutSuffix(setName, suffix); ok {
			if l, ok := byName[base]; ok {
				return l, suffix, true
			}
		}
	}
	return ListWithEntries{}, "", false
}

// splitFamilies sorts a list's entries into v4 and v6 element strings, each in
// nft's listing order (ascending by address). Unparsable rows are skipped.
func splitFamilies(entries []store.ListEntry) (v4, v6 []string) {
	type el struct {
		addr netip.Addr
		s    string
	}
	var e4, e6 []el
	for _, e := range entries {
		p, err := store.EntryPrefix(e.CIDR)
		if err != nil {
			continue
		}
		if p.Addr().Is4() {
			e4 = append(e4, el{p.Addr(), e.CIDR})
		} else {
			e6 = append(e6, el{p.Addr(), e.CIDR})
		}
	}
	for _, s := range [][]el{e4, e6} {
		sort.Slice(s, func(i, j int) bool { return s[i].addr.Compare(s[j].addr) < 0 })
	}
	for _, e := range e4 {
		v4 = append(v4, e.s)
	}
	for _, e := range e6 {
		v6 = append(v6, e.s)
	}
	return v4, v6
}

// writeDynSet emits a dynamic timeout set: declared empty with flags
// dynamic,timeout, the kernel populates it as ban rules fire. Per-element
// timeouts come from the `add @set { … timeout … }` statement, so no default
// timeout attribute is needed here.
func writeDynSet(b *strings.Builder, s DynSetDef) {
	fmt.Fprintf(b, "\tset %s {\n", s.Name)
	fmt.Fprintf(b, "\t\ttype %s\n", s.Type)
	b.WriteString("\t\tflags dynamic, timeout\n")
	b.WriteString("\t}\n\n")
}

// writeSet emits one named set in nft's canonical listing format: elements two
// per line, continuations aligned under the opening brace; an empty set has no
// elements line at all, exactly as nft lists one. Trailing blank line separates
// it from the next block.
func writeSet(b *strings.Builder, s SetDef) {
	fmt.Fprintf(b, "\tset %s {\n", s.Name)
	fmt.Fprintf(b, "\t\ttype %s\n", s.Type)
	b.WriteString("\t\tflags interval\n")
	if len(s.Elements) > 0 {
		b.WriteString("\t\telements = { ")
		for i, e := range s.Elements {
			if i > 0 {
				if i%2 == 0 {
					b.WriteString(",\n\t\t\t     ")
				} else {
					b.WriteString(", ")
				}
			}
			b.WriteString(e)
		}
		b.WriteString(" }\n")
	}
	b.WriteString("\t}\n\n")
}
