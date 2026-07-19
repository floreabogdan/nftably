// Package render turns nftably's object model — the tables, chains and rules
// the operator owns — into nftables config text, and drives the atomic apply /
// revert transactions. Nothing here is opinionated: it emits exactly the model,
// no injected baseline. Safety is the apply pipeline's armed auto-revert plus
// the lockout lint, not a forced ruleset.
//
// The output is written in `nft list` output style (tabs, one rule per line,
// bare values for single-element sets) so diffing it against the live tables is
// quiet when nothing changed.
package render

import (
	"fmt"
	"strings"

	"github.com/floreabogdan/nftably/internal/nftcat"
	"github.com/floreabogdan/nftably/internal/store"
)

// Model is the whole owned object graph: the tables in order, each with its
// chains, each chain with its rules (matches + statements already loaded).
type Model struct {
	Tables []TableTree
}

// TableTree is a table with its chains and the named sets its rules reference.
type TableTree struct {
	store.Table
	Chains []ChainTree
	// Sets are the named sets this table must declare because a rule in it
	// references one (via @name). Populated by ResolveSets.
	Sets []SetDef
	// DynSets are dynamic timeout sets a rule in this table populates at runtime
	// (an `add @set` ban statement) — declared empty with flags dynamic,timeout.
	// Populated by ResolveDynSets.
	DynSets []DynSetDef
}

// DynSetDef is one dynamic timeout set to emit: its nft name and element type.
// It carries no elements — the kernel fills it as rules fire.
type DynSetDef struct {
	Name string
	Type string // ipv4_addr | ipv6_addr
}

// ChainTree is a chain with its rules.
type ChainTree struct {
	store.Chain
	Rules []store.ChainRule
}

// SetDef is one named set to emit into a table: its nft name, element type and
// the (already sorted, canonical) element strings.
type SetDef struct {
	Name     string
	Type     string // ipv4_addr | ipv6_addr
	Elements []string
}

// ListWithEntries pairs a named address list with its entries — the source the
// render layer turns into nft sets when a rule references one.
type ListWithEntries struct {
	store.IPList
	Entries []store.ListEntry
}

// Config renders every owned table. Each becomes a `table <family> <name> { … }`
// block; base chains carry their hook/type/priority/policy line, regular chains
// do not. Only enabled rules render.
func Config(m Model) string {
	var b strings.Builder
	for i, t := range m.Tables {
		if i > 0 {
			b.WriteString("\n")
		}
		writeTable(&b, t)
	}
	return b.String()
}

// TableConfig renders a single table block — the unit the apply transaction
// replaces one at a time.
func TableConfig(t TableTree) string {
	var b strings.Builder
	writeTable(&b, t)
	return b.String()
}

func writeTable(b *strings.Builder, t TableTree) {
	fmt.Fprintf(b, "table %s %s {\n", t.Family, t.Name)
	for _, s := range t.DynSets {
		writeDynSet(b, s)
	}
	for _, s := range t.Sets {
		writeSet(b, s)
	}
	for j, c := range t.Chains {
		if j > 0 {
			b.WriteString("\n")
		}
		writeChain(b, t.Family, c)
	}
	b.WriteString("}\n")
}

func writeChain(b *strings.Builder, family string, c ChainTree) {
	fmt.Fprintf(b, "\tchain %s {\n", c.Name)
	if c.IsBase() {
		// e.g.  type filter hook input priority filter; policy drop;
		// ingress/egress hooks bind to an interface: ... hook ingress device "eth0" priority …
		fmt.Fprintf(b, "\t\ttype %s hook %s", c.ChainType, c.Hook)
		if c.Device != "" {
			fmt.Fprintf(b, " device %q", c.Device)
		}
		fmt.Fprintf(b, " priority %s;", c.Priority)
		if c.Policy != "" {
			fmt.Fprintf(b, " policy %s;", c.Policy)
		}
		b.WriteString("\n")
	}
	for _, r := range c.Rules {
		if !r.Enabled {
			continue
		}
		line, err := renderRule(family, r)
		if err != nil || line == "" {
			// A rule that cannot render (e.g. an unknown key from a downgrade)
			// is skipped rather than breaking the whole table; lint surfaces it.
			continue
		}
		b.WriteString("\t\t")
		b.WriteString(line)
		b.WriteString("\n")
	}
	b.WriteString("\t}\n")
}

// RenderRule renders one rule to its nft line (without indentation) — used by
// the editor's live preview. Returns an error describing the first knob that
// could not render.
func RenderRule(family string, r store.ChainRule) (string, error) {
	return renderRuleStrict(family, r)
}

// renderRule is the lenient renderer used while emitting a table: it returns an
// error so writeChain can skip a bad rule.
func renderRule(family string, r store.ChainRule) (string, error) {
	return renderRuleStrict(family, r)
}

func renderRuleStrict(family string, r store.ChainRule) (string, error) {
	ctx := nftcat.Ctx{Family: family}
	var parts []string
	for _, m := range r.Matches {
		frag, err := nftcat.RenderMatch(m.Key, m.Op, m.Value, ctx)
		if err != nil {
			return "", err
		}
		parts = append(parts, frag)
	}
	for _, st := range r.Statements {
		frag, err := nftcat.RenderStatement(st.Key, DecodeParams(st.Params), ctx)
		if err != nil {
			return "", err
		}
		parts = append(parts, frag)
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("rule has no conditions or actions")
	}
	if c := strings.TrimSpace(r.Comment); c != "" {
		parts = append(parts, fmt.Sprintf("comment %q", "nftably: "+c))
	}
	return strings.Join(parts, " "), nil
}
