// Package nft reads the live netfilter ruleset by shelling out to nft(8). It
// runs nft in JSON mode (`nft -j list ruleset`) for an authoritative,
// version-stable view of the tables, chains and rules, and in annotated-text
// mode (`nft -a list ruleset`) to recover each rule's canonical rendering by
// handle. This package is read-only: nothing here changes the running firewall.
// The apply path (atomic `nft -f`, with an armed auto-revert) arrives in a
// later milestone and will live alongside this reader.
package nft

import "encoding/json"

// Family is a netfilter address family. `inet` carries both IPv4 and IPv6 in a
// single table, which is the family nftably standardises on so one rule set
// covers both protocols — the whole point of managing v4 and v6 together.
type Family string

const (
	FamilyInet   Family = "inet"
	FamilyIP     Family = "ip"
	FamilyIP6    Family = "ip6"
	FamilyArp    Family = "arp"
	FamilyBridge Family = "bridge"
	FamilyNetdev Family = "netdev"
)

// Ruleset is the parsed live netfilter ruleset: the nft version that produced
// it and every table, each carrying its chains and their rules, in the order
// nft reported them.
type Ruleset struct {
	// NftVersion is what `nft -j` put in its metainfo, e.g. "1.0.6".
	NftVersion string
	Tables     []*Table
}

// Table is one netfilter table: a family plus a name, holding chains.
type Table struct {
	Family Family
	Name   string
	Handle int
	Chains []*Chain
}

// Chain is a chain within a table. A base chain (one attached to a netfilter
// hook) carries Type/Hook/Prio/Policy; a regular chain leaves them empty and is
// reached only by an explicit jump or goto from another chain.
type Chain struct {
	Family Family
	Table  string
	Name   string
	Handle int

	Type   string // filter | nat | route — empty for a regular chain
	Hook   string // input | output | forward | prerouting | postrouting — empty for regular
	Prio   int
	Policy string // accept | drop — empty for a regular chain

	Rules []*Rule
}

// IsBase reports whether the chain is attached to a netfilter hook (and so has
// a policy and sees traffic on its own), as opposed to a regular chain that
// only runs when jumped to.
func (c *Chain) IsBase() bool { return c.Hook != "" }

// Rule is one rule in a chain.
type Rule struct {
	Family  string
	Table   string
	Chain   string
	Handle  int
	Comment string

	// Text is nft's own rendering of the rule, recovered from `nft -a list
	// ruleset` by matching on handle, e.g. "ct state established,related
	// accept". Empty when the text output could not be matched (in which case
	// the UI falls back to a compact rendering of Expr).
	Text string

	// Expr is the raw JSON expression array from `nft -j`, kept verbatim so a
	// later milestone can model rules structurally without re-reading nft.
	Expr json.RawMessage
}

// TotalRules counts every rule across every chain — the headline number on the
// dashboard.
func (rs *Ruleset) TotalRules() int {
	n := 0
	for _, t := range rs.Tables {
		for _, c := range t.Chains {
			n += len(c.Rules)
		}
	}
	return n
}

// TotalChains counts every chain across every table.
func (rs *Ruleset) TotalChains() int {
	n := 0
	for _, t := range rs.Tables {
		n += len(t.Chains)
	}
	return n
}

// IsEmpty reports whether netfilter is carrying no tables at all — a fresh box
// where nftably has a clean slate to work with.
func (rs *Ruleset) IsEmpty() bool { return len(rs.Tables) == 0 }

// Families lists the distinct table families present, in first-seen order — so
// the dashboard can say "inet, ip6" at a glance.
func (rs *Ruleset) Families() []Family {
	var out []Family
	seen := map[Family]bool{}
	for _, t := range rs.Tables {
		if !seen[t.Family] {
			seen[t.Family] = true
			out = append(out, t.Family)
		}
	}
	return out
}
