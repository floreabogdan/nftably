package nft

import (
	"bufio"
	"encoding/json"
	"fmt"
	"strings"
)

// jsonEnvelope is the top-level shape of `nft -j list ruleset`: a single
// "nftables" array whose every element is an object with exactly one of the
// keys metainfo / table / chain / rule / set / map / … . We decode each element
// lazily and switch on which key it carries.
type jsonEnvelope struct {
	Nftables []map[string]json.RawMessage `json:"nftables"`
}

type jsonMetainfo struct {
	Version string `json:"version"`
}

type jsonTable struct {
	Family string `json:"family"`
	Name   string `json:"name"`
	Handle int    `json:"handle"`
}

type jsonChain struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
	Handle int    `json:"handle"`
	Type   string `json:"type"`
	Hook   string `json:"hook"`
	Prio   int    `json:"prio"`
	Policy string `json:"policy"`
}

type jsonRule struct {
	Family  string          `json:"family"`
	Table   string          `json:"table"`
	Chain   string          `json:"chain"`
	Handle  int             `json:"handle"`
	Comment string          `json:"comment"`
	Expr    json.RawMessage `json:"expr"`
}

// parseRuleset builds a Ruleset from the JSON produced by `nft -j list ruleset`
// and the annotated text from `nft -a list ruleset`. The JSON is authoritative
// for structure; the text only supplies each rule's human rendering, matched by
// handle. A parse of the JSON that fails is an error; a text mismatch is not —
// a rule simply keeps an empty Text and the UI renders from Expr instead.
func parseRuleset(jsonOut []byte, annotatedText string) (*Ruleset, error) {
	var env jsonEnvelope
	if err := json.Unmarshal(jsonOut, &env); err != nil {
		return nil, fmt.Errorf("nft: parse json ruleset: %w", err)
	}

	handleText := parseHandleText(annotatedText)

	rs := &Ruleset{}
	// Index tables and chains by their identity so rules and chains attach to
	// the right parent regardless of element ordering. nft emits parents before
	// children, but keying is cheap insurance against that ever changing.
	tableByKey := map[string]*Table{}
	chainByKey := map[string]*Chain{}

	for _, elem := range env.Nftables {
		switch {
		case elem["metainfo"] != nil:
			var m jsonMetainfo
			if err := json.Unmarshal(elem["metainfo"], &m); err == nil {
				rs.NftVersion = m.Version
			}

		case elem["table"] != nil:
			var t jsonTable
			if err := json.Unmarshal(elem["table"], &t); err != nil {
				return nil, fmt.Errorf("nft: parse table: %w", err)
			}
			tbl := &Table{Family: Family(t.Family), Name: t.Name, Handle: t.Handle}
			rs.Tables = append(rs.Tables, tbl)
			tableByKey[t.Family+"/"+t.Name] = tbl

		case elem["chain"] != nil:
			var ch jsonChain
			if err := json.Unmarshal(elem["chain"], &ch); err != nil {
				return nil, fmt.Errorf("nft: parse chain: %w", err)
			}
			c := &Chain{
				Family: Family(ch.Family), Table: ch.Table, Name: ch.Name, Handle: ch.Handle,
				Type: ch.Type, Hook: ch.Hook, Prio: ch.Prio, Policy: ch.Policy,
			}
			chainByKey[chainKey(ch.Family, ch.Table, ch.Name)] = c
			if tbl := tableByKey[ch.Family+"/"+ch.Table]; tbl != nil {
				tbl.Chains = append(tbl.Chains, c)
			}

		case elem["rule"] != nil:
			var r jsonRule
			if err := json.Unmarshal(elem["rule"], &r); err != nil {
				return nil, fmt.Errorf("nft: parse rule: %w", err)
			}
			rule := &Rule{
				Family: r.Family, Table: r.Table, Chain: r.Chain, Handle: r.Handle,
				Comment: r.Comment, Expr: r.Expr,
				Text: handleText[handleKey(r.Family, r.Table, r.Handle)],
			}
			if c := chainByKey[chainKey(r.Family, r.Table, r.Chain)]; c != nil {
				c.Rules = append(c.Rules, rule)
			}
		}
		// set / map / element / limit / counter objects are ignored for the M1
		// viewer; they surface in the raw text view and are modelled later.
	}
	return rs, nil
}

func chainKey(family, table, chain string) string { return family + "/" + table + "/" + chain }
func handleKey(family, table string, handle int) string {
	return fmt.Sprintf("%s/%s/%d", family, table, handle)
}

// parseHandleText scans `nft -a list ruleset` output and maps each rule's
// handle to its canonical text. Handles are unique within a table, so the key
// is (family, table, handle). Only lines inside a `chain { … }` block are
// considered, so a handle on a set element is never mistaken for a rule.
//
// The annotated output looks like this — note the table and chain openers carry
// a "# handle N" comment too, so they do not end in "{":
//
//	table inet filter { # handle 1
//		chain input { # handle 2
//			type filter hook input priority 0; policy drop;
//			ct state established,related accept # handle 4
//		}
//	}
func parseHandleText(text string) map[string]string {
	out := map[string]string{}
	if text == "" {
		return out
	}

	var family, table string
	// block is a tiny stack of the kinds of brace we are inside: "table",
	// "chain", or "other" (set/map/counter/…). We capture handles only when the
	// innermost block is a chain.
	var block []string

	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if line == "}" || strings.HasPrefix(line, "}") {
			if len(block) > 0 {
				block = block[:len(block)-1]
			}
			continue
		}
		// A block opener ends in "{" — but `nft -a` annotates the table/chain
		// opener with a "# handle N" comment too (`table inet filter { # handle 1`),
		// so strip that before the check. A rule line never ends in "{" even after
		// stripping (an anonymous set closes with "}"), so this can't misfire on a
		// rule.
		code := line
		if idx := strings.LastIndex(code, "# handle "); idx >= 0 {
			code = strings.TrimSpace(code[:idx])
		}
		if strings.HasSuffix(code, "{") {
			fields := strings.Fields(code)
			switch {
			case len(fields) >= 3 && fields[0] == "table":
				family, table = fields[1], fields[2]
				block = append(block, "table")
			case len(fields) >= 1 && fields[0] == "chain":
				block = append(block, "chain")
			default:
				block = append(block, "other")
			}
			continue
		}
		// A rule line inside a chain, carrying its handle as a trailing comment.
		if len(block) > 0 && block[len(block)-1] == "chain" {
			if h, ok := cutHandle(line); ok {
				ruleText := strings.TrimSpace(line[:strings.LastIndex(line, "# handle ")])
				out[handleKey(family, table, h)] = ruleText
			}
		}
	}
	return out
}

// cutHandle extracts N from a line ending in "# handle N", returning false when
// the line carries no handle comment.
func cutHandle(line string) (int, bool) {
	idx := strings.LastIndex(line, "# handle ")
	if idx < 0 {
		return 0, false
	}
	var h int
	if _, err := fmt.Sscanf(line[idx:], "# handle %d", &h); err != nil {
		return 0, false
	}
	return h, true
}
