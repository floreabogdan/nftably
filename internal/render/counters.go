package render

import "sort"

// counters.go derives the named counters a table must declare from how its rules
// use them: a `counter` statement with a name references a table-level named
// counter, so nftably emits a `counter <name>` declaration for each distinct
// name. This keeps named counters usage-driven — no separate object to manage.

// namedCountersOf returns the sorted, distinct named counters referenced by the
// enabled rules of a table. Raw rules are skipped (their statements are ignored).
func namedCountersOf(t TableTree) []string {
	seen := map[string]bool{}
	var names []string
	for _, c := range t.Chains {
		for _, r := range c.Rules {
			if !r.Enabled || r.IsRaw() {
				continue
			}
			for _, st := range r.Statements {
				if st.Key != "counter" {
					continue
				}
				name := DecodeParams(st.Params)["cname"]
				if name != "" && !seen[name] {
					seen[name] = true
					names = append(names, name)
				}
			}
		}
	}
	sort.Strings(names)
	return names
}
