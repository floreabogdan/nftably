package render

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/floreabogdan/nftably/internal/store"
)

// counterNameRe mirrors nftcat.identRe: a counter name is emitted verbatim into
// a table-level `counter <name> {` declaration, so it must be a bare identifier.
// The rule-level render already enforces this before a rule can be stored, but
// validating here too keeps the invariant local to the declaration site — a
// future store path that skipped RenderRule couldn't turn a crafted cname into a
// table-level injection.
var counterNameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)

// writeFlowtable emits a flowtable declaration: its ingress hook, priority, the
// interfaces it binds, and `flags offload` when hardware offload is requested.
func writeFlowtable(b *strings.Builder, f store.Flowtable) {
	fmt.Fprintf(b, "\tflowtable %s {\n", f.Name)
	fmt.Fprintf(b, "\t\thook ingress priority %s;\n", f.Priority)
	devs := f.DeviceList()
	quoted := make([]string, len(devs))
	for i, d := range devs {
		quoted[i] = fmt.Sprintf("%q", d)
	}
	fmt.Fprintf(b, "\t\tdevices = { %s };\n", strings.Join(quoted, ", "))
	if f.HWOffload {
		b.WriteString("\t\tflags offload;\n")
	}
	b.WriteString("\t}\n")
}

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
				if name != "" && counterNameRe.MatchString(name) && !seen[name] {
					seen[name] = true
					names = append(names, name)
				}
			}
		}
	}
	sort.Strings(names)
	return names
}
