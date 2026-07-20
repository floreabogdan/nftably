package render

import (
	"regexp"
	"sort"
	"strings"
)

// canonical.go reduces `nft list table` output — whether read back from the
// kernel or produced by nftably's own renderer — to a stable, comparable form.
//
// The kernel reformats a ruleset when it lists it back: it wraps set elements at
// its own width, reorders anonymous-set members (by numeric value), fills named
// counters with their live packet/byte totals, and quotes the counter name in a
// `counter name` statement. None of that is a change to the applied config, yet
// a byte diff against nftably's render lights up on every one of them — so the
// Changes page never goes quiet, and drift detection cries wolf the moment a
// counter ticks up. Canonicalizing both sides makes cosmetic differences vanish
// while a genuine rule or set-member change still shows.
var (
	reHandle    = regexp.MustCompile(`\s*# handle \d+`)
	reCtrInline = regexp.MustCompile(`counter packets \d+ bytes \d+`)
	reCtrObject = regexp.MustCompile(`(?m)^[ \t]*packets \d+ bytes \d+[ \t]*$`)
	reCtrName   = regexp.MustCompile(`counter name "([A-Za-z0-9_]+)"`)
	reElements  = regexp.MustCompile(`(?s)elements = \{[^}]*\}`)
	reInlineSet = regexp.MustCompile(`\{[^{}\n]*\}`)
	// The kernel stamps a default `size` on dynamic sets that nftably does not
	// emit, and lists a rate-limit detector's `add @m { … }` back as the `meter`
	// alias — both cosmetic. (Flags comma-spacing, `dynamic, timeout` vs
	// `dynamic,timeout`, is normalized per line below.)
	reSetSize    = regexp.MustCompile(`(?m)^[ \t]*size \d+[ \t]*$`)
	reInlineSize = regexp.MustCompile(` size \d+ \{`)
	reMeter      = regexp.MustCompile(`meter ([A-Za-z0-9_]+) \{`)
	// Some nft versions list an NFQUEUE bypass statement as `queue flags bypass
	// to N` rather than the `queue num N bypass` nftably renders.
	reQueue = regexp.MustCompile(`queue flags bypass to (\d+)`)
)

// CanonicalizeNftText normalizes one `nft list table` dump (or nftably's render
// of the same table) so two representations of the same applied ruleset compare
// equal.
func CanonicalizeNftText(s string) string {
	// A multi-line `elements = { … }` block: a dynamic set's members are kernel
	// runtime, not applied config, so the whole block is dropped to match the empty
	// set nftably applied — a timeout (ban) set's members carry `expires` (counting
	// down each second), a rate-meter set's carry `limit rate` (the sources it is
	// currently limiting). A static set's members are collapsed onto one line and
	// sorted, so the kernel's wrapping and ordering never read as a change (element
	// order is not significant in a set).
	s = reElements.ReplaceAllStringFunc(s, func(m string) string {
		if strings.Contains(m, "expires") || strings.Contains(m, "limit rate") {
			return ""
		}
		return "elements = " + sortBraceSet(m)
	})
	// Volatile counter totals: inline (`counter packets N bytes M`) and the named
	// counter object body (a bare `packets N bytes M` line), plus kernel handles.
	s = reCtrInline.ReplaceAllString(s, "counter")
	s = reCtrObject.ReplaceAllString(s, "")
	s = reHandle.ReplaceAllString(s, "")
	// The kernel quotes the name in a `counter name "x"` statement; nftably emits
	// it bare. Unquote so both agree (the name is a validated bare identifier).
	s = reCtrName.ReplaceAllString(s, "counter name $1")
	// Kernel-default `size` on dynamic sets — both as a set-body line and stamped
	// inline into a `meter <name> size N { … }` statement — and the several
	// spellings of the rate-limit detector (`meter <name> { … }` on some nft
	// versions, `add @<name> { … }` on others) folded to one form.
	s = reSetSize.ReplaceAllString(s, "")
	s = reInlineSize.ReplaceAllString(s, " {")
	s = reMeter.ReplaceAllString(s, "add @$1 {")
	s = reQueue.ReplaceAllString(s, "queue num $1 bypass")
	// Per line: sort inline anonymous-set members (e.g. `icmp type { … }`),
	// normalize flags comma-spacing (`dynamic, timeout` → `dynamic,timeout`), and
	// drop trailing whitespace and blank lines.
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		line = reInlineSet.ReplaceAllStringFunc(line, sortBraceSet)
		if strings.HasPrefix(strings.TrimSpace(line), "flags ") {
			line = strings.ReplaceAll(line, ", ", ",")
		}
		line = strings.TrimRight(line, " \t")
		if strings.TrimSpace(line) == "" {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// sortBraceSet takes a `{ a, b, c }` fragment (possibly spanning newlines) and
// returns it on one line with members trimmed, their internal whitespace
// collapsed, and sorted. A set or verdict map has no significant element order,
// so this is loss-free for comparison.
func sortBraceSet(brace string) string {
	open := strings.Index(brace, "{")
	end := strings.LastIndex(brace, "}")
	if open < 0 || end < open {
		return brace
	}
	parts := strings.Split(brace[open+1:end], ",")
	out := parts[:0]
	for _, p := range parts {
		p = strings.Join(strings.Fields(p), " ") // trim + collapse internal ws/newlines
		if p != "" {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return "{ " + strings.Join(out, ", ") + " }"
}
