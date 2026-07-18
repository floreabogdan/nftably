package render

import (
	"fmt"
	"strings"

	"github.com/floreabogdan/nftably/internal/store"
)

// BuildApplyFile wraps the owned tables in one atomic `nft -f` transaction. For
// each table nftably owns it emits the idempotent replace triple:
//
//	table <fam> <name> {}       ensure it exists (so the delete is always valid)
//	delete table <fam> <name>   drop the old contents
//	table <fam> <name> { … }    the candidate
//
// and, for each table the operator has deleted since the last apply, just the
// ensure+delete pair. The whole file commits as a single netfilter transaction,
// so there is never a moment where the box runs half a firewall — and tables
// nftably does not own are never named, so they are never touched.
func BuildApplyFile(tables []TableTree, remove []store.TableRef) string {
	var b strings.Builder
	for _, t := range tables {
		writeReplace(&b, t.Family, t.Name)
		b.WriteString(TableConfig(t))
	}
	for _, ref := range remove {
		writeReplace(&b, ref.Family, ref.Name)
	}
	return b.String()
}

// BuildRevertFile is the inverse: restore every captured table to exactly its
// pre-apply state. A snapshot that did not exist before is left deleted (the
// ensure+delete removes the table nftably created); one that existed is
// recreated from its captured text.
func BuildRevertFile(snaps []store.TableSnapshot) string {
	var b strings.Builder
	for _, s := range snaps {
		writeReplace(&b, s.Family, s.Name)
		if s.Exists {
			b.WriteString(s.Text)
			if !strings.HasSuffix(s.Text, "\n") {
				b.WriteString("\n")
			}
		}
	}
	return b.String()
}

// writeReplace emits the ensure-exists + delete pair for one table.
func writeReplace(b *strings.Builder, family, name string) {
	fmt.Fprintf(b, "table %s %s {}\n", family, name)
	fmt.Fprintf(b, "delete table %s %s\n", family, name)
}
