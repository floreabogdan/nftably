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

// BuildBootFile is the apply file as a standalone script for the system's
// nftables unit to load at boot, so a reboot comes back to the confirmed
// ruleset instead of an empty one.
//
// It is the same ensure+delete+create triple as BuildApplyFile, which is what
// makes it safe to run against a kernel that already has tables: only the tables
// nftably owns are named, so a `flush ruleset` — which would take Docker's and
// everyone else's tables with it — is never needed. Deleted tables are left out;
// at boot they do not exist to begin with.
func BuildBootFile(tables []TableTree, nftBin, stamp string) string {
	var b strings.Builder
	if nftBin == "" {
		nftBin = "/usr/sbin/nft"
	}
	fmt.Fprintf(&b, "#!%s -f\n", nftBin)
	b.WriteString("#\n# Managed by nftably — rewritten after every confirmed apply.\n")
	b.WriteString("# Edits here are lost; change the rules in nftably instead.\n")
	if stamp != "" {
		fmt.Fprintf(&b, "# %s\n", stamp)
	}
	b.WriteString("#\n")
	b.WriteString(BuildApplyFile(tables, nil))
	return b.String()
}

// BootFileMarker appears in every file BuildBootFile writes. nftably looks for
// it before overwriting a path, so a hand-written ruleset is backed up once
// rather than silently replaced.
const BootFileMarker = "Managed by nftably"

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
