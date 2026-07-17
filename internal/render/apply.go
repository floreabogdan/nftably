package render

import "strings"

// BuildApplyFile wraps a rendered table in the transaction that atomically
// replaces the previous one. The empty declaration first makes the delete
// always valid (delete of a missing table is an error, create-if-absent is
// not), so the same file works on first apply and on every one after:
//
//	table inet nftably {}       ensure it exists
//	delete table inet nftably   drop the old contents
//	table inet nftably { ... }  the candidate
//
// `nft -f` commits the whole file as one netfilter transaction — there is no
// moment where the box is running half a firewall.
func BuildApplyFile(candidate string) string {
	var b strings.Builder
	b.WriteString("table inet " + TableName + " {}\n")
	b.WriteString("delete table inet " + TableName + "\n")
	b.WriteString(candidate)
	return b.String()
}

// BuildRevertFile is the inverse: restore the pre-apply state. prevTable is
// the `nft list table inet nftably` output captured before the apply, empty
// with prevExisted=false when the table was not there at all — in which case
// the revert simply removes the table nftably created.
func BuildRevertFile(prevTable string, prevExisted bool) string {
	var b strings.Builder
	b.WriteString("table inet " + TableName + " {}\n")
	b.WriteString("delete table inet " + TableName + "\n")
	if prevExisted {
		b.WriteString(prevTable)
		if !strings.HasSuffix(prevTable, "\n") {
			b.WriteString("\n")
		}
	}
	return b.String()
}
