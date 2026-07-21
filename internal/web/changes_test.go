package web

import (
	"testing"

	nftconf "github.com/floreabogdan/nftably/internal/render"
)

// TestTruncateDiff guards the large-set safeguard: a normal diff passes through
// untouched, but one bigger than the cap is trimmed to the cap with the overflow
// reported — so a refreshed blocklist can't produce a browser-stalling diff.
func TestTruncateDiff(t *testing.T) {
	hunk := func(n int) nftconf.Hunk { return nftconf.Hunk{Lines: make([]nftconf.DiffLine, n)} }

	small := []nftconf.Hunk{hunk(5), hunk(5)}
	got, omitted := truncateDiff(small, maxDiffLines)
	if omitted != 0 || len(got) != 2 {
		t.Fatalf("a small diff must pass through untouched: omitted=%d hunks=%d", omitted, len(got))
	}

	big := []nftconf.Hunk{hunk(maxDiffLines - 50), hunk(200)} // 150 lines over the cap
	got, omitted = truncateDiff(big, maxDiffLines)
	kept := 0
	for _, h := range got {
		kept += len(h.Lines)
	}
	if kept != maxDiffLines || omitted != 150 {
		t.Fatalf("want %d kept / 150 omitted, got %d/%d", maxDiffLines, kept, omitted)
	}
}
