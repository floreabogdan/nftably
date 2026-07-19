package web

import "testing"

func TestCappedBatchSummarizesStorm(t *testing.T) {
	mk := func(n int) []alertItem {
		out := make([]alertItem, n)
		for i := range out {
			out[i] = alertItem{subject: "s", message: "m"}
		}
		return out
	}
	// Under the cap: everything passes through, no summary.
	if got := cappedBatch(mk(3), "banned"); len(got) != 3 {
		t.Errorf("3 items -> %d, want 3", len(got))
	}
	if got := cappedBatch(mk(maxPerBatch), "banned"); len(got) != maxPerBatch {
		t.Errorf("exactly-cap items -> %d, want %d (no summary)", len(got), maxPerBatch)
	}
	// Over the cap: maxPerBatch individuals + one summary.
	got := cappedBatch(mk(50), "banned")
	if len(got) != maxPerBatch+1 {
		t.Fatalf("50 items -> %d, want %d", len(got), maxPerBatch+1)
	}
	last := got[len(got)-1]
	if last.subject != "" || last.message == "" {
		t.Errorf("last item should be the summary: %+v", last)
	}
}
