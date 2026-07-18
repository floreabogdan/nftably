package web

import (
	"net/http"

	"github.com/floreabogdan/nftably/internal/klog"
)

// The /logs surface: the packets your rules with a Log action have logged, read
// from the kernel ring buffer. Read-only and best-effort — a note explains when
// the log can't be read (not Linux, no privilege) rather than erroring.

type logsVM struct {
	nav
	Entries []klog.Entry
	Note    string
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	entries, note := klog.Read()
	render(w, s.log, "logs.html", logsVM{
		nav:     s.navFor(r, "logs"),
		Entries: entries,
		Note:    note,
	})
}
