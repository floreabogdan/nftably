package web

import (
	"net"
	"net/http"
	"net/url"
	"strconv"

	"github.com/floreabogdan/nftably/internal/store"
)

// ownListenPort is nftably's own TCP port, parsed from its listen address; 0
// when loopback-bound or unparsable. Presets use it to allow the UI from the
// management set.
func (s *Server) ownListenPort() int {
	_, portStr, err := net.SplitHostPort(s.listenAddr)
	if err != nil {
		return 0
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0
	}
	return port
}

// audit records an operator action on the event timeline, attributed to the
// logged-in user. Best-effort: a failed audit write never blocks the action.
func (s *Server) audit(r *http.Request, message string) {
	_ = s.store.InsertAudit(s.currentUser(r).Username, store.EventModelChange, message)
}

// itoa is the compact int64→string used throughout the handlers for row ids in
// URLs and form values.
func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// urlEscape encodes a value for a query string (used for ?err= flash messages).
func urlEscape(s string) string { return url.QueryEscape(s) }

// serverError logs the real cause and shows the user a generic message. SQL
// text and file paths are for the journal, not the browser.
func (s *Server) serverError(w http.ResponseWriter, what string, err error) {
	s.log.Error(what, "error", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// currentUserID returns the logged-in user's id from the request context, set
// by requireAuth.
func currentUserID(r *http.Request) int64 {
	id, _ := r.Context().Value(ctxUserID).(int64)
	return id
}

// currentUser looks up the logged-in user. On any failure it returns a zero
// User — callers use it only for display (the username in the top bar), so a
// blank there is harmless, never a security decision.
func (s *Server) currentUser(r *http.Request) store.User {
	u, _, err := s.store.GetUserByID(currentUserID(r))
	if err != nil {
		s.log.Warn("current user lookup failed", "error", err)
	}
	return u
}

// nav is the shared header data every authenticated page needs: which sidebar
// item is active, the router label, and the logged-in username for the avatar.
type nav struct {
	Active      string
	RouterLabel string
	Username    string
}

func (s *Server) navFor(r *http.Request, active string) nav {
	n := nav{Active: active, Username: s.currentUser(r).Username}
	if st, ok, err := s.store.GetSettings(); err == nil && ok {
		n.RouterLabel = st.RouterLabel
	}
	return n
}

// tabParam returns the requested ?tab= value if it is one of the allowed tabs,
// otherwise the first allowed tab (the default). Used by pages with a tabbed
// layout so a bad or missing value lands on a sensible default.
func tabParam(r *http.Request, allowed ...string) string {
	want := r.URL.Query().Get("tab")
	for _, a := range allowed {
		if a == want {
			return a
		}
	}
	return allowed[0]
}
