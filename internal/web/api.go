package web

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/floreabogdan/nftably/internal/store"
)

// api.go is nftably's small automation API: token-authenticated endpoints to
// manage the blacklist programmatically — an external IDS, a threat-intel feed,
// or a script. It's model-consistent: a blocked address goes into the
// "blacklist" named set and takes effect on the next apply, behind the same
// armed auto-revert as every other change. Off unless an API token is set.

func (s *Server) apiToken() string {
	if st, ok, err := s.store.GetSettings(); err == nil && ok {
		return st.APIToken
	}
	return ""
}

// apiGuard runs h only when the API is enabled and the request carries the right
// bearer token; otherwise 404 (feature off, so it isn't even advertised) or 401.
func (s *Server) apiGuard(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := s.apiToken()
		if token == "" {
			http.NotFound(w, r)
			return
		}
		if !metricsAuthorized(r, token) { // same constant-time bearer check
			w.Header().Set("WWW-Authenticate", "Bearer")
			apiJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		h(w, r)
	}
}

func apiJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// apiBody reads ip and note from a JSON body or a form-encoded request.
func apiBody(r *http.Request) (ip, note string) {
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var b struct{ IP, Note string }
		_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&b)
		return strings.TrimSpace(b.IP), strings.TrimSpace(b.Note)
	}
	_ = r.ParseForm()
	return strings.TrimSpace(r.FormValue("ip")), strings.TrimSpace(r.FormValue("note"))
}

// handleAPIBlock adds an address/CIDR to the blacklist named set.
func (s *Server) handleAPIBlock(w http.ResponseWriter, r *http.Request) {
	ip, note := apiBody(r)
	norm, msg := store.NormalizeCIDR(ip)
	if msg != "" {
		apiJSON(w, http.StatusBadRequest, map[string]any{"error": msg})
		return
	}
	if note == "" {
		note = "blocked via API"
	}
	bl, err := s.blockList()
	if err != nil {
		apiJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not open the block list"})
		return
	}
	if err := s.store.AddListEntry(bl.ID, norm, note); err != nil {
		if errors.Is(err, store.ErrOverlap) {
			apiJSON(w, http.StatusOK, map[string]any{"blocked": norm, "already": true})
			return
		}
		apiJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	_ = s.store.InsertAudit("api", store.EventModelChange, "API blocked "+norm)
	apiJSON(w, http.StatusOK, map[string]any{"blocked": norm, "note": "takes effect on the next apply"})
}

// handleAPIUnblock removes an address from the blacklist named set.
func (s *Server) handleAPIUnblock(w http.ResponseWriter, r *http.Request) {
	ip, _ := apiBody(r)
	norm, msg := store.NormalizeCIDR(ip)
	if msg != "" {
		apiJSON(w, http.StatusBadRequest, map[string]any{"error": msg})
		return
	}
	l, err := s.store.GetListByName(blockListName)
	if err != nil {
		apiJSON(w, http.StatusOK, map[string]any{"unblocked": false, "reason": "no block list"})
		return
	}
	entries, err := s.store.ListEntries(l.ID)
	if err != nil {
		apiJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	for _, e := range entries {
		if e.CIDR == norm {
			if err := s.store.DeleteListEntry(e.ID); err != nil {
				apiJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
				return
			}
			_ = s.store.InsertAudit("api", store.EventModelChange, "API unblocked "+norm)
			apiJSON(w, http.StatusOK, map[string]any{"unblocked": norm})
			return
		}
	}
	apiJSON(w, http.StatusOK, map[string]any{"unblocked": false, "reason": "not in the block list"})
}

// handleAPIBlocked returns the current blacklist entries.
func (s *Server) handleAPIBlocked(w http.ResponseWriter, r *http.Request) {
	out := []map[string]string{}
	if l, err := s.store.GetListByName(blockListName); err == nil {
		entries, _ := s.store.ListEntries(l.ID)
		for _, e := range entries {
			out = append(out, map[string]string{"ip": e.CIDR, "note": e.Note})
		}
	}
	apiJSON(w, http.StatusOK, map[string]any{"blocked": out})
}
