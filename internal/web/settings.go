package web

import (
	"net/http"
	"strings"

	"github.com/floreabogdan/nftably/internal/store"
)

type settingsVM struct {
	nav
	Settings   store.Settings
	WideOpen   bool
	AccessErrs []string
	Saved      string // which section was just saved, for the success banner
}

func (s *Server) handleSettingsPage(w http.ResponseWriter, r *http.Request) {
	s.renderSettings(w, r, "", nil)
}

func (s *Server) renderSettings(w http.ResponseWriter, r *http.Request, saved string, accessErrs []string) {
	st, _, err := s.store.GetSettings()
	if err != nil {
		s.serverError(w, "get settings", err)
		return
	}
	render(w, s.log, "settings.html", settingsVM{
		nav:        s.navFor(r, "settings"),
		Settings:   st,
		WideOpen:   s.WideOpen(),
		AccessErrs: accessErrs,
		Saved:      saved,
	})
}

func (s *Server) handleSettingsIdentity(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	st, _, err := s.store.GetSettings()
	if err != nil {
		s.serverError(w, "get settings", err)
		return
	}
	st.RouterLabel = strings.TrimSpace(r.FormValue("router_label"))
	st.ListenAddr = strings.TrimSpace(r.FormValue("listen_addr"))
	st.NftBinary = strings.TrimSpace(r.FormValue("nft_binary"))
	if err := s.store.SaveSettings(st); err != nil {
		s.serverError(w, "save settings", err)
		return
	}
	_ = s.store.InsertAudit(s.currentUser(r).Username, store.EventSettings, "updated identity settings")
	s.renderSettings(w, r, "identity", nil)
}

func (s *Server) handleSettingsGeoIP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if err := s.store.SaveGeoIPDB(strings.TrimSpace(r.FormValue("geoip_db"))); err != nil {
		s.serverError(w, "save geoip db", err)
		return
	}
	_ = s.store.InsertAudit(s.currentUser(r).Username, store.EventSettings, "updated GeoIP database path")
	s.renderSettings(w, r, "geoip", nil)
}

func (s *Server) handleSettingsAccess(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	text := r.FormValue("access_whitelist")
	// Validate before saving so a typo can't silently lock the operator out.
	if _, errs := store.ParseAccessWhitelist(text); len(errs) > 0 {
		s.renderSettings(w, r, "", errs)
		return
	}
	if err := s.store.SaveAccessWhitelist(text); err != nil {
		s.serverError(w, "save access whitelist", err)
		return
	}
	s.reloadAccess()
	_ = s.store.InsertAudit(s.currentUser(r).Username, store.EventSettings, "updated access whitelist")
	s.renderSettings(w, r, "access", nil)
}
