package web

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/floreabogdan/nftably/internal/nft"
	"github.com/floreabogdan/nftably/internal/store"
)

type settingsVM struct {
	nav
	Tab        string // active tab: general | access | geoip | metrics | import
	Settings   store.Settings
	WideOpen   bool
	AccessErrs []string
	Saved      string // which section was just saved, for the success banner
	GeoIPErr   string // a GeoIP download failure, shown in the GeoIP section
	// GeoIP database status for the page.
	GeoIPManaged bool      // is the configured path nftably's own managed download?
	GeoIPExists  bool      // does the configured file exist on disk?
	GeoIPModTime time.Time // when the configured file was last written
	CanDownload  bool      // nftably has a writable data dir to download into
	// Import tab: the iptables coexistence report and the nft translation.
	Iptables nft.IptablesReport
	Blocks   []translateBlock
	// Alerts tab: the configured delivery destinations, and a flash from a test.
	Destinations []store.Destination
	Flash        string
	FlashErr     string
	// Backup tab: scheduled-backup state and the on-disk snapshots.
	BackupAuto  bool
	BackupDirOK bool
	AutoBackups []autoBackupFile
}

// settingsTabs are the settings tab keys in display order; the first is the
// default when no (or an unknown) ?tab= is given.
var settingsTabs = []string{"general", "access", "geoip", "metrics", "import", "backup", "alerts", "theme"}

// savedTab maps a just-saved section to the tab it lives on, so a save banner
// shows on the right tab.
var savedTab = map[string]string{
	"identity": "general", "access": "access",
	"geoip": "geoip", "geoip-download": "geoip", "metrics": "metrics",
	"backup": "backup",
}

func (s *Server) handleSettingsPage(w http.ResponseWriter, r *http.Request) {
	s.renderSettings(w, r, "", nil, "")
}

func (s *Server) renderSettings(w http.ResponseWriter, r *http.Request, saved string, accessErrs []string, geoErr string) {
	st, _, err := s.store.GetSettings()
	if err != nil {
		s.serverError(w, "get settings", err)
		return
	}
	vm := settingsVM{
		nav:         s.navFor(r, "settings"),
		Tab:         tabParam(r, settingsTabs...),
		Settings:    st,
		WideOpen:    s.WideOpen(),
		AccessErrs:  accessErrs,
		Saved:       saved,
		GeoIPErr:    geoErr,
		CanDownload: s.managedGeoIPPath() != "",
	}
	// Alerts tab: the configured destinations, and a flash from a "Test" click
	// (carried on the redirect query, not the save path).
	vm.Destinations, _ = s.store.ListAlertDestinations()
	vm.BackupAuto = st.BackupAuto
	vm.BackupDirOK = s.backupDir() != ""
	vm.AutoBackups = s.listAutoBackups()
	if m := r.URL.Query().Get("saved"); m != "" && saved == "" {
		vm.Flash = m
	}
	if m := r.URL.Query().Get("err"); m != "" {
		vm.FlashErr = m
		vm.Tab = "alerts"
	}
	// After a save (or an error), show the relevant tab rather than dropping the
	// operator back to the default one — a click shouldn't move them off the tab
	// they acted on.
	if t, ok := savedTab[saved]; ok {
		vm.Tab = t
	} else if len(accessErrs) > 0 {
		vm.Tab = "access"
	} else if geoErr != "" {
		vm.Tab = "geoip"
	}
	vm.GeoIPManaged = st.GeoIPDB != "" && st.GeoIPDB == s.managedGeoIPPath()
	if st.GeoIPDB != "" {
		if fi, err := os.Stat(st.GeoIPDB); err == nil {
			vm.GeoIPExists = true
			vm.GeoIPModTime = fi.ModTime()
		}
	}
	// Import tab data: the live iptables coexistence report, plus an nft
	// translation when there's actually something to import. Computed here so the
	// tab is ready for client-side switching without a reload.
	ctx, cancel := reqCtx(r)
	defer cancel()
	vm.Iptables = nft.ProbeIptables(ctx, s.iptablesSave, s.ip6tablesSave, s.iptablesBin)
	if vm.Iptables.V4Rules > 0 {
		b := translateBlock{Family: "IPv4"}
		if txt, err := nft.TranslateIptables(ctx, s.iptablesSave, s.iptablesTranslate); err != nil {
			b.Err = err.Error()
		} else {
			b.Text = txt
		}
		vm.Blocks = append(vm.Blocks, b)
	}
	if vm.Iptables.V6Rules > 0 {
		b := translateBlock{Family: "IPv6"}
		if txt, err := nft.TranslateIptables(ctx, s.ip6tablesSave, s.ip6tablesTranslate); err != nil {
			b.Err = err.Error()
		} else {
			b.Text = txt
		}
		vm.Blocks = append(vm.Blocks, b)
	}
	render(w, s.log, "settings.html", vm)
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
	s.renderSettings(w, r, "identity", nil, "")
}

func (s *Server) handleSettingsGeoIP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	path := strings.TrimSpace(r.FormValue("geoip_db"))
	autoUpdate := r.FormValue("geoip_autoupdate") == "on"
	if err := s.store.SaveGeoIP(path, autoUpdate); err != nil {
		s.serverError(w, "save geoip", err)
		return
	}
	_ = s.store.InsertAudit(s.currentUser(r).Username, store.EventSettings, "updated GeoIP settings")
	s.renderSettings(w, r, "geoip", nil, "")
}

// handleGeoIPDownload fetches the free DB-IP Lite country database on the
// operator's explicit request and points nftably at it. This is the only path
// that makes nftably reach the network, and it runs only when this button is
// clicked (or the opt-in monthly refresh fires).
func (s *Server) handleGeoIPDownload(w http.ResponseWriter, r *http.Request) {
	path, err := s.downloadGeoIP(r.Context())
	if err != nil {
		s.renderSettings(w, r, "", nil, "Download failed: "+err.Error())
		return
	}
	// Keep whatever auto-update choice is already set; just point at the file.
	if err := s.store.SaveGeoIPDB(path); err != nil {
		s.serverError(w, "save geoip db", err)
		return
	}
	_ = s.store.InsertAudit(s.currentUser(r).Username, store.EventSettings, "downloaded the DB-IP Lite country database")
	s.renderSettings(w, r, "geoip-download", nil, "")
}

// handleSettingsMetrics sets, generates or clears the Prometheus /metrics bearer
// token. An empty token disables the endpoint; "generate" mints a fresh random
// one server-side (no inline JS under the strict CSP).
func (s *Server) handleSettingsMetrics(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	token := strings.TrimSpace(r.FormValue("metrics_token"))
	if r.FormValue("generate") == "1" {
		tok, err := randomToken()
		if err != nil {
			s.serverError(w, "generate metrics token", err)
			return
		}
		token = tok
	}
	if err := s.store.SaveMetricsToken(token); err != nil {
		s.serverError(w, "save metrics token", err)
		return
	}
	action := "set the Prometheus metrics token"
	if token == "" {
		action = "disabled the Prometheus metrics endpoint"
	}
	_ = s.store.InsertAudit(s.currentUser(r).Username, store.EventSettings, action)
	s.renderSettings(w, r, "metrics", nil, "")
}

// handleSettingsAPI generates, sets or clears the automation-API bearer token.
func (s *Server) handleSettingsAPI(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	token := strings.TrimSpace(r.FormValue("api_token"))
	if r.FormValue("generate") == "1" {
		tok, err := randomToken()
		if err != nil {
			s.serverError(w, "generate api token", err)
			return
		}
		token = tok
	}
	if err := s.store.SaveAPIToken(token); err != nil {
		s.serverError(w, "save api token", err)
		return
	}
	action := "set the automation-API token"
	if token == "" {
		action = "disabled the automation API"
	}
	_ = s.store.InsertAudit(s.currentUser(r).Username, store.EventSettings, action)
	s.renderSettings(w, r, "metrics", nil, "")
}

// randomToken returns a URL-safe 32-byte random token for /metrics bearer auth.
func randomToken() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func (s *Server) handleSettingsAccess(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	text := r.FormValue("access_whitelist")
	// Validate before saving so a typo can't silently lock the operator out.
	if _, errs := store.ParseAccessWhitelist(text); len(errs) > 0 {
		s.renderSettings(w, r, "", errs, "")
		return
	}
	if err := s.store.SaveAccessWhitelist(text); err != nil {
		s.serverError(w, "save access whitelist", err)
		return
	}
	s.reloadAccess()
	_ = s.store.InsertAudit(s.currentUser(r).Username, store.EventSettings, "updated access whitelist")
	s.renderSettings(w, r, "access", nil, "")
}
