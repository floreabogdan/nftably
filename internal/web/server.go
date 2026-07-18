// Package web is nftably's embedded UI: login, a dashboard that reports the
// detected firewall backend, a read-only viewer of the live nftables ruleset, an
// iptables import preview, the rule model with its render/diff preview, plus
// settings and profile management. No frontend build step — server-rendered
// html/template pages plus a little vanilla JS.
//
// This is the M2 surface: it reads the firewall and models what it should be,
// but never writes it. The apply pipeline (atomic `nft -f` with an armed
// auto-revert, plus lint guardrails) arrives in M3 and will hang off this same
// Server.
package web

import (
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/floreabogdan/nftably/internal/nft"
	"github.com/floreabogdan/nftably/internal/store"
)

// Server is nftably's HTTP handler: it holds the store, the nft reader and the
// iptables tool paths, and serves every route.
type Server struct {
	store *store.Store
	nft   *nft.Client
	log   *slog.Logger

	// listenAddr is where nftably is bound, for the wide-open warning.
	listenAddr string

	// dataDir is where nftably may store downloaded artifacts (the optional
	// GeoIP database) — the directory holding its SQLite file.
	dataDir string

	// iptables tool paths for the coexistence probe and the import preview.
	iptablesSave       string
	ip6tablesSave      string
	iptablesBin        string
	iptablesTranslate  string
	ip6tablesTranslate string

	// login throttles failed logins per client IP.
	login *loginLimiter

	// applier is how the apply pipeline talks to nft — the concrete client in
	// production, a fake in tests. applyMu serialises everything that touches
	// the kernel table and the pending-apply record: two applies at once could
	// both pass the no-pending check and leave two "previous" snapshots.
	// pendingTimer is the armed auto-revert; guarded by applyMu.
	applier      applier
	applyMu      sync.Mutex
	pendingTimer *time.Timer

	// geo caches the optional MaxMind reader for the connections view.
	geo geoDB

	// accessMu guards accessList, the parsed access whitelist cached from
	// settings so the per-request gate never hits the database.
	accessMu   sync.RWMutex
	accessList []netip.Prefix

	mux *http.ServeMux
}

// Config is the dependency set and options New needs to build a Server.
type Config struct {
	Store              *store.Store
	Nft                *nft.Client
	Log                *slog.Logger
	ListenAddr         string
	DataDir            string
	IptablesSave       string
	Ip6tablesSave      string
	IptablesBin        string
	IptablesTranslate  string
	Ip6tablesTranslate string
	// Applier overrides how the apply pipeline reaches nft; nil uses Nft.
	// Exists so tests can drive apply/confirm/revert against a fake.
	Applier applier
}

// New builds a Server from cfg and wires up the routes.
func New(cfg Config) *Server {
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	s := &Server{
		store:              cfg.Store,
		nft:                cfg.Nft,
		log:                log,
		listenAddr:         cfg.ListenAddr,
		dataDir:            cfg.DataDir,
		iptablesSave:       cfg.IptablesSave,
		ip6tablesSave:      cfg.Ip6tablesSave,
		iptablesBin:        cfg.IptablesBin,
		iptablesTranslate:  cfg.IptablesTranslate,
		ip6tablesTranslate: cfg.Ip6tablesTranslate,
		login:              newLoginLimiter(),
		mux:                http.NewServeMux(),
	}
	if cfg.Applier != nil {
		s.applier = cfg.Applier
	} else {
		s.applier = cfg.Nft
	}
	s.routes()
	s.reloadAccess()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.accessAllowed(r) {
		// A blocked client gets no HTTP response at all: the connection is
		// closed, so a scanner cannot even tell there is a service listening.
		// Falls back to a bare 403 when the connection cannot be hijacked.
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				_ = conn.Close()
				return
			}
		}
		w.WriteHeader(http.StatusForbidden)
		return
	}
	setSecurityHeaders(w)
	if !sameOriginWrite(r) {
		http.Error(w, "cross-origin write rejected", http.StatusForbidden)
		return
	}
	s.mux.ServeHTTP(w, r)
}

// sameOriginWrite rejects browser write requests originating on another site.
// SameSite=Strict cookies and CSP form-action already cover modern browsers;
// this validates the request at the server as a separate boundary. Requests
// without browser origin headers remain supported for local CLI automation.
func sameOriginWrite(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return true
	}
	if site := strings.ToLower(r.Header.Get("Sec-Fetch-Site")); site == "cross-site" || site == "same-site" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	expectedScheme := "http"
	if r.TLS != nil {
		expectedScheme = "https"
	}
	return strings.EqualFold(u.Scheme, expectedScheme) && strings.EqualFold(u.Host, r.Host)
}

func (s *Server) routes() {
	// Public
	s.mux.HandleFunc("GET /login", s.handleLoginForm)
	s.mux.HandleFunc("POST /login", s.handleLoginSubmit)
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", staticHandler()))

	// Authenticated pages
	s.mux.Handle("GET /{$}", s.requireAuth(s.handleDashboard))
	s.mux.Handle("GET /ruleset", s.requireAuth(s.handleRuleset))
	s.mux.Handle("GET /ruleset/raw", s.requireAuth(s.handleRawRuleset))
	s.mux.Handle("GET /import", s.requireAuth(s.handleImport))
	s.mux.Handle("GET /timeline", s.requireAuth(s.handleTimeline))

	// The firewall object model: tables → chains → rules, with the typed,
	// explained rule editor. All model-only — nothing here writes to netfilter;
	// /changes renders, diffs and applies it with the armed auto-revert.
	s.mux.Handle("GET /firewall", s.requireAuth(s.handleFirewall))
	s.mux.Handle("POST /firewall/tables/new", s.requireAuth(s.handleTableCreate))
	s.mux.Handle("POST /firewall/tables/{id}/delete", s.requireAuth(s.handleTableDelete))
	s.mux.Handle("POST /firewall/tables/{id}/move", s.requireAuth(s.handleTableMove))
	s.mux.Handle("GET /firewall/tables/{id}/chains/new", s.requireAuth(s.handleChainNew))
	s.mux.Handle("POST /firewall/chains/new", s.requireAuth(s.handleChainSave))
	s.mux.Handle("GET /firewall/chains/{id}/edit", s.requireAuth(s.handleChainEdit))
	s.mux.Handle("POST /firewall/chains/{id}/edit", s.requireAuth(s.handleChainSave))
	s.mux.Handle("POST /firewall/chains/{id}/delete", s.requireAuth(s.handleChainDelete))
	s.mux.Handle("POST /firewall/chains/{id}/move", s.requireAuth(s.handleChainMove))
	s.mux.Handle("GET /firewall/chains/{id}/rules/new", s.requireAuth(s.handleRuleNew))
	s.mux.Handle("POST /firewall/chains/{id}/rules/new", s.requireAuth(s.handleRuleSave))
	s.mux.Handle("POST /firewall/rules/preview", s.requireAuth(s.handleRulePreview))
	s.mux.Handle("GET /firewall/rules/{id}/edit", s.requireAuth(s.handleRuleEditGet))
	s.mux.Handle("POST /firewall/rules/{id}/edit", s.requireAuth(s.handleRuleSave))
	s.mux.Handle("POST /firewall/rules/{id}/delete", s.requireAuth(s.handleRuleDelete))
	s.mux.Handle("POST /firewall/rules/{id}/toggle", s.requireAuth(s.handleRuleToggle))
	s.mux.Handle("POST /firewall/rules/{id}/move", s.requireAuth(s.handleRuleMove))
	s.mux.Handle("GET /changes", s.requireAuth(s.handleChanges))

	// Simulate: trace a synthetic packet through the candidate model (no kernel).
	s.mux.Handle("GET /simulate", s.requireAuth(s.handleSimulate))
	s.mux.Handle("POST /simulate", s.requireAuth(s.handleSimulateRun))

	// Presets: one-click best-practice starting points (BGP router, secure server).
	s.mux.Handle("GET /presets", s.requireAuth(s.handlePresets))
	s.mux.Handle("POST /presets/apply", s.requireAuth(s.handlePresetApply))

	// The apply pipeline: load into the kernel with an armed auto-revert.
	s.mux.Handle("POST /apply", s.requireAuth(s.handleApply))
	s.mux.Handle("POST /apply/confirm", s.requireAuth(s.handleApplyConfirm))
	s.mux.Handle("POST /apply/rollback", s.requireAuth(s.handleApplyRollback))

	// Connections: the live conntrack view with one-click block.
	s.mux.Handle("GET /connections", s.requireAuth(s.handleConnections))

	// Named address lists: as many as the operator wants, each either a
	// plain address group (rules source from it) or with instant behaviour
	// (allow-all / block-all). Plus the one-click block endpoint the
	// connections view posts to.
	s.mux.Handle("GET /lists", s.requireAuth(s.handleLists))
	s.mux.Handle("POST /lists/create", s.requireAuth(s.handleListCreate))
	s.mux.Handle("GET /lists/{id}", s.requireAuth(s.handleListDetail))
	s.mux.Handle("POST /lists/{id}/update", s.requireAuth(s.handleListUpdate))
	s.mux.Handle("POST /lists/{id}/delete", s.requireAuth(s.handleListDelete))
	s.mux.Handle("POST /lists/{id}/entries", s.requireAuth(s.handleListEntryAdd))
	s.mux.Handle("POST /lists/entries/{id}/delete", s.requireAuth(s.handleListEntryDelete))
	s.mux.Handle("POST /lists/block", s.requireAuth(s.handleQuickBlock))

	// The advisor (detect what runs on the box, suggest rules) is temporarily
	// unlinked while it is re-pointed at the new object model — its handlers
	// remain but are not routed.

	s.mux.Handle("GET /settings", s.requireAuth(s.handleSettingsPage))
	s.mux.Handle("POST /settings/identity", s.requireAuth(s.handleSettingsIdentity))
	s.mux.Handle("POST /settings/access", s.requireAuth(s.handleSettingsAccess))
	s.mux.Handle("POST /settings/geoip", s.requireAuth(s.handleSettingsGeoIP))
	s.mux.Handle("POST /settings/geoip/download", s.requireAuth(s.handleGeoIPDownload))

	s.mux.Handle("GET /profile", s.requireAuth(s.handleProfilePage))
	s.mux.Handle("POST /profile/identity", s.requireAuth(s.handleProfileIdentity))
	s.mux.Handle("POST /profile/password", s.requireAuth(s.handleProfilePassword))
	s.mux.Handle("POST /logout", s.requireAuth(s.handleLogout))

	// Authenticated JSON API — the topbar's nft-status dot.
	s.mux.Handle("GET /api/status", s.requireAuth(s.apiStatus))
}

// reloadAccess refreshes the cached access whitelist from settings. Called at
// startup and whenever the whitelist is edited.
func (s *Server) reloadAccess() {
	var list []netip.Prefix
	if settings, ok, err := s.store.GetSettings(); err == nil && ok {
		list, _ = store.ParseAccessWhitelist(settings.AccessWhitelist)
	}
	s.accessMu.Lock()
	s.accessList = list
	s.accessMu.Unlock()
}

func (s *Server) accessAllowed(r *http.Request) bool {
	ip := clientAddr(r)
	if !ip.IsValid() {
		return false // a malformed peer address must not bypass the allow-list
	}
	s.accessMu.RLock()
	defer s.accessMu.RUnlock()
	return store.AccessAllowed(s.accessList, ip)
}

// WideOpen reports whether nftably is reachable from any IP with no access
// restriction — the fresh-install default, worth warning about once at startup.
func (s *Server) WideOpen() bool {
	if host, _, err := net.SplitHostPort(s.listenAddr); err == nil {
		if host == "localhost" {
			return false // loopback-only: nothing off-box can reach it
		}
		if ip, err := netip.ParseAddr(host); err == nil && ip.IsLoopback() {
			return false
		}
	}
	s.accessMu.RLock()
	defer s.accessMu.RUnlock()
	return !store.AccessRestricted(s.accessList)
}

// clientAddr is the request's real TCP peer address — never a spoofable
// X-Forwarded-For header, since nftably is reached directly or over an SSH
// tunnel, not behind a proxy.
func clientAddr(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap()
}

// setSecurityHeaders hardens every response. nftably serves only its own
// embedded assets and is never framed, so the policy can be tight: no external
// resource loads, no framing, forms post only to nftably itself, and scripts
// must be loaded from embedded static assets. Styles retain inline support
// because a few compact layout values are data-driven style attributes.
func setSecurityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "same-origin")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
	h.Set("Content-Security-Policy",
		"default-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; "+
			"frame-ancestors 'none'; img-src 'self' data:; "+
			"style-src 'self' 'unsafe-inline'; script-src 'self'")
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}
