package web

import (
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/floreabogdan/nftably/internal/store"
	"golang.org/x/crypto/bcrypt"
)

const sessionTTL = 7 * 24 * time.Hour

// dummyPasswordHash is a valid bcrypt hash the login path compares against when
// the username does not exist, so an unknown-user attempt costs the same time as
// a wrong-password one (defeats username enumeration by response timing).
var dummyPasswordHash, _ = bcrypt.GenerateFromPassword([]byte("nftably-login-timing-equalizer"), bcrypt.DefaultCost)

func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	// Already logged in? go straight to the dashboard.
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		if _, ok, _ := s.store.GetSession(cookie.Value); ok {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}
	render(w, s.log, "login.html", map[string]any{"Error": r.URL.Query().Get("error")})
}

func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/login?error=1", http.StatusSeeOther)
		return
	}
	ip := clientIP(r)
	if s.login.blocked(ip) {
		http.Redirect(w, r, "/login?error=locked", http.StatusSeeOther)
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")

	user, ok, err := s.store.GetUserByUsername(username)
	if err != nil {
		s.log.Error("login lookup failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Always run bcrypt, even when the username is unknown, comparing against a
	// fixed dummy hash. Skipping the compare for a missing user would make a
	// bad-username response measurably faster than a bad-password one and leak
	// which usernames exist.
	hash := dummyPasswordHash
	if ok {
		hash = []byte(user.PasswordHash)
	}
	if bcrypt.CompareHashAndPassword(hash, []byte(password)) != nil || !ok {
		if s.login.fail(ip) {
			s.notifier.Notify(store.AlertLoginFailed, ip, "Repeated failed logins to nftably — that source is now locked out.")
		}
		http.Redirect(w, r, "/login?error=1", http.StatusSeeOther)
		return
	}
	s.login.reset(ip)

	token, err := newSessionToken()
	if err != nil {
		s.log.Error("failed to generate session token", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.store.CreateSession(token, user.ID, time.Now().Add(sessionTTL)); err != nil {
		s.log.Error("failed to create session", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	setSessionCookie(w, token, r.TLS != nil)
	_ = s.store.InsertAudit(user.Username, "login", "signed in")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		if err := s.store.DeleteSession(cookie.Value); err != nil {
			s.log.Warn("failed to delete session", "error", err)
		}
	}
	clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func newSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashPassword is used by `nftably init` and the password-change flow.
func HashPassword(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(h), err
}

// clientIP is the request's peer IP as a string, for the login limiter.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// loginLimiter throttles failed logins per client IP. Keying on the IP, not the
// username, matters: a username lockout would let anyone lock the real admin out
// by failing logins on purpose. An attacker only ever locks out themselves.
type loginLimiter struct {
	mu        sync.Mutex
	byIP      map[string]*attemptRecord
	max       int           // failures allowed before a lockout
	window    time.Duration // failures older than this are forgotten
	lockout   time.Duration // how long a locked-out IP stays out
	lastPrune time.Time     // when the full expiry sweep last ran
}

// limiterSweepInterval bounds how often the O(n) expiry sweep runs. Between
// sweeps the limiter's per-attempt cost is O(1), so a botnet cycling source
// addresses cannot turn every login into a full-map walk.
const limiterSweepInterval = time.Minute

type attemptRecord struct {
	count int
	first time.Time
	until time.Time // lockout expiry, zero when not locked
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{byIP: map[string]*attemptRecord{}, max: 5, window: 15 * time.Minute, lockout: 5 * time.Minute}
}

// maxLoginLimiterEntries bounds the limiter's memory: a botnet cycling source
// addresses must not grow the map without limit.
const maxLoginLimiterEntries = 4096

// prune sweeps expired records. The sweep is O(n), so it runs at most once per
// limiterSweepInterval; the hard entry cap is enforced separately, at insert
// time, so memory stays bounded between sweeps too.
func (l *loginLimiter) prune(now time.Time) {
	if now.Sub(l.lastPrune) < limiterSweepInterval {
		return
	}
	l.lastPrune = now
	for ip, rec := range l.byIP {
		if now.Sub(rec.first) > l.window && !now.Before(rec.until) {
			delete(l.byIP, ip)
		}
	}
}

// evictIfFull makes room for a new IP when the map is at capacity — a
// bounded-memory backstop under a source-cycling flood. It drops the first entry
// it encounters (preferring an expired one); forgetting a single best-effort
// lockout early is acceptable, and this stays O(1) rather than scanning for the
// true oldest on every attempt.
func (l *loginLimiter) evictIfFull(newIP string, now time.Time) {
	if len(l.byIP) < maxLoginLimiterEntries {
		return
	}
	if _, exists := l.byIP[newIP]; exists {
		return // replacing an existing key — no growth
	}
	for ip, rec := range l.byIP {
		if now.Sub(rec.first) > l.window && !now.Before(rec.until) {
			delete(l.byIP, ip) // an expired entry: the ideal victim
			return
		}
		delete(l.byIP, ip) // otherwise drop the first arbitrary entry
		return
	}
}

// blocked reports whether this IP is currently locked out.
func (l *loginLimiter) blocked(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune(time.Now())
	rec := l.byIP[ip]
	return rec != nil && time.Now().Before(rec.until)
}

// fail records a failed attempt and locks the IP out once it passes the limit.
func (l *loginLimiter) fail(ip string) (justLocked bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.prune(now)
	rec := l.byIP[ip]
	if rec == nil || now.Sub(rec.first) > l.window {
		l.evictIfFull(ip, now)
		rec = &attemptRecord{first: now}
		l.byIP[ip] = rec
	}
	rec.count++
	if rec.count >= l.max {
		rec.until = now.Add(l.lockout)
	}
	// True exactly on the transition to locked-out, so a caller can alert once.
	return rec.count == l.max
}

// reset clears an IP's record after a successful login.
func (l *loginLimiter) reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.byIP, ip)
}
