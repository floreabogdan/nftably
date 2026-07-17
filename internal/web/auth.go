package web

import (
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const sessionTTL = 7 * 24 * time.Hour

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
	if !ok || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		s.login.fail(ip)
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

// loginLimiter throttles failed logins per client IP: after maxFails within the
// window, that IP is blocked until the window elapses. A success resets it.
type loginLimiter struct {
	mu    sync.Mutex
	fails map[string]*failState
}

type failState struct {
	count int
	until time.Time
}

const (
	maxFails    = 5
	failWindow  = 5 * time.Minute
	blockWindow = 5 * time.Minute
)

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{fails: map[string]*failState{}}
}

func (l *loginLimiter) blocked(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.fails[ip]
	return f != nil && f.count >= maxFails && time.Now().Before(f.until)
}

func (l *loginLimiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.fails[ip]
	now := time.Now()
	if f == nil || now.After(f.until) {
		f = &failState{}
		l.fails[ip] = f
	}
	f.count++
	f.until = now.Add(blockWindow)
}

func (l *loginLimiter) reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, ip)
}
