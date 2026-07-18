package web

import (
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

type profileVM struct {
	nav
	Username string
	Saved    string
	Error    string
}

func (s *Server) handleProfilePage(w http.ResponseWriter, r *http.Request) {
	s.renderProfile(w, r, "", "")
}

func (s *Server) renderProfile(w http.ResponseWriter, r *http.Request, saved, errMsg string) {
	render(w, s.log, "profile.html", profileVM{
		nav:      s.navFor(r, "profile"),
		Username: s.currentUser(r).Username,
		Saved:    saved,
		Error:    errMsg,
	})
}

func (s *Server) handleProfileIdentity(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	if username == "" {
		s.renderProfile(w, r, "", "Username cannot be empty.")
		return
	}
	if err := s.store.SetUsername(currentUserID(r), username); err != nil {
		// The username column is UNIQUE; a clash is the likely cause.
		s.renderProfile(w, r, "", "Could not rename — is that username already taken?")
		return
	}
	s.renderProfile(w, r, "identity", "")
}

func (s *Server) handleProfilePassword(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	user := s.currentUser(r)
	current := r.FormValue("current_password")
	next := r.FormValue("new_password")
	confirm := r.FormValue("confirm_password")

	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(current)) != nil {
		s.renderProfile(w, r, "", "Current password is incorrect.")
		return
	}
	if len(next) < 8 {
		s.renderProfile(w, r, "", "New password must be at least 8 characters.")
		return
	}
	if next != confirm {
		s.renderProfile(w, r, "", "New passwords do not match.")
		return
	}
	hash, err := HashPassword(next)
	if err != nil {
		s.serverError(w, "hash password", err)
		return
	}
	if err := s.store.SetPassword(user.ID, hash); err != nil {
		s.serverError(w, "set password", err)
		return
	}
	// Evict every other session for this user: a change of password should end
	// any session opened under the old one (a shared machine, a leaked cookie),
	// while keeping the operator making the change signed in.
	keep := ""
	if c, err := r.Cookie(sessionCookieName); err == nil {
		keep = c.Value
	}
	if err := s.store.DeleteUserSessionsExcept(user.ID, keep); err != nil {
		s.log.Warn("could not evict other sessions after password change", "error", err)
	}
	s.renderProfile(w, r, "password", "")
}
