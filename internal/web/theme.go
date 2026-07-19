package web

import (
	"net/http"
	"net/url"
)

// theme.go persists the operator's theme preferences on the account (not just
// the browser), so the look follows them across logins and devices. The shell
// renders data-theme / data-theme-accent / data-theme-style onto <html> from
// these, so the theme is applied server-side — no flash, no flaky client JS.

var (
	themeAccents   = map[string]bool{"ocean": true, "emerald": true, "violet": true, "amber": true}
	themeDensities = map[string]bool{"comfortable": true, "compact": true}
	themeModes     = map[string]bool{"": true, "light": true, "dark": true}
)

// currentTheme returns the stored theme, filled with defaults.
func (s *Server) currentTheme() (mode, accent, density string) {
	accent, density = "ocean", "comfortable"
	if st, ok, err := s.store.GetSettings(); err == nil && ok {
		mode = st.ThemeMode
		if st.ThemeAccent != "" {
			accent = st.ThemeAccent
		}
		if st.ThemeDensity != "" {
			density = st.ThemeDensity
		}
	}
	return
}

// handleThemeMode toggles light/dark from the top-bar button and returns to the
// page it was clicked on. From dark it goes light; from light or system it goes
// dark.
func (s *Server) handleThemeMode(w http.ResponseWriter, r *http.Request) {
	mode, accent, density := s.currentTheme()
	if mode == "dark" {
		mode = "light"
	} else {
		mode = "dark"
	}
	if err := s.store.SaveTheme(mode, accent, density); err != nil {
		s.serverError(w, "save theme", err)
		return
	}
	http.Redirect(w, r, backTo(r), http.StatusSeeOther)
}

// backTo returns the same-site path to return to after the toggle: the Referer's
// path when it targets this host, else the dashboard. Never an off-site URL.
func backTo(r *http.Request) string {
	u, err := url.Parse(r.Header.Get("Referer"))
	if err != nil || u.Host != r.Host || u.Path == "" {
		return "/"
	}
	return u.RequestURI()
}

// handleThemeSave saves the accent + density chosen on the Theme tab (mode is
// left to the top-bar toggle).
func (s *Server) handleThemeSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	mode, _, _ := s.currentTheme()
	accent := r.FormValue("accent")
	density := r.FormValue("density")
	if !themeAccents[accent] {
		accent = "ocean"
	}
	if !themeDensities[density] {
		density = "comfortable"
	}
	if !themeModes[mode] {
		mode = ""
	}
	if err := s.store.SaveTheme(mode, accent, density); err != nil {
		s.serverError(w, "save theme", err)
		return
	}
	http.Redirect(w, r, "/settings?tab=theme&saved="+urlEscape("Theme saved."), http.StatusSeeOther)
}
