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
	// Accents match birdy: green is the base theme (no attribute), the rest are the
	// switchable hues. "emerald" (the old green accent) folds into the green base.
	themeAccents   = map[string]bool{"green": true, "ocean": true, "violet": true, "amber": true}
	themeDensities = map[string]bool{"comfortable": true, "compact": true}
	themeModes     = map[string]bool{"": true, "light": true, "dark": true}
)

// currentTheme returns the stored theme, filled with defaults (green Modern).
func (s *Server) currentTheme() (mode, accent, density string) {
	accent, density = "green", "comfortable"
	if st, ok, err := s.store.GetSettings(); err == nil && ok {
		mode = st.ThemeMode
		if st.ThemeAccent != "" {
			accent = st.ThemeAccent
		}
		if st.ThemeDensity != "" {
			density = st.ThemeDensity
		}
	}
	// "emerald" was the pre-redesign green accent; it is now the base, so map it to
	// the default so upgraded installs land on the same green as fresh ones.
	if accent == "emerald" {
		accent = "green"
	}
	return
}

// isFetch reports whether the request came from theme.js (fetch), which wants a
// bare 204 rather than a redirect to a page.
func isFetch(r *http.Request) bool { return r.Header.Get("X-Requested-With") == "fetch" }

// handleThemeMode applies the light/dark/system mode. theme.js POSTs the chosen
// mode via fetch and wants a 204; a no-JS form fallback toggles and redirects.
func (s *Server) handleThemeMode(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	mode, accent, density := s.currentTheme()
	// A present "mode" field sets it (theme.js and the settings form send one);
	// its absence means a no-JS toggle, which flips light/dark.
	if r.PostForm.Has("mode") {
		if v := r.PostForm.Get("mode"); themeModes[v] {
			mode = v
		}
	} else if mode == "dark" {
		mode = "light"
	} else {
		mode = "dark"
	}
	if err := s.store.SaveTheme(mode, accent, density); err != nil {
		s.serverError(w, "save theme", err)
		return
	}
	if isFetch(r) {
		w.WriteHeader(http.StatusNoContent)
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
	mode, _, density := s.currentTheme()
	// The Theme form sends mode alongside accent; theme.js's accent-only POST omits
	// it, so only override the stored mode when the field is actually present.
	if r.PostForm.Has("mode") {
		if v := r.PostForm.Get("mode"); themeModes[v] {
			mode = v
		}
	}
	accent := r.FormValue("accent")
	if !themeAccents[accent] {
		accent = "green"
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
	if isFetch(r) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, "/settings?tab=theme&saved="+urlEscape("Theme saved."), http.StatusSeeOther)
}
