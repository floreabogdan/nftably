package web

import (
	"embed"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"time"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*.css static/*.js static/fonts/*.woff2
var staticFS embed.FS

var funcs = template.FuncMap{
	// addRules sums two rule counts — the v4+v6 iptables total on the dashboard.
	"addRules": func(a, b int) int { return a + b },
	// inc turns a 0-based range index into a 1-based position for human-facing
	// labels (e.g. "Select rule 3").
	"inc": func(i int) int { return i + 1 },
	// list builds a slice from its arguments, for ranging over a fixed set of
	// option values inline in a template (log levels, rate units…).
	"list": func(items ...string) []string { return items },
	// rawURL marks an internally-constructed URL safe so html/template does not
	// re-escape its query string. Only ever used on URLs nftably builds itself
	// (e.g. the advisor's /simulate deep links, already url.Values-encoded), never
	// on user input.
	"rawURL": func(s string) template.URL { return template.URL(s) },
	"fmttime": func(t time.Time) string {
		if t.IsZero() {
			return "-"
		}
		return t.Local().Format("2006-01-02 15:04:05")
	},
	// isotime feeds data-ts attributes so the client can render relative times
	// ("2m ago") that stay correct without reloads.
	"isotime": func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.UTC().Format(time.RFC3339)
	},
	// policyBadge colours a base chain's default policy: drop is the safe
	// posture (green), accept is the permissive one (amber), for a firewall.
	"policyBadge": func(policy string) template.HTML {
		class, label := "badge", policy
		switch policy {
		case "drop", "reject":
			class = "badge-success"
		case "accept":
			class = "badge-warning"
		case "":
			label = "—"
		}
		return template.HTML(`<span class="badge ` + class + `">` + template.HTMLEscapeString(label) + `</span>`)
	},
	// eventBadge colours a timeline entry by kind.
	"eventBadge": func(kind string) template.HTML {
		class, label := "badge", kind
		switch kind {
		case "login":
			class, label = "badge-info", "login"
		case "logout":
			class, label = "badge", "logout"
		case "settings_change":
			class, label = "badge-info", "settings"
		case "ruleset_error":
			class, label = "badge-danger", "nft error"
		}
		return template.HTML(`<span class="badge ` + class + `">` + template.HTMLEscapeString(label) + `</span>`)
	},
}

var tmpl = template.Must(template.New("").Funcs(funcs).ParseFS(templateFS, "templates/*.html"))

func render(w http.ResponseWriter, log *slog.Logger, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, name, data); err != nil {
		log.Error("template render failed", "template", name, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func staticHandler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	return http.FileServerFS(sub)
}
