// Applies the operator's saved theme before first paint, from the nftably_theme
// cookie the server keeps in sync with the account (value "<mode>.<accent>"). No
// localStorage: the preference lives on the user; the cookie just carries it to
// the page so a toggle survives an immediate navigation before the POST lands.
(function () {
	try {
		var el = document.documentElement;
		el.setAttribute("data-theme-style", "modern"); // the only style now
		var m = document.cookie.match(/(?:^|;\s*)nftably_theme=([^;]+)/);
		if (!m) return; // no cookie yet — the server already rendered the DB theme
		var parts = decodeURIComponent(m[1]).split(".");
		var mode = parts[0] || "system", accent = parts[1] || "green";
		// system → no data-theme, so the prefers-color-scheme media query decides.
		if (mode === "light" || mode === "dark") el.setAttribute("data-theme", mode);
		else el.removeAttribute("data-theme");
		// green is the base :root, so it needs no attribute.
		if (accent && accent !== "green") el.setAttribute("data-theme-accent", accent);
		else el.removeAttribute("data-theme-accent");
	} catch (_) {
		// Storage/cookie access can be blocked; the server-rendered attrs are a full fallback.
	}
})();
