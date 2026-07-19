// Theme toggle. Reflects the current theme in the button — both visually (the
// icon shows the theme you'd switch TO) and to assistive tech (aria-pressed +
// a stateful label), rather than always showing a static sun.
// Layout-density picker (Settings → Theme): the second theme axis. Persisted in
// this browser only; independent of light/dark. Runs on every page but only does
// anything where the radios are present.
(function () {
	function currentStyle() {
		var s = document.documentElement.getAttribute("data-theme-style");
		return s === "compact" ? "compact" : "comfortable";
	}
	function setStyle(value) {
		var next = value === "compact" ? "compact" : "comfortable";
		document.documentElement.setAttribute("data-theme-style", next);
		document.querySelectorAll("[data-theme-choice]").forEach(function (c) { c.checked = c.value === next; });
		try { localStorage.setItem("nftably-theme-style", next); } catch (_) {}
	}
	setStyle(currentStyle()); // reflect the bootstrapped value into the controls
	document.querySelectorAll("[data-theme-choice]").forEach(function (c) {
		c.addEventListener("change", function () { setStyle(c.value); });
	});

	// Third axis: the accent palette. "ocean" is the default (no attribute).
	function currentAccent() {
		var a = document.documentElement.getAttribute("data-theme-accent");
		return a === "emerald" || a === "violet" || a === "amber" ? a : "ocean";
	}
	function setAccent(value) {
		var next = value === "emerald" || value === "violet" || value === "amber" ? value : "ocean";
		if (next === "ocean") document.documentElement.removeAttribute("data-theme-accent");
		else document.documentElement.setAttribute("data-theme-accent", next);
		document.querySelectorAll("[data-theme-accent-choice]").forEach(function (c) { c.checked = c.value === next; });
		try { localStorage.setItem("nftably-theme-accent", next); } catch (_) {}
	}
	setAccent(currentAccent());
	document.querySelectorAll("[data-theme-accent-choice]").forEach(function (c) {
		c.addEventListener("change", function () { setAccent(c.value); });
	});
})();

(function () {
	var btn = document.getElementById("theme-toggle");
	if (!btn) return;

	var attrs = 'viewBox="0 0 24 24" aria-hidden="true" focusable="false" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"';
	var SUN = '<svg ' + attrs + '><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>';
	var MOON = '<svg ' + attrs + '><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';

	function effective() {
		var t = document.documentElement.getAttribute("data-theme");
		if (t === "dark" || t === "light") return t;
		return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
	}
	function reflect() {
		var dark = effective() === "dark";
		btn.innerHTML = dark ? SUN : MOON;
		btn.setAttribute("aria-pressed", dark ? "true" : "false");
		var label = dark ? "Switch to light theme" : "Switch to dark theme";
		btn.setAttribute("aria-label", label);
		btn.setAttribute("title", label);
	}

	btn.addEventListener("click", function () {
		var next = effective() === "dark" ? "light" : "dark";
		document.documentElement.setAttribute("data-theme", next);
		localStorage.setItem("nftably-theme", next);
		reflect();
	});
	reflect();
})();
