// Theme toggle. Reflects the current theme in the button — both visually (the
// icon shows the theme you'd switch TO) and to assistive tech (aria-pressed +
// a stateful label), rather than always showing a static sun.
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
