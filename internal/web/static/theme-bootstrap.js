(function () {
	try {
		var saved = localStorage.getItem("nftably-theme");
		if (saved === "light" || saved === "dark") {
			document.documentElement.setAttribute("data-theme", saved);
		}
		// The second axis: layout density. Default "comfortable" (no override).
		var style = localStorage.getItem("nftably-theme-style");
		document.documentElement.setAttribute("data-theme-style", style === "compact" ? "compact" : "comfortable");
	} catch (_) {
		// Storage can be unavailable in hardened/private browser contexts. The
		// CSS system preference remains a complete fallback.
	}
})();
