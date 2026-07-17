(function () {
	// ---- relative time ----
	// Elements carrying data-ts (RFC3339) get their text swapped to a
	// relative form ("2m ago") and kept fresh; the absolute time stays
	// available in the title tooltip set by the template.
	function relTime(iso) {
		var d = new Date(iso);
		if (isNaN(d.getTime())) return "";
		var s = Math.floor((Date.now() - d.getTime()) / 1000);
		if (s < 0) s = 0;
		if (s < 10) return "just now";
		if (s < 60) return s + "s ago";
		if (s < 3600) return Math.floor(s / 60) + "m ago";
		if (s < 86400) {
			var h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
			return m ? h + "h " + m + "m ago" : h + "h ago";
		}
		return Math.floor(s / 86400) + "d ago";
	}
	function refreshTimes() {
		document.querySelectorAll("[data-ts]").forEach(function (el) {
			var iso = el.getAttribute("data-ts");
			if (iso) el.textContent = relTime(iso);
		});
	}
	window.nftablyRelTime = relTime;
	window.nftablyRefreshTimes = refreshTimes;
	refreshTimes();
	setInterval(refreshTimes, 30000);

	// ---- page filter ----
	// Filters any element marked data-search-target by its direct children's
	// text content, scoped to whatever's on the current page (sessions table,
	// timeline entries, looking-glass results).
	var input = document.getElementById("topbar-search-input");
	if (input) {
		var applyFilter = function () {
			var q = input.value.trim().toLowerCase();
			document.querySelectorAll("[data-search-target]").forEach(function (target) {
				Array.prototype.forEach.call(target.children, function (row) {
					var text = row.textContent.toLowerCase();
					row.style.display = !q || text.indexOf(q) !== -1 ? "" : "none";
				});
			});
		};
		window.nftablyApplyFilter = applyFilter;
		input.addEventListener("input", applyFilter);
		input.addEventListener("keydown", function (e) {
			if (e.key === "Escape") {
				input.value = "";
				applyFilter();
				input.blur();
			}
		});
		document.addEventListener("keydown", function (e) {
			if (e.key !== "/" || e.ctrlKey || e.metaKey || e.altKey) return;
			var t = e.target;
			if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.tagName === "SELECT" || t.isContentEditable)) return;
			e.preventDefault();
			input.focus();
		});
	}

	// ---- mobile navigation ----
	var navToggle = document.getElementById("nav-toggle");
	var scrim = document.getElementById("nav-scrim");
	if (navToggle) {
		navToggle.addEventListener("click", function () {
			document.body.classList.toggle("nav-open");
		});
	}
	if (scrim) {
		scrim.addEventListener("click", function () {
			document.body.classList.remove("nav-open");
		});
	}
	document.addEventListener("keydown", function (e) {
		if (e.key === "Escape") document.body.classList.remove("nav-open");
	});

	// ---- nft connection dot ----
	// Polled lightly on every authenticated page: whether nft is installed and
	// its ruleset is currently readable (i.e. nftably has the privilege it needs).
	var connDot = document.getElementById("nft-conn");
	var connLabel = document.getElementById("nft-conn-label");
	function setConn(cls, text) {
		if (connDot) connDot.className = "conn-dot " + cls;
		if (connLabel) connLabel.textContent = text;
	}
	function poll() {
		fetch("/api/status", { credentials: "same-origin" })
			.then(function (r) { return r.ok ? r.json() : null; })
			.then(function (data) {
				if (!data) { setConn("bad", "nft unreachable"); return; }
				if (!data.nftAvailable) {
					setConn("bad", "nft not installed");
				} else if (data.rulesetOK) {
					setConn("ok", "nft ready");
				} else {
					setConn("warn", "nft: permission denied");
				}
			})
			.catch(function () { setConn("bad", "nft unreachable"); });
	}
	if (connDot) {
		poll();
		setInterval(poll, 10000);
	}
})();
