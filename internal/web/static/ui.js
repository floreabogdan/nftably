// Delegated confirm dialogs: a form (or element) carrying data-confirm asks
// before submitting. Delegation keeps the templates free of inline handlers,
// which the CSP forbids.
(function () {
	document.addEventListener("submit", function (event) {
		var form = event.target.closest("form[data-confirm]");
		if (!form) return;
		if (!window.confirm(form.getAttribute("data-confirm"))) {
			event.preventDefault();
		}
	});
})();

// Delegated tab switching: activating a .chain-tab shows the matching
// .chain-panel within the same .chain-group, and keeps the ARIA tab pattern in
// sync (aria-selected + roving tabindex) so screen-reader and keyboard users get
// a real tablist. Left/Right/Home/End move between tabs. Used to organise a
// table's chains into tabs on the Firewall page.
(function () {
	function activate(tab, focus) {
		var group = tab.closest(".chain-group");
		if (!group) return;
		var panelId = tab.getAttribute("data-panel");
		group.querySelectorAll(".chain-tab").forEach(function (t) {
			var on = t === tab;
			t.classList.toggle("active", on);
			t.setAttribute("aria-selected", on ? "true" : "false");
			t.tabIndex = on ? 0 : -1;
		});
		group.querySelectorAll(".chain-panel").forEach(function (p) {
			p.classList.toggle("active", p.id === panelId);
		});
		if (focus) tab.focus();
	}

	document.addEventListener("click", function (event) {
		var tab = event.target.closest(".chain-tab");
		if (tab) activate(tab, false);
	});

	document.addEventListener("keydown", function (event) {
		var tab = event.target.closest && event.target.closest(".chain-tab");
		if (!tab) return;
		var keys = { ArrowLeft: -1, ArrowRight: 1, Home: "first", End: "last" };
		if (!(event.key in keys)) return;
		event.preventDefault();
		var tabs = Array.prototype.slice.call(tab.closest(".chain-tabs").querySelectorAll(".chain-tab"));
		var i = tabs.indexOf(tab);
		var move = keys[event.key];
		var next = move === "first" ? 0 : move === "last" ? tabs.length - 1 : (i + move + tabs.length) % tabs.length;
		activate(tabs[next], true);
	});
})();

// Source-specific fields: a [data-source-select] shows only the
// [data-source-field] groups whose space-separated value list includes the
// selected option (e.g. the country field for "geoip", the URL field for "url").
(function () {
	function sync(sel) {
		var val = sel.value;
		var scope = sel.closest("form") || document;
		scope.querySelectorAll("[data-source-field]").forEach(function (el) {
			el.hidden = el.getAttribute("data-source-field").split(" ").indexOf(val) === -1;
		});
	}
	document.addEventListener("change", function (e) {
		if (e.target.matches && e.target.matches("[data-source-select]")) sync(e.target);
	});
	// Run once now (this script is deferred, so the DOM is ready).
	document.querySelectorAll("[data-source-select]").forEach(sync);
})();

// Delegated modal open/close: [data-modal-open="id"] opens that modal;
// [data-modal-close], a click on the backdrop, or Escape closes the open one.
(function () {
	var lastTrigger = null;

	function focusables(m) {
		return Array.prototype.slice.call(m.querySelectorAll(
			'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled])'));
	}
	function open(id, trigger) {
		var m = document.getElementById(id);
		if (!m) return;
		lastTrigger = trigger || null;
		m.classList.add("open");
		// Move focus into the dialog so keyboard/AT users start inside it.
		var f = focusables(m);
		if (f.length) f[0].focus();
	}
	function closeAll() {
		var wasOpen = false;
		document.querySelectorAll(".modal-backdrop.open").forEach(function (m) {
			m.classList.remove("open");
			wasOpen = true;
		});
		// Restore focus to whatever opened the modal.
		if (wasOpen && lastTrigger) {
			try { lastTrigger.focus(); } catch (e) { /* trigger may be gone */ }
			lastTrigger = null;
		}
	}
	document.addEventListener("click", function (event) {
		var opener = event.target.closest("[data-modal-open]");
		if (opener) {
			event.preventDefault();
			open(opener.getAttribute("data-modal-open"), opener);
			return;
		}
		if (event.target.closest("[data-modal-close]")) {
			closeAll();
			return;
		}
		// A click on the backdrop itself (not its inner .modal) closes it.
		if (event.target.classList && event.target.classList.contains("modal-backdrop")) {
			closeAll();
		}
	});
	document.addEventListener("keydown", function (event) {
		if (event.key === "Escape") {
			closeAll();
			return;
		}
		// Trap Tab within the open dialog so focus can't wander behind it.
		if (event.key !== "Tab") return;
		var m = document.querySelector(".modal-backdrop.open");
		if (!m) return;
		var f = focusables(m);
		if (!f.length) return;
		var first = f[0], last = f[f.length - 1];
		if (event.shiftKey && document.activeElement === first) {
			event.preventDefault();
			last.focus();
		} else if (!event.shiftKey && document.activeElement === last) {
			event.preventDefault();
			first.focus();
		}
	});
})();
