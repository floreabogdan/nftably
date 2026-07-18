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

// Delegated tab switching: clicking a .chain-tab activates it and the matching
// .chain-panel within the same .chain-group. Used to organise a table's chains
// into tabs on the Firewall page.
(function () {
	document.addEventListener("click", function (event) {
		var tab = event.target.closest(".chain-tab");
		if (!tab) return;
		var group = tab.closest(".chain-group");
		if (!group) return;
		var panelId = tab.getAttribute("data-panel");
		group.querySelectorAll(".chain-tab").forEach(function (t) {
			t.classList.toggle("active", t === tab);
		});
		group.querySelectorAll(".chain-panel").forEach(function (p) {
			p.classList.toggle("active", p.id === panelId);
		});
	});
})();

// Delegated modal open/close: [data-modal-open="id"] opens that modal;
// [data-modal-close], a click on the backdrop, or Escape closes the open one.
(function () {
	function open(id) {
		var m = document.getElementById(id);
		if (m) m.classList.add("open");
	}
	function closeAll() {
		document.querySelectorAll(".modal-backdrop.open").forEach(function (m) {
			m.classList.remove("open");
		});
	}
	document.addEventListener("click", function (event) {
		var opener = event.target.closest("[data-modal-open]");
		if (opener) {
			event.preventDefault();
			open(opener.getAttribute("data-modal-open"));
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
		if (event.key === "Escape") closeAll();
	});
})();
