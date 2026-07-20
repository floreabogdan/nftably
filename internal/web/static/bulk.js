// bulk.js — bulk actions on rules. Each rule row has a checkbox; selecting one
// or more reveals that chain's bulk bar (enable / disable / move to another
// chain / delete). Actions POST the selected ids to /firewall/rules/bulk (same
// origin, like the reorder endpoints) and the page reloads.
//
// Scope is one chain panel: a bar acts only on the checkboxes inside its own
// panel, and a chain's "Select" checkbox toggles just that chain's rules.

(function () {
	"use strict";

	Array.prototype.forEach.call(document.querySelectorAll("[data-bulk-bar]"), function (bar) {
		var panel = bar.closest(".chain-panel");
		if (!panel) return;
		var allBox = panel.querySelector("[data-bulk-all]");
		var moveSel = bar.querySelector("[data-bulk-move]");

		function checks() {
			return Array.prototype.slice.call(panel.querySelectorAll(".bulk-check"));
		}
		function selectedIds() {
			return checks().filter(function (c) { return c.checked; })
				.map(function (c) { return c.getAttribute("data-bulk-id"); });
		}
		function update() {
			var all = checks();
			var n = all.filter(function (c) { return c.checked; }).length;
			var cnt = bar.querySelector("[data-bulk-count]");
			if (cnt) cnt.textContent = n;
			bar.hidden = n === 0;
			if (allBox) {
				allBox.checked = all.length > 0 && n === all.length;
				allBox.indeterminate = n > 0 && n < all.length;
			}
		}

		panel.addEventListener("change", function (e) {
			if (e.target.classList && e.target.classList.contains("bulk-check")) {
				update();
			} else if (e.target.hasAttribute && e.target.hasAttribute("data-bulk-all")) {
				var on = e.target.checked;
				checks().forEach(function (c) { c.checked = on; });
				update();
			}
		});

		bar.addEventListener("click", function (e) {
			var act = e.target.closest("[data-bulk-action]");
			if (act) { run(act.getAttribute("data-bulk-action"), act.getAttribute("data-bulk-confirm")); return; }
			if (e.target.closest("[data-bulk-clear]")) {
				checks().forEach(function (c) { c.checked = false; });
				update();
			}
		});

		if (moveSel) moveSel.addEventListener("change", function () { if (moveSel.value) run("move", null); });

		function run(action, confirmMsg) {
			var ids = selectedIds();
			if (!ids.length) return;
			if (confirmMsg && !window.confirm(confirmMsg)) return;
			var body = "action=" + encodeURIComponent(action) + "&ids=" + encodeURIComponent(ids.join(","));
			if (action === "move") {
				if (!moveSel || !moveSel.value) return;
				body += "&chain_id=" + encodeURIComponent(moveSel.value);
			}
			fetch("/firewall/rules/bulk", {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: body,
			}).then(function () { window.location.reload(); })
				.catch(function () { window.location.reload(); });
		}

		update();
	});
})();
