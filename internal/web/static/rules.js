// rules.js — drag-and-drop reordering of firewall rules on the Firewall page.
//
// Progressive enhancement: the up/down buttons in each rule row are the no-JS
// and keyboard-accessible fallback and always work. When JS is on, each rule row
// gets a drag grip; dragging it reorders the rows live and, on release, persists
// the new order for that chain via a same-origin POST (SameSite=Strict cookie +
// Origin check, like the live rule preview). Reordering is scoped to one chain —
// cross-chain moves are done from the rule editor's chain selector.
//
// This uses plain mouse/touch events rather than the native HTML5 drag API: it
// works with touch, never leaves a half-dragged row if the pointer leaves the
// window, and behaves predictably across browsers.

(function () {
	"use strict";

	Array.prototype.forEach.call(document.querySelectorAll("tbody[data-reorder]"), wireBody);

	function wireBody(body) {
		var chainID = body.getAttribute("data-chain-id");
		if (!chainID) return;
		Array.prototype.forEach.call(body.querySelectorAll("tr[data-rule-id]"), function (row) {
			var grip = row.querySelector(".rule-grip");
			if (!grip) return;
			grip.addEventListener("mousedown", function (e) { begin(e, row, body, chainID); });
			grip.addEventListener("touchstart", function (e) { begin(e, row, body, chainID); }, { passive: false });
		});
	}

	function pointerY(e) {
		return e.touches && e.touches.length ? e.touches[0].clientY : e.clientY;
	}

	// begin a drag: reorder rows as the pointer moves, persist on release.
	function begin(startEvent, row, body, chainID) {
		startEvent.preventDefault(); // no text selection / native image drag
		row.classList.add("row-dragging");
		document.body.classList.add("reordering");

		function onMove(e) {
			var y = pointerY(e);
			var over = rowAt(body, y);
			if (!over || over === row) return;
			var rect = over.getBoundingClientRect();
			var after = y > rect.top + rect.height / 2;
			body.insertBefore(row, after ? over.nextSibling : over);
			if (e.cancelable) e.preventDefault();
		}
		function onUp() {
			document.removeEventListener("mousemove", onMove);
			document.removeEventListener("mouseup", onUp);
			document.removeEventListener("touchmove", onMove);
			document.removeEventListener("touchend", onUp);
			row.classList.remove("row-dragging");
			document.body.classList.remove("reordering");
			persist(body, chainID);
		}
		document.addEventListener("mousemove", onMove);
		document.addEventListener("mouseup", onUp);
		document.addEventListener("touchmove", onMove, { passive: false });
		document.addEventListener("touchend", onUp);
	}

	// The rule row whose vertical span contains y, if any.
	function rowAt(body, y) {
		var rows = body.querySelectorAll("tr[data-rule-id]");
		for (var i = 0; i < rows.length; i++) {
			var r = rows[i].getBoundingClientRect();
			if (y >= r.top && y <= r.bottom) return rows[i];
		}
		return null;
	}

	// Post the current DOM order of a chain's rules back to the server.
	function persist(body, chainID) {
		var ids = Array.prototype.map.call(
			body.querySelectorAll("tr[data-rule-id]"),
			function (r) { return r.getAttribute("data-rule-id"); }
		).join(",");
		fetch("/firewall/chains/" + encodeURIComponent(chainID) + "/rules/reorder", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: "ids=" + encodeURIComponent(ids),
		}).catch(function () {
			// On failure, reload so the view reflects the true stored order.
			window.location.reload();
		});
	}
})();
