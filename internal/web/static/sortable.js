// sortable.js — generic drag-to-reorder for the Firewall page. One helper drives
// three levels: rules within a chain (vertical), chains within a table (the
// horizontal tab strip), and tables on the page (vertical cards).
//
// Progressive enhancement: every reorderable thing also has up/down buttons that
// work with no JS and from the keyboard. When JS is on, a drag grip appears; a
// drag reorders live and, on release, persists the new order via a same-origin
// POST (SameSite=Strict cookie + Origin check, like the live rule preview).
//
// Markup contract:
//   container:  [data-sortable] [data-sortable-endpoint="…"] [data-sortable-axis="x|y"]
//   items:      DIRECT children carrying [data-sortable-id]; other children
//               (headers, an "add" button) are left in place
//   grip:       an element with [data-sort-grip] inside each item
// The POST body is `ids=<comma-separated ids in the new order>`.
//
// Plain mouse/touch events are used rather than the native HTML5 drag API: it
// works with touch, can't strand a half-dragged item if the pointer leaves the
// window, and behaves predictably across browsers.

(function () {
	"use strict";

	Array.prototype.forEach.call(document.querySelectorAll("[data-sortable]"), wire);

	function wire(container) {
		var endpoint = container.getAttribute("data-sortable-endpoint");
		if (!endpoint) return;
		var horizontal = container.getAttribute("data-sortable-axis") === "x";
		items(container).forEach(function (item) {
			var grip = item.querySelector("[data-sort-grip]");
			if (!grip) return;
			grip.addEventListener("mousedown", function (e) { begin(e, item, container, endpoint, horizontal); });
			grip.addEventListener("touchstart", function (e) { begin(e, item, container, endpoint, horizontal); }, { passive: false });
		});
	}

	// Direct-child items only, so a container never captures items belonging to a
	// nested sortable (a table holds chains which hold rules, all data-sortable-id).
	function items(container) {
		return Array.prototype.filter.call(container.children, function (c) {
			return c.nodeType === 1 && c.hasAttribute("data-sortable-id");
		});
	}

	function point(e, horizontal) {
		var t = e.touches && e.touches.length ? e.touches[0] : e;
		return horizontal ? t.clientX : t.clientY;
	}

	function begin(startEvent, item, container, endpoint, horizontal) {
		startEvent.preventDefault(); // no text selection / native image drag
		item.classList.add("sort-dragging");
		document.body.classList.add("reordering");

		function onMove(e) {
			var p = point(e, horizontal);
			var over = itemAt(container, p, horizontal);
			if (!over || over === item) return;
			var rect = over.getBoundingClientRect();
			var mid = horizontal ? rect.left + rect.width / 2 : rect.top + rect.height / 2;
			var after = p > mid;
			container.insertBefore(item, after ? over.nextSibling : over);
			if (e.cancelable) e.preventDefault();
		}
		function onUp() {
			document.removeEventListener("mousemove", onMove);
			document.removeEventListener("mouseup", onUp);
			document.removeEventListener("touchmove", onMove);
			document.removeEventListener("touchend", onUp);
			item.classList.remove("sort-dragging");
			document.body.classList.remove("reordering");
			persist(container, endpoint);
		}
		document.addEventListener("mousemove", onMove);
		document.addEventListener("mouseup", onUp);
		document.addEventListener("touchmove", onMove, { passive: false });
		document.addEventListener("touchend", onUp);
	}

	// The item whose span along the drag axis contains coordinate p, if any.
	function itemAt(container, p, horizontal) {
		var list = items(container);
		for (var i = 0; i < list.length; i++) {
			var r = list[i].getBoundingClientRect();
			var lo = horizontal ? r.left : r.top;
			var hi = horizontal ? r.right : r.bottom;
			if (p >= lo && p <= hi) return list[i];
		}
		return null;
	}

	function persist(container, endpoint) {
		var ids = items(container).map(function (it) { return it.getAttribute("data-sortable-id"); }).join(",");
		fetch(endpoint, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: "ids=" + encodeURIComponent(ids),
		}).catch(function () {
			// On failure, reload so the view reflects the true stored order.
			window.location.reload();
		});
	}
})();
