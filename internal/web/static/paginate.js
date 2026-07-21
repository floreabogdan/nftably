// Client-side pagination for any <tbody data-paginate>. Rows are chunked into
// pages (default 25, override with data-page-size) and a pager footer is inserted
// after the table's scroll wrapper. The pager auto-hides when everything fits on
// one page, so short tables look untouched.
//
// It cooperates with the topbar search filter: a row is hidden when EITHER module
// marks it, via the CSS classes .filtered-out (search) and .page-hidden
// (pagination) — neither touches inline display, so they never fight. Pagination
// counts only rows the search left visible, and reflows (window.nftablyReflowPagination)
// whenever the filter changes.
(function () {
	var DEFAULT_SIZE = 25;

	function rowsOf(tbody) {
		return Array.prototype.filter.call(tbody.children, function (el) {
			return el.tagName === "TR";
		});
	}

	function Paginator(tbody) {
		this.tbody = tbody;
		this.size = parseInt(tbody.getAttribute("data-page-size"), 10) || DEFAULT_SIZE;
		this.page = 1;
		var table = tbody.closest("table");
		var anchor = (table && table.closest(".table-scroll")) || table || tbody;
		this.table = table;
		this.pager = document.createElement("div");
		this.pager.className = "pager";
		this.pager.hidden = true;
		anchor.parentNode.insertBefore(this.pager, anchor.nextSibling);

		var self = this;
		this.pager.addEventListener("click", function (e) {
			var btn = e.target.closest("[data-page]");
			if (!btn || btn.disabled) return;
			e.preventDefault();
			var v = btn.getAttribute("data-page");
			if (v === "prev") self.page -= 1;
			else if (v === "next") self.page += 1;
			else self.page = parseInt(v, 10) || 1;
			self.render();
			if (self.table) self.table.scrollIntoView({ block: "nearest" });
		});
		this.render();
	}

	Paginator.prototype.visibleRows = function () {
		return rowsOf(this.tbody).filter(function (r) {
			return !r.classList.contains("filtered-out");
		});
	};

	Paginator.prototype.render = function () {
		var rows = this.visibleRows();
		var pages = Math.max(1, Math.ceil(rows.length / this.size));
		if (this.page > pages) this.page = pages;
		if (this.page < 1) this.page = 1;
		var start = (this.page - 1) * this.size;
		var end = start + this.size;
		rows.forEach(function (r, i) {
			r.classList.toggle("page-hidden", i < start || i >= end);
		});
		this.renderPager(rows.length, pages, start, end);
	};

	Paginator.prototype.renderPager = function (total, pages, start, end) {
		if (pages <= 1) {
			this.pager.hidden = true;
			this.pager.innerHTML = "";
			return;
		}
		this.pager.hidden = false;
		var page = this.page;
		var shownEnd = Math.min(end, total);
		var parts = [
			'<span class="pager-info">' + (start + 1) + "–" + shownEnd + " of " + total + "</span>",
			'<span class="pager-btns">',
			btn("prev", "‹", page === 1, false, "Previous page"),
		];
		pageList(page, pages).forEach(function (p) {
			if (p === "gap") parts.push('<span class="pager-gap">…</span>');
			else parts.push(btn(String(p), String(p), false, p === page, "Page " + p));
		});
		parts.push(btn("next", "›", page === pages, false, "Next page"));
		parts.push("</span>");
		this.pager.innerHTML = parts.join("");
	};

	function btn(page, label, disabled, current, aria) {
		return (
			'<button type="button" class="pager-btn' +
			(current ? " is-current" : "") +
			'" data-page="' + page + '"' +
			(disabled ? " disabled" : "") +
			(current ? ' aria-current="page"' : "") +
			' aria-label="' + aria + '">' + label + "</button>"
		);
	}

	// A compact page window: first, last, and the pages either side of the current
	// one, with "gap" markers where a run is elided (1 … 4 5 6 … 20).
	function pageList(current, pages) {
		var span = 1;
		var lo = Math.max(2, current - span);
		var hi = Math.min(pages - 1, current + span);
		var out = [1];
		if (lo > 2) out.push("gap");
		for (var p = lo; p <= hi; p++) out.push(p);
		if (hi < pages - 1) out.push("gap");
		if (pages > 1) out.push(pages);
		return out;
	}

	var paginators = [];
	function init() {
		document.querySelectorAll("tbody[data-paginate]").forEach(function (tbody) {
			if (tbody.dataset.paginated) return;
			tbody.dataset.paginated = "1";
			paginators.push(new Paginator(tbody));
		});
	}

	// Re-run when the search filter changes: the set of visible rows moved, so page
	// counts change; snap back to the first page of the new result set.
	window.nftablyReflowPagination = function () {
		paginators.forEach(function (p) {
			p.page = 1;
			p.render();
		});
	};

	if (document.readyState === "loading") {
		document.addEventListener("DOMContentLoaded", init);
	} else {
		init();
	}
})();
