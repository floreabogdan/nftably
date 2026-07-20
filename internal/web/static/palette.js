// palette.js — a command palette: press Ctrl/Cmd-K (or click the ⌘K button) to
// fuzzily jump to any page or quick action from anywhere in the app.
//
// The index is built entirely from the DOM — every link in the sidebar nav,
// grouped by its section label — plus a few static quick actions, so it needs no
// server round-trip and always matches what the sidebar offers. Keyboard-first:
// type to filter, ↑/↓ to move, ↵ to open, Esc to close.

(function () {
	"use strict";

	var backdrop = document.getElementById("cmdk");
	var input = document.getElementById("cmdk-input");
	var list = document.getElementById("cmdk-list");
	if (!backdrop || !input || !list) return;

	// The topbar hint hardcodes the Mac glyph; correct it to Ctrl elsewhere —
	// nftably runs on Linux hosts, so most operators are not on a Mac.
	var isMac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent || "");
	var hint = document.querySelector(".cmdk-hint");
	if (hint && !isMac) hint.textContent = "Ctrl K";

	var index = buildIndex();
	var shown = [];   // currently displayed entries
	var active = 0;   // highlighted index within shown

	function buildIndex() {
		var out = [];
		var group = "";
		var nav = document.querySelector(".sidebar-nav");
		if (nav) {
			Array.prototype.forEach.call(nav.children, function (el) {
				if (el.classList && el.classList.contains("nav-label")) {
					group = (el.textContent || "").trim();
				} else if (el.tagName === "A" && el.getAttribute("href")) {
					out.push({ label: (el.textContent || "").trim(), href: el.getAttribute("href"), group: group });
				}
			});
		}
		// A few quick actions that aren't sidebar destinations.
		var actions = [
			{ label: "New rule", href: "/firewall", group: "Actions" },
			{ label: "Export configuration (download JSON)", href: "/settings/backup/export", group: "Actions" },
			{ label: "Profile", href: "/profile", group: "Actions" },
		];
		actions.forEach(function (a) {
			if (!out.some(function (e) { return e.href === a.href && e.label === a.label; })) out.push(a);
		});
		return out;
	}

	// Case-insensitive subsequence match, so "lru" finds "Live ruleset".
	function matches(hay, needle) {
		if (!needle) return true;
		hay = hay.toLowerCase();
		var j = 0;
		for (var i = 0; i < hay.length && j < needle.length; i++) {
			if (hay[i] === needle[j]) j++;
		}
		return j === needle.length;
	}

	function render() {
		var q = input.value.trim().toLowerCase();
		shown = index.filter(function (e) { return matches(e.label + " " + e.group, q); });
		if (active >= shown.length) active = Math.max(0, shown.length - 1);
		list.textContent = "";
		shown.forEach(function (e, i) {
			var li = document.createElement("li");
			li.id = "cmdk-opt-" + i;
			li.className = "cmdk-item" + (i === active ? " active" : "");
			li.setAttribute("role", "option");
			li.setAttribute("aria-selected", i === active ? "true" : "false");
			var label = document.createElement("span");
			label.className = "cmdk-item-label";
			label.textContent = e.label;
			var grp = document.createElement("span");
			grp.className = "cmdk-item-group";
			grp.textContent = e.group;
			li.appendChild(label);
			li.appendChild(grp);
			li.addEventListener("mousemove", function () { if (active !== i) { active = i; paint(); } });
			li.addEventListener("click", function () { go(i); });
			list.appendChild(li);
		});
		if (!shown.length) {
			var empty = document.createElement("li");
			empty.className = "cmdk-empty";
			empty.textContent = "No matches";
			list.appendChild(empty);
		}
		activeDescendant();
	}

	// Repaint the active-row highlight without rebuilding the list.
	function paint() {
		Array.prototype.forEach.call(list.querySelectorAll(".cmdk-item"), function (li, i) {
			var on = i === active;
			li.classList.toggle("active", on);
			li.setAttribute("aria-selected", on ? "true" : "false");
			if (on) li.scrollIntoView({ block: "nearest" });
		});
		activeDescendant();
	}

	// Point the input at the highlighted option so screen readers announce it as
	// the user arrows through the list.
	function activeDescendant() {
		if (shown.length) input.setAttribute("aria-activedescendant", "cmdk-opt-" + active);
		else input.removeAttribute("aria-activedescendant");
	}

	function go(i) {
		var e = shown[i];
		if (e) window.location.href = e.href;
	}

	function open() {
		backdrop.hidden = false;
		document.body.classList.add("cmdk-on");
		input.setAttribute("aria-expanded", "true");
		input.value = "";
		active = 0;
		render();
		input.focus();
	}
	function close() {
		backdrop.hidden = true;
		document.body.classList.remove("cmdk-on");
		input.setAttribute("aria-expanded", "false");
		input.removeAttribute("aria-activedescendant");
	}
	function isOpen() { return !backdrop.hidden; }

	// Global shortcut: Ctrl/Cmd-K toggles the palette.
	document.addEventListener("keydown", function (e) {
		if ((e.ctrlKey || e.metaKey) && (e.key === "k" || e.key === "K")) {
			e.preventDefault();
			isOpen() ? close() : open();
		} else if (isOpen() && e.key === "Escape") {
			close();
		}
	});

	var openBtn = document.getElementById("cmdk-open");
	if (openBtn) openBtn.addEventListener("click", open);

	backdrop.addEventListener("mousedown", function (e) { if (e.target === backdrop) close(); });

	input.addEventListener("input", function () { active = 0; render(); });
	input.addEventListener("keydown", function (e) {
		if (e.key === "ArrowDown") { e.preventDefault(); if (active < shown.length - 1) { active++; paint(); } }
		else if (e.key === "ArrowUp") { e.preventDefault(); if (active > 0) { active--; paint(); } }
		else if (e.key === "Enter") { e.preventDefault(); go(active); }
	});
})();
