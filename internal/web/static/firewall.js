// firewall.js drives the rule editor. It reads the embedded knob catalogue and
// the page data (this box's interfaces, the named sets, the sibling chains) and,
// as you build a rule, it: explains the chosen condition/action in plain words,
// swaps the value box for the right control (a dropdown of choices, of real
// interfaces, a named-set picker…), and reveals only the parameters the chosen
// action needs. The form still works without JS — this only makes it easier and
// clearer. Delegation-free but CSP-clean (external file, no inline handlers).
(function () {
	var cat = readJSON("catalogue");
	var page = readJSON("pagedata");
	if (!cat) return;
	var matches = cat.matches || {};
	var statements = cat.statements || {};
	var interfaces = (page && page.interfaces) || [];
	var sets = (page && page.sets) || [];
	var chains = (page && page.chains) || [];

	var ADDR_KEYS = { "ip.saddr": 1, "ip.daddr": 1, "ip6.saddr": 1, "ip6.daddr": 1 };

	function readJSON(id) {
		var el = document.getElementById(id);
		if (!el) return null;
		try { return JSON.parse(el.textContent); } catch (e) { return null; }
	}
	function esc(s) {
		var d = document.createElement("div");
		d.textContent = s == null ? "" : s;
		return d.innerHTML;
	}
	function opt(value, label, selected) {
		var o = document.createElement("option");
		o.value = value;
		o.textContent = label;
		if (selected) o.selected = true;
		return o;
	}

	// Shared datalists so text fields can suggest real values.
	function buildDatalist(id, values) {
		if (document.getElementById(id)) return;
		var dl = document.createElement("datalist");
		dl.id = id;
		values.forEach(function (v) { dl.appendChild(opt(v, v, false)); });
		document.body.appendChild(dl);
	}
	buildDatalist("iface-list", interfaces);
	buildDatalist("chain-list", chains);

	// renderHelp fills a row's help area with the plain-language help and an
	// example. For a flags condition (multi-choice) it adds clickable chips that
	// accumulate into the value box.
	function renderHelp(helpEl, info, valInput) {
		if (!helpEl) return;
		if (!info) { helpEl.innerHTML = ""; return; }
		var html = "";
		if (info.help) html += '<div class="knob-help-text">' + esc(info.help) + "</div>";
		if (info.example) html += '<div class="knob-example">Example: <code>' + esc(info.example) + "</code></div>";
		helpEl.innerHTML = html;
		if (valInput && info.kind === "flags" && info.options && info.options.length) {
			var wrap = document.createElement("div");
			wrap.className = "knob-chips";
			info.options.forEach(function (o) {
				var chip = document.createElement("button");
				chip.type = "button";
				chip.className = "chip chip-pick";
				chip.textContent = o.value;
				if (o.help) chip.title = o.help;
				chip.addEventListener("click", function () { addToList(valInput, o.value); });
				wrap.appendChild(chip);
			});
			helpEl.appendChild(wrap);
		}
	}

	function addToList(input, value) {
		var parts = input.value.split(",").map(function (s) { return s.trim(); }).filter(Boolean);
		if (parts.indexOf(value) === -1) parts.push(value);
		input.value = parts.join(", ");
	}

	// buildValue replaces a condition row's value cell with the control that fits
	// the chosen field, preserving the current text and keeping the c_val_N name.
	function buildValue(cell, name, fieldKey, current) {
		cell.innerHTML = "";
		var info = matches[fieldKey];
		var kind = info && info.kind;

		if (fieldKey && kind === "enum" && info.options) {
			var sel = document.createElement("select");
			sel.name = name;
			sel.className = "knob-val";
			info.options.forEach(function (o) {
				var label = o.label && o.label !== o.value ? o.value + " — " + o.label : o.value;
				sel.appendChild(opt(o.value, label, o.value === current));
			});
			cell.appendChild(sel);
			return;
		}

		var input = document.createElement("input");
		input.type = "text";
		input.name = name;
		input.className = "knob-val";
		input.autocomplete = "off";
		input.value = current || "";

		if (fieldKey && kind === "iface") {
			input.setAttribute("list", "iface-list");
			input.placeholder = "interface name";
		} else if (fieldKey) {
			input.placeholder = info && info.example ? info.example : "value";
		} else {
			input.placeholder = "value";
		}
		cell.appendChild(input);

		// Address fields get a named-set picker that inserts @name4 / @name6.
		if (fieldKey && ADDR_KEYS[fieldKey] && sets.length) {
			var suffix = fieldKey.indexOf("ip6.") === 0 ? "6" : "4";
			var pick = document.createElement("select");
			pick.className = "set-pick";
			pick.appendChild(opt("", "use a set…", false));
			sets.forEach(function (s) { pick.appendChild(opt(s, "@" + s, false)); });
			pick.addEventListener("change", function () {
				if (pick.value) { addToList(input, "@" + pick.value + suffix); pick.value = ""; }
			});
			cell.appendChild(pick);
		}
		return input;
	}

	function wireCondRow(row) {
		var field = row.querySelector(".knob-field");
		var cell = row.querySelector(".knob-val-cell");
		var help = row.querySelector(".knob-help");
		if (!field || !cell) return;
		var name = "c_val_" + row.getAttribute("data-index");
		function update() {
			var cur = "";
			var existing = cell.querySelector("[name='" + name + "']");
			if (existing) cur = existing.value;
			var valInput = buildValue(cell, name, field.value, cur);
			renderHelp(help, matches[field.value], valInput || null);
		}
		field.addEventListener("change", update);
		update();
	}

	function wireActRow(row) {
		var action = row.querySelector(".knob-action");
		var help = row.querySelector(".knob-help");
		var params = row.querySelectorAll(".param");
		if (!action) return;
		// jump/goto target suggests sibling chains.
		var target = row.querySelector("[name^='a_target_']");
		if (target) target.setAttribute("list", "chain-list");
		function update() {
			var key = action.value;
			params.forEach(function (p) {
				var forList = (p.getAttribute("data-for") || "").split(",");
				p.style.display = key && forList.indexOf(key) !== -1 ? "" : "none";
			});
			renderHelp(help, statements[key], null);
		}
		action.addEventListener("change", update);
		update();
	}

	document.querySelectorAll(".cond-row").forEach(wireCondRow);
	document.querySelectorAll(".act-row").forEach(wireActRow);

	// "Add condition" / "Add action" reveal the next hidden (.extra) row.
	function revealNext(containerId) {
		var container = document.getElementById(containerId);
		if (!container) return;
		var hidden = container.querySelector(".knob-row.extra");
		if (hidden) hidden.classList.remove("extra");
	}
	var addCond = document.getElementById("add-cond");
	if (addCond) addCond.addEventListener("click", function () { revealNext("conds"); updatePreview(); });
	var addAct = document.getElementById("add-act");
	if (addAct) addAct.addEventListener("click", function () { revealNext("acts"); updatePreview(); });

	// ── live "renders as" preview ────────────────────────────────────────────
	// As the form changes, ask the server to render the rule (the same renderer
	// the apply path uses, so the preview never drifts) and show it inside its
	// chain, with … standing in for the chain's other rules.
	var form = document.getElementById("rule-form");
	var box = document.getElementById("rule-preview");
	var timer = null;

	function showPreview(data) {
		if (!box) return;
		var chain = box.getAttribute("data-chain") || "chain";
		if (data.error) {
			box.textContent = data.error;
			return;
		}
		if (!data.line) {
			box.textContent = "(add a condition or action)";
			return;
		}
		box.textContent = "chain " + chain + " {\n        …\n        " + data.line + "\n        …\n}";
	}

	function updatePreview() {
		if (!form || !box) return;
		var body = new URLSearchParams(new FormData(form));
		fetch("/firewall/rules/preview", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: body.toString(),
		})
			.then(function (r) { return r.json(); })
			.then(showPreview)
			.catch(function () { /* leave the last good preview in place */ });
	}

	function schedulePreview() {
		if (timer) clearTimeout(timer);
		timer = setTimeout(updatePreview, 250);
	}

	if (form) {
		form.addEventListener("input", schedulePreview);
		form.addEventListener("change", schedulePreview);
		updatePreview(); // first paint in chain context
	}
})();
