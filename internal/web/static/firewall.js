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

	// Friendlier words for the operator dropdown. The value stays the real nft
	// operator (so the "Renders as" panel and the save are unaffected); only the
	// label reads in plain language.
	var OP_LABEL = { "==": "is", "!=": "is not", "<": "<", "<=": "≤", ">": ">", ">=": "≥" };
	var DEFAULT_OPS = ["==", "!="];

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

	// Shared datalist so the jump/goto target can suggest sibling chains.
	function buildDatalist(id, values) {
		if (document.getElementById(id)) return;
		var dl = document.createElement("datalist");
		dl.id = id;
		values.forEach(function (v) { dl.appendChild(opt(v, v, false)); });
		document.body.appendChild(dl);
	}
	buildDatalist("chain-list", chains);

	// One document handler closes any open combobox list when a click lands
	// outside it — registered once, so rebuilding value cells never leaks
	// listeners.
	document.addEventListener("mousedown", function (e) {
		document.querySelectorAll(".combo").forEach(function (c) {
			if (!c.contains(e.target)) {
				var l = c.querySelector(".combo-list");
				if (l) l.hidden = true;
				var inp = c.querySelector(".combo-input");
				if (inp) inp.setAttribute("aria-expanded", "false");
			}
		});
	});

	// renderHelp fills a row's help area with the plain-language help and an
	// example. (Multi-choice picking now lives in the value field's combobox.)
	function renderHelp(helpEl, info) {
		if (!helpEl) return;
		if (!info) { helpEl.innerHTML = ""; return; }
		var html = "";
		if (info.help) html += '<div class="knob-help-text">' + esc(info.help) + "</div>";
		if (info.example) html += '<div class="knob-example">Example: <code>' + esc(info.example) + "</code></div>";
		helpEl.innerHTML = html;
	}

	// makeCombo builds a "smart" value field: the operator can TYPE a value or
	// PICK one from a dropdown of suggestions, in the same control — replacing the
	// old split of a text box beside a separate set/flag picker. In multi mode the
	// chosen/typed values become removable chips and the form value is their
	// comma-join (so `@office4, 10.0.0.0/8` is one field); in single mode the
	// value is simply what's typed or picked. Suggestions come from the field
	// (named sets, interfaces, a flag's options); free text is always allowed, so
	// nothing the field can express is lost. Returns { el, input } — el to place,
	// input to focus.
	//
	// opts: { name, value, options:[{value,label,help}], multi, placeholder }
	function makeCombo(opts) {
		var multi = !!opts.multi;
		var options = opts.options || [];
		var chips = [];
		var highlight = -1;

		var wrap = document.createElement("div");
		wrap.className = "combo" + (multi ? " combo-multi" : "");
		var control = document.createElement("div");
		control.className = "combo-control";
		var listId = "combo-list-" + opts.name;
		var input = document.createElement("input");
		input.type = "text";
		input.className = "combo-input";
		input.autocomplete = "off";
		input.setAttribute("role", "combobox");
		input.setAttribute("aria-autocomplete", "list");
		input.setAttribute("aria-expanded", "false");
		input.setAttribute("aria-controls", listId);
		input.setAttribute("aria-label", opts.label || opts.placeholder || "Value");
		if (opts.placeholder) input.placeholder = opts.placeholder;
		var toggle = document.createElement("button");
		toggle.type = "button";
		toggle.className = "combo-toggle";
		toggle.tabIndex = -1;
		toggle.setAttribute("aria-label", "Show suggestions");
		toggle.textContent = "▾";
		var list = document.createElement("ul");
		list.id = listId;
		list.className = "combo-list";
		list.setAttribute("role", "listbox");
		list.hidden = true;
		var hidden = document.createElement("input");
		hidden.type = "hidden";
		hidden.name = opts.name;

		// The form value: committed chips plus whatever is half-typed, so an
		// uncommitted token still applies and shows in the live preview.
		function syncValue() {
			var v;
			if (multi) {
				var pend = input.value.trim();
				v = chips.concat(pend ? [pend] : []).join(", ");
			} else {
				v = input.value.trim();
			}
			hidden.value = v;
			hidden.dispatchEvent(new Event("input", { bubbles: true }));
		}
		function renderChips() {
			[].slice.call(control.querySelectorAll(".combo-chip")).forEach(function (c) { c.remove(); });
			chips.forEach(function (val, i) {
				var chip = document.createElement("span");
				chip.className = "combo-chip mono";
				chip.appendChild(document.createTextNode(val));
				var x = document.createElement("button");
				x.type = "button";
				x.className = "combo-chip-x";
				x.textContent = "×";
				x.setAttribute("aria-label", "Remove " + val);
				x.addEventListener("click", function () {
					chips.splice(i, 1); renderChips(); syncValue(); input.focus();
				});
				chip.appendChild(x);
				control.insertBefore(chip, input);
			});
		}
		function addChip(val) {
			val = String(val).trim();
			if (val && chips.indexOf(val) === -1) chips.push(val);
			input.value = "";
			renderChips();
			syncValue();
		}
		function choose(val) {
			if (multi) { addChip(val); openList(""); input.focus(); }
			else { input.value = val; syncValue(); closeList(); input.focus(); }
		}
		function openList(filter) {
			var q = (filter || "").toLowerCase();
			list.innerHTML = "";
			highlight = -1;
			var shown = options.filter(function (o) {
				if (multi && chips.indexOf(o.value) !== -1) return false;
				if (!q) return true;
				return (o.value + " " + (o.label || "")).toLowerCase().indexOf(q) !== -1;
			});
			if (!shown.length) { closeList(); return; }
			shown.forEach(function (o) {
				var li = document.createElement("li");
				li.className = "combo-option";
				li.setAttribute("role", "option");
				li.setAttribute("data-value", o.value);
				var main = document.createElement("span");
				main.className = "combo-option-main mono";
				main.textContent = o.label || o.value;
				li.appendChild(main);
				if (o.help) {
					var h = document.createElement("span");
					h.className = "combo-option-help";
					h.textContent = o.help;
					li.appendChild(h);
				}
				li.addEventListener("mousedown", function (e) { e.preventDefault(); choose(o.value); });
				list.appendChild(li);
			});
			list.hidden = false;
			input.setAttribute("aria-expanded", "true");
		}
		function closeList() {
			list.hidden = true;
			highlight = -1;
			input.setAttribute("aria-expanded", "false");
		}
		function moveHighlight(d) {
			if (list.hidden) { openList(input.value); }
			var items = list.querySelectorAll(".combo-option");
			if (!items.length) return;
			highlight = (highlight + d + items.length) % items.length;
			items.forEach(function (it, i) {
				var on = i === highlight;
				it.classList.toggle("active", on);
				if (on) it.scrollIntoView({ block: "nearest" });
			});
		}

		input.addEventListener("input", function () { openList(input.value); syncValue(); });
		input.addEventListener("keydown", function (e) {
			if (e.key === "ArrowDown") { e.preventDefault(); moveHighlight(1); }
			else if (e.key === "ArrowUp") { e.preventDefault(); moveHighlight(-1); }
			else if (e.key === "Enter") {
				var items = list.querySelectorAll(".combo-option");
				if (!list.hidden && highlight >= 0 && items[highlight]) {
					e.preventDefault(); choose(items[highlight].getAttribute("data-value"));
				} else if (multi && input.value.trim()) {
					e.preventDefault(); addChip(input.value); closeList();
				}
			} else if (e.key === "Escape") {
				if (!list.hidden) { e.stopPropagation(); closeList(); }
			} else if (e.key === "," && multi) {
				e.preventDefault(); addChip(input.value);
			} else if (e.key === "Backspace" && multi && input.value === "" && chips.length) {
				chips.pop(); renderChips(); syncValue();
			}
		});
		toggle.addEventListener("mousedown", function (e) {
			e.preventDefault();
			if (list.hidden) { input.focus(); openList(""); } else { closeList(); }
		});

		// seed from the stored value
		if (opts.value != null && opts.value !== "") {
			if (multi) {
				opts.value.split(",").forEach(function (t) { t = t.trim(); if (t) chips.push(t); });
			} else {
				input.value = opts.value;
			}
		}

		control.appendChild(input);
		control.appendChild(toggle);
		wrap.appendChild(control);
		wrap.appendChild(list);
		wrap.appendChild(hidden);
		renderChips();
		syncValue();
		return { el: wrap, input: input };
	}

	// buildValue replaces a condition row's value cell with the control that fits
	// the chosen field, preserving the current value and keeping the c_val_N name.
	// Fields that have suggestions (a named-set address, an interface, a flag set)
	// get a combobox — type or pick, in one field; the rest get a plain text box,
	// and a fixed enum keeps its dropdown.
	function buildValue(cell, name, fieldKey, current) {
		cell.innerHTML = "";
		var info = matches[fieldKey];
		var kind = info && info.kind;

		// A valueless match (e.g. the reverse-path check) takes no value at all.
		if (fieldKey && kind === "none") {
			var note = document.createElement("span");
			note.className = "knob-noval text-muted";
			note.textContent = "no value needed";
			cell.appendChild(note);
			return null;
		}

		if (fieldKey && kind === "enum" && info.options) {
			var sel = document.createElement("select");
			sel.name = name;
			sel.className = "knob-val";
			sel.setAttribute("aria-label", "Condition value");
			info.options.forEach(function (o) {
				var label = o.label && o.label !== o.value ? o.value + " — " + o.label : o.value;
				sel.appendChild(opt(o.value, label, o.value === current));
			});
			cell.appendChild(sel);
			return sel;
		}

		// Address: type an address/CIDR/range or pick a named set (as @name4/@name6).
		if (fieldKey && ADDR_KEYS[fieldKey]) {
			var suffix = fieldKey.indexOf("ip6.") === 0 ? "6" : "4";
			var setOpts = sets.map(function (s) {
				return { value: "@" + s + suffix, label: "@" + s, help: "named set" };
			});
			var addr = makeCombo({
				name: name, value: current, options: setOpts, multi: true,
				placeholder: (info && info.example) ? info.example + ", or @set…" : "address or @set",
			});
			cell.appendChild(addr.el);
			return addr.input;
		}

		// Flags / enum-list: pick one or more of the field's options, or type.
		if (fieldKey && kind === "flags" && info.options && info.options.length) {
			var flagOpts = info.options.map(function (o) {
				return { value: o.value, label: o.value, help: o.help || o.label };
			});
			var flags = makeCombo({
				name: name, value: current, options: flagOpts, multi: true, placeholder: "pick or type…",
			});
			cell.appendChild(flags.el);
			return flags.input;
		}

		// Interface: type a name or pick a real one off the box (multiple allowed).
		if (fieldKey && kind === "iface") {
			var ifOpts = interfaces.map(function (v) { return { value: v, label: v }; });
			var iface = makeCombo({
				name: name, value: current, options: ifOpts, multi: true, placeholder: "interface name",
			});
			cell.appendChild(iface.el);
			return iface.input;
		}

		var input = document.createElement("input");
		input.type = "text";
		input.name = name;
		input.setAttribute("aria-label", "Condition value");
		input.className = "knob-val";
		input.autocomplete = "off";
		input.value = current || "";
		input.placeholder = fieldKey && info && info.example ? info.example : "value";
		cell.appendChild(input);
		return input;
	}

	// buildOps repopulates a condition row's operator dropdown with only the
	// operators the chosen field supports (== / != for an address; the full
	// ordered set for a port or TTL), labelled in plain words. The current
	// operator is kept when the new field still allows it, else it falls back to
	// the field's first. With no field chosen the operator is hidden — it has
	// nothing to compare yet.
	function buildOps(sel, fieldKey, current) {
		var info = matches[fieldKey];
		var ops = (info && info.ops && info.ops.length) ? info.ops : DEFAULT_OPS;
		sel.hidden = !fieldKey;
		sel.innerHTML = "";
		var keep = ops.indexOf(current) !== -1 ? current : ops[0];
		ops.forEach(function (op) { sel.appendChild(opt(op, OP_LABEL[op] || op, op === keep)); });
	}

	// makeRemove builds the per-row "remove" control (an ×) and wires it to the
	// given clear function. Injected by JS so the no-JS form (which drops empty
	// rows on save) is unaffected.
	function makeRemove(clear) {
		var btn = document.createElement("button");
		btn.type = "button";
		btn.className = "knob-remove";
		btn.textContent = "×";
		btn.title = "Remove";
		btn.setAttribute("aria-label", "Remove this row");
		btn.addEventListener("click", clear);
		return btn;
	}

	function wireCondRow(row) {
		var field = row.querySelector(".knob-field");
		var op = row.querySelector(".knob-op");
		var cell = row.querySelector(".knob-val-cell");
		var help = row.querySelector(".knob-help");
		if (!field || !cell) return;
		var name = "c_val_" + row.getAttribute("data-index");
		var remove = makeRemove(function () {
			field.value = "";
			update();
			row.classList.add("extra"); // hide it; empty rows are ignored on save
			refreshAddButtons();
			schedulePreview();
		});
		cell.insertAdjacentElement("afterend", remove);
		function update(focusVal) {
			var cur = "";
			var existing = cell.querySelector("[name='" + name + "']");
			if (existing) cur = existing.value;
			if (op) {
				buildOps(op, field.value, op.value);
				// A valueless match compares nothing — hide the operator too.
				var mi = matches[field.value];
				if (mi && mi.kind === "none") op.hidden = true;
			}
			var valInput = buildValue(cell, name, field.value, cur);
			remove.hidden = !field.value;
			renderHelp(help, matches[field.value]);
			if (focusVal && valInput && valInput.focus) valInput.focus();
		}
		field.addEventListener("change", function () { update(true); });
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
		// Put the action select and its remove control on one line.
		var head = document.createElement("div");
		head.className = "act-head";
		action.parentNode.insertBefore(head, action);
		head.appendChild(action);
		var remove = makeRemove(function () {
			action.value = "";
			update();
			row.classList.add("extra");
			refreshAddButtons();
			schedulePreview();
		});
		head.appendChild(remove);
		function update() {
			var key = action.value;
			params.forEach(function (p) {
				var forList = (p.getAttribute("data-for") || "").split(",");
				p.style.display = key && forList.indexOf(key) !== -1 ? "" : "none";
			});
			remove.hidden = !key;
			renderHelp(help, statements[key], null);
		}
		action.addEventListener("change", update);
		update();
	}

	document.querySelectorAll(".cond-row").forEach(wireCondRow);
	document.querySelectorAll(".act-row").forEach(wireActRow);

	// "Add condition" / "Add action" reveal the next hidden (.extra) row, move
	// focus into it, and disable the button once no slots remain (a removed row
	// becomes a slot again).
	var addCond = document.getElementById("add-cond");
	var addAct = document.getElementById("add-act");

	function refreshAddButtons() {
		if (addCond) addCond.disabled = !document.querySelector("#conds .knob-row.extra");
		if (addAct) addAct.disabled = !document.querySelector("#acts .knob-row.extra");
	}

	function revealNext(containerId) {
		var container = document.getElementById(containerId);
		if (!container) return;
		var hidden = container.querySelector(".knob-row.extra");
		if (!hidden) return;
		hidden.classList.remove("extra");
		var focusable = hidden.querySelector(".knob-field, .knob-action");
		if (focusable) focusable.focus();
		refreshAddButtons();
	}

	if (addCond) addCond.addEventListener("click", function () { revealNext("conds"); updatePreview(); });
	if (addAct) addAct.addEventListener("click", function () { revealNext("acts"); updatePreview(); });
	refreshAddButtons();

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
