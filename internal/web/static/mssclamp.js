// The MSS-clamp wizard's mode switch: show only the input the chosen mode uses.
// Without JavaScript every field stays visible and the mode select still decides
// which one the server reads, so the form works either way.
(function () {
	var mode = document.querySelector("[data-mss-mode]");
	if (!mode) return;
	var fields = document.querySelectorAll("[data-mss-field]");

	function sync() {
		fields.forEach(function (f) {
			f.hidden = f.getAttribute("data-mss-field") !== mode.value;
		});
	}

	mode.addEventListener("change", sync);
	sync();
})();
