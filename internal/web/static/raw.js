(function () {
	var btn = document.getElementById("copy-raw");
	var pre = document.getElementById("raw-ruleset");
	if (!btn || !pre) return;
	btn.addEventListener("click", function () {
		navigator.clipboard.writeText(pre.textContent).then(function () {
			var old = btn.textContent;
			btn.textContent = "Copied";
			setTimeout(function () { btn.textContent = old; }, 1200);
		});
	});
})();
