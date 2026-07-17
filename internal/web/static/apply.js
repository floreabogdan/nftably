// Countdown for the pending-apply panel. The deadline is authoritative on the
// server; this only tells the operator how long they have. Shortly after it
// passes, reload — the server has reverted by then and the page should say so.
(function () {
	var panel = document.getElementById("pending-panel");
	var label = document.getElementById("apply-countdown");
	if (!panel || !label) return;
	var deadline = parseInt(panel.getAttribute("data-deadline"), 10) * 1000;
	function tick() {
		var left = Math.round((deadline - Date.now()) / 1000);
		if (left <= -2) {
			window.location.reload();
			return;
		}
		label.textContent = Math.max(left, 0) + "s";
		setTimeout(tick, 500);
	}
	tick();
})();
