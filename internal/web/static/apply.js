// Countdown for the pending-apply panel. The deadline is authoritative on the
// server; this only tells the operator how long they have. Shortly after it
// passes, reload — the server has reverted by then and the page should say so.
(function () {
	var panel = document.getElementById("pending-panel");
	var label = document.getElementById("apply-countdown");
	if (!panel || !label) return;
	var bar = document.getElementById("apply-countdown-bar");
	var live = document.getElementById("apply-countdown-live");
	var confirmBtn = document.getElementById("confirm-btn");
	var deadline = parseInt(panel.getAttribute("data-deadline"), 10) * 1000;
	var total = 0;
	var lastAnnounced = -1;

	// This is the highest-stakes moment in the app — land the operator on the
	// Confirm button so a keyboard/screen-reader user can act without hunting.
	if (confirmBtn) {
		try { confirmBtn.focus(); } catch (e) { /* focus is best-effort */ }
	}

	// Announce to assistive tech at a readable cadence — every 10s, then each of
	// the final five seconds — instead of on every 250ms tick.
	function announce(left) {
		if (!live) return;
		if ((left <= 5 || left % 10 === 0) && left !== lastAnnounced) {
			lastAnnounced = left;
			live.textContent = left + " seconds until auto-revert. Confirm to keep the new rules.";
		}
	}

	function tick() {
		var left = Math.round((deadline - Date.now()) / 1000);
		if (left <= -2) {
			window.location.reload();
			return;
		}
		var shown = Math.max(left, 0);
		if (total === 0) total = Math.max(shown, 1); // first tick ≈ the full window
		label.textContent = shown;
		if (bar) {
			bar.style.width = Math.max(0, Math.min(100, (shown / total) * 100)) + "%";
		}
		// Warm the panel as the deadline nears so urgency is visible at a glance.
		panel.classList.toggle("countdown-urgent", shown <= 10);
		announce(shown);
		setTimeout(tick, 250);
	}
	tick();
})();
