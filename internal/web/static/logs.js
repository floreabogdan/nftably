// Auto-refresh for the firewall-log viewer. Opt-in, remembered per browser —
// the same pattern as the connections view. A short interval so a live tail of
// logged packets stays current, but paused while the operator is filtering so a
// surprise reload never eats their query.
(function () {
	var box = document.getElementById('auto-refresh');
	if (!box) return;
	var KEY = 'nftably-logs-refresh';
	box.checked = localStorage.getItem(KEY) === '1';
	var timer = null;
	function arm() {
		if (timer) clearInterval(timer);
		timer = null;
		if (box.checked) {
			timer = setInterval(function () {
				var search = document.getElementById('topbar-search-input');
				if (search && (document.activeElement === search || search.value)) return;
				location.replace('/logs');
			}, 4000);
		}
	}
	box.addEventListener('change', function () {
		localStorage.setItem(KEY, box.checked ? '1' : '0');
		arm();
	});
	arm();
})();
