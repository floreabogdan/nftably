// Auto-refresh for the connections view. Opt-in, remembered per browser.
(function () {
	var box = document.getElementById('auto-refresh');
	if (!box) return;
	var KEY = 'nftably-conn-refresh';
	box.checked = localStorage.getItem(KEY) === '1';
	var timer = null;
	function arm() {
		if (timer) clearInterval(timer);
		timer = null;
		if (box.checked) {
			timer = setInterval(function () {
				// Skip the reload while the operator is filtering or has a
				// form mid-click; a surprise reload eats their input.
				var search = document.getElementById('topbar-search-input');
				if (search && (document.activeElement === search || search.value)) return;
				location.replace('/connections');
			}, 5000);
		}
	}
	box.addEventListener('change', function () {
		localStorage.setItem(KEY, box.checked ? '1' : '0');
		arm();
	});
	arm();
})();
