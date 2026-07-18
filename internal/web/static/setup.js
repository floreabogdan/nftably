// Live preview for the guided setup: post the form to /setup/preview
// (debounced) and swap the generated-config panel. The server rendered a
// correct preview on first paint, so with JS off nothing is lost.
(function () {
	var form = document.getElementById('setup-form');
	var panel = document.getElementById('setup-preview');
	if (!form || !panel) return;

	var timer = null;
	var inflight = null;

	function refresh() {
		if (inflight) inflight.abort();
		inflight = new AbortController();
		var body = new URLSearchParams(new FormData(form));
		fetch('/setup/preview', {
			method: 'POST',
			body: body,
			signal: inflight.signal,
			headers: { 'Accept': 'text/html' }
		}).then(function (res) {
			if (!res.ok) throw new Error('preview ' + res.status);
			return res.text();
		}).then(function (html) {
			panel.innerHTML = html;
		}).catch(function () { /* keep the last good preview */ });
	}

	form.addEventListener('input', function () {
		clearTimeout(timer);
		timer = setTimeout(refresh, 350);
	});
	form.addEventListener('change', function () {
		clearTimeout(timer);
		timer = setTimeout(refresh, 100);
	});
})();
