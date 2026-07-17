// Delegated confirm dialogs: a form (or element) carrying data-confirm asks
// before submitting. Delegation keeps the templates free of inline handlers,
// which the CSP forbids.
(function () {
	document.addEventListener("submit", function (event) {
		var form = event.target.closest("form[data-confirm]");
		if (!form) return;
		if (!window.confirm(form.getAttribute("data-confirm"))) {
			event.preventDefault();
		}
	});
})();
