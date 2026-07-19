// Alert destination form: show the webhook URL or the SMTP fields depending on
// the chosen type. Server-rendered hidden state is the no-JS fallback.
(function () {
	var form = document.querySelector("[data-alert-form]");
	if (!form) return;
	var sel = form.querySelector("[data-alert-type]");
	var urlGroup = form.querySelector('[data-alert-group="url"]');
	var emailGroup = form.querySelector('[data-alert-group="email"]');
	if (!sel) return;

	function sync() {
		var email = sel.value === "email";
		if (urlGroup) urlGroup.hidden = email;
		if (emailGroup) emailGroup.hidden = !email;
	}
	sel.addEventListener("change", sync);
	sync();
})();
