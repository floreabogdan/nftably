package web

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/floreabogdan/nftably/internal/store"
)

// alerts.go is the CRUD + test for alert destinations. The list lives on the
// Settings → Alerts tab; add/edit is a page of its own. Delivery is handled by
// the notify.Dispatcher; this is just configuration.

type alertFormVM struct {
	nav
	IsNew      bool
	Dest       store.Destination
	Errs       map[string]string
	EventKinds []store.AlertEventKind
}

func (s *Server) renderAlertForm(w http.ResponseWriter, r *http.Request, vm alertFormVM) {
	vm.nav = s.navFor(r, "settings")
	vm.EventKinds = store.AlertEventKinds()
	render(w, s.log, "alert_form.html", vm)
}

func (s *Server) handleAlertNew(w http.ResponseWriter, r *http.Request) {
	s.renderAlertForm(w, r, alertFormVM{
		IsNew: true,
		Dest:  store.Destination{Type: store.AlertWebhook, Enabled: true, SMTPPort: 587, SMTPSecurity: store.SMTPStartTLS},
	})
}

// alertFromPath loads the destination named by the {id} path value.
func (s *Server) alertFromPath(w http.ResponseWriter, r *http.Request) (store.Destination, bool) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	d, err := s.store.GetAlertDestination(id)
	if err != nil {
		http.NotFound(w, r)
		return store.Destination{}, false
	}
	return d, true
}

func (s *Server) handleAlertEdit(w http.ResponseWriter, r *http.Request) {
	d, ok := s.alertFromPath(w, r)
	if !ok {
		return
	}
	s.renderAlertForm(w, r, alertFormVM{Dest: d})
}

func (s *Server) handleAlertSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	d := alertFromForm(r)
	isNew := d.ID == 0
	if errs := d.Validate(); len(errs) > 0 {
		s.renderAlertForm(w, r, alertFormVM{IsNew: isNew, Dest: d, Errs: errs})
		return
	}
	var err error
	if isNew {
		_, err = s.store.CreateAlertDestination(d)
	} else {
		err = s.store.UpdateAlertDestination(d)
	}
	if err != nil {
		// A duplicate name is the common failure; surface it on the form.
		s.renderAlertForm(w, r, alertFormVM{IsNew: isNew, Dest: d, Errs: map[string]string{"name": "Could not save: " + err.Error()}})
		return
	}
	s.audit(r, "saved alert destination "+d.Name)
	http.Redirect(w, r, "/settings?tab=alerts", http.StatusSeeOther)
}

func (s *Server) handleAlertDelete(w http.ResponseWriter, r *http.Request) {
	d, ok := s.alertFromPath(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteAlertDestination(d.ID); err != nil {
		s.serverError(w, "delete alert destination", err)
		return
	}
	s.audit(r, "deleted alert destination "+d.Name)
	http.Redirect(w, r, "/settings?tab=alerts", http.StatusSeeOther)
}

func (s *Server) handleAlertTest(w http.ResponseWriter, r *http.Request) {
	d, ok := s.alertFromPath(w, r)
	if !ok {
		return
	}
	if err := s.notifier.SendTest(d); err != nil {
		http.Redirect(w, r, "/settings?tab=alerts&err="+urlEscape("Test to "+d.Name+" failed: "+err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/settings?tab=alerts&saved="+urlEscape("Test alert sent to "+d.Name+"."), http.StatusSeeOther)
}

// alertFromForm builds a Destination from the posted form (unvalidated).
func alertFromForm(r *http.Request) store.Destination {
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	port, _ := strconv.Atoi(r.FormValue("smtp_port"))
	// Selected event kinds; none checked ⇒ empty ⇒ all.
	var events []string
	for _, k := range store.AlertEventKinds() {
		if r.FormValue("event_"+k.Kind) != "" {
			events = append(events, k.Kind)
		}
	}
	return store.Destination{
		ID:           id,
		Name:         r.FormValue("name"),
		Type:         r.FormValue("type"),
		Enabled:      r.FormValue("enabled") != "",
		URL:          r.FormValue("url"),
		SMTPHost:     r.FormValue("smtp_host"),
		SMTPPort:     port,
		SMTPUsername: r.FormValue("smtp_username"),
		SMTPPassword: r.FormValue("smtp_password"),
		SMTPFrom:     r.FormValue("smtp_from"),
		SMTPTo:       r.FormValue("smtp_to"),
		SMTPSecurity: r.FormValue("smtp_security"),
		Events:       strings.Join(events, ","),
	}
}
