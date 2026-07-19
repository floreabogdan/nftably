package web

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/floreabogdan/nftably/internal/store"
)

// flowtables_web.go is the CRUD for flowtables on the Firewall page — the
// offload objects a rule references with a `flow add @name` statement. Like
// chains, they're owned per table and model-only until applied.

func (s *Server) handleFlowtableCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	tableID, _ := strconv.ParseInt(r.FormValue("table_id"), 10, 64)
	f := store.Flowtable{
		TableID:   tableID,
		Name:      strings.TrimSpace(r.FormValue("name")),
		Priority:  strings.TrimSpace(r.FormValue("priority")),
		Devices:   strings.TrimSpace(r.FormValue("devices")),
		HWOffload: r.FormValue("hw_offload") == "on",
	}
	if errs := f.Validate(); len(errs) > 0 {
		redirectErr(w, r, "/firewall", errs[0])
		return
	}
	if _, err := s.store.CreateFlowtable(f); err != nil {
		redirectErr(w, r, "/firewall", "Could not create flowtable: "+err.Error())
		return
	}
	s.audit(r, "created flowtable "+f.Name)
	http.Redirect(w, r, "/firewall?saved=1", http.StatusSeeOther)
}

func (s *Server) handleFlowtableDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteFlowtable(pathID(r)); err != nil {
		redirectErr(w, r, "/firewall", "Could not delete flowtable: "+err.Error())
		return
	}
	s.audit(r, "deleted a flowtable")
	http.Redirect(w, r, "/firewall?saved=1", http.StatusSeeOther)
}
