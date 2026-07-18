package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	nftconf "github.com/floreabogdan/nftably/internal/render"
	"github.com/floreabogdan/nftably/internal/store"
)

type forwardingVM struct {
	nav
	Firewall store.Firewall
	Forwards []store.PortForward
	Saved    bool
}

func (s *Server) handleForwarding(w http.ResponseWriter, r *http.Request) {
	fw, err := s.store.GetFirewall()
	if err != nil {
		s.serverError(w, "get firewall", err)
		return
	}
	pfs, err := s.store.ListPortForwards()
	if err != nil {
		s.serverError(w, "list port forwards", err)
		return
	}
	render(w, s.log, "forwarding.html", forwardingVM{
		nav:      s.navFor(r, "forwarding"),
		Firewall: fw,
		Forwards: pfs,
		Saved:    r.URL.Query().Get("saved") == "1",
	})
}

// handleForwardingSettings saves the router-wide knobs: WAN interface, forward
// policy, masquerade. Naming the WAN interface is what switches forwarding on.
func (s *Server) handleForwardingSettings(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	fw, err := s.store.GetFirewall()
	if err != nil {
		s.serverError(w, "get firewall", err)
		return
	}
	fw.WANIface = strings.TrimSpace(r.FormValue("wan_iface"))
	fw.ForwardPolicy = r.FormValue("forward_policy")
	fw.Masquerade = r.FormValue("masquerade") == "on"
	if err := s.store.SaveFirewall(fw); err != nil {
		// SaveFirewall's errors are already human-readable ("masquerade needs
		// the WAN interface set", bad interface name).
		http.Error(w, strings.TrimPrefix(err.Error(), "store: "), http.StatusBadRequest)
		return
	}
	if fw.WANIface == "" {
		s.audit(r, "switched forwarding off (no WAN interface)")
	} else {
		s.audit(r, fmt.Sprintf("set forwarding: wan %s, policy %s, masquerade %v", fw.WANIface, fw.ForwardPolicy, fw.Masquerade))
	}
	http.Redirect(w, r, "/forwarding?saved=1", http.StatusSeeOther)
}

type forwardFormVM struct {
	nav
	Forward store.PortForward
	IsNew   bool
	Errors  []string
	// Preview is the DNAT rule this forward renders to; empty while no WAN
	// interface is set (there is nothing true to show).
	Preview string
	// WANSet tells the form whether to warn that nothing renders yet.
	WANSet bool
}

func (s *Server) forwardPreview(p store.PortForward) (preview string, wanSet bool) {
	fw, err := s.store.GetFirewall()
	if err != nil || fw.WANIface == "" {
		return "", false
	}
	return nftconf.PortForwardLine(fw.WANIface, p), true
}

func (s *Server) handleForwardNew(w http.ResponseWriter, r *http.Request) {
	p := store.PortForward{Proto: "tcp", Enabled: true}
	_, wanSet := s.forwardPreview(p)
	render(w, s.log, "forward_form.html", forwardFormVM{
		nav:     s.navFor(r, "forwarding"),
		Forward: p,
		IsNew:   true,
		WANSet:  wanSet,
	})
}

func (s *Server) handleForwardEdit(w http.ResponseWriter, r *http.Request) {
	p, ok := s.forwardFromPath(w, r)
	if !ok {
		return
	}
	preview, wanSet := s.forwardPreview(p)
	render(w, s.log, "forward_form.html", forwardFormVM{
		nav:     s.navFor(r, "forwarding"),
		Forward: p,
		Preview: preview,
		WANSet:  wanSet,
	})
}

// handleForwardSave backs both the new and the edit form.
func (s *Server) handleForwardSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	isNew := r.PathValue("id") == ""
	p := store.PortForward{
		Name:     strings.TrimSpace(r.FormValue("name")),
		Proto:    r.FormValue("proto"),
		DPort:    strings.TrimSpace(r.FormValue("dport")),
		Dest:     strings.TrimSpace(r.FormValue("dest")),
		DestPort: strings.TrimSpace(r.FormValue("dest_port")),
		Enabled:  r.FormValue("enabled") == "on",
	}
	if !isNew {
		existing, ok := s.forwardFromPath(w, r)
		if !ok {
			return
		}
		p.ID = existing.ID
		p.Position = existing.Position
	}

	if errs := p.Validate(); len(errs) > 0 {
		_, wanSet := s.forwardPreview(p)
		render(w, s.log, "forward_form.html", forwardFormVM{
			nav:     s.navFor(r, "forwarding"),
			Forward: p,
			IsNew:   isNew,
			Errors:  errs,
			WANSet:  wanSet,
		})
		return
	}

	if isNew {
		if _, err := s.store.CreatePortForward(p); err != nil {
			s.serverError(w, "create port forward", err)
			return
		}
		s.audit(r, fmt.Sprintf("added port-forward %q (%s %s -> %s)", p.Name, p.Proto, p.DPort, p.Dest))
	} else {
		if err := s.store.UpdatePortForward(p); err != nil {
			s.serverError(w, "update port forward", err)
			return
		}
		s.audit(r, fmt.Sprintf("edited port-forward %q", p.Name))
	}
	http.Redirect(w, r, "/forwarding?saved=1", http.StatusSeeOther)
}

func (s *Server) handleForwardDelete(w http.ResponseWriter, r *http.Request) {
	p, ok := s.forwardFromPath(w, r)
	if !ok {
		return
	}
	if err := s.store.DeletePortForward(p.ID); err != nil {
		s.serverError(w, "delete port forward", err)
		return
	}
	s.audit(r, fmt.Sprintf("deleted port-forward %q", p.Name))
	http.Redirect(w, r, "/forwarding", http.StatusSeeOther)
}

func (s *Server) handleForwardToggle(w http.ResponseWriter, r *http.Request) {
	p, ok := s.forwardFromPath(w, r)
	if !ok {
		return
	}
	if err := s.store.SetPortForwardEnabled(p.ID, !p.Enabled); err != nil {
		s.serverError(w, "toggle port forward", err)
		return
	}
	verb := "enabled"
	if p.Enabled {
		verb = "disabled"
	}
	s.audit(r, fmt.Sprintf("%s port-forward %q", verb, p.Name))
	http.Redirect(w, r, "/forwarding", http.StatusSeeOther)
}

func (s *Server) handleForwardMove(w http.ResponseWriter, r *http.Request) {
	p, ok := s.forwardFromPath(w, r)
	if !ok {
		return
	}
	dir := 1
	if r.FormValue("dir") == "up" {
		dir = -1
	}
	if err := s.store.MovePortForward(p.ID, dir); err != nil {
		s.serverError(w, "move port forward", err)
		return
	}
	http.Redirect(w, r, "/forwarding", http.StatusSeeOther)
}

func (s *Server) forwardFromPath(w http.ResponseWriter, r *http.Request) (store.PortForward, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return store.PortForward{}, false
	}
	p, err := s.store.GetPortForward(id)
	if err == store.ErrNotFound {
		http.NotFound(w, r)
		return store.PortForward{}, false
	}
	if err != nil {
		s.serverError(w, "get port forward", err)
		return store.PortForward{}, false
	}
	return p, true
}
