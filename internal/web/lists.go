package web

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/floreabogdan/nftably/internal/store"
)

type listsVM struct {
	nav
	Mgmt  []store.ListEntry
	Block []store.ListEntry
	Saved bool
	Err   string
}

func (s *Server) handleLists(w http.ResponseWriter, r *http.Request) {
	mgmt, err := s.store.ListEntries(store.ListMgmt)
	if err != nil {
		s.serverError(w, "list mgmt entries", err)
		return
	}
	block, err := s.store.ListEntries(store.ListBlock)
	if err != nil {
		s.serverError(w, "list block entries", err)
		return
	}
	render(w, s.log, "lists.html", listsVM{
		nav:   s.navFor(r, "lists"),
		Mgmt:  mgmt,
		Block: block,
		Saved: r.URL.Query().Get("saved") == "1",
		Err:   r.URL.Query().Get("err"),
	})
}

func (s *Server) handleListAdd(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	list := r.FormValue("list")
	cidr := r.FormValue("cidr")
	note := r.FormValue("note")

	if list == store.ListBlock {
		if msg := s.refuseSelfBlock(r, cidr); msg != "" {
			listsRedirect(w, r, "err", msg)
			return
		}
	}
	if err := s.store.AddListEntry(list, cidr, note); err != nil {
		listsRedirect(w, r, "err", err.Error())
		return
	}
	verb := "blacklisted"
	if list == store.ListMgmt {
		verb = "added to the management list"
	}
	s.audit(r, fmt.Sprintf("%s %s", verb, cidr))
	listsRedirect(w, r, "saved", "1")
}

func (s *Server) handleListDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	e, err := s.store.GetListEntry(id)
	if err == store.ErrNotFound {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.serverError(w, "get list entry", err)
		return
	}
	if err := s.store.DeleteListEntry(id); err != nil && err != store.ErrNotFound {
		s.serverError(w, "delete list entry", err)
		return
	}
	s.audit(r, fmt.Sprintf("removed %s from the %s list", e.CIDR, e.List))
	http.Redirect(w, r, "/lists", http.StatusSeeOther)
}

// refuseSelfBlock stops the operator from blacklisting the address they are
// connecting from. The management list and established-state ordering would
// not save them: the blacklist is deliberately checked before established, so
// this block would cut the very session that clicked it.
func (s *Server) refuseSelfBlock(r *http.Request, cidr string) string {
	norm, msg := store.NormalizeCIDR(cidr)
	if msg != "" {
		return "" // let AddListEntry produce the real validation error
	}
	p, err := store.EntryPrefix(norm)
	if err != nil {
		return ""
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return ""
	}
	peer = peer.Unmap()
	if p.Contains(peer) {
		return fmt.Sprintf("%s contains %s — the address you are connecting from. Blocking yourself would cut this session on apply; if you really mean it, do it from another address.", norm, peer)
	}
	return ""
}

func listsRedirect(w http.ResponseWriter, r *http.Request, key, val string) {
	http.Redirect(w, r, "/lists?"+key+"="+url.QueryEscape(val), http.StatusSeeOther)
}

// handleQuickBlock is the one-click block: used by the Connections page (and
// anything else) to put a single address on the blacklist. Same guard, same
// review-then-apply flow — nothing reaches the kernel until /changes. The
// caller can name a local page to return to via "back".
func (s *Server) handleQuickBlock(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	back := r.FormValue("back")
	if !strings.HasPrefix(back, "/") || strings.HasPrefix(back, "//") {
		back = "/lists"
	}
	redirect := func(key, val string) {
		http.Redirect(w, r, back+"?"+key+"="+url.QueryEscape(val), http.StatusSeeOther)
	}

	ip := r.FormValue("ip")
	if msg := s.refuseSelfBlock(r, ip); msg != "" {
		redirect("err", msg)
		return
	}
	if err := s.store.AddListEntry(store.ListBlock, ip, "blocked from the connections view"); err != nil {
		if errors.Is(err, store.ErrOverlap) {
			redirect("err", "Already blocked: "+err.Error())
			return
		}
		redirect("err", err.Error())
		return
	}
	s.audit(r, "blacklisted "+ip+" from the connections view")
	redirect("saved", "1")
}
