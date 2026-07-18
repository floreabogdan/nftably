package web

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/floreabogdan/nftably/internal/store"
)

// listRow is one list on the overview: the list plus what hangs off it.
type listRow struct {
	store.IPList
	Entries   int
	UsedBy    int
	FirstCIDR string
}

type listsVM struct {
	nav
	Lists []listRow
	Saved bool
	Err   string
}

func (s *Server) handleLists(w http.ResponseWriter, r *http.Request) {
	lists, err := s.store.ListLists()
	if err != nil {
		s.serverError(w, "list lists", err)
		return
	}
	entries, err := s.store.AllEntries()
	if err != nil {
		s.serverError(w, "list entries", err)
		return
	}
	used, err := s.store.SetReferenceCounts()
	if err != nil {
		s.serverError(w, "set reference counts", err)
		return
	}

	vm := listsVM{
		nav:   s.navFor(r, "lists"),
		Saved: r.URL.Query().Get("saved") == "1",
		Err:   r.URL.Query().Get("err"),
	}
	for _, l := range lists {
		row := listRow{IPList: l, Entries: len(entries[l.ID]), UsedBy: used[l.Name]}
		if len(entries[l.ID]) > 0 {
			row.FirstCIDR = entries[l.ID][0].CIDR
		}
		vm.Lists = append(vm.Lists, row)
	}
	render(w, s.log, "lists.html", vm)
}

func (s *Server) handleListCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	l := store.IPList{
		Name:        strings.TrimSpace(r.FormValue("name")),
		Role:        r.FormValue("role"),
		Note:        strings.TrimSpace(r.FormValue("note")),
		Source:      r.FormValue("source"),
		SourceArg:   sourceArgFromForm(r),
		AutoRefresh: r.FormValue("auto_refresh") == "on",
	}
	id, err := s.store.CreateList(l)
	if err != nil {
		redirectMsg(w, r, "/lists", "err", err.Error())
		return
	}
	s.audit(r, fmt.Sprintf("created list %q (%s)", l.Name, roleLabel(l.Role)))
	// A sourced list is empty until its first refresh — do it now so the operator
	// lands on a populated page. Best-effort: the outcome (an error or a count) is
	// recorded on the list and shown on its page.
	if l.Source == store.SourceGeoIP || l.Source == store.SourceURL {
		_, _ = s.doRefresh(r.Context(), id)
	}
	http.Redirect(w, r, "/lists/"+strconv.FormatInt(id, 10), http.StatusSeeOther)
}

// sourceArgFromForm reads the source argument for the chosen source: the country
// code for GeoIP, the URL for a feed, nothing for a manual list.
func sourceArgFromForm(r *http.Request) string {
	switch r.FormValue("source") {
	case store.SourceGeoIP:
		return strings.TrimSpace(r.FormValue("country"))
	case store.SourceURL:
		return strings.TrimSpace(r.FormValue("feed_url"))
	}
	return ""
}

// doRefresh regenerates a sourced list's entries and records the result,
// returning the entry count. Safe to call on any list; a manual list simply gets
// an error note.
func (s *Server) doRefresh(ctx context.Context, listID int64) (int, error) {
	l, err := s.store.GetList(listID)
	if err != nil {
		return 0, err
	}
	n, err := s.refreshList(ctx, l)
	if err != nil {
		_ = s.store.SetListRefreshNote(listID, "refresh failed: "+err.Error())
		return 0, err
	}
	_ = s.store.SetListRefreshed(listID, refreshNote(n))
	return n, nil
}

// handleListRefresh regenerates a sourced list's entries on demand.
func (s *Server) handleListRefresh(w http.ResponseWriter, r *http.Request) {
	l, ok := s.listFromPath(w, r)
	if !ok {
		return
	}
	back := fmt.Sprintf("/lists/%d", l.ID)
	if !l.IsSourced() {
		redirectMsg(w, r, back, "err", "This list is hand-edited — there's no source to refresh.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	n, err := s.refreshList(ctx, l)
	if err != nil {
		_ = s.store.SetListRefreshNote(l.ID, "refresh failed: "+err.Error())
		redirectMsg(w, r, back, "err", "Refresh failed: "+err.Error())
		return
	}
	_ = s.store.SetListRefreshed(l.ID, refreshNote(n))
	s.audit(r, fmt.Sprintf("refreshed list %q (%d entries)", l.Name, n))
	redirectMsg(w, r, back, "saved", "1")
}

// listDetailVM is one list's page: entries, and the object-model rules that
// reference it as a set.
type listDetailVM struct {
	nav
	List        store.IPList
	Entries     []store.ListEntry
	UsedBy      []store.SetUsage
	LastRefresh time.Time // parsed List.LastRefresh, zero if never
	Saved       bool
	Err         string
}

func (s *Server) handleListDetail(w http.ResponseWriter, r *http.Request) {
	l, ok := s.listFromPath(w, r)
	if !ok {
		return
	}
	entries, err := s.store.ListEntries(l.ID)
	if err != nil {
		s.serverError(w, "list entries", err)
		return
	}
	usedBy, err := s.store.RulesReferencingSet(l.Name)
	if err != nil {
		s.serverError(w, "rules referencing set", err)
		return
	}
	var lastRefresh time.Time
	if l.LastRefresh != "" {
		lastRefresh, _ = time.Parse(time.RFC3339Nano, l.LastRefresh)
	}
	render(w, s.log, "list_detail.html", listDetailVM{
		nav:         s.navFor(r, "lists"),
		List:        l,
		Entries:     entries,
		UsedBy:      usedBy,
		LastRefresh: lastRefresh,
		Saved:       r.URL.Query().Get("saved") == "1",
		Err:         r.URL.Query().Get("err"),
	})
}

func (s *Server) handleListUpdate(w http.ResponseWriter, r *http.Request) {
	l, ok := s.listFromPath(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	back := fmt.Sprintf("/lists/%d", l.ID)
	l.Name = strings.TrimSpace(r.FormValue("name"))
	l.Role = r.FormValue("role")
	l.Note = strings.TrimSpace(r.FormValue("note"))
	l.Source = r.FormValue("source")
	l.SourceArg = sourceArgFromForm(r)
	l.AutoRefresh = r.FormValue("auto_refresh") == "on"
	if err := s.store.UpdateList(l); err != nil {
		redirectMsg(w, r, back, "err", err.Error())
		return
	}
	s.audit(r, fmt.Sprintf("updated list %q (%s)", l.Name, roleLabel(l.Role)))
	redirectMsg(w, r, back, "saved", "1")
}

func (s *Server) handleListDelete(w http.ResponseWriter, r *http.Request) {
	l, ok := s.listFromPath(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteList(l.ID); err != nil {
		redirectMsg(w, r, fmt.Sprintf("/lists/%d", l.ID), "err", err.Error())
		return
	}
	s.audit(r, fmt.Sprintf("deleted list %q", l.Name))
	http.Redirect(w, r, "/lists", http.StatusSeeOther)
}

func (s *Server) handleListEntryAdd(w http.ResponseWriter, r *http.Request) {
	l, ok := s.listFromPath(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	back := fmt.Sprintf("/lists/%d", l.ID)
	if l.IsSourced() {
		redirectMsg(w, r, back, "err", "This list's addresses come from its source — refresh it instead of editing by hand.")
		return
	}
	cidr := r.FormValue("cidr")
	if l.Role == store.RoleBlock {
		if msg := s.refuseSelfBlock(r, cidr); msg != "" {
			redirectMsg(w, r, back, "err", msg)
			return
		}
	}
	if err := s.store.AddListEntry(l.ID, cidr, r.FormValue("note")); err != nil {
		redirectMsg(w, r, back, "err", err.Error())
		return
	}
	s.audit(r, fmt.Sprintf("added %s to list %q", strings.TrimSpace(cidr), l.Name))
	redirectMsg(w, r, back, "saved", "1")
}

func (s *Server) handleListEntryDelete(w http.ResponseWriter, r *http.Request) {
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
	s.audit(r, fmt.Sprintf("removed %s from its list", e.CIDR))
	http.Redirect(w, r, fmt.Sprintf("/lists/%d", e.ListID), http.StatusSeeOther)
}

// handleQuickBlock is the one-click block: used by the Connections page (and
// anything else) to put a single address on the first block-role list. Same
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

	ip := r.FormValue("ip")
	if msg := s.refuseSelfBlock(r, ip); msg != "" {
		redirectMsg(w, r, back, "err", msg)
		return
	}
	bl, err := s.blockRoleList()
	if err != nil {
		s.serverError(w, "find block list", err)
		return
	}
	if err := s.store.AddListEntry(bl.ID, ip, "blocked from the connections view"); err != nil {
		if errors.Is(err, store.ErrOverlap) {
			redirectMsg(w, r, back, "err", "Already blocked: "+err.Error())
			return
		}
		redirectMsg(w, r, back, "err", err.Error())
		return
	}
	// Make sure something actually drops the blacklist: a bare set with no rule
	// referencing it blocks nothing. If there's an input chain, ensure the early
	// drop rules exist (a preset already adds them; this covers a hand-built
	// firewall so the Block button is never a no-op).
	if chainID, ok := s.primaryInputChainID(); ok {
		if _, err := s.ensureBlockDropRules(chainID, bl.Name); err != nil {
			s.log.Warn("could not ensure blacklist drop rules", "error", err)
		}
	}
	s.audit(r, fmt.Sprintf("blacklisted %s (list %q)", ip, bl.Name))
	redirectMsg(w, r, back, "saved", "1")
}

// blockRoleList returns the first block-role list, creating the default
// "blacklist" if the operator deleted them all.
func (s *Server) blockRoleList() (store.IPList, error) {
	lists, err := s.store.ListLists()
	if err != nil {
		return store.IPList{}, err
	}
	for _, l := range lists {
		if l.Role == store.RoleBlock {
			return l, nil
		}
	}
	id, err := s.store.CreateList(store.IPList{Name: "blacklist", Role: store.RoleBlock,
		Note: "Dropped before established connections — blocking also cuts live sessions."})
	if err != nil {
		return store.IPList{}, err
	}
	return s.store.GetList(id)
}

// refuseSelfBlock stops the operator from blacklisting the address they are
// connecting from. The established-state ordering would not save them: block
// lists are deliberately checked before established, so this block would cut
// the very session that clicked it.
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

func (s *Server) listFromPath(w http.ResponseWriter, r *http.Request) (store.IPList, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return store.IPList{}, false
	}
	l, err := s.store.GetList(id)
	if err == store.ErrNotFound {
		http.NotFound(w, r)
		return store.IPList{}, false
	}
	if err != nil {
		s.serverError(w, "get list", err)
		return store.IPList{}, false
	}
	return l, true
}

func redirectMsg(w http.ResponseWriter, r *http.Request, back, key, val string) {
	http.Redirect(w, r, back+"?"+key+"="+url.QueryEscape(val), http.StatusSeeOther)
}

func roleLabel(role string) string {
	switch role {
	case store.RoleAllow:
		return "always allow"
	case store.RoleBlock:
		return "always block"
	}
	return "address group"
}
