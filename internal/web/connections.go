package web

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"

	"github.com/floreabogdan/nftably/internal/conntrack"
	"github.com/floreabogdan/nftably/internal/store"
)

// maxConnRows caps the connections table; the top-IP aggregation still sees
// every flow. A busy router tracks tens of thousands of flows — rendering
// them all helps nobody.
const maxConnRows = 500

type connRow struct {
	Dir     string // in | out | routed
	Proto   string
	State   string
	Src     string // addr:port display form
	Dst     string
	Remote  netip.Addr
	Country string // flag + ISO, empty when unknown
	Blocked bool
}

type topIP struct {
	Addr    netip.Addr
	Count   int
	Country string
	Name    string
	Blocked bool
}

type connectionsVM struct {
	nav
	Note    string
	Rows    []connRow
	Total   int
	Shown   int
	Top     []topIP
	GeoOn   bool
	Saved   bool
	Err     string
	Refresh bool
}

// handleConnections is the live view: every flow conntrack knows about —
// to this box, from it, and (on a router) through it — with one-click block.
func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	flows, note := conntrack.Flows()

	st, _, err := s.store.GetSettings()
	if err != nil {
		s.serverError(w, "get settings", err)
		return
	}
	blockList, err := s.store.ListEntries(store.ListBlock)
	if err != nil {
		s.serverError(w, "list block entries", err)
		return
	}
	var blocked []netip.Prefix
	for _, e := range blockList {
		if p, err := store.EntryPrefix(e.CIDR); err == nil {
			blocked = append(blocked, p)
		}
	}
	isBlocked := func(a netip.Addr) bool {
		for _, p := range blocked {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}

	local := localAddrs()
	vm := connectionsVM{
		nav:     s.navFor(r, "connections"),
		Note:    note,
		GeoOn:   st.GeoIPDB != "",
		Saved:   r.URL.Query().Get("saved") == "1",
		Err:     r.URL.Query().Get("err"),
		Refresh: true,
	}

	counts := map[netip.Addr]int{}
	for _, f := range flows {
		if f.Src.IsLoopback() || f.Dst.IsLoopback() {
			continue
		}
		srcLocal, dstLocal := local[f.Src], local[f.Dst]
		if srcLocal && dstLocal {
			continue // the box talking to itself
		}
		dir, remote := classify(f, srcLocal, dstLocal)
		counts[remote]++
		vm.Total++
		if len(vm.Rows) >= maxConnRows {
			continue
		}
		iso, _ := s.geo.lookup(st.GeoIPDB, remote)
		vm.Rows = append(vm.Rows, connRow{
			Dir:     dir,
			Proto:   f.Proto,
			State:   f.State,
			Src:     hostPort(f.Src, f.SPort),
			Dst:     hostPort(f.Dst, f.DPort),
			Remote:  remote,
			Country: countryLabel(iso),
			Blocked: isBlocked(remote),
		})
	}
	vm.Shown = len(vm.Rows)

	for addr, n := range counts {
		iso, name := s.geo.lookup(st.GeoIPDB, addr)
		vm.Top = append(vm.Top, topIP{
			Addr: addr, Count: n,
			Country: countryLabel(iso), Name: name,
			Blocked: isBlocked(addr),
		})
	}
	sort.Slice(vm.Top, func(i, j int) bool {
		if vm.Top[i].Count != vm.Top[j].Count {
			return vm.Top[i].Count > vm.Top[j].Count
		}
		return vm.Top[i].Addr.Compare(vm.Top[j].Addr) < 0
	})
	if len(vm.Top) > 20 {
		vm.Top = vm.Top[:20]
	}

	render(w, s.log, "connections.html", vm)
}

// classify names a flow's direction relative to this box and picks the
// address worth aggregating on. For routed flows neither end is ours; prefer
// the public side, so a NATed LAN full of private addresses does not drown
// the actually-interesting internet peers.
func classify(f conntrack.Flow, srcLocal, dstLocal bool) (dir string, remote netip.Addr) {
	switch {
	case dstLocal && !srcLocal:
		return "in", f.Src
	case srcLocal && !dstLocal:
		return "out", f.Dst
	}
	srcPriv := f.Src.IsPrivate() || f.Src.IsLinkLocalUnicast()
	dstPriv := f.Dst.IsPrivate() || f.Dst.IsLinkLocalUnicast()
	if srcPriv && !dstPriv {
		return "routed", f.Dst
	}
	return "routed", f.Src
}

// localAddrs is the set of addresses assigned to this box's interfaces.
func localAddrs() map[netip.Addr]bool {
	out := map[netip.Addr]bool{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if addr, ok := netip.AddrFromSlice(ipn.IP); ok {
			out[addr.Unmap()] = true
		}
	}
	return out
}

func hostPort(a netip.Addr, port int) string {
	if port == 0 {
		return a.String()
	}
	if a.Is6() {
		return fmt.Sprintf("[%s]:%d", a, port)
	}
	return fmt.Sprintf("%s:%d", a, port)
}

func countryLabel(iso string) string {
	if iso == "" {
		return ""
	}
	if flag := flagEmoji(iso); flag != "" {
		return flag + " " + iso
	}
	return iso
}
