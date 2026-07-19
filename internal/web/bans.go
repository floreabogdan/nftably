package web

import (
	"context"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

// bans.go surfaces the live auto-ban timeout sets — who the kernel is currently
// blocking — and lets the operator lift a ban early. A ban is transient kernel
// state (it expires on its own), so unbanning acts on the kernel directly rather
// than through the reviewed model.

// banEntry is one currently-banned source.
type banEntry struct {
	Family string
	Table  string
	Set    string
	IP     string
}

// nftIdentRe is the safe identifier charset for a table/set name coming back on
// the unban form — the same closed set nft accepts as a bare identifier, so the
// value can't inject extra nft tokens when re-parsed from the command line.
var nftIdentRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)

var banFamilies = map[string]bool{"inet": true, "ip": true, "ip6": true, "arp": true, "bridge": true, "netdev": true}

// currentBans reads the live dynamic (timeout) sets and returns their members,
// sorted by set then address. Best-effort: no nft or a read error yields none.
func (s *Server) currentBans(ctx context.Context) []banEntry {
	if !s.nft.Available() {
		return nil
	}
	members, err := s.nft.DynamicSetMembers(ctx)
	if err != nil {
		return nil
	}
	var out []banEntry
	for key, ips := range members {
		parts := strings.SplitN(key, "/", 3) // "<family>/<table>/<set>"
		if len(parts) != 3 {
			continue
		}
		for _, ip := range ips {
			out = append(out, banEntry{Family: parts[0], Table: parts[1], Set: parts[2], IP: ip})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Set != out[j].Set {
			return out[i].Set < out[j].Set
		}
		return out[i].IP < out[j].IP
	})
	return out
}

// handleHardenUnban removes one source from a live ban set. Every field is
// validated (family against the known set, table/set as bare identifiers, the
// address parsed and re-serialized) so nothing untrusted reaches nft, which
// re-parses its argument list.
func (s *Server) handleHardenUnban(w http.ResponseWriter, r *http.Request) {
	family := strings.TrimSpace(r.FormValue("family"))
	table := strings.TrimSpace(r.FormValue("table"))
	set := strings.TrimSpace(r.FormValue("set"))
	rawIP := strings.TrimSpace(r.FormValue("ip"))

	if !banFamilies[family] || !nftIdentRe.MatchString(table) || !nftIdentRe.MatchString(set) {
		redirectErr(w, r, "/harden", "That ban reference isn't valid.")
		return
	}
	ip := canonicalAddr(rawIP)
	if ip == "" {
		redirectErr(w, r, "/harden", "That isn't a valid address to unban.")
		return
	}

	ctx, cancel := reqCtx(r)
	defer cancel()
	if err := s.nft.DeleteSetElement(ctx, family, table, set, ip); err != nil {
		redirectErr(w, r, "/harden", "Could not lift the ban: "+err.Error())
		return
	}
	s.audit(r, "lifted the ban on "+ip)
	http.Redirect(w, r, "/harden", http.StatusSeeOther)
}

// canonicalAddr parses an address or prefix and returns its canonical string, or
// "" if it isn't a valid address/prefix — so only a clean value reaches nft.
func canonicalAddr(v string) string {
	if p, err := netip.ParsePrefix(v); err == nil {
		return p.String()
	}
	if a, err := netip.ParseAddr(v); err == nil {
		return a.String()
	}
	return ""
}
