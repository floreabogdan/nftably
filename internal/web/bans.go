package web

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/floreabogdan/nftably/internal/nft"
)

// bans.go surfaces the live auto-ban timeout sets — who the kernel is currently
// blocking — and lets the operator lift a ban early. A ban is transient kernel
// state (it expires on its own), so unbanning acts on the kernel directly rather
// than through the reviewed model.

// banEntry is one currently-banned source, with the timeout metadata the kernel
// carries for it: when the ban started, how long it runs, and when it lifts.
type banEntry struct {
	Family string
	Table  string
	Set    string
	IP     string

	Country   string    // flag + ISO ("🇷🇺 RU"), empty when unknown or GeoIP off
	Duration  string    // total ban length, e.g. "1h" ("" if the element has no timeout)
	ExpiresIn string    // remaining until it lifts, e.g. "in 57m" ("never" if permanent)
	BannedAt  time.Time // when this ban started/refreshed; zero if unknown
	ExpiresAt time.Time // when it lifts; zero if unknown
}

// nftIdentRe is the safe identifier charset for a table/set name coming back on
// the unban form — the same closed set nft accepts as a bare identifier, so the
// value can't inject extra nft tokens when re-parsed from the command line.
var nftIdentRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)

var banFamilies = map[string]bool{"inet": true, "ip": true, "ip6": true, "arp": true, "bridge": true, "netdev": true}

// currentBans reads the live dynamic (timeout) sets and returns their members,
// each with its country (when geoPath points at a GeoIP DB) and ban timing, sorted
// by set then address. Best-effort: no nft or a read error yields none.
func (s *Server) currentBans(ctx context.Context, geoPath string) []banEntry {
	if !s.nft.Available() {
		return nil
	}
	members, err := s.nft.DynamicSetMembersDetailed(ctx)
	if err != nil {
		return nil
	}
	now := time.Now()
	var out []banEntry
	for key, ms := range members {
		parts := strings.SplitN(key, "/", 3) // "<family>/<table>/<set>"
		if len(parts) != 3 {
			continue
		}
		for _, m := range ms {
			e := banEntry{Family: parts[0], Table: parts[1], Set: parts[2], IP: m.Value}
			enrichBan(&e, m, now)
			if addr, ok := banAddr(m.Value); ok && geoPath != "" {
				iso, _ := s.geo.lookup(geoPath, addr)
				e.Country = countryLabel(iso)
			}
			out = append(out, e)
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

// enrichBan fills e's timing fields from an element's timeout/expiry (seconds).
// timeout is the configured ban length and expires the time left, so the ban
// started at now-(timeout-expires) and lifts at now+expires.
func enrichBan(e *banEntry, m nft.SetMember, now time.Time) {
	if m.Timeout > 0 {
		e.Duration = humanizeDuration(time.Duration(m.Timeout) * time.Second)
	}
	switch {
	case m.Expires > 0:
		e.ExpiresAt = now.Add(time.Duration(m.Expires) * time.Second)
		e.ExpiresIn = "in " + humanizeDuration(time.Duration(m.Expires)*time.Second)
	case m.Timeout == 0:
		e.ExpiresIn = "never" // a permanent (timeout-less) member
	}
	if m.Timeout > 0 && m.Expires >= 0 && m.Expires <= m.Timeout {
		e.BannedAt = now.Add(-time.Duration(m.Timeout-m.Expires) * time.Second)
	}
}

// banAddr yields the address to geo-locate for a ban value, taking the network
// address of a prefix (CIDR) ban.
func banAddr(v string) (netip.Addr, bool) {
	if p, err := netip.ParsePrefix(v); err == nil {
		return p.Addr(), true
	}
	if a, err := netip.ParseAddr(v); err == nil {
		return a, true
	}
	return netip.Addr{}, false
}

// humanizeDuration formats a duration compactly for the bans table: "45s", "12m",
// "1h", "1h30m", "2d", "2d6h".
func humanizeDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		h, m := int(d/time.Hour), int((d%time.Hour)/time.Minute)
		if m == 0 {
			return fmt.Sprintf("%dh", h)
		}
		return fmt.Sprintf("%dh%dm", h, m)
	default:
		days, h := int(d/(24*time.Hour)), int((d%(24*time.Hour))/time.Hour)
		if h == 0 {
			return fmt.Sprintf("%dd", days)
		}
		return fmt.Sprintf("%dd%dh", days, h)
	}
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
