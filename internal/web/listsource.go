package web

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"syscall"
	"time"

	"github.com/floreabogdan/nftably/internal/buildinfo"
	"github.com/floreabogdan/nftably/internal/store"
	"github.com/oschwald/maxminddb-golang"
)

// feedHTTPClient fetches remote blocklist feeds while refusing to connect to a
// non-public address. The check runs in the dialer's Control hook, after DNS
// resolution and for every connection attempt, so a hostname that resolves to a
// private IP — or an HTTP redirect to one — is blocked too. This turns the
// operator-supplied feed URL from a blind-SSRF hole (cloud metadata, loopback
// services, the LAN) into a public-fetch-only capability.
var feedHTTPClient = &http.Client{
	Timeout: 60 * time.Second,
	Transport: &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 10 * time.Second,
			Control: func(_, address string, _ syscall.RawConn) error {
				host, _, err := net.SplitHostPort(address)
				if err != nil {
					return err
				}
				ip, err := netip.ParseAddr(host)
				if err != nil {
					return fmt.Errorf("unresolved feed address %q", host)
				}
				if !isPublicAddr(ip) {
					return fmt.Errorf("refusing to fetch a feed from the non-public address %s", ip)
				}
				return nil
			},
		}).DialContext,
	},
}

// isPublicAddr reports whether an address is a routable public one — not
// loopback, private, link-local, unique-local, multicast or unspecified.
func isPublicAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	return !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast() && !ip.IsMulticast() && !ip.IsUnspecified() &&
		!ip.IsInterfaceLocalMulticast()
}

// This file populates sourced named sets: a GeoIP country's CIDRs, or a remote
// feed of addresses. Both flow into store.ReplaceListEntries, which normalizes
// and de-overlaps them into a set nft accepts. A feed is capped so a hostile or
// runaway source can't exhaust memory or produce an unusable set.

const (
	maxFeedBytes   = 32 << 20 // a feed body this large is almost certainly wrong
	maxFeedEntries = 200_000  // hard cap on entries taken from one source
)

// refreshNote describes a refresh outcome, flagging when the entry cap was hit
// so a silently-truncated (incomplete) set is never mistaken for a complete one.
func refreshNote(n int) string {
	if n >= maxFeedEntries {
		return fmt.Sprintf("%d entries — capped; the source has more, so this set is incomplete", n)
	}
	return fmt.Sprintf("%d entries", n)
}

// refreshList regenerates a sourced list's entries and records the outcome.
// Returns the number of entries written.
func (s *Server) refreshList(ctx context.Context, l store.IPList) (int, error) {
	var cidrs []string
	var err error
	switch l.Source {
	case store.SourceGeoIP:
		path := s.effectiveGeoIPPath()
		if path == "" {
			return 0, errors.New("no GeoIP database is configured — set one under Settings → GeoIP first")
		}
		cidrs, err = countryNetworks(path, l.SourceArg)
	case store.SourceURL:
		cidrs, err = fetchFeed(ctx, l.SourceArg)
	default:
		return 0, errors.New("this list has no source to refresh")
	}
	if err != nil {
		return 0, err
	}
	n, err := s.store.ReplaceListEntries(l.ID, cidrs)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// effectiveGeoIPPath is the configured GeoIP database path, or "" when none.
func (s *Server) effectiveGeoIPPath() string {
	if st, ok, err := s.store.GetSettings(); err == nil && ok {
		return st.GeoIPDB
	}
	return ""
}

// countryNetworks enumerates every network in the GeoIP database whose country
// is iso, as canonical CIDR strings (v4-mapped v6 networks are unmapped to v4).
func countryNetworks(path, iso string) ([]string, error) {
	r, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open GeoIP database: %w", err)
	}
	defer r.Close()

	iso = strings.ToUpper(iso)
	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	var out []string
	nets := r.Networks()
	for nets.Next() {
		ipnet, err := nets.Network(&rec)
		if err != nil {
			return nil, fmt.Errorf("read GeoIP networks: %w", err)
		}
		if strings.ToUpper(rec.Country.ISOCode) != iso {
			continue
		}
		ones, bits := ipnet.Mask.Size()
		addr, ok := netip.AddrFromSlice(ipnet.IP)
		if !ok {
			continue
		}
		if addr.Is4In6() {
			addr = addr.Unmap()
			if bits == 128 {
				ones -= 96 // the mask was expressed over the 128-bit form
			}
		}
		if ones < 0 || ones > addr.BitLen() {
			continue
		}
		out = append(out, netip.PrefixFrom(addr, ones).Masked().String())
		if len(out) >= maxFeedEntries {
			break
		}
	}
	if err := nets.Err(); err != nil {
		return nil, fmt.Errorf("iterate GeoIP networks: %w", err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no networks found for country %q in this database", iso)
	}
	return out, nil
}

// fetchFeed downloads a text feed of addresses/CIDRs (one per line, '#'/';'
// comments and trailing comments tolerated) and returns the parseable ones.
func fetchFeed(ctx context.Context, url string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "nftably/"+buildinfo.Version)
	resp, err := feedHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("feed returned HTTP %d", resp.StatusCode)
	}

	sc := bufio.NewScanner(io.LimitReader(resp.Body, maxFeedBytes))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	var out []string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.FieldsFunc(line, func(r rune) bool {
			return r == ' ' || r == '\t' || r == ',' || r == ';' || r == '#'
		})
		if len(fields) == 0 {
			continue
		}
		if _, err := store.EntryPrefix(fields[0]); err == nil {
			out = append(out, fields[0])
			if len(out) >= maxFeedEntries {
				break
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("the feed had no addresses nftably could parse")
	}
	return out, nil
}

// StartListRefresh refreshes auto-refresh sourced lists once at startup, then
// repeats every 12 hours for the life of the process. Best-effort and in the
// background; fires only if there is at least one auto-refresh list.
func (s *Server) StartListRefresh() {
	go func() {
		s.RefreshSourcedLists()
		t := time.NewTicker(12 * time.Hour)
		defer t.Stop()
		for range t.C {
			s.RefreshSourcedLists()
		}
	}()
}

// RefreshSourcedLists refreshes every auto-refresh sourced list once, in the
// background. Called at startup and on a periodic ticker; best-effort, so one
// failing feed never blocks the others.
func (s *Server) RefreshSourcedLists() {
	lists, err := s.store.AutoRefreshLists()
	if err != nil {
		s.log.Warn("auto-refresh: could not list sourced lists", "error", err)
		return
	}
	for _, l := range lists {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		n, err := s.refreshList(ctx, l)
		cancel()
		if err != nil {
			s.log.Warn("auto-refresh failed", "list", l.Name, "error", err)
			_ = s.store.SetListRefreshNote(l.ID, "auto-refresh failed: "+err.Error())
			s.notifier.Notify(store.AlertFeedFailed, l.Name, "Auto-refresh failed: "+err.Error())
			continue
		}
		_ = s.store.SetListRefreshed(l.ID, refreshNote(n))
		s.log.Info("list auto-refreshed", "list", l.Name, "entries", n)
	}
}
