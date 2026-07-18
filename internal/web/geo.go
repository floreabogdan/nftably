package web

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

// geoDB resolves addresses to countries through an operator-supplied MaxMind
// Country database (Settings → GeoIP). Everything is optional and offline:
// no path configured means no lookups, and nftably never phones anywhere.
type geoDB struct {
	mu       sync.RWMutex
	path     string
	reader   *maxminddb.Reader
	lastFail time.Time
}

// lookup returns the ISO code and English name for addr, or empty strings
// when no database is configured, the file is unreadable, or the address is
// simply not in it (private ranges never are). A failed open is retried at
// most every 30s so a bad path cannot turn every page load into disk churn.
//
// maxminddb.Reader.Lookup is safe for concurrent use, so only (re)opening the
// database takes the write lock; the lookups themselves run under the read lock
// and scale with cores — the connections view resolves hundreds of rows.
func (g *geoDB) lookup(path string, addr netip.Addr) (iso, name string) {
	if path == "" || !addr.IsValid() {
		return "", ""
	}

	// Fast path: the database is already open on this path — read-lock, grab the
	// reader, and look up without serializing against other lookups.
	g.mu.RLock()
	if g.path == path && g.reader != nil {
		reader := g.reader
		g.mu.RUnlock()
		return countryOf(reader, addr)
	}
	g.mu.RUnlock()

	// Slow path: open (or reopen on a path change) under the write lock.
	g.mu.Lock()
	if g.path != path {
		if g.reader != nil {
			g.reader.Close()
			g.reader = nil
		}
		g.path = path
		g.lastFail = time.Time{}
	}
	if g.reader == nil {
		if !g.lastFail.IsZero() && time.Since(g.lastFail) < 30*time.Second {
			g.mu.Unlock()
			return "", ""
		}
		r, err := maxminddb.Open(path)
		if err != nil {
			g.lastFail = time.Now()
			g.mu.Unlock()
			return "", ""
		}
		g.reader = r
	}
	reader := g.reader
	g.mu.Unlock()
	return countryOf(reader, addr)
}

// countryOf resolves one address against an open reader.
func countryOf(reader *maxminddb.Reader, addr netip.Addr) (iso, name string) {
	var rec struct {
		Country struct {
			ISOCode string            `maxminddb:"iso_code"`
			Names   map[string]string `maxminddb:"names"`
		} `maxminddb:"country"`
	}
	if err := reader.Lookup(net.IP(addr.AsSlice()), &rec); err != nil {
		return "", ""
	}
	return rec.Country.ISOCode, rec.Country.Names["en"]
}

// flagEmoji turns an ISO 3166 alpha-2 code into its flag emoji (regional
// indicator pair). Unknown input returns the empty string.
func flagEmoji(iso string) string {
	if len(iso) != 2 {
		return ""
	}
	var out []rune
	for _, r := range iso {
		if r < 'A' || r > 'Z' {
			return ""
		}
		out = append(out, 0x1F1E6+r-'A')
	}
	return string(out)
}
