package web

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/floreabogdan/nftably/internal/buildinfo"
	"github.com/oschwald/maxminddb-golang"
)

// GeoIP: an opt-in, no-key country database. The Connections view can show a
// flag/country for each remote address when nftably has an IP-to-country
// database. Operators can point at their own MaxMind file, or let nftably fetch
// the free DB-IP Lite database (CC-BY 4.0) — which is the ONLY thing that ever
// makes nftably reach the network, and only when the operator asks for it.

const (
	geoipFileName = "dbip-country-lite.mmdb"
	maxGeoIPBytes = 128 << 20 // decompression guard (the real file is ~10 MB)
	geoipStaleAge = 30 * 24 * time.Hour
)

// managedGeoIPPath is where a downloaded database lives, or "" when nftably has
// no writable data directory.
func (s *Server) managedGeoIPPath() string {
	if s.dataDir == "" {
		return ""
	}
	return filepath.Join(s.dataDir, geoipFileName)
}

// dbipURL is the DB-IP Lite country database URL for a given month.
func dbipURL(t time.Time) string {
	return fmt.Sprintf("https://download.db-ip.com/free/dbip-country-lite-%04d-%02d.mmdb.gz", t.Year(), int(t.Month()))
}

// downloadGeoIP fetches the current DB-IP Lite country database and writes it,
// decompressed and validated, to the data directory. Returns the stored path.
// Early in a month the current file may not be published yet, so it falls back
// to the previous month.
func (s *Server) downloadGeoIP(ctx context.Context) (string, error) {
	dst := s.managedGeoIPPath()
	if dst == "" {
		return "", fmt.Errorf("nftably has no writable data directory to store the database")
	}
	now := time.Now().UTC()
	var lastErr error
	for _, when := range []time.Time{now, now.AddDate(0, 0, -20)} {
		if err := s.fetchGeoIP(ctx, dbipURL(when), dst); err != nil {
			lastErr = err
			continue
		}
		return dst, nil
	}
	return "", lastErr
}

// fetchGeoIP downloads url, gunzips it, validates it is a real mmdb, and moves
// it into place atomically.
func (s *Server) fetchGeoIP(ctx context.Context, url, dst string) error {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "nftably/"+buildinfo.Version)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}

	gz, err := gzip.NewReader(io.LimitReader(resp.Body, maxGeoIPBytes))
	if err != nil {
		return fmt.Errorf("decompress: %w", err)
	}
	defer gz.Close()

	tmp, err := os.CreateTemp(s.dataDir, "geoip-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := io.Copy(tmp, io.LimitReader(gz, maxGeoIPBytes)); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	// Only commit a file the reader can actually open — a truncated or wrong
	// download must not replace a working database.
	r, err := maxminddb.Open(tmpName)
	if err != nil {
		return fmt.Errorf("downloaded file is not a valid mmdb: %w", err)
	}
	r.Close()

	if err := os.Chmod(tmpName, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpName, dst)
}

// RefreshGeoIPIfStale downloads a fresh DB-IP Lite database at startup when the
// operator has opted into auto-update and the managed file is missing or older
// than a month. Best-effort and in the background — a failed refresh just leaves
// the previous file (or no countries) in place. Called once from server start.
func (s *Server) RefreshGeoIPIfStale() {
	st, ok, err := s.store.GetSettings()
	if err != nil || !ok || !st.GeoIPAutoUpdate {
		return
	}
	dst := s.managedGeoIPPath()
	if dst == "" {
		return
	}
	if fi, err := os.Stat(dst); err == nil && time.Since(fi.ModTime()) < geoipStaleAge {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		path, err := s.downloadGeoIP(ctx)
		if err != nil {
			s.log.Warn("geoip auto-update failed", "error", err)
			return
		}
		if err := s.store.SaveGeoIPDB(path); err != nil {
			s.log.Warn("geoip auto-update: save path failed", "error", err)
			return
		}
		s.log.Info("geoip database auto-updated", "path", path)
	}()
}
