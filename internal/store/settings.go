package store

import (
	"database/sql"
	"fmt"
)

// Settings is nftably's single-row configuration: how the box is labelled,
// where the UI listens, which nft binary to use, and who may reach the UI.
type Settings struct {
	RouterLabel string
	ListenAddr  string
	// NftBinary overrides the nft(8) path; empty means "nft" resolved on PATH.
	NftBinary string
	// AccessWhitelist is the IPs/CIDRs allowed to reach nftably. Loopback is
	// always allowed and an empty list means no restriction, so it defaults open
	// and cannot lock out an SSH tunnel. See access.go.
	AccessWhitelist string
}

// GetSettings returns the single settings row, or (Settings{}, false, nil) if
// nftably hasn't been initialized yet.
func (s *Store) GetSettings() (Settings, bool, error) {
	var st Settings
	row := s.db.QueryRow(`
		SELECT router_label, listen_addr, nft_binary, access_whitelist
		FROM settings WHERE id = 1`)
	err := row.Scan(&st.RouterLabel, &st.ListenAddr, &st.NftBinary, &st.AccessWhitelist)
	if err == sql.ErrNoRows {
		return Settings{}, false, nil
	}
	if err != nil {
		return Settings{}, false, fmt.Errorf("store: get settings: %w", err)
	}
	return st, true, nil
}

// SaveSettings upserts the single settings row. It leaves the access whitelist
// alone (that has its own writer) so the identity form and the access form
// cannot clobber each other's fields.
func (s *Store) SaveSettings(st Settings) error {
	ts := now()
	_, err := s.db.Exec(`
		INSERT INTO settings (id, router_label, listen_addr, nft_binary, created_at, updated_at)
		VALUES (1, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			router_label = excluded.router_label,
			listen_addr = excluded.listen_addr,
			nft_binary = excluded.nft_binary,
			updated_at = excluded.updated_at
	`, st.RouterLabel, st.ListenAddr, st.NftBinary, ts, ts)
	if err != nil {
		return fmt.Errorf("store: save settings: %w", err)
	}
	return nil
}

// SaveAccessWhitelist updates only the access whitelist.
func (s *Store) SaveAccessWhitelist(text string) error {
	res, err := s.db.Exec(`UPDATE settings SET access_whitelist = ?, updated_at = ? WHERE id = 1`, text, now())
	if err != nil {
		return fmt.Errorf("store: save access whitelist: %w", err)
	}
	return affectedOne(res)
}
