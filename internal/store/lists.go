package store

import (
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// The two fixed lists. mgmt is the management allow list — sources accepted
// before everything else, so an operator's network can never lock itself out.
// block is the blacklist — sources dropped before established/related, so a
// block also cuts connections that are already open.
const (
	ListMgmt  = "mgmt"
	ListBlock = "block"
)

// ListEntry is one address or range on a list.
type ListEntry struct {
	ID   int64
	List string
	// CIDR is normalized: a bare IP for single hosts, a masked prefix
	// otherwise — the exact string nft prints for the set element.
	CIDR string
	Note string
}

// ErrOverlap is returned when an entry overlaps one already on the list —
// nft refuses overlapping intervals in a set, so the model must too.
var ErrOverlap = errors.New("overlaps an existing entry")

// NormalizeCIDR parses an IP or CIDR and returns its canonical form (bare IP
// for single hosts, masked prefix otherwise) — the form nft echoes back from
// a set. The second return is a human-readable error.
func NormalizeCIDR(text string) (string, string) {
	text = strings.TrimSpace(text)
	p, msg := parseCIDROrIP(text)
	if msg != "" {
		return "", msg
	}
	addr := p.Addr()
	if addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() {
		return "", fmt.Sprintf("%q is not a listable address (loopback is always accepted; unspecified and multicast make no sense here).", text)
	}
	if p.IsSingleIP() {
		return addr.String(), ""
	}
	return p.Masked().String(), ""
}

// EntryPrefix converts a stored CIDR back to a prefix.
func EntryPrefix(cidr string) (netip.Prefix, error) {
	if !strings.Contains(cidr, "/") {
		addr, err := netip.ParseAddr(cidr)
		if err != nil {
			return netip.Prefix{}, err
		}
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}
	return netip.ParsePrefix(cidr)
}

// ListEntries returns a list's entries in the order they were added.
func (s *Store) ListEntries(list string) ([]ListEntry, error) {
	rows, err := s.db.Query(`SELECT id, list, cidr, note FROM list_entries WHERE list = ? ORDER BY id`, list)
	if err != nil {
		return nil, fmt.Errorf("store: list entries: %w", err)
	}
	defer rows.Close()
	var out []ListEntry
	for rows.Next() {
		var e ListEntry
		if err := rows.Scan(&e.ID, &e.List, &e.CIDR, &e.Note); err != nil {
			return nil, fmt.Errorf("store: scan list entry: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AddListEntry validates, normalizes and inserts. cidr must not overlap any
// entry already on the same list (nft rejects overlapping set intervals) —
// that returns ErrOverlap wrapped with the entry it collides with.
func (s *Store) AddListEntry(list, cidr, note string) error {
	if list != ListMgmt && list != ListBlock {
		return fmt.Errorf("store: unknown list %q", list)
	}
	norm, msg := NormalizeCIDR(cidr)
	if msg != "" {
		return errors.New(msg)
	}
	note = strings.TrimSpace(strings.ReplaceAll(note, "\n", " "))
	if len(note) > 120 {
		return errors.New("note must be 120 characters or fewer")
	}

	p, err := EntryPrefix(norm)
	if err != nil {
		return fmt.Errorf("store: add list entry: %w", err)
	}
	existing, err := s.ListEntries(list)
	if err != nil {
		return err
	}
	for _, e := range existing {
		q, err := EntryPrefix(e.CIDR)
		if err != nil {
			continue
		}
		if p.Overlaps(q) {
			return fmt.Errorf("%q %w: %s", norm, ErrOverlap, e.CIDR)
		}
	}

	ts := now()
	if _, err := s.db.Exec(`
		INSERT INTO list_entries (list, cidr, note, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		list, norm, note, ts, ts); err != nil {
		return fmt.Errorf("store: add list entry: %w", err)
	}
	return nil
}

// DeleteListEntry removes an entry by id.
func (s *Store) DeleteListEntry(id int64) error {
	res, err := s.db.Exec(`DELETE FROM list_entries WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete list entry: %w", err)
	}
	return notFoundIfZero(res)
}

// GetListEntry returns one entry, or ErrNotFound.
func (s *Store) GetListEntry(id int64) (ListEntry, error) {
	var e ListEntry
	err := s.db.QueryRow(`SELECT id, list, cidr, note FROM list_entries WHERE id = ?`, id).
		Scan(&e.ID, &e.List, &e.CIDR, &e.Note)
	if err == sql.ErrNoRows {
		return ListEntry{}, ErrNotFound
	}
	if err != nil {
		return ListEntry{}, fmt.Errorf("store: get list entry: %w", err)
	}
	return e, nil
}
