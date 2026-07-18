package store

import (
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// List roles. A role gives a list instant firewall behaviour; a plain list
// (role "") is an address group that rules reference as their source.
const (
	RoleNone  = ""      // building block for rules
	RoleAllow = "allow" // accepted before everything — management networks
	RoleBlock = "block" // dropped before established — blacklists
)

// IPList is one named address list. Name doubles as the nft set name
// (<name>4 / <name>6 in the rendered config), so it is set-safe.
type IPList struct {
	ID       int64
	Name     string
	Role     string
	Note     string
	Position int
}

// ListEntry is one address or range on a list.
type ListEntry struct {
	ID     int64
	ListID int64
	// CIDR is normalized: a bare IP for single hosts, a masked prefix
	// otherwise — the exact string nft prints for the set element.
	CIDR string
	Note string
}

// ErrOverlap is returned when an entry overlaps one already on the list —
// nft refuses overlapping intervals in a set, so the model must too.
var ErrOverlap = errors.New("overlaps an existing entry")

// listNameRe keeps names usable as nft set names: what you type is what
// appears in the rendered config.
var listNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,23}$`)

var listRoles = map[string]bool{RoleNone: true, RoleAllow: true, RoleBlock: true}

func validateList(l *IPList) error {
	l.Name = strings.TrimSpace(l.Name)
	l.Note = strings.TrimSpace(l.Note)
	if !listNameRe.MatchString(l.Name) {
		return fmt.Errorf("list name %q must be lowercase letters, digits or _ (max 24, starting with a letter) — it becomes the nft set name", l.Name)
	}
	if !listRoles[l.Role] {
		return fmt.Errorf("role %q is not one of allow, block, or empty", l.Role)
	}
	if len(l.Note) > 200 {
		return errors.New("note must be 200 characters or fewer")
	}
	return nil
}

// CreateList adds a named list at the end of the order.
func (s *Store) CreateList(l IPList) (int64, error) {
	if err := validateList(&l); err != nil {
		return 0, err
	}
	ts := now()
	res, err := s.db.Exec(`
		INSERT INTO ip_lists (name, role, note, position, created_at, updated_at)
		VALUES (?, ?, ?, (SELECT COALESCE(MAX(position), 0) + 1 FROM ip_lists), ?, ?)`,
		l.Name, l.Role, l.Note, ts, ts)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return 0, fmt.Errorf("a list named %q already exists", l.Name)
		}
		return 0, fmt.Errorf("store: create list: %w", err)
	}
	return res.LastInsertId()
}

// UpdateList saves name, role and note.
func (s *Store) UpdateList(l IPList) error {
	if err := validateList(&l); err != nil {
		return err
	}
	res, err := s.db.Exec(`UPDATE ip_lists SET name = ?, role = ?, note = ?, updated_at = ? WHERE id = ?`,
		l.Name, l.Role, l.Note, now(), l.ID)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return fmt.Errorf("a list named %q already exists", l.Name)
		}
		return fmt.Errorf("store: update list: %w", err)
	}
	return notFoundIfZero(res)
}

// ListLists returns every list in order.
func (s *Store) ListLists() ([]IPList, error) {
	rows, err := s.db.Query(`SELECT id, name, role, note, position FROM ip_lists ORDER BY position, id`)
	if err != nil {
		return nil, fmt.Errorf("store: list lists: %w", err)
	}
	defer rows.Close()
	var out []IPList
	for rows.Next() {
		var l IPList
		if err := rows.Scan(&l.ID, &l.Name, &l.Role, &l.Note, &l.Position); err != nil {
			return nil, fmt.Errorf("store: scan list: %w", err)
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// GetList returns one list, or ErrNotFound.
func (s *Store) GetList(id int64) (IPList, error) {
	var l IPList
	err := s.db.QueryRow(`SELECT id, name, role, note, position FROM ip_lists WHERE id = ?`, id).
		Scan(&l.ID, &l.Name, &l.Role, &l.Note, &l.Position)
	if err == sql.ErrNoRows {
		return IPList{}, ErrNotFound
	}
	if err != nil {
		return IPList{}, fmt.Errorf("store: get list: %w", err)
	}
	return l, nil
}

// GetListByName returns the first list with name, or ErrNotFound.
func (s *Store) GetListByName(name string) (IPList, error) {
	var l IPList
	err := s.db.QueryRow(`SELECT id, name, role, note, position FROM ip_lists WHERE name = ?`, name).
		Scan(&l.ID, &l.Name, &l.Role, &l.Note, &l.Position)
	if err == sql.ErrNoRows {
		return IPList{}, ErrNotFound
	}
	if err != nil {
		return IPList{}, fmt.Errorf("store: get list by name: %w", err)
	}
	return l, nil
}

// DeleteList removes a list and its entries. A list still referenced by
// rules cannot be deleted — the rules would silently match nothing.
func (s *Store) DeleteList(id int64) error {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM fw_rules WHERE src_list_id = ?`, id).Scan(&n); err != nil {
		return fmt.Errorf("store: delete list: %w", err)
	}
	if n > 0 {
		return fmt.Errorf("%d rule(s) use this list as their source — delete or repoint them first", n)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM list_entries WHERE list_id = ?`, id); err != nil {
		return fmt.Errorf("store: delete list entries: %w", err)
	}
	res, err := tx.Exec(`DELETE FROM ip_lists WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete list: %w", err)
	}
	if err := notFoundIfZero(res); err != nil {
		return err
	}
	return tx.Commit()
}

// RulesUsingList returns the rules whose source is this list.
func (s *Store) RulesUsingList(id int64) ([]Rule, error) {
	rules, err := s.ListRules()
	if err != nil {
		return nil, err
	}
	var out []Rule
	for _, r := range rules {
		if r.SrcListID == id {
			out = append(out, r)
		}
	}
	return out, nil
}

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
func (s *Store) ListEntries(listID int64) ([]ListEntry, error) {
	rows, err := s.db.Query(`SELECT id, list_id, cidr, note FROM list_entries WHERE list_id = ? ORDER BY id`, listID)
	if err != nil {
		return nil, fmt.Errorf("store: list entries: %w", err)
	}
	defer rows.Close()
	var out []ListEntry
	for rows.Next() {
		var e ListEntry
		if err := rows.Scan(&e.ID, &e.ListID, &e.CIDR, &e.Note); err != nil {
			return nil, fmt.Errorf("store: scan list entry: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AllEntries returns every entry keyed by list id — one query for render.
func (s *Store) AllEntries() (map[int64][]ListEntry, error) {
	rows, err := s.db.Query(`SELECT id, list_id, cidr, note FROM list_entries ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store: all entries: %w", err)
	}
	defer rows.Close()
	out := map[int64][]ListEntry{}
	for rows.Next() {
		var e ListEntry
		if err := rows.Scan(&e.ID, &e.ListID, &e.CIDR, &e.Note); err != nil {
			return nil, fmt.Errorf("store: scan list entry: %w", err)
		}
		out[e.ListID] = append(out[e.ListID], e)
	}
	return out, rows.Err()
}

// AddListEntry validates, normalizes and inserts. cidr must not overlap any
// entry already on the same list (nft rejects overlapping set intervals) —
// that returns ErrOverlap wrapped with the entry it collides with.
func (s *Store) AddListEntry(listID int64, cidr, note string) error {
	if _, err := s.GetList(listID); err != nil {
		return err
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
	existing, err := s.ListEntries(listID)
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

	// The legacy "list" text column stays equal to the list id: pre-v4
	// databases enforce UNIQUE(list, cidr) and cannot drop it.
	ts := now()
	if _, err := s.db.Exec(`
		INSERT INTO list_entries (list, list_id, cidr, note, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		strconv.FormatInt(listID, 10), listID, norm, note, ts, ts); err != nil {
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
	err := s.db.QueryRow(`SELECT id, list_id, cidr, note FROM list_entries WHERE id = ?`, id).
		Scan(&e.ID, &e.ListID, &e.CIDR, &e.Note)
	if err == sql.ErrNoRows {
		return ListEntry{}, ErrNotFound
	}
	if err != nil {
		return ListEntry{}, fmt.Errorf("store: get list entry: %w", err)
	}
	return e, nil
}
