package store

import (
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
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

// List sources. A manual list is hand-edited; a sourced list's entries are
// (re)generated from an external source and are read-only in the UI.
const (
	SourceManual = "manual" // hand-edited entries
	SourceGeoIP  = "geoip"  // a country's CIDRs; SourceArg is the ISO 3166 code
	SourceURL    = "url"    // a remote feed of CIDRs; SourceArg is the URL
)

// IPList is one named address list. Name doubles as the nft set name
// (<name>4 / <name>6 in the rendered config), so it is set-safe.
type IPList struct {
	ID       int64
	Name     string
	Role     string
	Note     string
	Position int
	// Source and its argument: how the entries are populated. SourceManual (the
	// default) means the operator edits them; SourceGeoIP/SourceURL means they are
	// refreshed from SourceArg (a country ISO code, or a feed URL).
	Source      string
	SourceArg   string
	AutoRefresh bool
	LastRefresh string // RFC3339 of the last successful refresh, "" if never
	RefreshNote string // last refresh result or error, for the UI
}

// IsSourced reports whether this list's entries come from an external source
// (and so are refreshed, not hand-edited).
func (l IPList) IsSourced() bool { return l.Source == SourceGeoIP || l.Source == SourceURL }

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
var listSources = map[string]bool{SourceManual: true, SourceGeoIP: true, SourceURL: true}

// isoCountryRe is a 2-letter country code (the GeoIP source argument).
var isoCountryRe = regexp.MustCompile(`^[A-Za-z]{2}$`)

func validateList(l *IPList) error {
	l.Name = strings.TrimSpace(l.Name)
	l.Note = strings.TrimSpace(l.Note)
	l.SourceArg = strings.TrimSpace(l.SourceArg)
	if l.Source == "" {
		l.Source = SourceManual
	}
	if !listNameRe.MatchString(l.Name) {
		return fmt.Errorf("list name %q must be lowercase letters, digits or _ (max 24, starting with a letter) — it becomes the nft set name", l.Name)
	}
	if !listRoles[l.Role] {
		return fmt.Errorf("role %q is not one of allow, block, or empty", l.Role)
	}
	if !listSources[l.Source] {
		return fmt.Errorf("source %q is not one of manual, geoip, or url", l.Source)
	}
	switch l.Source {
	case SourceGeoIP:
		if !isoCountryRe.MatchString(l.SourceArg) {
			return errors.New("a GeoIP list needs a 2-letter country code (e.g. DE, CN, US)")
		}
		l.SourceArg = strings.ToUpper(l.SourceArg)
	case SourceURL:
		if !strings.HasPrefix(l.SourceArg, "https://") && !strings.HasPrefix(l.SourceArg, "http://") {
			return errors.New("a feed list needs an http(s):// URL to fetch the addresses from")
		}
	default:
		l.SourceArg, l.AutoRefresh = "", false // manual lists carry no source
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
		INSERT INTO ip_lists (name, role, note, source, source_arg, auto_refresh, position, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, (SELECT COALESCE(MAX(position), 0) + 1 FROM ip_lists), ?, ?)`,
		l.Name, l.Role, l.Note, l.Source, l.SourceArg, l.AutoRefresh, ts, ts)
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
	res, err := s.db.Exec(`UPDATE ip_lists SET name = ?, role = ?, note = ?, source = ?, source_arg = ?, auto_refresh = ?, updated_at = ? WHERE id = ?`,
		l.Name, l.Role, l.Note, l.Source, l.SourceArg, l.AutoRefresh, now(), l.ID)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return fmt.Errorf("a list named %q already exists", l.Name)
		}
		return fmt.Errorf("store: update list: %w", err)
	}
	return notFoundIfZero(res)
}

// listColumns is the full column list for a list row, in scanList order.
const listColumns = `id, name, role, note, position, source, source_arg, auto_refresh, last_refresh, refresh_note`

func scanList(sc interface{ Scan(...any) error }) (IPList, error) {
	var l IPList
	err := sc.Scan(&l.ID, &l.Name, &l.Role, &l.Note, &l.Position, &l.Source, &l.SourceArg, &l.AutoRefresh, &l.LastRefresh, &l.RefreshNote)
	return l, err
}

// ListLists returns every list in order.
func (s *Store) ListLists() ([]IPList, error) {
	rows, err := s.db.Query(`SELECT ` + listColumns + ` FROM ip_lists ORDER BY position, id`)
	if err != nil {
		return nil, fmt.Errorf("store: list lists: %w", err)
	}
	defer rows.Close()
	var out []IPList
	for rows.Next() {
		l, err := scanList(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scan list: %w", err)
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// GetList returns one list, or ErrNotFound.
func (s *Store) GetList(id int64) (IPList, error) {
	l, err := scanList(s.db.QueryRow(`SELECT `+listColumns+` FROM ip_lists WHERE id = ?`, id))
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
	l, err := scanList(s.db.QueryRow(`SELECT `+listColumns+` FROM ip_lists WHERE name = ?`, name))
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
	l, err := s.GetList(id)
	if err != nil {
		return err
	}
	// The general model references a list by its set name (@name4 / @name6);
	// deleting a still-referenced list would leave rules pointing at a set that no
	// longer exists, and the next apply would fail. Refuse it.
	if refs, err := s.RulesReferencingSet(l.Name); err != nil {
		return err
	} else if len(refs) > 0 {
		return fmt.Errorf("%d firewall rule(s) reference @%s — delete or repoint them first", len(refs), l.Name)
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

// SetUsage names one object-model rule that references a named set.
type SetUsage struct {
	TableFamily string
	TableName   string
	ChainName   string
	RuleID      int64
}

// setReferences scans every object-model match value and maps each referenced
// set's BASE name (the list name — the nft set's family suffix stripped) to the
// distinct rules that use it. This is how the general model references a list;
// the old fw_rules.src_list_id path is separate and dormant.
func (s *Store) setReferences() (map[string][]SetUsage, error) {
	rows, err := s.db.Query(`
		SELECT t.family, t.name, c.name, r.id, m.value
		FROM nft_rule_matches m
		JOIN nft_rules r  ON r.id = m.rule_id
		JOIN nft_chains c ON c.id = r.chain_id
		JOIN nft_tables t ON t.id = c.table_id
		WHERE m.value LIKE '%@%'`)
	if err != nil {
		return nil, fmt.Errorf("store: scan set references: %w", err)
	}
	defer rows.Close()
	out := map[string][]SetUsage{}
	seen := map[string]bool{} // "base|ruleID" — a rule counts once per set
	for rows.Next() {
		var u SetUsage
		var val string
		if err := rows.Scan(&u.TableFamily, &u.TableName, &u.ChainName, &u.RuleID, &val); err != nil {
			return nil, fmt.Errorf("store: scan set reference: %w", err)
		}
		for _, base := range referencedBaseNames(val) {
			key := base + "|" + strconv.FormatInt(u.RuleID, 10)
			if seen[key] {
				continue
			}
			seen[key] = true
			out[base] = append(out[base], u)
		}
	}
	return out, rows.Err()
}

// referencedBaseNames returns the list names a stored match value references via
// @name4 / @name6 tokens — the family suffix stripped, matching how the render
// layer maps a set name back to its list.
func referencedBaseNames(value string) []string {
	var out []string
	for _, tok := range strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '{' || r == '}'
	}) {
		name, ok := strings.CutPrefix(tok, "@")
		if !ok || name == "" {
			continue
		}
		if b, ok := strings.CutSuffix(name, "4"); ok {
			out = append(out, b)
		} else if b, ok := strings.CutSuffix(name, "6"); ok {
			out = append(out, b)
		} else {
			out = append(out, name)
		}
	}
	return out
}

// RulesReferencingSet returns the object-model rules that use the named set.
func (s *Store) RulesReferencingSet(name string) ([]SetUsage, error) {
	refs, err := s.setReferences()
	if err != nil {
		return nil, err
	}
	return refs[name], nil
}

// SetReferenceCounts returns, per list name, how many object-model rules use it.
func (s *Store) SetReferenceCounts() (map[string]int, error) {
	refs, err := s.setReferences()
	if err != nil {
		return nil, err
	}
	out := make(map[string]int, len(refs))
	for name, uses := range refs {
		out[name] = len(uses)
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

// ReplaceListEntries replaces all of a list's entries with cidrs, in one
// transaction — the write path a GeoIP/feed refresh uses. The input is
// normalized and de-overlapped (masked CIDRs are always disjoint or nested, so
// dropping any prefix contained in a kept one yields a set nft accepts).
// Returns the number of entries written.
func (s *Store) ReplaceListEntries(listID int64, cidrs []string) (int, error) {
	entries := dedupePrefixes(cidrs)
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM list_entries WHERE list_id = ?`, listID); err != nil {
		return 0, fmt.Errorf("store: clear list entries: %w", err)
	}
	stmt, err := tx.Prepare(`INSERT INTO list_entries (list, list_id, cidr, note, created_at, updated_at) VALUES (?, ?, ?, '', ?, ?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	ts := now()
	listCol := strconv.FormatInt(listID, 10)
	for _, e := range entries {
		if _, err := stmt.Exec(listCol, listID, e, ts, ts); err != nil {
			return 0, fmt.Errorf("store: insert list entry: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(entries), nil
}

// SetListRefreshed records the outcome of a refresh: the time and a note (an
// entry count on success, or an error message).
func (s *Store) SetListRefreshed(listID int64, note string) error {
	_, err := s.db.Exec(`UPDATE ip_lists SET last_refresh = ?, refresh_note = ?, updated_at = ? WHERE id = ?`,
		now(), note, now(), listID)
	if err != nil {
		return fmt.Errorf("store: set list refreshed: %w", err)
	}
	return nil
}

// SetListRefreshNote records a refresh outcome without stamping a success time —
// used when a refresh failed, so "last successful refresh" stays honest.
func (s *Store) SetListRefreshNote(listID int64, note string) error {
	_, err := s.db.Exec(`UPDATE ip_lists SET refresh_note = ?, updated_at = ? WHERE id = ?`, note, now(), listID)
	if err != nil {
		return fmt.Errorf("store: set list refresh note: %w", err)
	}
	return nil
}

// AutoRefreshLists returns the sourced lists that opted into periodic refresh.
func (s *Store) AutoRefreshLists() ([]IPList, error) {
	all, err := s.ListLists()
	if err != nil {
		return nil, err
	}
	var out []IPList
	for _, l := range all {
		if l.AutoRefresh && l.IsSourced() {
			out = append(out, l)
		}
	}
	return out, nil
}

// dedupePrefixes normalizes cidrs to canonical masked strings, sorts them
// (address then prefix length), and drops any prefix contained in one already
// kept. Because masked prefixes never partially overlap, a single running
// "cover" prefix is enough to catch all containment in one pass.
func dedupePrefixes(cidrs []string) []string {
	pfx := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := EntryPrefix(strings.TrimSpace(c))
		if err != nil {
			continue
		}
		mp := p.Masked()
		// Reject the default route and non-listable addresses (a stray 0.0.0.0/0
		// in a feed would otherwise become the "cover" and collapse the whole
		// family to "all addresses"). This mirrors what NormalizeCIDR enforces on
		// hand-added entries.
		if mp.Bits() == 0 || !listableAddr(mp.Addr()) {
			continue
		}
		pfx = append(pfx, mp)
	}
	sort.Slice(pfx, func(i, j int) bool {
		if pfx[i].Addr() != pfx[j].Addr() {
			return pfx[i].Addr().Less(pfx[j].Addr())
		}
		return pfx[i].Bits() < pfx[j].Bits()
	})
	var out []string
	var cover netip.Prefix
	haveCover := false
	for _, p := range pfx {
		if haveCover && cover.Contains(p.Addr()) && cover.Bits() <= p.Bits() {
			continue // p is inside the current cover — a duplicate or a subnet
		}
		out = append(out, prefixString(p))
		cover, haveCover = p, true
	}
	return out
}

// listableAddr reports whether an address may appear in a set — the same
// exclusions NormalizeCIDR applies to hand-added entries (loopback is always
// accepted anyway; unspecified and multicast make no sense in a source/dest set).
func listableAddr(a netip.Addr) bool {
	return !a.IsLoopback() && !a.IsUnspecified() && !a.IsMulticast()
}

// prefixString renders a prefix the way nft echoes set elements: a bare address
// for a single host, a masked prefix otherwise.
func prefixString(p netip.Prefix) string {
	if p.Bits() == p.Addr().BitLen() {
		return p.Addr().String()
	}
	return p.String()
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
