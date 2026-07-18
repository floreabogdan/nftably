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

// ErrNotFound is returned by Get/Update/Delete when the row does not exist.
var ErrNotFound = errors.New("not found")

// Rule is one operator-defined filter rule on a managed chain. The fields
// mirror the form: a rule matches (proto, dports, saddrs, iif) and takes an
// action. The baseline rules — loopback, established/related, essential
// ICMP/ICMPv6 — are not modelled; the render layer always emits them.
type Rule struct {
	ID       int64
	Position int
	// Name is a short operator label; it becomes the rule's comment in the
	// rendered config ("nftably: <name>") and in `nft list ruleset` output.
	Name string
	// Chain is where the rule filters: "input" (traffic to this host) or
	// "forward" (traffic routed through it). Forward rules only render once
	// forwarding is on — WANIface set on the firewall row.
	Chain  string // input | forward
	Action string // accept | drop | reject
	Proto  string // any | tcp | udp
	// DPorts is the destination ports text — numbers and a-b ranges, comma or
	// space separated. Only meaningful (and only allowed) for tcp/udp.
	DPorts string
	// SAddrs is the source IPs/CIDRs text; empty matches any source. Both
	// families may be mixed — the render layer splits them, since in the inet
	// family "ip saddr" matches only v4 packets and "ip6 saddr" only v6.
	SAddrs string
	// IIf is the ingress interface name; empty matches any interface.
	IIf     string
	Enabled bool
}

// ruleActions, ruleProtos and ruleChains are the closed sets the form offers.
var (
	ruleActions = map[string]bool{"accept": true, "drop": true, "reject": true}
	ruleProtos  = map[string]bool{"any": true, "tcp": true, "udp": true}
	ruleChains  = map[string]bool{"input": true, "forward": true}

	// ifaceRe accepts plausible Linux interface names. The name is embedded in
	// a quoted string in the rendered config, so the character set is closed —
	// nothing that could escape the quotes or the line.
	ifaceRe = regexp.MustCompile(`^[A-Za-z0-9._@:-]{1,15}\*?$`)
)

// Validate returns human-readable problems with the rule; empty means valid.
func (r *Rule) Validate() []string {
	var errs []string
	r.Name = strings.TrimSpace(r.Name)
	r.IIf = strings.TrimSpace(r.IIf)

	if len(r.Name) > 64 {
		errs = append(errs, "Name must be 64 characters or fewer.")
	}
	// The name lands inside a quoted comment in the rendered config; keep the
	// character set closed rather than trying to escape our way out.
	if strings.ContainsAny(r.Name, "\"\\\n\r") {
		errs = append(errs, `Name must not contain quotes, backslashes or line breaks.`)
	}
	if r.Chain == "" {
		r.Chain = "input" // rows predating M4 and forms that omit the field
	}
	if !ruleChains[r.Chain] {
		errs = append(errs, fmt.Sprintf("Chain %q is not one of input, forward.", r.Chain))
	}
	if !ruleActions[r.Action] {
		errs = append(errs, fmt.Sprintf("Action %q is not one of accept, drop, reject.", r.Action))
	}
	if !ruleProtos[r.Proto] {
		errs = append(errs, fmt.Sprintf("Protocol %q is not one of any, tcp, udp.", r.Proto))
	}
	if strings.TrimSpace(r.DPorts) != "" && r.Proto != "tcp" && r.Proto != "udp" {
		errs = append(errs, "Destination ports need a protocol of tcp or udp.")
	}
	if _, perrs := ParsePorts(r.DPorts); len(perrs) > 0 {
		errs = append(errs, perrs...)
	}
	if _, serrs := ParseSources(r.SAddrs); len(serrs) > 0 {
		errs = append(errs, serrs...)
	}
	if r.IIf != "" && !ifaceRe.MatchString(r.IIf) {
		errs = append(errs, fmt.Sprintf("%q is not a valid interface name.", r.IIf))
	}
	return errs
}

// ParsePorts reads the destination-ports text — numbers and a-b ranges, comma
// or space separated — into normalized tokens ("22", "8000-8100"). Returns the
// tokens and a list of human-readable errors.
func ParsePorts(text string) ([]string, []string) {
	var out []string
	var errs []string
	for _, tok := range strings.FieldsFunc(text, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' }) {
		lo, hi, ok := parsePortToken(tok)
		if !ok {
			errs = append(errs, fmt.Sprintf("%q is not a port (1-65535) or range (e.g. 8000-8100).", tok))
			continue
		}
		if lo == hi {
			out = append(out, strconv.Itoa(lo))
		} else {
			out = append(out, fmt.Sprintf("%d-%d", lo, hi))
		}
	}
	return out, errs
}

func parsePortToken(tok string) (lo, hi int, ok bool) {
	parse := func(s string) (int, bool) {
		n, err := strconv.Atoi(s)
		return n, err == nil && n >= 1 && n <= 65535
	}
	if a, b, found := strings.Cut(tok, "-"); found {
		lo, ok1 := parse(a)
		hi, ok2 := parse(b)
		return lo, hi, ok1 && ok2 && lo < hi
	}
	n, okn := parse(tok)
	return n, n, okn
}

// ParseSources reads the source-addresses text — IPs and CIDRs, comma, space or
// newline separated — into prefixes. Returns the prefixes and a list of
// human-readable errors.
func ParseSources(text string) ([]netip.Prefix, []string) {
	var out []netip.Prefix
	var errs []string
	for _, tok := range strings.FieldsFunc(text, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' }) {
		p, msg := parseCIDROrIP(tok)
		if msg != "" {
			errs = append(errs, msg)
			continue
		}
		out = append(out, p)
	}
	return out, errs
}

// ListRules returns every rule in render order.
func (s *Store) ListRules() ([]Rule, error) {
	rows, err := s.db.Query(`
		SELECT id, position, name, chain, action, proto, dports, saddrs, iif, enabled
		FROM fw_rules ORDER BY position, id`)
	if err != nil {
		return nil, fmt.Errorf("store: list rules: %w", err)
	}
	defer rows.Close()

	var out []Rule
	for rows.Next() {
		var r Rule
		if err := rows.Scan(&r.ID, &r.Position, &r.Name, &r.Chain, &r.Action, &r.Proto, &r.DPorts, &r.SAddrs, &r.IIf, &r.Enabled); err != nil {
			return nil, fmt.Errorf("store: scan rule: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetRule returns the rule with id, or ErrNotFound.
func (s *Store) GetRule(id int64) (Rule, error) {
	var r Rule
	row := s.db.QueryRow(`
		SELECT id, position, name, chain, action, proto, dports, saddrs, iif, enabled
		FROM fw_rules WHERE id = ?`, id)
	err := row.Scan(&r.ID, &r.Position, &r.Name, &r.Chain, &r.Action, &r.Proto, &r.DPorts, &r.SAddrs, &r.IIf, &r.Enabled)
	if err == sql.ErrNoRows {
		return Rule{}, ErrNotFound
	}
	if err != nil {
		return Rule{}, fmt.Errorf("store: get rule: %w", err)
	}
	return r, nil
}

// CreateRule inserts a rule at the end of the order and returns its id.
func (s *Store) CreateRule(r Rule) (int64, error) {
	ts := now()
	res, err := s.db.Exec(`
		INSERT INTO fw_rules (position, name, chain, action, proto, dports, saddrs, iif, enabled, created_at, updated_at)
		VALUES ((SELECT COALESCE(MAX(position), 0) + 1 FROM fw_rules), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.Name, ruleChain(r.Chain), r.Action, r.Proto, r.DPorts, r.SAddrs, r.IIf, r.Enabled, ts, ts)
	if err != nil {
		return 0, fmt.Errorf("store: create rule: %w", err)
	}
	return res.LastInsertId()
}

// UpdateRule saves an edited rule's match and action fields (not its position).
func (s *Store) UpdateRule(r Rule) error {
	res, err := s.db.Exec(`
		UPDATE fw_rules SET name = ?, chain = ?, action = ?, proto = ?, dports = ?, saddrs = ?, iif = ?, enabled = ?, updated_at = ?
		WHERE id = ?`,
		r.Name, ruleChain(r.Chain), r.Action, r.Proto, r.DPorts, r.SAddrs, r.IIf, r.Enabled, now(), r.ID)
	if err != nil {
		return fmt.Errorf("store: update rule: %w", err)
	}
	return notFoundIfZero(res)
}

// DeleteRule removes a rule.
func (s *Store) DeleteRule(id int64) error {
	res, err := s.db.Exec(`DELETE FROM fw_rules WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete rule: %w", err)
	}
	return notFoundIfZero(res)
}

// SetRuleEnabled flips a rule on or off without touching its definition.
func (s *Store) SetRuleEnabled(id int64, enabled bool) error {
	res, err := s.db.Exec(`UPDATE fw_rules SET enabled = ?, updated_at = ? WHERE id = ?`, enabled, now(), id)
	if err != nil {
		return fmt.Errorf("store: toggle rule: %w", err)
	}
	return notFoundIfZero(res)
}

// MoveRule shifts a rule one step up (towards the top, dir < 0) or down in the
// render order by swapping positions with its neighbour. Moving past either end
// is a no-op, not an error — the operator just clicked one time too many.
func (s *Store) MoveRule(id int64, dir int) error {
	return s.moveInOrder("fw_rules", id, dir)
}

// moveInOrder is the position-swap shared by every ordered table (fw_rules,
// port_forwards). table must be a compile-time constant, never user input.
func (s *Store) moveInOrder(table string, id int64, dir int) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var pos int
	if err := tx.QueryRow(fmt.Sprintf(`SELECT position FROM %s WHERE id = ?`, table), id).Scan(&pos); err != nil {
		if err == sql.ErrNoRows {
			return ErrNotFound
		}
		return fmt.Errorf("store: move %s: %w", table, err)
	}

	cmp, ord := ">", "ASC"
	if dir < 0 {
		cmp, ord = "<", "DESC"
	}
	var nid int64
	var npos int
	err = tx.QueryRow(fmt.Sprintf(
		`SELECT id, position FROM %s WHERE position %s ? ORDER BY position %s, id LIMIT 1`, table, cmp, ord),
		pos).Scan(&nid, &npos)
	if err == sql.ErrNoRows {
		return nil // already at the end it is moving towards
	}
	if err != nil {
		return fmt.Errorf("store: move %s: %w", table, err)
	}

	ts := now()
	if _, err := tx.Exec(fmt.Sprintf(`UPDATE %s SET position = ?, updated_at = ? WHERE id = ?`, table), npos, ts, id); err != nil {
		return fmt.Errorf("store: move %s: %w", table, err)
	}
	if _, err := tx.Exec(fmt.Sprintf(`UPDATE %s SET position = ?, updated_at = ? WHERE id = ?`, table), pos, ts, nid); err != nil {
		return fmt.Errorf("store: move %s: %w", table, err)
	}
	return tx.Commit()
}

// ruleChain normalizes an empty chain to "input" on the write path, so rows
// are always explicit even when a caller skipped Validate.
func ruleChain(c string) string {
	if c == "" {
		return "input"
	}
	return c
}

func notFoundIfZero(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// Firewall is the single-row chain-wide configuration.
type Firewall struct {
	// InputPolicy is the input chain's default verdict for traffic no rule
	// matched: "drop" (the safe default) or "accept".
	InputPolicy string
	// ForwardPolicy is the forward chain's default verdict. Only meaningful
	// once forwarding is on (WANIface set) — the chain is not rendered before.
	ForwardPolicy string
	// WANIface is the upstream interface. Naming it is what switches
	// forwarding on: the forward chain, masquerade and port-forwards all
	// render relative to it, and none render while it is empty.
	WANIface string
	// Masquerade NATs traffic leaving through WANIface — the standard home /
	// edge router setup where the LAN uses private addresses.
	Masquerade bool
}

// GetFirewall returns the chain-wide configuration, defaulting to policy drop
// when the row has never been written.
func (s *Store) GetFirewall() (Firewall, error) {
	f := Firewall{InputPolicy: "drop", ForwardPolicy: "drop"}
	err := s.db.QueryRow(`SELECT input_policy, forward_policy, wan_iface, masquerade FROM firewall WHERE id = 1`).
		Scan(&f.InputPolicy, &f.ForwardPolicy, &f.WANIface, &f.Masquerade)
	if err == sql.ErrNoRows {
		return Firewall{InputPolicy: "drop", ForwardPolicy: "drop"}, nil
	}
	if err != nil {
		return Firewall{}, fmt.Errorf("store: get firewall: %w", err)
	}
	return f, nil
}

// SaveFirewall upserts the chain-wide configuration. It validates here — a bad
// value would otherwise only fail at `nft -f` time.
func (s *Store) SaveFirewall(f Firewall) error {
	if f.InputPolicy != "drop" && f.InputPolicy != "accept" {
		return fmt.Errorf("store: input policy %q is not drop or accept", f.InputPolicy)
	}
	if f.ForwardPolicy == "" {
		f.ForwardPolicy = "drop"
	}
	if f.ForwardPolicy != "drop" && f.ForwardPolicy != "accept" {
		return fmt.Errorf("store: forward policy %q is not drop or accept", f.ForwardPolicy)
	}
	f.WANIface = strings.TrimSpace(f.WANIface)
	if f.WANIface != "" && !ifaceRe.MatchString(f.WANIface) {
		return fmt.Errorf("store: %q is not a valid interface name", f.WANIface)
	}
	if f.Masquerade && f.WANIface == "" {
		return errors.New("store: masquerade needs the WAN interface set")
	}
	ts := now()
	_, err := s.db.Exec(`
		INSERT INTO firewall (id, input_policy, forward_policy, wan_iface, masquerade, created_at, updated_at)
		VALUES (1, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			input_policy = excluded.input_policy, forward_policy = excluded.forward_policy,
			wan_iface = excluded.wan_iface, masquerade = excluded.masquerade,
			updated_at = excluded.updated_at`,
		f.InputPolicy, f.ForwardPolicy, f.WANIface, f.Masquerade, ts, ts)
	if err != nil {
		return fmt.Errorf("store: save firewall: %w", err)
	}
	return nil
}
