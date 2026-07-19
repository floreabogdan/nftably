package store

import (
	"database/sql"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// This file is the general nftables object model — the do-over. nftably owns a
// set of tables (any family); each table has chains (base chains hook into
// netfilter, regular chains are jump/goto targets); each chain has an ordered
// list of rules; each rule is a list of match conditions and action statements,
// every one keyed by an entry in the knob catalogue (internal/nftcat). The old
// flat Rule/Firewall model (rules.go) is dormant and unused by the render path.

// identRe is the character set for table and chain names. It is embedded
// unquoted in rendered nft config, so the set is closed to what nft accepts as
// a bare identifier — no way to break out of the token.
var identRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)

// The closed vocabularies the forms offer. nft is the final authority (every
// candidate is dry-run through `nft -c`), but validating here turns a typo into
// a friendly message instead of a kernel rejection at apply time.
var (
	nftFamilies   = map[string]bool{"inet": true, "ip": true, "ip6": true, "arp": true, "bridge": true, "netdev": true}
	chainKinds    = map[string]bool{"base": true, "regular": true}
	chainHooks    = map[string]bool{"input": true, "output": true, "forward": true, "prerouting": true, "postrouting": true, "ingress": true, "egress": true}
	chainTypes    = map[string]bool{"filter": true, "nat": true, "route": true}
	chainPolicies = map[string]bool{"accept": true, "drop": true}
	// priorityKeywords are nft's named base-chain priorities; a signed integer
	// is also accepted (validated separately).
	priorityKeywords = map[string]bool{
		"raw": true, "mangle": true, "dstnat": true, "filter": true,
		"security": true, "srcnat": true, "out": true,
	}
)

// ── Table ────────────────────────────────────────────────────────────────

// Table is one nftables table nftably owns, in a given family.
type Table struct {
	ID       int64
	Family   string // inet | ip | ip6 | arp | bridge | netdev
	Name     string
	Comment  string
	Position int
}

// Validate returns human-readable problems; empty means valid.
func (t *Table) Validate() []string {
	var errs []string
	t.Family = strings.TrimSpace(t.Family)
	t.Name = strings.TrimSpace(t.Name)
	t.Comment = strings.TrimSpace(t.Comment)
	if !nftFamilies[t.Family] {
		errs = append(errs, fmt.Sprintf("Family %q is not one of inet, ip, ip6, arp, bridge, netdev.", t.Family))
	}
	if !identRe.MatchString(t.Name) {
		errs = append(errs, "Name must start with a letter and contain only letters, digits and underscores (max 64).")
	}
	if strings.ContainsAny(t.Comment, "\"\\\n\r") {
		errs = append(errs, "Comment must not contain quotes, backslashes or line breaks.")
	}
	return errs
}

// ── Chain ────────────────────────────────────────────────────────────────

// Chain is a chain in a table. For a base chain (Kind=="base") the Hook,
// ChainType, Priority and Policy are meaningful and it hooks into netfilter;
// for a regular chain they are empty and it is only reached by jump/goto.
type Chain struct {
	ID        int64
	TableID   int64
	Name      string
	Kind      string // base | regular
	Hook      string // input | output | forward | prerouting | postrouting | ingress | egress
	ChainType string // filter | nat | route
	Priority  string // keyword (filter, srcnat, dstnat…) or signed integer
	Policy    string // accept | drop
	Device    string // interface name; required for ingress/egress hooks, empty otherwise
	Position  int
}

// deviceHooks are the base-chain hooks that bind to a single interface and so
// require a device.
var deviceHooks = map[string]bool{"ingress": true, "egress": true}

// ifaceNameRe is a conservative interface-name charset — emitted quoted into nft
// config, but kept closed so it can never break out of the token.
var ifaceNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// IsBase reports whether the chain hooks into netfilter.
func (c Chain) IsBase() bool { return c.Kind == "base" }

// Validate returns human-readable problems; empty means valid.
func (c *Chain) Validate() []string {
	var errs []string
	c.Name = strings.TrimSpace(c.Name)
	c.Kind = strings.TrimSpace(c.Kind)
	if c.Kind == "" {
		c.Kind = "base"
	}
	if !identRe.MatchString(c.Name) {
		errs = append(errs, "Name must start with a letter and contain only letters, digits and underscores (max 64).")
	}
	if !chainKinds[c.Kind] {
		errs = append(errs, fmt.Sprintf("Kind %q is not base or regular.", c.Kind))
	}
	if c.Kind == "base" {
		if !chainHooks[c.Hook] {
			errs = append(errs, fmt.Sprintf("Hook %q is not one of input, output, forward, prerouting, postrouting, ingress, egress.", c.Hook))
		}
		if !chainTypes[c.ChainType] {
			errs = append(errs, fmt.Sprintf("Type %q is not one of filter, nat, route.", c.ChainType))
		}
		if !validPriority(c.Priority) {
			errs = append(errs, "Priority must be a keyword (filter, srcnat, dstnat, raw, mangle, security) or a whole number.")
		}
		if c.Policy != "" && !chainPolicies[c.Policy] {
			errs = append(errs, fmt.Sprintf("Policy %q is not accept or drop.", c.Policy))
		}
		if c.Policy == "" {
			c.Policy = "accept"
		}
		// ingress/egress hooks bind to one interface and need a device; other
		// hooks must not carry one.
		c.Device = strings.TrimSpace(c.Device)
		if deviceHooks[c.Hook] {
			if !ifaceNameRe.MatchString(c.Device) {
				errs = append(errs, fmt.Sprintf("The %s hook needs a device (an interface name, e.g. eth0).", c.Hook))
			}
		} else {
			c.Device = ""
		}
	} else {
		// A regular chain carries none of the base attributes.
		c.Hook, c.ChainType, c.Priority, c.Policy, c.Device = "", "", "", "", ""
	}
	return errs
}

func validPriority(p string) bool {
	p = strings.TrimSpace(p)
	if p == "" {
		return false
	}
	if priorityKeywords[p] {
		return true
	}
	// A keyword with an offset, e.g. "filter + 10" / "srcnat - 5".
	if kw, rest, ok := strings.Cut(p, "+"); ok {
		if priorityKeywords[strings.TrimSpace(kw)] {
			if _, err := strconv.Atoi(strings.TrimSpace(rest)); err == nil {
				return true
			}
		}
	}
	if _, err := strconv.Atoi(p); err == nil {
		return true
	}
	return false
}

// ── Rule / matches / statements ───────────────────────────────────────────

// RuleMatch is one match condition on a rule, keyed by a catalogue id.
type RuleMatch struct {
	ID       int64
	RuleID   int64
	Position int
	Key      string // catalogue id, e.g. "ip.saddr", "tcp.dport", "ct.state"
	Op       string // == != < > <= >=
	Value    string
}

// RuleStatement is one action statement on a rule, keyed by a catalogue id.
// Params carries the statement's typed fields as JSON (empty {} for verdicts
// that take no parameters).
type RuleStatement struct {
	ID       int64
	RuleID   int64
	Position int
	Key      string // catalogue id, e.g. "accept", "log", "dnat"
	Params   string // JSON object
}

// ChainRule is one rule on a chain: an ordered set of match conditions and an
// ordered set of action statements, plus a comment and an enabled flag.
type ChainRule struct {
	ID         int64
	ChainID    int64
	Position   int
	Comment    string
	Enabled    bool
	Matches    []RuleMatch
	Statements []RuleStatement
	// Raw is a verbatim nft rule line for constructs the catalogue can't express.
	// When set, the rule renders as exactly this text and its Matches/Statements
	// are ignored. Validated for shape here and by the pre-apply nft --check.
	Raw string
}

// IsRaw reports whether this rule is a raw (verbatim) nft line.
func (r ChainRule) IsRaw() bool { return strings.TrimSpace(r.Raw) != "" }

// Validate returns human-readable problems; empty means valid. It checks shape
// only — that keys are non-empty and there is at least one statement; the knob
// catalogue and `nft -c` validate the values.
func (r *ChainRule) Validate() []string {
	var errs []string
	r.Comment = strings.TrimSpace(r.Comment)
	if strings.ContainsAny(r.Comment, "\"\\\n\r") {
		errs = append(errs, "Comment must not contain quotes, backslashes or line breaks.")
	}
	if len(r.Comment) > 128 {
		errs = append(errs, "Comment must be 128 characters or fewer.")
	}
	// A raw rule is a single verbatim line — its matches/statements are ignored,
	// and its shape is validated at render (ValidateRawRule) and by nft --check.
	if r.IsRaw() {
		return errs
	}
	for _, m := range r.Matches {
		if strings.TrimSpace(m.Key) == "" {
			errs = append(errs, "A match condition is missing its field.")
		}
	}
	if len(r.Statements) == 0 {
		errs = append(errs, "A rule needs at least one action (for example: accept).")
	}
	for _, st := range r.Statements {
		if strings.TrimSpace(st.Key) == "" {
			errs = append(errs, "An action is missing its type.")
		}
	}
	return errs
}

// ── Table CRUD ─────────────────────────────────────────────────────────────

// ListTables returns every owned table in render order.
func (s *Store) ListTables() ([]Table, error) {
	rows, err := s.db.Query(`SELECT id, family, name, comment, position FROM nft_tables ORDER BY position, id`)
	if err != nil {
		return nil, fmt.Errorf("store: list tables: %w", err)
	}
	defer rows.Close()
	var out []Table
	for rows.Next() {
		var t Table
		if err := rows.Scan(&t.ID, &t.Family, &t.Name, &t.Comment, &t.Position); err != nil {
			return nil, fmt.Errorf("store: scan table: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// GetTable returns one table, or ErrNotFound.
func (s *Store) GetTable(id int64) (Table, error) {
	var t Table
	row := s.db.QueryRow(`SELECT id, family, name, comment, position FROM nft_tables WHERE id = ?`, id)
	err := row.Scan(&t.ID, &t.Family, &t.Name, &t.Comment, &t.Position)
	if err == sql.ErrNoRows {
		return Table{}, ErrNotFound
	}
	if err != nil {
		return Table{}, fmt.Errorf("store: get table: %w", err)
	}
	return t, nil
}

// CreateTable inserts a table at the end of the order and returns its id.
func (s *Store) CreateTable(t Table) (int64, error) {
	ts := now()
	res, err := s.db.Exec(`
		INSERT INTO nft_tables (family, name, comment, position, created_at, updated_at)
		VALUES (?, ?, ?, (SELECT COALESCE(MAX(position), 0) + 1 FROM nft_tables), ?, ?)`,
		t.Family, t.Name, t.Comment, ts, ts)
	if err != nil {
		return 0, fmt.Errorf("store: create table: %w", err)
	}
	return res.LastInsertId()
}

// UpdateTable saves a table's family, name and comment.
func (s *Store) UpdateTable(t Table) error {
	res, err := s.db.Exec(`UPDATE nft_tables SET family = ?, name = ?, comment = ?, updated_at = ? WHERE id = ?`,
		t.Family, t.Name, t.Comment, now(), t.ID)
	if err != nil {
		return fmt.Errorf("store: update table: %w", err)
	}
	return notFoundIfZero(res)
}

// DeleteTable removes a table and (by cascade) its chains and rules.
func (s *Store) DeleteTable(id int64) error {
	res, err := s.db.Exec(`DELETE FROM nft_tables WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete table: %w", err)
	}
	return notFoundIfZero(res)
}

// MoveTable shifts a table up (dir<0) or down in render order.
func (s *Store) MoveTable(id int64, dir int) error {
	return s.moveInOrder("nft_tables", id, dir)
}

// ── Chain CRUD ─────────────────────────────────────────────────────────────

// ListChains returns the chains of one table in render order.
func (s *Store) ListChains(tableID int64) ([]Chain, error) {
	rows, err := s.db.Query(`
		SELECT id, table_id, name, kind, hook, chain_type, priority, policy, device, position
		FROM nft_chains WHERE table_id = ? ORDER BY position, id`, tableID)
	if err != nil {
		return nil, fmt.Errorf("store: list chains: %w", err)
	}
	defer rows.Close()
	return scanChains(rows)
}

// AllChains returns every chain grouped by table id — the render path's bulk load.
func (s *Store) AllChains() (map[int64][]Chain, error) {
	rows, err := s.db.Query(`
		SELECT id, table_id, name, kind, hook, chain_type, priority, policy, device, position
		FROM nft_chains ORDER BY position, id`)
	if err != nil {
		return nil, fmt.Errorf("store: all chains: %w", err)
	}
	defer rows.Close()
	chains, err := scanChains(rows)
	if err != nil {
		return nil, err
	}
	out := make(map[int64][]Chain)
	for _, c := range chains {
		out[c.TableID] = append(out[c.TableID], c)
	}
	return out, nil
}

func scanChains(rows *sql.Rows) ([]Chain, error) {
	var out []Chain
	for rows.Next() {
		var c Chain
		if err := rows.Scan(&c.ID, &c.TableID, &c.Name, &c.Kind, &c.Hook, &c.ChainType, &c.Priority, &c.Policy, &c.Device, &c.Position); err != nil {
			return nil, fmt.Errorf("store: scan chain: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetChain returns one chain, or ErrNotFound.
func (s *Store) GetChain(id int64) (Chain, error) {
	var c Chain
	row := s.db.QueryRow(`
		SELECT id, table_id, name, kind, hook, chain_type, priority, policy, device, position
		FROM nft_chains WHERE id = ?`, id)
	err := row.Scan(&c.ID, &c.TableID, &c.Name, &c.Kind, &c.Hook, &c.ChainType, &c.Priority, &c.Policy, &c.Device, &c.Position)
	if err == sql.ErrNoRows {
		return Chain{}, ErrNotFound
	}
	if err != nil {
		return Chain{}, fmt.Errorf("store: get chain: %w", err)
	}
	return c, nil
}

// CreateChain inserts a chain at the end of its table's order and returns its id.
func (s *Store) CreateChain(c Chain) (int64, error) {
	ts := now()
	res, err := s.db.Exec(`
		INSERT INTO nft_chains (table_id, name, kind, hook, chain_type, priority, policy, device, position, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, (SELECT COALESCE(MAX(position), 0) + 1 FROM nft_chains WHERE table_id = ?), ?, ?)`,
		c.TableID, c.Name, c.Kind, c.Hook, c.ChainType, c.Priority, c.Policy, c.Device, c.TableID, ts, ts)
	if err != nil {
		return 0, fmt.Errorf("store: create chain: %w", err)
	}
	return res.LastInsertId()
}

// UpdateChain saves a chain's definition (not its table or position).
func (s *Store) UpdateChain(c Chain) error {
	res, err := s.db.Exec(`
		UPDATE nft_chains SET name = ?, kind = ?, hook = ?, chain_type = ?, priority = ?, policy = ?, device = ?, updated_at = ?
		WHERE id = ?`,
		c.Name, c.Kind, c.Hook, c.ChainType, c.Priority, c.Policy, c.Device, now(), c.ID)
	if err != nil {
		return fmt.Errorf("store: update chain: %w", err)
	}
	return notFoundIfZero(res)
}

// DeleteChain removes a chain and (by cascade) its rules.
func (s *Store) DeleteChain(id int64) error {
	res, err := s.db.Exec(`DELETE FROM nft_chains WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete chain: %w", err)
	}
	return notFoundIfZero(res)
}

// MoveChain shifts a chain up (dir<0) or down within its table.
func (s *Store) MoveChain(id int64, dir int) error {
	return s.moveScoped("nft_chains", "table_id", id, dir)
}

// ── Rule CRUD (with match/statement children) ──────────────────────────────

// ListChainRules returns the rules of one chain, in order, with their matches
// and statements loaded.
func (s *Store) ListChainRules(chainID int64) ([]ChainRule, error) {
	rows, err := s.db.Query(`
		SELECT id, chain_id, position, comment, enabled, raw FROM nft_rules WHERE chain_id = ? ORDER BY position, id`, chainID)
	if err != nil {
		return nil, fmt.Errorf("store: list chain rules: %w", err)
	}
	rules, err := scanRules(rows)
	rows.Close()
	if err != nil {
		return nil, err
	}
	return s.attachChildren(rules)
}

// AllChainRules returns every rule grouped by chain id, with children loaded —
// the render path's bulk load.
func (s *Store) AllChainRules() (map[int64][]ChainRule, error) {
	rows, err := s.db.Query(`SELECT id, chain_id, position, comment, enabled, raw FROM nft_rules ORDER BY position, id`)
	if err != nil {
		return nil, fmt.Errorf("store: all chain rules: %w", err)
	}
	rules, err := scanRules(rows)
	rows.Close()
	if err != nil {
		return nil, err
	}
	rules, err = s.attachChildren(rules)
	if err != nil {
		return nil, err
	}
	out := make(map[int64][]ChainRule)
	for _, r := range rules {
		out[r.ChainID] = append(out[r.ChainID], r)
	}
	return out, nil
}

func scanRules(rows *sql.Rows) ([]ChainRule, error) {
	var out []ChainRule
	for rows.Next() {
		var r ChainRule
		if err := rows.Scan(&r.ID, &r.ChainID, &r.Position, &r.Comment, &r.Enabled, &r.Raw); err != nil {
			return nil, fmt.Errorf("store: scan rule: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// attachChildren loads the matches and statements for a set of rules in two
// bulk queries and hangs them off each rule (ordered). The queries are scoped to
// the passed-in rule ids, so fetching a single rule (or one chain) does not scan
// every match/statement in the database.
func (s *Store) attachChildren(rules []ChainRule) ([]ChainRule, error) {
	if len(rules) == 0 {
		return rules, nil
	}
	idx := make(map[int64]int, len(rules))
	ids := make([]any, len(rules))
	for i := range rules {
		idx[rules[i].ID] = i
		ids[i] = rules[i].ID
	}
	in := "(" + strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",") + ")"

	mrows, err := s.db.Query(`SELECT id, rule_id, position, key, op, value FROM nft_rule_matches WHERE rule_id IN `+in+` ORDER BY position, id`, ids...)
	if err != nil {
		return nil, fmt.Errorf("store: load matches: %w", err)
	}
	for mrows.Next() {
		var m RuleMatch
		if err := mrows.Scan(&m.ID, &m.RuleID, &m.Position, &m.Key, &m.Op, &m.Value); err != nil {
			mrows.Close()
			return nil, fmt.Errorf("store: scan match: %w", err)
		}
		if i, ok := idx[m.RuleID]; ok {
			rules[i].Matches = append(rules[i].Matches, m)
		}
	}
	mrows.Close()
	if err := mrows.Err(); err != nil {
		return nil, err
	}

	srows, err := s.db.Query(`SELECT id, rule_id, position, key, params FROM nft_rule_statements WHERE rule_id IN `+in+` ORDER BY position, id`, ids...)
	if err != nil {
		return nil, fmt.Errorf("store: load statements: %w", err)
	}
	for srows.Next() {
		var st RuleStatement
		if err := srows.Scan(&st.ID, &st.RuleID, &st.Position, &st.Key, &st.Params); err != nil {
			srows.Close()
			return nil, fmt.Errorf("store: scan statement: %w", err)
		}
		if i, ok := idx[st.RuleID]; ok {
			rules[i].Statements = append(rules[i].Statements, st)
		}
	}
	srows.Close()
	return rules, srows.Err()
}

// GetChainRule returns one rule with its children, or ErrNotFound.
func (s *Store) GetChainRule(id int64) (ChainRule, error) {
	var r ChainRule
	row := s.db.QueryRow(`SELECT id, chain_id, position, comment, enabled, raw FROM nft_rules WHERE id = ?`, id)
	err := row.Scan(&r.ID, &r.ChainID, &r.Position, &r.Comment, &r.Enabled, &r.Raw)
	if err == sql.ErrNoRows {
		return ChainRule{}, ErrNotFound
	}
	if err != nil {
		return ChainRule{}, fmt.Errorf("store: get chain rule: %w", err)
	}
	out, err := s.attachChildren([]ChainRule{r})
	if err != nil {
		return ChainRule{}, err
	}
	return out[0], nil
}

// CreateChainRule inserts a rule and its children in one transaction, at the
// end of the chain's order, and returns the rule id.
func (s *Store) CreateChainRule(r ChainRule) (int64, error) {
	return s.createChainRule(r, false)
}

// CreateChainRuleAtStart inserts a rule at the very start of the chain (before
// every existing rule) — used for an early drop, like a country block that must
// run before the accepts.
func (s *Store) CreateChainRuleAtStart(r ChainRule) (int64, error) {
	return s.createChainRule(r, true)
}

func (s *Store) createChainRule(r ChainRule, atStart bool) (int64, error) {
	// position is MAX+1 at the end, or MIN-1 at the start (gaps are fine; the
	// render order is just ORDER BY position).
	posExpr := `(SELECT COALESCE(MAX(position), 0) + 1 FROM nft_rules WHERE chain_id = ?)`
	if atStart {
		posExpr = `(SELECT COALESCE(MIN(position), 1) - 1 FROM nft_rules WHERE chain_id = ?)`
	}

	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	ts := now()
	res, err := tx.Exec(`
		INSERT INTO nft_rules (chain_id, position, comment, enabled, raw, created_at, updated_at)
		VALUES (?, `+posExpr+`, ?, ?, ?, ?, ?)`,
		r.ChainID, r.ChainID, r.Comment, r.Enabled, r.Raw, ts, ts)
	if err != nil {
		return 0, fmt.Errorf("store: create rule: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if err := writeChildren(tx, id, r); err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

// UpdateChainRule saves a rule's comment/enabled and fully replaces its match
// and statement children.
func (s *Store) UpdateChainRule(r ChainRule) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := tx.Exec(`UPDATE nft_rules SET comment = ?, enabled = ?, raw = ?, updated_at = ? WHERE id = ?`,
		r.Comment, r.Enabled, r.Raw, now(), r.ID)
	if err != nil {
		return fmt.Errorf("store: update rule: %w", err)
	}
	if err := notFoundIfZero(res); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM nft_rule_matches WHERE rule_id = ?`, r.ID); err != nil {
		return fmt.Errorf("store: clear matches: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM nft_rule_statements WHERE rule_id = ?`, r.ID); err != nil {
		return fmt.Errorf("store: clear statements: %w", err)
	}
	if err := writeChildren(tx, r.ID, r); err != nil {
		return err
	}
	return tx.Commit()
}

// writeChildren inserts a rule's matches and statements in position order.
func writeChildren(tx *sql.Tx, ruleID int64, r ChainRule) error {
	for i, m := range r.Matches {
		if strings.TrimSpace(m.Key) == "" {
			continue
		}
		op := m.Op
		if op == "" {
			op = "=="
		}
		if _, err := tx.Exec(`INSERT INTO nft_rule_matches (rule_id, position, key, op, value) VALUES (?, ?, ?, ?, ?)`,
			ruleID, i+1, m.Key, op, m.Value); err != nil {
			return fmt.Errorf("store: insert match: %w", err)
		}
	}
	for i, st := range r.Statements {
		if strings.TrimSpace(st.Key) == "" {
			continue
		}
		params := st.Params
		if strings.TrimSpace(params) == "" {
			params = "{}"
		}
		if _, err := tx.Exec(`INSERT INTO nft_rule_statements (rule_id, position, key, params) VALUES (?, ?, ?, ?)`,
			ruleID, i+1, st.Key, params); err != nil {
			return fmt.Errorf("store: insert statement: %w", err)
		}
	}
	return nil
}

// DeleteChainRule removes a rule and (by cascade) its children.
func (s *Store) DeleteChainRule(id int64) error {
	res, err := s.db.Exec(`DELETE FROM nft_rules WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete rule: %w", err)
	}
	return notFoundIfZero(res)
}

// SetChainRuleEnabled flips a rule on or off without touching its definition.
func (s *Store) SetChainRuleEnabled(id int64, enabled bool) error {
	res, err := s.db.Exec(`UPDATE nft_rules SET enabled = ?, updated_at = ? WHERE id = ?`, enabled, now(), id)
	if err != nil {
		return fmt.Errorf("store: toggle rule: %w", err)
	}
	return notFoundIfZero(res)
}

// MoveChainRule shifts a rule up (dir<0) or down within its chain.
func (s *Store) MoveChainRule(id int64, dir int) error {
	return s.moveScoped("nft_rules", "chain_id", id, dir)
}

// moveScoped is moveInOrder restricted to a parent scope: it swaps positions
// with the neighbour that shares the same scopeCol value (table_id for chains,
// chain_id for rules), so moving never crosses into another table/chain.
// table and scopeCol must be compile-time constants, never user input.
func (s *Store) moveScoped(table, scopeCol string, id int64, dir int) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var pos, scope int64
	if err := tx.QueryRow(fmt.Sprintf(`SELECT position, %s FROM %s WHERE id = ?`, scopeCol, table), id).Scan(&pos, &scope); err != nil {
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
	var npos int64
	err = tx.QueryRow(fmt.Sprintf(
		`SELECT id, position FROM %s WHERE %s = ? AND position %s ? ORDER BY position %s, id LIMIT 1`,
		table, scopeCol, cmp, ord), scope, pos).Scan(&nid, &npos)
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
