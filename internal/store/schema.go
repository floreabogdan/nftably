package store

// schema is nftably's schema: the state nftably keeps about itself, plus the
// firewall model — rules (M2), config versions and the pending apply (M3),
// forwarding and port-forwards (M4). New tables are added here (all IF NOT
// EXISTS); new columns on existing tables go through migrate().
const schema = `
CREATE TABLE IF NOT EXISTS settings (
	id               INTEGER PRIMARY KEY CHECK (id = 1),
	router_label     TEXT NOT NULL DEFAULT '',
	listen_addr      TEXT NOT NULL DEFAULT '127.0.0.1:8080',
	-- Optional override for the nft binary path; empty means "nft" on PATH.
	nft_binary       TEXT NOT NULL DEFAULT '',
	-- IPs/CIDRs allowed to reach nftably at all — an application-level firewall
	-- in front of the firewall manager. Loopback is always allowed and an empty
	-- list means no restriction, so it defaults open and cannot lock out an SSH
	-- tunnel.
	access_whitelist TEXT NOT NULL DEFAULT '',
	-- Optional path to a MaxMind/DB-IP Country database; empty means the
	-- connections view shows no countries.
	geoip_db         TEXT NOT NULL DEFAULT '',
	-- Opt-in: refresh a downloaded DB-IP Lite database monthly. The only thing
	-- that ever makes nftably reach the network.
	geoip_autoupdate INTEGER NOT NULL DEFAULT 0,
	created_at       TEXT NOT NULL,
	updated_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	username      TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
	token      TEXT PRIMARY KEY,
	user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	created_at TEXT NOT NULL,
	expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	ts         TEXT NOT NULL,
	kind       TEXT NOT NULL,
	actor      TEXT NOT NULL DEFAULT '',
	message    TEXT NOT NULL,
	created_at TEXT NOT NULL
);
-- The timeline paginates by id (a monotonic proxy for time), so events(id) —
-- the primary key — is the only index it needs; no separate ts index.

-- Note: the pre-redesign flat model (fw_rules, firewall, port_forwards tables)
-- has been retired — the general object model below replaced it. Databases
-- created before the redesign keep those tables, dormant and unread; new
-- databases never create them.

-- M3: every apply is recorded here with the exact text loaded into the kernel.
-- status: pending (armed, waiting for confirm), confirmed, reverted (the timer
-- fired or the operator rolled back), or failed (nft -f rejected it).
CREATE TABLE IF NOT EXISTS config_versions (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	ts         TEXT NOT NULL,
	actor      TEXT NOT NULL DEFAULT '',
	config     TEXT NOT NULL,
	status     TEXT NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);

-- M6 named address lists, rendered as nft sets (<name>4 / <name>6). The
-- operator creates as many as they want. role gives a list instant
-- behaviour: 'allow' is accepted before everything, even before block lists
-- (a management network that can never be locked out); 'block' is dropped
-- before established/related (blocking also cuts live connections); '' is a
-- plain address group that rules reference as their source. The name doubles
-- as the nft set name, so it is set-safe by validation. Two lists are seeded
-- on migration: management (allow) and blacklist (block).
CREATE TABLE IF NOT EXISTS ip_lists (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	name       TEXT NOT NULL UNIQUE,      -- ^[a-z][a-z0-9_]{0,23}$
	role       TEXT NOT NULL DEFAULT '',  -- '' | allow | block
	note       TEXT NOT NULL DEFAULT '',
	position   INTEGER NOT NULL,
	-- Where the entries come from: 'manual' (hand-edited), 'geoip' (a country's
	-- CIDRs from the GeoIP database, source_arg = ISO code) or 'url' (fetched from
	-- a remote feed, source_arg = the URL). Sourced lists are refreshed, not
	-- hand-edited. auto_refresh opts into the periodic background refresh.
	source       TEXT NOT NULL DEFAULT 'manual',
	source_arg   TEXT NOT NULL DEFAULT '',
	auto_refresh INTEGER NOT NULL DEFAULT 0,
	last_refresh TEXT NOT NULL DEFAULT '',  -- RFC3339 of the last successful refresh
	refresh_note TEXT NOT NULL DEFAULT '',  -- last refresh result or error, for the UI
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);

-- One address/range on a list. cidr is stored normalized: a bare IP for
-- single hosts, a masked prefix otherwise — exactly how nft echoes set
-- elements back. (The legacy "list" text column predates ip_lists.)
CREATE TABLE IF NOT EXISTS list_entries (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	list       TEXT NOT NULL DEFAULT '',
	list_id    INTEGER NOT NULL DEFAULT 0,
	cidr       TEXT NOT NULL,
	note       TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	UNIQUE(list_id, cidr)
);

-- Advisor suggestions the operator waved away, by stable suggestion key. A
-- rescan re-derives suggestions but keeps honouring these until restored.
CREATE TABLE IF NOT EXISTS advisor_dismissed (
	key          TEXT PRIMARY KEY,
	dismissed_at TEXT NOT NULL
);

-- The armed apply, persisted so a crash during the confirm window still ends
-- in a revert: server startup finds this row and restores the snapshot.
-- prev_tables is a JSON array of every owned table's pre-apply text (the
-- general model manages many tables, so one blob no longer suffices); the
-- legacy prev_table/prev_exists columns are retained empty for old databases.
CREATE TABLE IF NOT EXISTS pending_apply (
	id          INTEGER PRIMARY KEY CHECK (id = 1),
	version_id  INTEGER NOT NULL REFERENCES config_versions(id),
	prev_table  TEXT NOT NULL DEFAULT '',   -- legacy single-table snapshot (unused)
	prev_exists INTEGER NOT NULL DEFAULT 0, -- legacy (unused)
	prev_tables TEXT NOT NULL DEFAULT '[]', -- JSON [{family,name,text,exists}] snapshot
	deadline    TEXT NOT NULL,
	created_at  TEXT NOT NULL
);

-- ── The general nftables object model (the do-over) ──────────────────────
-- nftably no longer owns one fixed inet/nftably table. It manages the set of
-- tables recorded here — and never touches a table it does not own (e.g.
-- Docker's). The model is the source of truth; the render layer walks these
-- rows into nft config text, and apply replaces exactly these tables in one
-- atomic transaction.

-- A table nftably owns, in any netfilter family.
CREATE TABLE IF NOT EXISTS nft_tables (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	family     TEXT NOT NULL,             -- inet | ip | ip6 | arp | bridge | netdev
	name       TEXT NOT NULL,             -- ^[a-zA-Z][a-zA-Z0-9_]{0,63}$
	comment    TEXT NOT NULL DEFAULT '',
	position   INTEGER NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	UNIQUE(family, name)
);

-- A chain in a table. A base chain hooks into netfilter (type+hook+priority+
-- policy); a regular chain is just a named jump/goto target (those four are
-- empty). position is render/eval order within the table.
CREATE TABLE IF NOT EXISTS nft_chains (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	table_id   INTEGER NOT NULL REFERENCES nft_tables(id) ON DELETE CASCADE,
	name       TEXT NOT NULL,             -- ^[a-zA-Z][a-zA-Z0-9_]{0,63}$
	kind       TEXT NOT NULL DEFAULT 'base',  -- base | regular
	hook       TEXT NOT NULL DEFAULT '',  -- input|output|forward|prerouting|postrouting|ingress|egress
	chain_type TEXT NOT NULL DEFAULT '',  -- filter | nat | route
	priority   TEXT NOT NULL DEFAULT '',  -- keyword (filter, srcnat, dstnat, …) or signed int
	policy     TEXT NOT NULL DEFAULT '',  -- accept | drop (base chains)
	position   INTEGER NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	UNIQUE(table_id, name)
);

-- One rule on a chain. The match conditions and action statements are child
-- rows (nft_rule_matches / nft_rule_statements), each keyed by a catalogue id.
CREATE TABLE IF NOT EXISTS nft_rules (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	chain_id   INTEGER NOT NULL REFERENCES nft_chains(id) ON DELETE CASCADE,
	position   INTEGER NOT NULL,
	comment    TEXT NOT NULL DEFAULT '',   -- becomes the rule's nft comment
	enabled    INTEGER NOT NULL DEFAULT 1,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);

-- A match condition: catalogue key (ip.saddr, tcp.dport, ct.state, meta.iifname…),
-- an operator, and the typed value text. position orders the conditions on a rule.
CREATE TABLE IF NOT EXISTS nft_rule_matches (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	rule_id    INTEGER NOT NULL REFERENCES nft_rules(id) ON DELETE CASCADE,
	position   INTEGER NOT NULL,
	key        TEXT NOT NULL,             -- catalogue id
	op         TEXT NOT NULL DEFAULT '==',-- == != < > <= >= (negation folded into !=)
	value      TEXT NOT NULL DEFAULT ''
);

-- An action statement: catalogue key (accept, drop, reject, jump, log, counter,
-- dnat, snat, masquerade, meta.mark.set…) and its parameters as JSON.
CREATE TABLE IF NOT EXISTS nft_rule_statements (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	rule_id    INTEGER NOT NULL REFERENCES nft_rules(id) ON DELETE CASCADE,
	position   INTEGER NOT NULL,
	key        TEXT NOT NULL,             -- catalogue id
	params     TEXT NOT NULL DEFAULT '{}' -- JSON of the statement's typed fields
);

-- The set of tables nftably had in the kernel as of the last confirmed apply.
-- The next apply diffs the current model against this to know which tables the
-- operator deleted (so they can be removed from the kernel too). Single row.
CREATE TABLE IF NOT EXISTS applied_state (
	id     INTEGER PRIMARY KEY CHECK (id = 1),
	tables TEXT NOT NULL DEFAULT '[]'   -- JSON [{family,name}]
);

-- Indexes for the object-model foreign keys: every rule-editor and render read
-- filters children by their parent id, so index those columns to keep a
-- single-rule/single-chain fetch from scanning the whole child table.
CREATE INDEX IF NOT EXISTS idx_nft_chains_table ON nft_chains(table_id);
CREATE INDEX IF NOT EXISTS idx_nft_rules_chain ON nft_rules(chain_id);
CREATE INDEX IF NOT EXISTS idx_nft_rule_matches_rule ON nft_rule_matches(rule_id);
CREATE INDEX IF NOT EXISTS idx_nft_rule_statements_rule ON nft_rule_statements(rule_id);
`
