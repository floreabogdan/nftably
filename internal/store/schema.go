package store

// schema is nftably's schema: the state nftably keeps about itself, plus (from
// M2 on) the firewall rule model. Zones, NAT and config versions arrive in
// later milestones as new tables, added here (all IF NOT EXISTS) and wired
// through migrate().
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
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);

-- The M2 rule model: an ordered list of input-chain filter rules. What nftably
-- renders (and, from M3, applies) is exactly this list plus the baseline rules
-- the render layer always emits. position is the render order; gaps are fine,
-- uniqueness is maintained by the move/create paths.
CREATE TABLE IF NOT EXISTS fw_rules (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	position   INTEGER NOT NULL,
	name       TEXT NOT NULL DEFAULT '',
	action     TEXT NOT NULL DEFAULT 'accept',   -- accept | drop | reject
	proto      TEXT NOT NULL DEFAULT 'any',      -- any | tcp | udp
	dports     TEXT NOT NULL DEFAULT '',         -- "22, 80, 8000-8100" (tcp/udp only)
	saddrs     TEXT NOT NULL DEFAULT '',         -- source IPs/CIDRs; empty = any
	iif        TEXT NOT NULL DEFAULT '',         -- ingress interface; empty = any
	enabled    INTEGER NOT NULL DEFAULT 1,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);

-- Single-row chain-wide configuration for the managed input chain.
CREATE TABLE IF NOT EXISTS firewall (
	id           INTEGER PRIMARY KEY CHECK (id = 1),
	input_policy TEXT NOT NULL DEFAULT 'drop',   -- drop | accept
	created_at   TEXT NOT NULL,
	updated_at   TEXT NOT NULL
);

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

-- Advisor suggestions the operator waved away, by stable suggestion key. A
-- rescan re-derives suggestions but keeps honouring these until restored.
CREATE TABLE IF NOT EXISTS advisor_dismissed (
	key          TEXT PRIMARY KEY,
	dismissed_at TEXT NOT NULL
);

-- The armed apply, persisted so a crash during the confirm window still ends
-- in a revert: server startup finds this row and restores prev_table.
CREATE TABLE IF NOT EXISTS pending_apply (
	id          INTEGER PRIMARY KEY CHECK (id = 1),
	version_id  INTEGER NOT NULL REFERENCES config_versions(id),
	prev_table  TEXT NOT NULL,      -- pre-apply "nft list table inet nftably" text
	prev_exists INTEGER NOT NULL,   -- 0: the table was absent before the apply
	deadline    TEXT NOT NULL,
	created_at  TEXT NOT NULL
);
`
