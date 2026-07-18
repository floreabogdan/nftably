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
	-- Optional path to a MaxMind GeoLite2/GeoIP2 Country database; empty
	-- means the connections view shows no countries.
	geoip_db         TEXT NOT NULL DEFAULT '',
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

-- The M2 rule model: an ordered list of filter rules on the managed chains
-- (input since M2, forward since M4). What nftably renders (and, from M3,
-- applies) is exactly this list plus the baseline rules the render layer
-- always emits. position is the render order; gaps are fine, uniqueness is
-- maintained by the move/create paths.
CREATE TABLE IF NOT EXISTS fw_rules (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	position   INTEGER NOT NULL,
	name       TEXT NOT NULL DEFAULT '',
	chain      TEXT NOT NULL DEFAULT 'input',    -- input | forward
	action     TEXT NOT NULL DEFAULT 'accept',   -- accept | drop | reject
	proto      TEXT NOT NULL DEFAULT 'any',      -- any | tcp | udp
	dports     TEXT NOT NULL DEFAULT '',         -- "22, 80, 8000-8100" (tcp/udp only)
	saddrs     TEXT NOT NULL DEFAULT '',         -- source IPs/CIDRs; empty = any
	iif        TEXT NOT NULL DEFAULT '',         -- ingress interface; empty = any
	enabled    INTEGER NOT NULL DEFAULT 1,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);

-- Single-row chain-wide configuration for the managed chains. The M4 routing
-- fields: forwarding (forward chain, NAT, port-forwards) stays entirely off
-- until wan_iface names the upstream interface.
CREATE TABLE IF NOT EXISTS firewall (
	id             INTEGER PRIMARY KEY CHECK (id = 1),
	input_policy   TEXT NOT NULL DEFAULT 'drop',   -- drop | accept
	forward_policy TEXT NOT NULL DEFAULT 'drop',   -- drop | accept
	wan_iface      TEXT NOT NULL DEFAULT '',       -- upstream interface; empty = forwarding off
	masquerade     INTEGER NOT NULL DEFAULT 0,     -- NAT LAN sources out wan_iface
	created_at     TEXT NOT NULL,
	updated_at     TEXT NOT NULL
);

-- M4 port-forwards: DNAT rules on the WAN interface. dport is one external
-- port or one a-b range; dest_port empty means "same port(s) as dport".
CREATE TABLE IF NOT EXISTS port_forwards (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	position   INTEGER NOT NULL,
	name       TEXT NOT NULL DEFAULT '',
	proto      TEXT NOT NULL DEFAULT 'tcp',   -- tcp | udp
	dport      TEXT NOT NULL,                 -- external port or range
	dest       TEXT NOT NULL,                 -- internal IP (v4 or v6)
	dest_port  TEXT NOT NULL DEFAULT '',      -- internal port; empty = preserve
	enabled    INTEGER NOT NULL DEFAULT 1,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
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

-- M6 block/allow lists, rendered as named sets. list "mgmt" is the
-- management allow list (accepted before everything, even the blacklist);
-- list "block" is the blacklist (dropped before established, so blocking an
-- address also cuts its live connections). cidr is stored normalized: a bare
-- IP for single hosts, a masked prefix otherwise — exactly how nft echoes
-- set elements back.
CREATE TABLE IF NOT EXISTS list_entries (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	list       TEXT NOT NULL,             -- mgmt | block
	cidr       TEXT NOT NULL,
	note       TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	UNIQUE(list, cidr)
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
