package store

// schema is nftably's M1 (read-only) schema: just the state nftably keeps about
// itself. The firewall model — zones, rules, NAT, config versions — arrives in
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
`
