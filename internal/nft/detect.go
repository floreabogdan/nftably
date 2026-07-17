package nft

import "context"

// Backend summarises what nftables tooling this host has and what netfilter is
// currently carrying. It is the model behind the dashboard's "what am I looking
// at" panel and behind `nftably detect`.
type Backend struct {
	// NftAvailable is whether the nft binary is present at all. On a modern
	// Debian/Ubuntu box it always is; its absence means this is not an nftables
	// host and nftably has nothing to manage.
	NftAvailable bool
	NftVersion   string

	// RulesetErr is non-empty when nft is present but reading the ruleset
	// failed — nearly always "Operation not permitted", i.e. nftably is not
	// running with CAP_NET_ADMIN. Surfaced so the fix ("run as root") is
	// obvious rather than a blank screen.
	RulesetErr string

	// Ruleset is the live netfilter ruleset, or nil when RulesetErr is set.
	Ruleset *Ruleset
}

// Detect probes nft: is it installed, what version, and what is the live
// ruleset. Every step is best-effort — a failure is recorded, not returned, so
// the caller always gets a Backend it can render.
func Detect(ctx context.Context, c *Client) Backend {
	b := Backend{NftAvailable: c.Available()}
	if !b.NftAvailable {
		return b
	}
	if v, err := c.Version(ctx); err == nil {
		b.NftVersion = v
	}
	rs, err := c.Ruleset(ctx)
	if err != nil {
		b.RulesetErr = err.Error()
		return b
	}
	b.Ruleset = rs
	return b
}
