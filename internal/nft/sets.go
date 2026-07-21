package nft

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// DynamicSetMembers returns the current members of every dynamic set in the live
// ruleset, keyed by "<family>/<table>/<set>". Dynamic sets are the ones the
// kernel populates at runtime — the auto-ban timeout sets — so polling this and
// diffing across calls spots a fresh ban the moment it lands. Best-effort: a
// parse hiccup yields an empty map, never an error from the data.
func (c *Client) DynamicSetMembers(ctx context.Context) (map[string][]string, error) {
	out, err := c.run(ctx, "-j", "list", "ruleset")
	if err != nil {
		return nil, err
	}
	return parseDynamicSets([]byte(out))
}

// DeleteSetElement removes one element from a live set — used to lift an
// auto-ban early. It operates directly on the kernel (a ban is transient state,
// not part of the reviewed model). The caller must have validated element as a
// real address/prefix; family/table/set come from DynamicSetMembers.
func (c *Client) DeleteSetElement(ctx context.Context, family, table, set, element string) error {
	_, err := c.run(ctx, "delete", "element", family, table, set, "{", element, "}")
	return err
}

// PreservedBanElements returns `add element` statements that re-create the current
// members of every live dynamic TIMEOUT set (the auto-ban sets) whose
// "<family>/<table>/<name>" key is in keep, each carrying its remaining expiry in
// seconds. An apply that delete+recreates a table appends these in the same nft -f
// transaction, so active bans survive the apply instead of being freed. Rate-meter
// sets (dynamic, no timeout) hold ephemeral rate state and are skipped, as are sets
// no longer in the model. Best-effort: a parse hiccup yields "".
func (c *Client) PreservedBanElements(ctx context.Context, keep map[string]bool) (string, error) {
	out, err := c.run(ctx, "-j", "list", "ruleset")
	if err != nil {
		return "", err
	}
	return buildPreservedElements([]byte(out), keep), nil
}

func buildPreservedElements(jsonOut []byte, keep map[string]bool) string {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal(jsonOut, &doc) != nil {
		return ""
	}
	var b strings.Builder
	for _, item := range doc.Nftables {
		raw, ok := item["set"]
		if !ok {
			continue
		}
		var set struct {
			Family string            `json:"family"`
			Table  string            `json:"table"`
			Name   string            `json:"name"`
			Flags  []string          `json:"flags"`
			Elem   []json.RawMessage `json:"elem"`
		}
		if json.Unmarshal(raw, &set) != nil {
			continue
		}
		hasTimeout, hasDynamic := false, false
		for _, f := range set.Flags {
			switch f {
			case "timeout":
				hasTimeout = true
			case "dynamic":
				hasDynamic = true
			}
		}
		if !hasTimeout || !hasDynamic || !keep[set.Family+"/"+set.Table+"/"+set.Name] {
			continue
		}
		var elems []string
		for _, e := range set.Elem {
			if val, expires := elemValueExpiry(e); val != "" && expires > 0 {
				elems = append(elems, fmt.Sprintf("%s timeout %ds", val, expires))
			}
		}
		if len(elems) > 0 {
			fmt.Fprintf(&b, "add element %s %s %s { %s }\n", set.Family, set.Table, set.Name, strings.Join(elems, ", "))
		}
	}
	return b.String()
}

// elemValueExpiry pulls an element's address and remaining timeout (seconds) from
// a timeout-set element, which nft -j prints as {"elem":{"val":…,"expires":N}}.
func elemValueExpiry(raw json.RawMessage) (string, int) {
	var wrap struct {
		Elem struct {
			Val     json.RawMessage `json:"val"`
			Expires int             `json:"expires"`
			Timeout int             `json:"timeout"`
		} `json:"elem"`
	}
	if json.Unmarshal(raw, &wrap) == nil && len(wrap.Elem.Val) > 0 {
		var v string
		if json.Unmarshal(wrap.Elem.Val, &v) == nil {
			exp := wrap.Elem.Expires
			if exp == 0 {
				exp = wrap.Elem.Timeout
			}
			return v, exp
		}
	}
	return "", 0
}

func parseDynamicSets(jsonOut []byte) (map[string][]string, error) {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(jsonOut, &doc); err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, item := range doc.Nftables {
		raw, ok := item["set"]
		if !ok {
			continue
		}
		var set struct {
			Family string            `json:"family"`
			Table  string            `json:"table"`
			Name   string            `json:"name"`
			Flags  []string          `json:"flags"`
			Elem   []json.RawMessage `json:"elem"`
		}
		if err := json.Unmarshal(raw, &set); err != nil {
			continue
		}
		dynamic := false
		for _, f := range set.Flags {
			if f == "dynamic" {
				dynamic = true
			}
		}
		if !dynamic {
			continue
		}
		key := set.Family + "/" + set.Table + "/" + set.Name
		members := make([]string, 0, len(set.Elem))
		for _, e := range set.Elem {
			if v := elemValue(e); v != "" {
				members = append(members, v)
			}
		}
		out[key] = members
	}
	return out, nil
}

// elemValue extracts an element's address, whether nft printed it as a bare
// string or, for a timeout set, wrapped as {"elem":{"val":"1.2.3.4",…}}.
func elemValue(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var wrap struct {
		Elem struct {
			Val json.RawMessage `json:"val"`
		} `json:"elem"`
	}
	if json.Unmarshal(raw, &wrap) == nil && len(wrap.Elem.Val) > 0 {
		var v string
		if json.Unmarshal(wrap.Elem.Val, &v) == nil {
			return v
		}
	}
	return ""
}
