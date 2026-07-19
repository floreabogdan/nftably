package nft

import (
	"context"
	"encoding/json"
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
