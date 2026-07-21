package nft

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
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

// SetMember is one dynamic-set element with its timeout metadata: Timeout is the
// element's configured ban length and Expires its remaining time, both in seconds,
// and both 0 when the element carries no timeout (a bare or rate-meter element).
type SetMember struct {
	Value   string
	Timeout int
	Expires int
}

// DynamicSetMembersDetailed is DynamicSetMembers with each element's timeout and
// remaining expiry, so the bans view can show when a ban started, how long it
// runs, and when it lifts. Best-effort, like DynamicSetMembers.
func (c *Client) DynamicSetMembersDetailed(ctx context.Context) (map[string][]SetMember, error) {
	out, err := c.run(ctx, "-j", "list", "ruleset")
	if err != nil {
		return nil, err
	}
	return parseDynamicSetsDetailed([]byte(out))
}

// DeleteSetElement removes one element from a live set — used to lift an
// auto-ban early. It operates directly on the kernel (a ban is transient state,
// not part of the reviewed model). The caller must have validated element as a
// real address/prefix; family/table/set come from DynamicSetMembers.
func (c *Client) DeleteSetElement(ctx context.Context, family, table, set, element string) error {
	_, err := c.run(ctx, "delete", "element", family, table, set, "{", element, "}")
	return err
}

// AddSetElements adds elements to a live set in one atomic nft transaction — used
// to push an automated block or feed update straight into the kernel so it takes
// effect without a full apply. The caller validates the elements and picks the set
// for their family. An error (e.g. the set/table is not applied yet) is the
// caller's to swallow.
func (c *Client) AddSetElements(ctx context.Context, family, table, set string, elements []string) error {
	return c.setElementOp(ctx, "add", family, table, set, elements)
}

// DeleteSetElements removes elements from a live set in one atomic transaction.
func (c *Client) DeleteSetElements(ctx context.Context, family, table, set string, elements []string) error {
	return c.setElementOp(ctx, "delete", family, table, set, elements)
}

func (c *Client) setElementOp(ctx context.Context, op, family, table, set string, elements []string) error {
	if len(elements) == 0 {
		return nil
	}
	script := fmt.Sprintf("%s element %s %s %s { %s }\n", op, family, table, set, strings.Join(elements, ", "))
	f, err := os.CreateTemp("", "nftably-setsync-*.nft")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, werr := f.WriteString(script); werr != nil {
		f.Close()
		return werr
	}
	f.Close()
	_, err = c.run(ctx, "-f", f.Name())
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
			if frag, ok := banElement(e); ok {
				elems = append(elems, frag)
			}
		}
		if len(elems) > 0 {
			fmt.Fprintf(&b, "add element %s %s %s { %s }\n", set.Family, set.Table, set.Name, strings.Join(elems, ", "))
		}
	}
	return b.String()
}

// banElement returns the `add element` fragment for one live ban-set element —
// "<addr> timeout <remaining>s", or a bare "<addr>" for a permanent (timeout-less)
// entry — and whether it was decodable. It handles a timeout wrapper
// ({"elem":{"val":…,"expires":N}}) and a bare element, and both a plain address and
// a prefix (CIDR) value, so a CIDR or permanent ban is preserved rather than
// silently dropped. expires is read as a float to tolerate any fractional form.
func banElement(raw json.RawMessage) (string, bool) {
	var wrap struct {
		Elem struct {
			Val     json.RawMessage `json:"val"`
			Expires float64         `json:"expires"`
		} `json:"elem"`
	}
	val := raw
	if json.Unmarshal(raw, &wrap) == nil && len(wrap.Elem.Val) > 0 {
		val = wrap.Elem.Val
	}
	addr := decodeElemAddr(val)
	if addr == "" {
		return "", false
	}
	if exp := int(wrap.Elem.Expires); exp > 0 {
		return fmt.Sprintf("%s timeout %ds", addr, exp), true
	}
	return addr, true // permanent — no remaining timeout to carry
}

// decodeElemAddr extracts an address or prefix from an nft -j element value: a bare
// "1.2.3.4" string, or a {"prefix":{"addr":"1.2.3.0","len":24}} object. Returns ""
// for a range or any form it can't safely re-add.
func decodeElemAddr(val json.RawMessage) string {
	var s string
	if json.Unmarshal(val, &s) == nil {
		return s
	}
	var p struct {
		Prefix struct {
			Addr string `json:"addr"`
			Len  int    `json:"len"`
		} `json:"prefix"`
	}
	if json.Unmarshal(val, &p) == nil && p.Prefix.Addr != "" {
		return fmt.Sprintf("%s/%d", p.Prefix.Addr, p.Prefix.Len)
	}
	return ""
}

func parseDynamicSetsDetailed(jsonOut []byte) (map[string][]SetMember, error) {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(jsonOut, &doc); err != nil {
		return nil, err
	}
	out := map[string][]SetMember{}
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
		members := make([]SetMember, 0, len(set.Elem))
		for _, e := range set.Elem {
			if m, ok := decodeSetMember(e); ok {
				members = append(members, m)
			}
		}
		out[key] = members
	}
	return out, nil
}

// decodeSetMember pulls an element's value plus, for a timeout set, its configured
// timeout and remaining expiry (seconds). Handles a bare value, a
// {"elem":{"val":…,"timeout":N,"expires":M}} wrapper, and a prefix value.
func decodeSetMember(raw json.RawMessage) (SetMember, bool) {
	var wrap struct {
		Elem struct {
			Val     json.RawMessage `json:"val"`
			Timeout float64         `json:"timeout"`
			Expires float64         `json:"expires"`
		} `json:"elem"`
	}
	val := raw
	var timeout, expires int
	if json.Unmarshal(raw, &wrap) == nil && len(wrap.Elem.Val) > 0 {
		val = wrap.Elem.Val
		timeout, expires = int(wrap.Elem.Timeout), int(wrap.Elem.Expires)
	}
	addr := decodeElemAddr(val)
	if addr == "" {
		return SetMember{}, false
	}
	return SetMember{Value: addr, Timeout: timeout, Expires: expires}, true
}

// parseDynamicSets is parseDynamicSetsDetailed flattened to bare member values —
// used by the alert poller, which only diffs who is present.
func parseDynamicSets(jsonOut []byte) (map[string][]string, error) {
	detailed, err := parseDynamicSetsDetailed(jsonOut)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]string, len(detailed))
	for k, ms := range detailed {
		vals := make([]string, len(ms))
		for i, m := range ms {
			vals[i] = m.Value
		}
		out[k] = vals
	}
	return out, nil
}
