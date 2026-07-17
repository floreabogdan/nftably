package nft

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Client shells out to nft(8). Reading the ruleset needs CAP_NET_ADMIN, so in
// practice nftably runs as root (or with that capability); a permission error
// from nft surfaces verbatim so `nftably doctor` and the UI can explain it.
type Client struct {
	bin     string
	timeout time.Duration
}

// New returns a Client that invokes bin (default "nft", resolved via PATH).
func New(bin string) *Client {
	if bin == "" {
		bin = "nft"
	}
	return &Client{bin: bin, timeout: 10 * time.Second}
}

// Available reports whether the nft binary can be found on PATH (or exists at
// the absolute path given). It does not run it, so it never needs privileges.
func (c *Client) Available() bool {
	_, err := exec.LookPath(c.bin)
	return err == nil
}

// Version returns nft's own version string, e.g. "nftables v1.0.6 (Lester
// Gooch #5)".
func (c *Client) Version(ctx context.Context) (string, error) {
	out, err := c.run(ctx, "--version")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// Ruleset reads the full live ruleset. It runs nft twice — once as JSON for the
// authoritative structure, once as annotated text to recover each rule's
// canonical rendering by handle. The text pass is best-effort: if it fails, the
// ruleset is still returned, with rules carrying their raw expression only.
func (c *Client) Ruleset(ctx context.Context) (*Ruleset, error) {
	jsonOut, err := c.run(ctx, "-j", "list", "ruleset")
	if err != nil {
		return nil, err
	}
	// -a annotates every rule with "# handle N"; failure here is not fatal.
	annotated, _ := c.run(ctx, "-a", "list", "ruleset")
	return parseRuleset([]byte(jsonOut), annotated)
}

// RawRuleset returns `nft -a list ruleset` verbatim — the text an operator
// already knows how to read, for the raw view and copy-to-clipboard.
func (c *Client) RawRuleset(ctx context.Context) (string, error) {
	return c.run(ctx, "-a", "list", "ruleset")
}

// Table returns `nft list table <family> <name>` verbatim, with exists=false
// (and no error) when the table simply is not there — the normal state before
// the first apply, not a failure.
func (c *Client) Table(ctx context.Context, family, name string) (text string, exists bool, err error) {
	out, err := c.run(ctx, "list", "table", family, name)
	if err != nil {
		// nft says "Error: No such file or directory" (ENOENT passed through)
		// for a table that does not exist.
		if strings.Contains(err.Error(), "No such file or directory") {
			return "", false, nil
		}
		return "", false, err
	}
	return out, true, nil
}

// Ping is a cheap liveness/permission probe — `nft list tables` touches
// netfilter without serialising the whole ruleset, so the status-dot poll can
// run every few seconds without cost. A nil error means nft is present and
// nftably has the privilege to read it.
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.run(ctx, "list", "tables")
	return err
}

// run executes nft with args and returns stdout, mapping a non-zero exit into
// an error that carries nft's stderr (where "Operation not permitted" and
// syntax errors land).
func (c *Client) run(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, c.bin, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("nft %s: %s", strings.Join(args, " "), msg)
	}
	return stdout.String(), nil
}
