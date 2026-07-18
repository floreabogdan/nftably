package nft

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// IptablesReport is what nftably found about iptables rules coexisting with the
// nftables ruleset. This matters because on a modern Debian/Ubuntu box
// `iptables` is usually the nft-based shim (iptables-nft): rules added through
// it live in the same kernel netfilter as nftably's own ruleset, under the ip/
// ip6 families. Surfacing them up front stops nftably from silently
// double-managing a box that already has an iptables-era ruleset — the operator
// gets told to import (translate once) and take ownership.
type IptablesReport struct {
	V4Available bool
	V6Available bool
	// V4Rules / V6Rules count the "-A" (append-rule) lines in *-save output.
	V4Rules int
	V6Rules int
	// Mode is the backend iptables itself reports, "nf_tables" or "legacy",
	// parsed from `iptables --version`. Empty when iptables is absent.
	Mode string
	// Err records why a probe could not complete (e.g. not permitted), so the
	// UI never silently claims "no iptables rules" when it simply could not look.
	Err string
}

// HasRules reports whether any iptables rules were found in either family.
func (r IptablesReport) HasRules() bool { return r.V4Rules > 0 || r.V6Rules > 0 }

// ProbeIptables counts the rules the iptables save tools report and reads the
// backend mode. Every step is best-effort. v4save/v6save/iptablesBin default to
// iptables-save / ip6tables-save / iptables when empty.
func ProbeIptables(ctx context.Context, v4save, v6save, iptablesBin string) IptablesReport {
	v4save = orDefault(v4save, "iptables-save")
	v6save = orDefault(v6save, "ip6tables-save")
	iptablesBin = orDefault(iptablesBin, "iptables")

	var r IptablesReport
	r.V4Available = onPath(v4save)
	r.V6Available = onPath(v6save)

	if onPath(iptablesBin) {
		if out, err := runSimple(ctx, iptablesBin, "--version"); err == nil {
			r.Mode = parseIptablesMode(out)
		}
	}
	if r.V4Available {
		if out, err := runSimple(ctx, v4save); err == nil {
			r.V4Rules = countAppendRules(out)
		} else {
			r.Err = err.Error()
		}
	}
	if r.V6Available {
		if out, err := runSimple(ctx, v6save); err == nil {
			r.V6Rules = countAppendRules(out)
		} else if r.Err == "" {
			r.Err = err.Error()
		}
	}
	return r
}

// TranslateIptables produces the nft commands equivalent to the current
// iptables ruleset, by piping `iptables-save` through
// `iptables-restore-translate`. It is a reference preview only — nftably never
// applies the translation — and best-effort: the translate tool ships in
// iptables 1.8+ but is not always installed. save/translate default to
// iptables-save / iptables-restore-translate.
func TranslateIptables(ctx context.Context, save, translate string) (string, error) {
	save = orDefault(save, "iptables-save")
	translate = orDefault(translate, "iptables-restore-translate")
	if !onPath(save) {
		return "", fmt.Errorf("%s is not installed", save)
	}
	if !onPath(translate) {
		return "", fmt.Errorf("%s is not installed (part of iptables 1.8+)", translate)
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	dump, err := runSimple(ctx, save)
	if err != nil {
		return "", fmt.Errorf("%s: %w", save, err)
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, translate)
	cmd.Stdin = strings.NewReader(dump)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("%s: %s", translate, msg)
	}
	return stdout.String(), nil
}

// countAppendRules counts the "-A" lines in iptables-save output — one per
// rule. ":" lines are chain policy declarations, "*" lines name a table, and
// "COMMIT"/comments are neither.
func countAppendRules(save string) int {
	n := 0
	for _, line := range strings.Split(save, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "-A ") {
			n++
		}
	}
	return n
}

// parseIptablesMode extracts "nf_tables" or "legacy" from the parenthesised
// suffix of `iptables --version`, e.g. "iptables v1.8.7 (nf_tables)".
func parseIptablesMode(version string) string {
	open := strings.LastIndex(version, "(")
	close := strings.LastIndex(version, ")")
	if open < 0 || close < 0 || close < open {
		return ""
	}
	return strings.TrimSpace(version[open+1 : close])
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func onPath(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

func runSimple(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("%s", msg)
	}
	return stdout.String(), nil
}
