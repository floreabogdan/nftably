// Package doctor implements nftably's preflight checks (`nftably doctor`): is
// nft installed and its ruleset readable, does an iptables-era ruleset still
// coexist, and is nftably's own database writable. Every check is independent
// and best-effort — one failing check never prevents the others from running
// and reporting.
package doctor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/floreabogdan/nftably/internal/nft"
)

type Status int

const (
	OK Status = iota
	Warn
	Fail
)

func (s Status) String() string {
	switch s {
	case OK:
		return "OK"
	case Warn:
		return "WARN"
	default:
		return "FAIL"
	}
}

type Result struct {
	Name   string
	Status Status
	Detail string
}

type Config struct {
	NftBinary     string // e.g. "nft" (resolved via PATH) or an absolute path
	IptablesSave  string // iptables-save
	Ip6tablesSave string // ip6tables-save
	IptablesBin   string // iptables (for --version / backend mode)
	DBPath        string // nftably's own SQLite file
	SystemdUnit   string // e.g. "nftables" — the unit that restores the ruleset at boot
}

// Run executes every check and returns all results, regardless of individual
// failures.
func Run(cfg Config) []Result {
	c := nft.New(cfg.NftBinary)
	return []Result{
		checkNft(c),
		checkRuleset(c),
		checkIptables(cfg),
		checkSystemd(cfg),
		checkDBDir(cfg),
	}
}

// Failed reports whether any result is a hard failure.
func Failed(results []Result) bool {
	for _, r := range results {
		if r.Status == Fail {
			return true
		}
	}
	return false
}

func checkNft(c *nft.Client) Result {
	if !c.Available() {
		return Result{"nft binary", Fail, "nft not found in PATH — install nftables (apt install nftables)"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	v, err := c.Version(ctx)
	if err != nil {
		return Result{"nft binary", Warn, "found, but --version failed: " + err.Error()}
	}
	return Result{"nft binary", OK, v}
}

// checkRuleset is the one that most often catches a real problem: reading the
// ruleset needs CAP_NET_ADMIN, so if nftably is not root the read fails with
// "Operation not permitted" — and the fix (run as root) belongs in front of the
// operator, not buried in a stack trace.
func checkRuleset(c *nft.Client) Result {
	if !c.Available() {
		return Result{"ruleset readable", Warn, "skipped — nft is not installed"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rs, err := c.Ruleset(ctx)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "permitted") {
			return Result{"ruleset readable", Fail, "cannot read the ruleset — nftably needs CAP_NET_ADMIN (run as root). " + err.Error()}
		}
		return Result{"ruleset readable", Fail, err.Error()}
	}
	if rs.IsEmpty() {
		return Result{"ruleset readable", OK, "readable — netfilter is currently empty (clean slate)"}
	}
	return Result{"ruleset readable", OK, fmt.Sprintf("readable — %d tables, %d chains, %d rules",
		len(rs.Tables), rs.TotalChains(), rs.TotalRules())}
}

// checkIptables warns when an iptables-era ruleset still exists alongside
// nftables. It is informational: those rules are fine today, but nftably will
// want to import (translate once) and take ownership so nothing is
// double-managed.
func checkIptables(cfg Config) Result {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	rep := nft.ProbeIptables(ctx, cfg.IptablesSave, cfg.Ip6tablesSave, cfg.IptablesBin)
	if !rep.V4Available && !rep.V6Available {
		return Result{"iptables coexistence", OK, "iptables tools not installed — pure nftables host"}
	}
	if rep.Err != "" && !rep.HasRules() {
		return Result{"iptables coexistence", Warn, "could not read iptables rules: " + rep.Err}
	}
	if !rep.HasRules() {
		return Result{"iptables coexistence", OK, "no iptables rules present" + modeSuffix(rep.Mode)}
	}
	return Result{"iptables coexistence", Warn, fmt.Sprintf(
		"%d IPv4 + %d IPv6 iptables rules present%s — import them from nftably so they are not double-managed",
		rep.V4Rules, rep.V6Rules, modeSuffix(rep.Mode))}
}

func modeSuffix(mode string) string {
	if mode == "" {
		return ""
	}
	return " (" + mode + " backend)"
}

func checkSystemd(cfg Config) Result {
	unit := cfg.SystemdUnit
	if unit == "" {
		unit = "nftables"
	}
	path, err := exec.LookPath("systemctl")
	if err != nil {
		return Result{"nftables service", Warn, "systemctl not found (not a systemd host?)"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, path, "is-enabled", unit).Output()
	state := strings.TrimSpace(string(out))
	if state == "enabled" {
		return Result{"nftables service", OK, fmt.Sprintf("systemd unit %q is enabled — the ruleset is restored at boot", unit)}
	}
	if state == "" {
		state = "not found"
	}
	return Result{"nftables service", Warn, fmt.Sprintf(
		"systemd unit %q is %s — enable it (systemctl enable nftables) so rules survive a reboot", unit, state)}
}

func checkDBDir(cfg Config) Result {
	dir := filepath.Dir(cfg.DBPath)
	if dir == "" || dir == "." {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return Result{"database path", Fail, fmt.Sprintf("cannot create %s: %v", dir, err)}
	}
	probe := filepath.Join(dir, ".nftably-write-test")
	if err := os.WriteFile(probe, []byte("ok"), 0o640); err != nil {
		return Result{"database path", Fail, fmt.Sprintf("%s is not writable: %v", dir, err)}
	}
	os.Remove(probe)

	// A writable directory is not enough: run "nftably init" as root and the
	// database file it creates belongs to root, while the service runs as
	// nftably. nftably can then read its state but not write it — so it starts,
	// serves a login page, and fails on the first login. Check the file itself.
	if _, err := os.Stat(cfg.DBPath); err == nil {
		f, err := os.OpenFile(cfg.DBPath, os.O_WRONLY, 0)
		if err != nil {
			return Result{"database path", Fail, fmt.Sprintf(
				"%s exists but is not writable by this user: %v — fix with: sudo chown -R nftably:nftably %s", cfg.DBPath, err, dir)}
		}
		f.Close()
	}
	return Result{"database path", OK, dir + " and the database file are writable"}
}
