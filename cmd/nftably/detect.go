package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/floreabogdan/nftably/internal/nft"
)

// cmdDetect prints what nftably found: the nft version, a table/chain/rule
// summary of the live ruleset, and any coexisting iptables rules. It is the
// command-line twin of the dashboard, useful over SSH before ever opening the
// web UI.
func cmdDetect(args []string) error {
	fs := flag.NewFlagSet("detect", flag.ExitOnError)
	nftBinary := fs.String("nft-binary", defaultNftBinary, "nft binary name or path")
	fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	c := nft.New(*nftBinary)
	b := nft.Detect(ctx, c)

	if !b.NftAvailable {
		fmt.Println("nft:      not installed (this is not an nftables host)")
		return nil
	}
	fmt.Printf("nft:      %s\n", b.NftVersion)
	if b.RulesetErr != "" {
		fmt.Printf("ruleset:  ERROR — %s\n", b.RulesetErr)
	} else {
		rs := b.Ruleset
		fmt.Printf("ruleset:  %d tables, %d chains, %d rules\n", len(rs.Tables), rs.TotalChains(), rs.TotalRules())
		for _, t := range rs.Tables {
			fmt.Printf("  table %s %s\n", t.Family, t.Name)
			for _, ch := range t.Chains {
				if ch.IsBase() {
					fmt.Printf("    chain %-12s base: hook %s priority %d, policy %s (%d rules)\n",
						ch.Name, ch.Hook, ch.Prio, ch.Policy, len(ch.Rules))
				} else {
					fmt.Printf("    chain %-12s regular (%d rules)\n", ch.Name, len(ch.Rules))
				}
			}
		}
	}

	rep := nft.ProbeIptables(ctx, "", "", "")
	switch {
	case !rep.V4Available && !rep.V6Available:
		fmt.Println("iptables: tools not installed — pure nftables host")
	case rep.HasRules():
		fmt.Printf("iptables: %d IPv4 + %d IPv6 rules present%s — candidates for one-time import\n",
			rep.V4Rules, rep.V6Rules, parenMode(rep.Mode))
	default:
		fmt.Printf("iptables: no rules present%s\n", parenMode(rep.Mode))
	}
	return nil
}

func parenMode(mode string) string {
	if mode == "" {
		return ""
	}
	return " (" + mode + " backend)"
}
