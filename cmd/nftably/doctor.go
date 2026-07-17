package main

import (
	"flag"
	"fmt"

	"github.com/floreabogdan/nftably/internal/doctor"
)

func cmdDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	nftBinary := fs.String("nft-binary", defaultNftBinary, "nft binary name or path")
	iptablesSave := fs.String("iptables-save", defaultIptablesSave, "iptables-save binary (for coexistence check)")
	ip6tablesSave := fs.String("ip6tables-save", defaultIP6tablesSave, "ip6tables-save binary (for coexistence check)")
	systemdUnit := fs.String("systemd-unit", defaultSystemdUnit, "systemd unit that restores the ruleset at boot")
	dbPath := fs.String("db", defaultDBPath, "path to nftably's SQLite database")
	fs.Parse(args)

	results := doctor.Run(doctor.Config{
		NftBinary:     *nftBinary,
		IptablesSave:  *iptablesSave,
		Ip6tablesSave: *ip6tablesSave,
		IptablesBin:   "iptables",
		SystemdUnit:   *systemdUnit,
		DBPath:        *dbPath,
	})

	for _, r := range results {
		fmt.Printf("[%-4s] %-20s %s\n", r.Status, r.Name, r.Detail)
	}

	if doctor.Failed(results) {
		fmt.Println("\nOne or more checks failed.")
		return fmt.Errorf("preflight checks failed")
	}
	fmt.Println("\nAll checks passed (or are informational warnings).")
	return nil
}
