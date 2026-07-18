// Command nftably is an nftables manager: a web UI, backed by SQLite, that
// models the firewall as tables, chains and rules, renders it to nft config and
// applies it as one atomic transaction with an armed auto-revert so a bad rule
// can never lock you out of the box you're editing. Run `nftably init` once,
// then `nftably server` (normally under systemd).
package main

import (
	"fmt"
	"os"

	"github.com/floreabogdan/nftably/internal/buildinfo"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "doctor":
		err = cmdDoctor(os.Args[2:])
	case "detect":
		err = cmdDetect(os.Args[2:])
	case "server":
		err = cmdServer(os.Args[2:])
	case "version":
		fmt.Println("nftably " + buildinfo.Version)
		return
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "nftably: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "nftably:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `nftably — single-host nftables manager

Usage:
  nftably init [flags]     create the database and admin account
  nftably doctor [flags]   run preflight checks against nftables and the filesystem
  nftably detect [flags]   print the detected firewall backend and a ruleset summary
  nftably server [flags]   run the read-only web UI
  nftably version          print the version

Run "nftably <command> -h" for flags on a specific command.
`)
}
