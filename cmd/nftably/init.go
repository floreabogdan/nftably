package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/floreabogdan/nftably/internal/store"
	"github.com/floreabogdan/nftably/internal/web"
)

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dbPath := fs.String("db", defaultDBPath, "path to nftably's SQLite database")
	listen := fs.String("listen", defaultListen, "address for the web UI to listen on")
	label := fs.String("label", "", "friendly name for this router (e.g. its hostname)")
	nftBinary := fs.String("nft-binary", "", "override the nft binary path (blank = nft on PATH)")
	username := fs.String("username", "admin", "admin username")
	password := fs.String("password", "", "admin password (if omitted, you'll be prompted — preferred, since flags can end up in shell history)")
	fs.Parse(args)

	st, err := store.Open(*dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer st.Close()

	hasUser, err := st.HasAnyUser()
	if err != nil {
		return err
	}
	if hasUser {
		return fmt.Errorf("nftably is already initialized at %s (a user account already exists)", *dbPath)
	}

	pw := *password
	if pw == "" {
		pw, err = promptPassword()
		if err != nil {
			return err
		}
	}
	if len(pw) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}

	hash, err := web.HashPassword(pw)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	if _, err := st.CreateUser(*username, hash); err != nil {
		return fmt.Errorf("create user: %w", err)
	}

	if err := st.SaveSettings(store.Settings{
		RouterLabel: *label,
		ListenAddr:  *listen,
		NftBinary:   *nftBinary,
	}); err != nil {
		return fmt.Errorf("save settings: %w", err)
	}

	// Close before handing the files over: SQLite still has the -wal open, and
	// the chown has to cover it too.
	st.Close()
	adoptDBOwnership(*dbPath)

	fmt.Printf("nftably initialized at %s\n", *dbPath)
	fmt.Printf("  admin user:     %s\n", *username)
	fmt.Printf("  listen address: %s\n", *listen)
	fmt.Println("\nNext: run \"nftably doctor\" to check nft access, then \"nftably server\".")
	return nil
}

func promptPassword() (string, error) {
	fmt.Print("Admin password (not hidden — run in a private session): ")
	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	pw := strings.TrimRight(line, "\r\n")
	fmt.Print("Confirm password: ")
	line2, err := r.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read password confirmation: %w", err)
	}
	if strings.TrimRight(line2, "\r\n") != pw {
		return "", fmt.Errorf("passwords did not match")
	}
	return pw, nil
}
