package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/floreabogdan/nftably/internal/nft"
	"github.com/floreabogdan/nftably/internal/store"
	"github.com/floreabogdan/nftably/internal/web"
)

func cmdServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	dbPath := fs.String("db", defaultDBPath, "path to nftably's SQLite database")
	listen := fs.String("listen", "", "override listen address (defaults to the value set by \"nftably init\")")
	nftBinary := fs.String("nft-binary", "", "override the nft binary path (defaults to the value set by \"nftably init\", or \"nft\" on PATH)")
	iptablesSave := fs.String("iptables-save", defaultIptablesSave, "iptables-save binary (coexistence probe + import preview)")
	ip6tablesSave := fs.String("ip6tables-save", defaultIP6tablesSave, "ip6tables-save binary (coexistence probe + import preview)")
	iptablesTranslate := fs.String("iptables-translate", "iptables-restore-translate", "iptables-restore-translate binary (import preview)")
	ip6tablesTranslate := fs.String("ip6tables-translate", "ip6tables-restore-translate", "ip6tables-restore-translate binary (import preview)")
	fs.Parse(args)

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	st, err := store.Open(*dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer st.Close()

	// Refuse to run half-broken: nftably keeps its own state (logins, events)
	// here, so an unwritable database would only fail on the first login with an
	// opaque "internal error".
	if err := st.CheckWritable(); err != nil {
		return fmt.Errorf(`the database at %s is not writable by the user nftably runs as: %w

This usually means "nftably init" ran as root while the service runs as the nftably user.
Fix it with:

  sudo chown -R nftably:nftably %s`, *dbPath, err, filepath.Dir(*dbPath))
	}

	settings, ok, err := st.GetSettings()
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("nftably has not been initialized — run \"nftably init\" first")
	}

	effListen := firstNonEmpty(*listen, settings.ListenAddr, defaultListen)
	effNft := firstNonEmpty(*nftBinary, settings.NftBinary, defaultNftBinary)

	client := nft.New(effNft)
	if !client.Available() {
		log.Warn("nft binary not found — the UI will start but cannot read the ruleset until nftables is installed",
			"nft", effNft)
	}

	srv := web.New(web.Config{
		Store:              st,
		Nft:                client,
		Log:                log,
		ListenAddr:         effListen,
		IptablesSave:       *iptablesSave,
		Ip6tablesSave:      *ip6tablesSave,
		IptablesBin:        "iptables",
		IptablesTranslate:  *iptablesTranslate,
		Ip6tablesTranslate: *ip6tablesTranslate,
	})

	// Said once, at startup: nftably binds every interface by default and has no
	// TLS, so an allow-all access list means the login crosses the network in the
	// clear to anyone who finds the port.
	if srv.WideOpen() {
		log.Warn("nftably is reachable from any IP and has no TLS — set the access list under Settings → Access control, or bind loopback with --listen 127.0.0.1:8080",
			"addr", effListen)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	httpServer := &http.Server{Addr: effListen, Handler: srv}
	errCh := make(chan error, 1)
	go func() {
		log.Info("nftably listening", "addr", effListen)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-errCh:
		return err
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return httpServer.Shutdown(shutdownCtx)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
