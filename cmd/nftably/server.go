package main

import (
	"context"
	"crypto/tls"
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
	tlsCert := fs.String("tls-cert", "", "PEM certificate file for native HTTPS (requires --tls-key)")
	tlsKey := fs.String("tls-key", "", "PEM private key file for native HTTPS (requires --tls-cert)")
	nftBinary := fs.String("nft-binary", "", "override the nft binary path (defaults to the value set by \"nftably init\", or \"nft\" on PATH)")
	iptablesSave := fs.String("iptables-save", defaultIptablesSave, "iptables-save binary (coexistence probe + import preview)")
	ip6tablesSave := fs.String("ip6tables-save", defaultIP6tablesSave, "ip6tables-save binary (coexistence probe + import preview)")
	iptablesTranslate := fs.String("iptables-translate", "iptables-restore-translate", "iptables-restore-translate binary (import preview)")
	ip6tablesTranslate := fs.String("ip6tables-translate", "ip6tables-restore-translate", "ip6tables-restore-translate binary (import preview)")
	fs.Parse(args)
	if (*tlsCert == "") != (*tlsKey == "") {
		return fmt.Errorf("--tls-cert and --tls-key must be provided together")
	}

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
		DataDir:            filepath.Dir(*dbPath),
		IptablesSave:       *iptablesSave,
		Ip6tablesSave:      *ip6tablesSave,
		IptablesBin:        "iptables",
		IptablesTranslate:  *iptablesTranslate,
		Ip6tablesTranslate: *ip6tablesTranslate,
	})

	// A crash or restart during an apply's confirm window must end in a revert:
	// the operator never confirmed, and restarting the service is not a way to
	// skip the confirm step.
	srv.RecoverPendingApply()

	// If the operator opted into GeoIP auto-update, refresh a stale/missing
	// database in the background. Does nothing unless they turned it on.
	srv.RefreshGeoIPIfStale()

	// Keep GeoIP/feed-sourced named sets that opted into auto-refresh up to date:
	// once at startup, then periodically. Does nothing without such a list.
	srv.StartListRefresh()

	// Said once, at startup: nftably binds every interface by default, so an
	// allow-all access list means anyone who finds the port reaches the login —
	// and without TLS, the login crosses the network in the clear.
	if srv.WideOpen() {
		if *tlsCert == "" {
			log.Warn("nftably is reachable from any IP and has no TLS — set the access list under Settings → Access control, configure --tls-cert/--tls-key, or bind loopback with --listen 127.0.0.1:8080",
				"addr", effListen)
		} else {
			log.Warn("nftably is reachable from any IP — narrow the access list under Settings → Access control",
				"addr", effListen)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Bound connection lifetimes prevent a small number of slow clients from
	// exhausting the public server's file descriptors or goroutines.
	httpServer := &http.Server{
		Addr:              effListen,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}
	errCh := make(chan error, 1)
	go func() {
		log.Info("nftably listening", "addr", effListen, "tls", *tlsCert != "")
		var err error
		if *tlsCert != "" {
			err = httpServer.ListenAndServeTLS(*tlsCert, *tlsKey)
		} else {
			err = httpServer.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
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
