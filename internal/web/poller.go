package web

import (
	"context"
	"strings"
	"time"

	"github.com/floreabogdan/nftably/internal/store"
)

// poller.go runs the background checks behind the operational alerts: whether nft
// is reachable, and whether the kernel has auto-banned a new source (a fresh
// member in a dynamic timeout set). Event-driven alerts (apply/revert, feed
// failures) fire from their own code paths; only these two need polling.

// StartAlertPoller launches the background alert poll loop. interval <= 0 uses a
// sensible default. It runs for the life of the process.
func (s *Server) StartAlertPoller(interval time.Duration) {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	go func() {
		nftUp := true
		seen := map[string]bool{} // "<setkey>|<member>" already alerted
		firstRun := true
		t := time.NewTicker(interval)
		defer t.Stop()
		for range t.C {
			s.pollAlertsOnce(&nftUp, seen, &firstRun)
		}
	}()
}

// pollAlertsOnce is one poll: nft availability transitions and new auto-bans.
func (s *Server) pollAlertsOnce(nftUp *bool, seen map[string]bool, firstRun *bool) {
	if !s.nft.Available() {
		if *nftUp {
			s.notifier.Notify(store.AlertNftDown, "", "The nft binary is not available.")
			*nftUp = false
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, err := s.nft.Ruleset(ctx)
	up := err == nil
	switch {
	case *nftUp && !up:
		s.notifier.Notify(store.AlertNftDown, "", "Cannot read the kernel ruleset: "+err.Error())
	case !*nftUp && up:
		s.notifier.Notify(store.AlertNftUp, "", "The kernel ruleset is readable again.")
	}
	*nftUp = up
	if !up {
		return
	}

	// Auto-bans: diff the dynamic timeout sets against what we've already seen.
	members, err := s.nft.DynamicSetMembers(ctx)
	if err != nil {
		return
	}
	fresh := map[string]bool{}
	for key, ips := range members {
		set := key[strings.LastIndex(key, "/")+1:]
		for _, ip := range ips {
			id := key + "|" + ip
			fresh[id] = true
			// Don't alert on the bans already present at startup — only new ones.
			if !seen[id] && !*firstRun {
				s.notifier.Notify(store.AlertAutoBan, ip, "Auto-banned "+ip+" (set "+set+").")
			}
		}
	}
	// Replace the seen set with the current membership, so a source that is
	// banned, expires, and is banned again later alerts a second time.
	for k := range seen {
		delete(seen, k)
	}
	for k := range fresh {
		seen[k] = true
	}
	*firstRun = false
}
