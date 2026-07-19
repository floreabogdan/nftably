package web

import (
	"context"
	"strings"
	"time"

	"github.com/floreabogdan/nftably/internal/store"
)

// poller.go runs the background checks behind the operational alerts: whether nft
// is reachable, whether the kernel has auto-banned a new source, and — on a
// slower cadence — whether a service has become reachable from outside.
// Event-driven alerts (apply/revert, feed failures, failed logins) fire from
// their own code paths; only these need polling.

// exposureEveryN runs the (heavier) exposed-services scan once every N poll
// ticks, rather than on every one.
const exposureEveryN = 5

type alertPollState struct {
	tick          int
	nftUp         bool
	firstBanRun   bool
	firstExpoRun  bool
	seenBans      map[string]bool // "<setkey>|<member>"
	seenExposures map[string]bool // finding key
}

// StartAlertPoller launches the background alert poll loop. interval <= 0 uses a
// sensible default. It runs for the life of the process.
func (s *Server) StartAlertPoller(interval time.Duration) {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	go func() {
		st := &alertPollState{
			nftUp: true, firstBanRun: true, firstExpoRun: true,
			seenBans: map[string]bool{}, seenExposures: map[string]bool{},
		}
		t := time.NewTicker(interval)
		defer t.Stop()
		for range t.C {
			st.tick++
			s.pollAlertsOnce(st)
		}
	}()
}

func (s *Server) pollAlertsOnce(st *alertPollState) {
	if !s.nft.Available() {
		if st.nftUp {
			s.notifier.Notify(store.AlertNftDown, "", "The nft binary is not available.")
			st.nftUp = false
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, err := s.nft.Ruleset(ctx)
	up := err == nil
	switch {
	case st.nftUp && !up:
		s.notifier.Notify(store.AlertNftDown, "", "Cannot read the kernel ruleset: "+err.Error())
	case !st.nftUp && up:
		s.notifier.Notify(store.AlertNftUp, "", "The kernel ruleset is readable again.")
	}
	st.nftUp = up
	if !up {
		return
	}

	s.checkNewBans(ctx, st)
	if st.tick == 1 || st.tick%exposureEveryN == 0 {
		s.checkNewExposures(st)
	}
}

// checkNewBans diffs the dynamic timeout sets against what we've already seen and
// alerts on each fresh member.
func (s *Server) checkNewBans(ctx context.Context, st *alertPollState) {
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
			if !st.seenBans[id] && !st.firstBanRun {
				s.notifier.Notify(store.AlertAutoBan, ip, "Auto-banned "+ip+" (set "+set+").")
			}
		}
	}
	// Replace seen with the current membership, so a source that is banned,
	// expires, and is banned again later alerts a second time.
	st.seenBans = fresh
	st.firstBanRun = false
}

// checkNewExposures re-runs the exposed-services scan and alerts when a service
// becomes reachable from outside that wasn't before — the "scan alert".
func (s *Server) checkNewExposures(st *alertPollState) {
	visible, _, _, err := s.advisorFindings()
	if err != nil {
		return
	}
	fresh := map[string]bool{}
	for _, f := range visible {
		if f.Severity != "warn" { // "warn" == reachable from outside
			continue
		}
		fresh[f.Key] = true
		if !st.seenExposures[f.Key] && !st.firstExpoRun {
			s.notifier.Notify(store.AlertNewExposure, f.Title, f.Detail)
		}
	}
	st.seenExposures = fresh
	st.firstExpoRun = false
}
