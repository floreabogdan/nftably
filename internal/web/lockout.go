package web

import (
	"fmt"
	"net/http"

	nftconf "github.com/floreabogdan/nftably/internal/render"
	"github.com/floreabogdan/nftably/internal/simulate"
)

// simulatedLockoutWarnings traces a NEW connection from the operator's own
// address to the UI port and to SSH, and warns precisely when it would be
// dropped. This catches what the heuristic lint (render.Lint) misses: an accept
// rule that exists but is scoped to a source the operator isn't in — e.g. `ip
// saddr @mgmt tcp dport 22 accept` reads as "SSH is accepted" to the heuristic,
// yet drops the operator if their address isn't in @mgmt.
//
// The current session survives via established/related; this is about whether the
// operator can reconnect after it. A trace that comes back uncertain is not
// warned on, to avoid crying wolf.
func (s *Server) simulatedLockoutWarnings(r *http.Request, m nftconf.Model) []string {
	client := clientAddr(r)
	if !client.IsValid() || client.IsLoopback() {
		return nil // loopback (e.g. an SSH tunnel) is always accepted
	}
	iif := firstNonLoopbackIface() // the operator's traffic arrives on a real iface, not lo

	checks := []struct {
		port  int
		label string
	}{
		{listenPortOf(s.listenAddr), "the nftably UI"},
		{22, "SSH"},
	}
	var out []string
	for _, c := range checks {
		if c.port <= 0 {
			continue
		}
		tr := simulate.Simulate(m, "input", simulate.Packet{
			Proto: "tcp", Src: client, DPort: c.port, Iif: iif, CtState: "new",
		})
		if tr.Uncertain {
			continue
		}
		if tr.Final == "DROP" || tr.Final == "REJECT" {
			out = append(out, fmt.Sprintf(
				"A new connection from your address (%s) to %s (port %d) would be %s — you'd keep this session, but could be locked out on reconnect. Add your address to the management set, or an allow rule.",
				client, c.label, c.port, tr.Final))
		}
	}
	return out
}
