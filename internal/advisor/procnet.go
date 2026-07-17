package advisor

import (
	"bufio"
	"encoding/hex"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// parseProcNet reads one /proc/net/{tcp,tcp6,udp,udp6} table into listeners.
// TCP rows count when in LISTEN (0A); UDP rows when unconnected (07), which is
// what a bound datagram socket sits in. Rows whose socket state does not match
// are skipped; the caller merges v4 and v6 and attaches process names.
//
// The format is stable kernel ABI: whitespace-separated columns, the second
// being local_address as HEXIP:HEXPORT with the IP in little-endian 32-bit
// groups.
func parseProcNet(r io.Reader, proto string) []Listener {
	wantState := "0A" // TCP_LISTEN
	if proto == "udp" {
		wantState = "07" // TCP_CLOSE: an unconnected, bound UDP socket
	}

	var out []Listener
	sc := bufio.NewScanner(r)
	sc.Scan() // header line
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		if !strings.EqualFold(fields[3], wantState) {
			continue
		}
		addr, port, ok := parseHexAddr(fields[1])
		if !ok || port == 0 {
			continue
		}
		inode := fields[9]
		out = append(out, Listener{
			Proto:   proto,
			Addr:    addr.String(),
			Port:    port,
			Wild:    addr.IsUnspecified(),
			Process: inode, // temporarily the inode; resolved to a name later
		})
	}
	return out
}

// parseHexAddr decodes "0100007F:1F90" (v4) or 32 hex chars:port (v6). The IP
// half is written as little-endian 32-bit words, so each 8-char group is
// byte-reversed.
func parseHexAddr(s string) (netip.Addr, int, bool) {
	ipHex, portHex, found := strings.Cut(s, ":")
	if !found {
		return netip.Addr{}, 0, false
	}
	port64, err := strconv.ParseInt(portHex, 16, 32)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	raw, err := hex.DecodeString(ipHex)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.Addr{}, 0, false
	}
	for g := 0; g < len(raw); g += 4 {
		raw[g], raw[g+1], raw[g+2], raw[g+3] = raw[g+3], raw[g+2], raw[g+1], raw[g]
	}
	addr, ok := netip.AddrFromSlice(raw)
	if !ok {
		return netip.Addr{}, 0, false
	}
	// A v4-mapped socket in the tcp6 table is really a v4 listener.
	return addr.Unmap(), int(port64), true
}
