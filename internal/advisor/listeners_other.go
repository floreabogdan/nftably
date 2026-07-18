//go:build !linux

package advisor

// listeners is Linux-only: it reads /proc/net. Elsewhere (a development
// machine) the advisor still detects installed software, but says why the
// socket half is missing.
func listeners() ([]Listener, string) {
	return nil, "Listening-socket detection needs Linux (/proc/net) — only installed software is shown here."
}

func ipForwarding() bool { return false }
