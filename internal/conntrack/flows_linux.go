//go:build linux

package conntrack

import (
	"bytes"
	"os"
	"os/exec"
)

// Flows reads the live conntrack table: /proc/net/nf_conntrack when the
// kernel exposes it, otherwise the conntrack(8) tool over netlink (some
// kernels are built without CONFIG_NF_CONNTRACK_PROCFS). The note explains
// an empty result that is a platform limitation rather than a quiet box.
func Flows() ([]Flow, string) {
	if f, err := os.Open("/proc/net/nf_conntrack"); err == nil {
		defer f.Close()
		return parse(f), ""
	}
	if path, err := exec.LookPath("conntrack"); err == nil {
		var flows []Flow
		ran := false
		for _, family := range []string{"ipv4", "ipv6"} {
			out, err := exec.Command(path, "-L", "-f", family).Output()
			if err != nil {
				continue
			}
			ran = true
			flows = append(flows, parse(bytes.NewReader(out))...)
		}
		if ran {
			return flows, ""
		}
	}
	return nil, "Could not read the conntrack table: this kernel does not expose /proc/net/nf_conntrack and the conntrack(8) tool is not installed. Install conntrack-tools (package \"conntrack\" on Debian/Ubuntu, \"conntrack-tools\" on Alpine) to enable this view."
}
