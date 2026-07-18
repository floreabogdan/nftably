//go:build !linux

package conntrack

// Flows is Linux-only: it reads /proc/net/nf_conntrack.
func Flows() ([]Flow, string) {
	return nil, "The live connections view needs Linux (/proc/net/nf_conntrack)."
}
