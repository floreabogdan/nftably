package web

import (
	"net/netip"
	"testing"
)

func TestIsPublicAddr(t *testing.T) {
	public := []string{"8.8.8.8", "1.1.1.1", "203.0.113.9", "2606:4700:4700::1111"}
	blocked := []string{
		"127.0.0.1", "::1", // loopback
		"10.0.0.1", "192.168.1.1", "172.16.0.1", // private v4
		"169.254.169.254",    // link-local (cloud metadata)
		"fe80::1",            // link-local v6
		"fc00::1", "fd00::1", // unique-local v6 (IsPrivate)
		"0.0.0.0", "::", // unspecified
		"224.0.0.1", "ff02::1", // multicast
	}
	for _, s := range public {
		if !isPublicAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s should be public", s)
		}
	}
	for _, s := range blocked {
		if isPublicAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s should be blocked", s)
		}
	}
}
