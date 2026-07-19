package web

import "testing"

// TestValidPort pins the 1–65535 bound: the `[0-9]{1,5}` shape check alone waved
// through out-of-range values like 99999 (left for nft --check to reject later);
// validPort rejects them at the door.
func TestValidPort(t *testing.T) {
	ok := []string{"1", "22", "443", "8080", "65535"}
	for _, s := range ok {
		if !validPort(s) {
			t.Errorf("validPort(%q) = false, want true", s)
		}
	}
	bad := []string{"", "0", "65536", "99999", "-1", "80x", " 80", "abc"}
	for _, s := range bad {
		if validPort(s) {
			t.Errorf("validPort(%q) = true, want false", s)
		}
	}
}
