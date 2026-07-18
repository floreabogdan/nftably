package web

import (
	"testing"
	"time"
)

func TestDBIPURL(t *testing.T) {
	got := dbipURL(time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC))
	want := "https://download.db-ip.com/free/dbip-country-lite-2026-07.mmdb.gz"
	if got != want {
		t.Errorf("dbipURL = %q, want %q", got, want)
	}
	// The month is zero-padded.
	if got := dbipURL(time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC)); got != "https://download.db-ip.com/free/dbip-country-lite-2026-01.mmdb.gz" {
		t.Errorf("january url = %q", got)
	}
}
