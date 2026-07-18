package klog

import (
	"testing"
	"time"
)

func TestParseNetfilterLine(t *testing.T) {
	boot := time.Unix(1_700_000_000, 0)

	// A real nft `log prefix "blocked "` line as dmesg renders it.
	line := `[  123.456789] blocked IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=198.51.100.7 DST=203.0.113.2 LEN=60 TOS=0x00 PREC=0x00 TTL=54 ID=0 DF PROTO=TCP SPT=51000 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0`
	e, ok := parseNetfilterLine(line, boot)
	if !ok {
		t.Fatal("should parse a netfilter LOG line")
	}
	if e.Prefix != "blocked" {
		t.Errorf("prefix = %q, want %q", e.Prefix, "blocked")
	}
	if e.In != "eth0" || e.Out != "" {
		t.Errorf("iface in=%q out=%q", e.In, e.Out)
	}
	if e.Src != "198.51.100.7" || e.Dst != "203.0.113.2" {
		t.Errorf("addrs src=%q dst=%q", e.Src, e.Dst)
	}
	if e.Proto != "TCP" || e.SPort != 51000 || e.DPort != 22 {
		t.Errorf("proto=%q sport=%d dport=%d", e.Proto, e.SPort, e.DPort)
	}
	if want := boot.Add(123456789 * time.Microsecond); e.Time.Sub(want).Abs() > time.Millisecond {
		t.Errorf("time = %v, want ~%v", e.Time, want)
	}
}

func TestParseIgnoresNonLogLines(t *testing.T) {
	for _, line := range []string{
		`[ 65116.231358] docker0: port 2(veth0) entered forwarding state`,
		`random kernel chatter`,
		`[ 1.0] IN=eth0 OUT=`, // no SRC/DST — not a usable LOG line
		``,
	} {
		if _, ok := parseNetfilterLine(line, time.Time{}); ok {
			t.Errorf("should not parse %q as a netfilter log line", line)
		}
	}
}

func TestParseUDPNoUptime(t *testing.T) {
	// journald-style line without the [uptime] stamp, UDP.
	line := `dropped IN=wan0 OUT= SRC=192.0.2.50 DST=203.0.113.9 PROTO=UDP SPT=53 DPT=51820`
	e, ok := parseNetfilterLine(line, time.Time{})
	if !ok {
		t.Fatal("should parse a line without an uptime stamp")
	}
	if e.Prefix != "dropped" || e.Proto != "UDP" || e.DPort != 51820 || e.In != "wan0" {
		t.Errorf("parsed wrong: %+v", e)
	}
	if !e.Time.IsZero() {
		t.Errorf("no uptime and no boot time should leave Time zero, got %v", e.Time)
	}
}
