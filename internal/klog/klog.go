// Package klog reads the kernel log and extracts netfilter LOG lines — the
// output of nftables `log` statements — into structured entries for the log
// viewer. A rule like `... log prefix "blocked "` writes a line to the kernel
// ring buffer (via nf_log_syslog) that dmesg/journald expose; this package
// parses those lines. Reading needs Linux and the privilege to read the kernel
// log (root or CAP_SYSLOG); off Linux, or without it, it degrades to a note.
package klog

import (
	"strconv"
	"strings"
	"time"
)

// Entry is one logged packet.
type Entry struct {
	Time   time.Time
	Prefix string // the rule's log prefix, e.g. "blocked "
	In     string // ingress interface
	Out    string // egress interface
	Src    string // source address
	Dst    string // destination address
	Proto  string // TCP | UDP | ICMP | …
	SPort  int    // source port (0 if none)
	DPort  int    // destination port
}

// maxEntries bounds how many parsed entries the viewer keeps (newest kept).
const maxEntries = 500

// Read returns the recent netfilter log entries, newest first. The string is a
// human note explaining why there are none (not Linux, no privilege) — empty
// when the read itself succeeded (even if it found nothing).
func Read() ([]Entry, string) {
	lines, note := rawKernelLog()
	if note != "" {
		return nil, note
	}
	boot := bootTime()
	var out []Entry
	for _, l := range lines {
		if e, ok := parseNetfilterLine(l, boot); ok {
			out = append(out, e)
		}
	}
	// Newest first, capped.
	reverse(out)
	if len(out) > maxEntries {
		out = out[:maxEntries]
	}
	return out, ""
}

// parseNetfilterLine parses one dmesg line into an Entry, reporting false when
// it is not a netfilter LOG line. A LOG line looks like:
//
//	[  123.456789] <prefix>IN=eth0 OUT= MAC=… SRC=1.2.3.4 DST=5.6.7.8 … PROTO=TCP SPT=1234 DPT=22 …
//
// The bracketed value is seconds since boot; boot converts it to wall-clock time.
func parseNetfilterLine(line string, boot time.Time) (Entry, bool) {
	// Optional "[  123.456789] " uptime stamp.
	var uptime float64
	haveUptime := false
	if strings.HasPrefix(line, "[") {
		if end := strings.Index(line, "] "); end > 0 {
			if f, err := strconv.ParseFloat(strings.TrimSpace(line[1:end]), 64); err == nil {
				uptime, haveUptime = f, true
			}
			line = line[end+2:]
		}
	}

	// The netfilter LOG format always carries an "IN=" field; the operator's
	// prefix is whatever precedes it. Prefer the space-delimited " IN=" so a
	// prefix that itself contains "IN=" (e.g. "WIN= ") isn't split mid-word; fall
	// back to a leading "IN=" for a prefix with no trailing space.
	in := strings.Index(line, " IN=")
	if in >= 0 {
		in++ // step past the leading space onto "IN="
	} else if strings.HasPrefix(line, "IN=") {
		in = 0
	} else {
		return Entry{}, false
	}
	prefix := strings.TrimRight(line[:in], " ")
	kv := map[string]string{}
	for _, tok := range strings.Fields(line[in:]) {
		if k, v, ok := strings.Cut(tok, "="); ok {
			kv[k] = v
		}
	}
	// A real LOG line has both SRC and DST; anything else is noise.
	if kv["SRC"] == "" || kv["DST"] == "" {
		return Entry{}, false
	}

	e := Entry{
		Prefix: prefix,
		In:     kv["IN"],
		Out:    kv["OUT"],
		Src:    kv["SRC"],
		Dst:    kv["DST"],
		Proto:  kv["PROTO"],
	}
	e.SPort, _ = strconv.Atoi(kv["SPT"])
	e.DPort, _ = strconv.Atoi(kv["DPT"])
	if haveUptime && !boot.IsZero() {
		e.Time = boot.Add(time.Duration(uptime * float64(time.Second)))
	}
	return e, true
}

func reverse(e []Entry) {
	for i, j := 0, len(e)-1; i < j; i, j = i+1, j-1 {
		e[i], e[j] = e[j], e[i]
	}
}
