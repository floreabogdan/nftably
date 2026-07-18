//go:build linux

package klog

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// rawKernelLog returns the kernel ring buffer as lines. It shells out to dmesg,
// which is universal (busybox and util-linux both have it). A failure is almost
// always a permission problem (dmesg_restrict), turned into a note rather than
// an error so the page can explain the fix.
func rawKernelLog() ([]string, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var stdout bytes.Buffer
	cmd := exec.CommandContext(ctx, "dmesg")
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return nil, "Could not read the kernel log — nftably needs root or CAP_SYSLOG to run dmesg (or set kernel.dmesg_restrict=0). Logged packets will appear here once it can."
	}
	return strings.Split(strings.TrimRight(stdout.String(), "\n"), "\n"), ""
}

// bootTime reads the system boot time from /proc/stat (btime, unix seconds), so
// dmesg's since-boot timestamps can be shown as wall-clock time. Zero on failure
// (entries then simply carry no timestamp).
func bootTime() time.Time {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "btime "); ok {
			if secs, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 64); err == nil {
				return time.Unix(secs, 0)
			}
		}
	}
	return time.Time{}
}
