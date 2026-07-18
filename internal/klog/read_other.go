//go:build !linux

package klog

import "time"

// rawKernelLog is Linux-only: the kernel log and dmesg do not exist elsewhere.
func rawKernelLog() ([]string, string) {
	return nil, "Reading the firewall log needs Linux — this instance is running on another OS (fine for development; the log is empty)."
}

func bootTime() time.Time { return time.Time{} }
