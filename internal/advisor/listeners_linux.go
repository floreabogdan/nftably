//go:build linux

package advisor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// listeners reads the kernel's socket tables and resolves each socket to the
// process holding it (best-effort — resolving needs to read other processes'
// /proc entries, which works when nftably runs as root, as it must anyway to
// drive nft).
func listeners() ([]Listener, string) {
	var out []Listener
	for _, t := range []struct{ path, proto string }{
		{"/proc/net/tcp", "tcp"}, {"/proc/net/tcp6", "tcp"},
		{"/proc/net/udp", "udp"}, {"/proc/net/udp6", "udp"},
	} {
		f, err := os.Open(t.path)
		if err != nil {
			continue
		}
		out = append(out, parseProcNet(f, t.proto)...)
		f.Close()
	}

	byInode := socketProcesses()
	seen := map[string]bool{}
	var deduped []Listener
	for _, l := range out {
		inode := l.Process
		l.Process = byInode[inode]
		// The same service often appears in both the v4 and v6 table; one
		// entry per proto/port/addr is enough for advice.
		k := fmt.Sprintf("%s/%d/%s", l.Proto, l.Port, l.Addr)
		if seen[k] {
			continue
		}
		seen[k] = true
		deduped = append(deduped, l)
	}
	return deduped, ""
}

// socketProcesses maps socket inode → process name by walking /proc/*/fd.
func socketProcesses() map[string]string {
	byInode := map[string]string{}
	procs, err := filepath.Glob("/proc/[0-9]*/fd")
	if err != nil {
		return byInode
	}
	for _, fdDir := range procs {
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // not ours to read
		}
		var comm string
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || !strings.HasPrefix(target, "socket:[") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
			if comm == "" {
				raw, err := os.ReadFile(filepath.Join(filepath.Dir(fdDir), "comm"))
				if err != nil {
					break
				}
				comm = strings.TrimSpace(string(raw))
			}
			if _, taken := byInode[inode]; !taken {
				byInode[inode] = comm
			}
		}
	}
	return byInode
}
