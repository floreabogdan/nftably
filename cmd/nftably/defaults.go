package main

const (
	defaultDBPath = "/var/lib/nftably/nftably.db"
	// nftably binds every interface so a fresh install is reachable without
	// editing anything. It has no TLS and its access list starts as allow-all,
	// so the UI says so until Settings → Access narrows it. Bind loopback with
	// --listen 127.0.0.1:8080 (plus an SSH tunnel) for the closed posture.
	defaultListen = "0.0.0.0:8080"
	// nftBinary is the nft(8) command nftably shells out to for every read
	// (and, from M3 on, every atomic apply). Resolved via PATH by default.
	defaultNftBinary       = "nft"
	defaultIptablesSave    = "iptables-save"
	defaultIP6tablesSave   = "ip6tables-save"
	defaultIptablesTransBn = "iptables-translate"
	defaultSystemdUnit     = "nftables"
)
