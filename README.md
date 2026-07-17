# nftably

A web UI for **nftables** that runs on your router. nftably detects the host
firewall, shows you the live ruleset — IPv4 and IPv6 together — and (over the
coming milestones) lets you manage it safely: render rules from a model, preview
the diff, and apply with an armed auto-revert so a bad rule can never lock you
out of the box you're editing.

It's a single Go binary backed by SQLite. No agent, no cloud, no external
dependencies at runtime beyond `nft` itself. Install the package, run
`nftably init`, and go.

> **Status: M1 (read-only).** This release detects the backend and shows the
> live ruleset. It never writes to netfilter yet — see the roadmap below.

---

## Why

Managing a router's firewall by hand-editing `/etc/nftables.conf` over SSH is
error-prone, and the scariest part is that the mistake which locks you out is
the same command that applies the fix. nftably's job is to make firewall changes
on a remote router **safe to make**:

- **One model for v4 and v6.** netfilter's `inet` family carries both in a single
  table, so a rule is written once and covers both protocols.
- **Lockout safety (coming in M3).** Every apply is an atomic `nft -f`
  transaction with an armed auto-revert: if you don't confirm within N seconds,
  the previous ruleset is restored — even if your SSH session drops.
- **Opinionated guardrails.** A lint layer that refuses the classic footguns:
  dropping your own management connection, dropping `established,related`, or
  black-holing the ICMPv6 (ND/RA/PMTUD) that IPv6 needs to function.

## Roadmap

| Milestone | What it adds | State |
|-----------|--------------|-------|
| **M1** | Detect backend, read-only ruleset viewer, iptables import preview | ✅ this release |
| **M2** | Rule model → render → diff → preview (no apply) | planned |
| **M3** | Apply + commit-confirmed auto-revert + lint guardrails | planned |
| **M4** | Zones / forward filtering / NAT / port-forwards | planned |
| **M5** | Rule library ("pick rules") + one-click hardening | planned |

## Quick start

### From a package (Debian/Ubuntu)

```sh
sudo apt install ./nftably_*_amd64.deb   # pulls in nftables
sudo nftably init                        # create the admin account
sudo nftably doctor                      # check nft access + database
sudo systemctl enable --now nftably
```

Then browse to `http://<router>:8080`.

### From source

```sh
go build -o nftably ./cmd/nftably
sudo ./nftably init --db /var/lib/nftably/nftably.db
sudo ./nftably server --db /var/lib/nftably/nftably.db
```

`nftably` reads netfilter through `nft`, which needs `CAP_NET_ADMIN` — in
practice run it as root, or (as the packaged systemd unit does) as a dedicated
account granted only that one capability.

## Commands

```
nftably init      create the database and admin account
nftably doctor    preflight: nft installed & readable, iptables coexistence, db writable
nftably detect    print the detected backend and a ruleset summary (the CLI twin of the dashboard)
nftably server    run the read-only web UI
nftably version   print the version
```

## Security posture

nftably binds every interface by default and has **no TLS**. On a fresh install
its access list is empty (allow-all), and the UI warns you about this until you
narrow it. Two ways to close it down:

- **Access list** — Settings → Access control. One IP/CIDR per line. Loopback is
  always allowed, so an SSH tunnel can never lock you out.
- **Loopback + SSH tunnel** — start with `--listen 127.0.0.1:8080` and reach it
  over `ssh -L 8080:127.0.0.1:8080 router`.

The blocked-client path closes the TCP connection outright, so a scanner can't
even tell there's a service on the port.

## Architecture

```
cmd/nftably/       CLI: init · doctor · detect · server
internal/nft/      shell out to nft (-j JSON for structure, -a text for rule wording);
                   backend detection; iptables coexistence probe + translate preview
internal/store/    SQLite: settings, users, sessions, event timeline (pure-Go driver)
internal/doctor/   preflight checks
internal/web/      server-rendered UI (html/template), auth, access control
```

The live ruleset is **always read fresh from `nft`** — never cached in the
database. The database holds only nftably's own state (login, settings, events).
The firewall model (zones, rules, NAT, config versions) lands in later
milestones as new tables.

## Development

```sh
go build ./...
go test ./...
go vet ./...
GOOS=linux GOARCH=amd64 go build -o nftably-linux-amd64 ./cmd/nftably   # cross-compile to the router
```

nftably compiles and its web UI runs on any OS (handy for development); the
firewall-reading paths simply report "nft not installed" off Linux.

## License

0BSD — see [LICENSE](LICENSE).
