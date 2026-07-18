# nftably

A web UI for **nftables** that runs on your router. nftably detects the host
firewall, shows you the live ruleset — IPv4 and IPv6 together — and (over the
coming milestones) lets you manage it safely: render rules from a model, preview
the diff, and apply with an armed auto-revert so a bad rule can never lock you
out of the box you're editing.

It's a single Go binary backed by SQLite. No agent, no cloud, no external
dependencies at runtime beyond `nft` itself. Install the package, run
`nftably init`, and go.

> **Status: M6.** nftably now starts with a guided setup — it detects what
> runs on the box, pre-checks the right rules with the reasoning attached,
> and shows the generated config live while you decide. Around it: named
> address lists (create as many as you want — plain groups your rules source
> from, always-allow management networks, always-block blacklists), a live
> connections view with optional GeoIP countries and one-click block, and
> everything still applied as one atomic transaction with the armed
> auto-revert.

---

## Why

Managing a router's firewall by hand-editing `/etc/nftables.conf` over SSH is
error-prone, and the scariest part is that the mistake which locks you out is
the same command that applies the fix. nftably's job is to make firewall changes
on a remote router **safe to make**:

- **One model for v4 and v6.** netfilter's `inet` family carries both in a single
  table, so a rule is written once and covers both protocols.
- **Lockout safety.** Every apply is an atomic `nft -f` transaction with an
  armed auto-revert: if you don't confirm within the window, the previous
  ruleset is restored — even if your SSH session drops, and even if nftably
  itself is restarted mid-window (the revert snapshot is persisted).
- **Opinionated guardrails.** The rendered config always starts with the
  baseline that makes a drop policy survivable — loopback, `established,related`,
  and the ICMPv6 (ND/RA/PMTUD) IPv6 needs — and a lint pass warns before an
  apply that would leave no way in for new SSH or UI connections.
- **A router when you ask, a host when you don't.** Forwarding is off until the
  WAN interface is named. Once it is, the forward chain gets its own survivable
  baseline (replies, DNAT'ed flows and LAN→WAN pass; the policy decides the
  rest), masquerade is one checkbox, and port-forwards are DNAT rules that work
  under a drop policy without extra accepts.
- **Named lists, as many as you want.** A list is a group of IPs/ranges,
  rendered as nft sets. Point rules at one as their source ("SSH only from
  @office") and edit the list later — every rule follows. Or give a list
  instant behaviour: *always allow* (accepted before everything — a
  management network that can never be locked out) or *always block*
  (dropped before established connections, so a block also cuts live
  sessions). Allow beats block; block beats established.
- **See, then act.** The Connections page shows every flow conntrack knows
  about — to, from and through the box, with countries when you point nftably
  at a GeoIP database — and every remote address has a Block button.
- **Explained, not just configured.** The guided setup detects what runs on
  the box (nginx listening on 80, sshd, a routing kernel…), pre-checks the
  matching rules from a curated catalogue — each with the why attached, and
  databases deliberately absent — prefills your management network from the
  address you are connecting from, and previews the generated nftables
  config live as you change choices. It saves the model; Changes applies it
  with the auto-revert armed.

## Roadmap

| Milestone | What it adds | State |
|-----------|--------------|-------|
| **M1** | Detect backend, read-only ruleset viewer, iptables import preview | ✅ |
| **M2** | Rule model → render → diff → preview (no apply) | ✅ |
| **M3** | Apply + commit-confirmed auto-revert + lint guardrails | ✅ |
| — | Advisor: detect installed software & listeners, advise rules | ✅ |
| **M4** | Forward filtering / NAT / port-forwards | ✅ |
| **M5** | Rule catalogue + one-click hardening (now inside the guided setup) | ✅ |
| **M6** | Guided setup, named lists (+roles), list-sourced rules, live connections + top IPs (GeoIP), one-click block | ✅ this release |
| **M7** | Drop logging + viewer, rate limiting / brute-force protection, country blocking | planned |

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

nftably binds every interface by default and serves plain HTTP unless you give
it a certificate. On a fresh install its access list is empty (allow-all), and
the UI warns you about this until you narrow it. Ways to close it down:

- **Access list** — Settings → Access control. One IP/CIDR per line. Loopback is
  always allowed, so an SSH tunnel can never lock you out.
- **Native TLS** — `--tls-cert cert.pem --tls-key key.pem` (TLS 1.2 minimum).
- **Loopback + SSH tunnel** — start with `--listen 127.0.0.1:8080` and reach it
  over `ssh -L 8080:127.0.0.1:8080 router`.

The blocked-client path closes the TCP connection outright, so a scanner can't
even tell there's a service on the port. Every response carries hardening
headers (a strict CSP with no inline scripts, no framing, no cross-origin
reads), cross-origin POSTs are rejected server-side, failed logins are
rate-limited per IP, and operator actions are recorded on the event timeline.

Found a vulnerability? See [SECURITY.md](SECURITY.md).

## Architecture

```
cmd/nftably/       CLI: init · doctor · detect · server
internal/nft/      shell out to nft (-j JSON for structure, -a text for rule wording);
                   backend detection; iptables coexistence probe + translate preview
internal/store/    SQLite: settings, users, sessions, events, the rule model,
                   port-forwards, named address lists, config versions + the
                   persisted pending apply
internal/render/   model → `table inet nftably` config text (sets + input/
                   forward/nat chains); apply/revert transactions; lockout
                   lint; unified diff
internal/conntrack/ read the kernel's live connection table (procfs, or the
                   conntrack tool where the kernel hides procfs)
internal/advisor/  detect installed software + listening sockets, suggest rules
internal/doctor/   preflight checks
internal/web/      server-rendered UI (html/template), auth, access control
```

The live ruleset is **always read fresh from `nft`** — never cached in the
database. The database holds nftably's own state (login, settings, events) and
the model: rules, forwarding settings, port-forwards, lists, config versions.
GeoIP lookups (optional, Settings → GeoIP) run against a local MaxMind file —
nftably never phones anywhere.

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
