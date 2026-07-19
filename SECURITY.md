# Security Policy

nftably manages a host's nftables firewall — the thing standing between the machine and
the network. Please treat a security report here as you would for any infrastructure tool.

## Reporting a vulnerability

**Please report privately. Do not open a public issue for a security problem.**

Use GitHub's private vulnerability reporting: on the repository's **Security** tab, click
**Report a vulnerability** ([Security Advisories](https://github.com/floreabogdan/nftably/security/advisories/new)).
This opens a private channel with the maintainer.

Please include:

- the nftably version (`nftably version`) and the nftables version,
- what you found and how it can be reproduced,
- the impact you think it has.

## What to expect

This is a personal project maintained on a best-effort basis. There is **no SLA, no bounty,
and no guarantee of a fix or a timeline.** Reports are read and taken seriously, and a fix
will be made when one is warranted and practical. Coordinated disclosure is appreciated: give
a reasonable window before publishing details.

## Scope and non-issues

Some properties are documented and by design, not vulnerabilities:

- **nftably listens on every interface out of the box** (`0.0.0.0:8080`), and its IP allow-list
  starts as allow-all. This is deliberate: a firewall UI that will not answer until a config file
  is edited does not get set up. nftably warns once in its startup log while it is in that state,
  and flags it on the Access settings page. Narrow it under Settings → Access control — an
  unlisted address then has its connection closed with no response — or bind it closed with
  `--listen 127.0.0.1:8080` and reach it over an SSH tunnel.
- **TLS is off by default.** Unless you pass `--tls-cert`/`--tls-key` (TLS 1.2 minimum),
  nftably serves plain HTTP, so on a public address the login and session cookie travel in the
  clear; the allow-list governs who may connect, not what is readable on the wire. Give it a
  certificate, or put nftably on a management network you trust or on loopback behind an SSH
  tunnel. Operator actions are recorded in an audit trail on the event timeline.
- **The database file is sensitive.** It holds the admin password hash (bcrypt) and session
  tokens (stored only as SHA-256 hashes, so a read does not hand over usable cookies); protect it
  like any credential store on the host.

Reports that amount to "you can do damage if you already have the nftably database, the login
cookie, or root on the host" are out of scope — those are equivalent to already controlling
the machine.

## Supported versions

Only the latest release (and `main`) is supported. There are no backports.
