# Changelog

All notable changes to nftably are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims for
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed — the general-model redesign

nftably was reworked from an opinionated single-host firewall into a **general
nftables manager**: it now models the real object graph — tables (any family) →
chains (base or regular) → rules — and exposes every match and statement as a
typed, explained control instead of a fixed form.

- **Object model.** Manage tables, chains and rules directly. Base chains hook
  into the traffic path (input/output/forward/prerouting/postrouting); regular
  chains are jump/goto targets. Rules are a list of match conditions and action
  statements.
- **The knob catalogue** (`internal/nftcat`). Every match and statement carries a
  plain-language label, a one-line explanation and an example — the single source
  the editor and the renderer both use.
- **Explained rule editor.** Chains shown as tabs; a catalogue-driven form with
  per-knob help, smart pickers (enum dropdowns, the box's real interfaces, a
  named-set picker, sibling-chain jump targets) and a live "renders as" preview.
- **Named sets** are rendered into the tables that reference them, so a rule can
  point at `@office` and you edit the addresses in one place.
- **Presets** (`/presets`): one-click best-practice scaffolds — a hardened **BGP
  edge router** (control-plane hardening, SSH/BGP/BFD from editable `@mgmt`/
  `@peers` sets, an early `@blacklist` drop, output-leak hygiene, seeded so it
  can't lock you out) and a **basic secure server**.
- **Multi-table atomic apply.** The armed auto-revert / persisted-pending /
  crash-recovery safety now covers many tables at once, and removes tables you
  delete from the model. Every candidate is gated by `nft --check`.
- The Connections **Block** button now takes effect immediately (the presets drop
  `@blacklist` before established connections).

### Added

- **One-click "block this country"** on the Connections view. Next to a remote
  address's country, a single click builds a GeoIP set of that country's CIDRs
  (auto-refreshing, so it stays current) and adds early `ip saddr @blk_xx drop`
  rules to the input chain — before the accepts, so it drops even established
  connections — then drops you on Review & apply. Idempotent, and model-only
  until you apply.
- **Firewall log viewer** (`/logs`). Packets logged by a rule's **Log** action now
  show in-app — time, prefix, interfaces, source → destination, protocol/ports —
  read live from the kernel ring buffer (dmesg). Pairs with the per-rule counters:
  add *Count + Log* to a rule and watch, in numbers and in detail, what it catches.
- **Sourced named sets — GeoIP countries and remote feeds.** A named set can now
  be populated automatically instead of by hand: from **a country's CIDRs** (built
  from the GeoIP database you already load — so a rule can `ip saddr @country_cn
  drop` or allow SSH only from `@country_de`), or from a **remote feed** of
  addresses (a threat-intel blocklist), fetched and de-overlapped into a set nft
  accepts. Refresh on demand or let it refresh automatically in the background.
  Sourced sets are read-only in the UI; a cap keeps a runaway source bounded and
  says so when it's hit.
- **Security check** (`/harden`) — a plain-language posture score. It grades your
  model against what a solid host firewall needs — default-deny inbound, the
  survivable base (loopback, established/related, invalid dropped), IPv6's
  mandatory ICMP, anti-spoofing, and a scoped SSH — and explains *why each
  matters*, so it teaches while it checks. Where it's safe, one click adds the
  missing rule and drops you on Review & apply (behind the armed auto-revert); the
  fixes only ever add an accept or drop clearly-bad traffic, so a fix can't lock
  you out. A compact score card on the Dashboard links straight to it.
- **Concepts** (`/learn`) — a plain-language guide to how nftables actually works,
  for someone who has never written a firewall rule: the packet's journey through
  the hooks (input/forward/output/pre-/postrouting), base vs regular chains,
  matches and verdicts, connection tracking (the "why does nothing work?" idea),
  address families, and sets. Every concept links to where you act on it — the
  packet simulator, the Security check, the Firewall page — so a newcomer can go
  from "what's a chain?" to a hardened box.
- **Packet-path simulator** (`/simulate`). Describe a packet — hook, protocol,
  source/destination, ports, interfaces, connection state — and see a step-by-step
  trace of which rule decides it, ending in ACCEPT/DROP/REJECT. It walks the
  candidate model exactly as netfilter would (base chains in priority order,
  rules top to bottom, following jump/goto) but touches nothing: pure Go, no
  kernel, no privilege. Conditions it can't model (marks, tcp flags, icmp types)
  mark a rule *indeterminate* and flag the trace as uncertain rather than
  guessing — so you can answer "will my SSH still get in?" before you apply.
- **Advisor, reworked** (`/advisor`). Instead of generic tips keyed on installed
  binaries, it now scans the box's live listening sockets and runs each one
  through the packet simulator against your model, reporting what the firewall
  actually does: "sshd listens on :22 — a connection from the internet would be
  DROPPED" or "PostgreSQL is reachable from the internet (would ACCEPT)". Each
  finding offers a one-click *Allow* (adds the accept rule and drops you on
  Review & apply), a deep link into the simulator, and a dismiss/restore.
- **Live rule preview.** The editor's "renders as" panel now updates as you type
  (debounced, server-rendered so it can't drift from what applies) and shows the
  rule inside its chain — `chain input { … <your rule> … }`.
- **A smarter rule editor.** Each condition now offers only the operators its
  field actually supports — *is* / *is not* for an address or interface, the full
  ordered set (`is`, `is not`, `<`, `≤`, `>`, `≥`) for a port or TTL — instead of
  a fixed list that let you build a rule nft then rejected. Operators read in
  plain words (the "renders as" panel still shows the true nft), the operator
  stays hidden until you pick a field, choosing a field jumps focus to its value,
  every condition and action has an explicit **remove (×)**, and *Add
  condition*/*Add action* grey out when no slots remain.
- **One smart field instead of a box-plus-dropdown.** A value that has
  suggestions — an address (your named sets), an interface (the box's real ones),
  a connection-state / ICMP-type / flag set (the explained choices) — is now a
  single **combobox**: type what you want *or* pick from the dropdown, in the same
  field. Multiple values accumulate as removable chips (`@office4`, `10.0.0.0/8`),
  each suggestion carries its one-line explanation, and free text is always
  allowed, so nothing the field can express is lost. This replaces the old split
  of a text box beside a separate "use a set…" menu and the flag chips tucked in
  the help line.
- **Live per-rule hit counters.** A rule that carries a *Count* action now shows
  its running packet/byte total next to it on the Firewall page, read live from
  the kernel — build a rule, apply it, and watch it catch traffic. Counters are
  read best-effort (blank when `nft` is unreachable or the table isn't applied
  yet) and are aligned to model rules by position, only when the applied ruleset
  matches the model, so a count is never shown against the wrong rule.
- **Closing the build → apply loop.** Lockout warnings now also appear on the
  Firewall page, one screen before Review & apply, with a link to simulate the
  concern. Review & apply gained a scannable "What this applies" outline (tables,
  chains, hooks, policies, rule counts) above the raw diff, and both pages
  cross-link to the packet simulator.
- **Opt-in GeoIP download.** Settings → GeoIP can fetch the free DB-IP Lite
  country database (CC-BY 4.0, no account), validate it, and optionally refresh it
  monthly. Your own MaxMind file still works. This is the only thing that ever
  makes nftably reach the network, and only when you ask.
- Catalogue knobs for BGP GTSM (`ip ttl` / `ip6 hoplimit`) and connection marks.
- **Attack-mitigation knobs most people never find in nftables.** The editor now
  exposes, each explained in plain language: **SYN-proxy** (`synproxy`) — complete
  the TCP handshake in the kernel so a SYN flood never reaches the service;
  **MSS clamping** (`tcp option maxseg size set rt mtu`) — the classic cure when
  pages hang over a VPN or PPPoE link; **byte quota** (`quota`) — cut a service
  off after it has served so much; **NFQUEUE** (`queue`, with fail-open) — hand
  traffic to an inline IDS/IPS such as Suricata; **notrack** — skip connection
  tracking for high-volume stateless traffic; **owning-user/-group egress
  matches** (`meta skuid`/`skgid`) — filter this box's *outbound* traffic by the
  local user that owns the socket; and a **reverse-path check** (`fib saddr . iif
  oif missing`) — drop spoofed source addresses, nftables' answer to `rp_filter`.
  Every rendered form was verified against `nft` (v1.1.3) in a Linux container.

### Security

- **Rule values are validated before they render.** Match values and statement
  params are checked against nft's structural characters (and, where the grammar
  is known, typed: jump/goto targets must be chain identifiers, marks numeric,
  NAT targets real addresses, log levels and rate units against fixed sets). The
  match **operator** is now checked the same way — a field only accepts the
  operators it offers, so an ordered comparison on an address (`ip saddr > …`) is
  refused at the model boundary instead of slipping through to `nft --check`. This
  closes a path by which an authenticated admin could inject nft that escaped the
  owned-table model — and so escaped the pre-apply snapshot and the auto-revert.
- **Session tokens are hashed (SHA-256) at rest**, so a database read no longer
  yields usable bearer tokens. Changing your password now evicts every other
  session, and the login path always runs bcrypt so an unknown username can't be
  told apart from a wrong password by timing.
- **Adoption warning.** Review & apply now flags a kernel table you are about to
  replace that nftably did not create (a hand-written `nftables.conf`, another
  tool), before you overwrite it.
- **The apply's kernel operations run on a background context**, so an apply that
  cuts off your own connection can't cancel the `nft` transaction mid-flight.
- **Lockout lint covers `output` and `forward` chains**, not just `input`.
- **Tighter Content-Security-Policy.** The templates now carry no inline style
  attributes, so `style-src` drops `'unsafe-inline'` — inline styles are blocked
  as strictly as inline scripts already were (asserted by a test).
- **The login limiter's hot path is O(1).** The expiry sweep runs at most once a
  minute and the entry cap is enforced by an O(1) eviction on insert, so a botnet
  cycling source addresses can no longer turn every login attempt into a full-map
  walk.
- **Feed-sourced sets fetch only public addresses.** A URL feed can't be turned
  into a request against the box's own internal surface (cloud metadata, loopback,
  the LAN) — the dialer refuses non-public destinations, after DNS and across
  redirects.
- **Precise, simulator-based lockout warning.** Before you apply, nftably traces a
  new connection from *your own address* to the UI port and SSH and warns if it
  would be dropped — catching the case the heuristic misses, where access is
  allowed but scoped to a management set you're not in.

### Fixed

- **The Live ruleset viewer showed "expression not rendered" for every rule** on
  real nft: the handle-text parser only recognised a table/chain opener when the
  line ended in `{`, but nft annotates openers with `# handle N` too. It now
  strips that before the check, so each rule's canonical wording is recovered.
- **Live per-rule counters are shown only when the model matches what's applied**
  — an unapplied reorder no longer misattributes the running config's counts to
  the wrong rows.
- **`ingress`/`egress` base chains now render their required `device`** (an
  interface). Previously the editor offered these hooks but produced a config nft
  rejects; they now work on a netdev-capable kernel (and the chain form asks for
  the device only when it applies).
- **Simulator verdicts corrected.** A negated match (`!=`) no longer wrongly fires
  on a wrong-family/protocol packet (nft negates only the value, not the implicit
  family/proto gate), and a rule in an `ip6`-only table no longer matches IPv4
  packets. The advisor, which runs on the same engine, is corrected with it.
- **The Connections "Block" button now actually blocks** even without a preset: it
  wires up the early `@blacklist` drop rules, instead of adding to a set that
  nothing drops.
- **Named-set usage is tracked against the object model.** A set used only by
  object-model rules no longer shows "0 uses" and can't be deleted out from under
  them (which would break the next apply).
- The "Filter this page" box now works on the Firewall page, and is hidden on
  pages with nothing to filter.
- Fetching a single rule (or one chain) no longer scans every match/statement in
  the database; added the object-model foreign-key indexes.
- The starter table/lists are seeded only on a genuinely new database, so a schema
  upgrade never resurrects objects you deleted. Dropped an unused `events` index.
- GeoIP lookups run under a read lock (they no longer serialize), and the SQLite
  connection pool is bounded.

### Changed — accessibility & UX

- The armed-apply countdown is now the visual centrepiece — a large numeral and a
  depleting bar that warms as it nears zero — announced to assistive tech, with
  focus moved to Confirm when it appears.
- WCAG AA contrast for muted explanatory text; accessible names on icon-only
  controls; a skip link and `main` landmark; a complete, keyboard-navigable chain
  tab pattern; modal focus trap/restore; a stateful theme toggle. The apply page
  is now consistently named **Review & apply**.

### Removed

- The opinionated pages `/rules`, `/forwarding`, `/setup` and `/library`, folded
  into the object model and presets. (The advisor is back, rebuilt against the new
  model — see Added.)
- The dormant pre-redesign flat firewall model (`fw_rules`, `firewall`,
  `port_forwards` tables and their Go code) — fully superseded by the object model
  and unreferenced by the UI. Existing databases keep the now-unread tables; fresh
  installs never create them.

## Earlier

Pre-redesign milestones (M1–M6) added the read-only ruleset viewer, iptables
import preview, the first rule model with render/diff/apply, forwarding, a rule
library and a guided setup, named lists, and a live connections view with GeoIP.
Those are superseded by the redesign above.

[Unreleased]: https://github.com/floreabogdan/nftably/commits/main
