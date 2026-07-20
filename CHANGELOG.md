# Changelog

All notable changes to nftably are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims for
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.4] - 2026-07-20

### Fixed

- **More `nft list` readback quirks no longer show as phantom Changes/drift.** The
  rate-limit auto-ban feature surfaced version-dependent reformatting the 0.1.3
  canonicalizer didn't yet fold away: the kernel-default `size` on dynamic sets (both
  as a set-body line and stamped inline into `meter … size N`), the `flags
  dynamic,timeout` comma-spacing, the rate detector printed as `meter m { … }` or
  `add @m { … }` depending on the nft version, and an NFQUEUE fail-open detector
  listed as `queue flags bypass to N` vs the rendered `queue num N bypass`. All are
  normalized now, on both the Changes diff and the drift fingerprint. Verified with
  a live-kernel round-trip.

## [0.1.3] - 2026-07-20

### Fixed

- **The Changes diff now goes quiet after a clean apply.** nftably compared the raw
  `nft list` text against its own render, so the kernel's cosmetic reformatting — live
  counter totals, one-per-line set-element wrapping, reordered anonymous sets like
  `icmp type { … }`, and the quoted `counter name "…"` — showed as phantom differences
  that never resolved. Both sides are now canonicalized before diffing, so only real
  changes appear.
- **No more false config-drift alerts.** The drift fingerprint stripped inline counter
  values but not a named counter's object body (`packets N bytes M`), so a counter that
  merely counted traffic changed the fingerprint and tripped a spurious "changed outside
  nftably" alarm. Drift now shares the same canonicalization.
- **The firewall log viewer works under systemd out of the box.** The unit now grants
  `CAP_SYSLOG` alongside `CAP_NET_ADMIN`, so reading the kernel ring buffer (`dmesg`) no
  longer needs root or `kernel.dmesg_restrict=0`.

## [0.1.2] - 2026-07-20

### Changed

- **The default listen port is now `8099`** (was `8080`), so nftably coexists with the
  sister project birdy — which owns `8080` — without a port clash out of the box.
  Existing installs are unaffected: the port is whatever `nftably init` stored, so only
  a fresh install that does not pass `--listen` picks up the new default.

## [0.1.1] - 2026-07-20

### Changed

- **Port-forward and flowtable are now modals.** Both moved off the Firewall page body
  into dialogs opened from buttons beside *New table*, and the flowtable dialog gained a
  table picker — so the "Add flowtable" panel no longer repeats on every table card.
  Named sets' *New list* form likewise became a modal opened from the page header.
- **Auto-ban quick-fill.** The *Auto-ban any service* form gained one-click **SSH** and
  **HTTP** buttons that prefill it, and the separate *Brute-force auto-ban for SSH* card
  was removed as redundant — the SSH button reproduces it exactly.
- **Reordering polish.** A drag now shows a cursor-following chip naming what is being
  moved, with clearer drop styling; text can no longer be selected mid-drag; and where
  drag is available the per-item up/down buttons are hidden (they remain as the no-JS
  fallback).

### Fixed

- The left navigation now scrolls when it is taller than the viewport, so the lower items
  (down to Settings) are always reachable.
- Page-title icons are vertically centered with their heading; the Firewall how-to step
  numbers align with the arrows, and chain rule-count badges are centered.
- The topbar Ctrl-K hint no longer wraps onto two lines.

### Docs

- README: added beta **Warning** and **Caution** callouts, and regenerated every
  screenshot as a lossless PNG.

## [0.1.0] - 2026-07-20

### Added — editing workflow

- **Drag-and-drop reordering** of rules within a chain, chains within a table (the
  tab strip), and tables on the page — one generic, axis-aware helper. The up/down
  buttons remain as the keyboard-accessible, no-JS fallback.
- **Bulk rule actions.** Select rules with per-row checkboxes (or a chain's "Select"
  toggle) and enable, disable, move to another chain, or delete the whole selection
  at once.
- **Move or copy a rule across chains.** The rule editor's Chain selector relocates a
  rule to another chain of the same table, and each row's "copy to…" picker
  duplicates a rule straight into another chain.
- **Command palette.** Ctrl-K / ⌘K opens a fuzzy launcher to jump to any page or
  quick action from anywhere, keyboard-driven and needing no backend.

### Added — power features & integrations

- **Verdict maps (vmap).** A rule can now be a single O(1) map — `tcp dport vmap
  { 22 : accept, 80 : accept, 443 : accept }` — instead of a stack of one-per-port
  rules. Entries can jump to a chain to branch into a sub-policy per key.
- **Flowtable fast-path offload.** A first-class flowtable object (created per table
  on the Firewall page, bound to interfaces, optional hardware offload) plus a *Flow
  offload* action (`flow add @ft`) that hands established connections to the kernel
  fast path — a big throughput win on a router. The rule editor suggests the
  flowtables defined in the table as you type.
- **Named counters.** The *Count* action takes an optional name; same-named counters
  across rules add into one running total, and nftably declares the `counter <name>`
  object automatically from usage.
- **Raw rules + tags.** A guarded *raw* rule type accepts a verbatim nft line for what
  the catalogue can't yet express (validated so it can't break out of its chain and
  still gated by `nft --check`), and freeform comma-separated **tags** organise and
  filter rules.
- **Generic brute-force auto-ban.** The kernel fail2ban is no longer SSH-only — a form
  on the Posture page protects any service (name, tcp/udp, port(s), rate) with the
  detect-and-ban dynamic set.
- **DNS-sourced named sets.** A set can track a hostname, resolved to its live A/AAAA
  addresses and refreshed on schedule — alongside the existing GeoIP and remote-feed
  sources.
- **Port-forward wizard.** Turns "expose external tcp/443 to 192.168.1.10:8443" into
  the DNAT rule (creating a nat table/prerouting chain if needed) plus the matching
  forward-accept, model-only.
- **Token-gated block API.** `/api/block`, `/api/unblock`, `/api/blocked` let external
  tooling feed addresses into a blocklist set behind a bearer token.
- **Drift detection.** nftably fingerprints the tables it owns and detects when the
  live ruleset was changed outside nftably, with a matching **config-drift** alert.
- **More alert channels and triggers.** Telegram, ntfy and Gotify join webhook /
  Slack / Discord / email; new triggers for new-exposure, failed-login bursts and
  config drift.
- **Scheduled automatic backups** (rolling daily on-disk snapshots, pruned) and
  **config-version restore** from a past version's saved model snapshot.

### Fixed — data integrity & false alarms

- **Backup / version-restore now round-trips raw rules, tags and flowtables.** The
  export format carried none of them: restoring a config that contained any raw rule
  aborted outright, and tags/flowtables were silently dropped. All three are now
  exported and rebuilt (flowtables validated up front, before the destructive reset).
- **Drift no longer false-alarms on the auto-ban set.** The kernel fills the dynamic
  ban set with offender addresses whose `expires` counts down every second; the
  fingerprint now ignores dynamic (timeout) set contents while still catching edits
  to static sets.
- **Duplicating a rule no longer drops its raw text and tags** — duplicating a raw
  rule used to produce an empty, non-rendering rule.
- **Port inputs are bounded to 1–65535** at entry (port-forward and per-service
  auto-ban) instead of relying on `nft --check` to reject an out-of-range value.

### Changed — polish

- New controls (drag grips, bulk bar, command palette, the "copy to…" picker) now
  use the shared design tokens, so they follow light/dark and the accent themes;
  the command-palette hint reads **Ctrl-K** off macOS.
- Accessibility: the palette announces the highlighted result to screen readers
  (`aria-activedescendant`); the mouse-only drag grips and bulk checkboxes are hidden
  when JavaScript is off, so keyboard users never land on dead controls.
- The empty Firewall page now offers a "Create your first table" button instead of
  pointing at a control that isn't there.

### Changed — interface cleanup

- **Named sets are just address groups now.** The per-set *role* (address group /
  always-allow / always-block) is gone, along with its dropdown. A role never
  enforced anything on its own — only a rule referencing the set does — so it was a
  confusing extra step. The Connections **Block** button and presets still work:
  they use a set named `blacklist` by convention (created on demand) and the drop
  rule that references it. (An old database's now-unused `role` column is left in
  place and never read.)
- **No default lists are seeded.** A fresh install no longer ships `management` and
  `blacklist` sets — they duplicated what a preset creates (`@mgmt`/`@blacklist`).
  Presets build the sets they need; the Block button creates `blacklist` on first
  use.
- **Advisor merged into Security**, and the **sidebar regrouped** into Observe /
  Manage / Secure / Learn / System, with Concepts in its own group.
- **Settings is now tabbed** by scope — General, Access, GeoIP, Metrics, Import —
  matching the pattern used elsewhere. The standalone **iptables import** page
  moved in as the *Import* tab (`/import` redirects to `/settings?tab=import`).
- **Clearer nav names.** The Security page is now **Posture** (its page title reads
  *Security Posture*), *Review & apply* is the **Changes** page, and *Simulate a
  packet* is **Simulate**. Simulate and Changes sit under **Manage**; Posture and
  Presets under **Secure**.
- **Consistent page headers.** Every page now leads with the same band — group
  eyebrow + breadcrumb, then an icon'd title over a one-line description — including
  the Firewall, Presets and the create/edit forms, which were missing it. The Live
  ruleset page was rebuilt (it had a broken class mismatch): a summary row, each
  table flagged managed-by-nftably or external, and rules as a clean numbered list.

### Fixed

- **Port-forward lint warning.** A DNAT/SNAT/redirect that maps to a port needs the
  rule to have matched a transport protocol first, or nft rejects the config with a
  cryptic error. The Firewall and Changes pages now warn about that specific combo
  before you apply — surfaced by a full real-kernel sweep that applied every
  catalogue knob and tweak to an isolated nftables container, now repeatable via
  `scripts/validate-catalogue.sh` (103 variations load cleanly on nft 1.0.9).
- **Prometheus label values were double-escaped.** A rule comment (or table/chain
  name) containing a quote or backslash came out escaped twice in `/metrics`,
  storing the wrong value in Prometheus. The purpose-built escaper now runs once.
- **The Settings tabs are now wired for screen readers** — each tab carries
  `aria-controls`, and each panel is a labelled `role="tabpanel"`, matching the
  Firewall page's tabs. Each tab also shows its own save confirmation instead of a
  duplicate top-of-page one.
- **The Connections *Block* button no longer leaves an empty `blacklist` set
  behind** when handed an address that doesn't parse — the value is validated
  before the set is created.
- The exposed-services scan logs a warning instead of silently blanking on a read
  error, and the Named-sets save banners link to the **Changes** page.

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

- **Alerts** (Settings → Alerts). Get notified when the firewall does something
  notable: an armed apply **auto-reverts** (you may have been cut off), a source is
  **auto-banned** (a fresh member lands in a dynamic ban set), a service becomes
  **newly reachable from outside** (the exposed-services scan, re-run in the
  background), a **failed-login burst** locks out a source, a blocklist **feed
  fails** to refresh, or **nft goes unreachable** (and recovers). Delivered to a
  generic JSON **webhook**, **Slack**, **Discord**, or by **email (SMTP)** — filter
  each destination to specific events, and send a test. Apply/revert and feed alerts
  are event-driven; nft-availability and auto-bans are watched by a lightweight
  background poller. Ported from the sister project birdy.
- **Theming** (Settings → Theme) grew two more axes on top of light/dark, all
  stored in the browser and applied before first paint: an **accent palette**
  (Ocean, Emerald, Violet, Amber — recolours links, buttons and highlights, with
  dark-mode-aware shades) and a **layout density** (Comfortable or Compact — tighter
  spacing and flatter panels). Both work with light and dark and with each other.
  Follows the multi-axis, token-based approach from the sister project birdy.
- **More catalogue knobs.** Transparent proxy (**tproxy**) for handing traffic to a
  local proxy without rewriting its destination; **DSCP/QoS** — matching (`ip`/`ip6
  dscp`) and setting (`… dscp set ef`); a **conntrack-helper** match (`ct helper
  "ftp"`); and a **trace toggle** (`meta nftrace set 1`) that lights up
  `nft monitor trace` for debugging. Each is fully explained like every other knob
  and verified against nft 1.0.9 (tproxy needs the kernel's TPROXY module, like
  synproxy/queue). Left out for now: numgen/jhash load-balancing and secmark, which
  need map/object or SELinux support that doesn't fit the single-knob model.
- **Three more presets for the hosts people actually run.** A **web server** (HTTP/
  HTTPS open, SSH from @mgmt); a **database server** (PostgreSQL/MySQL scoped to an
  @app tier, never the internet); and a **Docker / container host** — which
  deliberately creates *no* forward chain, since Docker manages the forward hook and
  container NAT itself and a drop-policy forward chain would break container traffic,
  so it only hardens the host's own input.
- **Config backup & restore** (Settings → Backup). Export the whole model — tables,
  chains, rules, and named sets with their entries — as one portable JSON file. It's
  the model, not the database: no login credentials, no settings, so it's safe to
  share, keep in version control, or move to another box. Restore replaces the
  current model wholesale and is model-only — it drops you on Changes to review the
  diff and apply behind the armed auto-revert, and it validates the file before
  touching anything, so a bad upload can't leave a half-restored config.
- **Four new Learn lessons** alongside Concepts, each a sibling page under the Learn
  group with a cross-lesson nav strip: **NAT &amp; port-forwarding** (dnat/snat/
  masquerade, prerouting vs postrouting, and why a port-forward is always two
  rules), a task-oriented **recipe cookbook** (open a service, scope SSH, port-
  forward, rate-limit, auto-ban, block a country — each with a simulate link),
  **Troubleshooting** ("why isn't my rule matching?" — order, the established
  short-circuit, family mismatch, regular-vs-base chains, and debugging with the
  simulator/counters/log), and **Coming from iptables** (mental-model shift,
  terminology map, a side-by-side example, and the import tool).
- **Home router / gateway preset.** Shares one internet connection: a default-deny
  input (LAN-side management, DHCP and DNS; the internet reaches nothing), a forward
  chain that lets the LAN out and replies back but blocks the internet from starting
  connections in, and an inet nat table that masquerades LAN traffic out the wan
  interface — with an empty prerouting chain ready for port-forwards. Verified
  against nftables v1.0.9. Rename the `wan`/`lan` interfaces to match your box.
- **One-click IDS/IPS inspection.** A Posture-page recipe sends forwarded traffic to
  an NFQUEUE for an inline Suricata/Snort to inspect. It's fail-open (a stopped
  inspector lets traffic through rather than blackholing transit) and touches only
  the forward chain, so the operator's own session is never queued — built on the
  existing `queue` action. The rule is added **disabled**: the queue target needs
  kernel NFQUEUE support (`nfnetlink_queue`), and because an apply is one atomic
  transaction, an unsupported rule would reject everything — so you enable it once
  your inspector is attached. A **Setup examples** modal shows copy-pasteable
  Suricata and Snort commands.
- **Posture page grouped into bands.** Assessment (score, best-practice checks,
  exposed services) reads top-to-bottom, then the one-click recipes sit together
  under a *One-click hardening* heading — kept as one scannable page rather than
  tabs, since a posture read is most useful all at once.
- **WireGuard VPN server preset.** The basic secure-server base plus the WireGuard
  essentials: UDP 51820 accepted (the tunnel is key-authenticated), the wg0
  interface trusted for traffic to this box, and a default-drop forward chain that
  routes the tunnel (established/related and traffic in/out of wg0). Clients-to-
  internet masquerade is left to the operator, since it needs the uplink interface
  name.
- **Brute-force auto-ban for SSH** — fail2ban in the kernel, no daemon. One click on
  the Posture page adds a rule that puts any source opening SSH connections faster
  than 10/minute into a **dynamic timeout set** and drops it for an hour, plus an
  early drop of everything in that set (IPv4 and IPv6, inserted above any SSH
  allow). It's built on a new first-class **Rate-ban the source** action
  (`meter … limit rate over … add @set … drop`) usable on any rule; nftably declares
  the `flags dynamic, timeout` set automatically. Verified against nftables v1.0.9.
- **One-click "block this country"** on the Connections view. Next to a remote
  address's country, a single click builds a GeoIP set of that country's CIDRs
  (auto-refreshing, so it stays current) and adds early `ip saddr @blk_xx drop`
  rules to the input chain — before the accepts, so it drops even established
  connections — then drops you on Changes. Idempotent, and model-only
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
  says so when it's hit. The feed-URL field now suggests **well-known public
  blocklists** (FireHOL Level 1/2, Emerging Threats, abuse.ch Feodo, CINS Army) so
  you can subscribe to a reputable threat feed without hunting for the URL.
- **Security** (`/harden`) — one page that both assesses and hardens. A
  plain-language **posture score** grades your model against what a solid host
  firewall needs — default-deny inbound, the survivable base (loopback,
  established/related, invalid dropped), IPv6's mandatory ICMP, anti-spoofing, and a
  scoped SSH — explaining *why each matters*. On the same page, an **Exposed
  services** section scans what's actually listening and runs each through the
  simulator against your model (the former *Advisor*, now merged in). Both halves
  offer safe one-click fixes that land on Changes behind the armed
  auto-revert. A compact score card on the Dashboard links straight to it.
  (`/advisor` now redirects here.)
- **Prometheus metrics** (`/metrics`) — an opt-in exposition endpoint so the
  firewall can be graphed and alerted on in Grafana/Prometheus. Every rule with a
  **Count** action becomes a time series (`nftably_rule_packets_total`,
  `nftably_rule_bytes_total`, labelled by table/chain/rule), alongside
  table/chain/rule counts, an `nftably_up` health gauge, an `nftably_apply_pending`
  gauge, and build info. It's off by default: enable it under Settings, which mints
  a random bearer token; until then `/metrics` returns 404, and once enabled it
  requires `Authorization: Bearer <token>` — on top of the access list that already
  fronts every route. One live nft read per scrape; touches nothing.
- **Docker demo sandbox** (`docker-compose.demo.yml`). A one-command way to try
  nftably in a browser without touching a host firewall: it runs in its own network
  namespace, where — with `CAP_NET_ADMIN` — it has a private, fully writable
  nftables to manage. `docker compose -f docker-compose.demo.yml up --build`, then
  open `http://127.0.0.1:8099` and log in as `admin` / `nftably-demo`. The admin
  account is auto-provisioned on first boot; nft is fully live, so presets apply,
  counters tick and `/metrics` reports `nftably_up 1` — all isolated from the host.
- **Concepts** (`/learn`) — a plain-language guide to how nftables actually works,
  for someone who has never written a firewall rule: the packet's journey through
  the hooks (input/forward/output/pre-/postrouting), base vs regular chains,
  matches and verdicts, connection tracking (the "why does nothing work?" idea),
  address families, and sets. Every concept links to where you act on it — the
  packet simulator, the Security check, the Firewall page — so a newcomer can go
  from "what's a chain?" to a hardened box.
- **Sidebar reorganised** into clearer intents — **Observe** (read the live state),
  **Secure** (Security + Simulate), **Manage** (build the model), **Learn**
  (Concepts), **System** — so the growing set of pages is easier to navigate.
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
  Changes), a deep link into the simulator, and a dismiss/restore.
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
  Firewall page, one screen before Changes, with a link to simulate the
  concern. Changes gained a scannable "What this applies" outline (tables,
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
- **Adoption warning.** Changes now flags a kernel table you are about to
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
  is now consistently named **Changes**.

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
