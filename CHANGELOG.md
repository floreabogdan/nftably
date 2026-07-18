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

- **Packet-path simulator** (`/simulate`). Describe a packet — hook, protocol,
  source/destination, ports, interfaces, connection state — and see a step-by-step
  trace of which rule decides it, ending in ACCEPT/DROP/REJECT. It walks the
  candidate model exactly as netfilter would (base chains in priority order,
  rules top to bottom, following jump/goto) but touches nothing: pure Go, no
  kernel, no privilege. Conditions it can't model (marks, tcp flags, icmp types)
  mark a rule *indeterminate* and flag the trace as uncertain rather than
  guessing — so you can answer "will my SSH still get in?" before you apply.
- **Live rule preview.** The editor's "renders as" panel now updates as you type
  (debounced, server-rendered so it can't drift from what applies) and shows the
  rule inside its chain — `chain input { … <your rule> … }`.
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

### Security

- **Rule values are validated before they render.** Match values and statement
  params are checked against nft's structural characters (and, where the grammar
  is known, typed: jump/goto targets must be chain identifiers, marks numeric,
  NAT targets real addresses, log levels and rate units against fixed sets). This
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

### Fixed

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
  into the object model and presets. The advisor UI is temporarily unlinked
  pending a re-point at the new model.

## Earlier

Pre-redesign milestones (M1–M6) added the read-only ruleset viewer, iptables
import preview, the first rule model with render/diff/apply, forwarding, a rule
library and a guided setup, named lists, and a live connections view with GeoIP.
Those are superseded by the redesign above.

[Unreleased]: https://github.com/floreabogdan/nftably/commits/main
