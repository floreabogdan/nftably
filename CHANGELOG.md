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
