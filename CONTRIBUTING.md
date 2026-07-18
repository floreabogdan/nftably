# Contributing to nftably

Thanks for your interest. nftably is a personal project released in the hope it is useful to
someone else. Issues and pull requests are welcome — and, as the README says, may be ignored or
declined. Please read this first so we don't waste each other's time.

## Before you start

nftably's design goal is **"everything nftables can express, but explained and safe by default."**
It models the real object graph (tables → chains → rules, any family) and exposes every match and
statement as a typed, explained control — but it refuses to be a footgun: every apply is validated
by `nft --check`, loaded as one atomic transaction, and armed with an auto-revert so a bad rule
can't lock you out.

If your change adds a knob, it should land as an entry in the catalogue (`internal/nftcat`) with a
plain-language label, help text and an example — that's what keeps the tool approachable. If it
adds a dependency or broadens scope, **open an issue first** and describe the use case. If you
disagree with the approach, hand-writing the nftables ruleset is a perfectly good way to run a
firewall, and forking is free (it's 0BSD).

## Development

Requires Go 1.26+. There is no frontend build step — the UI is server-rendered `html/template`
with `go:embed` and a little vanilla JavaScript, and there will not be a node toolchain.

```sh
go test -race ./...    # the whole suite, under the race detector
gofmt -l .             # must print nothing
go vet ./...           # must pass
golangci-lint run      # if you have it installed; CI runs it
govulncheck ./...      # known-vulnerability scan; CI runs it
```

Before opening a PR, make sure `gofmt`, `go vet`, `golangci-lint`, `go test -race ./...` and
`govulncheck ./...` all pass — CI runs exactly these and will reject a red build.

Cross-compile to try it on a router (static binary, no cgo):

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o nftably ./cmd/nftably
```

The firewall paths need Linux and `nft`; the easiest way to exercise them is a container:

```sh
docker run --rm -it --network=host --cap-add=NET_ADMIN -v $PWD:/src -w /src \
  golang:1.26-alpine sh -c 'apk add --no-cache nftables && go test ./...'
```

## House conventions

- **Comments explain *why*, not *what*.** nftably's comments carry the reasoning behind a
  decision; match that. Don't add comments that restate the next line.
- **Keep the dependency list short.** The whole point is a single static binary; a new dependency
  needs a strong justification.
- **Validate at the model boundary, and let `nft` be the final judge.** Anything interpolated into
  the ruleset is validated in the store; every candidate is dry-run through `nft --check` before it
  can reach the kernel.
- **New knobs go in the catalogue,** with a label, help and example — never a bare control.
- **Never log or render secrets**, and never put a real network's addresses or ASN in committed
  code, tests, docs or screenshots — use the documentation ranges (RFC 5737 `192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24`; RFC 3849 `2001:db8::/32`; AS64496–AS64511).
- **Tests come with behavior changes.** The store, render and web layers have good coverage; keep
  it that way.

## Pull requests

- Branch from `main`, keep the PR focused, and write a clear description of the problem and the fix.
- One logical change per PR. Unrelated cleanups are welcome but as separate PRs.
- By contributing you agree your work is released under the project's [0BSD license](LICENSE) —
  public-domain-equivalent, no attribution required. No CLA, no sign-off needed.

## Security

Please do **not** file security issues in public. See [SECURITY.md](SECURITY.md).
