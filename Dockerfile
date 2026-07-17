# syntax=docker/dockerfile:1

# ── build ────────────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS build
WORKDIR /src

# Cache modules first.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=0.1.0-dev
# CGO stays off — modernc.org/sqlite is pure Go, so the binary is static and
# needs nothing from the final image to run.
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags="-s -w -X github.com/floreabogdan/nftably/internal/buildinfo.Version=${VERSION}" \
      -o /out/nftably ./cmd/nftably

# ── runtime ──────────────────────────────────────────────────────────────
FROM alpine:3.20
# nftables: the nft binary nftably shells out to. iptables: the coexistence
# probe and one-time import preview.
RUN apk add --no-cache nftables iptables ip6tables \
 && addgroup -S nftably \
 && adduser -S -G nftably -H -h /var/lib/nftably nftably \
 && mkdir -p /var/lib/nftably \
 && chown nftably:nftably /var/lib/nftably

COPY --from=build /out/nftably /usr/bin/nftably

VOLUME /var/lib/nftably
EXPOSE 8080
# NOTE: reading the host firewall from a container requires --network=host and
# --cap-add=NET_ADMIN (a container in its own net namespace only sees its own,
# empty ruleset). Run init first to create the admin account:
#   docker run --rm -it --network=host --cap-add=NET_ADMIN \
#     -v nftably-data:/var/lib/nftably nftably init
#   docker run -d --network=host --cap-add=NET_ADMIN \
#     -v nftably-data:/var/lib/nftably nftably
ENTRYPOINT ["nftably"]
CMD ["server", "--listen", "0.0.0.0:8080"]
