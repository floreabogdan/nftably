#!/usr/bin/env bash
# validate-catalogue.sh — apply every catalogue knob and tweak nftably can emit
# to a REAL, network-isolated nftables kernel, so we validate against the kernel
# itself, not just `nft -c`.
#
# It renders each candidate via tools/nftcheck (the actual render pipeline), then
# loads each into a disposable `--network none` container, flushing between every
# one. Requires Docker.
#
#   scripts/validate-catalogue.sh
#
# Results are classed three ways:
#   PASS  — the kernel loaded it.
#   SKIP  — "No such file or directory": this kernel lacks that netfilter module
#           (e.g. nft_fib, nf_synproxy, nft_quota, nfnetlink_queue on a minimal
#           WSL2/CI kernel). The syntax is valid; the host just can't load it.
#   FAIL  — any other error: a real defect in what nftably rendered. Exits non-zero.
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE=nftcheck-nft
BOX=nftcheck-box

echo "→ building the nft test image ($IMAGE)…"
docker build -q -t "$IMAGE" - >/dev/null <<'DOCKER'
FROM alpine:3.20
RUN apk add --no-cache nftables
DOCKER

echo "→ rendering candidates via tools/nftcheck…"
CANDS=$(mktemp)
go run ./tools/nftcheck > "$CANDS"
total=$(grep -cE '^@@@[^E]' "$CANDS" || true)
echo "  $total candidates"

WORK=$(mktemp -d)
awk '
/^@@@END$/ { b=0; next }
/^@@@/ { name=substr($0,4); gsub(/[^A-Za-z0-9._()!=:+-]/,"_",name); f=WORK "/" (++n) "__" name ".nft"; b=1; next }
b { print > f }
' WORK="$WORK" "$CANDS"

docker rm -f "$BOX" >/dev/null 2>&1 || true
docker run -d --rm --name "$BOX" --cap-add=NET_ADMIN --network none \
	--entrypoint sleep "$IMAGE" 3600 >/dev/null
trap 'docker rm -f "$BOX" >/dev/null 2>&1 || true; rm -rf "$WORK" "$CANDS"' EXIT
echo "→ applying to $(docker exec "$BOX" nft --version)"
echo

pass=0 skip=0 fail=0 skips="" fails=""
for f in "$WORK"/*.nft; do
	name=$(basename "$f" .nft | sed 's/^[0-9]*__//')
	err=$(docker exec -i "$BOX" sh -c 'nft flush ruleset 2>/dev/null; nft -f - 2>&1 1>/dev/null' < "$f" || true)
	if [ -z "$err" ]; then
		pass=$((pass + 1))
	elif echo "$err" | grep -qi 'no such file or directory'; then
		skip=$((skip + 1)); skips="${skips}\n  · ${name} (kernel module not present)"
	else
		fail=$((fail + 1)); fails="${fails}\n  ✗ ${name}: $(echo "$err" | grep -i error | head -1 | sed 's/^.*Error: //')"
	fi
done

echo "════════════════════════════════════════════════════════"
echo "  PASS $pass   SKIP $skip (kernel-module)   FAIL $fail"
echo "════════════════════════════════════════════════════════"
[ "$skip" -gt 0 ] && echo -e "SKIPPED (host kernel lacks the module — valid syntax):$skips"
if [ "$fail" -gt 0 ]; then
	echo -e "\nREAL FAILURES:$fails"
	exit 1
fi
echo "All rendered rules the kernel can load, loaded cleanly."
