#!/usr/bin/env bash
# Copies the rust_jwk_duo conformance vectors into assets/conformance/.
# Source of truth is the rust_jwk_duo repo; the copies are gitignored.
# Override the source with JWK_DUO_CONFORMANCE_DIR.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
src="${JWK_DUO_CONFORMANCE_DIR:-$here/../../../rust_jwk_duo/conformance}"
dst="$here/assets/conformance"
wyche=ecdsa_secp256r1_sha256_p1363_test.json

[ -d "$src/jwk_duo" ] || { echo "copy_conformance: missing source dir $src/jwk_duo" >&2; exit 1; }
[ -f "$src/wycheproof/$wyche" ] || { echo "copy_conformance: missing $src/wycheproof/$wyche" >&2; exit 1; }

rm -rf "$dst"
mkdir -p "$dst/jwk_duo" "$dst/wycheproof"
cp "$src"/jwk_duo/*.json "$dst/jwk_duo/"
cp "$src/wycheproof/$wyche" "$dst/wycheproof/"

n=$(find "$dst" -name '*.json' | wc -l | tr -d ' ')
[ "$n" -ge 11 ] || { echo "copy_conformance: only $n files copied, expected >= 11" >&2; exit 1; }
echo "copy_conformance: copied $n files into $dst"
