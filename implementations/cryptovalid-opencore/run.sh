#!/usr/bin/env bash
# cryptovalid-opencore driver for ScopeBlind/agent-governance-testvectors.
# Reads fixtures from ../../fixtures/, evaluates each input against fixtures/policy/*.cedar with the OFFICIAL Cedar
# bindings (cedarpy, the cedar-policy Rust crate — never the fixtures' expected_decision), and writes one Acta 2.1
# envelope receipt per input to ../../receipts/cryptovalid-opencore/, chained per draft-farley-acta-signed-receipts-03 §6.7,
# policy_digest per §6.8, signed with the fixture seed (fixtures/keys/README.md). Exit 77 = cannot run here.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT="$REPO_ROOT/receipts/cryptovalid-opencore"
rm -rf "$OUT" && mkdir -p "$OUT"
command -v python3 >/dev/null 2>&1 || { echo "skip: python3 required"; exit 77; }
VENV="${CRYPTOVALID_VENV:-$SCRIPT_DIR/.venv}"
if [ ! -x "$VENV/bin/python" ]; then
    python3 -m venv "$VENV" || { echo "skip: cannot create a venv"; exit 77; }
    "$VENV/bin/pip" install -q --extra-index-url https://robertolocatelli81-dev.github.io/pypi/ "cryptovalid-opencore>=0.15.0" cedarpy cryptography \
        || { echo "skip: cannot install cryptovalid-opencore / cedarpy / cryptography"; exit 77; }
fi
"$VENV/bin/python" -c "import cedarpy, cryptovalid_acta" 2>/dev/null || { echo "skip: cedarpy or cryptovalid_acta not importable"; exit 77; }
echo "cryptovalid-opencore: $("$VENV/bin/python" -c 'import importlib.metadata as m; print(m.version("cryptovalid-opencore"))') on $("$VENV/bin/python" --version), cedarpy $("$VENV/bin/python" -c 'import importlib.metadata as m; print(m.version("cedarpy"))')"
SEED="0000000000000000000000000000000000000000000000000000000000000001"
"$VENV/bin/python" -m cryptovalid_acta run-vectors "$REPO_ROOT" "$OUT" --seed "$SEED" || exit 1
ls "$OUT"/receipt-*.json | wc -l | xargs -I{} echo "cryptovalid-opencore: {} receipts in $OUT"
