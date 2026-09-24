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
    # Immutable install (review of #25): the package from a pinned commit with --no-deps, its two dependencies from
    # PyPI at pinned versions. No extra index — with one, pip would take whichever index offers the highest version of
    # ANY of these names, so a later run of this oracle could execute whatever that index served at the time.
    CV_COMMIT="4a92a54e1847a376d5879f3c4dbc1ac6c3de2fb2"
    "$VENV/bin/pip" install -q --no-deps "cryptovalid-opencore @ git+https://github.com/robertolocatelli81-dev/cryptovalid-opencore@${CV_COMMIT}" \
        || { echo "skip: cannot install cryptovalid-opencore at ${CV_COMMIT}"; exit 77; }
    "$VENV/bin/pip" install -q "cedarpy==4.12.0" "cryptography==50.0.1" \
        || { echo "skip: cannot install cedarpy / cryptography"; exit 77; }
fi
"$VENV/bin/python" -c "import cedarpy, cryptovalid_acta" 2>/dev/null || { echo "skip: cedarpy or cryptovalid_acta not importable"; exit 77; }
echo "cryptovalid-opencore: $("$VENV/bin/python" -c 'import importlib.metadata as m; print(m.version("cryptovalid-opencore"))') on $("$VENV/bin/python" --version), cedarpy $("$VENV/bin/python" -c 'import importlib.metadata as m; print(m.version("cedarpy"))')"
SEED="0000000000000000000000000000000000000000000000000000000000000001"
"$VENV/bin/python" -m cryptovalid_acta run-vectors "$REPO_ROOT" "$OUT" --seed "$SEED" || exit 1
ls "$OUT"/receipt-*.json | wc -l | xargs -I{} echo "cryptovalid-opencore: {} receipts in $OUT"
