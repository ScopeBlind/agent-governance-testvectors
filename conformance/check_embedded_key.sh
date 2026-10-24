#!/usr/bin/env bash
# check_embedded_key.sh - a receipt's own key must never be trusted.
#
# Issue #21, section 9.5 of draft-farley-acta-signed-receipts-03. Carrying a
# key inside a receipt is permitted; the Acta envelope may name its key and the
# reference receipts carry one inside the signed bytes. Trusting it is what is
# forbidden, because a signature that verifies under a key the signer supplied
# establishes only that one party wrote both.
#
# The vectors under negative/embedded-key/ are schema-valid receipts whose
# signatures verify perfectly under the key they carry. Three cases per vector:
#
#   no --key            must be undecidable, error code embedded_key_rejected.
#                       NOT merely a non-zero exit: exit 2 is the whole
#                       undecidable class, and "unknown shape" or "malformed"
#                       would also land there while testing nothing about 9.5.
#
#   --key <bystander>   must be exit 1. A valid key that did not sign is a
#                       check that RAN and FAILED. Without this case a verifier
#                       could pass the whole suite by refusing everything.
#
#   SIMULATE=1          hand the receipt its OWN embedded key. It must verify,
#                       exit 0. That is the behaviour 9.5 forbids, reproduced
#                       deliberately, and it is the only thing proving this
#                       gate can fire at all. In that mode the script exits 1,
#                       because an accepted self-keyed receipt is the failure.
#
# Usage:
#   ./conformance/check_embedded_key.sh
#   SIMULATE_EMBEDDED_KEY_RESOLUTION=1 ./conformance/check_embedded_key.sh
#   VERIFY_PKG=@veritasacta/verify@0.10.20 ./conformance/check_embedded_key.sh   (pin a verifier)
#
# Exit: 0 all vectors behaved, 1 a vector was trusted or a case failed,
#       2 nothing could be measured.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VECTOR_DIR="$REPO_ROOT/negative/embedded-key"

command -v npx >/dev/null 2>&1 || { echo "error: 'npx' required"; exit 2; }
[ -d "$VECTOR_DIR" ] || { echo "error: $VECTOR_DIR does not exist"; exit 2; }

# A valid Ed25519 key that signed nothing here. Seed 00..02; see KEYS.md.
BYSTANDER_KEY="7422b9887598068e32c4448a949adb290d0f4e35b9e01b0ee5f1a1e600fe2674"

SIMULATE="${SIMULATE_EMBEDDED_KEY_RESOLUTION:-0}"

# Sets CODE (the verifier's --json error code) and RC (its exit status).
#
# Deliberately NOT a function called in a command substitution. That form runs
# in a subshell, so the exit status is assigned in the child and never reaches
# the caller: the status this entire check turns on would be silently dropped,
# which is the defect class this suite is about. Globals are uglier and they
# survive.
#
# Output is captured rather than discarded. An earlier version of this script
# redirected it to /dev/null and then reported the verifier as silent. It was
# not silent; the codes were there the whole time in --json.
verify_receipt() {
    VOUT="$(npx --yes "${VERIFY_PKG:-@veritasacta/verify}" "$@" --json 2>/dev/null)"
    RC=$?
    case "$VOUT" in
        *"npm ERR"*|*"npm error"*|*"could not determine executable"*)
            echo "ERROR: npx could not run @veritasacta/verify"
            printf '  %s\n' "$(printf '%s' "$VOUT" | head -1)"
            echo "Nothing was measured, so there is no result to report."
            exit 2 ;;
    esac
    CODE="$(printf '%s' "$VOUT" | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("error") or "")
except Exception: print("__UNPARSEABLE__")')"
}

PASSED=0
FAILED=0
CHECKED=0
ok()   { echo "  ok    $1"; PASSED=$((PASSED+1)); }
bad()  { echo "  FAIL  $1"; FAILED=$((FAILED+1)); }

if [ "$SIMULATE" = "1" ]; then
    echo "!! SIMULATE_EMBEDDED_KEY_RESOLUTION=1"
    echo "!! Each receipt is handed its own embedded key, which is what a"
    echo "!! verifier that resolved keys from receipts would do to itself."
    echo "!! Every vector must verify and this script must exit 1."
    echo ""
fi

for f in "$VECTOR_DIR"/*.json; do
    [ -e "$f" ] || continue
    CHECKED=$((CHECKED+1))
    name="$(basename "$f")"
    echo "$name"

    if [ "$SIMULATE" = "1" ]; then
        EK="$(python3 "$VECTOR_DIR/extract_key.py" "$f")" || EK=""
        if [ -z "$EK" ]; then
            bad "no extractable key, so it cannot test a rule about embedded keys"
            continue
        fi
        verify_receipt --key "$EK" "$f"
        if [ "$RC" -eq 0 ]; then
            ok "verifies under its own embedded key, so the gate can fire"
        else
            bad "did not verify under its own key (exit $RC, code '${CODE:-none}'): either this receipt is not self-certifying or the check is unreachable"
        fi
        continue
    fi

    # Case 1: no key. Undecidable, and named.
    verify_receipt "$f"
    if [ "$CODE" = "embedded_key_rejected" ]; then
        ok "no --key: embedded_key_rejected (exit $RC)"
    else
        bad "no --key: expected embedded_key_rejected, got '${CODE:-none}' (exit $RC)"
    fi

    # Case 2: a valid key that did not sign it. A check that ran and failed.
    verify_receipt --key "$BYSTANDER_KEY" "$f"
    if [ "$RC" -eq 1 ]; then
        ok "--key bystander: exit 1, the signature check ran and failed"
    else
        bad "--key bystander: expected exit 1, got exit $RC (code '${CODE:-none}')"
    fi
done

echo ""
if [ "$CHECKED" -eq 0 ]; then
    echo "ERROR: no vectors found in $VECTOR_DIR"
    exit 2
fi

echo "$CHECKED vector(s), $PASSED check(s) passed, $FAILED failed"

if [ "$SIMULATE" = "1" ]; then
    if [ "$FAILED" -gt 0 ]; then
        echo "FAIL: the mutation test did not reproduce the forbidden behaviour,"
        echo "      so a passing normal run proves nothing."
        exit 1
    fi
    echo "FAIL (expected): every vector was accepted under the key it carries."
    echo "      That is the behaviour section 9.5 forbids. The gate fires."
    exit 1
fi

[ "$FAILED" -eq 0 ] || exit 1
echo "PASS: no vector was trusted under its own key, and a wrong key still fails."
