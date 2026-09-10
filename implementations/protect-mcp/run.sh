#!/usr/bin/env bash
# Reference driver: protect-mcp (TypeScript / npm).
# Reads fixtures from ../../fixtures/, writes receipts to ../../receipts/protect-mcp/.
#
# The policy is evaluated by protect-mcp itself: `sign --cedar` loads
# fixtures/policy, evaluates the call with the tool name as the Cedar action,
# and signs the resulting decision and policy digest. Needs protect-mcp 0.13.0
# or later; earlier releases sign a default allow and ignore --cedar.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FIXTURES="$REPO_ROOT/fixtures"
OUT="$REPO_ROOT/receipts/protect-mcp"
rm -rf "$OUT" && mkdir -p "$OUT"

command -v npx >/dev/null 2>&1 || { echo "skip: npx not found"; exit 77; }
command -v node >/dev/null 2>&1 || { echo "skip: node not found"; exit 77; }

PMCP="${PROTECT_MCP_CMD:-npx --yes protect-mcp@latest}"

# Deterministic test keypair: fixtures/keys/README.md documents the seed.
# protect-mcp accepts --key as a JSON file carrying the 32-byte seed.
SEED="0000000000000000000000000000000000000000000000000000000000000001"
KEY="$OUT/.key.json"
node -e '
const c = require("node:crypto");
const seed = process.argv[1];
const priv = c.createPrivateKey({
  key: Buffer.from("302e020100300506032b657004220420" + seed, "hex"),
  format: "der", type: "pkcs8",
});
const pub = Buffer.from(c.createPublicKey(priv).export({format:"der",type:"spki"}).slice(-32)).toString("hex");
require("node:fs").writeFileSync(process.argv[2], JSON.stringify({
  privateKey: seed, publicKey: pub, kid: "conformance",
}, null, 2));
' "$SEED" "$KEY"

# Say which gate and runtime produced these receipts, so a CI log explains itself.
echo "protect-mcp: $($PMCP --version 2>/dev/null </dev/null | head -n 1 || echo 'version unknown') on node $(node --version)"

WORK="$OUT/.work"
rm -rf "$WORK" && mkdir -p "$WORK"
signed_count=0
for input_file in "$FIXTURES/inputs"/*.json; do
    name="$(basename "$input_file" .json)"
    tool_name="$(node -p "JSON.parse(require('fs').readFileSync('$input_file','utf8')).tool_name")"
    tool_input="$(node -p "JSON.stringify(JSON.parse(require('fs').readFileSync('$input_file','utf8')).tool_input)")"
    context="$(node -p "JSON.stringify(JSON.parse(require('fs').readFileSync('$input_file','utf8')).context || {})")"
    # sign --cedar evaluates the fixture policy and signs the real decision with
    # the policy digest (protect-mcp 0.13.0+). --action-model tool: the policy
    # models the tool name as the Cedar action. stdin is /dev/null: sign reads a
# hook payload from stdin whenever stdin is a pipe, and under CI or a harness
# an inherited pipe never closes.
    # The evaluator's own verdict, with the matched policy ids and any errors,
    # so a wrong decision in CI is diagnosable from the log.
    verdict="$($PMCP evaluate --cedar "$FIXTURES/policy" --action-model tool --tool "$tool_name" \
        --input "$tool_input" --context "$context" --json </dev/null 2>&1 | tr -d '\n' | cut -c1-400)"
    echo "protect-mcp: $name evaluate -> $verdict"
    # A fail-closed deny because the policy engine could not load is not a
    # policy decision. Refuse to sign receipts that would record it as one.
    case "$verdict" in *cedar_wasm_not_available*|*policy_error*)
        echo "protect-mcp: the gate could not evaluate the policy on this runtime ($verdict);" >&2
        echo "  receipts signed now would record an engine outage as a policy deny. Failing instead." >&2
        rm -rf "$WORK"; rm -f "$KEY"; exit 1;;
    esac
    result="$($PMCP sign --cedar "$FIXTURES/policy" --action-model tool --tool "$tool_name" \
        --input "$tool_input" --context "$context" --receipts "$WORK" --key "$KEY" </dev/null 2>/dev/null)"
    line="$(tail -n 1 "$WORK/receipts.jsonl" 2>/dev/null || true)"
    if [ -n "$line" ] && node -e '
        const r = JSON.parse(process.argv[1]);
        process.exit(r.signature && r.signature.sig ? 0 : 1);
      ' "$line" 2>/dev/null; then
        printf '%s\n' "$line" > "$OUT/$name.json"
        signed_count=$((signed_count + 1))
    else
        echo "protect-mcp: $name produced no signed receipt: ${result:-<no output>}" >&2
    fi
done
rm -rf "$WORK"
rm -f "$KEY"

total="$(ls "$FIXTURES/inputs"/*.json 2>/dev/null | wc -l | tr -d ' ')"
echo "protect-mcp: $signed_count/$total signed receipts in $OUT"
if [ "$signed_count" -eq 0 ]; then
    echo "protect-mcp: no receipts were signed; the sign verb needs a version that" >&2
    echo "  resolves a signer and accepts --cedar (0.13.0 does)." >&2
    exit 1
fi
exit 0
