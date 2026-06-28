#!/usr/bin/env bash
#
# Cedar policy gate conformance runner.
#
# Drives the mechanically-checkable cases (1, 2, 4, 5) against an implementation
# command, feeding each case's input.json and asserting the returned DECISION
# (ALLOW or DENY) matches expected-output.json.
#
# Cases 3 and 6 are NOT driven here: they require manipulating engine
# availability and the boot self-test respectively, which are implementation
# specific. See:
#   3-fail-closed-engine-unavailable/README.md  (remove or disable the engine)
#   6-self-test-required/README.md              (doctor / self-test command)
#
# Usage:
#   ./run.sh "<impl-command>"
#
# The implementation command must expose an `evaluate` verb with this contract:
#   <impl-command> evaluate --policy <file> --tool <tool> --input <json>
#   exit 2 = DENY, exit 0 = ALLOW
#
# Invocation contract (so this is engine-agnostic, not protect-mcp specific):
#   Each input.json carries an `input` object. Its fields are bound at the TOP
#   level of the Cedar request `context`. So input {"command":"rm"} means the
#   policy sees `context.command == "rm"`. An implementation that nests the
#   input under some other key (e.g. context.input.command) must remap it, or
#   the policies here will reference a missing attribute (itself an evaluation
#   error, which a conformant gate must treat as a deny, not an allow).
#
# This runner checks the DECISION only (the coarse ALLOW/DENY outcome). It does
# not assert WHY a gate denied: a clean rule-match deny and a deny-on-error both
# exit 2. "Deny for the right reason" (case 4) is verified by inspecting the
# emitted reason field or the reference implementation's unit tests, not here.
# Where the implementation prints a JSON line with a `reason`, this runner echoes
# it for human inspection.
#
# Reference invocation (protect-mcp 0.7.0):
#   ./run.sh "npx protect-mcp@0.7.0"
#
# Requires: jq.

set -u

IMPL="${1:-npx protect-mcp@0.7.0}"
HERE="$(cd "$(dirname "$0")" && pwd)"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is required" >&2
  exit 3
fi

# Evaluate one case and print its decision word to stdout (ALLOW / DENY /
# POLICY_LOAD_REJECTED). Also echoes the impl's reason line to stderr when the
# impl prints JSON with a `.reason`, for human inspection only.
decide() {
  local case="$1"
  local dir="$HERE/$case"
  local input="$dir/input.json"
  local policy_file="$TMPDIR/$case.cedar"
  local tool input_json out code reason

  tool="$(jq -r '.tool' "$input")"
  jq -r '.policy' "$input" > "$policy_file"
  input_json="$(jq -c '.input' "$input")"

  # shellcheck disable=SC2086
  out="$($IMPL evaluate --policy "$policy_file" --tool "$tool" --input "$input_json" 2>/dev/null)"
  code=$?

  reason="$(printf '%s' "$out" | jq -r '.reason // empty' 2>/dev/null)"
  [ -n "$reason" ] && echo "    reason: $reason" >&2

  case "$code" in
    0) echo "ALLOW" ;;
    2) echo "DENY" ;;
    *) echo "POLICY_LOAD_REJECTED" ;;
  esac
}

# Liveness precondition. Case 5 (a safe action under a valid policy) must ALLOW.
# This proves the implementation is actually deciding, not uniformly erroring or
# crashing. Only after this do we honor the POLICY_LOAD_REJECTED tolerance on the
# deny cases: a crash-on-everything gate fails here and cannot bank cases 1 and 2.
echo "liveness: 5-valid-permit-allows must ALLOW"
live="$(decide 5-valid-permit-allows)"
if [ "$live" != "ALLOW" ]; then
  echo "FAIL  implementation is not live: case 5 must ALLOW, got $live" >&2
  echo "      a conformant gate makes value-dependent decisions; aborting." >&2
  exit 1
fi
echo "PASS  5-valid-permit-allows  (ALLOW)"
echo

CASES="1-in-on-string-rejection 2-errored-policy-no-permit 4-valid-forbid-denies"

pass=1   # case 5 already passed above
fail=0

for case in $CASES; do
  dir="$HERE/$case"
  expected_file="$dir/expected-output.json"

  if [ ! -f "$dir/input.json" ] || [ ! -f "$expected_file" ]; then
    echo "SKIP  $case (missing input.json or expected-output.json)"
    continue
  fi

  expected="$(jq -r '.decision' "$expected_file")"
  actual="$(decide "$case")"

  # An implementation conforms if its decision is in the case's acceptable set.
  # POLICY_LOAD_REJECTED is acceptable on the deny cases ONLY because the
  # liveness precondition above already proved the impl is not uniformly erroring.
  ok=0
  while IFS= read -r acceptable; do
    if [ "$actual" = "$acceptable" ]; then ok=1; fi
  done < <(jq -r '.acceptable_decisions[]?' "$expected_file")
  if [ "$ok" = "0" ] && [ "$actual" = "$expected" ]; then ok=1; fi

  if [ "$ok" = "1" ]; then
    echo "PASS  $case  (expected $expected, got $actual)"
    pass=$((pass + 1))
  else
    echo "FAIL  $case  (expected $expected, got $actual)"
    fail=$((fail + 1))
  fi
done

echo
echo "cedar-policy-gate: $pass passed, $fail failed (cases 3 and 6 checked by hand)"
[ "$fail" -eq 0 ]
