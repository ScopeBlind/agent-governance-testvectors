# Case 6 - self-test required before arming

## What this proves

A conformant gate proves its own restraint before it enforces. It runs a boot
self-test that puts known deny/allow vectors through its real evaluator, and it
refuses to arm enforcement if that self-test does not pass. A gate that cannot
demonstrate it denies a known-forbidden vector must not start.

## The required vectors

The self-test must, at minimum, prove all four (see `input.json`):

1. engine-unavailable denies (runs even with no engine present),
2. a valid forbid denies the forbidden command,
3. a valid permit allows a safe command,
4. the `in`-on-String forbid does NOT permit-all (the advisory regression).

Vector 4 is the load-bearing one: it puts the exact discarded-forbid pattern from
case 1 through the live evaluator and asserts DENY, so a regression that
reintroduces fail-open is caught at boot rather than in production.

## Required outcome

- The implementation exposes a self-test that returns `passed = true` when every
  vector matches its expected decision.
- The enforcing entrypoint refuses to start when the self-test returns false.

## Mapping to protect-mcp 0.7.0

- `runEvaluatorSelfTest()` in `packages/protect-mcp/src/cedar-evaluator.ts` runs
  the four vectors live and returns `{ passed, cases }`.
- `protect-mcp serve --enforce` calls it before arming the gate and exits
  non-zero ("Refusing to arm the gate") if `passed` is false. See
  `packages/protect-mcp/src/cli.ts`.
- `protect-mcp doctor` runs the same self-test and reports each case, so an
  operator can confirm restraint without starting the server.

## How to check this case

```sh
# Doctor reports the self-test cases (human-readable).
npx protect-mcp@0.7.0 doctor

# Arming an enforcing gate runs the self-test first and refuses to start on failure.
npx protect-mcp@0.7.0 serve --enforce --cedar ./policies
# If the self-test fails, the process exits non-zero before the gate is armed.
```

An implementation under test proves conformance by exposing an equivalent
self-test command (returning a pass/fail result over the four vectors) and by
making its enforcing entrypoint refuse to start on failure.

## The precise failure mode a non-conformant gate exhibits

It arms enforcement without ever checking that it can deny. A fail-open
regression (the engine silently discarding a forbid, or not evaluating the policy
at all) then ships undetected, because nothing proved the gate's restraint before
it went live.

## Disclosure links

- wshobson/agents issue #598 (the discarded-forbid vector this self-test guards
  against) and issue #601 (the evaluate/sign verbs missing from the pinned
  version, which the self-test and the new verbs together close).
- Upstream Cedar behavior: cedar-policy/cedar#2428.
- protect-mcp 0.7.0 is the reference conformant implementation.
