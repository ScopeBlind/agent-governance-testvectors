# Case 3 - fail closed when the engine is unavailable

## What this proves

When the policy engine cannot produce a decision (it is not installed, it is
unreachable, or evaluation throws), the gate must DENY. It must never fall back to
ALLOW just because it could not run the policy.

The policy in this case is a deliberately permissive `permit(principal, action,
resource);`. With a working engine it would ALLOW. The test condition is the
engine being unavailable, so the required outcome flips to DENY. This is exactly
the property a naive gate gets wrong: it treats "could not evaluate" as "no
applicable forbid" and permits.

## Required decision

DENY. protect-mcp 0.7.0 returns DENY via the `onEvalError()` chokepoint when
`ensureCedarWasm()` resolves false (`cedar_wasm_not_available`) or when the
`isAuthorized` call throws (`cedar_eval_error`). See
`packages/protect-mcp/src/cedar-evaluator.ts`. Before 0.7.0 this path returned
ALLOW; the 0.7.0 security release inverts it (see the package CHANGELOG).

## How an implementation simulates engine-unavailable

Pick whichever is cleanest for the implementation under test:

- Run `evaluate` in an environment where the Cedar engine dependency is not
  installed. For protect-mcp this means the optional `@cedar-policy/cedar-wasm`
  module is absent, so `ensureCedarWasm()` returns false and the gate denies.
- Point the gate at an engine endpoint that is down, or inject a fault that makes
  the engine call throw.
- Use the implementation's own self-test path: protect-mcp's
  `runEvaluatorSelfTest()` includes an "engine unavailable denies" case that runs
  even when the engine is absent, asserting DENY.

## The precise failure mode a non-conformant gate exhibits

It returns ALLOW because no `forbid` rule was evaluated (none could be), so it
concludes nothing forbids the action. A request that should have been blocked
proceeds with no policy actually applied.

## Why this case is not driven by run.sh

`run.sh` drives the mechanically-checkable cases (1, 2, 4, 5) that depend only on
policy text and input. Case 3 requires manipulating the engine availability of
the implementation under test, which is implementation-specific, so it is
verified by hand per the simulation notes above.

## Disclosure links

- The fail-open default is the same class of defect documented for the 0.5.x and
  0.6.x lines in the protect-mcp CHANGELOG (0.7.0 security release).
- protect-mcp 0.7.0 is the reference conformant implementation.
