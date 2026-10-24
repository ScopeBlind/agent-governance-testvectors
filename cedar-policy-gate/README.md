# Cedar policy gate conformance vectors

The security conformance bar for a Cedar policy gate, encoded as six
engine-agnostic test cases. It came out of a real disclosure: a Cedar policy gate
must DENY (fail closed) when policy evaluation is uncertain, and must never let
the Cedar `in`-on-String type error silently discard a `forbid` rule into a
permit-all.

Every case is decision-only. No signing, no keys, no crypto. Any implementation
that can evaluate a Cedar policy against a tool call and return ALLOW or DENY can
run these. That keeps the bar portable across implementations.

## Invocation contract

Each `input.json` carries an `input` object. Its fields bind at the top level of
the Cedar request `context`: input `{"command":"rm"}` means the policy sees
`context.command == "rm"`. An implementation that nests tool input under a
different key (for example `context.input.command`) must remap it to match, or
the policies here will reference a missing attribute. Referencing a missing
context attribute is itself a Cedar evaluation error, which a conformant gate
must treat as a deny, not an allow.

No Cedar schema is assumed. The bar is "evaluate the policy as written, and deny
on any per-policy evaluation error," so an engine-agnostic implementation must
surface per-policy diagnostics (the equivalent of Cedar's `Response.diagnostics`
errors) rather than only reading the final allow/deny bit.

## The bar

A gate is conformant if and only if it produces the required decision for all six
cases below.

| # | Case | Required decision | Proves |
|---|------|-------------------|--------|
| 1 | [`1-in-on-string-rejection/`](./1-in-on-string-rejection/) | DENY (or policy-load rejection) | The discarded-forbid advisory vector does not open the gate. |
| 2 | [`2-errored-policy-no-permit/`](./2-errored-policy-no-permit/) | DENY | A per-policy error does not let a residual permit stand. |
| 3 | [`3-fail-closed-engine-unavailable/`](./3-fail-closed-engine-unavailable/) | DENY | An unavailable or throwing engine denies, never defaults to allow. |
| 4 | [`4-valid-forbid-denies/`](./4-valid-forbid-denies/) | DENY (for the right reason) | A correctly written forbid actually denies (positive control). |
| 5 | [`5-valid-permit-allows/`](./5-valid-permit-allows/) | ALLOW | A safe action is allowed (liveness control; not deny-all). |
| 6 | [`6-self-test-required/`](./6-self-test-required/) | self-test passes and gates enforcement | The gate proves its own restraint before arming. |

- Cases 1 to 3 prove the gate fails closed: it denies when evaluation is
  uncertain, when a policy errors, and when the engine cannot decide.
- Cases 4 and 5 are positive controls. Without them a gate could pass cases 1 to 3
  by denying everything. Case 4 denies a real dangerous action (the rule actually
  matched, not an error path); case 5 allows a real safe action. Together they
  prove the gate is making genuine value-dependent decisions, not a degenerate
  deny-all.
- "For the right reason" in case 4 is a claim about the deny CATEGORY (a clean
  rule-match, not a deny-on-error). The mechanical runner checks only the coarse
  ALLOW/DENY decision, since a clean deny and a deny-on-error both exit 2. The
  category is verified by inspecting the implementation's emitted `reason` field
  (the reference impl prints `cedar_deny` with an empty policy-error list) or its
  unit tests. The runner echoes the reason line when the impl prints one.
- Case 6 proves self-attestation: the gate runs a boot self-test that denies a
  known-forbidden vector (including the `in`-on-String discard) and refuses to arm
  enforcement if it cannot.

## Why this exists (the disclosure)

Cedar treats `in` as entity-hierarchy membership, not string-set membership.
Applying `context.<attr> in [stringList]` therefore type-errors. Cedar does not
abort: it silently discards the erroring policy and continues. If that policy was
your only `forbid`, the surviving terminal `permit` fires and the gate allows
what it was meant to block.

- wshobson/agents issue #598 (reporter matiaszabal): the Cedar `in`-on-String
  type error silently discards all forbid rules, and the terminal permit fires.
- wshobson/agents issue #601: the `evaluate` and `sign` verbs did not exist in the
  pinned version, so hook configs that invoked them were not actually gating.
- Upstream Cedar behavior: cedar-policy/cedar#2428.

The correct idiom is `["a","b"].contains(context.<attr>)`, which is set membership
on a set literal and is well typed. Cases 4 and 5 use it; cases 1 and 2 use the
hazardous `in` form to prove the gate does not get fooled by it.

## Reference implementation

protect-mcp 0.7.0 is the reference implementation and passes all six cases.

- The fail-closed chokepoint, the per-policy-error detection, and the corrected
  Cedar PolicySet call shape live in
  `protect-mcp/src/cedar-evaluator.ts` (`onEvalError`, `extractPolicyErrors`,
  `parseWasmResult`, `evaluateCedar`).
- The one-shot `evaluate` verb (exit 2 = deny, exit 0 = allow; missing policy
  denies unless `--fail-on-missing-policy false`) lives in
  `protect-mcp/src/cli.ts` (`handleEvaluate`).
- The boot self-test (`runEvaluatorSelfTest`) gates `serve --enforce` and is
  reported by `doctor`.
- A CI tripwire (`policy-lint.test.ts`) fails the build if the discarded
  `in`-on-String pattern is reintroduced into a shipped policy.

See the protect-mcp 0.7.0 CHANGELOG for the full security-release notes.

## Running the suite

```sh
# Drive the mechanically-checkable cases (1, 2, 4, 5) against protect-mcp 0.7.0:
./run.sh "npx protect-mcp@0.7.0"

# Cases 3 and 6 are checked by hand:
#   3 by removing or disabling the engine (see 3-fail-closed-engine-unavailable/README.md)
#   6 via the self-test / doctor command (see 6-self-test-required/README.md)
```

`run.sh` reads each case's `input.json`, runs the implementation, and asserts the
returned decision matches `expected-output.json`. See the script for the
reference invocation contract (a command that exits 2 on deny and 0 on allow).

## Other implementations: prove conformance

This bar is engine-agnostic on purpose. If you ship an agent policy gate, run
these six cases and show your gate denies cases 1 to 3, denies case 4 for the
right reason, allows case 5, and self-attests in case 6. Implementations invited
to demonstrate conformance:

- sb-runtime (Rust)
- protect-mcp-adk (Python)
- aps-governance-hook (Python)

To prove conformance, run `./run.sh "<your-evaluate-command>"` and show your gate
denies cases 1 and 2, allows case 5, and denies case 4, plus check cases 3 and 6
by hand per their READMEs. This family is self-contained: it needs no driver under
the repo's top-level `implementations/` directory (those belong to the
signed-receipt chain suite, not to this decision-only family). If you want to
record your result, open a PR adding a short note here with your command and its
`run.sh` output. If your gate diverges on any case, either it or the expected
output has a bug. Almost always it is the gate, and that is the point of the bar.

## Files

```
cedar-policy-gate/
├── README.md                          this file (the bar)
├── run.sh                             drives cases 1, 2, 4, 5 by decision
├── 1-in-on-string-rejection/          fail-closed: discarded forbid denies
├── 2-errored-policy-no-permit/        fail-closed: errored policy denies
├── 3-fail-closed-engine-unavailable/  fail-closed: dead engine denies (by hand)
├── 4-valid-forbid-denies/             positive control: real forbid denies
├── 5-valid-permit-allows/             liveness control: safe action allows
└── 6-self-test-required/              self-attestation gates enforcement (by hand)
```

Each case directory has `input.json`, `expected-output.json`, and `README.md`.

## Standards

- Cedar (AWS) for policy evaluation.
- The conformance contract here is decision-only and does not depend on the
  signed-receipt wire format used by the rest of this repo, so a gate can prove
  policy soundness independently of how it records decisions.
