# Case 2 - errored policy must not let a residual permit stand

## What this proves

A per-policy evaluation error poisons the entire decision. Even when a separate,
correctly typed `permit` exists and matches the input, a gate must not return
that permit while another policy in the set errored.

```cedar
forbid(principal, action, resource) when { context.command in ["rm"] };
permit(principal, action, resource) when { context.command == "rm" };
```

The forbid errors (the `in`-on-String type error) and is discarded. The permit is
valid and matches `rm`. A naive engine reports ALLOW because, after the forbid is
dropped, the permit is the matching rule.

## Required decision

DENY under enforcement. The decision is unsound because one of the policies could
not be evaluated. protect-mcp 0.7.0 denies whenever `extractPolicyErrors()`
returns a non-empty list, regardless of what the surviving rules decide. See the
per-policy-error branch in `evaluateCedar()` in
`packages/protect-mcp/src/cedar-evaluator.ts`.

Note that this is stricter than raw Cedar authorization. Under vanilla Cedar
semantics this request ALLOWs: the errored forbid is dropped and the valid permit
matches. The conformance requirement here is therefore "Cedar evaluation PLUS a
mandatory deny on any per-policy error." An engine-agnostic implementation must
expose per-policy diagnostics (the equivalent of Cedar's `Response.diagnostics`
errors) to detect the discarded forbid. A gate that reads only the final
allow/deny bit from a diagnostics-blind `isAuthorized()` wrapper will return ALLOW
and fail this case, which is exactly the hazard the bar exists to catch.

## How this differs from case 1

Case 1 has a bare terminal permit (permit-all) and proves the discarded forbid
opens the gate. Case 2 has a permit that genuinely matches the input, proving the
rule is the same even when the residual permit is not a degenerate permit-all: an
errored sibling policy still forces a deny.

## The precise failure mode a non-conformant gate exhibits

It returns ALLOW because it evaluates only the rules that did not error and finds
the matching permit, never surfacing that a sibling forbid was silently dropped.

## Reference invocation

```sh
printf '%s' "$(jq -r .policy input.json)" > /tmp/case2.cedar
npx protect-mcp@0.7.0 evaluate \
  --policy /tmp/case2.cedar \
  --tool Bash \
  --input "$(jq -c .input input.json)"
# exit 2 = DENY (conformant). exit 0 = ALLOW (non-conformant).
```

## Disclosure links

- wshobson/agents issue #598: discarded forbid rules from the `in`-on-String
  type error.
- Upstream Cedar behavior: cedar-policy/cedar#2428.
- protect-mcp 0.7.0 is the reference conformant implementation.
