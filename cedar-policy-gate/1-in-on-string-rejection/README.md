# Case 1 - in-on-String rejection (the core advisory vector)

## What this proves

A Cedar policy gate must not let a type-erroring `forbid` rule be silently
discarded into a permit-all. The policy here intends to block dangerous shell
commands:

```cedar
forbid(principal, action, resource) when { context.command in ["rm", "dd", "mkfs"] };
permit(principal, action, resource);
```

The forbid rule uses `context.command in [...]`. In Cedar, `in` is the
entity-hierarchy membership operator (for example `principal in Group::"admins"`
or `action in [Action::"read"]`), not string-set membership. Applied to a String
operand it is a type error. Cedar discards the erroring policy and continues
evaluation, so the only surviving rule is the terminal `permit`. The tool call
`rm` is then ALLOWED.

## Required decision

DENY (or policy-load rejection). A conformant gate either:

1. rejects this policy at load time (the `context.<attr> in [strings]` hazard is
   detectable statically, which is what the protect-mcp CI tripwire in
   `policy-lint.test.ts` enforces against shipped policies), or
2. detects the per-policy evaluation error at runtime and denies (fail closed).

protect-mcp 0.7.0 takes path 2 at evaluate time: `extractPolicyErrors()` finds
the discarded policy, and the single `onEvalError()` chokepoint maps any
per-policy error to DENY under enforcement. See
`packages/protect-mcp/src/cedar-evaluator.ts`.

## The precise failure mode a non-conformant gate exhibits

It returns ALLOW for `rm`. The erroring forbid vanishes, the residual permit
fires, and the gate reports success with no error surfaced to the caller. The
operator believes `rm`, `dd`, and `mkfs` are blocked; they are not.

## Reference invocation

```sh
printf '%s' "$(jq -r .policy input.json)" > /tmp/case1.cedar
npx protect-mcp@0.7.0 evaluate \
  --policy /tmp/case1.cedar \
  --tool Bash \
  --input "$(jq -c .input input.json)"
# exit 2 = DENY (conformant). exit 0 = ALLOW (non-conformant: the advisory vector fired).
```

## Disclosure links

- wshobson/agents issue #598 (reporter matiaszabal): Cedar `in`-on-String
  silently discards all forbid rules; the terminal permit fires.
- Upstream Cedar behavior: cedar-policy/cedar#2428.
- protect-mcp 0.7.0 is the reference conformant implementation.
