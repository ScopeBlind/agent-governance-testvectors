# Case 4 - valid forbid denies (positive control)

## What this proves

A correctly written `forbid` actually denies the forbidden action, and does so
because the rule matched, not because a policy errored. This is a positive
control: it stops a gate from passing the suite by simply denying everything that
involves an error.

```cedar
forbid(principal, action, resource) when { ["rm", "dd", "mkfs"].contains(context.command) };
permit(principal, action, resource);
```

This uses the correct Cedar idiom: `[set].contains(operand)` is set membership on
a set literal and is well typed when the operand is a String. It is the
recommended replacement for the hazardous `context.<attr> in [strings]` form. The
forbid matches `command == "rm"` and denies cleanly. No per-policy error is
raised.

## Required decision

DENY for the right reason. The rule matched and produced an authoritative deny.
protect-mcp 0.7.0 returns a `cedar_deny` decision with an empty policy-error list,
which is distinct from the deny-on-error path exercised by cases 1 and 2.

The mechanical runner (`run.sh`) only checks the coarse decision: a clean
rule-match deny and a deny-on-error both exit 2, so the exit code alone cannot
tell them apart. The "right reason" is verified by reading the implementation's
emitted `reason` field (here, `cedar_deny` with no policy errors) or its unit
tests. The point of this case in the suite is the value-dependent pairing with
case 5: the same valid policy must DENY `rm` here and ALLOW `ls` there.

## Why this case matters

Cases 1, 2, and 3 all deny. Without a positive control, an implementation that
hard-codes DENY for every input would pass them. This case (deny because a real
rule fired) plus case 5 (allow a safe action) prove the gate is making genuine
policy decisions, not refusing everything.

## The precise failure mode a non-conformant gate would exhibit

If an implementation returns ALLOW here, it is not evaluating the forbid at all
(for example the pre-0.7.0 defect where the policy was passed as a bare string
and never evaluated against the pinned engine, so every call allowed). That is the
companion defect to the `in`-on-String discard.

## Reference invocation

```sh
printf '%s' "$(jq -r .policy input.json)" > /tmp/case4.cedar
npx protect-mcp@0.7.0 evaluate \
  --policy /tmp/case4.cedar \
  --tool Bash \
  --input "$(jq -c .input input.json)"
# exit 2 = DENY (conformant). exit 0 = ALLOW (non-conformant: forbid not evaluated).
```

## Disclosure links

- The "Cedar policies are actually evaluated now" fix in the protect-mcp 0.7.0
  CHANGELOG (the bare-string PolicySet defect), reported alongside the verb gap in
  wshobson/agents issue #601.
- protect-mcp 0.7.0 is the reference conformant implementation.
