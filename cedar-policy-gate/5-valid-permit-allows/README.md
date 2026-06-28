# Case 5 - valid permit allows (positive control)

## What this proves

A safe action under a valid, non-erroring policy is ALLOWED. This is the liveness
control: it stops a gate from passing the suite by denying everything.

```cedar
forbid(principal, action, resource) when { ["rm", "dd", "mkfs"].contains(context.command) };
permit(principal, action, resource);
```

The input command is `ls`, which is not in the forbidden set, so the forbid does
not match and the terminal permit applies. The action is allowed.

## Required decision

ALLOW. protect-mcp 0.7.0 returns `allowed: true` with an empty policy-error list
and exits 0.

## Why this case matters

Cases 1 through 4 all deny. A gate that simply returns DENY for every input would
pass all of them and still be useless (it would block every legitimate tool
call). This case proves the gate makes a real, value-dependent decision: deny the
dangerous command (case 4), allow the safe one (this case). Together they show the
gate is sound (fail closed on uncertainty) without being degenerate (deny-all).

## The precise failure mode a non-conformant gate would exhibit

If an implementation returns DENY here, it is over-denying: it is not actually
evaluating the policy and instead refusing all traffic, which is operationally
equivalent to having no gate (users disable it). A conformant gate must let safe
actions through.

## Reference invocation

```sh
printf '%s' "$(jq -r .policy input.json)" > /tmp/case5.cedar
npx protect-mcp@0.7.0 evaluate \
  --policy /tmp/case5.cedar \
  --tool Bash \
  --input "$(jq -c .input input.json)"
# exit 0 = ALLOW (conformant). exit 2 = DENY (non-conformant: over-denial).
```

## Disclosure links

- The same 0.7.0 evaluation-correctness fix that makes case 4 deny also makes this
  case allow (the gate actually evaluates the policy). See the protect-mcp 0.7.0
  CHANGELOG and wshobson/agents issue #601.
- protect-mcp 0.7.0 is the reference conformant implementation.
