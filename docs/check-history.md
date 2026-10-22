# Conformance check history

Historical implementation notes and the measured defects that shaped this suite.
For current results, use the [status table](../README.md#status) and
[reproducible evidence](project-evidence.md).

History:

- **v0.1** (first release): fixtures, expected schema, TypeScript driver,
  bash runner, GitHub Actions CI stub. Drivers for the other three
  implementations are placeholders inviting their authors to open PRs.
- **v0.2 target**: all four drivers plus a proper cross-verification
  matrix (every implementation's output verified by every verifier).
- **v0.3** (September 2026): the checks made to gate (see the next
  section), four receipt shapes recognised, the chain link pinned to
  section 6.7 of draft-farley-acta-signed-receipts-03, and a check 3 that
  compares each receipt's outcome to the expected chain. Three implementations
  now verify in CI on Node 20 and Node 22: the protect-mcp reference (0.13.1;
  `sign --cedar` signs the decision it actually makes), nobulex (#12), and the
  APS governance hook (#1). protect-mcp-adk is still a placeholder driver and
  sb-runtime needs a CLI that is not public, so both report a skip.

## What the checks found about themselves

Between August and September 2026 this suite was found to report green on
receipt sets that did not conform. Every finding below was measured from a
clean clone, reproduced by the maintainer, and is fixed in the tree you are
reading. They are kept here because a conformance suite whose checks did not
check is the same failure the receipts exist to prevent, one level up.

1. `run.sh` printed `NON-CONFORMANT` and exited 0, so CI was green on a
   failing suite.
2. The reference driver produced zero receipts against the published CLI.
3. Check 2 never passed a key, so a missing key was reported as a tampered
   signature.
4. Checks 1 and 2 accepted disjoint sets. Both shapes the schema defined were
   unknown to the verifier, and the shape the verifier accepted failed the
   schema, including this repository's own reference receipts.
5. Check 3 computed an expected chain hash and then discarded it. Any
   non-empty link passed.
6. `expected_decision` was read by no code. A driver could ignore the policy,
   sign four receipts with arbitrary decisions, and be reported conformant.
   The reference driver was doing exactly that.
7. Check 2 handed the verifier a glob. It verified only the last file, so a
   driver could forge three of four signatures and still see `PASS`.
8. The fixture policy was not valid Cedar. Its Bash clauses used `in`, which
   is Cedar's entity-hierarchy operator, on a string (`"git" in ["git"]`);
   cedar-wasm reports a type error and, fail-closed, denies. A subset
   evaluator that treats `in` as list membership accepted it and matched the
   expected decisions, so the invalid policy was never noticed. The clauses
   now use `.contains()`, and `spec.md` records the rule.
9. The reference driver signed receipts whose denies were not decisions. On
   Node 20 the published protect-mcp could not load its Cedar engine (the
   package root's ESM entry imports a `.wasm` module, which Node 20 rejects),
   every evaluation was a fail-closed deny with reason
   `cedar_wasm_not_available`, and `sign` recorded each one as `cedar_deny`.
   Check 3 caught the wrong outcomes; the log could not say why. The driver
   now prints the evaluator's verdict per input and refuses to sign when the
   engine or policy failed to load, and protect-mcp 0.13.1 loads the engine
   through the package's `/nodejs` entry and records the evaluator's reason.
10. A driver's exit 77 ("cannot run on this runner") was counted as a
    failure, so every run was red whether or not anything failed. Skips are
    now reported as skips; the run fails only on a failure, or when nothing
    was verified at all.
11. An engine that skips erroring policies turns an invalid policy into a
    silent deny. cedarpy does not raise on the string-in-list clauses of
    finding 8; it skips those policies, returns Deny, and reports the type
    error only in diagnostics. Under it, sequence 2 was a deny for the wrong
    reason and sequence 3, the one negative vector in the set, was a deny
    with an empty reason list: the forbid clause never evaluated, so the
    vector passed without testing anything. Measured and reported by
    [@aeoess](https://github.com/aeoess) in
    [#1](https://github.com/ScopeBlind/agent-governance-testvectors/pull/1).
    The APS driver now fails on any Cedar diagnostic instead of reading the
    resulting Deny as a decision, and nobulex's subset evaluator refuses the
    invalid form rather than guessing at it
    ([@arian-gogani](https://github.com/arian-gogani),
    [#12](https://github.com/ScopeBlind/agent-governance-testvectors/pull/12)).
12. A driver rewrote the policy before evaluating it. An earlier revision of
    the APS driver turned `context.X in [ ... ]` into `[ ... ].contains(context.X)`
    for evaluation while computing `policy_digest` over the on-disk bytes, so
    its receipts matched the expected set by evaluating text the fixture did
    not contain. The rewrite was disclosed in the pull request body and not
    weighed in review; it stayed invisible for three months because the
    transformed clauses are the same text #17 later wrote into the fixture.
    Disclosed and removed by [@aeoess](https://github.com/aeoess); the
    rule it leaves behind is in `spec.md`: the policy under test is the
    on-disk bytes.
13. Check 3 compared `policy_digest` only when a receipt carried no `policy_id`:
    the digest branch was the `else` of the id branch. A receipt carrying a
    correct `policy_id` and `policy_digest: sha256:deadbeef` passed, and every
    driver in the tree carries `policy_id`, so the digest the draft makes
    normative was never checked in practice. Reported by
    [@arian-gogani](https://github.com/arian-gogani) on #12 and, from the
    other direction, by [@aeoess](https://github.com/aeoess) in #18. Both
    comparisons are now independent.
14. The reference `policy_digest` in `expected/chain.jsonl` could not be
    derived from anything the repository said. It is the section 6.8
    construction over the fixture policy, and reproduces exactly, but nothing
    named the construction, so two implementers hashed the file and concluded
    the value matched no revision on disk. A reference value nobody can derive
    is not a reference. The construction is now named beside the chain rule
    and `harness/policy-digest.py` recomputes it. Reported by
    [@aeoess](https://github.com/aeoess) (#18) and
    [@arian-gogani](https://github.com/arian-gogani) (#12).

Findings 1 to 7 were reported, with position-by-position measurements, by
[@arian-gogani](https://github.com/arian-gogani) in
[#13](https://github.com/ScopeBlind/agent-governance-testvectors/issues/13),
who also sent the fix for 7 ([#15](https://github.com/ScopeBlind/agent-governance-testvectors/pull/15))
and the second implementation ([#12](https://github.com/ScopeBlind/agent-governance-testvectors/pull/12)).
The schema half of finding 4 was independently reported through the draft's
errata review.

What changed: `run.sh` returns its verdict; check 2 loops over every receipt
with the fixture key; check 1 validates against the schema, which accepts the two shapes the published verifier reads (the Acta 2.1 envelope and the APS decision_receipt) and
says which one the draft specifies; check 3 reads `expected/chain.jsonl`,
compares each receipt's outcome to it, cross-checks it against the fixtures'
`expected_decision`, and pins the chain link to section 6.7 of
draft-farley-acta-signed-receipts-03, naming which convention a
non-conformant producer actually used instead of failing with "mismatch";
the fixture policy is valid Cedar; the reference driver signs real decisions
and refuses to sign an engine outage; CI installs the Python drivers'
dependencies and runs every driver on Node 20 and 22, reporting skips as
skips; drivers evaluate the on-disk policy and fail on Cedar diagnostics.

The rule this leaves behind: a check that cannot fail manufactures confidence
rather than withholding it. Each check here was rewritten so that a planted
failure is caught, and the planted failures are recorded in the pull requests
that closed each finding.

