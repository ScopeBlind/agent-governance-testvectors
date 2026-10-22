# Implementation and maintenance evidence

Reviewed 22 October 2026. This page links to public code, recorded runs and
accepted contributions so a developer can inspect what works and reproduce the
checks. It is an evidence snapshot, not a certification or an endorsement by the
projects named below.

## Which project does what?

| Project | Role | Licence |
| --- | --- | --- |
| [protect-mcp](https://github.com/ScopeBlind/scopeblind-gateway) | Evaluates agent tool calls against configured policies and produces signed decision receipts. Its protection depends on the paths routed through it. | MIT |
| [Veritas Acta verifier](https://github.com/VeritasActa/verify) | Checks supported receipt formats using independently supplied keys; offers a CLI and browser engine. | Apache-2.0 |
| [This conformance suite](../README.md) | Exercises receipt producers and tests a reference verifier against local and externally contributed cases. | Apache-2.0 |
| [Acta](https://github.com/VeritasActa/Acta) | Public-record reference application and protocol website, with its own Charter and application rules. | Apache-2.0 |

The [receipt draft](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/)
is an individual Internet-Draft, not an adopted IETF standard. ScopeBlind maintains
these projects; external contributions do not imply independent foundation governance.

## Recorded compatibility results

The baseline is suite commit
[`8043c5516defcd18492e534305f8fdbb72a7a09f`](https://github.com/ScopeBlind/agent-governance-testvectors/tree/8043c5516defcd18492e534305f8fdbb72a7a09f).
The [recorded CI run](https://github.com/ScopeBlind/agent-governance-testvectors/actions/runs/39722478336)
ran on Ubuntu with Node 20 and 22. Each job reported **four producers verified,
zero failed, two skipped**. Inspect its logs and receipt artifacts, rather than
treating the green overall job as proof that every listed integration ran.

| Producer | Source exercised at the baseline | Result and scope |
| --- | --- | --- |
| protect-mcp | Published 0.31.1, as printed in the run log; driver maintained here | Four fixture receipts passed schema, signature, expected-decision and chain checks. |
| nobulex | [Contributed driver and evaluator](https://github.com/ScopeBlind/agent-governance-testvectors/tree/8043c5516defcd18492e534305f8fdbb72a7a09f/implementations/nobulex) | Same four fixtures passed. This is the contributed implementation in this suite, not a claim about every release of an upstream package. |
| APS governance hook | [Contributed driver](https://github.com/ScopeBlind/agent-governance-testvectors/tree/8043c5516defcd18492e534305f8fdbb72a7a09f/implementations/aps-governance-hook), using Cedar and the Agent Passport SDK | Same four fixtures passed. |
| cryptovalid-opencore | [Upstream commit `4a92a54e`](https://github.com/robertolocatelli81-dev/cryptovalid-opencore/tree/4a92a54e1847a376d5879f3c4dbc1ac6c3de2fb2), reporting 0.15.1 | Same four fixtures passed. |
| protect-mcp-adk | Placeholder driver | Skipped; no passing integration claimed. |
| sb-runtime | Older-envelope driver | Skipped; no passing integration claimed. |

The last three passing producers are independently contributed/maintained. All
four are checked with **one reference verifier maintained by the draft author**.
An independent-verifier matrix is not implemented here yet. GDI's additional
[driver proposal](https://github.com/ScopeBlind/agent-governance-testvectors/pull/7)
is separate from the recorded four passing producers.

### External test data

| Test set | Exact input | Recorded result | Limits |
| --- | --- | --- | --- |
| agent-evidence-vectors | 0.24.0 receipt-signature corpus; wheel hash and signed corpus digest checked by the [adapter](../verifier-vectors/agent-evidence-vectors/) | 25/25 expected outcomes with `@veritasacta/verify@0.10.27` in the baseline CI run | One corpus and one verifier; not a whole-product assessment. |
| TRACE Acta fixtures | [`b8d2ce6161e57d41dd0b49be78efc05e86baeca5`](https://github.com/agentrust-io/trace-spec/tree/b8d2ce6161e57d41dd0b49be78efc05e86baeca5/examples/action-receipts/acta) | 11 fixtures, 35 compared checks, no differences in the verifier's [report](https://github.com/VeritasActa/verify/blob/0c819c920ab9b9b4557e4bd51b85e74040fbffa0/docs/trace-fixtures.md) and [run](https://github.com/VeritasActa/verify/actions/runs/39699422635) | Policy freshness and session binding are explicitly not compared. This runs in the verifier repository, not this producer matrix. |

Other [verifier vectors](../verifier-vectors/README.md) distinguish enforced
checks from proposed timeliness rules and the unresolved revocation gap. Passing
the suite does not establish receipt completeness, policy adequacy, or the truth
of the action reported by a signer.

## Reproduce and inspect

For the existing producer suite, start with [Running locally](../README.md#running-locally)
and the [baseline workflow](https://github.com/ScopeBlind/agent-governance-testvectors/blob/8043c5516defcd18492e534305f8fdbb72a7a09f/.github/workflows/conformance.yml).
Use a disposable checkout or CI runner with synthetic fixtures. Installation and
external-corpus retrieval require network access; no customer records are needed.

To reproduce the baseline source and the pinned verifier-vector check:

```bash
git clone https://github.com/ScopeBlind/agent-governance-testvectors.git
cd agent-governance-testvectors
git checkout 8043c5516defcd18492e534305f8fdbb72a7a09f
node verifier-vectors/run.mjs
```

Requires Node.js 20 or 22 and npm/npx. Exit 0 means all scored cases matched;
exit 1 means a mismatch; exit 77 means the verifier could not be installed.
The producer suite also needs the Python dependencies described in the workflow;
the external corpus adds Python 3.13 and cosign.

**Reproducibility limit:** this baseline is not a fully locked environment.
`protect-mcp` defaults to `latest`, the producer signature step uses an unpinned
verifier, and some Python dependencies are unpinned. The log records protect-mcp
0.31.1 for the cited run. The verifier-vector runner and external-corpus replay
pin 0.10.27. Do not describe a later run as byte-for-byte reproduction solely
because its suite commit matches. Full dependency pinning is follow-up work.

## Evidence of maintenance beyond these repositories

These merged contributions show concrete collaboration, not endorsement or
customer adoption:

- [Cedar for Agents #64](https://github.com/cedar-policy/cedar-for-agents/pull/64):
  WASM bindings for the policy schema generator, merged 15 April 2026.
- [Agent Governance Toolkit #667](https://github.com/microsoft/agent-governance-toolkit/pull/667):
  protect-mcp integration, merged 3 April 2026.
- [TRACE #592](https://github.com/agentrust-io/trace-spec/pull/592):
  Acta positive and negative fixtures, merged 20 October 2026.

Within this suite, [the check history](check-history.md) credits contributors
who found incorrect success reports and supplied implementations and fixes.
The gateway's [downstream bug report](https://github.com/ScopeBlind/scopeblind-gateway/issues/10)
also records a reported integration problem and the maintainer's released fix.

## Release evidence

Verifier 0.10.27 was published by the
[trusted-publishing workflow](https://github.com/VeritasActa/verify/actions/runs/39699567539)
from commit `0c819c920ab9b9b4557e4bd51b85e74040fbffa0`, with npm provenance.
Provenance connects a package to its build; it is not a security assessment.
The gateway's 0.31.1 registry metadata did not carry npm provenance at this
review. A configured workflow is not evidence that a particular release used it.

## Next work, not current results

- Run supported profiles through a second independently written verifier.
- Record an explicit producer/verifier matrix with unsupported cases separated.
- Extend adversarial fixtures and tests of the harness, starting from an inventory
  of existing cases.
- Lock the reproducible test environment and obtain targeted independent review.

These are proposed follow-up deliverables. This documentation pass adds no new
verifier adapter or adversarial corpus and does not claim grant funding or review
has been awarded. When updating this page, change the date, source revisions,
run links and limitations together; do not infer stronger claims from a larger
test count.
