# Phase 1 Requirements — Foundation + Vertical Slice

Status: implemented on `feature/phase1-bounded-remediation`; not released, no
version change. Source: the Phase 1 work package (document version 1.0,
2026-10-26) supplied by the maintainer. This file is the public copy CI reads;
the private Kiro spec under `.kiro/` is not needed (AC41, AC42).

Goal: for a human-approved remediation contract, verify one candidate change
independently and get the same verdict from the CLI, Kiro and a protected CI
gate. Not a goal: a general autonomous repair loop, AWS calls, deploy, merge,
release, or proof of runtime safety.

Requirement numbers are local to this spec. v1.0 / v1.1 requirements are cited
as "v1.0 Requirement N" / "v1.1 Requirement N".

## Scenarios (fixtures fixed before implementation)

* **SC-01** `dynamodb-billing-mode-v1`: make `BillingMode` and
  `ProvisionedThroughput` of one `AWS::DynamoDB::Table` consistent. Allowed:
  `BillingMode` add/replace, `ProvisionedThroughput` remove (profile also
  permits add/replace). Everything else is protected.
* **SC-02** `iam-inline-policy-overbroad-v1`: remove over-broad Allow
  statements (`*`, `svc:*`, `NotAction`) from one Role's inline `Policies`
  and keep the statement with the contract's Sid unchanged.

Fixtures: `benchmark/remediation/scenarios/` (synthetic; not data from a real
account or from the articles the work package mentions). Cases:
`benchmark/remediation/cases.json` (53 cases in the 24 families C01–C24).

## Acceptance criteria

| AC | Requirement (condensed) |
| --- | --- |
| AC01 | v1.1.0 tag/commit, tool versions and gate results recorded as a reproducible baseline |
| AC02 | the five Skills, Review_Report, Delta_Report, existing CLIs and exit codes unchanged |
| AC03 | 19 frozen reports and Benchmark 34/34 unchanged |
| AC04 | existing inputs and parser limits unchanged; no new lint/type findings |
| AC05 | `init` drafts a contract for both profiles; unknown fields, duplicate keys, ambiguous scope rejected |
| AC06 | a PR that relaxes contract/rules does not change the contract or rules used |
| AC07 | a forged `approved_by`, a self-made approval record or a self-declared digest never yields VERIFIED |
| AC08 | revision/digest/base-binding mismatch or an unapproved contract stops non-zero |
| AC09 | approved operations on allowed properties pass; any other property/attribute/section change is BLOCKED |
| AC10 | other files added/removed/modified/renamed, mode changes, symlinks and submodules are caught |
| AC11 | logical rename, Type change or Template loss is never counted as a fix |
| AC12 | typed paths: numeric keys, Unicode/case/prefix collisions, parent replacement, list reorder cannot widen scope |
| AC13 | cfn-lint/cfn-guard run through fixed adapters; rule and input digests recorded |
| AC14 | invariants checked on Base and Head, outcome checked on Head; a Base-failing invariant is not accepted silently |
| AC15 | a vanished finding, a skipped rule, an empty evaluation or a deleted Resource is not an achieved outcome |
| AC16 | missing tool, version mismatch, crash, timeout, bad output, output over the limit: non-zero, nothing reused |
| AC17 | the report binds Base, Head, contract, rules, validator, tools and inputs |
| AC18 | old evidence cannot pass after Head, Base or rule updates |
| AC19 | a forged PASS report in the PR does not replace re-running the checks |
| AC20 | the same inputs give a byte-identical decision payload, separate from run metadata |
| AC21 | four decisions, priority, non-zero exits and next action agree between JSON and Summary |
| AC22 | local preview, trusted verification and merge enforcement are kept apart |
| AC23 | Transform, nested template, dynamic reference or condition evaluation needs are never guessed to VERIFIED |
| AC24 | a no-op is BLOCKED if the purpose is unmet, `already_satisfied` if met; never "runtime verified" |
| AC25 | CI evidence shows workflow, validator, contract and rules come from outside the PR head |
| AC26 | no untrusted PR script/CDK/package/workflow runs with privileges; no shell strings from PR content |
| AC27 | check-name spoofing, skipped jobs, Head replacement and missing protection are tested on GitHub |
| AC28 | with an actor without bypass, a violating PR cannot merge and a correct PR can satisfy the checks |
| AC29 | sample contract drafting and verification run without AWS credentials or an LLM |
| AC30 | profile input is Template + Resource + purpose; no raw report is prepared by hand |
| AC31 | violations, unverified items and next steps are distinct; missing tools are not installed |
| AC32 | first sample run within 10 minutes with tools installed; author and third party measured separately |
| AC33 | one added Skill; the five Skills unchanged |
| AC34 | in a fresh Kiro workspace with the Power's revision recorded, SC-01 and SC-02 are demonstrated |
| AC35 | Kiro cannot relax the contract or checks; one candidate, one verification, then stop |
| AC36 | CLI and Power runs give the same payload for the same snapshot and contract; no mocked IDE PASS |
| AC37 | canaries in contract/template/rules/tool output (paths, keys, bidi, numeric keys) do not leak |
| AC38 | outside an allowed disclosure mode, no values, finding text, tracebacks or raw tool output in reports |
| AC39 | existing safe parser, DAG check and I/O limits are reused; no cycle, fan-out or merge-key bypass added |
| AC40 | each external check has a timeout and output limit and its process group is stopped; CPU/RSS limits stated as residual risk |
| AC41 | a clean checkout without `.kiro/` and `.agents/` runs the CLI, examples, regressions and AC checks |
| AC42 | requirements, design points, task status and AC map are public under `docs/v2/phase1/` |
| AC43 | PASS/FAIL/SKIP counts with reasons, commands, exit codes, versions, commits and logs are kept |
| AC44 | raw logs, sensitive inputs and credentials are kept out of public evidence, without deleting all evidence |
| AC45 | the same candidates go through A (official tools), B (A + v1.1), C (B + Phase 1), D (equivalent Guard + small script) |
| AC46 | at least 24 pre-fixed cases; zero dangerous false accepts, zero evidence false accepts, all supported correct cases accepted |
| AC47 | setup, contract authoring, verification and result-reading effort measured, not only detection |
| AC48 | a continue / narrow / adapter recommendation; unmeasured targets (30%, 95% recall, third-party use) not claimed |

The verification method, test and evidence of each AC are in
[ac-traceability.json](ac-traceability.json). Status per AC is in
[implementation-evidence.md](implementation-evidence.md).

## Decision vocabulary

`VERIFIED` (exit 0), `BLOCKED` (20), `UNVERIFIED` (21), `ERROR` (22);
representative value `ERROR > BLOCKED > UNVERIFIED > VERIFIED`. `VERIFIED`
means the listed checks passed for the bound revisions and contract; it is not
merge approval, deploy success or runtime safety.
