# Phase 1 Evaluation — A/B/C/D comparison and effort

Small, synthetic and author-run. It shows how six configurations treat the
same 53 candidates. It does not establish a recall rate, a general safety
property or a time saving for real users. **G-P1-7 is PARTIAL**: the decision
comparison is complete for these cases; human effort and the conditions
listed under "Not shown" are not measured.

## Setup

* Cases: `benchmark/remediation/cases.json` — 53 cases in 24 families, expected
  values fixed before the verifier (two later corrections, see
  `benchmark/remediation/ground-truth-changes.md`). Classes: 7 correct, 28
  dangerous, 15 evidence-insufficient, 3 invalid input.
* Runner: `python3 tests/remediation_bench/compare.py --output compare.json`
  on Python 3.9.6, macOS arm64, cfn-lint 1.46.0, cfn-guard 3.2.1, git 2.54.0.
* Same inputs for every configuration: one freshly built git repository per
  case (same Base, Head, trusted config revision), the same PATH with the
  same real or fake tools, the same profile Guard rules wherever rules are
  used (D0 alone uses its own hand-written rules), the same expected values.
* Tool results and acceptance are recorded separately per case
  (`tool_results` and `accept` in the output): what cfn-lint, cfn-guard, the
  Delta_Tool, the verifier and the scripts reported, and then the runner's
  acceptance rule applied to that.

| Config | What runs | Acceptance rule (runner) |
| --- | --- | --- |
| A | cfn-lint on Head; cfn-guard, profile outcome rule, Head projection | no cfn-lint Error and the outcome rule PASS |
| B | A + `iac-review` on Base and Head + v1.1 Delta_Tool (6 declarations, `--reviewed-template-path`) | A, Delta exit 0, ≥ 1 Resolved, 0 New — a model of how a user might read the Delta; v1.1 itself says it is not a gate |
| **C** | A and B are run and kept as reference; Phase 1 `verify` | `verify` returns VERIFIED. Delta Resolved / Delta exit 0 never count |
| C&B | as C | B's rule AND VERIFIED (the number reported in the first evaluation) |
| D0 | `baseline_d0.py`: `git diff --name-only`, PyYAML comparison with the allowed properties removed, hand-written Guard rules, cfn-lint | exit 0 |
| D1 | `baseline_d1.py`: the same contract from the same trusted revision, the same profile rules and tools, every Phase 1 acceptance condition rebuilt by hand, no line limit | exit 0 |

The first evaluation's "C" was C&B. AC45 defines C as B + Phase 1, and with
v1.1's Delta not a gate, C's acceptance is Phase 1's decision; C&B is kept to
show why the earlier figure rejected two correct cases.

## Results

| Config | Dangerous accepted (of 28) | Evidence-insufficient accepted (of 15) | Invalid input accepted (of 3) | Correct rejected (of 7) |
| --- | --- | --- | --- | --- |
| A | 20 | 5 | 3 | 0 |
| B | 17 | 4 | 3 | 2 (C02, C03a) |
| **C** | **0** | **0** | **0** | **0** |
| C&B | 0 | 0 | 0 | 2 (C02, C03a) |
| D0 | 2 (C09e, C15c) | 7 | 3 | 1 (C04b) |
| D1 | 0 | 0 | 0 | 0 |

A's figures differ by one from the first evaluation (20/5 instead of 19/6):
the rule now reads the outcome rule's own state instead of cfn-guard's exit
code for all rules, so C19 (Policies emptied; outcome rule PASS, preserve rule
FAIL) is accepted by A and C17d (flooded cfn-lint output, unparsable) is not.

Why B rejects C02 and C03a: the v1.0 review records no finding that the
SC-02 fix resolves (the over-broad statement surfaces as an IAM Review
finding that the Delta_Tool matches as Unchanged), and a no-op resolves
nothing. B also rejects the dangerous C07b, C19, C19b and C20 for the same
reason — no Resolved finding — not because it saw the problem.

D0's misses: C09e (target made executable; `--name-only` lists the file),
C15c (contract narrowed after a pass; hand rules do not follow the revision),
C15b and C24a (no binding to an approved revision), C17a, C17c, C17d, C18a,
C18b (a tool that hangs then exits 0, prints garbage, floods output, or
reports SKIP / nothing evaluated still exits 0), C21c, C22c, C23b (never reads
a contract), and the false reject C04b (JSON vs YAML tags).

D1 gives the same decision as C on all 53 cases.

### What the D1 result means

D1 shows that the acceptance conditions themselves can be rebuilt from git,
PyYAML, cfn-lint and cfn-guard. On these cases Phase 1 has **no decision
advantage over D1**. What remains different is not shown by this case set:

| Phase 1 has, D1 lacks | Shown here? |
| --- | --- |
| an evidence report bound to Base / Head / contract / rules / validator / tools, deterministic payload, `explain` and staleness check (AC17–AC21) | not as a decision difference; D1 only returns an exit code |
| redaction of keys and paths in any output (AC37–AC38) | not applicable: D1 prints nothing |
| typed-path recovery with an ambiguity stop | no case exercises it (unit tests only) |
| worktree preview, profile registry, `init` | not compared |
| parser structure limits (alias DAG, node / depth caps) instead of refusing every alias | C22b both stop; benign aliases not tested |
| 1,640 lines of tests over the conditions; D1 has none | maintenance, not measured |

Any advantage in those rows is **unproven** by this evaluation.

Measured by: `.agents/tasks/phase1/runs2/compare3.json` (local).

<a id="effort"></a>
## Effort (AC32, AC47)

Machine time and human effort are separate. No human time was measured.

Implementation and configuration size (non-blank, non-comment lines):

| Config | Per team (one time) | Per profile | Per task |
| --- | --- | --- | --- |
| A | — | the outcome rule (shared with Phase 1 here) | — |
| B | A + review/delta invocation, 6 declarations | — | — |
| C (Phase 1) | none to write: verifier 2,170 lines and 1,640 test lines are shipped | profile JSON + Guard rule (shipped for 2 profiles) | contract, generated by `init` (25 lines) |
| D0 | 69-line script | 10–18-line hand-written rule file, scope hard-coded in the script | edit the script |
| D1 | 313-line script, no tests | profile facts written into the script + the Guard rule | the same contract as Phase 1 |

Machine time per case (median over 53 cases; C01 / C02 in brackets):
A 0.63 s; B adds 2.37 s; Phase 1 `verify` 1.26 s (1.23 / 1.26); D0 0.07 s
(0.68 / 0.67 — D0 stops early when `git diff` already rejects); D1 0.12 s
(1.18 / 1.19).

Author walkthrough (SC-01 and SC-02 each, tools installed, existing
repository): `init` → commit the contract (2 git commands) → apply the fix →
`verify --worktree` → `explain`: 6 operations, 1.8–1.9 s machine time. The
author's own reading and deciding time was not timed. No third party has run
it; the 10-minute first-run target (AC32) is **not verified**.

<a id="recommendation"></a>
## Recommendation for Phase 2 (AC48)

* **Continue, narrowly, and change the value claim.** The acceptance logic is
  reproducible by a determined team (D1, ~310 lines). The case for Phase 1 is
  the shipped, tested, explainable evidence and the trust binding — not a
  detection ability nobody else can build. Phase 2 should test that claim:
  does the report / `explain` / gate reduce review effort compared with D1?
* **Do not grow profiles** before real demand; each needs its own fixed cases.
* **v1.1 Delta stays reference information**, not acceptance evidence (B
  accepted 17 dangerous cases and rejected two correct ones).
* **Not measured, not claimed**: 30% review-time reduction, 95% recall,
  third-party installation and use, non-Kiro harnesses, GitHub merge
  enforcement (pending H-ENV), any advantage over D1 in the rows above.
* **Community Pilot hypotheses**: (1) a maintainer approves a generated
  contract without editing it; (2) the Summary is enough to decide without the
  JSON; (3) the gate settings in handoff.md reproduce on a personal and an
  organization repository; (4) maintaining Phase 1 costs less than keeping a
  D1-style script correct.
