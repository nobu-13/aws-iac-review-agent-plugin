# Phase 1 Evaluation — A/B/C/D comparison and effort

Small, synthetic and author-run. It shows how four configurations treat the
same 53 candidates; it does not establish a recall rate, a general safety
property or a time saving for real users.

## Setup

* Cases: `benchmark/remediation/cases.json` (53 cases, 24 families, expected
  values fixed before the verifier was written; two later corrections are in
  `benchmark/remediation/ground-truth-changes.md`). Classes: 7 correct, 28
  dangerous, 15 evidence-insufficient, 3 invalid input.
* Runner: `python3 tests/remediation_bench/compare.py --output compare.json`
  (Python 3.9.6, macOS arm64, cfn-lint 1.46.0, cfn-guard 3.2.1, git 2.54.0,
  branch commit `88e48ee` plus the documentation commits). Every case is
  rebuilt as a fresh git repository; each configuration gets the same Base,
  Head and PATH (real or fake tools).
* Configurations:
  * **A** official tools: cfn-lint on Head has no Error and cfn-guard with the
    profile's outcome rule passes on Head.
  * **B** A + v1.1: `iac-review` on Base and Head (cfn-lint, cfn-guard,
    iam-review), then the Delta_Tool with all six declarations and
    `--reviewed-template-path`; accepted when A accepts, at least one finding
    is Resolved and none is New.
  * **C** B + Phase 1 (`verify` returns VERIFIED). `C_only` is Phase 1 alone.
  * **D** the same contract by hand: `git diff --name-only`, a PyYAML
    comparison with the allowed properties deleted, hand-written Guard rules
    against the Logical ID, cfn-lint (`tests/remediation_bench/baseline_d.py`,
    about 90 lines, plus 2 rule files).

## Results

| Config | Dangerous accepted (of 28) | Evidence-insufficient accepted (of 15) | Invalid input accepted (of 3) | Correct rejected (of 7) |
| --- | --- | --- | --- | --- |
| A | 19 | 6 | 3 | 0 |
| B | 17 | 5 | 3 | 2 (C02, C03a) |
| C | 0 | 0 | 0 | 2 (C02, C03a, inherited from B) |
| C_only | **0** | **0** | **0** | **0** |
| D | 2 (C09e, C15c) | 7 | 3 | 1 (C04b) |

Where D differs from Phase 1:

* C09e: the target Template became executable; `git diff --name-only` only
  lists the file, so D accepts it.
* C15c: the contract was narrowed after a pass; D's hand-written rules do not
  follow the approved contract revision.
* C15b, C24a: D has no notion of an approved revision bound to Base; a contract
  that only the candidate carries or an unapproved draft does not stop it.
* C17a, C17c, C17d, C18a, C18b: a tool that hangs and exits 0, prints garbage,
  floods its output, or reports every rule as SKIP or nothing evaluated, still
  exits 0, and D accepts.
* C04b: the same structure rewritten as JSON compares unequal under PyYAML
  tags (`!GetAtt` vs `Fn::GetAtt`), a false reject.
* C21c, C22c, C23b: D never reads a contract, so a malformed one goes
  unnoticed (counted as accepted).

Where A and B differ from Phase 1: A and B look at Head (and B at finding
deltas) only, so every edit that keeps cfn-lint clean and the outcome rule
passing is accepted: IAM widening, environment variables, Outputs, deletion
policy, other Resources, other files, workflow and contract edits, forged
reports. B rejects C02 because the v1.0 review records no finding that the
SC-02 fix resolves (the over-broad statement surfaces as an IAM Review finding
that the Delta_Tool matches as Unchanged), and C03a because a no-op resolves
nothing. B also rejects the dangerous C07b and C19b for the same reason (no
Resolved finding), not because it saw the problem.

Measured by: `.agents/tasks/phase1/compare2.json` (local), rerunnable with the
command above. Raw per-case output is not published.

<a id="effort"></a>
## Effort (AC32, AC47)

| Config | What a team writes for one profile | Commands per verification | Machine time, correct case C02 |
| --- | --- | --- | --- |
| A | the outcome rule (14–28 lines) | 2 | 0.74 s |
| B | A + 6 declarations and the reviewed-path option | 5 (2 reviews, delta, 2 of A) | 0.74 s + 2.76 s |
| C_only | nothing per profile (shipped); one generated contract (25 lines) per task | 1 (`verify`) + `explain` | 1.48 s |
| D | ~90-line script + 12–22-line rule file per contract; no binding, no evidence handling | 1 | 0.82 s |

Author walkthrough, SC-01 and SC-02 each, tools already installed, from an
existing repository: `init` → commit the contract (2 git commands) → apply
the fix → `verify --worktree` → `explain`: 6 operations, 1.9 s of machine time
per scenario. Reading the Summary and deciding was not timed. No third party
has run it: the 10-minute first-run target (AC32) is **not verified** for
anyone but the author.

<a id="recommendation"></a>
## Recommendation for Phase 2 (AC48)

* **Continue**, narrowly. On these cases Phase 1 is the only configuration
  with zero dangerous and zero evidence false accepts while accepting every
  correct case. The difference against D is not detection breadth but the
  things a hand-written script does not do: binding to an approved revision,
  refusing stale or partial evidence, treating tool failure and SKIP as
  unverified, whole-tree mode/symlink checks.
* **Do not** grow profiles before Phase 2 shows real demand; the profile
  format plus Guard rules is the extension point, and each new profile needs
  its own fixed cases.
* **Adapter direction**: the v1.1 Delta did not help as a gate (B accepted 17
  dangerous cases and rejected a correct one). Keep it as review context, not
  as acceptance evidence.
* **Not measured, not claimed**: the 30% review-time reduction, 95% recall,
  third-party installation and use, non-Kiro harnesses, and GitHub merge
  enforcement (pending H-ENV).
* **Community Pilot hypotheses**: (1) a maintainer can approve a generated
  contract without editing it; (2) the Summary is enough to decide without
  reading the JSON; (3) the gate settings in handoff.md are reproducible on a
  personal and an organization repository.
