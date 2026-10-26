# Phase 1 Implementation Evidence

Local evidence only. CI on GitHub, the merge-enforcement tests and the Kiro
run are pending the steps in [handoff.md](handoff.md) and are marked
`NOT VERIFIED` here. Counts come from JUnit XML or the pytest summary line,
never from progress dots. Raw logs are kept locally under
`.agents/tasks/phase1/` and are not published.

Environment: macOS 26.6.2 arm64; `/usr/bin/python3` 3.9.6 (PyYAML 6.0.3,
pytest 8.3.4, pytest-cov 6.0.0, hypothesis 6.141.1); cfn-lint 1.46.0;
cfn-guard 3.2.1; git 2.54.0; ruff 0.8.6; mypy 1.14.1. No dependency was
installed or upgraded.

<a id="baseline"></a>
## Baseline (AC01)

`v1.1.0` is an annotated tag on `a2754086cc33d7cb5c5d07b96c745dc86633a9ed`
(= `origin/main`). The working tree at the start was that tree (local `main`
was behind; untracked `.agents/` only). The branch
`feature/phase1-bounded-remediation` was created from the tag.

| Gate | Command | Exit | Result |
| --- | --- | --- | --- |
| pytest + coverage | `python3 -m pytest -p no:cacheprovider --cov=iacreview --cov=benchmark/harness --cov-fail-under=80 --junitxml=…` | 0 | JUnit: 6,763 tests, 0 failures, 0 errors, 35 skipped (6,728 passed); coverage 97.55%; 605 s |
| Benchmark | `python3 benchmark/harness/run_benchmark.py --cases benchmark/cases --mode combined` | 0 | PASS, 34/34 matched |
| Determinism | `PYTHONHASHSEED=random python3 -m pytest tests/property/test_prop_determinism.py` | 0 | passed |
| Secret scan | `python3 .github/scripts/scan_secrets.py` | 0 | 0 findings in 568 files |
| Ground_Truth order | `python3 .github/scripts/check_ground_truth_order.py --cases benchmark/cases` | 0 | 17/17 |
| ruff | `ruff check iacreview` / `ruff check .` | 1 | 5 / 40 (advisory) |
| mypy | `mypy iacreview` | 1 | 12 errors in 7 files (advisory) |

## Commits

| Commit | Scope |
| --- | --- |
| `c96896c` | OBS-1: `cdk._is_contained` treats `RuntimeError` from a symlink cycle as not contained; regression test |
| `88e48ee` | `proc.run_bounded`, `iacreview/remediation/`, profiles, Skill, cases, tests, design |
| `676c7fd` | public spec, evaluation, handoff, traceability test, comparison harness |
| (this commit) | this evidence file |

Changed existing files: `iacreview/proc.py` (additive), `iacreview/cdk.py`
(OBS-1), `tests/unit/test_skills.py` (closed Skill list gains one entry),
`CHANGELOG.md` (Unreleased). `plugin.json`, `pyproject.toml`, CI, Steering,
`.gitignore`, schemas and every other existing test are unchanged.

<a id="gates"></a>
## Phase 1 head (G-P1-5)

Run on the working tree at `676c7fd` (Python 3.9.6) unless noted.

| Gate | Exit | Result | Baseline |
| --- | --- | --- | --- |
| pytest + coverage, clean export of `676c7fd` (no `.kiro/`, no `.agents/`) | 0 | JUnit: 7,030 tests, 0 failures, 0 errors, 45 skipped (6,985 passed); coverage 96.37%; 909 s | v1.1 clean export: 44 skipped |
| pytest + coverage, working tree before the last test fix | 1 | 6,993 passed, 1 failed, 36 skipped; the failure was `test_cfn_lint_states[not json]` hitting its own 2 s timeout under load, fixed in `676c7fd` (timeout only for the timeout case); the fixed file passes 43/43 | — |
| Benchmark `--mode combined` | 0 | PASS, 34/34 matched, FP 0, FN 0 | 34/34 |
| Determinism (`PYTHONHASHSEED=random`) | 0 | 1 passed | passed |
| Secret scan (tracked) | 0 | 0 findings in 623 files | 0 / 568 |
| Ground_Truth order | 0 | 17/17 | 17/17 |
| ruff `iacreview` / `.` | 1 | 5 / 40 | 5 / 40 |
| mypy `iacreview` | 1 | 12 errors in 7 files (none in new code) | 12 |
| Phase 1 cases `python3 tests/remediation_bench/run_cases.py` | 0 | 53/53 match ground truth, payload digest equal across two runs for every case | — |
| A/B/C/D comparison | 0 | see evaluation.md | — |

Skips in the clean export: 44 are the v1.1 ones (Spec files under `.kiro/`,
clean benchmark cases, placeholder detectors); the one new skip is
`test_a_non_utf8_file_name_is_handled_and_redacted`, which APFS cannot run
(it refuses non-UTF-8 file names) and Linux CI is expected to run. No Phase 1
test depends on `.kiro/`.

Coverage of new modules (working-tree run): remediation package 83–100% per
module (`gitsnap.py` 83%, the rest ≥ 89%).

<a id="clean-checkout"></a>
## Clean checkout (AC41, G-P1-6)

`git archive 676c7fd | tar -x` into an empty directory (no `.kiro/`, no
`.agents/`, no untracked files), then the full pytest + coverage command above
from that directory: exit 0, counts as in the table. That run includes the 53
cases (`tests/integration/test_remediation_cases.py`), the CLI tests, the
traceability test over `docs/v2/phase1/ac-traceability.json` and the reference
gate checks.

## Not verified here

| Item | Why | Where it gets verified |
| --- | --- | --- |
| Six-environment CI (Ubuntu / macOS × 3.9 / 3.11 / 3.13) | push needs human credentials | handoff.md step 1–2 |
| Trusted gate runs, required check, ruleset, spoof / skip / head update / actor tests | GitHub settings and a second account | handoff.md step 3–6 |
| Kiro Power install and SC-01 / SC-02 in Kiro, CLI-vs-Power payload equality | changes global Kiro settings | handoff.md step 7 |
| Third-party first run (10 minutes) | no third party | Phase 2 pilot |
| Python 3.11 / 3.13 locally | only 3.9.6 has the dependencies on this machine | CI |

## Process notes

* While confirming that the OBS-1 regression test fails without the fix, the
  agent once used `git stash push iacreview/cdk.py` / `git stash pop` on its
  own uncommitted change only (no pre-existing work involved); later checks
  used a file copy instead.
* Two ground-truth corrections, with before/after and reasons:
  `benchmark/remediation/ground-truth-changes.md`.
* Design changes found during implementation and recorded in design.md: the
  verifier reads the cfn-guard record envelope itself (the v1.0 parser rejects
  the clause shapes the profile rules produce), `expression_unevaluated` alone
  does not make an allowed change unsupported (conditions, dynamic references,
  external values and Transforms do), cfn-lint output is digested after
  parsing (its result Ids change per file name), and typed paths are recovered
  from both documents because `semdiff` paths turn digit keys into ints.
