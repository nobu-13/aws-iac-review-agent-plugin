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

| Commit | Scope | Code or check conditions changed? |
| --- | --- | --- |
| `c96896c` | OBS-1 first fix (cycle treated as not contained) | yes |
| `88e48ee` | `proc.run_bounded`, `iacreview/remediation/`, profiles, Skill, cases, tests, design | yes |
| `676c7fd` | public spec, evaluation, handoff, traceability test, comparison harness | tests only |
| `4688b74` | evidence and design notes | docs |
| `feed1b4` | OBS-1 correction: cycles reported in `errors[]`, not dropped | yes (`cdk.py`) |
| `96177a5` | typed-path ambiguity never allows a change | yes (`boundary.py`) |
| `b4ee268` | failure-path tests; gitsnap reads its output limit at call time | yes (`gitsnap.py`) |
| `f7413b6`, `e70c24b` | comparison per AC45, D0 / D1 baselines, docs | tests and docs |
| final commit | this evidence file | docs only |

**Verified commit: `e70c24b`.** Every gate below ran on it. The final commit
differs from it only in this file (`git diff --stat e70c24b HEAD` lists
`docs/v2/phase1/implementation-evidence.md` and nothing else), so no gate needs
re-running for it.

Changed existing files since `v1.1.0`: `iacreview/proc.py` (additive),
`iacreview/cdk.py` (OBS-1), `tests/unit/test_skills.py` (the closed Skill list
gains one entry), `CHANGELOG.md` (Unreleased). `plugin.json`,
`pyproject.toml`, CI, Steering, `.gitignore`, schemas and every other existing
test are unchanged.

<a id="gates"></a>
## Phase 1 gates on `e70c24b` (G-P1-5)

| Gate | Command | Exit | Result | Baseline (`v1.1.0`) |
| --- | --- | --- | --- | --- |
| pytest + coverage on a clean export (no `.kiro/`, no `.agents/`) | `git archive e70c24b \| tar -x`; `python3 -m pytest -p no:cacheprovider -rs --cov=iacreview --cov=benchmark/harness --cov-fail-under=80 --junitxml=…` | 0 | JUnit: tests 7,060 = passed 7,015 + failed 0 + error 0 + skipped 45; coverage 96.82%; 1,035 s | clean export: 44 skipped |
| Benchmark | `python3 benchmark/harness/run_benchmark.py --cases benchmark/cases --mode combined` | 0 | PASS, 34/34 matched, FP 0, FN 0 | 34/34 |
| v1.0 Review_Report digests | `run_iac_review.py --target <t>` for the 17 benchmark cases and 2 examples, SHA-256 compared with docs/v2/v1.1-implementation-evidence.md §5-2 | 0 ×19 | 19/19 equal | 19/19 |
| Determinism | `PYTHONHASHSEED=random python3 -m pytest tests/property/test_prop_determinism.py` | 0 | 1 passed | passed |
| Secret scan | `python3 .github/scripts/scan_secrets.py` | 0 | 0 findings in 625 tracked files | 0 / 568 |
| Ground_Truth order | `python3 .github/scripts/check_ground_truth_order.py --cases benchmark/cases` | 0 | 17/17 | 17/17 |
| ruff | `ruff check iacreview` / `ruff check .` | 1 | 5 / 40 (all pre-existing) | 5 / 40 |
| mypy | `mypy iacreview` | 1 | 12 errors in 7 files (none in new code) | 12 |
| Phase 1 cases | `python3 tests/remediation_bench/run_cases.py` | 0 | 53/53 match; payload digest equal across two runs for every case | — |
| Comparison | `python3 tests/remediation_bench/compare.py` | 0 | evaluation.md (per-case acceptance identical in two runs) | — |
| H-ENV helper tests | `python3 -m pytest .agents/tasks/phase1/henv/test_phase1_henv.py` (local, not committed) | 0 | 23 passed | — |
| Local gate simulation | helper `push-branch` + `demo-prepare` against local bare remotes, then `verify` per scenario branch | — | G1 VERIFIED (0); G2, G3, G4, G5, G6, G10, G7 BLOCKED (20); G8 UNVERIFIED `base_not_ancestor_of_head` (21); validator pinned to the commit, not the branch | — |

Skips (45): 44 are the v1.1 ones (Spec files under `.kiro/`, clean benchmark
cases, placeholder detectors, one prompt fixture); the one new skip is
`test_a_non_utf8_file_name_is_handled_and_redacted`, which APFS cannot run
(non-UTF-8 file names are refused) and Linux CI is expected to run. No Phase 1
test depends on `.kiro/`.

Coverage by file (clean run), with the reviewed gaps:

| File | Cover | Uncovered, after review |
| --- | --- | --- |
| `remediation/gitsnap.py` | 87% | git output-format / ls-tree / ls-files format errors, an oid of the wrong shape after `cat-file -s`, a worktree read racing a writer; each raises `GitError` → ERROR or UNVERIFIED (never VERIFIED) |
| `remediation/checks.py` | 94% | `--version` that times out or overflows; guard records whose lists are not lists (covered by unit tests on `parse_guard_record`) |
| `remediation/contract.py` | 94% | individual "invalid value" branches of fields already covered by the same validator |
| `remediation/boundary.py` | 94% | `_operation` lookups on malformed documents; a path through a scalar |
| `remediation/profiles.py` | 94% | malformed shipped-profile branches (no profile ships malformed) |
| `remediation/report.py`, `verify.py`, `cli.py` | 94–96% | non-UTF-8 statement text in canonical JSON, `--output` write failures |
| `proc.py` | 91% | v1.0 lines; the new `run_bounded` branches are covered |

The trust and exception branches found uncovered in the first round (missing
or symlinked contract, working-tree change during the run, oversized or
non-UTF-8 Template, Base with the required Sid twice, change-entry limit,
broken profile, git limits, unmerged index, submodule entries, every
`--check-binding` reason) now have tests in
`tests/unit/test_remediation_failure_paths.py`.

<a id="clean-checkout"></a>
## Clean checkout (AC41, G-P1-6)

`git archive e70c24b | tar -x` into an empty directory (no `.kiro/`, no
`.agents/`, no untracked files), then the full pytest + coverage command
above from that directory: exit 0, counts as in the table. That run includes
the 53 cases, the CLI tests, the traceability test over
`docs/v2/phase1/ac-traceability.json` and the reference gate checks.

## OBS-1 re-check (directory input)

`run_iac_review.py --target <dir>/ --sources iam-review`, CPython 3.9.6 (and
3.12 / 3.13 with the 3.9 site-packages, reference only):

| Directory | `c96896c` (first fix) | `feed1b4` (current) | `v1.1.0` |
| --- | --- | --- | --- |
| `ok.yaml` + `loop.yaml → loop.yaml` | exit 0, files `[ok.yaml]`, `errors[]` empty (cycle dropped silently) | exit 0, files `[ok.yaml]`, `errors[]`: `input_not_found` for `loop.yaml`; same on 3.12 / 3.13 | 3.9–3.12: exit 1 + traceback; 3.13: as current |
| `loop.yaml` only | exit 8 | exit 3, `errors[]`: `input_not_found` for `loop.yaml` | 3.9–3.12: exit 1 + traceback |
| `ok.yaml`, `link.yaml → ok.yaml`, `sub/s.yaml` | exit 0, files `[ok, sub/s]`, `input_not_found` for `link.yaml` | unchanged | unchanged |
| two-link cycle + `ok.yaml` | as first row | `input_not_found` for both links | as first row |

No traceback in any current run. The single-file path keeps exit 2
(`tests/regression/test_sec_symlink_loop.py`). Exit 0 with an `errors[]`
entry for a mixed directory is the existing v1.0 treatment of any unreadable
directory entry and is not changed (a CLI behaviour change would need
approval); a gate that needs "every candidate reviewed" must read `errors[]`.

## CI run 40325732554 on `5aee146` and the fix (`0963502`, `b638f88`)

Reported by the maintainer (not re-read by the agent): 6 test jobs, 4 PASS
(macOS 3.9 / 3.11 / 3.13, Ubuntu 3.11), 2 FAIL (Ubuntu 3.9 and 3.13), both on
`tests/integration/test_remediation_cases.py::test_case_matches_its_ground_truth[C17d]`
with decision UNVERIFIED, exit 21 and `tool_output_too_large` as expected and
`payload_deterministic` False. Determinism and Repository Hygiene jobs PASS.

Root cause (implementation, not harness): on a timeout or the output limit,
`proc.run_bounded` stops the process group and returns the prefix it had
read. How long that prefix is depends on pipe buffering and scheduling. The
verifier hashed it into `checks[].output_sha256`, so two runs of the same
input could differ there and nowhere else. The prefix is never parsed and is
not evidence of anything.

Reproduction on macOS: the CI fixture writes in large, regular blocks and did
not reproduce locally (C17a–C17d, 10 runs each: 1 distinct payload). A fake
cfn-lint writing 9 MiB in random chunk sizes did: 6 runs, 6 distinct
payloads, differing only at `/checks/<cfn-lint>/output_sha256`.

Fix: a run stopped by TIMEOUT or OUTPUT_TOO_LARGE records its state with
`output_sha256` and `exit_code` null; completed runs keep their digest. The
decision, exit code, codes, limits (60 s, 8 MiB) and expected values are
unchanged. After the fix: the random-chunk tool, 10 runs, 1 distinct payload;
C16a, C16b, C17b, C17c, C17d, C18a, C18b 20 runs each and C17a 8 runs, 1
distinct payload each. Regression tests:
`test_an_output_limit_stop_records_no_digest_of_the_partial_output`,
`test_a_timeout_stop_records_no_digest_of_the_partial_output` (both fail on
the previous code), `test_a_completed_run_still_records_its_output_digest`.

Also in this round: the timeout drill of C17a lowers the check timeout for the
whole run, so at 3 s a slow runner could make the real cfn-lint time out too;
it is now 10 s (test harness only; the fake cfn-guard sleeps 30 s). The
Summary qualifies `task_outcome: resolved` / `already_satisfied` when the
decision is not VERIFIED ("outcome rules only; the candidate as a whole is
UNVERIFIED, not verified"); the payload is unchanged.

Lint advisory: compared finding by finding (file and rule, line numbers
ignored) with `v1.1.0`: ruff 40 = 40 and mypy 12 = 12, identical sets. One
new E741 introduced by this round's test was removed before the commit. The
advisory job exits non-zero on `v1.1.0` as well.

Gates on `b638f88` (clean export, CPython 3.9.6): pytest exit 0, tests 7,067 =
passed 7,022 + failed 0 + error 0 + skipped 45, coverage 96.82%; Benchmark
34/34 (FP 0, FN 0); 19/19 Review_Report digests; Determinism 1 passed; Secret
scan 0 findings in 625 files; Ground_Truth order 17/17; ruff 5 / 40, mypy 12;
53/53 cases with payload equal across two runs. The same pytest totals on
`0963502`. The commit after `b638f88` changes only this file.

## CI run 40416536363 on `5412a73` (six environments)

Run started by the maintainer through H-ENV A; jobs and log saved locally by
`phase1_henv.py ci-evidence` and read by the agent. Event `pull_request`,
head `5412a730ade13d6fe939d71cee636e280e92d4db`, conclusion success.

| Job | pytest (summary line) | Coverage | Benchmark |
| --- | --- | --- | --- |
| tests (ubuntu-latest, Python 3.9) | 7022 passed, 45 skipped | 95.14% | 34/34 |
| tests (ubuntu-latest, Python 3.11) | 7022 passed, 45 skipped | 95.16% | 34/34 |
| tests (ubuntu-latest, Python 3.13) | 7022 passed, 45 skipped | 95.16% | 34/34 |
| tests (macos-15-intel, Python 3.9) | 7021 passed, 46 skipped | 95.08% | 34/34 |
| tests (macos-latest, Python 3.11) | 7021 passed, 46 skipped | 95.11% | 34/34 |
| tests (macos-latest, Python 3.13) | 7021 passed, 46 skipped | 95.11% | 34/34 |

`determinism` and `repository hygiene` success; `lint (advisory)` failure, as
on `v1.1.0` (findings identical, see above). No job failed a test. The CI
pytest step has no `-rs`, so which test is skipped on macOS only (46 vs 45)
is not visible in the log; the APFS-only skip in `test_remediation_security.py`
is the expected candidate (NOT VERIFIED from the log). Coverage in CI is lower
than locally (95.1% vs 96.8%) because CI runs without `.kiro/`; the 80% gate
holds.

## H-ENV B re-planned for a single (owner) account

No second GitHub account exists. The demo repository and ruleset 25921565
stay as published; the scenarios run as the owner through a separate command
set (handoff.md B). The items that need a write-only, non-bypass actor, a
merge or a ruleset change are recorded as NOT VERIFIED there and below.

## Not verified here

| Item | Why | Where it gets verified |
| --- | --- | --- |
| Gate runs G1–G7 and G10 as the owner | not yet run | handoff.md B (owner run) |
| AC28 write-only actor merge refusal, G1 positive mergeability, check-vs-review attribution, admin bypass, G8, G9 | no second account; a merge or ruleset change would be needed | NOT VERIFIED (separate approval and account required) |
| Kiro Power install and SC-01 / SC-02 in Kiro, CLI-vs-Power payload equality | changes global Kiro settings | handoff.md C |
| Independent review of the two ground-truth corrections | only the author agent reviewed them | Human review (H-P1) |
| Any Phase 1 advantage over D1 beyond these 53 decisions | not measured | Phase 2 |
| Third-party first run (10 minutes), human effort | no third party; no human timing | Phase 2 pilot |
| Python 3.11 / 3.13 locally | only 3.9.6 has the dependencies on this machine | CI |

## Process notes

* While confirming that the OBS-1 regression test fails without the fix, the
  agent once used `git stash push iacreview/cdk.py` / `git stash pop` on its
  own uncommitted change only. Re-checked: `git stash list` is empty, no
  pre-existing work was involved, and the committed `cdk.py` history is
  `c96896c` → `feed1b4`. Later checks use a file copy; stash is not used again.
* Two ground-truth corrections, with before/after and reasons:
  `benchmark/remediation/ground-truth-changes.md`.
* Design changes found during implementation and recorded in design.md: the
  verifier reads the cfn-guard record envelope itself (the v1.0 parser rejects
  the clause shapes the profile rules produce), `expression_unevaluated` alone
  does not make an allowed change unsupported (conditions, dynamic references,
  external values and Transforms do), cfn-lint output is digested after
  parsing (its result Ids change per file name), and typed paths are recovered
  from both documents because `semdiff` paths turn digit keys into ints.
