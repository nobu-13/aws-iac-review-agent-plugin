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

<a id="gates"></a>
## Phase 1 head (G-P1-5)

Filled in by the final gate run; see the bottom of this file.

<a id="clean-checkout"></a>
## Clean checkout (AC41, G-P1-6)

Filled in by the final gate run; see the bottom of this file.
