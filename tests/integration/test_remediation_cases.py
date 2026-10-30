"""Phase 1: every case of ``benchmark/remediation/cases.json`` through the CLI.

The expected values were fixed before the verifier existed
(``benchmark/remediation/ground-truth-changes.md`` records the two later
corrections and why). Each case builds its own git repository, runs
``python3 -m iacreview.remediation verify`` as a subprocess with a PATH holding
only git and the case's tools, and checks decision, exit code, task outcome,
required codes and the case's extra observations (markers, canaries, stale
evidence, contract and validator provenance).
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PLUGIN_ROOT / "tests" / "remediation_bench"))

import casegen  # noqa: E402
import run_cases  # noqa: E402

CASES = casegen.load_cases()

pytestmark = [
    pytest.mark.skipif(shutil.which("cfn-lint") is None, reason="cfn-lint is not installed"),
    pytest.mark.skipif(shutil.which("cfn-guard") is None, reason="cfn-guard is not installed"),
    pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed"),
]


def test_the_case_set_covers_the_24_families() -> None:
    families = {case["family"] for case in CASES}
    assert families == {"C{0:02d}".format(i) for i in range(1, 25)}
    assert len({case["id"] for case in CASES}) == len(CASES)


def test_every_case_has_a_builder() -> None:
    assert {case["mutation"] for case in CASES} <= set(casegen.BUILDERS)


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_case_matches_its_ground_truth(case: dict, tmp_path: Path) -> None:
    result = run_cases.evaluate(case, tmp_path / case["id"])
    failed = {name: value for name, value in result["checks"].items() if not value}
    assert not failed, (result["actual"], failed)
