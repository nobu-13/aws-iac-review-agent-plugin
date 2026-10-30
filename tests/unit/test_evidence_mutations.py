"""Mutation detection of the evidence foundation (Phase 2 M1 WP4-6, WP5-5, M1-03).

Runs ``tests/mutation/evidence_mutants.py``: each of the 32 mutants (MU-01..12 from WP4, MU-13..29 from WP5, MU-30..32 from the Pre-Commit Remediation) is applied to an isolated temporary copy
(never to the work tree) and its kill tests must fail there by an assertion, after a passing baseline.
"""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
HARNESS = ROOT / "tests" / "mutation" / "evidence_mutants.py"
REQUIRED = {"MU-{0:02d}".format(n) for n in range(1, 33)}


def _harness() -> Any:
    spec = importlib.util.spec_from_file_location("evidence_mutants_harness", HARNESS)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_every_mutant_edit_matches_its_source_exactly_once() -> None:
    h = _harness()
    assert {m.mutant_id for m in h.MUTANTS} == REQUIRED
    assert [p for m in h.MUTANTS for p in h.edit_problems(m)] == []
    for m in h.MUTANTS:
        for test in m.kill_tests:
            file, _, name = test.partition("::")
            assert ("def " + name + "(") in (ROOT / file).read_text(encoding="utf-8"), test


def test_every_mutant_is_killed_in_an_isolated_copy() -> None:
    h = _harness()
    before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in (ROOT / "iacreview" / "evidence").glob("*.py")}
    result = h.run()
    after = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in (ROOT / "iacreview" / "evidence").glob("*.py")}
    assert before == after  # the work tree is never mutated
    assert result["baseline"]["exit_code"] == 0, result["baseline"]
    survivors = [r for r in result["mutants"] if not r["killed"]]
    assert survivors == [] and result["killed"] == result["total"] == 32
