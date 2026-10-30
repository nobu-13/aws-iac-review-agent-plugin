"""Mutation detection of the Remediation Evidence Chain, WP1 (Phase 2 M2, MU2-01..MU2-20).

Runs ``tests/mutation/chain_mutants.py``: each mutant is applied to an isolated temporary copy (never to
the work tree) and its kill tests must fail there by an assertion, after a passing baseline. The detection
rate is for this mutant set only. MU2-21..MU2-32 belong to WP2 (Gate) and WP4 (Transport).
"""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
HARNESS = ROOT / "tests" / "mutation" / "chain_mutants.py"
REQUIRED = {"MU2-{0:02d}".format(n) for n in range(1, 21)}


def _harness() -> Any:
    spec = importlib.util.spec_from_file_location("chain_mutants_harness", HARNESS)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_every_chain_mutant_edit_matches_its_source_exactly_once() -> None:
    h = _harness()
    assert {m.mutant_id for m in h.MUTANTS} == REQUIRED
    assert [p for m in h.MUTANTS for p in h.edit_problems(m)] == []
    for m in h.MUTANTS:
        for test in m.kill_tests:
            file, _, name = test.partition("::")
            assert ("def " + name + "(") in (ROOT / file).read_text(encoding="utf-8"), test


def test_every_chain_mutant_is_killed_in_an_isolated_copy() -> None:
    h = _harness()
    package = ROOT / "iacreview" / "chain"
    before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in package.glob("*.py")}
    result = h.run()
    after = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in package.glob("*.py")}
    assert before == after  # the work tree is never mutated
    assert result["baseline"]["exit_code"] == 0, result["baseline"]
    survivors = [r for r in result["mutants"] if not r["killed"]]
    assert survivors == [] and result["killed"] == result["total"] == 20
