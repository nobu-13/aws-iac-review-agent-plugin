"""TC-00: the M2 chain package leaves M1 and Phase 1 alone (Phase 2 M2 WP1).

Source: docs/v2/phase2/m2/wp0/m2-acceptance-test-matrix.md §12, m2-scope-and-baseline.md §3-§5,
m2-threat-model.md §7. The full M1 check (``evidence_ci_check.py``) runs in its own CI job; these tests
pin what the chain package must not change and the import direction.
"""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from typing import List

from iacreview.evidence import evaluator, replay

ROOT = Path(__file__).resolve().parents[2]

#: M1 Baseline (m2-scope-and-baseline.md §3). These values are copied from the approved baseline record.
M1_EXPECTED_FILE_SHA256 = "ebe177bdd64e8ec74d90fab0c44ff4f982e93122109c9df8cfa524166346e841"
M1_EVALUATOR_SOURCE_SHA256 = "ee765e0c18ba76b9d4a27a0d4277548f21296757f03a77879763d1824dae58d6"
M1_DEFINITION_SHA256 = "fb4ddef0b86d36e436e4492e1ff2d209812e80b6e993dea47ba07dc7a856b1d0"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_tc_00_01_the_m1_expected_values_and_sources_are_unchanged() -> None:
    expected = ROOT / "tests" / "fixtures" / "evidence_replay" / "expected.json"
    assert _sha(expected) == M1_EXPECTED_FILE_SHA256
    doc = json.loads(expected.read_text(encoding="utf-8"))
    assert doc["evaluator_source_sha256"] == M1_EVALUATOR_SOURCE_SHA256
    assert evaluator.evaluator_source_sha256() == M1_EVALUATOR_SOURCE_SHA256
    _, definition_sha = replay.load_definition()
    assert definition_sha == M1_DEFINITION_SHA256 == doc["definition_sha256"]


def test_tc_00_01_the_chain_package_is_outside_the_m1_source_digest() -> None:
    assert all("/" not in name and not name.startswith("chain") for name in evaluator._SOURCES)
    assert not (ROOT / "iacreview" / "evidence" / "chain").exists()


def _imports(path: Path) -> List[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out: List[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            out.append(node.module)
    return out


def test_tc_00_03_nothing_outside_the_chain_package_imports_it() -> None:
    offenders = []
    for path in sorted((ROOT / "iacreview").rglob("*.py")):
        if "chain" in path.relative_to(ROOT / "iacreview").parts[:1]:
            continue
        if any(name == "iacreview.chain" or name.startswith("iacreview.chain.") for name in _imports(path)):
            offenders.append(str(path.relative_to(ROOT)))
    for path in sorted((ROOT / "skills").rglob("*.py")):
        if any(name.startswith("iacreview.chain") for name in _imports(path)):
            offenders.append(str(path.relative_to(ROOT)))
    assert offenders == []


def test_tc_00_03_the_chain_package_imports_only_the_allowed_modules() -> None:
    allowed_prefixes = ("iacreview.chain", "iacreview.evidence", "iacreview.remediation", "iacreview.reportcheck", "iacreview")
    for path in sorted((ROOT / "iacreview" / "chain").glob("*.py")):
        for name in _imports(path):
            if name.startswith("iacreview"):
                assert name.startswith(allowed_prefixes), (path.name, name)
                assert name in ("iacreview",) or name.split(".")[1] in ("chain", "evidence", "remediation", "reportcheck"), (path.name, name)
