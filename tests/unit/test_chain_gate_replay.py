"""Gate Regression Anchor (Phase 2 M2 WP2, D2-4 / R2-4): COMPLETE, NOT_PROVEN and BROKEN chains with gate records.

Source: docs/v2/phase2/m2/wp0/wp0-revision-2.md §4 and §8. The expected digests are in their own file,
tests/fixtures/chain_replay/expected-gate.json, so the WP1 anchor (expected.json) keeps its scenarios and
meaning. The values are recorded by hand after Human review and detect change; they do not prove the
implementation correct. The status and codes of each scenario are checked against the specification
before the digests are compared.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

import chain_synth as cs
from iacreview.chain import status as st
from iacreview.chain import validator

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_GATE = cs.FIXTURES / "expected-gate.json"
EXPECTED_WP1 = cs.FIXTURES / "expected.json"

#: What the specification requires of each scenario (m2-acceptance-test-matrix.md TC-10-07, TC-10-04, TC-09-04).
SPEC = {
    "gate-complete": ("COMPLETE", []),
    "gate-not-proven": ("NOT_PROVEN", ["approval_not_shown"]),
    "gate-broken": ("BROKEN", ["pr_head_mismatch"]),
}


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    cs.block_network(monkeypatch)


def expected() -> Dict[str, Any]:
    doc = json.loads(EXPECTED_GATE.read_text(encoding="utf-8"))
    assert doc["expected_format"] == "iacreview.chain.replay-expected-gate/1"
    return doc


@pytest.fixture(scope="module")
def chains(tmp_path_factory: pytest.TempPathFactory) -> Dict[str, cs.GateChain]:
    return {n: cs.fixture_gate_chain(tmp_path_factory.mktemp(n), n) for n in cs.GATE_SCENARIOS}


def _separate_process(path: Path, repo: Path) -> str:
    code = ("import sys; from pathlib import Path; from iacreview.chain import validator; "
            "r = validator.validate(Path(sys.argv[1]), Path(sys.argv[2])); print(r['metadata']['payload_sha256'])")
    env = dict(os.environ, PYTHONHASHSEED="random", PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE="1")
    out = subprocess.run([sys.executable, "-c", code, str(path), str(repo)], env=env, cwd=str(ROOT),
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600, check=True)
    return out.stdout.decode("ascii").strip()


@pytest.mark.parametrize("name", cs.GATE_SCENARIOS)
def test_gate_anchor_scenarios_meet_the_specification(chains: Dict[str, cs.GateChain], name: str) -> None:
    result = validator.validate(chains[name].path, chains[name].setup.repo)
    gate = next(e for e in result["payload"]["links"] if e["link"] == "gate")
    assert (result["payload"]["chain_status"], gate["codes"]) == SPEC[name]
    assert gate["observed"]["approval_authority"] == "NOT_PROVEN"
    assert result["payload"]["not_claimed"] == list(st.NOT_CLAIMED)


@pytest.mark.parametrize("name", cs.GATE_SCENARIOS)
def test_gate_anchor_four_runs_give_the_expected_payload_digest(chains: Dict[str, cs.GateChain], name: str) -> None:
    exp = expected()
    assert validator.validator_source_sha256() == exp["validator_source_sha256"], (
        "iacreview/chain changed: the gate anchor needs a Human-reviewed update")
    g = chains[name]
    runs: List[str] = []
    for _ in range(2):
        result = validator.validate(g.path, g.setup.repo)
        runs.append(result["metadata"]["payload_sha256"])
    runs += [_separate_process(g.path, g.setup.repo) for _ in range(2)]
    want = exp["scenarios"][name]
    assert result["payload"]["chain_status"] == want["chain_status"]
    assert result["payload"]["manifest_sha256"] == want["manifest_sha256"]
    assert set(runs) == {want["payload_sha256"]}, runs


def test_gate_anchor_is_separate_from_the_wp1_anchor() -> None:
    wp1 = json.loads(EXPECTED_WP1.read_text(encoding="utf-8"))
    gate = expected()
    assert set(wp1["scenarios"]) == {"sc01", "sc02"} and set(gate["scenarios"]) == set(cs.GATE_SCENARIOS)
    assert gate["validator_source_sha256"] == wp1["validator_source_sha256"]


def test_no_test_writes_the_gate_anchor() -> None:
    here = Path(__file__).resolve().parent
    for path in sorted(here.glob("test_chain_*.py")) + [here / "chain_synth.py"]:
        for line in path.read_text(encoding="utf-8").splitlines():
            if re.search(r"(EXPECTED_GATE|expected-gate\.json)[^\n]*\.(write_text|write_bytes)\(", line):
                raise AssertionError("{0} writes the gate anchor: {1}".format(path.name, line.strip()))
