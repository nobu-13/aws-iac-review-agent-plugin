"""M2-07: determinism and replay of the Chain Result (Phase 2 M2 WP1).

Source: docs/v2/phase2/m2/wp0/m2-acceptance-test-matrix.md (TC-07-01..TC-07-04).
The inputs are the committed fixtures under tests/fixtures/chain_replay/ and the frozen Phase 1 cases;
the expected digests in tests/fixtures/chain_replay/expected.json are maintained by hand after Human
review and are never written by a test.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

import chain_synth as cs
from iacreview.chain import validator

ROOT = Path(__file__).resolve().parents[2]
EXPECTED = cs.FIXTURES / "expected.json"
SCENARIOS = ("sc01", "sc02")


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    cs.block_network(monkeypatch)


def expected() -> Dict[str, Any]:
    doc = json.loads(EXPECTED.read_text(encoding="utf-8"))
    assert doc["expected_format"] == "iacreview.chain.replay-expected/1"
    return doc


@pytest.fixture(scope="module")
def chains(tmp_path_factory: pytest.TempPathFactory) -> Dict[str, cs.Chain]:
    return {s: cs.fixture_chain(tmp_path_factory.mktemp("replay-" + s), s) for s in SCENARIOS}


def _separate_process(chain: cs.Chain) -> str:
    code = ("import sys; from pathlib import Path; from iacreview.chain import validator; "
            "r = validator.validate(Path(sys.argv[1]), Path(sys.argv[2])); print(r['metadata']['payload_sha256'])")
    env = dict(os.environ, PYTHONHASHSEED="random", PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE="1")
    out = subprocess.run([sys.executable, "-c", code, str(chain.path), str(chain.setup.repo)], env=env, cwd=str(ROOT),
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600, check=True)
    return out.stdout.decode("ascii").strip()


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_tc_07_01_four_runs_give_the_expected_payload_digest(chains: Dict[str, cs.Chain], scenario: str) -> None:
    chain = chains[scenario]
    exp = expected()
    assert validator.validator_source_sha256() == exp["validator_source_sha256"], (
        "iacreview/chain changed: the expected digests need a Human-reviewed update")
    runs: List[str] = []
    for _ in range(2):
        result = validator.validate(chain.path, chain.setup.repo)
        runs.append(result["metadata"]["payload_sha256"])
    runs += [_separate_process(chain) for _ in range(2)]
    want = exp["scenarios"][scenario]
    assert result["payload"]["manifest_sha256"] == want["manifest_sha256"]
    assert result["payload"]["chain_status"] == want["chain_status"]
    assert set(runs) == {want["payload_sha256"]}, runs


def test_tc_07_01_four_runs_agree_and_keep_the_link_order(chains: Dict[str, cs.Chain]) -> None:
    """The same property without the expected file, so that it also holds in a mutated copy (MU2-19, MU2-20)."""
    from iacreview.chain import status as st

    chain = chains["sc02"]
    results = [validator.validate(chain.path, chain.setup.repo) for _ in range(2)]
    runs = [r["metadata"]["payload_sha256"] for r in results] + [_separate_process(chain) for _ in range(2)]
    assert len(set(runs)) == 1, runs
    assert [e["link"] for e in results[0]["payload"]["links"]] == list(st.LINKS)


def test_tc_07_02_the_payload_holds_no_time_path_process_id_or_float(chains: Dict[str, cs.Chain]) -> None:
    for chain in chains.values():
        result = validator.validate(chain.path, chain.setup.repo)
        text = json.dumps(result["payload"])
        for forbidden in (str(chain.root), str(chain.setup.repo), str(Path.home()), "/tmp", "/var/folders", str(os.getpid())):
            assert forbidden not in text
        assert re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}", text) is None
        assert not any(isinstance(v, float) for v in _leaves(result["payload"]))
        assert set(result["metadata"]) == {"generated_at", "duration_ms", "payload_sha256", "diagnostics"}


def _leaves(value: Any) -> List[Any]:
    if isinstance(value, dict):
        return [x for v in value.values() for x in _leaves(v)]
    if isinstance(value, list):
        return [x for v in value for x in _leaves(v)]
    return [value]


def test_tc_07_03_a_one_character_change_in_the_validator_changes_its_digest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    copy = tmp_path / "chain"
    shutil.copytree(str(Path(validator.__file__).resolve().parent), str(copy), ignore=shutil.ignore_patterns("__pycache__"))
    monkeypatch.setattr(validator, "_PACKAGE", copy)
    same = validator.validator_source_sha256()
    status = copy / "status.py"
    status.write_text(status.read_text(encoding="utf-8").replace("BROKEN", "BR0KEN", 1), encoding="utf-8")
    changed = validator.validator_source_sha256()
    assert same == expected()["validator_source_sha256"] and changed != same


def test_tc_07_04_no_test_writes_the_expected_digests() -> None:
    here = Path(__file__).resolve().parent
    for path in sorted(here.glob("test_chain_*.py")) + [here / "chain_synth.py"]:
        for line in path.read_text(encoding="utf-8").splitlines():
            if re.search(r"(EXPECTED|chain_replay/expected\.json|FIXTURES\s*/\s*\"expected)[^\n]*\.(write_text|write_bytes)\(", line) or \
                    re.search(r"open\(\s*(str\()?(EXPECTED|FIXTURES)[^\n]*['\"][wax]", line):
                raise AssertionError("{0} writes an expected value: {1}".format(path.name, line.strip()))
