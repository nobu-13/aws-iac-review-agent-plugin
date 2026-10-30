"""The M2 chain-integrity CI job and its check script (Phase 2 M2 WP1, D-5).

Source: docs/v2/phase2/m2/wp0/m2-work-plan.md §4. The job must be independent of the M1
evidence-integrity job, read-only, and fail on any failure, skip, missing required test or digest
mismatch. The script is loaded by path (``.github`` is not a package) and fed hand-written JUnit files.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, List

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
SCRIPT = ROOT / ".github" / "scripts" / "chain_ci_check.py"
M1_SCRIPT = ROOT / ".github" / "scripts" / "evidence_ci_check.py"
JOB = "chain-integrity"


def _load(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def script() -> ModuleType:
    return _load(SCRIPT, "chain_ci_check_under_test")


@pytest.fixture(scope="module")
def job() -> Dict[str, Any]:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"][JOB]


def _runs(job: Dict[str, Any]) -> List[str]:
    return [str(s.get("run", "")) for s in job["steps"]]


def test_the_chain_job_is_independent_of_the_m1_job(job: Dict[str, Any]) -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert "needs" not in job and "needs" not in workflow["jobs"]["evidence-integrity"]
    text = " ".join(_runs(job))
    assert "evidence_replay" not in text and "evidence_ci_check" not in text
    assert "tests/unit/test_chain_*.py" in text and "chain_ci_check.py" in text


def test_the_chain_job_keeps_the_read_only_token_and_uses_no_secret(job: Dict[str, Any]) -> None:
    assert "permissions" not in job and "environment" not in job and "env" not in job
    raw = WORKFLOW.read_text(encoding="utf-8")
    section = raw[raw.index("  chain-integrity:"):raw.index("  lint:")]
    assert "secrets." not in section and "actions/cache" not in section and "cache:" not in section
    assert "upload-artifact" not in section and "github.token" not in section and "${{ secrets" not in section
    checkout = next(s for s in job["steps"] if str(s.get("uses", "")).startswith("actions/checkout@"))
    assert checkout["with"]["persist-credentials"] is False


def test_the_chain_check_runs_even_after_a_test_failure(job: Dict[str, Any]) -> None:
    step = next(s for s in job["steps"] if "chain_ci_check.py" in str(s.get("run", "")))
    assert step.get("if") == "${{ always() }}" and not step.get("continue-on-error", False)


def test_the_check_exit_codes_are_disjoint_from_m1_and_the_reserved_chain_codes(script: ModuleType) -> None:
    m1 = _load(M1_SCRIPT, "evidence_ci_check_for_chain_ci")
    mine = set(script.EXIT.values()) - {0}
    assert not mine & (set(m1.EXIT.values()) - {0})
    assert not mine & {31, 32, 33, 34}


def _junit(tmp: Path, cases: List[str]) -> Path:
    body = "".join(cases)
    path = tmp / "junit.xml"
    path.write_text('<?xml version="1.0"?><testsuites><testsuite name="pytest">{0}</testsuite></testsuites>'.format(body), encoding="utf-8")
    return path


def _case(node: str, child: str = "") -> str:
    file, _, name = node.partition("::")
    cls = file[:-3].replace("/", ".")
    return '<testcase classname="{0}" name="{1}">{2}</testcase>'.format(cls, name, child)


def _expected(tmp: Path, script: ModuleType, **over: Any) -> Path:
    sys.path.insert(0, str(ROOT))
    from iacreview.chain import validator

    doc: Dict[str, Any] = {"expected_format": "iacreview.chain.replay-expected/1", "note": "test",
                           "validator_source_sha256": validator.validator_source_sha256(),
                           "scenarios": {s: {"chain_status": "INCOMPLETE", "manifest_sha256": "a" * 64, "payload_sha256": "b" * 64}
                                         for s in ("sc01", "sc02")}}
    doc.update(over)
    path = tmp / "expected.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def _run(script: ModuleType, tmp: Path, cases: List[str], **over: Any) -> int:
    return int(script.main(["--junit", str(_junit(tmp, cases)), "--expected", str(_expected(tmp, script, **over))]))


def test_all_required_tests_passing_is_ok(script: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    assert _run(script, tmp_path, [_case(t) for t in script.REQUIRED_TESTS]) == 0


def test_a_failure_is_test_failures(script: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    cases = [_case(t) for t in script.REQUIRED_TESTS] + [_case("tests/unit/test_chain_x.py::test_y", "<failure/>")]
    assert _run(script, tmp_path, cases) == 42


def test_any_skip_is_refused(script: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    cases = [_case(t) for t in script.REQUIRED_TESTS] + [_case("tests/unit/test_chain_x.py::test_z", "<skipped/>")]
    assert _run(script, tmp_path, cases) == 43


def test_a_missing_required_test_is_refused(script: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    assert _run(script, tmp_path, [_case(t) for t in script.REQUIRED_TESTS[1:]]) == 43


def test_an_invalid_expected_file_is_refused(script: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    assert _run(script, tmp_path, [_case(t) for t in script.REQUIRED_TESTS], expected_format="other/1") == 41


def test_another_validator_source_is_refused(script: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    assert _run(script, tmp_path, [_case(t) for t in script.REQUIRED_TESTS], validator_source_sha256="0" * 64) == 44


def test_an_unreadable_junit_is_a_check_error(script: ModuleType, tmp_path: Path) -> None:
    expected = _expected(tmp_path, script)
    assert script.main(["--junit", str(tmp_path / "absent.xml"), "--expected", str(expected)]) == 40


def test_every_required_test_exists(script: ModuleType) -> None:
    for node in script.REQUIRED_TESTS:
        file, _, name = node.partition("::")
        assert ("def " + name + "(") in (ROOT / file).read_text(encoding="utf-8"), node


def test_the_summary_names_no_path(script: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(target))
    _run(script, tmp_path, [_case(t) for t in script.REQUIRED_TESTS])
    text = target.read_text(encoding="utf-8")
    assert str(tmp_path) not in text and str(ROOT) not in text and "PASS for the checks this job runs" in text
