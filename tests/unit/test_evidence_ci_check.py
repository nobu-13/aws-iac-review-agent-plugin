"""The M1 evidence CI gate, ``.github/scripts/evidence_ci_check.py`` (Phase 2 M1 CI Integration).

Git is replaced by a fake that answers from the working tree, so these tests give the same result in a shallow CI
checkout and in a full clone. The JUnit reports are written here, not produced by a pytest run.
"""

from __future__ import annotations

import importlib.util
import json
import socket
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github" / "scripts" / "evidence_ci_check.py"
EXPECTED = ROOT / "tests" / "fixtures" / "evidence_replay" / "expected.json"
POLICY = ROOT / "docs" / "v2" / "phase2" / "m1" / "precommit" / "definition-versioning-policy.md"


@pytest.fixture(scope="module")
def ci() -> ModuleType:
    spec = importlib.util.spec_from_file_location("ci_script_evidence_ci_check", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def fake_git(missing: Iterable[str] = (), not_ancestor: Iterable[str] = (), diff: Sequence[str] = (),
             base_files: Optional[Dict[str, bytes]] = None, diff_fails: bool = False) -> Any:
    missing, not_ancestor = set(missing), set(not_ancestor)

    def run(args: Sequence[str]) -> Tuple[int, bytes]:
        if list(args[:2]) == ["rev-parse", "HEAD"]:
            return 0, b"f" * 40 + b"\n"
        if list(args[:2]) == ["cat-file", "-e"]:
            return (1 if args[2].split("^", 1)[0] in missing else 0), b""
        if args[0] == "merge-base":
            return (1 if args[2] in not_ancestor else 0), b""
        if list(args[:2]) == ["cat-file", "blob"]:
            _, path = args[2].split(":", 1)
            if base_files is not None and path in base_files:
                return 0, base_files[path]
            return 0, (ROOT / path).read_bytes()
        if args[0] == "diff":
            return (1, b"") if diff_fails else (0, "\0".join(diff).encode())
        raise AssertionError("unexpected git call {0}".format(args))
    return run


def junit(tmp_path: Path, ci: ModuleType, skip: Iterable[str] = (), drop: Iterable[str] = (), fail: Iterable[str] = (),
          extra: Iterable[str] = ()) -> Path:
    skip, drop, fail = set(skip), set(drop), set(fail)
    nodes = list(dict.fromkeys(list(ci.REQUIRED_TESTS) + [f + "::test_x" for f in ci.REQUIRED_FILES] + list(ci.LOCAL_ONLY) + list(extra)))
    cases = []
    for node in nodes:
        if node in drop:
            continue
        path, name = node.split("::", 1)
        cls = path[:-3].replace("/", ".")
        inner = "<skipped message=\"x\"/>" if node in skip else ("<failure message=\"x\"/>" if node in fail else "")
        cases.append('<testcase classname="{0}" name="{1}">{2}</testcase>'.format(cls, name, inner))
    p = tmp_path / "junit.xml"
    p.write_text('<?xml version="1.0"?><testsuites><testsuite name="pytest">{0}</testsuite></testsuites>'.format("".join(cases)), encoding="utf-8")
    return p


def expected_copy(tmp_path: Path, **changes: Any) -> Path:
    doc = json.loads(EXPECTED.read_text(encoding="utf-8"))
    doc.update(changes)
    p = tmp_path / "expected.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return p


def run(ci: ModuleType, tmp_path: Path, git: Any = None, expected: Optional[Path] = None, j: Optional[Path] = None,
        separate: bool = False) -> Any:
    out, _ = ci.run(j or junit(tmp_path, ci), expected or EXPECTED, git=git or fake_git(), separate_process=separate)
    return out


def names(out: Any) -> List[str]:
    return [n for n, _ in out.failures]


# ---------------------------------------------------------------------------
# The expected file and its policy
# ---------------------------------------------------------------------------


def test_the_expected_file_is_the_approved_baseline(ci: ModuleType) -> None:
    doc = json.loads(EXPECTED.read_text(encoding="utf-8"))
    assert ci.expected_problems(doc) == []
    assert doc["baseline_commit"] == "dd6f6295272834175b1eb0eb10ddf23dffc46fed"
    policy = POLICY.read_text(encoding="utf-8")
    for key in ("evaluator_source_sha256", "definition_sha256", "legacy_result_sha256"):
        assert doc[key] in policy, key  # the values the Version Policy §4 fixed as the first baseline
    assert doc["evaluator_version"] in policy


def test_the_whole_check_passes_on_this_source(ci: ModuleType, tmp_path: Path) -> None:
    out = run(ci, tmp_path, separate=True)
    assert out.failures == [] and out.exit_code == 0
    assert out.values["replay_runs"] == 4 and out.values["native_result_sha256"] == json.loads(EXPECTED.read_text())["native_result_sha256"]


def test_the_exit_codes_are_distinct_and_non_zero(ci: ModuleType) -> None:
    codes = [ci.EXIT[n] for n in ci.ORDER] + [ci.EXIT["CHECK_ERROR"]]
    assert len(set(codes)) == len(codes) and 0 not in codes and ci.EXIT["OK"] == 0


@pytest.mark.parametrize("change,needle", [
    ({"surprise": 1}, "keys differ"), ({"native_result_sha256": "X" * 64}, "lower-case SHA-256"),
    ({"baseline_commit": "abc"}, "40-hex"), ({"definition_version": True}, "positive integer"),
    ({"legacy_result_path": "../outside.json"}, "safe relative path"), ({"expected_format": "other/1"}, "expected_format"),
])
def test_an_altered_expected_file_is_refused(ci: ModuleType, tmp_path: Path, change: Dict[str, Any], needle: str) -> None:
    out = run(ci, tmp_path, expected=expected_copy(tmp_path, **change))
    assert names(out)[0] == "EXPECTED_INVALID" and needle in out.failures[0][1] and out.exit_code == 10


def test_an_altered_expected_hash_is_a_mismatch_not_an_update(ci: ModuleType, tmp_path: Path) -> None:
    path = expected_copy(tmp_path, native_result_sha256="0" * 64)
    before = path.read_bytes()
    out = run(ci, tmp_path, expected=path)
    assert names(out) == ["REPLAY_MISMATCH"] and out.exit_code == 15
    assert path.read_bytes() == before and EXPECTED.read_bytes() == EXPECTED.read_bytes()  # never rewritten


# ---------------------------------------------------------------------------
# Hash checks
# ---------------------------------------------------------------------------


def test_a_replay_hash_mismatch_fails(ci: ModuleType, tmp_path: Path) -> None:
    out = run(ci, tmp_path, expected=expected_copy(tmp_path, native_result_sha256="a" * 64))
    assert out.exit_code == ci.EXIT["REPLAY_MISMATCH"]


def test_a_final_report_mismatch_fails(ci: ModuleType, tmp_path: Path) -> None:
    out = run(ci, tmp_path, expected=expected_copy(tmp_path, final_report_sha256="b" * 64))
    assert names(out) == ["REPORT_MISMATCH"] and out.exit_code == 16


def test_a_source_hash_mismatch_fails(ci: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from iacreview.evidence import evaluator
    monkeypatch.setattr(evaluator, "evaluator_source_sha256", lambda: "c" * 64)
    out = run(ci, tmp_path)
    assert "SOURCE_MISMATCH" in names(out) and out.exit_code == 11


def test_a_definition_hash_mismatch_fails(ci: ModuleType, tmp_path: Path) -> None:
    out = run(ci, tmp_path, expected=expected_copy(tmp_path, definition_sha256="d" * 64))
    assert names(out)[0] == "DEFINITION_MISMATCH" and out.exit_code == 12


def test_an_evaluator_version_mismatch_fails(ci: ModuleType, tmp_path: Path) -> None:
    out = run(ci, tmp_path, expected=expected_copy(tmp_path, evaluator_version="iacreview.evidence.evaluator/2"))
    assert names(out) == ["DEFINITION_MISMATCH"]


def test_a_legacy_result_mismatch_fails(ci: ModuleType, tmp_path: Path) -> None:
    out = run(ci, tmp_path, expected=expected_copy(tmp_path, legacy_result_sha256="e" * 64))
    assert names(out) == ["LEGACY_RESULT_MISMATCH"] and out.exit_code == 17


# ---------------------------------------------------------------------------
# Baseline, history, changed paths
# ---------------------------------------------------------------------------


def test_a_baseline_commit_not_in_the_clone_fails(ci: ModuleType, tmp_path: Path) -> None:
    base = json.loads(EXPECTED.read_text())["baseline_commit"]
    out = run(ci, tmp_path, git=fake_git(missing=[base]))
    assert names(out) == ["BASELINE_MISMATCH"] and out.exit_code == 13


def test_a_baseline_commit_that_is_not_an_ancestor_fails(ci: ModuleType, tmp_path: Path) -> None:
    base = json.loads(EXPECTED.read_text())["baseline_commit"]
    out = run(ci, tmp_path, git=fake_git(not_ancestor=[base]))
    assert names(out) == ["BASELINE_MISMATCH"]


def test_another_baseline_commit_fails(ci: ModuleType, tmp_path: Path) -> None:
    out = run(ci, tmp_path, expected=expected_copy(tmp_path, baseline_commit="1" * 40), git=fake_git(missing=["1" * 40]))
    assert names(out) == ["BASELINE_MISMATCH"]


def test_expected_values_that_do_not_come_from_the_baseline_fail(ci: ModuleType, tmp_path: Path) -> None:
    """A PR that changes the evaluator and expected.json together is caught here only if the baseline commit still
    names the old evaluator (ci-security-acceptance.md describes the limit)."""
    rules = (ROOT / "iacreview/evidence/rules_s7.py").read_bytes() + b"# changed\n"
    out = run(ci, tmp_path, git=fake_git(base_files={"iacreview/evidence/rules_s7.py": rules}))
    assert names(out) == ["BASELINE_MISMATCH"] and "evaluator source at the baseline" in out.failures[0][1]


def test_missing_history_fails(ci: ModuleType, tmp_path: Path) -> None:
    out = run(ci, tmp_path, git=fake_git(missing=["24b7a6eae6f6b55813f71e1418bd56f3425019c6"]))
    assert names(out) == ["HISTORY_INSUFFICIENT"] and "fetch-depth: 0" in out.failures[0][1] and out.exit_code == 14


def test_a_change_to_a_phase1_original_fails(ci: ModuleType, tmp_path: Path) -> None:
    out = run(ci, tmp_path, git=fake_git(diff=["docs/v2/phase1/app-demo-plan.md", "README.md"]))
    assert names(out) == ["FORBIDDEN_CHANGE"] and out.exit_code == 18


@pytest.mark.parametrize("path", [".agents/tasks/x.json", ".kiro/steering/a.md"])
def test_a_tracked_private_path_fails(ci: ModuleType, tmp_path: Path, path: str) -> None:
    assert names(run(ci, tmp_path, git=fake_git(diff=[path]))) == ["FORBIDDEN_CHANGE"]


def test_changes_that_can_weaken_the_gate_are_listed_for_review(ci: ModuleType, tmp_path: Path) -> None:
    changed = [".github/workflows/ci.yml", ".github/scripts/evidence_ci_check.py", "tests/fixtures/evidence_replay/expected.json",
               "iacreview/evidence/evaluator.py", "README.md"]
    out = run(ci, tmp_path, git=fake_git(diff=changed))
    assert out.failures == [] and out.review_paths == sorted(changed[:4])
    assert "`tests/fixtures/evidence_replay/expected.json`" in ci.summary(out, json.loads(EXPECTED.read_text()))


def test_an_unlistable_diff_fails(ci: ModuleType, tmp_path: Path) -> None:
    assert names(run(ci, tmp_path, git=fake_git(diff_fails=True))) == ["FORBIDDEN_CHANGE"]


# ---------------------------------------------------------------------------
# Skips and test results
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("node", [
    "tests/unit/test_evidence_s7_definition.py::test_every_historical_clause_occurs_once_at_every_verified_commit",
    "tests/unit/test_evidence_preflight.py::test_this_repository_public_set_passes_the_preflight",
    "tests/unit/test_evidence_mutations.py::test_every_mutant_is_killed_in_an_isolated_copy",
    "tests/unit/test_evidence_replay.py::test_x",
])
def test_a_skipped_required_test_fails(ci: ModuleType, tmp_path: Path, node: str) -> None:
    out = run(ci, tmp_path, j=junit(tmp_path, ci, skip=[node]))
    assert names(out) == ["REQUIRED_TEST_SKIPPED"] and out.exit_code == 19


def test_a_required_test_that_did_not_run_fails(ci: ModuleType, tmp_path: Path) -> None:
    node = ci.REQUIRED_TESTS[0]
    out = run(ci, tmp_path, j=junit(tmp_path, ci, drop=[node]))
    assert names(out) == ["REQUIRED_TEST_SKIPPED"] and "did not run" in out.failures[0][1]


def test_an_unlisted_skip_fails(ci: ModuleType, tmp_path: Path) -> None:
    node = "tests/unit/test_evidence_store.py::test_something"
    out = run(ci, tmp_path, j=junit(tmp_path, ci, skip=[node], extra=[node]))
    assert names(out) == ["REQUIRED_TEST_SKIPPED"] and "not on the local-only list" in out.failures[0][1]


def test_local_only_skips_are_not_verified_and_never_pass(ci: ModuleType, tmp_path: Path) -> None:
    out = run(ci, tmp_path, j=junit(tmp_path, ci, skip=list(ci.LOCAL_ONLY)))
    assert out.failures == [] and out.exit_code == 0 and len(out.local_only) == 3
    text = ci.summary(out, json.loads(EXPECTED.read_text()))
    assert "this is not a PASS of M1 as a whole" in text and "Local-only tests (NOT_VERIFIED in CI)" in text
    assert all(node in text for node in ci.LOCAL_ONLY)
    assert "| M1-10 Phase 1 file trace | NOT_VERIFIED (CI): needs .agents/ |" in text


def test_failed_tests_fail_the_check(ci: ModuleType, tmp_path: Path) -> None:
    out = run(ci, tmp_path, j=junit(tmp_path, ci, fail=[ci.REQUIRED_TESTS[1]]))
    assert names(out) == ["TEST_FAILURES"] and out.exit_code == 20


def test_an_empty_junit_report_fails(ci: ModuleType, tmp_path: Path) -> None:
    p = tmp_path / "empty.xml"
    p.write_text("<testsuites/>", encoding="utf-8")
    assert "TEST_FAILURES" in names(run(ci, tmp_path, j=p))


def test_the_listed_tests_exist(ci: ModuleType) -> None:
    for node in list(ci.REQUIRED_TESTS) + list(ci.LOCAL_ONLY):
        path, name = node.split("::", 1)
        assert ("def " + name + "(") in (ROOT / path).read_text(encoding="utf-8"), node
    for path in ci.REQUIRED_FILES:
        assert (ROOT / path).is_file(), path


# ---------------------------------------------------------------------------
# Abnormal termination, network, entry point
# ---------------------------------------------------------------------------


def test_bad_arguments_and_unreadable_inputs_exit_2(ci: ModuleType, tmp_path: Path) -> None:
    assert ci.main([]) == 2
    assert ci.main(["--junit", str(tmp_path / "none.xml"), "--expected", str(EXPECTED)]) == 2
    bad = tmp_path / "bad.json"
    bad.write_text("{", encoding="utf-8")
    assert ci.main(["--junit", str(junit(tmp_path, ci)), "--expected", str(bad)]) == 2


def test_an_unexpected_exception_exits_2_not_0(ci: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                capsys: pytest.CaptureFixture) -> None:
    def boom(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("synthetic")

    monkeypatch.setattr(ci, "run", boom)
    assert ci.main(["--junit", str(junit(tmp_path, ci)), "--expected", str(EXPECTED)]) == 2
    assert "aborted: RuntimeError" in capsys.readouterr().err


def test_the_replay_needs_no_network(ci: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("network access")

    for name in ("socket", "create_connection", "getaddrinfo"):
        monkeypatch.setattr(socket, name, refuse)
    out = ci.Outcome()
    ci.check_replay(json.loads(EXPECTED.read_text()), out, separate_process=False)
    assert out.failures == []
    with ci.no_network():
        with pytest.raises(OSError, match="network access is not allowed"):
            socket.create_connection(("example.invalid", 443))


def test_the_synthetic_spec_is_the_pipeline_test_spec(ci: ModuleType, tmp_path: Path) -> None:
    import test_evidence_pipeline as pipeline
    from iacreview.evidence import replay
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    assert replay.replay(ci.build_spec(a)) == replay.replay(pipeline.build(b))


def test_main_writes_the_summary_and_returns_the_exit_code(ci: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                           capsys: pytest.CaptureFixture) -> None:
    monkeypatch.setattr(ci, "_git", lambda root: fake_git())
    summary = tmp_path / "summary.md"
    code = ci.main(["--junit", str(junit(tmp_path, ci, skip=list(ci.LOCAL_ONLY))), "--expected", str(EXPECTED), "--summary", str(summary)])
    assert code == 0 and "## M1 evidence integrity (CI)" in summary.read_text(encoding="utf-8")
    assert "verdict: **PASS for the checks this job runs**" in capsys.readouterr().out
    code = ci.main(["--junit", str(junit(tmp_path, ci)), "--expected", str(expected_copy(tmp_path, native_result_sha256="0" * 64)),
                    "--summary", str(summary)])
    assert code == 15
