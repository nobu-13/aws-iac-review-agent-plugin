"""Phase 1 security regressions: git side effects, paths, leaks, fail-closed internals."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from iacreview.remediation import gitsnap, report, verify

PLUGIN_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PLUGIN_ROOT / "tests" / "remediation_bench"))

import casegen  # noqa: E402

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


def _case(case_id: str, tmp_path: Path) -> casegen.Setup:
    case = next(c for c in casegen.load_cases() if c["id"] == case_id)
    return casegen.build(case, tmp_path / case_id)


def test_snapshots_run_no_hook_filter_textconv_fsmonitor_or_pager(tmp_path: Path) -> None:
    setup = _case("C21d", tmp_path)
    repo = gitsnap.check_repo(setup.repo)
    base = gitsnap.commit_snapshot(repo, gitsnap.resolve_commit(repo, setup.base))
    head = gitsnap.commit_snapshot(repo, gitsnap.resolve_commit(repo, setup.head or "HEAD"))
    assert base.entries.keys() == head.entries.keys()
    gitsnap.read_blob(repo, head.entries[casegen.TARGET].oid, 1 << 20)
    gitsnap.worktree_snapshot(repo)
    gitsnap.is_ancestor(repo, setup.base, setup.head or "HEAD")
    assert setup.marker is not None and not setup.marker.exists()


def test_the_safe_options_override_repository_config() -> None:
    options = " ".join(gitsnap.SAFE_OPTIONS)
    for needle in ("core.fsmonitor=false", "core.hooksPath=/dev/null", "protocol.allow=never", "diff.external=", "--no-pager"):
        assert needle in options


@pytest.mark.parametrize("rev", ["-x", "--output=/tmp/x", "a..b", "a b", "", "x" * 300, "HEAD:path"])
def test_revision_text_is_validated_before_git_sees_it(tmp_path: Path, rev: str) -> None:
    setup = _case("C01", tmp_path)
    with pytest.raises(gitsnap.GitError):
        gitsnap.resolve_commit(setup.repo, rev)


def test_an_unknown_revision_is_an_error_decision(tmp_path: Path) -> None:
    setup = _case("C01", tmp_path)
    res = verify.run(verify.Request(setup.repo, "deadbeef" * 5, setup.head, setup.base, setup.contract_path, None))
    assert res.decision == "ERROR"
    assert "revision_not_found" in res.codes


def test_worktree_reads_do_not_follow_a_symlinked_target(tmp_path: Path) -> None:
    setup = _case("C01", tmp_path)
    secret = tmp_path / "outside.txt"
    secret.write_text("zqx-CANARY-7f3c9a\n", encoding="utf-8")
    target = setup.repo / casegen.TARGET
    target.unlink()
    os.symlink(str(secret), str(target))
    with pytest.raises(gitsnap.GitError):
        gitsnap.read_worktree_file(setup.repo, casegen.TARGET, 1 << 20)
    res = verify.run(verify.Request(setup.repo, setup.base, None, setup.base, setup.contract_path, None))
    assert res.decision == "BLOCKED"
    assert "target_not_regular_file" in res.codes
    assert "zqx-CANARY" not in report.serialize(report.build_report(res, 0.0))


def test_a_non_utf8_file_name_is_handled_and_redacted(tmp_path: Path) -> None:
    setup = _case("C01", tmp_path)
    name = b"weird-\xff-zqx-CANARY.txt"
    try:
        with open(os.path.join(os.fsencode(str(setup.repo)), name), "wb") as handle:
            handle.write(b"x")
    except OSError:
        pytest.skip("this filesystem refuses non-UTF-8 names (APFS); exercised on Linux CI")
    res = verify.run(verify.Request(setup.repo, setup.base, None, setup.base, setup.contract_path, None))
    text = report.serialize(report.build_report(res, 0.0))
    assert "zqx-CANARY" not in text
    assert res.decision in ("BLOCKED", "UNVERIFIED")


def test_an_internal_exception_fails_closed_without_detail(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    setup = _case("C01", tmp_path)

    def boom(*_a, **_k):
        raise RuntimeError("zqx-CANARY-7f3c9a")

    monkeypatch.setattr(verify.boundary, "repository", boom)
    res = verify.run(verify.Request(setup.repo, setup.base, setup.head, setup.base, setup.contract_path, None))
    assert res.decision == "ERROR" and res.codes == ["internal_error"]
    assert "zqx-CANARY" not in report.serialize(report.build_report(res, 0.0))


def test_the_cli_prints_no_traceback_on_an_internal_error(tmp_path: Path) -> None:
    env = dict(os.environ, PYTHONPATH=str(PLUGIN_ROOT))
    result = subprocess.run(
        [sys.executable, "-c", "import sys;from iacreview.remediation import cli;cli.cmd_verify=lambda a:1/0;sys.exit(cli.main(['verify','--base','x','--head','y','--contract-file','z']))"],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60, check=False,
    )
    assert result.returncode == 22
    assert "Traceback" not in result.stderr and "ZeroDivision" not in result.stderr


def test_a_report_never_holds_an_absolute_host_path(tmp_path: Path) -> None:
    setup = _case("C05", tmp_path)
    res = verify.run(verify.Request(setup.repo, setup.base, setup.head, setup.base, setup.contract_path, None))
    text = report.serialize(report.build_report(res, 0.0))
    assert str(tmp_path) not in text and str(Path.home()) not in text
    assert json.loads(text)["payload"]["decision"] in ("BLOCKED", "UNVERIFIED")
