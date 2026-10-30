"""Phase 1 failure paths of the trust boundary and the pipeline (coverage review).

Each test drives one branch that decides between "stop" and "continue" and
checks it stops on the safe side: missing contract, changing working tree,
oversized or non-UTF-8 Template, a Base with a duplicated required statement,
the change-entry limit, a broken profile, git failures and limits, and the
staleness reasons of ``explain --check-binding``.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

import pytest

from iacreview import deltaschema, template
from iacreview.remediation import cli, gitsnap, profiles, report, rschema, verify

PLUGIN_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PLUGIN_ROOT / "tests" / "remediation_bench"))

import casegen  # noqa: E402

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
needs_tools = pytest.mark.skipif(
    shutil.which("cfn-lint") is None or shutil.which("cfn-guard") is None, reason="cfn-lint / cfn-guard not installed"
)


def setup_for(case_id: str, tmp_path: Path) -> casegen.Setup:
    case = next(c for c in casegen.load_cases() if c["id"] == case_id)
    return casegen.build(case, tmp_path / case_id)


def request(s: casegen.Setup, **overrides) -> verify.Request:
    fields = dict(repo=s.repo, base=s.base, head=s.head, config_rev=s.base, contract_path=s.contract_path, contract_file=None)
    fields.update(overrides)
    return verify.Request(**fields)


def test_a_contract_missing_from_the_trusted_revision_is_an_error(tmp_path: Path) -> None:
    s = setup_for("C01", tmp_path)
    res = verify.run(request(s, contract_path=".iac-remediation/contracts/absent.yaml"))
    assert res.decision == "ERROR" and "contract_not_found" in res.codes


def test_a_missing_draft_file_is_an_error(tmp_path: Path) -> None:
    s = setup_for("C01", tmp_path)
    res = verify.run(request(s, config_rev=None, contract_path=None, contract_file=tmp_path / "nope.yaml"))
    assert res.decision == "ERROR" and "contract_not_found" in res.codes


def test_a_contract_that_is_a_symlink_in_the_revision_is_not_read(tmp_path: Path) -> None:
    s = setup_for("C01", tmp_path)
    repo = casegen.Repo.__new__(casegen.Repo)
    repo.path = s.repo
    contract = s.repo / (s.contract_path or "")
    contract.unlink()
    contract.symlink_to("../../infra/template.yaml")
    config = repo.commit("contract replaced by a symlink")
    res = verify.run(request(s, config_rev=config, base=config, head=config))
    assert res.decision == "ERROR" and "contract_not_found" in res.codes


@needs_tools
def test_a_worktree_that_changes_during_verification_is_unverified(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    s = setup_for("C03b", tmp_path)
    (s.repo / casegen.TARGET).write_text(casegen.scenario_text("sc01", "fixed"), encoding="utf-8")
    real = gitsnap.worktree_snapshot
    calls = {"n": 0}

    def changing(repo: Path) -> gitsnap.Snapshot:
        snap = real(repo)
        calls["n"] += 1
        if calls["n"] > 1:
            snap.entries["late-file"] = gitsnap.Entry("100644", "1" * 40)
        return snap

    monkeypatch.setattr(gitsnap, "worktree_snapshot", changing)
    res = verify.run(request(s, head=None))
    assert res.decision == "UNVERIFIED" and "snapshot_changed" in res.codes


def test_a_worktree_target_that_differs_from_its_snapshot_is_unverified(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    s = setup_for("C03b", tmp_path)
    monkeypatch.setattr(verify, "_blob_id", lambda repo, data: "f" * 40)
    res = verify.run(request(s, head=None))
    assert "snapshot_changed" in res.codes and res.decision != "VERIFIED"


@pytest.mark.parametrize("mutate", ["oversized", "not-utf8"])
def test_an_unreadable_head_template_is_not_comparable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutate: str) -> None:
    s = setup_for("C01", tmp_path)
    repo = casegen.Repo.__new__(casegen.Repo)
    repo.path = s.repo
    if mutate == "oversized":
        monkeypatch.setattr(template, "MAX_TEMPLATE_BYTES", 64)
    else:
        (s.repo / casegen.TARGET).write_bytes(b"Resources:\n  X: \xff\xfe\n")
        s.head = repo.commit("non-utf8 head")
    res = verify.run(request(s))
    assert "template_not_comparable" in res.codes
    assert res.decision in ("BLOCKED", "UNVERIFIED")


@needs_tools
def test_a_base_with_the_required_sid_twice_is_unverified(tmp_path: Path) -> None:
    case = next(c for c in casegen.load_cases() if c["id"] == "C02")
    root = tmp_path / "dup"
    text = casegen.scenario_text("sc02", "base").replace(
        "              - Sid: Everything\n",
        "              - Sid: ReadInput\n                Effect: Allow\n                Action: s3:ListBucket\n                Resource: \"*\"\n              - Sid: Everything\n",
    )
    repo = casegen._base_repo(root, "sc02", text)
    base = repo.commit("base")
    repo.write(casegen.TARGET, text.replace('              - Sid: Everything\n                Effect: Allow\n                Action: "*"\n                Resource: "*"\n', ""))
    head = repo.commit("candidate")
    del case
    res = verify.run(verify.Request(repo.path, base, head, base, casegen.contract_path("sc02"), None))
    assert "invariant_failed_on_base" in res.codes
    assert res.decision in ("UNVERIFIED", "BLOCKED"), res.codes


def test_the_change_entry_limit_stops_the_comparison(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    s = setup_for("C05", tmp_path)
    monkeypatch.setattr(deltaschema, "MAX_CHANGE_ENTRIES", 1)
    res = verify.run(request(s))
    assert "template_not_comparable" in res.codes and res.decision != "VERIFIED"


def test_a_broken_shipped_profile_is_an_internal_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    s = setup_for("C01", tmp_path)

    def broken() -> dict:
        raise profiles.ProfileError("x")

    monkeypatch.setattr(profiles, "load_all", broken)
    res = verify.run(request(s))
    assert res.decision == "ERROR" and res.codes == ["internal_error"]


@pytest.mark.parametrize("limit", ["tree", "git_output"])
def test_git_limits_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, limit: str) -> None:
    s = setup_for("C01", tmp_path)
    if limit == "tree":
        monkeypatch.setattr(rschema, "MAX_TREE_ENTRIES", 2)
    else:
        monkeypatch.setattr(rschema, "GIT_MAX_OUTPUT_BYTES", 32)
    res = verify.run(request(s))
    assert res.decision == "ERROR" and "repository_unreadable" in res.codes


def test_an_unmerged_index_stops_the_worktree_preview(tmp_path: Path) -> None:
    s = setup_for("C01", tmp_path)
    repo = casegen.Repo.__new__(casegen.Repo)
    repo.path = s.repo
    repo.git("checkout", "-q", "-b", "other", s.base)
    repo.write("docs/notes.md", "other side\n")
    repo.commit("other")
    repo.git("checkout", "-q", "main")
    repo.write("docs/notes.md", "main side\n")
    repo.commit("main")
    try:
        repo.git("merge", "-q", "other")
    except Exception:  # noqa: BLE001 - the conflict is the point
        pass
    with pytest.raises(gitsnap.GitError):
        gitsnap.worktree_snapshot(s.repo)


def test_a_submodule_entry_is_kept_from_the_index(tmp_path: Path) -> None:
    s = setup_for("C01", tmp_path)
    repo = casegen.Repo.__new__(casegen.Repo)
    repo.path = s.repo
    repo.git("update-index", "--add", "--cacheinfo", "160000,{0},vendor/lib".format(s.base))
    snap = gitsnap.worktree_snapshot(s.repo)
    assert snap.entries["vendor/lib"].mode == "160000"
    assert "submodule_worktree_not_inspected" in snap.notes


def test_read_blob_refuses_an_oversized_blob(tmp_path: Path) -> None:
    s = setup_for("C01", tmp_path)
    snap = gitsnap.commit_snapshot(s.repo, s.base)
    assert gitsnap.read_blob(s.repo, snap.entries[casegen.TARGET].oid, 10) is None
    with pytest.raises(gitsnap.GitError):
        gitsnap.read_blob(s.repo, "not-an-oid", 10)


# ---------------------------------------------------------------------------
# explain --check-binding: every staleness reason
# ---------------------------------------------------------------------------


def _report_for(s: casegen.Setup) -> dict:
    res = verify.run(request(s))
    return json.loads(report.serialize(report.build_report(res, 0.0)))


def _args(s: casegen.Setup, **overrides) -> argparse.Namespace:
    fields = dict(repo=str(s.repo), base=s.base, head=s.head, config_rev=s.base, contract=s.contract_path)
    fields.update(overrides)
    return argparse.Namespace(**fields)


def test_binding_reports_each_missing_or_changed_item(tmp_path: Path) -> None:
    s = setup_for("C05", tmp_path)
    rep = _report_for(s)
    assert cli.binding_mismatches(rep, _args(s)) == []
    assert "head not given; cannot confirm" in cli.binding_mismatches(rep, _args(s, head=None))
    assert "contract not given; cannot confirm" in cli.binding_mismatches(rep, _args(s, contract=None))
    changed = json.loads(json.dumps(rep))
    changed["payload"]["validator"]["source_sha256"] = "0" * 64
    changed["payload"]["trust"]["profile_sha256"] = "0" * 64
    found = cli.binding_mismatches(changed, _args(s))
    assert "validator changed" in found and "profile or rules changed" in found
    assert "repository could not be read" in cli.binding_mismatches(rep, _args(s, repo=str(tmp_path / "nowhere")))
    preview = json.loads(json.dumps(rep))
    preview["payload"]["subject"]["head"]["kind"] = "worktree"
    assert "report is a worktree preview" in cli.binding_mismatches(preview, _args(s))


def test_explain_refuses_an_oversized_or_missing_file(tmp_path: Path) -> None:
    big = tmp_path / "big.json"
    big.write_bytes(b" " * (rschema.MAX_REPORT_BYTES + 1))
    assert cli._load_report(str(big)) is None
    assert cli._load_report(str(tmp_path / "missing.json")) is None


def test_main_without_a_subcommand_is_an_invalid_invocation(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main([]) == 22
    assert capsys.readouterr().out == ""
