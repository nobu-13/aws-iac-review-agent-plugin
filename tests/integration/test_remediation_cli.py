"""Phase 1 CLI: ``init`` / ``verify`` / ``explain`` behaviour and output channels."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PLUGIN_ROOT / "tests" / "remediation_bench"))

import casegen  # noqa: E402

needs_tools = [
    pytest.mark.skipif(shutil.which("cfn-lint") is None, reason="cfn-lint is not installed"),
    pytest.mark.skipif(shutil.which("cfn-guard") is None, reason="cfn-guard is not installed"),
]


def _env(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}
    env["PYTHONPATH"] = str(PLUGIN_ROOT)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.update(extra or {})
    return env


def cli(args: List[str], cwd: Path, extra: Optional[Dict[str, str]] = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "iacreview.remediation", *args],
        cwd=str(cwd),
        env=_env(extra),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=300,
        check=False,
    )


@pytest.fixture
def sc01(tmp_path: Path) -> casegen.Setup:
    case = next(c for c in casegen.load_cases() if c["id"] == "C01")
    return casegen.build(case, tmp_path / "C01")


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------


def test_init_lists_both_profiles(tmp_path: Path) -> None:
    result = cli(["init", "--list-profiles"], tmp_path)
    assert result.returncode == 0
    assert "dynamodb-billing-mode-v1" in result.stdout
    assert "iam-inline-policy-overbroad-v1" in result.stdout


@pytest.mark.parametrize(
    "scenario,profile,resource,params",
    [
        ("sc01", "dynamodb-billing-mode-v1", "OrdersTable", []),
        ("sc02", "iam-inline-policy-overbroad-v1", "IngestRole", ["--parameter", "required_statement_sid=ReadInput"]),
    ],
)
def test_init_writes_a_draft_that_matches_the_fixture_contract(
    tmp_path: Path, scenario: str, profile: str, resource: str, params: List[str]
) -> None:
    from iacreview.remediation import contract as contract_mod
    from iacreview.remediation import profiles

    (tmp_path / "infra").mkdir()
    (tmp_path / "infra" / "template.yaml").write_text(casegen.scenario_text(scenario, "base"), encoding="utf-8")
    result = cli(["init", "--profile", profile, "--template", "infra/template.yaml", "--resource", resource, *params], tmp_path)
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("# DRAFT")
    draft = contract_mod.parse_contract_bytes(result.stdout.encode("utf-8"))
    contract_mod.bind_profile(draft, profiles.load_all())
    fixture = contract_mod.parse_contract_bytes(casegen.contract_text(scenario).encode("utf-8"))
    assert draft.allowed_edits == fixture.allowed_edits
    assert draft.required_outcomes == fixture.required_outcomes
    assert set(draft.preserve_invariants) == set(fixture.preserve_invariants)
    assert draft.parameters == fixture.parameters


def test_init_output_refuses_to_overwrite(tmp_path: Path) -> None:
    (tmp_path / "infra").mkdir()
    (tmp_path / "infra" / "template.yaml").write_text(casegen.scenario_text("sc01", "base"), encoding="utf-8")
    (tmp_path / "c.yaml").write_text("keep\n", encoding="utf-8")
    result = cli(
        ["init", "--profile", "dynamodb-billing-mode-v1", "--template", "infra/template.yaml", "--resource", "OrdersTable", "--output", "c.yaml"],
        tmp_path,
    )
    assert result.returncode == 22
    assert (tmp_path / "c.yaml").read_text(encoding="utf-8") == "keep\n"


@pytest.mark.parametrize(
    "args",
    [
        ["--profile", "nope-v1", "--template", "infra/template.yaml", "--resource", "OrdersTable"],
        ["--profile", "dynamodb-billing-mode-v1", "--template", "../template.yaml", "--resource", "OrdersTable"],
        ["--profile", "dynamodb-billing-mode-v1", "--template", "infra/template.yaml", "--resource", "OrdersFunction"],
        ["--profile", "dynamodb-billing-mode-v1", "--template", "infra/template.yaml", "--resource", "Orders*"],
        ["--profile", "iam-inline-policy-overbroad-v1", "--template", "infra/template.yaml", "--resource", "OrdersFunctionRole"],
        ["--profile", "iam-inline-policy-overbroad-v1", "--template", "infra/template.yaml", "--resource", "OrdersFunctionRole", "--parameter", "required_statement_sid=a b"],
    ],
)
def test_init_rejects_bad_input_without_a_traceback(tmp_path: Path, args: List[str]) -> None:
    (tmp_path / "infra").mkdir()
    (tmp_path / "infra" / "template.yaml").write_text(casegen.scenario_text("sc01", "base"), encoding="utf-8")
    result = cli(["init", *args], tmp_path)
    assert result.returncode == 22
    assert result.stdout == ""
    assert "Traceback" not in result.stderr


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "args",
    [
        ["verify", "--base", "HEAD"],
        ["verify", "--base", "HEAD", "--head", "HEAD"],
        ["verify", "--base", "HEAD", "--head", "HEAD", "--config-rev", "HEAD"],
        ["verify", "--base", "HEAD", "--head", "HEAD", "--config-rev", "HEAD", "--contract", "../c.yaml"],
        ["verify", "--base", "HEAD", "--head", "HEAD", "--contract-file", "c.yaml", "--config-rev", "HEAD", "--contract", "c.yaml"],
        ["verify", "--base", "HEAD", "--head", "HEAD", "--worktree", "--contract-file", "c.yaml"],
        ["verify", "--base", "HEAD", "--head", "HEAD", "--contract-file", "c.yaml", "--repository-id", "a b"],
    ],
)
def test_verify_rejects_invalid_invocations_with_22(tmp_path: Path, args: List[str]) -> None:
    result = cli(args, tmp_path)
    assert result.returncode == 22
    assert result.stdout == ""
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize("rev", ["--upload-pack=x", "HEAD..main", "a b", "$(id)"])
def test_verify_rejects_option_like_and_range_revisions(sc01: casegen.Setup, rev: str) -> None:
    args = ["verify", "--repo", str(sc01.repo), "--base=" + rev, "--head", sc01.head or "", "--config-rev", sc01.base, "--contract", sc01.contract_path or ""]
    result = cli(args, sc01.repo)
    report = json.loads(result.stdout)
    assert result.returncode == 22
    assert report["payload"]["decision"] == "ERROR"


def test_verify_outside_a_repository_is_an_error(tmp_path: Path) -> None:
    result = cli(["verify", "--repo", str(tmp_path), "--base", "HEAD", "--head", "HEAD", "--contract-file", "x.yaml"], tmp_path)
    assert result.returncode == 22
    assert json.loads(result.stdout)["payload"]["decision"] == "ERROR"


@pytest.mark.parametrize("_", [0], ids=["no-aws-no-llm"])
def test_verify_needs_no_aws_credentials_or_network(sc01: casegen.Setup, _: int) -> None:
    pytest.importorskip("yaml")
    if shutil.which("cfn-lint") is None or shutil.which("cfn-guard") is None:
        pytest.skip("cfn-lint / cfn-guard not installed")
    extra = {"AWS_CONFIG_FILE": os.devnull, "AWS_SHARED_CREDENTIALS_FILE": os.devnull, "HTTPS_PROXY": "http://127.0.0.1:9", "HTTP_PROXY": "http://127.0.0.1:9"}
    result = cli(casegen.verify_argv(sc01), sc01.repo, extra)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)["payload"]
    assert payload["decision"] == "VERIFIED"
    assert payload["runtime_validated"] is False
    assert payload["enforcement_status"] == "not_verified"


def test_stdout_is_json_only_and_the_summary_goes_to_stderr(sc01: casegen.Setup) -> None:
    if shutil.which("cfn-lint") is None or shutil.which("cfn-guard") is None:
        pytest.skip("cfn-lint / cfn-guard not installed")
    result = cli(casegen.verify_argv(sc01) + ["--summary"], sc01.repo)
    json.loads(result.stdout)
    assert "Remediation verification: VERIFIED" in result.stderr
    assert "Remediation verification" not in result.stdout


@pytest.mark.parametrize("case_id", ["C01", "C02", "C05", "C19", "C16a", "C23a"])
def test_the_payload_is_byte_identical_across_runs_and_metadata_differs(tmp_path: Path, case_id: str) -> None:
    if shutil.which("cfn-lint") is None or shutil.which("cfn-guard") is None:
        pytest.skip("cfn-lint / cfn-guard not installed")
    from iacreview.remediation import report

    case = next(c for c in casegen.load_cases() if c["id"] == case_id)
    setup = casegen.build(case, tmp_path / case_id)
    env = casegen.tool_env(setup, case.get("tools"))
    runs = []
    for seed in ("1", "2"):
        env["PYTHONHASHSEED"] = seed
        runs.append(
            subprocess.run(
                [sys.executable, "-m", "iacreview.remediation", *casegen.verify_argv(setup)],
                env=env, cwd=str(setup.repo), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300, check=False,
            )
        )
    first, second = (json.loads(r.stdout) for r in runs)
    assert report.canonical(first["payload"]) == report.canonical(second["payload"])
    assert first["metadata"]["payload_sha256"] == second["metadata"]["payload_sha256"]
    assert first["metadata"]["run_id"] != second["metadata"]["run_id"]


def test_worktree_preview_sees_an_uncommitted_fix_and_an_untracked_file(tmp_path: Path) -> None:
    if shutil.which("cfn-lint") is None or shutil.which("cfn-guard") is None:
        pytest.skip("cfn-lint / cfn-guard not installed")
    case = next(c for c in casegen.load_cases() if c["id"] == "C03b")  # Head == Base, unresolved
    setup = casegen.build(case, tmp_path / "wt")
    (setup.repo / casegen.TARGET).write_text(casegen.scenario_text("sc01", "fixed"), encoding="utf-8")
    ok = cli(casegen.verify_argv(setup, worktree=True), setup.repo)
    assert ok.returncode == 0, ok.stdout
    payload = json.loads(ok.stdout)["payload"]
    assert payload["subject"]["head"]["kind"] == "worktree"
    assert "ignored_files_not_inspected" in payload["snapshot_notes"]
    (setup.repo / "untracked.sh").write_text("echo hi\n", encoding="utf-8")
    blocked = cli(casegen.verify_argv(setup, worktree=True), setup.repo)
    assert blocked.returncode == 20
    codes = {v["code"] for v in json.loads(blocked.stdout)["payload"]["violations"]}
    assert "file_added_outside_scope" in codes


# ---------------------------------------------------------------------------
# explain
# ---------------------------------------------------------------------------


def _report(sc01: casegen.Setup) -> Path:
    result = cli(casegen.verify_argv(sc01), sc01.repo)
    path = sc01.repo.parent / "report.json"
    path.write_text(result.stdout, encoding="utf-8")
    return path


def test_explain_restates_the_report_and_matches_json(sc01: casegen.Setup) -> None:
    if shutil.which("cfn-lint") is None or shutil.which("cfn-guard") is None:
        pytest.skip("cfn-lint / cfn-guard not installed")
    path = _report(sc01)
    data = json.loads(path.read_text(encoding="utf-8"))
    result = cli(["explain", str(path)], sc01.repo)
    assert result.returncode == 0
    assert "Remediation verification: {0}".format(data["payload"]["decision"]) in result.stdout
    assert "Next action ({0})".format(data["payload"]["next_action"]) in result.stdout
    assert "proves nothing by itself" in result.stdout


def test_explain_check_binding_accepts_the_matching_state(sc01: casegen.Setup) -> None:
    if shutil.which("cfn-lint") is None or shutil.which("cfn-guard") is None:
        pytest.skip("cfn-lint / cfn-guard not installed")
    path = _report(sc01)
    args = ["explain", str(path), "--check-binding", "--repo", str(sc01.repo), "--base", sc01.base, "--head", sc01.head or "", "--config-rev", sc01.base, "--contract", sc01.contract_path or ""]
    result = cli(args, sc01.repo)
    assert result.returncode == 0, result.stdout
    assert "Binding: report matches" in result.stdout


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r["payload"].__setitem__("decision", "VERIFIED") or r["payload"].__setitem__("exit_code", 1),
        lambda r: r["payload"].__setitem__("task_outcome", "already_satisfied"),
        lambda r: r.__setitem__("extra", 1),
        lambda r: r["metadata"].__setitem__("payload_sha256", "0" * 64),
    ],
    ids=["inconsistent-exit", "edited-payload", "unknown-key", "forged-digest"],
)
def test_explain_rejects_edited_or_forged_reports(sc01: casegen.Setup, mutate) -> None:
    if shutil.which("cfn-lint") is None or shutil.which("cfn-guard") is None:
        pytest.skip("cfn-lint / cfn-guard not installed")
    path = _report(sc01)
    data = json.loads(path.read_text(encoding="utf-8"))
    mutate(data)
    path.write_text(json.dumps(data), encoding="utf-8")
    result = cli(["explain", str(path)], sc01.repo)
    assert result.returncode == 22
    assert result.stdout == ""


def test_explain_rejects_the_c13_forged_report(tmp_path: Path) -> None:
    case = next(c for c in casegen.load_cases() if c["id"] == "C13")
    setup = casegen.build(case, tmp_path / "C13")
    result = cli(["explain", str(setup.repo / "remediation-report.json")], setup.repo)
    assert result.returncode == 22
