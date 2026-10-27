"""Spike (not deployed): the verify job's outputs come from the report, not from the workflow.

Covers ``docs/v2/phase1/ci/spike/gate_outputs.py``: synthetic reports for each
refusal, real verifier reports (C01 VERIFIED, C05 BLOCKED) for schema
compatibility, and the chain gate_outputs → publish_check.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import shutil
import sys
from pathlib import Path
from typing import Any, Callable, Dict

import pytest

from iacreview.remediation import report as rreport
from iacreview.remediation import verify

ROOT = Path(__file__).resolve().parents[2]
SPIKE = ROOT / "docs" / "v2" / "phase1" / "ci" / "spike"
sys.path.insert(0, str(ROOT / "tests" / "remediation_bench"))

import casegen  # noqa: E402


def _load(name: str, file: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, SPIKE / file)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


gout = _load("spike_gate_outputs", "gate_outputs.py")
pub = _load("spike_publish_check_chain", "publish_check.py")

BASE = "c" * 40
HEAD = "a" * 40
CONTRACT = ".iac-remediation/contracts/billing-mode-orders.yaml"


def synthetic(decision: str = "VERIFIED") -> Dict[str, Any]:
    payload = {
        "decision": decision,
        "exit_code": gout.DECISION_EXIT_CODES[decision],
        "execution_mode": "trusted_ci",
        "preview_only": False,
        "subject": {"repository_id": "owner/demo", "base": {"commit": BASE}, "head": {"kind": "commit", "commit": HEAD}},
        "trust": {"trusted_config_commit": BASE, "contract_path": CONTRACT},
    }
    return seal({"report_kind": "remediation_verification", "report_schema_version": "0.1.0", "payload": payload,
                 "metadata": {"run_id": "1-1"}})


def seal(rep: Dict[str, Any]) -> Dict[str, Any]:
    rep["metadata"]["payload_sha256"] = hashlib.sha256(rreport.canonical(rep["payload"])).hexdigest()
    return rep


def write(tmp_path: Path, rep: Any) -> Path:
    path = tmp_path / "remediation-report.json"
    path.write_text(json.dumps(rep) if not isinstance(rep, str) else rep, encoding="utf-8")
    return path


def env(path: Path, status: str = "0", **overrides: str) -> Dict[str, str]:
    base = {"REPORT_PATH": str(path), "VERIFY_STATUS": status, "EXPECTED_BASE_SHA": BASE, "EXPECTED_HEAD_SHA": HEAD,
            "EXPECTED_CONTRACT_PATH": CONTRACT, "GITHUB_OUTPUT": str(path.parent / "github_output")}
    base.update(overrides)
    return base


def read_outputs(path: Path) -> Dict[str, str]:
    lines = (path.parent / "github_output").read_text(encoding="utf-8").splitlines()
    return dict(line.split("=", 1) for line in lines)


def test_the_canonical_form_is_the_verifiers() -> None:
    sample = {"b": [1, "é", None], "a": {"z": True, "y": 1.5}}
    assert gout.canonical(sample) == rreport.canonical(sample)


def test_a_consistent_verified_report_gives_its_own_values(tmp_path: Path) -> None:
    rep = synthetic()
    path = write(tmp_path, rep)
    assert gout.main(env(path)) == 0
    assert read_outputs(path) == {"exit_code": "0", "decision": "VERIFIED", "head_sha": HEAD,
                                  "payload_sha256": rep["metadata"]["payload_sha256"]}


@pytest.mark.parametrize("decision,status", [("BLOCKED", "20"), ("UNVERIFIED", "21"), ("ERROR", "22")])
def test_a_consistent_failing_report_passes_its_decision_through(tmp_path: Path, decision: str, status: str) -> None:
    path = write(tmp_path, synthetic(decision))
    assert gout.main(env(path, status)) == int(status)
    assert read_outputs(path)["decision"] == decision and read_outputs(path)["exit_code"] == status


def test_an_early_error_without_a_head_still_reports_error(tmp_path: Path) -> None:
    rep = synthetic("ERROR")
    rep["payload"]["subject"]["head"] = {"kind": None, "commit": None}
    path = write(tmp_path, seal(rep))
    assert gout.main(env(path, "22")) == 22
    assert read_outputs(path)["head_sha"] == "" and read_outputs(path)["decision"] == "ERROR"


def _set(path: str, value: Any) -> Callable[[Dict[str, Any]], None]:
    def mutate(rep: Dict[str, Any]) -> None:
        node = rep
        keys = path.split(".")
        for key in keys[:-1]:
            node = node[key]
        node[keys[-1]] = value
    return mutate


@pytest.mark.parametrize(
    "mutate,reseal,reason",
    [
        (_set("payload.decision", "BLOCKED"), False, "digest does not match"),
        (_set("metadata.payload_sha256", "0" * 64), False, "digest does not match"),
        (_set("metadata.payload_sha256", "XYZ"), False, "digest missing"),
        (_set("report_kind", "review"), True, "not a remediation verification report"),
        (_set("payload", []), False, "not a remediation verification report"),
        (_set("payload.decision", "APPROVED"), True, "decision missing or unknown"),
        (_set("payload.exit_code", 20), True, "exit_code does not match"),
        (_set("payload.execution_mode", "local_preview"), True, "trusted_ci"),
        (_set("payload.preview_only", True), True, "trusted_ci"),
        (_set("payload.subject.head.commit", "b" * 40), True, "report head is not the event head"),
        (_set("payload.subject.head.commit", HEAD + "\nexit_code=0"), True, "report head is not the event head"),
        (_set("payload.subject.head.kind", "worktree"), True, "head is not a commit"),
        (_set("payload.subject.base.commit", "b" * 40), True, "report base is not the event base"),
        (_set("payload.trust.trusted_config_commit", "b" * 40), True, "contract not read from the base commit"),
        (_set("payload.trust.contract_path", ".iac-remediation/contracts/relaxed.yaml"), True, "another contract path"),
    ],
)
def test_a_report_that_disagrees_gives_empty_outputs_and_fails(
    tmp_path: Path, mutate: Callable[[Dict[str, Any]], None], reseal: bool, reason: str, capsys: pytest.CaptureFixture[str]
) -> None:
    rep = synthetic()
    mutate(rep)
    if reseal:
        seal(rep)
    path = write(tmp_path, rep)
    assert gout.main(env(path)) == 1
    assert read_outputs(path) == {k: "" for k in gout.OUTPUT_KEYS}
    assert reason in capsys.readouterr().err


@pytest.mark.parametrize(
    "overrides,reason",
    [
        ({"VERIFY_STATUS": "22"}, "does not match the report's decision"),
        ({"VERIFY_STATUS": "1"}, "does not match the report's decision"),
        ({"VERIFY_STATUS": ""}, "VERIFY_STATUS"),
        ({"VERIFY_STATUS": "0\nx"}, "VERIFY_STATUS"),
        ({"VERIFY_STATUS": "0\n"}, "VERIFY_STATUS"),
        ({"EXPECTED_HEAD_SHA": HEAD + "\n"}, "EXPECTED_HEAD_SHA"),
        ({"EXPECTED_HEAD_SHA": ""}, "EXPECTED_HEAD_SHA"),
        ({"EXPECTED_BASE_SHA": "main"}, "EXPECTED_BASE_SHA"),
        ({"EXPECTED_CONTRACT_PATH": ""}, "EXPECTED_CONTRACT_PATH"),
        ({"EXPECTED_HEAD_SHA": "b" * 40}, "report head is not the event head"),
    ],
)
def test_inputs_that_disagree_with_the_report_give_empty_outputs(
    tmp_path: Path, overrides: Dict[str, str], reason: str, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write(tmp_path, synthetic())
    assert gout.main(env(path, **overrides)) == 1
    assert read_outputs(path)["exit_code"] == ""
    assert reason in capsys.readouterr().err


def test_a_missing_symlinked_oversized_or_invalid_report_gives_empty_outputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = tmp_path / "out"
    out.mkdir()
    real = write(tmp_path, synthetic())
    link = out / "link.json"
    link.symlink_to(real)
    cases = {"missing": out / "absent.json", "symlink": link, "directory": out}
    for label, path in cases.items():
        e = env(real, REPORT_PATH=str(path))
        assert gout.main(e) == 1, label
    for text in ("not json", "[]", "\"x\""):
        assert gout.main(env(write(tmp_path, text))) == 1, text
    (tmp_path / "remediation-report.json").write_bytes(b"\xff\xfe")
    assert gout.main(env(tmp_path / "remediation-report.json")) == 1
    monkeypatch.setattr(gout, "MAX_REPORT_BYTES", 10)
    assert gout.main(env(write(tmp_path, synthetic()))) == 1
    assert gout.main(env(real, REPORT_PATH="")) == 1


def test_without_github_output_nothing_is_claimed(tmp_path: Path) -> None:
    path = write(tmp_path, synthetic())
    assert gout.main(env(path, GITHUB_OUTPUT="")) == 1


# ---------------------------------------------------------------------------
# Real verifier reports
# ---------------------------------------------------------------------------

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
needs_tools = pytest.mark.skipif(shutil.which("cfn-lint") is None or shutil.which("cfn-guard") is None,
                                 reason="cfn-lint / cfn-guard not installed")


def real_report(case_id: str, tmp_path: Path) -> Dict[str, Any]:
    case = next(c for c in casegen.load_cases() if c["id"] == case_id)
    s = casegen.build(case, tmp_path / case_id)
    req = verify.Request(repo=s.repo, base=s.base, head=s.head, config_rev=s.base, contract_path=s.contract_path,
                         contract_file=None, execution_mode="trusted_ci", repository_id="owner/demo")
    rep = json.loads(rreport.serialize(rreport.build_report(verify.run(req), 0.0)))
    rep["_setup"] = {"base": rep["payload"]["subject"]["base"]["commit"], "head": rep["payload"]["subject"]["head"]["commit"],
                     "contract": s.contract_path}
    return rep


def _real_env(path: Path, rep: Dict[str, Any], status: str) -> Dict[str, str]:
    return env(path, status, EXPECTED_BASE_SHA=rep["_setup"]["base"], EXPECTED_HEAD_SHA=rep["_setup"]["head"],
               EXPECTED_CONTRACT_PATH=rep["_setup"]["contract"])


@needs_git
@needs_tools
def test_a_real_verified_report_is_accepted_and_a_tampered_copy_is_not(tmp_path: Path) -> None:
    rep = real_report("C01", tmp_path)
    assert rep["payload"]["decision"] == "VERIFIED"
    setup = rep.pop("_setup")
    path = write(tmp_path, rep)
    e = _real_env(path, {"_setup": setup}, "0")
    assert gout.main(e) == 0
    assert read_outputs(path)["head_sha"] == setup["head"]
    tampered = copy.deepcopy(rep)
    tampered["payload"]["violations"] = []
    tampered["payload"]["decision"] = "VERIFIED"
    tampered["payload"]["trust"]["contract_path"] = "relaxed.yaml"
    (tmp_path / "github_output").unlink()
    assert gout.main(_real_env(write(tmp_path, tampered), {"_setup": setup}, "0")) == 1


@needs_git
def test_a_real_blocked_report_passes_blocked_through(tmp_path: Path) -> None:
    rep = real_report("C05", tmp_path)
    assert rep["payload"]["decision"] == "BLOCKED"
    setup = rep.pop("_setup")
    path = write(tmp_path, rep)
    assert gout.main(_real_env(path, {"_setup": setup}, "20")) == 20
    assert read_outputs(path)["decision"] == "BLOCKED"


# ---------------------------------------------------------------------------
# Chain: gate_outputs → publish_check
# ---------------------------------------------------------------------------


class Echo:
    def __init__(self) -> None:
        self.bodies: list = []

    def open(self, request: Any, timeout: float = 0) -> Any:
        body = json.loads(request.data.decode("utf-8"))
        self.bodies.append(body)
        data = json.dumps(dict(body, id=1, app={"id": 7})).encode("utf-8")

        class R:
            status = 201

            def read(self, limit: int = -1) -> bytes:
                return data

            def __enter__(self) -> "R":
                return self

            def __exit__(self, *exc: object) -> None:
                return None

        return R()


def publisher_env(tmp_path: Path, outputs: Dict[str, str], job_result: str) -> Dict[str, str]:
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"action": "opened", "repository": {"full_name": "owner/demo", "default_branch": "main"},
                                 "pull_request": {"head": {"sha": HEAD}, "base": {"ref": "main", "repo": {"full_name": "owner/demo"}}}}),
                     encoding="utf-8")
    return {
        "GITHUB_API_URL": "https://api.github.com", "GITHUB_SERVER_URL": "https://github.com", "GITHUB_REPOSITORY": "owner/demo",
        "GITHUB_RUN_ID": "5", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_EVENT_NAME": "pull_request_target", "GITHUB_EVENT_PATH": str(event),
        "GITHUB_REF": "refs/heads/main", "GITHUB_WORKFLOW_REF": "owner/demo/.github/workflows/remediation-gate.yml@refs/heads/main",
        "RUNNER_ENVIRONMENT": "github-hosted", "CHECK_NAME": "remediation-gate/verified", "EXPECTED_APP_ID": "7", "APP_TOKEN": "ghs_x",
        "VERIFY_JOB_RESULT": job_result, "VERIFY_EXIT_CODE": outputs["exit_code"], "VERIFY_DECISION": outputs["decision"],
        "VERIFIED_HEAD_SHA": outputs["head_sha"], "PAYLOAD_SHA256": outputs["payload_sha256"],
    }


@pytest.mark.parametrize(
    "decision,status,tamper,job_result,conclusion",
    [
        ("VERIFIED", "0", False, "success", "success"),
        ("BLOCKED", "20", False, "failure", "failure"),
        ("VERIFIED", "0", True, "failure", "failure"),
    ],
    ids=["verified", "blocked", "tampered-report"],
)
def test_the_chain_publishes_what_the_report_says(
    tmp_path: Path, decision: str, status: str, tamper: bool, job_result: str, conclusion: str, capsys: pytest.CaptureFixture[str]
) -> None:
    rep = synthetic(decision)
    if tamper:
        rep["payload"]["trust"]["contract_path"] = "relaxed.yaml"
    path = write(tmp_path, rep)
    gout.main(env(path, status))
    fake = Echo()
    assert pub.publish(publisher_env(tmp_path, read_outputs(path), job_result), opener=fake) == 0
    assert fake.bodies[0]["conclusion"] == conclusion and fake.bodies[0]["head_sha"] == HEAD
    capsys.readouterr()
