"""Spike (not deployed): App-published required check, against a fake GitHub API.

Covers ``docs/v2/phase1/ci/spike/publish_check.py`` and the static shape of
``docs/v2/phase1/ci/spike/remediation-gate-app.yml``. Nothing here talks to
GitHub; the fake opener records the request instead.
"""

from __future__ import annotations

import importlib.util
import io
import json
import re
import sys
import urllib.error
from pathlib import Path
from typing import Any, Dict, List

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SPIKE = ROOT / "docs" / "v2" / "phase1" / "ci" / "spike"
_spec = importlib.util.spec_from_file_location("spike_publish_check", SPIKE / "publish_check.py")
assert _spec is not None and _spec.loader is not None
pub = importlib.util.module_from_spec(_spec)
sys.modules["spike_publish_check"] = pub
_spec.loader.exec_module(pub)

HEAD = "a" * 40
DIGEST = "d" * 64
TOKEN = "ghs_FAKEINSTALLATIONTOKEN000000000000000"


def env(**overrides: str) -> Dict[str, str]:
    base = {
        "GITHUB_API_URL": "https://api.github.com", "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_REPOSITORY": "owner/demo", "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
        "EVENT_HEAD_SHA": HEAD, "VERIFY_JOB_RESULT": "success", "VERIFIED_HEAD_SHA": HEAD,
        "VERIFY_EXIT_CODE": "0", "PAYLOAD_SHA256": DIGEST, "CHECK_NAME": "remediation-gate/verified", "APP_TOKEN": TOKEN,
    }
    base.update(overrides)
    return base


class FakeResponse:
    def __init__(self, status: int) -> None:
        self.status = status

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class FakeGitHub:
    """Records POSTs; answers with a fixed status or raises like urllib does."""

    def __init__(self, status: int = 201, error: Exception = None) -> None:
        self.status = status
        self.error = error
        self.requests: List[Any] = []

    def open(self, request: Any, timeout: float = 0) -> FakeResponse:
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        if self.status >= 400:
            raise urllib.error.HTTPError(request.full_url, self.status, "error", {}, io.BytesIO(b""))
        return FakeResponse(self.status)

    @property
    def body(self) -> Dict[str, Any]:
        return json.loads(self.requests[-1].data.decode("utf-8"))


def run(e: Dict[str, str], fake: FakeGitHub, capsys: pytest.CaptureFixture[str]) -> int:
    code = pub.publish(e, opener=fake)
    out = capsys.readouterr()
    assert TOKEN not in out.out + out.err
    return code


def test_a_verified_run_publishes_success_on_the_event_head(capsys: pytest.CaptureFixture[str]) -> None:
    fake = FakeGitHub()
    assert run(env(), fake, capsys) == 0
    req = fake.requests[0]
    assert req.full_url == "https://api.github.com/repos/owner/demo/check-runs" and req.get_method() == "POST"
    assert req.get_header("Authorization") == "Bearer " + TOKEN
    body = fake.body
    assert body["head_sha"] == HEAD and body["conclusion"] == "success" and body["status"] == "completed"
    assert body["name"] == "remediation-gate/verified"
    assert body["external_id"] == "123.1:" + DIGEST
    assert body["details_url"] == "https://github.com/owner/demo/actions/runs/123"
    assert TOKEN not in json.dumps(body)


@pytest.mark.parametrize(
    "overrides,reason",
    [
        ({"VERIFY_EXIT_CODE": "20", "VERIFY_JOB_RESULT": "failure"}, None),
        ({"VERIFY_EXIT_CODE": "21", "VERIFY_JOB_RESULT": "failure"}, None),
        ({"VERIFY_EXIT_CODE": "22", "VERIFY_JOB_RESULT": "failure"}, None),
        ({"VERIFY_EXIT_CODE": ""}, "exit code"),
        ({"VERIFY_EXIT_CODE": "0; echo"}, "exit code"),
        ({"VERIFY_JOB_RESULT": "cancelled"}, "job result"),
        ({"VERIFY_JOB_RESULT": "skipped", "VERIFY_EXIT_CODE": "", "VERIFIED_HEAD_SHA": "", "PAYLOAD_SHA256": ""}, "exit code"),
        ({"VERIFY_JOB_RESULT": "failure"}, "job result"),
        ({"VERIFY_EXIT_CODE": "20", "VERIFY_JOB_RESULT": "success"}, "job result"),
        ({"VERIFIED_HEAD_SHA": "b" * 40}, "head SHA"),
        ({"VERIFIED_HEAD_SHA": ""}, "head SHA"),
        ({"PAYLOAD_SHA256": ""}, "digest"),
        ({"PAYLOAD_SHA256": "z" * 64}, "digest"),
    ],
)
def test_anything_but_a_consistent_verified_run_publishes_failure(
    overrides: Dict[str, str], reason: str, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = FakeGitHub()
    assert run(env(**overrides), fake, capsys) == 0
    body = fake.body
    assert body["conclusion"] == "failure" and body["head_sha"] == HEAD
    if reason:
        assert "inconsistent" in body["output"]["title"]
        assert any(reason in line for line in body["output"]["summary"].splitlines() if line.startswith("problem:"))


@pytest.mark.parametrize(
    "overrides",
    [
        {"APP_TOKEN": ""}, {"APP_TOKEN": "a b"}, {"EVENT_HEAD_SHA": "HEAD"}, {"GITHUB_REPOSITORY": "owner/demo;rm"},
        {"CHECK_NAME": "verify\nx"}, {"CHECK_NAME": ""}, {"GITHUB_API_URL": "http://api.github.com"},
        {"GITHUB_API_URL": "https://evil.example/$(id)"}, {"GITHUB_RUN_ID": "1a"},
    ],
)
def test_invalid_configuration_publishes_nothing(overrides: Dict[str, str], capsys: pytest.CaptureFixture[str]) -> None:
    fake = FakeGitHub()
    assert run(env(**overrides), fake, capsys) == 2
    assert fake.requests == []


@pytest.mark.parametrize("fake", [FakeGitHub(status=403), FakeGitHub(status=422), FakeGitHub(status=500), FakeGitHub(status=200),
                                  FakeGitHub(error=urllib.error.URLError("down"))], ids=["403", "422", "500", "200", "unreachable"])
def test_a_failed_publish_fails_the_job_so_the_required_check_stays_missing(fake: FakeGitHub, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(env(), fake, capsys) == 3


def test_the_summary_carries_no_template_or_tool_text(capsys: pytest.CaptureFixture[str]) -> None:
    fake = FakeGitHub()
    run(env(VERIFY_EXIT_CODE="20", VERIFY_JOB_RESULT="failure"), fake, capsys)
    summary = fake.body["output"]["summary"]
    assert set(re.findall(r"^(\w[\w ]*):", summary, flags=re.M)) <= {"decision", "verify job", "verified head", "payload_sha256", "problem"}


# ---------------------------------------------------------------------------
# Static shape of the prototype workflow
# ---------------------------------------------------------------------------

WF = yaml.safe_load((SPIKE / "remediation-gate-app.yml").read_text(encoding="utf-8"))
TEXT = (SPIKE / "remediation-gate-app.yml").read_text(encoding="utf-8")
VERIFY = WF["jobs"]["verify"]
PUBLISH = WF["jobs"]["publish"]


def test_the_verify_job_has_no_secret_no_environment_and_read_only_token() -> None:
    assert VERIFY["permissions"] == {"contents": "read"}
    assert "environment" not in VERIFY
    assert "secrets." not in yaml.safe_dump(VERIFY) and "vars." not in yaml.safe_dump(VERIFY)
    assert set(VERIFY["outputs"]) == {"exit_code", "head_sha", "payload_sha256"}


def test_the_publisher_holds_the_key_only_in_a_protected_environment_and_runs_no_repository_code() -> None:
    assert PUBLISH["needs"] == "verify" and PUBLISH["if"] == "always()"
    assert PUBLISH["environment"] == "remediation-publisher"
    assert PUBLISH["permissions"] == {}
    checkouts = [s for s in PUBLISH["steps"] if str(s.get("uses", "")).startswith("actions/checkout@")]
    assert len(checkouts) == 1
    w = checkouts[0]["with"]
    assert w["repository"] == "nobu-13/aws-iac-review-agent-plugin" and re.match(r"^[0-9a-f]{40}$", w["ref"])
    assert w["sparse-checkout"] == "docs/v2/phase1/ci/spike/publish_check.py" and w["persist-credentials"] is False
    token = next(s for s in PUBLISH["steps"] if str(s.get("uses", "")).startswith("actions/create-github-app-token@"))
    assert token["with"]["permission-checks"] == "write"
    assert set(k for k in token["with"] if k.startswith("permission-")) == {"permission-checks"}
    assert "secrets.REMEDIATION_APP_PRIVATE_KEY" in str(token["with"]["private-key"])
    publish = PUBLISH["steps"][-1]
    assert "${{" not in publish["run"]
    assert publish["env"]["CHECK_NAME"] != "verify"


def test_every_action_is_pinned_and_no_pr_head_is_checked_out() -> None:
    for job in (VERIFY, PUBLISH):
        for step in job["steps"]:
            if "uses" in step:
                assert re.match(r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$", step["uses"]), step["uses"]
    assert "head.ref" not in TEXT and "pull_request.title" not in TEXT
    refs = [str(s.get("with", {}).get("ref", "")) for job in (VERIFY, PUBLISH) for s in job["steps"]]
    assert not any("head.sha" in r for r in refs)
    assert set(WF.get("on", WF.get(True))) == {"pull_request_target"}
