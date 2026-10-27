"""Spike (not deployed): App-published required check, against a fake GitHub API.

Covers ``docs/v2/phase1/ci/spike/publish_check.py`` and the static shape of
``docs/v2/phase1/ci/spike/remediation-gate-app.yml``. Nothing here talks to
GitHub; the fake opener records the request instead. The redirect test uses
two local HTTP servers on 127.0.0.1.

Groups: run context (authenticity of the run), target SHA, verify outputs,
GitHub's response, transport, and the workflow's shape.
"""

from __future__ import annotations

import http.server
import importlib.util
import io
import json
import re
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SPIKE = ROOT / "docs" / "v2" / "phase1" / "ci" / "spike"
_spec = importlib.util.spec_from_file_location("spike_publish_check", SPIKE / "publish_check.py")
assert _spec is not None and _spec.loader is not None
pub = importlib.util.module_from_spec(_spec)
sys.modules["spike_publish_check"] = pub
_spec.loader.exec_module(pub)

REPO = "owner/demo"
HEAD = "a" * 40
OTHER = "b" * 40
DIGEST = "d" * 64
APP_ID = "424242"
TOKEN = "ghs_FAKEINSTALLATIONTOKEN000000000000000"
WORKFLOW_REF = REPO + "/.github/workflows/remediation-gate.yml@refs/heads/main"


def event_payload(**overrides: Any) -> Dict[str, Any]:
    event: Dict[str, Any] = {
        "action": "synchronize",
        "repository": {"full_name": REPO, "default_branch": "main"},
        "pull_request": {
            "number": 7,
            "head": {"sha": HEAD, "ref": "fix", "repo": {"full_name": "someone/fork"}},
            "base": {"sha": "c" * 40, "ref": "main", "repo": {"full_name": REPO}},
        },
    }
    for dotted, value in overrides.items():
        node = event
        keys = dotted.split("__")
        for key in keys[:-1]:
            node = node[key]
        node[keys[-1]] = value
    return event


@pytest.fixture
def event_file(tmp_path: Path) -> Path:
    path = tmp_path / "event.json"
    path.write_text(json.dumps(event_payload()), encoding="utf-8")
    return path


def env(event_path: Path, **overrides: str) -> Dict[str, str]:
    base = {
        "GITHUB_API_URL": "https://api.github.com", "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_REPOSITORY": REPO, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_EVENT_NAME": "pull_request_target", "GITHUB_EVENT_PATH": str(event_path),
        "GITHUB_REF": "refs/heads/main", "GITHUB_WORKFLOW_REF": WORKFLOW_REF, "RUNNER_ENVIRONMENT": "github-hosted",
        "VERIFY_JOB_RESULT": "success", "VERIFIED_HEAD_SHA": HEAD, "VERIFY_EXIT_CODE": "0", "VERIFY_DECISION": "VERIFIED",
        "PAYLOAD_SHA256": DIGEST, "CHECK_NAME": "remediation-gate/verified", "EXPECTED_APP_ID": APP_ID, "APP_TOKEN": TOKEN,
    }
    base.update(overrides)
    return base


class FakeResponse:
    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self._body = body

    def read(self, limit: int = -1) -> bytes:
        return self._body if limit < 0 else self._body[:limit]

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class FakeGitHub:
    """Records POSTs; echoes the request as GitHub would, or answers as told."""

    def __init__(self, status: int = 201, error: Optional[Exception] = None, app_id: Any = int(APP_ID),
                 tamper: Optional[Dict[str, Any]] = None, raw: Optional[bytes] = None) -> None:
        self.status = status
        self.error = error
        self.app_id = app_id
        self.tamper = tamper or {}
        self.raw = raw
        self.requests: List[Any] = []

    def open(self, request: Any, timeout: float = 0) -> FakeResponse:
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        if self.status >= 400:
            raise urllib.error.HTTPError(request.full_url, self.status, "error", {}, io.BytesIO(b""))  # type: ignore[arg-type]
        if self.raw is not None:
            return FakeResponse(self.status, self.raw)
        created = dict(json.loads(request.data.decode("utf-8")), id=1, app={"id": self.app_id, "slug": "remediation-gate"})
        created.update(self.tamper)
        return FakeResponse(self.status, json.dumps(created).encode("utf-8"))

    @property
    def body(self) -> Dict[str, Any]:
        return json.loads(self.requests[-1].data.decode("utf-8"))


def run(e: Dict[str, str], fake: FakeGitHub, capsys: pytest.CaptureFixture[str]) -> int:
    code = pub.publish(e, opener=fake)
    out = capsys.readouterr()
    assert TOKEN not in out.out + out.err
    return code


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_a_verified_run_publishes_success_on_the_event_head(event_file: Path, capsys: pytest.CaptureFixture[str]) -> None:
    fake = FakeGitHub()
    assert run(env(event_file), fake, capsys) == 0
    req = fake.requests[0]
    assert req.full_url == "https://api.github.com/repos/owner/demo/check-runs" and req.get_method() == "POST"
    assert req.get_header("Authorization") == "Bearer " + TOKEN
    body = fake.body
    assert body["head_sha"] == HEAD and body["conclusion"] == "success" and body["status"] == "completed"
    assert body["name"] == "remediation-gate/verified"
    assert body["external_id"] == "123.1:" + DIGEST
    assert body["details_url"] == "https://github.com/owner/demo/actions/runs/123"
    assert TOKEN not in json.dumps(body)


# ---------------------------------------------------------------------------
# Run context: anything but the base gate publishes nothing (exit 2)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        {"GITHUB_EVENT_NAME": "pull_request"},
        {"GITHUB_EVENT_NAME": "workflow_dispatch"},
        {"GITHUB_EVENT_NAME": "push"},
        {"GITHUB_EVENT_NAME": ""},
        {"GITHUB_WORKFLOW_REF": REPO + "/.github/workflows/spoof.yml@refs/heads/main"},
        {"GITHUB_WORKFLOW_REF": REPO + "/.github/workflows/remediation-gate.yml@refs/pull/7/merge"},
        {"GITHUB_WORKFLOW_REF": REPO + "/.github/workflows/remediation-gate.yml@refs/heads/fix"},
        {"GITHUB_WORKFLOW_REF": "other/repo/.github/workflows/remediation-gate.yml@refs/heads/main"},
        {"GITHUB_WORKFLOW_REF": ""},
        {"GITHUB_REF": "refs/pull/7/merge"},
        {"GITHUB_REF": "refs/heads/fix"},
        {"RUNNER_ENVIRONMENT": "self-hosted"},
        {"RUNNER_ENVIRONMENT": ""},
        {"GITHUB_REPOSITORY": "owner/other"},
    ],
)
def test_a_run_that_is_not_the_base_gate_publishes_nothing(
    event_file: Path, overrides: Dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    fake = FakeGitHub()
    assert run(env(event_file, **overrides), fake, capsys) == 2
    assert fake.requests == []


@pytest.mark.parametrize(
    "event_overrides",
    [
        {"action": "closed"},
        {"action": "edited"},
        {"repository__full_name": "owner/other"},
        {"pull_request__base__repo__full_name": "someone/fork"},
        {"pull_request__base__ref": "release"},
        {"repository__default_branch": "release"},
        {"repository__default_branch": "main\nx"},
        {"pull_request__head__sha": ""},
        {"pull_request__head__sha": HEAD.upper()},
        {"pull_request__head__sha": HEAD + "\n"},
        {"repository__default_branch": "main\n"},
        {"pull_request__head__sha": None},
    ],
)
def test_an_event_payload_that_is_not_a_pr_into_the_default_branch_publishes_nothing(
    tmp_path: Path, event_overrides: Dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "event.json"
    path.write_text(json.dumps(event_payload(**event_overrides)), encoding="utf-8")
    fake = FakeGitHub()
    assert run(env(path), fake, capsys) == 2
    assert fake.requests == []


@pytest.mark.parametrize("content", [None, b"", b"not json", b"[]", b"\xff\xfe"], ids=["missing", "empty", "text", "array", "binary"])
def test_a_missing_or_unreadable_event_payload_publishes_nothing(
    tmp_path: Path, content: Optional[bytes], capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "event.json"
    if content is not None:
        path.write_bytes(content)
    fake = FakeGitHub()
    assert run(env(path), fake, capsys) == 2
    assert fake.requests == []


def test_an_oversized_event_payload_is_not_read(event_file: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(pub, "MAX_EVENT_BYTES", 10)
    fake = FakeGitHub()
    assert run(env(event_file), fake, capsys) == 2
    assert fake.requests == []


def test_an_event_path_that_is_a_directory_publishes_nothing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    fake = FakeGitHub()
    assert run(env(tmp_path), fake, capsys) == 2
    assert fake.requests == []


# ---------------------------------------------------------------------------
# Target SHA: only the event payload's head
# ---------------------------------------------------------------------------


def test_the_check_goes_on_the_event_head_whatever_the_environment_or_outputs_say(
    event_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fake = FakeGitHub()
    # A stray EVENT_HEAD_SHA / GITHUB_SHA must not steer the target.
    assert run(env(event_file, EVENT_HEAD_SHA=OTHER, GITHUB_SHA=OTHER), fake, capsys) == 0
    assert fake.body["head_sha"] == HEAD


def test_outputs_that_verified_another_head_give_failure_on_the_event_head(event_file: Path, capsys: pytest.CaptureFixture[str]) -> None:
    fake = FakeGitHub()
    assert run(env(event_file, VERIFIED_HEAD_SHA=OTHER), fake, capsys) == 0
    assert fake.body["head_sha"] == HEAD and fake.body["conclusion"] == "failure"
    assert "problem: the verify job did not verify the event's head SHA" in fake.body["output"]["summary"]


def test_a_new_push_does_not_inherit_an_old_success(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # G7: the old run verified HEAD; the event of the new push names OTHER.
    path = tmp_path / "event.json"
    path.write_text(json.dumps(event_payload(pull_request__head__sha=OTHER)), encoding="utf-8")
    fake = FakeGitHub()
    assert run(env(path, VERIFIED_HEAD_SHA=HEAD), fake, capsys) == 0
    assert fake.body["head_sha"] == OTHER and fake.body["conclusion"] == "failure"


# ---------------------------------------------------------------------------
# Verify outputs: only a consistent VERIFIED run is success
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "overrides,reason",
    [
        ({"VERIFY_EXIT_CODE": "20", "VERIFY_DECISION": "BLOCKED", "VERIFY_JOB_RESULT": "failure"}, None),
        ({"VERIFY_EXIT_CODE": "21", "VERIFY_DECISION": "UNVERIFIED", "VERIFY_JOB_RESULT": "failure"}, None),
        ({"VERIFY_EXIT_CODE": "22", "VERIFY_DECISION": "ERROR", "VERIFY_JOB_RESULT": "failure"}, None),
        ({"VERIFY_EXIT_CODE": "20", "VERIFY_DECISION": "BLOCKED", "VERIFY_JOB_RESULT": "failure", "VERIFIED_HEAD_SHA": ""}, None),
        ({"VERIFY_EXIT_CODE": ""}, "exit code"),
        ({"VERIFY_EXIT_CODE": "0; echo"}, "exit code"),
        ({"VERIFY_EXIT_CODE": "00"}, "exit code"),
        ({"VERIFY_DECISION": ""}, "decision"),
        ({"VERIFY_DECISION": "verified"}, "decision"),
        ({"VERIFY_DECISION": "BLOCKED"}, "decision"),
        ({"VERIFY_JOB_RESULT": "cancelled"}, "job result"),
        ({"VERIFY_JOB_RESULT": "neutral"}, "job result"),
        ({"VERIFY_JOB_RESULT": ""}, "job result"),
        ({"VERIFY_JOB_RESULT": "skipped", "VERIFY_EXIT_CODE": "", "VERIFY_DECISION": "", "VERIFIED_HEAD_SHA": "", "PAYLOAD_SHA256": ""}, "exit code"),
        ({"VERIFY_JOB_RESULT": "failure"}, "job result"),
        ({"VERIFY_EXIT_CODE": "20", "VERIFY_DECISION": "BLOCKED", "VERIFY_JOB_RESULT": "success"}, "job result"),
        ({"VERIFIED_HEAD_SHA": ""}, "head SHA"),
        ({"VERIFIED_HEAD_SHA": HEAD.upper()}, "head SHA"),
        ({"PAYLOAD_SHA256": ""}, "digest"),
        ({"PAYLOAD_SHA256": "z" * 64}, "digest"),
        ({"PAYLOAD_SHA256": DIGEST + "\n"}, "digest"),
    ],
)
def test_anything_but_a_consistent_verified_run_publishes_failure(
    event_file: Path, overrides: Dict[str, str], reason: Optional[str], capsys: pytest.CaptureFixture[str]
) -> None:
    fake = FakeGitHub()
    assert run(env(event_file, **overrides), fake, capsys) == 0
    body = fake.body
    assert body["conclusion"] == "failure" and body["head_sha"] == HEAD
    if reason:
        assert "inconsistent" in body["output"]["title"]
        assert any(reason in line for line in body["output"]["summary"].splitlines() if line.startswith("problem:"))


def test_a_failure_without_a_digest_still_names_the_run(event_file: Path, capsys: pytest.CaptureFixture[str]) -> None:
    fake = FakeGitHub()
    run(env(event_file, VERIFY_JOB_RESULT="skipped", VERIFY_EXIT_CODE="", VERIFY_DECISION="", PAYLOAD_SHA256=""), fake, capsys)
    assert fake.body["external_id"] == "123.1:none"


def test_the_summary_carries_no_template_tool_or_output_text(event_file: Path, capsys: pytest.CaptureFixture[str]) -> None:
    fake = FakeGitHub()
    run(env(event_file, VERIFY_EXIT_CODE="20", VERIFY_DECISION="BLOCKED", VERIFY_JOB_RESULT="weird\nproblem: injected"), fake, capsys)
    summary = fake.body["output"]["summary"]
    assert "injected" not in summary and "weird" not in summary
    assert set(re.findall(r"^(\w[\w ]*):", summary, flags=re.M)) <= {
        "decision", "verify job", "event head", "verified head", "payload_sha256", "problem"}


@pytest.mark.parametrize(
    "overrides",
    [
        {"APP_TOKEN": ""}, {"APP_TOKEN": "a b"}, {"APP_TOKEN": "x" * 1001}, {"GITHUB_REPOSITORY": "owner/demo;rm"},
        {"CHECK_NAME": "verify\nx"}, {"CHECK_NAME": ""}, {"GITHUB_API_URL": "http://api.github.com"},
        {"GITHUB_API_URL": "https://evil.example/$(id)"}, {"GITHUB_RUN_ID": "1a"}, {"GITHUB_RUN_ATTEMPT": ""},
        {"EXPECTED_APP_ID": ""}, {"EXPECTED_APP_ID": "12a"},
        # Trailing newlines: "$" alone would accept these.
        {"GITHUB_RUN_ID": "123\n"}, {"EXPECTED_APP_ID": APP_ID + "\n"}, {"CHECK_NAME": "remediation-gate/verified\n"},
        {"GITHUB_REPOSITORY": REPO + "\n"},
    ],
)
def test_invalid_configuration_publishes_nothing(event_file: Path, overrides: Dict[str, str], capsys: pytest.CaptureFixture[str]) -> None:
    fake = FakeGitHub()
    assert run(env(event_file, **overrides), fake, capsys) == 2
    assert fake.requests == []


# ---------------------------------------------------------------------------
# Publishing and GitHub's response
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fake", [FakeGitHub(status=401), FakeGitHub(status=403), FakeGitHub(status=404), FakeGitHub(status=422),
                                  FakeGitHub(status=500), FakeGitHub(status=200), FakeGitHub(status=302),
                                  FakeGitHub(error=urllib.error.URLError("down")), FakeGitHub(error=TimeoutError())],
                         ids=["401", "403", "404", "422", "500", "200", "302", "unreachable", "timeout"])
def test_a_failed_publish_fails_the_job_so_the_required_check_stays_missing(
    event_file: Path, fake: FakeGitHub, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(env(event_file), fake, capsys) == 3


@pytest.mark.parametrize(
    "fake",
    [
        FakeGitHub(app_id=15368), FakeGitHub(app_id=None), FakeGitHub(tamper={"app": None}),
        FakeGitHub(tamper={"head_sha": OTHER}), FakeGitHub(tamper={"name": "verify"}),
        FakeGitHub(tamper={"conclusion": "failure"}), FakeGitHub(tamper={"external_id": "999.1:" + DIGEST}),
        FakeGitHub(tamper={"status": "in_progress"}), FakeGitHub(raw=b"not json"), FakeGitHub(raw=b"[]"), FakeGitHub(raw=b""),
    ],
    ids=["actions-app", "no-app-id", "no-app", "other-head", "other-name", "other-conclusion", "other-external-id",
         "not-completed", "text", "array", "empty"],
)
def test_a_response_that_does_not_confirm_the_request_is_not_success(
    event_file: Path, fake: FakeGitHub, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(env(event_file), fake, capsys) == 4


def test_an_oversized_response_is_not_parsed(event_file: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(pub, "MAX_RESPONSE_BYTES", 16)
    assert run(env(event_file), FakeGitHub(), capsys) == 4


def test_publish_uses_the_no_redirect_opener_by_default(event_file: Path, monkeypatch: pytest.MonkeyPatch,
                                                        capsys: pytest.CaptureFixture[str]) -> None:
    fake = FakeGitHub()
    monkeypatch.setattr(pub, "default_opener", lambda: fake)
    assert pub.publish(env(event_file)) == 0 and len(fake.requests) == 1
    capsys.readouterr()


class _Recorder(http.server.BaseHTTPRequestHandler):
    """Records each request; answers ``code`` with ``location`` when set, else 201."""

    hits: List[Optional[str]] = []
    code = 201
    location = ""

    def _answer(self) -> None:
        type(self).hits.append(self.headers.get("Authorization"))
        self.send_response(self.code)
        if self.location:
            self.send_header("Location", self.location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802 - http.server API
        self._answer()

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        self._answer()

    def log_message(self, *args: object) -> None:
        return None


def _serve(**attrs: Any) -> http.server.HTTPServer:
    handler = type("Handler", (_Recorder,), dict(attrs, hits=[]))
    server = http.server.HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture
def servers() -> Iterator[List[http.server.HTTPServer]]:
    started: List[http.server.HTTPServer] = []
    yield started
    for server in started:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_the_token_never_follows_a_redirect(servers: List[http.server.HTTPServer], code: int) -> None:
    target = _serve()
    redirector = _serve(code=code, location="http://127.0.0.1:{0}/stolen".format(target.server_port))
    servers.extend([target, redirector])
    request = urllib.request.Request("http://127.0.0.1:{0}/repos/x/y/check-runs".format(redirector.server_port),
                                     data=b"{}", headers={"Authorization": "Bearer " + TOKEN}, method="POST")
    with pytest.raises(urllib.error.HTTPError) as caught:
        pub.default_opener().open(request, timeout=5)
    assert caught.value.code == code
    assert len(redirector.RequestHandlerClass.hits) == 1  # type: ignore[attr-defined]
    assert target.RequestHandlerClass.hits == []  # type: ignore[attr-defined]


def test_control_a_plain_urllib_opener_would_forward_the_token(servers: List[http.server.HTTPServer]) -> None:
    # Why NoRedirect exists: urllib turns a POST + 302 into a GET to the new
    # location and copies the Authorization header.
    target = _serve()
    redirector = _serve(code=302, location="http://127.0.0.1:{0}/stolen".format(target.server_port))
    servers.extend([target, redirector])
    request = urllib.request.Request("http://127.0.0.1:{0}/x".format(redirector.server_port), data=b"{}",
                                     headers={"Authorization": "Bearer " + TOKEN}, method="POST")
    with urllib.request.build_opener().open(request, timeout=5):
        pass
    assert target.RequestHandlerClass.hits == ["Bearer " + TOKEN]  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Static shape of the prototype workflow
# ---------------------------------------------------------------------------

WF = yaml.safe_load((SPIKE / "remediation-gate-app.yml").read_text(encoding="utf-8"))
TEXT = (SPIKE / "remediation-gate-app.yml").read_text(encoding="utf-8")
VERIFY = WF["jobs"]["verify"]
PUBLISH = WF["jobs"]["publish"]


def _checkouts(job: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [s for s in job["steps"] if str(s.get("uses", "")).startswith("actions/checkout@")]


def test_the_two_pins_are_the_h_env_validator_and_an_unset_placeholder() -> None:
    assert WF["env"]["VALIDATOR_COMMIT"] == "5412a730ade13d6fe939d71cee636e280e92d4db"
    assert WF["env"]["GATE_SCRIPTS_COMMIT"] == "0" * 40
    assert WF["env"]["VALIDATOR_REPOSITORY"] == "nobu-13/aws-iac-review-agent-plugin"


def test_the_verify_job_has_no_secret_no_environment_and_read_only_token() -> None:
    assert VERIFY["permissions"] == {"contents": "read"} and WF["permissions"] == {"contents": "read"}
    assert "environment" not in VERIFY
    dumped = yaml.safe_dump(VERIFY)
    assert "secrets." not in dumped and "vars." not in dumped
    assert set(VERIFY["outputs"]) == {"exit_code", "decision", "head_sha", "payload_sha256"}
    assert all("steps.outputs.outputs." in v for v in VERIFY["outputs"].values())


def test_the_verify_outputs_come_from_the_report_not_from_the_workflow() -> None:
    step = next(s for s in VERIFY["steps"] if s.get("id") == "outputs")
    assert step["if"] == "always()"
    assert step["run"].strip() == "python3 gate-scripts/docs/v2/phase1/ci/spike/gate_outputs.py"
    assert step["env"]["EXPECTED_HEAD_SHA"] == "${{ github.event.pull_request.head.sha }}"
    verify_step = next(s for s in VERIFY["steps"] if s.get("id") == "verify")
    assert "set +e" in verify_step["run"] and 'exit "$status"' in verify_step["run"]
    assert "head_sha=" not in verify_step["run"] and "payload_sha256" not in verify_step["run"]
    gate_scripts = [c for c in _checkouts(VERIFY) if c["with"].get("path") == "gate-scripts"]
    assert len(gate_scripts) == 1 and gate_scripts[0]["with"]["ref"] == "${{ env.GATE_SCRIPTS_COMMIT }}"
    assert gate_scripts[0]["with"]["sparse-checkout"] == "docs/v2/phase1/ci/spike/gate_outputs.py"


def test_the_publisher_holds_the_key_only_in_a_protected_environment_and_runs_no_repository_code() -> None:
    assert PUBLISH["needs"] == "verify" and PUBLISH["if"] == "always()"
    assert PUBLISH["environment"] == "remediation-publisher"
    assert PUBLISH["permissions"] == {}
    checkouts = _checkouts(PUBLISH)
    assert len(checkouts) == 1
    w = checkouts[0]["with"]
    assert w["repository"] == "${{ env.VALIDATOR_REPOSITORY }}" and w["ref"] == "${{ env.GATE_SCRIPTS_COMMIT }}"
    assert w["sparse-checkout"] == "docs/v2/phase1/ci/spike/publish_check.py" and w["persist-credentials"] is False
    token = next(s for s in PUBLISH["steps"] if str(s.get("uses", "")).startswith("actions/create-github-app-token@"))
    assert token["with"]["permission-checks"] == "write"
    assert set(k for k in token["with"] if k.startswith("permission-")) == {"permission-checks"}
    assert "owner" not in token["with"] and "repositories" not in token["with"]
    assert "secrets.REMEDIATION_APP_PRIVATE_KEY" in str(token["with"]["private-key"])
    publish = PUBLISH["steps"][-1]
    assert "${{" not in publish["run"]
    assert publish["env"]["CHECK_NAME"] == "remediation-gate/verified"
    assert publish["env"]["EXPECTED_APP_ID"] == "${{ vars.REMEDIATION_APP_ID }}"
    # The target SHA is read from the event payload by the script, not passed in.
    assert not any("head.sha" in str(v) for v in publish["env"].values())
    assert "token" not in yaml.safe_dump(PUBLISH.get("outputs", {}))


def test_the_secret_is_referenced_only_by_the_token_step() -> None:
    assert TEXT.count("secrets.") == 1


def test_every_action_is_pinned_and_no_pr_head_is_checked_out() -> None:
    for job in (VERIFY, PUBLISH):
        for step in job["steps"]:
            if "uses" in step:
                assert re.match(r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$", step["uses"]), step["uses"]
    assert "head.ref" not in TEXT and "pull_request.title" not in TEXT and "pull_request.body" not in TEXT
    refs = [str(s.get("with", {}).get("ref", "")) for job in (VERIFY, PUBLISH) for s in job["steps"]]
    assert not any("head.sha" in r for r in refs)
    assert set(WF.get("on", WF.get(True))) == {"pull_request_target"}
    assert "allow-unsafe-pr-checkout" not in TEXT
