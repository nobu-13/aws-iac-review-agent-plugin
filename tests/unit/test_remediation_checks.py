"""Phase 1 check adapters: version pins, tool states, strict Guard envelope, bounded runs."""

from __future__ import annotations

import json
import shutil
import stat
import sys
import time
from pathlib import Path

import pytest

from iacreview import proc
from iacreview.errors import InvalidArgumentsError, ToolUnavailableError
from iacreview.remediation import checks, rschema

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "iacreview/remediation/profiles/dynamodb-billing-mode-v1/rules.guard"


def script(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def tool(path: Path, name: str, version: str) -> checks.ToolIdentity:
    return checks.ToolIdentity(name, version, version, "PASS", str(path))


# ---------------------------------------------------------------------------
# proc.run_bounded
# ---------------------------------------------------------------------------


def test_run_bounded_captures_bytes_and_exit_code() -> None:
    result = proc.run_bounded([sys.executable, "-c", "import sys;sys.stdout.write('o');sys.stderr.write('e');sys.exit(3)"], 30, 1024)
    assert (result.exit_code, result.stdout, result.stderr, result.timed_out, result.output_exceeded) == (3, b"o", b"e", False, False)


def test_run_bounded_kills_on_output_limit() -> None:
    result = proc.run_bounded([sys.executable, "-c", "import sys\nwhile True: sys.stdout.write('x'*65536)"], 30, 200_000)
    assert result.output_exceeded and result.exit_code is None
    assert len(result.stdout) <= 200_000


def test_run_bounded_kills_the_group_on_timeout(tmp_path: Path) -> None:
    marker = tmp_path / "grandchild-alive"
    child = "import time,pathlib\ntime.sleep(3)\npathlib.Path({0!r}).write_text('x')\n".format(str(marker))
    code = "import subprocess,sys,time\nsubprocess.Popen([sys.executable,'-c',{0!r}])\ntime.sleep(60)\n".format(child)
    started = time.monotonic()
    result = proc.run_bounded([sys.executable, "-c", code], 1, 1024)
    assert result.timed_out and result.exit_code is None
    assert time.monotonic() - started < 10
    time.sleep(4)
    assert not marker.exists()


def test_run_bounded_rejects_bad_arguments() -> None:
    with pytest.raises(InvalidArgumentsError):
        proc.run_bounded("echo hi", 1, 1)  # type: ignore[arg-type]
    with pytest.raises(InvalidArgumentsError):
        proc.run_bounded(["echo"], 0, 1)
    with pytest.raises(InvalidArgumentsError):
        proc.run_bounded(["echo"], 1, True)  # type: ignore[arg-type]
    with pytest.raises(ToolUnavailableError):
        proc.run_bounded(["iacreview-no-such-tool-9f3a"], 1, 1)


def test_run_bounded_does_not_pass_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "zqx-CANARY-7f3c9a")
    result = proc.run_bounded([sys.executable, "-c", "import os,json;print(json.dumps(sorted(os.environ)))"], 30, 65536)
    assert "AWS_SECRET_ACCESS_KEY" not in json.loads(result.stdout)


# ---------------------------------------------------------------------------
# Version pins
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body,state,observed",
    [
        ("echo 'cfn-guard 3.2.1'\n", "PASS", "3.2.1"),
        ("echo 'cfn-guard 3.2.0'\n", "VERSION_MISMATCH", "3.2.0"),
        ("echo 'no version here'\n", "OUTPUT_INVALID", None),
        ("exit 4\n", "FAILED", None),
    ],
)
def test_identify_requires_the_exact_pinned_version(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str, state: str, observed) -> None:
    script(tmp_path, "cfn-guard", body)
    monkeypatch.setenv("PATH", str(tmp_path))
    identity = checks.identify("cfn-guard", "3.2.1")
    assert (identity.state, identity.observed_version) == (state, observed)


def test_identify_reports_a_missing_tool(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", str(tmp_path))
    assert checks.identify("cfn-lint", "1.46.0").state == "TOOL_UNAVAILABLE"


# ---------------------------------------------------------------------------
# Guard envelope
# ---------------------------------------------------------------------------


def record(**overrides) -> bytes:
    base = {"name": "x", "metadata": {}, "status": "PASS", "not_compliant": [], "not_applicable": [], "compliant": ["a_rule"]}
    base.update(overrides)
    return json.dumps(base).encode()


@pytest.mark.parametrize(
    "raw,expected",
    [
        (record(), (set(), {"a_rule"}, set())),
        (record(status="FAIL", compliant=[], not_compliant=[{"Rule": {"name": "a_rule", "checks": []}}]), ({"a_rule"}, set(), set())),
        (record(status="SKIP", compliant=[], not_applicable=["a_rule"]), (set(), set(), {"a_rule"})),
        (record(status="PASS", compliant=[]), (set(), set(), set())),
    ],
)
def test_guard_envelope_accepts_consistent_records(raw: bytes, expected) -> None:
    assert checks.parse_guard_record(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"Validation PASS",
        record(status="FAIL"),
        record(status="PASS", compliant=[], not_compliant=[{"Rule": {"name": "a_rule"}}]),
        record(status="WEIRD"),
        record(extra=1),
        record(compliant=["Not A Rule"]),
        record(compliant="a_rule"),
        record(not_compliant=[{"Rule": {"name": 1}}], status="FAIL"),
        record() + record(),
        b'{"name":"x","name":"y","metadata":{},"status":"PASS","not_compliant":[],"not_applicable":[],"compliant":["a"]}',
    ],
    ids=["empty", "text", "fail-without-rule", "pass-with-failure", "status", "extra-key", "bad-name", "not-a-list", "name-type", "two-records", "duplicate-key"],
)
def test_guard_envelope_rejects_anything_else(raw: bytes) -> None:
    assert checks.parse_guard_record(raw) is None


def test_projection_always_has_a_target_and_is_canonical() -> None:
    assert json.loads(checks.projection({"Resources": {}}, "T", {})) == {"Params": {}, "Target": {}}
    a = checks.projection({"Resources": {"T": {"b": 1, "a": 2}}}, "T", {"p": "v"})
    assert a == b'{"Params":{"p":"v"},"Target":{"a":2,"b":1}}'


def test_projection_refuses_values_json_cannot_hold() -> None:
    import datetime

    with pytest.raises(TypeError):
        checks.projection({"Resources": {"T": {"d": datetime.datetime(2026, 1, 1)}}}, "T", {})


# ---------------------------------------------------------------------------
# Tool runs with fake executables
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body,state",
    [
        ("echo '[]'\nexit 0\n", "PASS"),
        ("echo '[]'\nexit 2\n", "OUTPUT_INVALID"),
        ("echo 'not json'\nexit 0\n", "OUTPUT_INVALID"),
        ("exit 1\n", "FAILED"),
        ("kill -9 $$\n", "FAILED"),
        ("exec /bin/sleep 20\n", "TIMEOUT"),
    ],
)
def test_cfn_lint_states(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str, state: str) -> None:
    # A short timeout only for the case that is meant to time out: under a
    # loaded full run a fake tool can take more than a couple of seconds to start.
    monkeypatch.setenv(checks.TIMEOUT_OVERRIDE_ENV, "2" if state == "TIMEOUT" else "45")
    path = script(tmp_path, "cfn-lint", body)
    run = checks.run_cfn_lint(tool(path, "cfn-lint", "1.46.0"), b"Resources: {}\n", "yaml", "head")
    assert run.state == state


def test_cfn_lint_error_level_is_a_fail(tmp_path: Path) -> None:
    payload = [{"Rule": {"Id": "E3638"}, "Level": "Error", "Message": "zqx-CANARY-7f3c9a", "Location": {"Path": ["Resources"]}, "Filename": "x"}]
    path = script(tmp_path, "cfn-lint", "cat <<'EOF'\n{0}\nEOF\nexit 2\n".format(json.dumps(payload)))
    run = checks.run_cfn_lint(tool(path, "cfn-lint", "1.46.0"), b"Resources: {}\n", "yaml", "head")
    assert run.state == "FAIL"
    assert run.rule_ids == ("E3638",)
    assert "zqx-CANARY" not in json.dumps(run.as_dict())


def test_guard_exit_codes_outside_0_and_19_are_failures(tmp_path: Path) -> None:
    path = script(tmp_path, "cfn-guard", "exit 5\n")
    run = checks.run_guard(tool(path, "cfn-guard", "3.2.1"), RULES, b"{}", ["billing_mode_consistent"], "head")
    assert run.state == "FAILED"
    assert checks.rule_state(run, "billing_mode_consistent") == "FAILED"


def test_a_tool_that_is_not_pass_is_not_run(tmp_path: Path) -> None:
    missing = checks.ToolIdentity("cfn-guard", "3.2.1", None, "TOOL_UNAVAILABLE")
    run = checks.run_guard(missing, RULES, b"{}", ["billing_mode_consistent"], "head")
    assert run.state == "TOOL_UNAVAILABLE"
    assert checks.rule_state(run, "billing_mode_consistent") == "TOOL_UNAVAILABLE"


@pytest.mark.parametrize("value,expected", [("", 60), ("5", 5), ("600", 60), ("0", 60), ("-1", 60), ("abc", 60)])
def test_the_timeout_override_can_only_lower(monkeypatch: pytest.MonkeyPatch, value: str, expected: int) -> None:
    monkeypatch.setenv(checks.TIMEOUT_OVERRIDE_ENV, value)
    assert checks.check_timeout_s() == expected
    assert rschema.CHECK_TIMEOUT_S == 60 and rschema.CHECK_MAX_OUTPUT_BYTES == 8 * 1024 * 1024


@pytest.mark.skipif(shutil.which("cfn-guard") is None, reason="cfn-guard is not installed")
def test_real_guard_on_the_sc01_rule_gives_fail_then_pass() -> None:
    real = checks.identify("cfn-guard", "3.2.1")
    if real.state != "PASS":
        pytest.skip("cfn-guard is not the pinned version")
    bad = {"Resources": {"T": {"Type": "AWS::DynamoDB::Table", "Properties": {"BillingMode": "PAY_PER_REQUEST", "ProvisionedThroughput": {}}}}}
    good = {"Resources": {"T": {"Type": "AWS::DynamoDB::Table", "Properties": {"BillingMode": "PAY_PER_REQUEST"}}}}
    for doc, state in ((bad, "FAIL"), (good, "PASS"), ({"Resources": {}}, "FAIL")):
        run = checks.run_guard(real, RULES, checks.projection(doc, "T", {}), ["billing_mode_consistent"], "head")
        assert checks.rule_state(run, "billing_mode_consistent") == state
