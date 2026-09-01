"""Regression: no ``errors[]`` message may carry an absolute host path.

Requirement guarded
-------------------

Requirement 16 AC11: two invocations with identical input produce byte-identical
stdout, "containing no timestamps, no absolute host paths, and no other
environment-dependent values". design.md's failure mode matrix puts a parse
failure and a non-reviewable file on stdout as a partial report, so the messages
those failures carry are stdout content and fall under AC11. steering/security.md
adds the security reading: an absolute path discloses the layout of the machine
the review ran on, to whoever receives the report.

Why this is fixed as a regression
---------------------------------

The defect was live and reached four entry points.
:class:`~iacreview.errors.TemplateParseError` and
:class:`~iacreview.errors.NotReviewableError` were built from the path the caller
passed, and every standalone Skill passes what
:func:`iacreview.pathguard.resolve_within` returns -- an absolute path, correctly
so, since that is what an external tool has to be given. A malformed Template
therefore put the host's directory layout into ``errors[].message`` on stdout.
The ``iac-review`` orchestrator did not leak, because it loads Templates by their
workspace-relative path; that difference is exactly why a per-caller fix is not
enough. One caller had already worked around it locally, three had not, and the
next caller written would have had to know.

The fix renders the path once, inside :mod:`iacreview.template`
(:func:`iacreview.source.display_path`), which is the same choice
:mod:`iacreview.proc` makes for an executable path: reduce it at the single point
that builds the message, so no call site can reintroduce it. The sweep that
followed found two more messages of the same shape -- an unreadable
``--agent-findings`` file, and an unusable cfn-guard rule sidecar -- and both are
pinned here beside the original.

Each case below asserts two things: that the message still *names* the file (a
message that identifies nothing would satisfy AC11 and help nobody), and that it
names it without an absolute path.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Tuple

import pytest

from iacreview import agentin, exitcodes, template
from iacreview.cfnguard import load_rule_metadata
from iacreview.errors import (
    InputNotFoundError,
    NotReviewableError,
    PathContainmentError,
    TemplateParseError,
)

#: Inputs whose failure message named an absolute path before the fix.
PARSE_FAILURE_FIXTURES: Tuple[str, ...] = (
    "malformed_syntax.yaml",
    "malformed_syntax.json",
    "truncated.yaml",
    "binary_content.yaml",
    "empty_file.yaml",
    "tab_indentation.yaml",
    "unsupported_yaml_tag.yaml",
    "python_object_tag.yaml",
    "bom_prefixed.json",
)

#: Inputs that parse and are still not reviewable.
NOT_REVIEWABLE_FIXTURES: Tuple[str, ...] = (
    "no_resources.yaml",
    "empty_resources.json",
)

#: The Skill whose leak was reported: it hands ``load_template`` the resolved
#: absolute path and prints a partial report for a parse failure. One subprocess
#: case is enough here, because the fix is in the shared module and
#: ``tests/integration/test_malformed_input.py`` runs the whole matrix.
LEAKING_SKILL = Path("skills") / "iam-review" / "scripts" / "run_iam_scan.py"

TIMEOUT_S = 60


def copy_fixture(name: str, fixtures_dir: Path, destination: Path) -> Path:
    """Copy ``name`` from ``tests/fixtures/invalid`` into ``destination``.

    Returned as an *absolute* path, which is the shape a caller holds after
    containment and therefore the shape that reproduced the defect. The
    destination is outside the workspace root of the test session, so a message
    that leaked would leak the temporary directory -- visible in the assertion
    below rather than hidden behind a coincidentally relative path.
    """
    target = destination / name
    target.write_bytes((fixtures_dir / "invalid" / name).read_bytes())
    return target


def assert_names_the_file_but_not_the_path(message: str, path: Path) -> None:
    """The message identifies the file without disclosing where it lives."""
    assert path.name in message, message
    assert str(path) not in message, message
    assert str(path.parent) not in message, message


@pytest.mark.parametrize("name", PARSE_FAILURE_FIXTURES)
def test_a_parse_failure_message_carries_no_absolute_path(
    name: str, fixtures_dir: Path, tmp_path: Path
) -> None:
    path = copy_fixture(name, fixtures_dir, tmp_path)

    with pytest.raises(TemplateParseError) as caught:
        template.load_template(path)

    error = caught.value
    assert_names_the_file_but_not_the_path(error.message, path)
    # The rendered StructuredError is what actually reaches stdout, so the
    # assertion is repeated against it: a future field carrying the path would
    # pass the check above and still leak.
    assert str(path) not in json.dumps(error.to_structured_error())


@pytest.mark.parametrize("name", NOT_REVIEWABLE_FIXTURES)
def test_a_not_reviewable_message_carries_no_absolute_path(
    name: str, fixtures_dir: Path, tmp_path: Path
) -> None:
    path = copy_fixture(name, fixtures_dir, tmp_path)

    with pytest.raises(NotReviewableError) as caught:
        template.load_template(path)

    assert_names_the_file_but_not_the_path(caught.value.message, path)


def test_an_unreadable_input_leaks_neither_the_path_nor_the_oserror_filename(
    tmp_path: Path,
) -> None:
    """An ``OSError`` from the open reaches ``errors[]`` without leaking the path.

    Two leaks in one message before the fix: the path this module was given, and
    the filename CPython appends to ``str(OSError)``. The errno and its text are
    kept, because they are the whole diagnostic value.

    A missing file is used, so ``os.open`` fails with ``ENOENT``: this is the
    ``input_not_found`` branch of the fd-based reader, the one that still carries
    an ``OSError`` filename to strip. (A directory now takes a different branch --
    it opens, and is refused as a non-regular file; that message is pinned
    below.)
    """
    missing = tmp_path / "templates" / "app.yaml"

    with pytest.raises(InputNotFoundError) as caught:
        template.load_template(missing)

    message = caught.value.message
    assert str(missing) not in message, message
    assert "errno" in message, message


def test_a_non_regular_file_refusal_names_no_absolute_path(
    tmp_path: Path,
) -> None:
    """A directory now opens and is refused as a non-regular file (AC6).

    The refusal is a ``path_violation`` rather than an ``input_not_found``, and
    its message names no absolute host path (Requirement 16 AC11, Requirement 17
    AC9).
    """
    directory = tmp_path / "templates"
    directory.mkdir()

    with pytest.raises(PathContainmentError) as caught:
        template.load_template(directory)

    message = caught.value.message
    assert caught.value.error_class == "path_violation"
    assert str(directory) not in message, message


def test_an_unreadable_agent_findings_file_carries_no_absolute_path(
    tmp_path: Path,
) -> None:
    """``iac-review`` records this failure in ``errors[]`` rather than raising.

    So the message is stdout content, and the same two leaks applied: the
    resolved path and the ``OSError`` filename. A directory is used because
    :func:`iacreview.pathguard.resolve_within` has already established that the
    path exists by the time this function sees it.
    """
    directory = tmp_path / "agent-findings"
    directory.mkdir()

    with pytest.raises(InputNotFoundError) as caught:
        agentin.load_agent_findings(directory)

    message = caught.value.message
    assert str(directory) not in message, message
    assert directory.name in message, message


def test_a_broken_rule_sidecar_names_the_category_not_its_directory(
    tmp_path: Path,
) -> None:
    """The cfn-guard rule metadata failure is an ``errors[]`` entry too.

    Reached with the bundled rule set, its path is the plugin's install
    directory, which is as environment-dependent as any other absolute path. The
    category directory plus the file name is what a contributor needs to find it.
    """
    category = tmp_path / "encryption"
    category.mkdir()
    (category / "r.guard").write_text("rule r { Resources exists }", encoding="utf-8")
    (category / "_meta.json").write_text("{not json", encoding="utf-8")

    (error,) = load_rule_metadata([tmp_path]).errors

    message = str(error["message"])
    assert "encryption/_meta.json" in message, message
    assert str(tmp_path) not in message, message
    assert str(tmp_path) not in str(error["remediation"]), error["remediation"]


def test_a_standalone_skill_prints_no_absolute_path_for_a_parse_failure(
    plugin_root: Path, fixtures_dir: Path, tmp_path: Path
) -> None:
    """The defect as it was reported: from outside the process, on stdout.

    The Skill runs with the workspace as its working directory, is given a
    workspace-relative ``--target``, and resolves it to an absolute path
    internally -- which is the step that used to reach stdout.
    """
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    copy_fixture("malformed_syntax.yaml", fixtures_dir, workspace)

    completed = subprocess.run(
        [
            sys.executable,
            str(plugin_root / LEAKING_SKILL),
            "--target",
            "malformed_syntax.yaml",
        ],
        cwd=str(workspace),
        env=dict(os.environ),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=TIMEOUT_S,
    )

    assert completed.returncode == exitcodes.PARSE_FAILURE, completed.stderr
    report = json.loads(completed.stdout)
    assert [entry["error_class"] for entry in report["errors"]] == ["parse_failure"]
    assert "malformed_syntax.yaml" in str(report["errors"][0]["message"])
    for absolute in (str(workspace), str(tmp_path), sys.executable):
        assert absolute not in completed.stdout


# ---------------------------------------------------------------------------
# Requirement 18 (v0.8.0): a host path in *tool stderr* must not reach the
# report's stderr_head either.
#
# The fixes above render the *plugin's own* messages without an absolute path.
# stderr_head is different: it carries untrusted text the external tool wrote,
# and a tool routinely names the file it was handed -- an absolute path in this
# plugin, because that is what a tool has to be given. Requirement 18 AC2 asks
# that such a path be redacted before it reaches the report, and AC3 that the
# result be byte-identical across runs. The redaction lives in one place,
# iacreview.errors.redact_host_paths, applied per retained line in _head_lines.
# ---------------------------------------------------------------------------

TEMPLATE_TEXT = """\
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  DataBucket:
    Type: AWS::S3::Bucket
"""


def _reproduce_cfnlint_failure_with_host_path_in_stderr(
    monkeypatch: pytest.MonkeyPatch,
    fakebin_dir: Path,
    tmp_path: Path,
) -> Tuple[dict, Path]:
    """Drive cfn-lint into a crash whose stderr names an absolute host path.

    The configurable fake writes a crash traceback that embeds the workspace's
    absolute path -- exactly the shape a real analyzer emits when it reports the
    file it failed on. ``PATH`` resolves cfn-lint only to the fake, so no
    installed tool is consulted; ``TMPDIR`` is the fake's configuration channel
    (:mod:`iacreview.proc` drops invented variables).

    Returns the single StructuredError produced and the workspace path whose
    absence from ``stderr_head`` is under test.
    """
    from iacreview import cfnlint

    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True)
    (workspace / "template.yaml").write_text(TEMPLATE_TEXT, encoding="utf-8")

    host_path = str(workspace / "template.yaml")
    config = {
        "results_text": "",
        "exit_code": 1,
        "stderr": (
            "cfn-lint: internal error while processing {0}\n"
            "Traceback (most recent call last):\n"
            "  File \"{0}\", line 1\n"
            "RuntimeError: fake cfn-lint always crashes\n".format(host_path)
        ),
    }
    config_dir = tmp_path / "cfg"
    config_dir.mkdir()
    (config_dir / "fake-cfn-lint.json").write_text(json.dumps(config), encoding="utf-8")

    monkeypatch.setenv(
        "PATH", os.pathsep.join([str(fakebin_dir), str(Path(sys.executable).parent)])
    )
    monkeypatch.setenv("TMPDIR", str(config_dir))

    result = cfnlint.run_and_normalize(
        workspace / "template.yaml", workspace_root=workspace
    )
    assert result.findings == []
    assert len(result.errors) == 1, result.errors
    return result.errors[0], workspace


def test_tool_stderr_host_path_does_not_reach_stderr_head(
    monkeypatch: pytest.MonkeyPatch, fakebin_dir: Path, tmp_path: Path
) -> None:
    """Requirement 18 AC2/AC4: the absolute path cfn-lint wrote to stderr is
    redacted before it lands in the report's ``stderr_head``."""
    error, workspace = _reproduce_cfnlint_failure_with_host_path_in_stderr(
        monkeypatch, fakebin_dir, tmp_path
    )

    assert error["error_class"] == "tool_execution"
    stderr_head = error["stderr_head"]
    assert 0 < len(stderr_head) <= 5

    joined = "\n".join(stderr_head)
    assert str(workspace) not in joined, joined
    assert str(workspace / "template.yaml") not in joined, joined
    # ``error`` is the rendered StructuredError dict -- what actually reaches
    # stdout -- so the assertion is repeated against its full serialization.
    assert str(workspace) not in json.dumps(error), error
    # The diagnostic value survives: the line still names the tool and the fault.
    assert "cfn-lint" in joined
    assert "RuntimeError" in joined


def test_redacted_stderr_head_is_byte_identical_across_two_runs(
    monkeypatch: pytest.MonkeyPatch, fakebin_dir: Path, tmp_path: Path
) -> None:
    """Requirement 18 AC3: the same tool failure yields a byte-identical
    ``stderr_head`` on a second run, carrying no environment-dependent path."""
    first, _ = _reproduce_cfnlint_failure_with_host_path_in_stderr(
        monkeypatch, fakebin_dir, tmp_path / "run1"
    )
    second, _ = _reproduce_cfnlint_failure_with_host_path_in_stderr(
        monkeypatch, fakebin_dir, tmp_path / "run2"
    )

    assert first["stderr_head"] == second["stderr_head"]
    assert json.dumps(first["stderr_head"]) == json.dumps(second["stderr_head"])


# ---------------------------------------------------------------------------
# Requirement 20 (v0.9.0): a labeled PID and a recognized timestamp in tool
# stderr must not reach the report, while a bare number a tool prints (a rule
# id, a line number) is preserved. The redaction lives in one place,
# iacreview.errors.redact_stderr_line, applied per retained line in _head_lines.
# ---------------------------------------------------------------------------


def _reproduce_cfnlint_failure_with_pid_and_timestamp_in_stderr(
    monkeypatch: pytest.MonkeyPatch,
    fakebin_dir: Path,
    tmp_path: Path,
) -> dict:
    """Drive cfn-lint into a crash whose stderr carries a labeled PID, a
    timestamp, and a bare rule id / line number that must survive.

    Same fake mechanism as the host-path reproduction: ``PATH`` resolves
    cfn-lint only to the fake, and ``TMPDIR`` is the fake's configuration
    channel.
    """
    from iacreview import cfnlint

    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True)
    (workspace / "template.yaml").write_text(TEMPLATE_TEXT, encoding="utf-8")

    config = {
        "results_text": "",
        "exit_code": 1,
        "stderr": (
            "cfn-lint worker pid 4242 crashed\n"
            "at 2026-09-01T21:25:14Z during rule E3012 on line 9\n"
            "RuntimeError: fake cfn-lint always crashes\n"
        ),
    }
    config_dir = tmp_path / "cfg"
    config_dir.mkdir()
    (config_dir / "fake-cfn-lint.json").write_text(json.dumps(config), encoding="utf-8")

    monkeypatch.setenv(
        "PATH", os.pathsep.join([str(fakebin_dir), str(Path(sys.executable).parent)])
    )
    monkeypatch.setenv("TMPDIR", str(config_dir))

    result = cfnlint.run_and_normalize(
        workspace / "template.yaml", workspace_root=workspace
    )
    assert result.findings == []
    assert len(result.errors) == 1, result.errors
    return result.errors[0]


def test_tool_stderr_pid_and_timestamp_do_not_reach_stderr_head(
    monkeypatch: pytest.MonkeyPatch, fakebin_dir: Path, tmp_path: Path
) -> None:
    """Requirement 20 AC1/AC2/AC4: the labeled PID and the ISO-8601 timestamp
    cfn-lint wrote to stderr are redacted; the bare rule id and line number are
    preserved (AC3)."""
    error = _reproduce_cfnlint_failure_with_pid_and_timestamp_in_stderr(
        monkeypatch, fakebin_dir, tmp_path
    )

    assert error["error_class"] == "tool_execution"
    joined = "\n".join(error["stderr_head"])

    # The environment-dependent values are gone.
    assert "4242" not in joined, joined
    assert "2026-09-01T21:25:14Z" not in joined, joined
    assert "<pid>" in joined
    assert "<timestamp>" in joined
    # The whole rendered StructuredError, which is what reaches stdout.
    assert "4242" not in json.dumps(error), error
    assert "2026-09-01T21:25:14Z" not in json.dumps(error), error
    # The diagnostic value survives: rule id, line number, tool name, and fault.
    assert "E3012" in joined
    assert "line 9" in joined
    assert "cfn-lint" in joined
    assert "RuntimeError" in joined


def test_redacted_pid_and_timestamp_are_byte_identical_across_two_runs(
    monkeypatch: pytest.MonkeyPatch, fakebin_dir: Path, tmp_path: Path
) -> None:
    """Requirement 20 AC4: the same failure yields a byte-identical
    ``stderr_head`` on a second run, carrying no PID and no timestamp."""
    first = _reproduce_cfnlint_failure_with_pid_and_timestamp_in_stderr(
        monkeypatch, fakebin_dir, tmp_path / "run1"
    )
    second = _reproduce_cfnlint_failure_with_pid_and_timestamp_in_stderr(
        monkeypatch, fakebin_dir, tmp_path / "run2"
    )

    assert first["stderr_head"] == second["stderr_head"]
