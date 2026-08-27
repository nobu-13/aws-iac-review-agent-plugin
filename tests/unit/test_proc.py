"""Tests for the argv-array subprocess wrapper.

The five cases required by tasks.md 4.1 are covered: successful execution, a
missing executable, a timeout, non-propagation of AWS credentials, and
inheritance of ``AWS_REGION``. Two further cases assert behaviour the
requirements state directly: stdin is closed (Requirement 16 AC9) and a
non-zero exit status is returned rather than raised, because for cfn-lint and
cfn-guard it means "findings exist".

Two later cases cover Requirement 16 AC11 at this level: an ``argv[0]`` that is an
absolute path -- which is what every Source passes, so the version-checked binary
is the one that runs -- must be reported by its bare name, and the exec-failure
branch must describe the errno rather than ``str(exc)``, which carries the
filename. ``tests/integration/test_tool_unavailable.py`` asserts the same property
across the whole tool matrix; these two pin it where it is implemented.

``python3`` is used as the child process because it is the one interpreter the
plugin already requires, so no fake binary is needed to observe the child's
environment.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from iacreview import proc
from iacreview.errors import (
    InvalidArgumentsError,
    ToolTimeoutError,
    ToolUnavailableError,
)

PYTHON = "python3"

#: Child program that writes one ``NAME=VALUE`` line per environment variable.
DUMP_ENV = "import os\nfor k, v in os.environ.items():\n    print(k + '=' + v)\n"

pytestmark = pytest.mark.skipif(
    shutil.which(PYTHON) is None,
    reason="python3 is not on PATH; the child process cannot be started",
)


def _child_env(result: proc.ProcResult) -> dict:
    """Parse the output of :data:`DUMP_ENV` back into a dict."""
    env = {}
    for line in result.stdout.splitlines():
        name, _, value = line.partition("=")
        env[name] = value
    return env


# --- (a) successful execution -----------------------------------------------


def test_successful_execution_returns_stdout_and_zero_exit() -> None:
    result = proc.run([PYTHON, "-c", "print(1)"], timeout_s=30)

    assert result.exit_code == 0
    assert result.stdout.strip() == "1"
    assert result.stderr == ""
    assert result.timed_out is False


# --- (b) missing executable -------------------------------------------------


def test_missing_executable_raises_tool_unavailable() -> None:
    with pytest.raises(ToolUnavailableError) as excinfo:
        proc.run(["iacreview-no-such-tool-9f3a", "--version"], timeout_s=30)

    error = excinfo.value
    assert error.tool == "iacreview-no-such-tool-9f3a"
    assert error.error_class == "tool_unavailable"
    # No process ran, so no observed tool exit code exists (design.md,
    # StructuredError example).
    assert error.to_structured_error()["exit_code"] is None


# --- (c) timeout ------------------------------------------------------------


def test_timeout_raises_tool_timeout() -> None:
    with pytest.raises(ToolTimeoutError) as excinfo:
        proc.run([PYTHON, "-c", "import time;time.sleep(5)"], timeout_s=1)

    assert excinfo.value.tool == PYTHON
    assert excinfo.value.error_class == "tool_timeout"


# --- Requirement 16 AC11: no absolute host path in a reported failure -------


def test_an_absolute_argv0_is_reported_by_its_bare_name() -> None:
    """Callers pass a resolved absolute path; the error may not repeat it.

    :func:`iacreview.toolcheck.require_known_tool` hands Sources a
    :class:`~iacreview.toolcheck.ToolInfo` whose ``path`` becomes ``argv[0]``, so
    that the binary that was version checked is the binary that runs. Reporting
    that path would put the host's directory layout into ``errors[].tool`` and
    ``errors[].message``, which Requirement 16 AC11 forbids.
    """
    interpreter = shutil.which(PYTHON)
    assert interpreter is not None and Path(interpreter).is_absolute()

    with pytest.raises(ToolTimeoutError) as excinfo:
        proc.run(
            [interpreter, "-c", "import time;time.sleep(5)"], timeout_s=1
        )

    error = excinfo.value
    assert error.tool == Path(interpreter).name
    assert interpreter not in error.message


@pytest.mark.parametrize(
    "exc,expected",
    [
        pytest.param(
            OSError(2, "No such file or directory", "/private/tmp/bin/cfn-lint"),
            "errno 2: No such file or directory",
            id="errno-and-message",
        ),
        pytest.param(OSError(), "OSError", id="neither"),
    ],
)
def test_os_error_detail_describes_the_failure_without_the_filename(
    exc: OSError, expected: str
) -> None:
    """The exec failure branch renders the errno, never ``str(exc)``.

    ``str(OSError)`` appends the offending filename, which for this module is the
    absolute path of the executable. The second case is the platform that
    supplies neither an errno nor a message: the class name is reported so the
    message never degrades to an empty string.
    """
    detail = proc._os_error_detail(exc)

    assert detail == expected
    assert "cfn-lint" not in detail


# --- (d) AWS credentials are not propagated ---------------------------------


def test_aws_credentials_are_not_propagated_to_the_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "EXAMPLE_ACCESS_KEY_PLACEHOLDER")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "EXAMPLE_SECRET_KEY_PLACEHOLDER")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "EXAMPLE_SESSION_TOKEN_PLACEHOLDER")
    monkeypatch.setenv("AWS_PROFILE", "example-profile")

    result = proc.run([PYTHON, "-c", DUMP_ENV], timeout_s=30)
    child_env = _child_env(result)

    assert result.exit_code == 0
    for dropped in (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_PROFILE",
    ):
        assert dropped not in child_env
    # Not just the names: no credential value reaches the child under any name.
    assert "PLACEHOLDER" not in result.stdout


def test_no_unallowlisted_parent_var_reaches_the_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("IACREVIEW_UNRELATED_VAR", "leaked")
    monkeypatch.setenv("AWS_ENDPOINT_URL", "https://example.invalid")

    # What the wrapper hands to the child, before the child's own startup adds
    # anything. On macOS the ``python3`` shim injects SDKROOT, CPATH and others
    # into its own environment, so the child's view is not a reliable place to
    # assert the allowlist is exhaustive; this is.
    assert set(proc._minimal_env()) <= set(proc.INHERITED_ENV_VARS) | {"PATH"}

    child_env = _child_env(proc.run([PYTHON, "-c", DUMP_ENV], timeout_s=30))

    assert "IACREVIEW_UNRELATED_VAR" not in child_env
    # AWS_* beyond the two region variables is dropped as a class, not by name.
    aws_vars = {name for name in child_env if name.startswith("AWS_")}
    assert aws_vars <= {"AWS_REGION", "AWS_DEFAULT_REGION"}


# --- (e) AWS_REGION is inherited --------------------------------------------


def test_aws_region_is_inherited(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_REGION", "ap-northeast-1")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")

    child_env = _child_env(proc.run([PYTHON, "-c", DUMP_ENV], timeout_s=30))

    assert child_env["AWS_REGION"] == "ap-northeast-1"
    assert child_env["AWS_DEFAULT_REGION"] == "us-east-1"


# --- Requirement 16 AC9: non-interactive execution --------------------------


def test_child_stdin_is_closed() -> None:
    result = proc.run(
        [PYTHON, "-c", "import sys;print(repr(sys.stdin.read()))"], timeout_s=30
    )

    assert result.exit_code == 0
    assert result.stdout.strip() == "''"


# --- Non-zero exit is data, not an error ------------------------------------


def test_non_zero_exit_is_returned_not_raised() -> None:
    result = proc.run(
        [PYTHON, "-c", "import sys;sys.stderr.write('boom\\n');sys.exit(3)"],
        timeout_s=30,
    )

    assert result.exit_code == 3
    assert "boom" in result.stderr


# --- Argument validation ----------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        pytest.param([], id="empty"),
        pytest.param([""], id="empty-executable-name"),
        pytest.param("python3 -c print(1)", id="bare-string"),
        pytest.param([PYTHON, 1], id="non-string-token"),
    ],
)
def test_malformed_argv_raises_invalid_arguments(argv: object) -> None:
    with pytest.raises(InvalidArgumentsError):
        proc.run(argv, timeout_s=30)  # type: ignore[arg-type]


@pytest.mark.parametrize("timeout_s", [0, -1])
def test_non_positive_timeout_raises_invalid_arguments(timeout_s: int) -> None:
    with pytest.raises(InvalidArgumentsError):
        proc.run([PYTHON, "-c", "print(1)"], timeout_s=timeout_s)
