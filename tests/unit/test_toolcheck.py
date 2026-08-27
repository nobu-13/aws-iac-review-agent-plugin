"""Unit tests for :mod:`iacreview.toolcheck`.

External tools are replaced by shell scripts written into ``tmp_path`` and
``PATH`` is pointed at that directory, so the four outcomes are exercised
against a real subprocess without depending on cfn-lint, cfn-guard, or the CDK
CLI being installed:

(a) a sufficient version resolves
(b) an insufficient version raises ``ToolVersionError``
(c) an absent tool raises ``ToolUnavailableError``
(d) an unparsable banner warns and continues

Cases (b), (c), and (d) run for all three external tools, which is the
completion condition of the task: nine paths, each landing on a defined
structured error or a warning.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Callable, List

import pytest

from iacreview.errors import (
    InvalidArgumentsError,
    ToolUnavailableError,
    ToolVersionError,
)
from iacreview.toolcheck import (
    CDK,
    CFN_GUARD,
    CFN_LINT,
    PYTHON3,
    TOOL_REQUIREMENTS,
    UNKNOWN_VERSION,
    ToolInfo,
    extract_version,
    require_known_tool,
    require_tool,
    requirement_for,
)

#: Tools whose PATH resolution is checked here, with a version below and a
#: version at or above the table minimum.
TOOL_MATRIX = [
    (CFN_LINT, "0.9.1", "1.22.3"),
    (CFN_GUARD, "2.1.3", "3.1.1"),
    (CDK, "1.130.0", "2.1006.0 (build 1e9d8b1)"),
]


@pytest.fixture
def fake_tool(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Callable[..., Path]:
    """Return a factory that installs a fake executable as the only tool on PATH.

    PATH is replaced rather than prepended so that a real cfn-lint installed on
    the developer's machine cannot satisfy a test that expects the tool to be
    missing.
    """
    bindir = tmp_path / "bin"
    bindir.mkdir()
    monkeypatch.setenv("PATH", str(bindir))

    def install(name: str, banner: str, *, on_stderr: bool = False) -> Path:
        redirect = " >&2" if on_stderr else ""
        script = bindir / name
        script.write_text(
            "#!/bin/sh\nprintf '%s\\n' \"{0}\"{1}\n".format(banner, redirect)
        )
        script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)
        return script

    return install


def _require(name: str) -> ToolInfo:
    """Verify ``name`` against its table row."""
    return require_known_tool(name)


# ---------------------------------------------------------------------------
# (a) sufficient version
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name, _too_old, current", TOOL_MATRIX)
def test_sufficient_version_resolves(
    fake_tool: Callable[..., Path], name: str, _too_old: str, current: str
) -> None:
    script = fake_tool(name, "{0} {1}".format(name, current))

    info = _require(name)

    assert info.name == name
    assert info.path == str(script)
    assert info.version == current.split()[0]


def test_equal_to_minimum_is_accepted(fake_tool: Callable[..., Path]) -> None:
    fake_tool(CFN_LINT, "cfn-lint 1.0.0")

    assert _require(CFN_LINT).version == "1.0.0"


def test_two_component_version_is_padded(fake_tool: Callable[..., Path]) -> None:
    """``python3 --version`` reports 3.9.x against a table minimum of ``3.9``."""
    fake_tool(PYTHON3, "Python 3.9.6", on_stderr=True)

    assert _require(PYTHON3).version == "3.9.6"


def test_version_on_stderr_is_read(fake_tool: Callable[..., Path]) -> None:
    fake_tool(CFN_GUARD, "cfn-guard 3.1.1", on_stderr=True)

    assert _require(CFN_GUARD).version == "3.1.1"


# ---------------------------------------------------------------------------
# (b) insufficient version -> ToolVersionError
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name, too_old, _current", TOOL_MATRIX)
def test_insufficient_version_raises_tool_version_error(
    fake_tool: Callable[..., Path], name: str, too_old: str, _current: str
) -> None:
    fake_tool(name, "{0} {1}".format(name, too_old))
    minimum = requirement_for(name).min_version

    with pytest.raises(ToolVersionError) as excinfo:
        _require(name)

    error = excinfo.value
    message = error.message.lower()
    # Requirement 15 AC6: detected version, required version, upgrade steps.
    assert "detected" in message
    assert "required" in message
    assert "upgrade" in message
    assert too_old in error.message
    assert minimum in error.message

    assert error.detected_version == too_old
    assert error.required_min_version == minimum
    assert requirement_for(name).upgrade_command in (error.remediation or "")

    structured = error.to_structured_error(source=name)
    assert structured["error_class"] == "tool_version"
    assert structured["detected_version"] == too_old
    assert structured["required_min_version"] == minimum


def test_version_comparison_is_numeric_not_lexicographic(
    fake_tool: Callable[..., Path]
) -> None:
    """``"1.10.0" < "1.9.0"`` as strings, but 1.10.0 is newer than the minimum."""
    fake_tool(CFN_LINT, "cfn-lint 1.10.0")

    assert _require(CFN_LINT).version == "1.10.0"


# ---------------------------------------------------------------------------
# (c) tool absent -> ToolUnavailableError
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name, _too_old, _current", TOOL_MATRIX)
def test_missing_tool_raises_tool_unavailable_error(
    fake_tool: Callable[..., Path], name: str, _too_old: str, _current: str
) -> None:
    # Fixture emptied PATH; install a different tool so the directory exists
    # but the requested one does not.
    fake_tool("unrelated-tool", "unrelated 9.9.9")
    minimum = requirement_for(name).min_version

    with pytest.raises(ToolUnavailableError) as excinfo:
        _require(name)

    error = excinfo.value
    # Requirement 15 AC4: tool name, minimum version, installation command.
    assert name in error.message
    assert minimum in error.message
    assert error.tool == name
    assert error.required_min_version == minimum

    remediation = error.remediation or ""
    assert requirement_for(name).install_macos in remediation
    assert requirement_for(name).install_linux in remediation

    structured = error.to_structured_error(source=name)
    assert structured["error_class"] == "tool_unavailable"
    assert structured["exit_code"] is None


def test_missing_cfn_lint_remediation_names_pip_install(
    fake_tool: Callable[..., Path]
) -> None:
    """Requirement 4 AC10 asks for ``pip install cfn-lint`` specifically."""
    fake_tool("unrelated-tool", "unrelated 9.9.9")

    with pytest.raises(ToolUnavailableError) as excinfo:
        _require(CFN_LINT)

    assert "pip install cfn-lint" in (excinfo.value.remediation or "")


def test_missing_cfn_guard_remediation_references_docs(
    fake_tool: Callable[..., Path]
) -> None:
    """Requirement 5 AC5 asks for a reference to the installation docs."""
    fake_tool("unrelated-tool", "unrelated 9.9.9")

    with pytest.raises(ToolUnavailableError) as excinfo:
        _require(CFN_GUARD)

    assert requirement_for(CFN_GUARD).docs_url in (excinfo.value.remediation or "")


# ---------------------------------------------------------------------------
# (d) unparsable banner -> warning, no exception
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name, _too_old, _current", TOOL_MATRIX)
def test_unparsable_version_warns_and_continues(
    fake_tool: Callable[..., Path],
    capsys: pytest.CaptureFixture[str],
    name: str,
    _too_old: str,
    _current: str,
) -> None:
    script = fake_tool(name, "version information unavailable")

    info = _require(name)

    assert info == ToolInfo(name=name, path=str(script), version=UNKNOWN_VERSION)

    captured = capsys.readouterr()
    assert name in captured.err
    assert "warning" in captured.err
    # Determinism: diagnostics must never reach stdout (Requirement 16 AC11).
    assert captured.out == ""


def test_version_command_failure_warns_and_continues(
    fake_tool: Callable[..., Path], capsys: pytest.CaptureFixture[str]
) -> None:
    """A non-zero ``--version`` with no parsable banner is not fatal."""
    bindir = Path(os.environ["PATH"])
    script = bindir / CFN_LINT
    script.write_text("#!/bin/sh\necho 'boom' >&2\nexit 3\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)

    info = _require(CFN_LINT)

    assert info.version == UNKNOWN_VERSION
    assert "warning" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Version extraction
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "output, expected",
    [
        ("cfn-lint 1.22.3", "1.22.3"),
        ("cfn-guard 3.1.1", "3.1.1"),
        ("2.1006.0 (build 1e9d8b1)", "2.1006.0"),
        ("Python 3.9.6", "3.9.6"),
        ("3.9", "3.9"),
        ("", None),
        ("no digits here", None),
        ("v1", None),
        ("cfn-lint 1.0.0\n/usr/lib/python3.11/site-packages\n", "1.0.0"),
    ],
)
def test_extract_version(output: str, expected: str) -> None:
    assert extract_version(output) == expected


# ---------------------------------------------------------------------------
# Requirement table and argument validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name, minimum",
    [(CFN_LINT, "1.0.0"), (CFN_GUARD, "3.0.0"), (CDK, "2.0.0"), (PYTHON3, "3.9")],
)
def test_table_matches_design_minimums(name: str, minimum: str) -> None:
    assert requirement_for(name).min_version == minimum


@pytest.mark.parametrize("name", sorted(TOOL_REQUIREMENTS))
def test_table_rows_are_complete(name: str) -> None:
    requirement = TOOL_REQUIREMENTS[name]

    assert requirement.name == name
    assert requirement.version_argv[0] == name
    assert requirement.version_argv[-1] == "--version"
    for field in (
        requirement.install_macos,
        requirement.install_linux,
        requirement.upgrade_command,
        requirement.docs_url,
    ):
        assert field.strip()


def test_requirement_for_unknown_tool_is_rejected() -> None:
    with pytest.raises(InvalidArgumentsError):
        requirement_for("terraform")


@pytest.mark.parametrize(
    "name, min_version, version_argv",
    [
        ("", "1.0.0", ["cfn-lint", "--version"]),
        ("cfn lint", "1.0.0", ["cfn-lint", "--version"]),
        (CFN_LINT, "latest", [CFN_LINT, "--version"]),
    ],
)
def test_malformed_arguments_are_rejected_before_execution(
    name: str, min_version: str, version_argv: List[str]
) -> None:
    with pytest.raises(InvalidArgumentsError):
        require_tool(name, min_version, version_argv)


@pytest.mark.parametrize("version_argv", [[], [CFN_GUARD, "--version"]])
def test_version_argv_must_name_the_requested_tool(
    fake_tool: Callable[..., Path], version_argv: List[str]
) -> None:
    fake_tool(CFN_LINT, "cfn-lint 1.22.3")

    with pytest.raises(InvalidArgumentsError):
        require_tool(CFN_LINT, "1.0.0", version_argv)
