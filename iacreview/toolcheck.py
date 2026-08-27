"""PATH resolution and minimum-version verification for external tools.

Requirement 15 AC4 and AC6 ask for two specific error reports, and this module
is the only place that produces them:

absent from ``PATH``
    :class:`~iacreview.errors.ToolUnavailableError` carrying the tool name, the
    minimum version required, and the installation command for the host OS.

present but too old
    :class:`~iacreview.errors.ToolVersionError` carrying the detected version,
    the required version, and the upgrade command.

A third outcome exists and is deliberately *not* an error: the tool answered
``--version`` with something no version number could be read from. Refusing to
run in that case would make the plugin unusable against a tool build whose
banner format changed, which is a far more likely event than an actually
unsupported version. So an unparsable banner produces a warning on **stderr**
(never stdout, which must stay byte-stable per Requirement 16 AC11) and the
review continues with :data:`UNKNOWN_VERSION` recorded on the
:class:`ToolInfo`. design.md's error table takes the same position: version
problems are recorded and reported, they do not abort the pipeline.

:data:`TOOL_REQUIREMENTS` holds design.md's minimum version table (Portability
Design, "外部ツールの最低バージョン") as data rather than as prose duplicated
across Skills, so the README, the error messages, and the actual check cannot
drift apart.

Version comparison is a tuple comparison over ``(major, minor, patch)``
integers, not a string comparison: ``"0.9.1" < "1.0.0"`` happens to hold
lexicographically while ``"1.10.0" < "1.9.0"`` also holds, which is wrong. No
dependency on ``packaging`` is taken for this; pre-release and epoch handling
would be unused here, and the tools in the table all report plain dotted
numbers.
"""

from __future__ import annotations

import re
import shutil
import sys
from dataclasses import dataclass
from types import MappingProxyType
from typing import List, Mapping, Optional, Sequence, Tuple

from iacreview import proc
from iacreview.errors import (
    InvalidArgumentsError,
    ToolExecutionError,
    ToolTimeoutError,
    ToolUnavailableError,
    ToolVersionError,
)

__all__ = [
    "CFN_LINT",
    "CFN_GUARD",
    "CDK",
    "PYTHON3",
    "UNKNOWN_VERSION",
    "VERSION_CHECK_TIMEOUT_S",
    "VERSION_PATTERN",
    "ToolInfo",
    "ToolRequirement",
    "TOOL_REQUIREMENTS",
    "extract_version",
    "requirement_for",
    "require_tool",
    "require_known_tool",
]

#: Canonical executable names, so call sites and the table agree on spelling.
CFN_LINT = "cfn-lint"
CFN_GUARD = "cfn-guard"
CDK = "cdk"
PYTHON3 = "python3"

#: Recorded as :attr:`ToolInfo.version` when the ``--version`` output could not
#: be parsed. A sentinel string rather than ``None`` keeps the field a ``str``
#: as design.md specifies, and keeps it safe to interpolate into a report.
UNKNOWN_VERSION = "unknown"

#: Timeout for a ``--version`` invocation. Generous for a banner print, short
#: enough that a hung tool does not consume the per-template budget
#: (Requirement 5 AC1: 60 seconds per template for the tool run itself).
VERSION_CHECK_TIMEOUT_S = 10

#: Version number as it appears in a tool banner: ``1.0`` or ``1.0.0``. The
#: group is non-capturing so :meth:`re.Match.group` (with no argument) yields
#: the whole version rather than only the patch part.
VERSION_PATTERN = re.compile(r"\d+\.\d+(?:\.\d+)?")


@dataclass(frozen=True)
class ToolInfo:
    """A resolved, version-checked external tool.

    Attributes:
        name: Executable name as requested, for example ``"cfn-lint"``.
        path: Absolute path the name resolved to on ``PATH``. Callers pass this
            to :func:`iacreview.proc.run` so the binary that was version
            checked is the binary that runs, even if ``PATH`` changes in
            between.
        version: Detected version string, or :data:`UNKNOWN_VERSION` when the
            banner was unparsable.
    """

    name: str
    path: str
    version: str


@dataclass(frozen=True)
class ToolRequirement:
    """One row of design.md's minimum version table.

    Attributes:
        name: Executable name resolved against ``PATH`` (Requirement 15 AC1:
            resolved by name, never bundled inside the plugin).
        min_version: Lowest supported version, dotted numeric.
        version_argv: Full detection command, ``argv[0]`` included.
        install_macos: Installation command for macOS.
        install_linux: Installation command for Linux.
        upgrade_command: Command that raises an existing install to a newer
            version. Reported by :class:`~iacreview.errors.ToolVersionError`
            (Requirement 15 AC6 asks for upgrade instructions specifically, not
            just install instructions).
        docs_url: Upstream documentation, included in remediation text for the
            tools whose installation is not a single command on every distro.
    """

    name: str
    min_version: str
    version_argv: Tuple[str, ...]
    install_macos: str
    install_linux: str
    upgrade_command: str
    docs_url: str


#: design.md, Portability Design / "外部ツールの最低バージョン" (Requirement 10
#: AC6). PyYAML is absent on purpose: it is a Python import, not a ``PATH``
#: lookup, so it is verified where it is imported rather than here.
#:
#: ``cdk`` is required only for ``--confirm-cdk-synth``; it being listed here
#: does not make it a mandatory dependency of the core review flow
#: (Requirement 10 AC1).
TOOL_REQUIREMENTS: Mapping[str, ToolRequirement] = MappingProxyType(
    {
        CFN_LINT: ToolRequirement(
            name=CFN_LINT,
            # 1.0.0: the series in which the JSON output ``Rule`` object shape
            # is stable, and in which both ``--include-checks`` and
            # ``--non-zero-exit-code`` exist (design.md, cfn-lint Integration).
            min_version="1.0.0",
            version_argv=(CFN_LINT, "--version"),
            install_macos="pip install cfn-lint",
            install_linux="pip install cfn-lint",
            upgrade_command="pip install --upgrade cfn-lint",
            docs_url="https://github.com/aws-cloudformation/cfn-lint",
        ),
        CFN_GUARD: ToolRequirement(
            name=CFN_GUARD,
            min_version="3.0.0",
            version_argv=(CFN_GUARD, "--version"),
            install_macos="brew install cloudformation-guard",
            install_linux="cargo install cfn-guard",
            upgrade_command="cargo install --force cfn-guard",
            docs_url=(
                "https://github.com/aws-cloudformation/cloudformation-guard"
                "#installation"
            ),
        ),
        CDK: ToolRequirement(
            name=CDK,
            min_version="2.0.0",
            version_argv=(CDK, "--version"),
            install_macos="npm install -g aws-cdk",
            install_linux="npm install -g aws-cdk",
            upgrade_command="npm install -g aws-cdk@latest",
            docs_url="https://docs.aws.amazon.com/cdk/v2/guide/getting_started.html",
        ),
        PYTHON3: ToolRequirement(
            name=PYTHON3,
            min_version="3.9",
            version_argv=(PYTHON3, "--version"),
            install_macos="brew install python@3.11",
            install_linux="use the distribution package manager, or pyenv",
            upgrade_command="brew upgrade python (macOS), or use pyenv",
            docs_url="https://www.python.org/downloads/",
        ),
    }
)


def _warn(message: str) -> None:
    """Emit a warning on stderr.

    stdout carries the report and must stay byte-identical between runs
    (Requirement 16 AC11), so diagnostics never go there.
    """
    print("warning: {0}".format(message), file=sys.stderr)


def extract_version(output: str) -> Optional[str]:
    """Return the first version number found in a ``--version`` output.

    Lines are scanned in order and the first line containing a match wins.
    Scanning per line rather than over the whole blob keeps an interpreter path
    such as ``/usr/lib/python3.11/site-packages/...`` on a later line from
    being mistaken for the tool's own version.

    Args:
        output: Captured stdout or stderr of the detection command.

    Returns:
        The matched version string, or ``None`` if no line held one.
    """
    if not output:
        return None
    for line in output.splitlines():
        match = VERSION_PATTERN.search(line)
        if match is not None:
            return match.group()
    return None


def _version_tuple(version: str) -> Tuple[int, int, int]:
    """Parse a dotted version into a comparable ``(major, minor, patch)``.

    A missing patch component becomes ``0``, so ``"3.9"`` and ``"3.9.0"``
    compare equal. That is what the table needs: Python 3 is specified as
    ``3.9`` and ``python3 --version`` reports ``3.9.6``.

    Raises:
        InvalidArgumentsError: ``version`` holds no dotted numeric version.
            Reserved for a caller passing a bad ``min_version``; a bad value
            read from tool output is handled as an unparsable banner instead.
    """
    match = VERSION_PATTERN.search(version)
    if match is None:
        raise InvalidArgumentsError(
            "not a dotted numeric version: {0!r}".format(version)
        )
    parts = [int(part) for part in match.group().split(".")]
    while len(parts) < 3:
        parts.append(0)
    return (parts[0], parts[1], parts[2])


def _install_hint(requirement: Optional[ToolRequirement], name: str) -> str:
    """Render the installation guidance for a missing tool.

    Both OS variants are always shown. The plugin does not branch on
    :data:`sys.platform` here because the message is also read in reports and
    logs that get shared across machines, and a single-OS hint would be
    misleading there.
    """
    if requirement is None:
        return "Install {0} and ensure it is on PATH.".format(name)
    return (
        "Install {name} {min_version} or newer, then ensure it is on PATH. "
        "macOS: {macos}. Linux: {linux}. See {docs}".format(
            name=requirement.name,
            min_version=requirement.min_version,
            macos=requirement.install_macos,
            linux=requirement.install_linux,
            docs=requirement.docs_url,
        )
    )


def _upgrade_hint(requirement: Optional[ToolRequirement], name: str) -> str:
    """Render the upgrade guidance for a too-old tool (Requirement 15 AC6)."""
    if requirement is None:
        return "Upgrade {0} to a supported version.".format(name)
    return "Upgrade {0} with: {1}. See {2}".format(
        requirement.name, requirement.upgrade_command, requirement.docs_url
    )


def _unavailable_error(
    name: str, min_version: str, requirement: Optional[ToolRequirement]
) -> ToolUnavailableError:
    """Build the Requirement 15 AC4 error: name + minimum version + install command."""
    return ToolUnavailableError(
        "{0} was not found on PATH. required minimum version {1}. "
        "install with: {2}".format(
            name,
            min_version,
            requirement.install_linux if requirement is not None else "see the docs",
        ),
        tool=name,
        required_min_version=min_version,
        remediation=_install_hint(requirement, name),
    )


def _validate_version_argv(name: str, version_argv: Sequence[str]) -> List[str]:
    """Check the detection command and return its arguments after ``argv[0]``.

    ``argv[0]`` is dropped by the caller in favour of the already-resolved
    absolute path, but it is still validated so that a caller passing a
    detection command for a *different* tool is caught rather than silently
    version checking the wrong binary.

    Raises:
        InvalidArgumentsError: ``version_argv`` is empty, is a bare string, or
            names something other than ``name``.
    """
    if isinstance(version_argv, (str, bytes)):
        raise InvalidArgumentsError(
            "version_argv must be a list of tokens, not a string"
        )
    if not version_argv:
        raise InvalidArgumentsError(
            "version_argv must start with the executable name: {0}".format(name)
        )
    if version_argv[0] != name:
        raise InvalidArgumentsError(
            "version_argv[0] must be {0!r}, got {1!r}".format(name, version_argv[0])
        )
    return list(version_argv[1:])


def _detect_version(
    name: str,
    resolved_path: str,
    version_argv: Sequence[str],
    min_version: str,
    requirement: Optional[ToolRequirement],
) -> Optional[str]:
    """Run the detection command and read a version out of its output.

    Returns:
        The detected version string, or ``None`` when it could not be
        determined. Every ``None`` path emits a warning first, so a silent
        skip of the version check is not possible.

    Raises:
        ToolUnavailableError: The tool disappeared from ``PATH`` between the
            resolution and this call.
    """
    arguments = _validate_version_argv(name, version_argv)
    # The resolved absolute path, not the bare name: PATH is consulted once, in
    # require_tool, so the version reported here belongs to the binary the
    # caller will actually execute.
    argv = [resolved_path, *arguments]

    try:
        result = proc.run(argv, timeout_s=VERSION_CHECK_TIMEOUT_S)
    except ToolUnavailableError as exc:
        # A TOCTOU race: which() found it, exec did not. Re-raise with the
        # table's remediation rather than proc's generic one.
        raise _unavailable_error(name, min_version, requirement) from exc
    except (ToolTimeoutError, ToolExecutionError) as exc:
        # The tool exists. Failing the review because its banner could not be
        # obtained would be a worse outcome than running unverified.
        _warn(
            "could not determine {0} version ({1}); continuing without the "
            "version check. minimum supported version is {2}".format(
                name, exc.message, min_version
            )
        )
        return None

    # stdout first, then stderr: most tools print the banner on stdout, but
    # some (python3 before 3.4, and several Node-based CLIs on error paths) use
    # stderr. A non-zero exit code is not treated as fatal here for the same
    # reason: the banner may still be present and usable.
    detected = extract_version(result.stdout) or extract_version(result.stderr)
    if detected is None:
        _warn(
            "could not parse a version from `{0} {1}` (exit code {2}); "
            "continuing without the version check. minimum supported version "
            "is {3}".format(
                name, " ".join(arguments), result.exit_code, min_version
            )
        )
    return detected


def require_tool(name: str, min_version: str, version_argv: List[str]) -> ToolInfo:
    """Resolve ``name`` on ``PATH`` and verify it meets ``min_version``.

    Args:
        name: Executable name, a single token. Resolved against ``PATH``
            (Requirement 15 AC1); no binary is bundled with the plugin.
        min_version: Lowest acceptable version, dotted numeric such as
            ``"1.0.0"``.
        version_argv: Detection command including ``argv[0]``, for example
            ``["cfn-lint", "--version"]``.

    Returns:
        A :class:`ToolInfo`. Its ``version`` is :data:`UNKNOWN_VERSION` when the
        banner could not be parsed; a warning was written to stderr in that
        case and the caller may proceed.

    Raises:
        InvalidArgumentsError: ``name`` is empty or not a single token,
            ``min_version`` is not a dotted numeric version, or ``version_argv``
            is malformed.
        ToolUnavailableError: ``name`` is not on ``PATH`` (Requirement 15 AC4).
        ToolVersionError: The detected version is below ``min_version``
            (Requirement 15 AC6).
    """
    if not name or not name.strip() or len(name.split()) != 1:
        raise InvalidArgumentsError(
            "tool name must be a single non-empty token, got {0!r}".format(name)
        )

    requirement = TOOL_REQUIREMENTS.get(name)
    # Parsed up front: a malformed minimum is a programming error and should
    # surface before any subprocess runs.
    required = _version_tuple(min_version)

    resolved = shutil.which(name)
    if resolved is None:
        raise _unavailable_error(name, min_version, requirement)

    detected = _detect_version(name, resolved, version_argv, min_version, requirement)
    if detected is None:
        return ToolInfo(name=name, path=resolved, version=UNKNOWN_VERSION)

    if _version_tuple(detected) < required:
        raise ToolVersionError(
            "{0}: detected version {1}, required minimum {2}. "
            "upgrade with: {3}".format(
                name,
                detected,
                min_version,
                requirement.upgrade_command
                if requirement is not None
                else "a supported release",
            ),
            tool=name,
            detected_version=detected,
            required_min_version=min_version,
            remediation=_upgrade_hint(requirement, name),
        )

    return ToolInfo(name=name, path=resolved, version=detected)


def requirement_for(name: str) -> ToolRequirement:
    """Return the :data:`TOOL_REQUIREMENTS` row for ``name``.

    Raises:
        InvalidArgumentsError: ``name`` has no row. This is a programming error,
            not a user-facing condition: the table is the closed set of tools
            the plugin knows how to check.
    """
    requirement = TOOL_REQUIREMENTS.get(name)
    if requirement is None:
        raise InvalidArgumentsError(
            "no minimum version is defined for tool {0!r}; known tools: {1}".format(
                name, ", ".join(sorted(TOOL_REQUIREMENTS))
            )
        )
    return requirement


def require_known_tool(name: str) -> ToolInfo:
    """Verify a tool using its :data:`TOOL_REQUIREMENTS` row.

    The intended entry point for Sources (``cfnlint``, ``cfnguard``, the CDK
    synth path), so no call site restates a minimum version.

    Raises:
        InvalidArgumentsError: ``name`` is not in the table.
        ToolUnavailableError: ``name`` is not on ``PATH``.
        ToolVersionError: The detected version is below the table minimum.
    """
    requirement = requirement_for(name)
    return require_tool(
        requirement.name,
        requirement.min_version,
        list(requirement.version_argv),
    )
