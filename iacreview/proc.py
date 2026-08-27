"""argv-array subprocess wrapper: the only place the plugin starts a process.

Every external tool invocation (cfn-lint, cfn-guard, ``cdk synth``) goes
through :func:`run`. Concentrating process creation here is what makes the
security properties checkable in one file rather than argued about per call
site:

``shell=False``, argv arrays
    No shell interprets the arguments, so shell metacharacters carry no special
    meaning and shell injection cannot occur (Requirement 9 AC4). There is no
    code path in this module that builds a command by string concatenation
    (Requirement 16 AC6): ``argv`` arrives as a list and is passed as a list.
    :func:`iacreview.pathguard.assert_no_shell_metacharacters` remains a
    defense-in-depth layer applied to user-supplied values by callers, not a
    substitute for this one.

``stdin=subprocess.DEVNULL``
    Child processes run non-interactively (Requirement 16 AC9). A tool that
    decides to prompt sees EOF and exits instead of hanging until the timeout.

:func:`_tool_name`
    Every error raised here names the tool by its bare executable name, never by
    the path it was resolved from. Callers pass an absolute path as ``argv[0]``
    on purpose (:attr:`iacreview.toolcheck.ToolInfo.path`, so the binary that was
    version checked is the binary that runs), and that path would otherwise reach
    ``errors[].tool`` and ``errors[].message`` in the report, where Requirement 16
    AC11 forbids an absolute host path. Stripping it here rather than in each
    Source is what makes the guarantee hold for every call site at once.

:func:`_minimal_env`
    Only an explicit allowlist of environment variables reaches the child, so
    AWS credentials present in the parent environment are not propagated. v0.1
    calls no AWS API and both external tools are static analyzers, so removing
    credentials structurally prevents an unexpected API call and prevents a
    credential value from surfacing in captured stderr (Requirement 9 AC2, AC3).

The wrapper does not sandbox the child. Once started, cfn-lint, cfn-guard, and
especially ``cdk synth`` can read and write anything the invoking user can. Path
containment applies to this process, not to its children; ``docs/security-model.md``
records that residual risk.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Optional, Sequence

from iacreview.errors import (
    InvalidArgumentsError,
    ToolExecutionError,
    ToolTimeoutError,
    ToolUnavailableError,
)

# Aliased under the private name this module has always used it by. The renderer
# itself lives in iacreview.errors because the same "no filename in the message"
# rule applies to every file this plugin fails to open, not only to an executable
# it fails to start (see iacreview.template).
from iacreview.errors import os_error_detail as _os_error_detail

__all__ = [
    "INHERITED_ENV_VARS",
    "ProcResult",
    "run",
]

#: Environment variables copied from the parent into the child, and nothing
#: else. ``AWS_REGION`` and ``AWS_DEFAULT_REGION`` are on the list because some
#: cfn-lint features need a region to resolve region-specific data; neither is
#: a credential. Every other ``AWS_*`` variable, including
#: ``AWS_ACCESS_KEY_ID``, ``AWS_SECRET_ACCESS_KEY``, ``AWS_SESSION_TOKEN`` and
#: ``AWS_PROFILE``, is dropped (design.md, "コマンド実行").
INHERITED_ENV_VARS: FrozenSet[str] = frozenset(
    {
        "PATH",
        "HOME",
        "LANG",
        "LC_ALL",
        "TMPDIR",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
    }
)


@dataclass(frozen=True)
class ProcResult:
    """Outcome of one external command execution.

    Attributes:
        exit_code: The child's exit status.
        stdout: Captured stdout, decoded as text.
        stderr: Captured stderr, decoded as text.
        timed_out: Always ``False`` on a value returned by :func:`run`, which
            raises :class:`~iacreview.errors.ToolTimeoutError` instead. The
            field exists because result interpreters such as
            ``interpret_guard_result`` accept a ``ProcResult`` describing a
            timeout, which their caller constructs after catching that
            exception. Keeping one result type avoids a parallel timeout type.
    """

    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False


def _minimal_env() -> Dict[str, str]:
    """Build the child environment from :data:`INHERITED_ENV_VARS`.

    An allowlist rather than a denylist: a denylist would silently leak any
    credential variable that AWS introduces later, or any that a wrapper tool
    invents. Variables absent from the parent environment stay absent from the
    child, so no empty-string defaults are invented.

    ``PATH`` falls back to :data:`os.defpath` when the parent has none. Without
    it the child would inherit an empty ``PATH``, which breaks tools that
    invoke helper binaries (``cdk`` locating ``node``, for example) with an
    error unrelated to the actual cause.
    """
    env = {
        name: value
        for name, value in os.environ.items()
        if name in INHERITED_ENV_VARS
    }
    if "PATH" not in env:
        env["PATH"] = os.defpath
    return env


def _tool_name(executable: str) -> str:
    """Return the bare executable name of ``executable``.

    Args:
        executable: ``argv[0]`` as the caller wrote it: either a bare name
            resolved against ``PATH``, or an absolute path to an executable.

    Returns:
        The final path component, or ``executable`` unchanged when it has none
        (a trailing separator, which cannot name an executable but should not
        turn error reporting into an empty string).

    Note:
        A bare name is returned unchanged, so this is a no-op for the callers
        that pass one. It matters for the callers that pass
        :attr:`iacreview.toolcheck.ToolInfo.path`: the report may not carry an
        absolute host path (Requirement 16 AC11).
    """
    return os.path.basename(executable) or executable


def _validate_argv(argv: Sequence[str]) -> None:
    """Reject an ``argv`` that ``subprocess`` could not accept.

    Raises:
        InvalidArgumentsError: ``argv`` is empty, is a bare string rather than
            a list of tokens, contains a non-string element, or starts with an
            empty executable name.
    """
    if isinstance(argv, (str, bytes)):
        # A bare string would be split by subprocess only under shell=True,
        # which this module never uses; passed as-is it becomes a single
        # executable name containing spaces. Reject it as a programming error
        # rather than fail later with a confusing "not found".
        raise InvalidArgumentsError("argv must be a list of tokens, not a string")
    if not argv:
        raise InvalidArgumentsError("argv must start with an executable name")
    for index, token in enumerate(argv):
        if not isinstance(token, str):
            raise InvalidArgumentsError(
                "argv[{0}] must be a string, got {1}".format(
                    index, type(token).__name__
                )
            )
    if not argv[0]:
        raise InvalidArgumentsError("argv must start with an executable name")


def run(argv: List[str], timeout_s: int) -> ProcResult:
    """Execute ``argv`` without a shell and capture its output.

    Args:
        argv: Command tokens. ``argv[0]`` is an executable name resolved
            against ``PATH``, or an absolute path to an executable. Remaining
            elements are passed to the child verbatim; they are never
            re-parsed, quoted, or joined.
        timeout_s: Wall-clock limit in whole seconds. Must be positive.

    Returns:
        A :class:`ProcResult` with ``timed_out=False``. A non-zero
        ``exit_code`` is returned, not raised: for cfn-lint and cfn-guard a
        non-zero status normally means "findings exist", and only the caller
        knows how to read the status of the tool it invoked.

    Raises:
        InvalidArgumentsError: ``argv`` is malformed or ``timeout_s`` is not
            positive.
        ToolUnavailableError: ``argv[0]`` was not found on ``PATH``
            (Requirement 15 AC4).
        ToolTimeoutError: The child exceeded ``timeout_s``. It has been killed
            and reaped before this is raised.
        ToolExecutionError: The child could not be started (not executable,
            permission denied, and similar OS-level failures).
    """
    _validate_argv(argv)
    if timeout_s <= 0:
        raise InvalidArgumentsError(
            "timeout_s must be a positive number of seconds, got {0!r}".format(
                timeout_s
            )
        )

    executable = argv[0]
    # Every error below reports this, not `executable`: a caller that passed a
    # resolved absolute path must not have it copied into the report
    # (Requirement 16 AC11). See _tool_name.
    tool = _tool_name(executable)
    # Resolving here, rather than letting subprocess raise FileNotFoundError,
    # lets a missing tool be reported as tool_unavailable with a remediation
    # instead of as an OS error. The resolved absolute path is then what gets
    # executed, so PATH is consulted exactly once.
    resolved = shutil.which(executable)
    if resolved is None:
        raise ToolUnavailableError(
            "required external tool not found on PATH: {0}".format(tool),
            tool=tool,
            remediation="Install {0} and ensure it is on PATH.".format(tool),
        )

    try:
        completed = subprocess.run(  # noqa: S603 - shell=False, argv array
            [resolved, *argv[1:]],
            shell=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            env=_minimal_env(),
            # cwd=None: inherit this process's working directory. Paths handed
            # to tools are already absolute and containment-checked, so no
            # directory change is needed and none is performed.
            cwd=None,
        )
    except subprocess.TimeoutExpired as exc:
        # subprocess.run kills the child and waits for it before re-raising, so
        # no orphan of the direct child remains. Grandchildren it spawned are
        # not tracked by CPython and may survive; that is a documented limit,
        # not something this wrapper can fix without a process group.
        raise ToolTimeoutError(
            "{0} exceeded its {1}s timeout and was terminated".format(
                tool, timeout_s
            ),
            tool=tool,
            stderr=_decode_partial(exc.stderr),
            remediation=(
                "Retry with a larger timeout, or review a smaller input."
            ),
        ) from exc
    except OSError as exc:
        # Found on PATH but unusable: not executable, a broken interpreter
        # line, a dangling symlink.
        raise ToolExecutionError(
            "failed to execute {0}: {1}".format(tool, _os_error_detail(exc)),
            tool=tool,
        ) from exc

    return ProcResult(
        exit_code=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        timed_out=False,
    )


def _decode_partial(stream: Optional[object]) -> Optional[str]:
    """Return partial output from a :class:`subprocess.TimeoutExpired` as text.

    ``text=True`` normally makes these attributes ``str``, but CPython leaves
    them as ``bytes`` on some paths. Decoding defensively keeps a timeout from
    turning into a ``TypeError`` inside error construction, where it would be
    far harder to diagnose than the timeout itself.
    """
    if stream is None:
        return None
    if isinstance(stream, bytes):
        return stream.decode("utf-8", errors="replace")
    return str(stream)
