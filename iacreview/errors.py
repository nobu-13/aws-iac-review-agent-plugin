"""Exception hierarchy and StructuredError construction.

Every failure inside the plugin travels through one of the exceptions defined
here, and every one of them renders to the same dict shape via
:meth:`IacReviewError.to_structured_error`. That single shape is what makes
Requirement 12 AC7 (structured error instead of an unhandled exception) and
AC8 (structured error for malformed input) satisfiable by one mechanism rather
than by ad hoc dicts scattered across modules.

Two different exit codes exist in this module and they must not be confused:

``IacReviewError.exit_code`` (``ClassVar``)
    The *process* exit status an entry-point script returns when the exception
    reaches ``main()``. Values come from :mod:`iacreview.exitcodes`.

``to_structured_error()["exit_code"]``
    The exit status *observed from an external tool*, or ``None`` when no
    external process ran. design.md's StructuredError example shows ``null``
    here for a ``tool_unavailable`` error even though that class exits the
    process with 5, because the tool was never executed. It is carried on the
    instance as ``tool_exit_code``.

``stderr_head`` is capped at the first 5 lines of external tool stderr
(Requirement 15 AC7). The cap also bounds how much untrusted tool output, which
may include fragments of the reviewed template, can reach the report.
"""

from __future__ import annotations

import re
from typing import ClassVar, FrozenSet, List, Optional, Pattern, Sequence, Tuple

from iacreview import exitcodes

__all__ = [
    "ERROR_CLASSES",
    "STRUCTURED_ERROR_KEYS",
    "STDERR_HEAD_MAX_LINES",
    "HOST_PATH_PLACEHOLDER",
    "os_error_detail",
    "redact_host_paths",
    "IacReviewError",
    "InvalidArgumentsError",
    "InputNotFoundError",
    "InputTooLargeError",
    "TemplateParseError",
    "ToolUnavailableError",
    "ToolVersionError",
    "ToolExecutionError",
    "ToolTimeoutError",
    "PathContainmentError",
    "UnsafeArgumentError",
    "NotReviewableError",
    "SchemaViolationError",
    "MappingFileError",
    "ERROR_CLASS_HIERARCHY",
]

#: Closed set of permitted ``error_class`` values (design.md, StructuredError
#: schema). Consumers may switch on these strings, so the set is part of the
#: output contract. Note it holds 12 values while 13 exception classes exist:
#: ``InvalidArgumentsError`` / ``UnsafeArgumentError`` both report
#: ``invalid_arguments``, since an unsafe argument is an argument validation
#: failure from the caller's point of view.
#:
#: ``input_too_large`` (v0.8.0, Requirement 17 AC1/AC2/AC9) is distinct from
#: ``input_not_found``: the file exists and is readable, but the plugin refuses
#: to load it because its size, or the aggregate size of a directory target,
#: exceeds a documented limit. Keeping it separate lets a consumer tell a
#: read-refusal apart from a missing file.
ERROR_CLASSES: FrozenSet[str] = frozenset(
    {
        "invalid_arguments",
        "input_not_found",
        "input_too_large",
        "parse_failure",
        "tool_unavailable",
        "tool_version",
        "tool_execution",
        "tool_timeout",
        "path_violation",
        "no_reviewable_template",
        "schema_violation",
        "unexpected",
    }
)

#: Keys every StructuredError carries, always all of them. A fixed key set lets
#: report consumers index without existence checks and keeps the serialized
#: output byte-stable (Requirement 16 AC11).
STRUCTURED_ERROR_KEYS: Tuple[str, ...] = (
    "error_class",
    "source",
    "tool",
    "exit_code",
    "message",
    "required_min_version",
    "detected_version",
    "remediation",
    "stderr_head",
)

#: Maximum number of external tool stderr lines copied into a StructuredError.
STDERR_HEAD_MAX_LINES = 5

#: Fixed string every redacted absolute host path collapses to. Constant, not a
#: per-path derivation, so a redacted ``stderr_head`` is byte-identical across
#: runs of the same input (Requirement 18 AC3).
HOST_PATH_PLACEHOLDER = "<path>"

#: Matches a POSIX absolute-path-like token: a ``/`` that *begins* a path -- it
#: is not preceded by a path-segment character (a word char, ``.``, ``-``, or
#: another ``/``) -- followed by one or more non-whitespace characters, so it
#: carries at least one segment.
#:
#: The negative lookbehind is what distinguishes a leading ``/`` from a
#: mid-token one. It leaves relative fragments intact (``and/or``, ``read/write``
#: -- the slash follows a letter) and a lone arithmetic ``/`` intact (a space
#: follows, so ``\S+`` cannot match), while still catching a path embedded in
#: the punctuation a tool wraps it in: ``open('/etc/passwd')`` and
#: ``File "/opt/tool/x.py"`` redact because a quote is not a path-segment
#: character. Trailing punctuation is captured with the token and collapses into
#: the placeholder, which over-redacts by a character or two -- preferred over
#: leaking a host path (steering/security.md, "判断が付かない場合は伏せる側に倒す").
_HOST_PATH_TOKEN: Pattern[str] = re.compile(r"(?<![\w./-])/\S+")


def os_error_detail(exc: OSError) -> str:
    """Describe an :class:`OSError` without the filename it carries.

    ``str(exc)`` appends the offending filename -- an absolute path in every
    place this plugin opens a file -- and those messages reach ``errors[]`` on
    stdout, where Requirement 16 AC11 forbids one. The errno and its message
    hold the whole diagnostic value: the caller named the file itself and
    already knows which one it asked about.

    Args:
        exc: The failure raised by an ``open``, ``read``, or ``exec`` attempt.

    Returns:
        ``"errno 13: Permission denied"``, or the exception's class name when the
        platform supplied neither an errno nor a message, so the detail never
        degrades to an empty string.
    """
    parts: List[str] = []
    if exc.errno is not None:
        parts.append("errno {0}".format(exc.errno))
    if exc.strerror:
        parts.append(exc.strerror)
    if not parts:
        parts.append(type(exc).__name__)
    return ": ".join(parts)


def redact_host_paths(line: str) -> str:
    """Replace absolute-path-like tokens in ``line`` with :data:`HOST_PATH_PLACEHOLDER`.

    External tool stderr is untrusted output that routinely names the files it
    was handed, and in this plugin those are absolute paths (an external tool
    has to be given one). Copying such a line verbatim into ``stderr_head`` would
    disclose the reviewing machine's directory layout and make the report
    environment-dependent, which Requirement 16 AC11 and Requirement 18 AC2/AC3
    forbid. This is the single place that redaction happens; callers apply it per
    retained line rather than reimplementing the pattern.

    Only a ``/`` that *begins* a path is redacted: it must not be preceded by a
    path-segment character (a word char, ``.``, ``-``, or another ``/``), and it
    must be followed by at least one more non-whitespace character. Relative
    fragments (``and/or``, ``read/write``) and a bare arithmetic ``/`` are left
    untouched, while a genuine path is redacted whole -- including one wrapped in
    the quotes or parens a tool emits (``open('/etc/passwd')``,
    ``File "/opt/x.py"``). When the token is ambiguous, redaction wins: leaking a
    host path is worse than collapsing a ``/foo/bar`` string that was never a
    path (steering/security.md, "判断が付かない場合は伏せる側に倒す"). The scope is
    absolute POSIX paths; PIDs and timestamps are out of scope for v0.8.0.

    Args:
        line: One line of captured tool stderr, already stripped of its ending.

    Returns:
        The line with every absolute-path-like token replaced by
        ``<path>`` and the rest of the text left intact. A line with no such
        token is returned unchanged, so the function is safe to apply to every
        retained line.
    """
    return _HOST_PATH_TOKEN.sub(HOST_PATH_PLACEHOLDER, line)


def _head_lines(stderr: Optional[str]) -> List[str]:
    """Return the first :data:`STDERR_HEAD_MAX_LINES` lines of ``stderr``, redacted.

    ``None`` and the empty string both yield an empty list, so the
    ``stderr_head`` key is a list in every StructuredError. Line endings are
    dropped; ``splitlines`` also handles ``\\r\\n`` from tools running on
    Windows.

    Redaction is applied *after* truncating to :data:`STDERR_HEAD_MAX_LINES`, to
    each retained line, so that no absolute host path survives into the report.
    This reconciles Requirement 15 AC7 (report the first 5 stderr lines) with
    Requirement 16 AC11 / Requirement 18 AC2 (byte-identical output, no absolute
    host path). Truncating first keeps the redaction cost bounded by the cap
    rather than by the full stderr size.
    """
    if not stderr:
        return []
    return [redact_host_paths(line) for line in stderr.splitlines()[:STDERR_HEAD_MAX_LINES]]


class IacReviewError(Exception):
    """Base class for every failure the plugin raises deliberately.

    Entry points catch this type to map a failure onto :attr:`exit_code`, and
    catch bare ``Exception`` separately to return
    :data:`iacreview.exitcodes.UNEXPECTED`. Raising this base class directly is
    allowed and reports as ``unexpected``; prefer a subclass whenever the
    failure has a known class.
    """

    error_class: ClassVar[str] = "unexpected"
    exit_code: ClassVar[int] = exitcodes.UNEXPECTED

    def __init__(
        self,
        message: str,
        *,
        tool: Optional[str] = None,
        tool_exit_code: Optional[int] = None,
        required_min_version: Optional[str] = None,
        detected_version: Optional[str] = None,
        remediation: Optional[str] = None,
        stderr: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.tool = tool
        self.tool_exit_code = tool_exit_code
        self.required_min_version = required_min_version
        self.detected_version = detected_version
        self.remediation = remediation
        self.stderr_head: List[str] = _head_lines(stderr)

    def to_structured_error(self, source: str | None = None) -> dict[str, object]:
        """Render the exception as a StructuredError dict.

        Args:
            source: Name of the review Source that produced the failure (for
                example ``"cfn-lint"``). ``None`` when the failure happened
                outside a Source, such as during argument validation.

        Returns:
            A dict whose keys are exactly :data:`STRUCTURED_ERROR_KEYS`.

        Raises:
            ValueError: If :attr:`error_class` is outside
                :data:`ERROR_CLASSES`. This guards against a new subclass
                introducing a value that report consumers cannot interpret.
        """
        if self.error_class not in ERROR_CLASSES:
            raise ValueError(
                "{0}.error_class is not a permitted value: {1!r}".format(
                    type(self).__name__, self.error_class
                )
            )
        return {
            "error_class": self.error_class,
            "source": source,
            "tool": self.tool,
            "exit_code": self.tool_exit_code,
            "message": self.message,
            "required_min_version": self.required_min_version,
            "detected_version": self.detected_version,
            "remediation": self.remediation,
            # Copied so a caller mutating the report cannot alter the
            # exception, and vice versa.
            "stderr_head": list(self.stderr_head),
        }


class InvalidArgumentsError(IacReviewError):
    """Missing argument, unknown flag, or otherwise unusable argv."""

    error_class: ClassVar[str] = "invalid_arguments"
    exit_code: ClassVar[int] = exitcodes.INVALID_ARGUMENTS


class InputNotFoundError(IacReviewError):
    """Input path does not exist or cannot be read."""

    error_class: ClassVar[str] = "input_not_found"
    exit_code: ClassVar[int] = exitcodes.INPUT_NOT_FOUND


class InputTooLargeError(IacReviewError):
    """Input exceeds a documented size limit and is refused without reading.

    Raised when a single Template file is larger than
    :data:`iacreview.template.MAX_TEMPLATE_BYTES`, or when the aggregate size of
    the Templates read from a directory target exceeds the orchestration layer's
    ``MAX_AGGREGATE_BYTES`` (Requirement 17 AC1, AC2). It is a read-refusal
    rather than a missing file, so it shares :data:`INPUT_NOT_FOUND
    <iacreview.exitcodes.INPUT_NOT_FOUND>`'s exit code while reporting the
    distinct ``input_too_large`` error class (AC9). The message never names an
    absolute host path (Requirement 16 AC11).
    """

    error_class: ClassVar[str] = "input_too_large"
    exit_code: ClassVar[int] = exitcodes.INPUT_NOT_FOUND


class TemplateParseError(IacReviewError):
    """Input could not be parsed as YAML or JSON.

    Requirement 3 AC6 asks for the parse error *type* and the *line* and
    *column* at which parsing failed, which no other failure mode carries. They
    live on the instance rather than in the StructuredError dict: the dict's key
    set is a fixed output contract (:data:`STRUCTURED_ERROR_KEYS`) that report
    consumers index without existence checks, so widening it for one exception
    class would change the shape of every other error too. Callers that need the
    position read the attributes and place them where the report defines them.

    All three default to ``None`` so that ``TemplateParseError("...")`` still
    works for callers that have no position to report; :mod:`iacreview.template`
    always fills them in, substituting :data:`~iacreview.template.DEFAULT_LINE`
    and :data:`~iacreview.template.DEFAULT_COLUMN` when the underlying parser
    gives no mark.
    """

    error_class: ClassVar[str] = "parse_failure"
    exit_code: ClassVar[int] = exitcodes.PARSE_FAILURE

    def __init__(
        self,
        message: str,
        *,
        error_type: Optional[str] = None,
        line: Optional[int] = None,
        column: Optional[int] = None,
        tool: Optional[str] = None,
        tool_exit_code: Optional[int] = None,
        required_min_version: Optional[str] = None,
        detected_version: Optional[str] = None,
        remediation: Optional[str] = None,
        stderr: Optional[str] = None,
    ) -> None:
        super().__init__(
            message,
            tool=tool,
            tool_exit_code=tool_exit_code,
            required_min_version=required_min_version,
            detected_version=detected_version,
            remediation=remediation,
            stderr=stderr,
        )
        self.error_type = error_type
        self.line = line
        self.column = column


class ToolUnavailableError(IacReviewError):
    """A required external tool is absent from PATH (Requirement 15 AC4)."""

    error_class: ClassVar[str] = "tool_unavailable"
    exit_code: ClassVar[int] = exitcodes.TOOL_UNAVAILABLE


class ToolVersionError(IacReviewError):
    """External tool found but older than the minimum (Requirement 15 AC6)."""

    error_class: ClassVar[str] = "tool_version"
    exit_code: ClassVar[int] = exitcodes.TOOL_UNAVAILABLE


class ToolExecutionError(IacReviewError):
    """External tool ran and failed for reasons other than rule violations."""

    error_class: ClassVar[str] = "tool_execution"
    exit_code: ClassVar[int] = exitcodes.TOOL_EXECUTION_FAILURE


class ToolTimeoutError(IacReviewError):
    """External tool exceeded its timeout and was killed."""

    error_class: ClassVar[str] = "tool_timeout"
    exit_code: ClassVar[int] = exitcodes.TOOL_EXECUTION_FAILURE


class PathContainmentError(IacReviewError):
    """A resolved path escapes the workspace root or the plugin root."""

    error_class: ClassVar[str] = "path_violation"
    exit_code: ClassVar[int] = exitcodes.PATH_VIOLATION


class UnsafeArgumentError(IacReviewError):
    """A user-supplied value contains a shell metacharacter.

    Reported as ``invalid_arguments`` because the value is rejected during
    argument validation; it is never sanitized and reused.
    """

    error_class: ClassVar[str] = "invalid_arguments"
    exit_code: ClassVar[int] = exitcodes.INVALID_ARGUMENTS


class NotReviewableError(IacReviewError):
    """Input parsed but holds nothing reviewable (no ``Resources`` mapping)."""

    error_class: ClassVar[str] = "no_reviewable_template"
    exit_code: ClassVar[int] = exitcodes.NO_REVIEWABLE_TEMPLATE


class SchemaViolationError(IacReviewError):
    """Structured input violates its expected schema (for example Agent Findings)."""

    error_class: ClassVar[str] = "schema_violation"
    exit_code: ClassVar[int] = exitcodes.PARSE_FAILURE


class MappingFileError(IacReviewError):
    """A plugin-owned mapping or metadata file is missing or corrupt.

    This indicates a broken installation rather than bad user input, so it
    reports as ``unexpected`` and exits 1.
    """

    error_class: ClassVar[str] = "unexpected"
    exit_code: ClassVar[int] = exitcodes.UNEXPECTED


#: Every concrete exception class, in the order design.md lists them. Exposed
#: for tests and documentation generation so neither has to rediscover the
#: hierarchy by introspection.
ERROR_CLASS_HIERARCHY: Sequence[type] = (
    IacReviewError,
    InvalidArgumentsError,
    InputNotFoundError,
    InputTooLargeError,
    TemplateParseError,
    ToolUnavailableError,
    ToolVersionError,
    ToolExecutionError,
    ToolTimeoutError,
    PathContainmentError,
    UnsafeArgumentError,
    NotReviewableError,
    SchemaViolationError,
    MappingFileError,
)
