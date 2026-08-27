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

from typing import ClassVar, FrozenSet, List, Optional, Sequence, Tuple

from iacreview import exitcodes

__all__ = [
    "ERROR_CLASSES",
    "STRUCTURED_ERROR_KEYS",
    "STDERR_HEAD_MAX_LINES",
    "os_error_detail",
    "IacReviewError",
    "InvalidArgumentsError",
    "InputNotFoundError",
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
#: output contract. Note it holds 11 values while 12 exception classes exist:
#: ``InvalidArgumentsError`` / ``UnsafeArgumentError`` both report
#: ``invalid_arguments``, since an unsafe argument is an argument validation
#: failure from the caller's point of view.
ERROR_CLASSES: FrozenSet[str] = frozenset(
    {
        "invalid_arguments",
        "input_not_found",
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


def _head_lines(stderr: Optional[str]) -> List[str]:
    """Return the first :data:`STDERR_HEAD_MAX_LINES` lines of ``stderr``.

    ``None`` and the empty string both yield an empty list, so the
    ``stderr_head`` key is a list in every StructuredError. Line endings are
    dropped; ``splitlines`` also handles ``\\r\\n`` from tools running on
    Windows.
    """
    if not stderr:
        return []
    return stderr.splitlines()[:STDERR_HEAD_MAX_LINES]


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
