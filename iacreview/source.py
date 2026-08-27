"""``SourceResult``: the one value every review Source returns.

design.md gives ``run_and_normalize`` the same return type in the cfn-lint
Source, the cfn-guard Source, and the IAM Source
(``SourceResult(source, findings, errors, stats)``), and the orchestration loop
in ``run_iac_review.py`` consumes all three through that single shape. The type
therefore lives here rather than inside any one Source module: whichever Source
defined it would become an import target for the others, and a second copy would
let the four field names drift apart between Sources that a report merges.

:mod:`iacreview.finding` was the other candidate. It is not used because that
module owns the *single Finding* schema -- the 13 fields, their closed value
sets, and their validation. A per-Source aggregate that also carries
StructuredErrors and a stats dict is a different concern, and putting it there
would make :mod:`iacreview.finding` import the error vocabulary of things that
are not Findings at all.

**Why errors never stop a Source.** Requirement 4 AC12 and Requirement 5 AC6
both require a failed tool to be *reported* while the rest of the review
continues. That is only expressible if a Source can return successfully while
saying "I failed": hence ``findings`` and ``errors`` are independent, and an
empty ``findings`` list with one ``errors`` entry is a normal, well-formed
result rather than an exception. Sources raise only for failures that make the
whole run meaningless (a path outside the workspace, a corrupt mapping file).

**Why a path helper is here.** Every Source fills ``Location.File``, and the
schema requires a workspace-relative path there (Requirement 16 AC11: no
absolute host path in output, so a report stays byte-identical across
machines). :func:`workspace_relative` is that one conversion, shared rather
than reimplemented per Source.

**Why an exit status helper is here.** A Skill invoked on its own has to turn
``errors`` back into a process exit code, and design.md's failure matrix assigns
those codes per failure mode rather than per exception class. The one place the
two disagree is a tool whose *output* did not match the expected structure:
``parse_output`` raises :class:`~iacreview.errors.TemplateParseError`, whose
class-level ``exit_code`` is 4 (a template that would not parse), while the
matrix asks for 6 (an external tool that did not do its job). Reading
``exc.exit_code`` would report the wrong one, so
:data:`SOURCE_ERROR_EXIT_CODES` states the mapping the matrix defines and
:meth:`SourceResult.exit_status` applies it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path, PurePath
from types import MappingProxyType
from typing import Any, Dict, List, Mapping, Optional, Union

from iacreview import exitcodes
from iacreview.finding import SOURCES, Finding, schema_violation

__all__ = [
    "StructuredError",
    "SOURCE_ERROR_EXIT_CODES",
    "PARENT_DIRECTORY",
    "SourceResult",
    "workspace_relative",
    "display_path",
]

#: A rendered :meth:`~iacreview.errors.IacReviewError.to_structured_error`
#: payload. Its keys are exactly
#: :data:`iacreview.errors.STRUCTURED_ERROR_KEYS`; it is an alias rather than a
#: dataclass because that is the shape the report serializes directly.
StructuredError = Dict[str, Any]

#: ``error_class`` -> exit code a Source's Skill returns when run on its own
#: (design.md, Error Handling / Failure mode マトリクス).
#:
#: ``parse_failure`` maps to 6, not to the 4 that
#: :class:`~iacreview.errors.TemplateParseError` carries: inside a Source the
#: payload that failed to parse is an external tool's output, which the matrix
#: classifies as a tool execution failure. A template that fails to parse is
#: detected earlier, in ``template.load_template``, and never reaches a Source.
SOURCE_ERROR_EXIT_CODES: Mapping[str, int] = MappingProxyType(
    {
        "tool_unavailable": exitcodes.TOOL_UNAVAILABLE,
        "tool_version": exitcodes.TOOL_UNAVAILABLE,
        "tool_execution": exitcodes.TOOL_EXECUTION_FAILURE,
        "tool_timeout": exitcodes.TOOL_EXECUTION_FAILURE,
        "parse_failure": exitcodes.TOOL_EXECUTION_FAILURE,
        "schema_violation": exitcodes.TOOL_EXECUTION_FAILURE,
        "unexpected": exitcodes.UNEXPECTED,
    }
)


#: Path component meaning "the directory above". A path containing one is not
#: usable as a ``Location.File`` value, however it was produced.
PARENT_DIRECTORY = ".."


def workspace_relative(
    text: Optional[str], workspace_root: Optional[Union[str, Path]] = None
) -> Optional[str]:
    """Render a path a tool reported as a workspace-relative ``Location.File``.

    Pure string and path arithmetic: nothing is resolved, opened, or stat'ed, so
    the Finding-building step of every Source stays a testable pure function.
    Containment of the *input* path was already established by
    :func:`iacreview.pathguard.resolve_within` before the tool ran; this
    function only decides how to display it.

    Args:
        text: The path as the tool reported it, for example a cfn-lint
            ``Filename``. ``None``, empty, and whitespace-only all yield
            ``None``.
        workspace_root: Absolute root the result is displayed relative to.
            Required to relativize an absolute ``text``; without it an absolute
            path yields ``None``.

    Returns:
        A ``/``-separated relative path, or ``None`` when ``text`` cannot be
        expressed as one: it is absolute and outside ``workspace_root``, it
        climbs out through :data:`PARENT_DIRECTORY`, or it is empty. ``None``
        means "use your own fallback", which for a Source is the reviewed
        Template's own relative path -- the file it asked the tool about.
        Returning ``None`` rather than the original string is deliberate: an
        absolute path would leak the host's directory layout into the report,
        and a ``../`` path would name a file outside the reviewed workspace.

    Note:
        Separators are normalized to ``/`` so that a report generated on Windows
        and one generated on Linux are byte-identical.
    """
    if text is None or not text.strip():
        return None

    candidate = PurePath(text)
    if candidate.is_absolute():
        if workspace_root is None:
            return None
        try:
            candidate = candidate.relative_to(PurePath(workspace_root))
        except ValueError:
            return None

    parts = tuple(part for part in candidate.parts if part not in (".", ""))
    if not parts or PARENT_DIRECTORY in parts:
        return None
    return "/".join(parts)


def display_path(
    path: Union[str, Path], workspace_root: Optional[Union[str, Path]] = None
) -> str:
    """Render ``path`` the way a message that may reach stdout must name it.

    :func:`workspace_relative` answers "can this be a ``Location.File``" and
    returns ``None`` when it cannot. A message has no such option -- it has to
    name the file somehow -- so this wrapper supplies the fallback every caller
    would otherwise write for itself: the bare file name, which identifies the
    file without disclosing the directory it sits in.

    Args:
        path: Any path the plugin holds, absolute or relative.
        workspace_root: Root the result is displayed relative to. Defaults to
            the current working directory, which is the workspace root of every
            entry point of this plugin (see each Skill's ``workspace_root``).

    Returns:
        A ``/``-separated relative path when ``path`` lies inside the workspace,
        otherwise the file name alone. Never an absolute path, which is the
        point: Requirement 16 AC11 makes stdout a function of the input, and an
        absolute path is a function of the host.

    Note:
        Purely lexical, like :func:`workspace_relative`: nothing is resolved or
        stat'ed, so this is safe to call while reporting a failure on a path
        that no longer exists.
    """
    text = str(path)
    root = Path.cwd() if workspace_root is None else Path(workspace_root)
    relative = workspace_relative(text, root)
    if relative is not None:
        return relative
    # ``.name`` is empty for a root directory or a trailing separator; the raw
    # text is then the only thing left to say, and it names no file to leak.
    return PurePath(text).name or text


@dataclass(frozen=True)
class SourceResult:
    """Everything one review Source produced for one Template.

    Attributes:
        source: The Source name, one of :data:`iacreview.finding.SOURCES`. Always
            set, including when ``findings`` is empty, because Requirement 4
            AC13 asks a clean run to identify its Source rather than return
            nothing at all.
        findings: Normalized Findings, in the order the Source produced them.
            Report-wide ordering (Requirement 7 AC15) and ``ID`` assignment
            happen after every Source has run, so these Findings still carry
            :data:`iacreview.finding.UNASSIGNED_ID`.
        errors: StructuredErrors for failures that did not stop the Source.
        stats: Source-specific counters for the report's ``stats`` section. The
            key set is fixed per Source so that output stays byte-stable
            (Requirement 16 AC11); each Source documents its own keys.

    The dataclass is frozen, but the three containers are not: a Source builds
    its lists first and constructs the result once. Freezing the container is
    what keeps a consumer from reassigning ``source`` on a result it received.
    """

    source: str
    findings: List[Finding] = field(default_factory=list)
    errors: List[StructuredError] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Reject a Source name the report schema does not permit.

        Cheap, and it catches the one mistake that is otherwise invisible until
        a report is validated: a misspelled Source name on a result whose
        Findings all carry the correct one.

        Raises:
            SchemaViolationError: ``source`` is outside
                :data:`iacreview.finding.SOURCES`.
        """
        if self.source not in SOURCES:
            raise schema_violation(
                "source",
                "{0!r} is not one of {1}".format(self.source, list(SOURCES)),
            )

    def exit_status(self) -> int:
        """Exit code a standalone Skill returns for this result.

        Returns:
            :data:`iacreview.exitcodes.OK` when ``errors`` is empty -- zero
            findings is a successful review, not a failure (Requirement 4 AC13).
            Otherwise the :data:`SOURCE_ERROR_EXIT_CODES` entry for the *first*
            error, or :data:`iacreview.exitcodes.UNEXPECTED` for an
            ``error_class`` the table does not list.

        Note:
            The first error decides, because a Source stops at the failure that
            prevented it from producing findings and that failure is appended
            first. A Source that keeps going after a non-fatal error and still
            returns findings should not use this helper: the first error would
            then describe something it recovered from.
        """
        if not self.errors:
            return exitcodes.OK
        error_class = self.errors[0].get("error_class")
        return SOURCE_ERROR_EXIT_CODES.get(str(error_class), exitcodes.UNEXPECTED)
