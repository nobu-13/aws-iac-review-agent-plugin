"""The cfn-lint Source: run the tool, decode what it said, build Findings.

Execution is one function, :func:`run_and_normalize`. Everything it needs to
decide is factored into pure functions that never start a process, so the
interesting behaviour is reachable from a string literal or a fixture
(Requirement 12 AC9 asks for exactly that: a test of every field mapping between
cfn-lint's JSON and the normalized Finding).

Below, first the pure decisions:

:func:`decode_cfnlint_exit`
    Turns an exit status into "the tool succeeded and reported findings" /
    "the tool succeeded with nothing to report" / "the tool failed".

:func:`parse_output`
    Turns cfn-lint's ``-f json`` stdout into a list of :class:`RawResult`, or
    fails with a ``parse_failure``.

:func:`resource_from_path`
    Turns a cfn-lint ``Location.Path`` into the Resource logical ID a Finding
    belongs to, or ``None`` for a template-level finding.

:func:`normalize_results` / :func:`finding_from_result`
    Turn :class:`RawResult` values into Findings, filling all 13 fields from
    design.md's "JSON field 対応表". They consult the category mapping but touch
    neither the process table nor the filesystem: the caller supplies the
    Template's display path, because only the caller knows the workspace root.

:func:`build_argv`
    The invocation, as data. Separated so a test can assert the exact command
    without a cfn-lint installation.

Then :func:`run_and_normalize` composes them: resolve, run, decode, parse,
classify, and return a :class:`~iacreview.source.SourceResult`.

**Errors are returned, not raised.** A missing tool, an old tool, a crash, a
timeout, and output that did not match the expected structure all become entries
in ``SourceResult.errors`` while the function returns normally with an empty
``findings`` list (Requirement 4 AC10, AC12). Only failures that invalidate the
whole run propagate: a path outside the workspace, a nonexistent input, and a
corrupt ``category_map.json``. The dividing line is whether the rest of the
review can still mean something.

**Why the exit code needs decoding at all.** cfn-lint's exit status is a bit
mask, not an ordinal: bit 1 (2) means an Error-level finding was reported, bit 2
(4) a Warning, bit 3 (8) an Informational one, and they combine. So 6 means
"Errors and Warnings were reported", not "something worse than 4 happened". Any
code whose set bits fall inside ``{2, 4, 8}`` is a *successful* run that found
something (Requirement 4 AC11); any code with a bit outside that set, exit 1
included, is a crash or usage error (Requirement 4 AC12). Reading the status as
a magnitude would report a Warning-only template as a tool failure and
misclassify a genuine crash. design.md records this as [Correction] C-1 against
the original wording of AC11/AC12.

**Untrusted input.** stdout of an external tool is untrusted input like any
template: it can be truncated, empty, valid JSON of the wrong shape, or valid
JSON with a string where a line number belongs. :func:`parse_output` therefore
validates the shape it depends on and, on any mismatch, discards every finding
in the payload rather than emitting a half-populated Finding. Partial results
from a structurally unknown payload cannot be trusted to mean what their field
names suggest, and a silently dropped finding is worse than a reported parse
failure (design.md, Error Handling: "当該 Source の findings は破棄").
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from iacreview import categories, pathguard, proc
from iacreview.categories import CategoryMap
from iacreview.errors import (
    IacReviewError,
    InvalidArgumentsError,
    TemplateParseError,
    ToolExecutionError,
)
from iacreview.finding import (
    CONFIRMED,
    UNASSIGNED_ID,
    Evidence,
    Finding,
    Location,
    redact_finding,
    sorted_sources,
)
from iacreview.source import SourceResult, StructuredError, workspace_relative
from iacreview.toolcheck import CFN_LINT, ToolInfo, require_known_tool

__all__ = [
    "CFNLINT_FINDING_BITS",
    "PARSE_ERROR_TYPE",
    "RESOURCES_SECTION",
    "SOURCE_NAME",
    "TIMEOUT_S",
    "STATS_KEYS",
    "NO_MESSAGE_TEXT",
    "CfnLintExitDecision",
    "RawResult",
    "build_argv",
    "decode_cfnlint_exit",
    "finding_from_result",
    "initial_stats",
    "normalize_results",
    "parse_output",
    "resource_from_path",
    "run_and_normalize",
]

#: Bits cfn-lint sets to report that findings exist: 2 (Error), 4 (Warning),
#: 8 (Informational). Their union is 14, and every subset of it -- 2, 4, 6, 8,
#: 10, 12, 14 -- is a successful run.
CFNLINT_FINDING_BITS = 2 | 4 | 8

# design.md pseudocode name. Same value, so there is one definition of the mask.
_CFNLINT_FINDING_BITS = CFNLINT_FINDING_BITS

#: ``TemplateParseError.error_type`` used when cfn-lint's JSON is well-formed
#: JSON but not the structure this module expects. Distinct from a JSON syntax
#: error, which reports the underlying decoder's exception name.
PARSE_ERROR_TYPE = "cfn-lint output structure"

#: First element of a ``Location.Path`` that points inside the Resources
#: section of a template.
RESOURCES_SECTION = "Resources"

#: This Source's name in ``Finding.Source`` and ``StructuredError.source``. The
#: same string as the executable name, which is why :data:`CFN_LINT` is reused
#: rather than a second literal written here.
SOURCE_NAME = CFN_LINT

#: Wall-clock limit for one cfn-lint run, in seconds. Matches the per-Template
#: budget design.md gives both deterministic tools.
TIMEOUT_S = 60

#: Fixed keys of :attr:`~iacreview.source.SourceResult.stats`. Always all of
#: them, so the report's stats section has a stable shape (Requirement 16 AC11).
#:
#: There is no ``rules_evaluated`` key. cfn-lint's ``-f json`` output lists the
#: rules that *fired* and says nothing about how many were evaluated, and
#: inventing the number from the count of distinct rule IDs would report
#: something the tool never claimed. ``rules_triggered`` is the honest counter;
#: an actual evaluated-rule count would need a second invocation
#: (``cfn-lint --listrules``), which this Source does not make.
STATS_KEYS: Tuple[str, ...] = (
    "tool_version",
    "exit_code",
    "results_parsed",
    "rules_triggered",
    "informational_rules_enabled",
)

#: Stand-in for ``Message`` when cfn-lint reported none. ``Finding`` and
#: ``Evidence.Detail`` are both ``minLength: 1`` in the schema, so a missing
#: message needs a value rather than an empty tail.
NO_MESSAGE_TEXT = "no message was reported"

#: ``WhyItMatters`` when neither the mapping file nor ``Rule.ShortDescription``
#: offers wording.
WHY_IT_MATTERS_FALLBACK = (
    "cfn-lint reported this rule at {level} level, which this plugin maps to "
    "FindingType {finding_type} and Severity {severity}."
)

#: ``Recommendation`` when neither the mapping file nor ``Rule.Description``
#: offers wording.
RECOMMENDATION_FALLBACK = (
    "Consult the cfn-lint documentation for rule {rule_id} and correct the "
    "reported condition in the template."
)

#: A ``Location.Path`` element: mapping key or sequence index.
TemplatePathItem = Union[str, int]


@dataclass(frozen=True)
class CfnLintExitDecision:
    """What a cfn-lint exit status means.

    Attributes:
        ok: The tool ran to completion. ``False`` means crash, usage error, or
            termination by a signal, and the caller reports a
            ``tool_execution`` error with the first lines of stderr instead of
            trusting stdout.
        has_findings: cfn-lint signalled that it reported at least one finding.
            Only meaningful when ``ok`` is ``True``; it is ``False`` on a
            failure decision even though a failing invocation may still have
            written parsable JSON, because on that path the exit status is not
            evidence of anything about stdout. A caller that wants to salvage
            findings from a failed run parses stdout itself and reports both the
            error and whatever it recovered (design.md, "その他" row).
    """

    ok: bool
    has_findings: bool


@dataclass(frozen=True)
class RawResult:
    """One cfn-lint result object, reduced to the fields the Source consumes.

    A faithful capture of the tool's own vocabulary (``Level``, ``Rule.Id``),
    deliberately not a :class:`~iacreview.finding.Finding`: mapping a Level onto
    a FindingType and Severity needs the category mapping, which
    ``run_and_normalize`` owns. Keeping the two apart is what lets the parsing
    contract be tested against literal JSON with no mapping file involved.

    ``Location.End`` is not captured. The Finding schema carries a single
    position, and the end position is recoverable from ``template_path`` if it
    is ever needed (design.md, "``Location.End`` は保持しない").

    Attributes:
        rule_id: ``Rule.Id``, for example ``"E3002"``. The classification key
            and the Evidence ``RuleId``.
        rule_short_description: ``Rule.ShortDescription``. The default
            ``WhyItMatters`` when the mapping file defines no override.
        rule_description: ``Rule.Description``. The default ``Recommendation``.
        rule_source: ``Rule.Source``, a documentation URL, appended to the
            Evidence detail.
        level: ``Level``: ``"Error"``, ``"Warning"``, or ``"Informational"``.
            Not validated against that set here; an unfamiliar level is data to
            classify, not a reason to discard a whole payload, and the mapping
            file has a default for exactly that case.
        message: ``Message``, the human-readable violation text. An absent
            ``Message`` becomes the empty string rather than discarding the
            payload: the rule ID already identifies the check, and losing every
            finding in the file over one missing message would cost more than
            it protects.
        line: ``Location.Start.LineNumber``, or ``None`` when cfn-lint reports
            no usable position.
        column: ``Location.Start.ColumnNumber``, or ``None``.
        template_path: ``Location.Path`` as a tuple, or ``None`` when absent.
            An empty path stays an empty tuple: "cfn-lint gave a path and it was
            empty" and "cfn-lint gave no path" both mean template-level, but
            only the first is a statement the tool actually made.
        filename: ``Filename`` verbatim, still whatever cfn-lint printed.
            Normalizing it to a workspace-relative path is the caller's job,
            because only the caller knows the workspace root.
    """

    rule_id: str
    rule_short_description: Optional[str]
    rule_description: Optional[str]
    rule_source: Optional[str]
    level: str
    message: str
    line: Optional[int]
    column: Optional[int]
    template_path: Optional[Tuple[TemplatePathItem, ...]]
    filename: Optional[str]


# ---------------------------------------------------------------------------
# Exit code decoding
# ---------------------------------------------------------------------------


def decode_cfnlint_exit(code: int) -> CfnLintExitDecision:
    """Decode a cfn-lint exit status (design.md, "Exit code の bit mask 復号").

    Args:
        code: The observed exit status. Negative values, which CPython uses for
            "killed by signal N", are handled by the same rule and land on a
            failure decision.

    Returns:
        ``ok=True, has_findings=False`` for 0; ``ok=True, has_findings=True``
        for 2, 4, 6, 8, 10, 12, 14; ``ok=False, has_findings=False`` for
        everything else, exit 1 included.

    Raises:
        InvalidArgumentsError: ``code`` is not an integer. A caller passing
            something else has a bug, and defaulting to "failure" would hide it
            behind a plausible-looking tool_execution error.

    Note:
        The decoding assumes ``--non-zero-exit-code`` is left at its default, as
        the invocation in ``run_and_normalize`` does. Passing ``none`` would make
        exit 0 stop meaning "no findings" and would invalidate the first branch.
    """
    if isinstance(code, bool) or not isinstance(code, int):
        raise InvalidArgumentsError(
            "cfn-lint exit code must be an integer, got {0}".format(
                type(code).__name__
            )
        )
    if code == 0:
        return CfnLintExitDecision(ok=True, has_findings=False)
    if code & ~_CFNLINT_FINDING_BITS == 0:  # 2, 4, 6, 8, 10, 12, 14 only
        return CfnLintExitDecision(ok=True, has_findings=True)
    return CfnLintExitDecision(ok=False, has_findings=False)


# ---------------------------------------------------------------------------
# Resource logical ID extraction
# ---------------------------------------------------------------------------


def resource_from_path(path: Optional[Sequence[object]]) -> Optional[str]:
    """Extract the Resource logical ID a ``Location.Path`` points into.

    Args:
        path: A cfn-lint ``Location.Path``, such as
            ``["Resources", "MyBucket", "Properties", "BucketName"]``. ``None``
            and an empty sequence are both accepted and mean "no path".

    Returns:
        The logical ID when the path starts with ``Resources`` followed by a
        string key, otherwise ``None``. ``["Resources", "MyBucket"]`` yields
        ``"MyBucket"`` just as a deeper path does; a path into ``Parameters``,
        ``Outputs``, or any other section yields ``None``, as does a
        template-level finding such as ``E0000`` whose path is empty or absent.

    Note:
        ``None`` is not a value that matches another ``None``. Requirement 14
        AC5 keys deduplication on logical ID and Category, and two
        template-level findings that share a Category are not thereby the same
        finding, so a merge would destroy information. See design.md,
        "``Resource == null`` の Finding の扱い".
    """
    if not path:
        return None
    if len(path) >= 2 and path[0] == RESOURCES_SECTION and isinstance(path[1], str):
        return path[1]
    return None


# ---------------------------------------------------------------------------
# JSON output parsing
# ---------------------------------------------------------------------------


def _parse_failure(
    field: str,
    reason: str,
    *,
    error_type: str = PARSE_ERROR_TYPE,
    line: Optional[int] = None,
    column: Optional[int] = None,
) -> TemplateParseError:
    """Build the ``parse_failure`` reported for unusable cfn-lint output.

    :class:`~iacreview.errors.TemplateParseError` is reused because its
    ``error_class`` is ``parse_failure``, which is what design.md's Error
    Handling table specifies for a tool output structure mismatch, and because
    it is the one error type that carries ``error_type`` / ``line`` / ``column``
    for a JSON syntax error. ``tool`` is set to ``cfn-lint`` so the resulting
    StructuredError names the tool whose output failed, which is what
    distinguishes this from a template that failed to parse.

    Args:
        field: Path into the JSON payload, for example ``"[2].Rule.Id"``.
        reason: What was wrong with it.
        error_type: Category of parse failure.
        line: 1-based line in the payload, for a JSON syntax error.
        column: 1-based column, for a JSON syntax error.

    Returns:
        The exception, not raised.
    """
    error = TemplateParseError(
        "cfn-lint JSON output at {0}: {1}".format(field, reason),
        error_type=error_type,
        line=line,
        column=column,
        tool=CFN_LINT,
        remediation=(
            "Check that cfn-lint supports -f json and meets the minimum "
            "supported version."
        ),
    )
    error.field = field
    error.reason = reason
    return error


def _type_name(value: object) -> str:
    return type(value).__name__


def _require_object(field: str, value: object) -> Dict[str, Any]:
    """Require a JSON object with string keys."""
    if not isinstance(value, dict):
        raise _parse_failure(
            field, "expected an object, got {0}".format(_type_name(value))
        )
    for key in value:
        if not isinstance(key, str):
            raise _parse_failure(
                field, "keys must be strings, got {0}".format(_type_name(key))
            )
    return value


def _require_text(field: str, value: object) -> str:
    """Require a non-empty string.

    Empty is rejected for the fields this is applied to (``Rule.Id``, ``Level``)
    because they are the classification inputs: an empty rule ID would silently
    take the mapping file's default path and produce a Finding attributed to no
    rule at all.
    """
    if not isinstance(value, str):
        raise _parse_failure(
            field, "expected a string, got {0}".format(_type_name(value))
        )
    if not value:
        raise _parse_failure(field, "must not be empty")
    return value


def _optional_text(field: str, value: object) -> Optional[str]:
    """Accept ``None``, a missing key, or any string including the empty one.

    Applied to descriptive fields (``Message``, ``Rule.Description``,
    ``Filename``). cfn-lint omits some of them for some rules, and an omission
    is not a structural mismatch; the empty string is kept as-is rather than
    folded into ``None`` so the tool's output is not second-guessed here.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise _parse_failure(
            field, "expected a string or null, got {0}".format(_type_name(value))
        )
    return value


def _optional_position(field: str, value: object) -> Optional[int]:
    """Read a line or column number, normalizing "no position" to ``None``.

    cfn-lint reports ``0`` for a finding it cannot place on a line, for example
    a template-level parse error. The Finding schema expresses the absence of a
    position as ``None`` and rejects ``0`` as a line number, so a non-positive
    value is translated here rather than carried downstream to fail schema
    validation. No information is lost: zero was never a position.

    A non-integer, on the other hand, is a structural mismatch. Booleans count
    as non-integers despite ``bool`` subclassing ``int``.
    """
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise _parse_failure(
            field, "expected an integer or null, got {0}".format(_type_name(value))
        )
    if value <= 0:
        return None
    return value


def _optional_template_path(
    field: str, value: object
) -> Optional[Tuple[TemplatePathItem, ...]]:
    """Read ``Location.Path`` as a tuple of mapping keys and sequence indices."""
    if value is None:
        return None
    if not isinstance(value, list):
        raise _parse_failure(
            field, "expected a list or null, got {0}".format(_type_name(value))
        )
    items: List[TemplatePathItem] = []
    for index, item in enumerate(value):
        if isinstance(item, bool) or not isinstance(item, (str, int)):
            raise _parse_failure(
                "{0}[{1}]".format(field, index),
                "expected a mapping key or sequence index, got {0}".format(
                    _type_name(item)
                ),
            )
        items.append(item)
    return tuple(items)


def _result_from_object(field: str, payload: Dict[str, Any]) -> RawResult:
    """Build one :class:`RawResult` from one cfn-lint result object.

    Only the fields listed in design.md's "JSON field 対応表" are read. Unknown
    keys are ignored rather than rejected: cfn-lint may add fields in a future
    version, and refusing to parse output that carries more than we need would
    break the Source on a tool upgrade that broke nothing.
    """
    rule = _require_object("{0}.Rule".format(field), payload.get("Rule"))
    location_value = payload.get("Location")
    location = (
        {}
        if location_value is None
        else _require_object("{0}.Location".format(field), location_value)
    )
    start_value = location.get("Start")
    start = (
        {}
        if start_value is None
        else _require_object("{0}.Location.Start".format(field), start_value)
    )
    return RawResult(
        rule_id=_require_text("{0}.Rule.Id".format(field), rule.get("Id")),
        rule_short_description=_optional_text(
            "{0}.Rule.ShortDescription".format(field), rule.get("ShortDescription")
        ),
        rule_description=_optional_text(
            "{0}.Rule.Description".format(field), rule.get("Description")
        ),
        rule_source=_optional_text(
            "{0}.Rule.Source".format(field), rule.get("Source")
        ),
        level=_require_text("{0}.Level".format(field), payload.get("Level")),
        message=_optional_text("{0}.Message".format(field), payload.get("Message"))
        or "",
        line=_optional_position(
            "{0}.Location.Start.LineNumber".format(field), start.get("LineNumber")
        ),
        column=_optional_position(
            "{0}.Location.Start.ColumnNumber".format(field),
            start.get("ColumnNumber"),
        ),
        template_path=_optional_template_path(
            "{0}.Location.Path".format(field), location.get("Path")
        ),
        filename=_optional_text("{0}.Filename".format(field), payload.get("Filename")),
    )


def parse_output(raw: str) -> List[RawResult]:
    """Parse cfn-lint ``-f json`` stdout into results, or fail.

    Pure: no process, no filesystem, no mapping file. Feed it a string literal
    or a fixture and every branch below is reachable.

    Args:
        raw: Captured stdout. Whitespace-only input, including the empty
            string, is read as zero results. cfn-lint prints ``[]`` for a clean
            template, but a build that prints nothing at all on a clean run is
            reporting success, and answering that with a parse failure would
            turn a passing review into an error. A caller that wants to catch
            "findings were signalled but stdout was empty" compares this
            against :attr:`CfnLintExitDecision.has_findings`.

    Returns:
        One :class:`RawResult` per result object, in the order cfn-lint emitted
        them. Order is preserved rather than sorted: report ordering is
        Requirement 7 AC15's job and applies to the whole merged Finding list,
        not to one Source's output.

    Raises:
        TemplateParseError: ``raw`` is not valid JSON, is not a JSON array, or
            holds an element that does not match the expected result structure.
            ``error_class`` is ``parse_failure`` and ``tool`` is ``cfn-lint``.
            Nothing partial is returned: on any mismatch the whole payload is
            discarded, because the caller cannot tell which of the remaining
            objects mean what their keys suggest. The exception carries
            ``field`` and ``reason`` attributes naming the offending JSON path,
            in addition to the standard StructuredError payload.
    """
    if not isinstance(raw, str):
        raise _parse_failure(
            "<stdout>", "expected text, got {0}".format(_type_name(raw))
        )
    if not raw.strip():
        return []

    try:
        payload = json.loads(raw)
    except ValueError as exc:
        # json.JSONDecodeError subclasses ValueError and carries lineno/colno;
        # a plain ValueError from a non-standard decoder would not, hence getattr.
        raise _parse_failure(
            "<stdout>",
            str(exc),
            error_type=type(exc).__name__,
            line=getattr(exc, "lineno", None),
            column=getattr(exc, "colno", None),
        ) from exc

    if not isinstance(payload, list):
        raise _parse_failure(
            "<stdout>",
            "expected a JSON array of results, got {0}".format(_type_name(payload)),
        )

    results: List[RawResult] = []
    for index, element in enumerate(payload):
        field = "[{0}]".format(index)
        results.append(_result_from_object(field, _require_object(field, element)))
    return results


# ---------------------------------------------------------------------------
# Invocation
# ---------------------------------------------------------------------------


def build_argv(template_path: Union[str, Path], executable: str = CFN_LINT) -> List[str]:
    """Build the cfn-lint command line (design.md, cfn-lint Integration).

    The command is fixed. Nothing about it depends on user input except the
    Template path, which occupies the last position, after ``--``, so that a
    filename beginning with ``-`` can never be read as a flag. Combined with
    ``shell=False`` in :mod:`iacreview.proc`, that is the whole argument-safety
    story for this Source (Requirement 9 AC4, AC5).

    Two flags are worth their own note:

    ``-c I``
        Enables Informational rules, which cfn-lint does not evaluate by
        default. Requirement 4 AC8 requires it explicitly, and without it
        Requirement 4 AC7's Informational mapping and the report's
        ``Informational`` summary bucket are unreachable code (design.md,
        [Correction] C-7).

    ``--non-zero-exit-code`` (absent)
        Left at its default, ``informational``, which is what makes exit 0 mean
        "no findings" and keeps :func:`decode_cfnlint_exit` valid. Passing
        ``none`` would break that decoding.

    Args:
        template_path: Path to the Template. Must already have passed through
            :func:`iacreview.pathguard.resolve_within`; this function performs
            no validation of its own.
        executable: What to place in ``argv[0]``. Defaults to the bare name for
            readability in tests; :func:`run_and_normalize` passes
            :attr:`~iacreview.toolcheck.ToolInfo.path` so that the binary whose
            version was checked is the binary that runs.

    Returns:
        A fresh list, safe for the caller to keep or log.
    """
    return [executable, "-f", "json", "-c", "I", "--", str(template_path)]


def initial_stats() -> Dict[str, Any]:
    """Return the :data:`STATS_KEYS` dict for a run that has not started.

    Every key is present from the outset, so a result produced by a Source that
    failed before starting the tool has the same shape as one from a complete
    run. ``informational_rules_enabled`` is ``True`` unconditionally because
    :func:`build_argv` always passes ``-c I``; it records that fact in the
    report rather than leaving Requirement 4 AC8 verifiable only by reading the
    source.
    """
    return {
        "tool_version": None,
        "exit_code": None,
        "results_parsed": 0,
        "rules_triggered": 0,
        "informational_rules_enabled": True,
    }


# ---------------------------------------------------------------------------
# Finding construction
# ---------------------------------------------------------------------------


def _message_text(result: RawResult) -> str:
    """``Message``, or a stand-in when cfn-lint reported none."""
    return result.message or NO_MESSAGE_TEXT


def _finding_text(result: RawResult) -> str:
    """``Finding``: ``"[{Rule.Id}] {Message}"`` (design.md field table)."""
    return "[{0}] {1}".format(result.rule_id, _message_text(result))


def _evidence_detail(result: RawResult) -> str:
    """``Evidence[0].Detail``, with ``Rule.Source`` appended as a reference URL.

    The rule ID, the level cfn-lint assigned, and its message are all recorded
    here rather than only in ``Finding``, because Evidence is what a reader
    consults to answer "on what basis". ``Excerpt`` stays ``None``: Confidence
    is ``Confirmed``, so the rule that fired *is* the evidence, and quoting
    template text would add nothing a deterministic check needs
    (Requirement 7 AC11 requires an Excerpt only below ``Confirmed``).
    """
    detail = "cfn-lint reported {0} at {1} level: {2}".format(
        result.rule_id, result.level, _message_text(result)
    )
    if result.rule_source:
        detail = "{0} Reference: {1}".format(detail, result.rule_source)
    return detail


def _why_it_matters(
    result: RawResult, override: Dict[str, Any], finding_type: str, severity: str
) -> str:
    """``WhyItMatters``: mapping file override, else ``Rule.ShortDescription``.

    The override wins because it is wording a maintainer wrote for this plugin's
    audience, whereas ``ShortDescription`` is cfn-lint's own one-liner. The
    final fallback exists because the field is ``minLength: 1`` and some rules
    carry no description at all.
    """
    return (
        override.get("why_it_matters")
        or result.rule_short_description
        or WHY_IT_MATTERS_FALLBACK.format(
            level=result.level, finding_type=finding_type, severity=severity
        )
    )


def _recommendation(result: RawResult, override: Dict[str, Any]) -> str:
    """``Recommendation``: mapping file override, else ``Rule.Description``."""
    return (
        override.get("recommendation")
        or result.rule_description
        or RECOMMENDATION_FALLBACK.format(rule_id=result.rule_id)
    )


def _location(
    result: RawResult, template_file: str, workspace_root: Optional[Path]
) -> Location:
    """Build ``Location`` from ``Filename`` and ``Location.Start`` / ``Path``.

    ``File`` prefers cfn-lint's ``Filename`` made relative to the workspace, and
    falls back to the reviewed Template's own relative path when that is not
    possible -- an absolute path outside the workspace, or one climbing out
    through ``..``. The fallback is not a guess: this Source runs cfn-lint
    against exactly one Template, so every result belongs to that file
    regardless of how the tool spelled it. What the fallback prevents is an
    absolute host path or an out-of-workspace path reaching the report, which
    :func:`iacreview.finding.validate` would reject for the first case and
    silently accept for the second.
    """
    return Location(
        File=workspace_relative(result.filename, workspace_root) or template_file,
        Line=result.line,
        Column=result.column,
        TemplatePath=(
            None if result.template_path is None else list(result.template_path)
        ),
    )


def finding_from_result(
    result: RawResult,
    *,
    template_file: str,
    workspace_root: Optional[Path] = None,
    cmap: Optional[CategoryMap] = None,
) -> Finding:
    """Build one Finding from one cfn-lint result (design.md field table).

    All 13 fields are filled here. The three that are constant for this Source:

    * ``Confidence`` is always ``Confirmed`` (Requirement 7 AC8): cfn-lint
      reports what it found, not what it suspects.
    * ``Source`` is always ``["cfn-lint"]``, built through
      :func:`iacreview.finding.sorted_sources` so the list satisfies the
      schema's ordering rule without this module knowing the order.
    * ``SuggestedRemediation`` is always ``None``. design.md maps it from a
      mapping-file override, and ``category_map.json``'s cfn-lint override
      schema currently defines no such key; when one is added it belongs here.
      ``Recommendation`` already carries the actionable wording.

    ``ID`` is :data:`~iacreview.finding.UNASSIGNED_ID`. IDs are sequential over
    the sorted, deduplicated report (Requirement 7 AC1, AC15), which is decided
    long after this function runs. A Finding returned from here therefore does
    *not* pass :func:`iacreview.finding.validate` until the report assigns its
    ID; that is by design and documented on ``validate``.

    Args:
        result: One parsed cfn-lint result.
        template_file: Workspace-relative path of the reviewed Template, used
            when ``Filename`` cannot be relativized. Never absolute.
        workspace_root: Absolute workspace root, needed to relativize an
            absolute ``Filename``.
        cmap: Category mapping to classify with. ``None`` loads the bundled one;
            :func:`normalize_results` passes an already-loaded map so a payload
            of many results reads the file once.

    Returns:
        The Finding. Not validated here: see above on ``ID``.

    Raises:
        MappingFileError: ``cmap`` is ``None`` and the bundled mapping file is
            missing or corrupt.
    """
    if cmap is None:
        cmap = categories.load_map()

    classification = categories.classify_cfnlint(result.rule_id, result.level, cmap)
    # One lookup for the wording overrides. classify_cfnlint already applied the
    # category / finding_type / severity parts of the same entry; the two remaining
    # keys are text, which classification has no opinion about.
    override = cmap.cfnlint_override(result.rule_id) or {}

    finding = Finding(
        ID=UNASSIGNED_ID,
        Normalized_Category=classification.category,
        FindingType=classification.finding_type,
        Severity=classification.severity,
        Confidence=CONFIRMED,
        Source=sorted_sources([SOURCE_NAME]),
        Resource=resource_from_path(result.template_path),
        Location=_location(result, template_file, workspace_root),
        Finding=_finding_text(result),
        WhyItMatters=_why_it_matters(
            result, override, classification.finding_type, classification.severity
        ),
        Evidence=[
            Evidence(
                Source=SOURCE_NAME,
                Detail=_evidence_detail(result),
                RuleId=result.rule_id,
                Excerpt=None,
            )
        ],
        Recommendation=_recommendation(result, override),
        SuggestedRemediation=None,
    )

    # Credential redaction (design.md, O-11) is applied on the way out, as it is
    # for every Source. This Source quotes no Template text, so today it changes
    # nothing; wiring it here means a result that does carry an Excerpt is covered
    # by the same rule, including the W1011 / W2501 locations this Source's own
    # RuleId identifies. No NoEcho names are passed: cfn-lint runs as a
    # subprocess and this module never parses the Template.
    return redact_finding(finding)


def normalize_results(
    results: Sequence[RawResult],
    *,
    template_file: str,
    workspace_root: Optional[Path] = None,
    cmap: Optional[CategoryMap] = None,
) -> List[Finding]:
    """Build Findings for every result, preserving cfn-lint's order.

    Order is preserved rather than sorted: Requirement 7 AC15 sorts the merged
    report, not one Source's output, and re-sorting here would only make the
    intermediate value look final.

    Args:
        results: Output of :func:`parse_output`.
        template_file: Workspace-relative path of the reviewed Template.
        workspace_root: Absolute workspace root.
        cmap: Category mapping. ``None`` loads the bundled one once for the
            whole batch.

    Returns:
        One Finding per result, all carrying
        :data:`~iacreview.finding.UNASSIGNED_ID`.
    """
    if cmap is None:
        cmap = categories.load_map()
    return [
        finding_from_result(
            result,
            template_file=template_file,
            workspace_root=workspace_root,
            cmap=cmap,
        )
        for result in results
    ]


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------


def _record(
    errors: List[StructuredError], exc: IacReviewError
) -> List[StructuredError]:
    """Append ``exc`` to ``errors`` as a StructuredError attributed to cfn-lint."""
    errors.append(exc.to_structured_error(source=SOURCE_NAME))
    return errors


def _execution_error(exit_code: int, stderr: str) -> ToolExecutionError:
    """Build the ``tool_execution`` error for a non-findings exit status.

    Reached for exit 1 (crash or usage error) and for any status carrying a bit
    outside ``{2, 4, 8}``. ``stderr`` is passed whole and truncated to five lines
    by :class:`~iacreview.errors.IacReviewError` (Requirement 15 AC7), which also
    bounds how much untrusted tool output -- possibly quoting the template --
    reaches the report.
    """
    return ToolExecutionError(
        "cfn-lint exited with code {0}, which does not indicate reported "
        "findings".format(exit_code),
        tool=CFN_LINT,
        tool_exit_code=exit_code,
        stderr=stderr,
        remediation=(
            "Run cfn-lint on the template directly to see the full error. An "
            "exit code of 1 usually means a crash or a usage error."
        ),
    )


def _count(stats: Dict[str, Any], results: Sequence[RawResult]) -> None:
    """Record how much cfn-lint reported (see :data:`STATS_KEYS`)."""
    stats["results_parsed"] = len(results)
    stats["rules_triggered"] = len({result.rule_id for result in results})


def run_and_normalize(
    template: Path,
    tool: Optional[ToolInfo] = None,
    *,
    workspace_root: Optional[Path] = None,
    cmap: Optional[CategoryMap] = None,
) -> SourceResult:
    """Run cfn-lint against one Template and return normalized Findings.

    The whole Source in one call: contain the path, verify the tool, run it,
    decode the exit status, parse stdout, classify each result. A clean Template
    yields ``findings=[]`` with ``source="cfn-lint"`` rather than nothing at all
    (Requirement 4 AC13).

    Args:
        template: Path to the Template. Passed through
            :func:`iacreview.pathguard.resolve_within` before it reaches the
            command line, so containment holds even if the caller forgot
            (Requirement 9 AC4, AC5).
        tool: An already-verified cfn-lint. ``None`` verifies it here through
            :func:`iacreview.toolcheck.require_known_tool`, which is the normal
            path; an orchestrator that reviews many Templates passes one
            :class:`~iacreview.toolcheck.ToolInfo` so ``--version`` runs once.
        workspace_root: Containment root and the root ``Location.File`` is
            relative to. Defaults to the current working directory, which is the
            workspace root for every entry point of this plugin.
        cmap: Category mapping. ``None`` loads the bundled one.

    Returns:
        A :class:`~iacreview.source.SourceResult` whose ``source`` is always
        ``"cfn-lint"``. ``errors`` holds one entry for each of these, and
        ``findings`` is then empty:

        ============================  ==================
        Situation                     ``error_class``
        ============================  ==================
        cfn-lint absent from PATH     ``tool_unavailable``
        cfn-lint older than 1.0.0     ``tool_version``
        crash or unknown exit status  ``tool_execution``
        exceeded :data:`TIMEOUT_S`    ``tool_timeout``
        stdout did not match          ``parse_failure``
        ============================  ==================

        On an unknown exit status stdout is still parsed, and any findings it
        yields are returned *alongside* the error (design.md, "その他" row); a
        parse failure on that path is not reported separately, because the exit
        status already said stdout is not to be trusted.

    Raises:
        UnsafeArgumentError: ``template`` contains a shell metacharacter.
        InvalidArgumentsError: ``template`` is empty or cannot be normalized.
        PathContainmentError: ``template`` resolves outside ``workspace_root``.
        InputNotFoundError: ``template`` or ``workspace_root`` does not exist.
        MappingFileError: The bundled category mapping is missing or corrupt.

        These five are not folded into ``errors``: they mean the caller asked
        for something that cannot be reviewed, or that the installation is
        broken, and continuing would report a review that never happened.
    """
    root = Path.cwd() if workspace_root is None else Path(workspace_root)
    resolved = pathguard.resolve_within(str(template), root)
    # resolve_within guarantees containment, so this is relative; `.name` covers
    # only the degenerate case of the root itself being handed in.
    template_file = workspace_relative(str(resolved), root) or resolved.name

    errors: List[StructuredError] = []
    stats = initial_stats()

    if tool is None:
        try:
            tool = require_known_tool(CFN_LINT)
        except IacReviewError as exc:
            # tool_unavailable (Requirement 4 AC10) and tool_version. Reported,
            # not raised: the other Sources can still run.
            return SourceResult(
                source=SOURCE_NAME,
                findings=[],
                errors=_record(errors, exc),
                stats=stats,
            )
    stats["tool_version"] = tool.version

    try:
        result = proc.run(build_argv(resolved, executable=tool.path), timeout_s=TIMEOUT_S)
    except IacReviewError as exc:
        # tool_timeout, or tool_execution / tool_unavailable if the binary
        # became unusable between the version check and now.
        return SourceResult(
            source=SOURCE_NAME,
            findings=[],
            errors=_record(errors, exc),
            stats=stats,
        )

    stats["exit_code"] = result.exit_code
    decision = decode_cfnlint_exit(result.exit_code)

    if not decision.ok:
        _record(errors, _execution_error(result.exit_code, result.stderr))
        try:
            salvaged = parse_output(result.stdout)
        except TemplateParseError:
            salvaged = []
        _count(stats, salvaged)
        return SourceResult(
            source=SOURCE_NAME,
            findings=normalize_results(
                salvaged,
                template_file=template_file,
                workspace_root=root,
                cmap=cmap,
            ),
            errors=errors,
            stats=stats,
        )

    try:
        results = parse_output(result.stdout)
    except TemplateParseError as exc:
        # Structure mismatch: the whole payload is discarded (design.md,
        # "当該 Source の findings は破棄"). The report keeps error_class
        # parse_failure; the standalone exit code for it is 6, which
        # SourceResult.exit_status resolves -- not the class's own 4, which
        # belongs to a template that would not parse.
        return SourceResult(
            source=SOURCE_NAME,
            findings=[],
            errors=_record(errors, exc),
            stats=stats,
        )

    _count(stats, results)
    return SourceResult(
        source=SOURCE_NAME,
        findings=normalize_results(
            results,
            template_file=template_file,
            workspace_root=root,
            cmap=cmap,
        ),
        errors=errors,
        stats=stats,
    )
