"""The cfn-guard Source: execution, result interpretation, Finding normalization.

:func:`run_and_normalize` is the whole Source in one call. Everything else is
one of its steps, public because each is worth testing on its own:

:func:`interpret_guard_result`
    Classifies one execution as ``timeout`` / ``all_passed`` / ``violations`` /
    ``tool_error``, without trusting any particular exit code value.

:func:`parse_records`
    Turns cfn-guard's ``--output-format json`` stdout into one
    :class:`GuardRecord` per evaluated rule file, or fails with a
    ``parse_failure``.

:func:`parse_output`
    The same input reduced to one :class:`RawResult` per violated check, which
    is what Finding construction consumes.

:func:`load_rule_metadata`
    Reads the ``_meta.json`` sidecars that supply the FindingType, Severity and
    Normalized_Category cfn-guard itself has no concept of.

:func:`build_argv`, :func:`resolve_rules_dirs`, :func:`count_rules`,
:func:`finding_from_result`, :func:`normalize_results`
    The command line, the rule directories it names, the ``rules_evaluated`` /
    ``rules_passed`` counters, and the mapping from a violated check onto the 13
    Finding fields.

Only :func:`run_and_normalize`, :func:`resolve_rules_dirs` and
:func:`load_rule_metadata` touch the filesystem, and only the first starts a
process. Classification, parsing, counting and Finding construction are pure
functions of their arguments, so every branch in them is reachable from a string
literal or a captured fixture with cfn-guard absent (Requirement 16 AC10).

**Why the exit code is not the primary signal.** cfn-guard guarantees only that
0 means every rule passed. The non-zero codes are not enumerated in its
documentation and are not stable across versions: 3.2.1 was measured to return
19 for rule violations, 5 for a rule file that fails to parse, and 255 for a
missing rules directory or an unparsable template, with every one of those
failures writing nothing at all to stdout. ``docs/architecture.md`` records the
measurements and why no branch here reads them. Requirement 5 AC7 therefore
makes the decision structural rather than numeric: a non-zero run whose stdout
parses as the expected result structure is a set of rule violations, and one
whose stdout does not is an execution failure. The observed code is recorded on
the interpretation so it still reaches ``StructuredError.exit_code``
(Requirement 15 AC7), but nothing branches on its value. design.md records this
as [Correction] C-3.

**The output is a JSON stream, not a JSON array.** cfn-guard 3.2.1 with
``--output-format json --show-summary none`` writes one pretty-printed JSON
object per evaluated rule *file*, concatenated with no separator and no
enclosing array. ``json.loads`` rejects the whole thing, so
:func:`parse_records` decodes it incrementally with
:meth:`json.JSONDecoder.raw_decode`. A version that emits a single array would
also be accepted, since a top-level array of records is read as the same
sequence.

**Empty stdout is not "no violations".** For cfn-lint, silent stdout is a clean
run; for cfn-guard it is the signature of a rule file that failed to parse,
where the explanation went to stderr and the exit code was 5. Zero violations
already has an unambiguous representation, exit 0, which
:func:`interpret_guard_result` handles before parsing. So an empty payload is
rejected here, and that rejection is what keeps a rule-parse failure from being
reported as a clean review.

**Untrusted input.** stdout of an external tool is untrusted like any template.
On any structural mismatch the whole payload is discarded rather than partially
interpreted: a Finding assembled from fields whose meaning we cannot confirm
would assert a policy violation the tool may never have reported, which
steering/security.md forbids ("推測だけで脆弱性が存在すると断定しない"). A reported
``parse_failure`` is the honest outcome (design.md, 出力の解析).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import (
    Any,
    Dict,
    FrozenSet,
    Iterable,
    Iterator,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Union,
)

from iacreview import categories, pathguard, proc
from iacreview.errors import (
    STDERR_HEAD_MAX_LINES,
    IacReviewError,
    InvalidArgumentsError,
    TemplateParseError,
    ToolExecutionError,
    os_error_detail,
)
from iacreview.finding import (
    CONFIRMED,
    FINDING_TYPES,
    SEVERITIES,
    UNASSIGNED_ID,
    Evidence,
    Finding,
    Location,
    TemplatePathItem,
    canonical_template_path,
    sorted_sources,
)
from iacreview.proc import ProcResult
from iacreview.source import SourceResult, StructuredError, workspace_relative
from iacreview.toolcheck import CFN_GUARD, ToolInfo, require_known_tool

__all__ = [
    "SOURCE_NAME",
    "PARSE_ERROR_TYPE",
    "META_FILENAME",
    "GUARD_RULE_SUFFIX",
    "DEFAULT_RULES_RELATIVE_PATH",
    "SUPPORTED_META_SCHEMA_MAJOR",
    "FALLBACK_FINDING_TYPE",
    "FALLBACK_SEVERITY",
    "RESOURCES_SECTION",
    "TIMEOUT_S",
    "STATS_KEYS",
    "RULES_COUNT_FROM_OUTPUT",
    "RULES_COUNT_FROM_DECLARATIONS",
    "KIND_TIMEOUT",
    "KIND_ALL_PASSED",
    "KIND_VIOLATIONS",
    "KIND_TOOL_ERROR",
    "INTERPRETATION_KINDS",
    "CLAUSE_KEY",
    "CLAUSE_KINDS",
    "CHECK_KINDS",
    "RESOLVED_FROM_KEY",
    "RESOLVED_UNARY_VALUE_KEY",
    "RawResult",
    "GuardRecord",
    "GuardInterpretation",
    "RuleMeta",
    "CategoryMeta",
    "RuleMetadata",
    "parse_records",
    "parse_output",
    "try_parse_guard_json",
    "interpret_guard_result",
    "resource_from_path",
    "load_rule_metadata",
    "build_argv",
    "resolve_rules_dirs",
    "initial_stats",
    "count_rules",
    "sort_results",
    "finding_from_result",
    "normalize_results",
    "run_and_normalize",
]

#: Source name recorded on every StructuredError and Finding this module feeds.
SOURCE_NAME = CFN_GUARD

#: ``TemplateParseError.error_type`` for stdout that is well-formed JSON but not
#: the structure this module expects. A JSON syntax error reports the decoder's
#: own exception name instead.
PARSE_ERROR_TYPE = "cfn-guard output structure"

#: Per-category metadata sidecar filename (design.md, Severity の付与方式, 案 C).
META_FILENAME = "_meta.json"

#: Extension cfn-guard collects when handed a directory, and therefore the one
#: this module treats as declaring a rule. ``.ruleset`` files are not scanned:
#: the bundled rule set is one rule per ``.guard`` file by convention
#: (Task 10.1), and a ``.ruleset`` bundles rules whose names cannot be derived
#: from the filename.
GUARD_RULE_SUFFIX = ".guard"

#: Bundled rule root, relative to the plugin root.
DEFAULT_RULES_RELATIVE_PATH = "rules"

#: ``schema_version`` MAJOR this module understands in a ``_meta.json``. A
#: sidecar declaring anything else is treated as unreadable and its category
#: falls back, rather than being read with the wrong expectations.
SUPPORTED_META_SCHEMA_MAJOR = 1

#: Last resort when neither ``rules[<rule>]`` nor ``default`` supplies a value
#: (design.md: ``rules[<rule_name>].<field>`` -> ``default.<field>`` ->
#: hardcoded fallback).
FALLBACK_FINDING_TYPE = "BestPractice"
FALLBACK_SEVERITY = "MEDIUM"

#: First segment of a cfn-guard property path that points inside the Resources
#: section of a template.
RESOURCES_SECTION = "Resources"

#: Wall-clock limit for one cfn-guard run, in seconds. Requirement 5 AC1 states
#: the budget per Template, which is why this Source submits one Template per
#: invocation even though ``--data`` is repeatable: a single run covering many
#: Templates could only be given a shared timeout.
TIMEOUT_S = 60

# -- stats ------------------------------------------------------------------

#: Fixed keys of :attr:`~iacreview.source.SourceResult.stats`. Always all of
#: them, so the report's stats section has a stable shape (Requirement 16 AC11).
#:
#: ``rules_evaluated`` and ``rules_passed`` are what Requirement 5 AC4 asks a
#: clean run to report. ``rules_not_applicable`` is here because the three do
#: not otherwise add up: a rule whose ``when`` guard did not match was neither
#: passed nor violated, and without its own counter a reader would have to
#: conclude that ``rules_evaluated - rules_passed`` rules failed.
#: ``rules_evaluated_source`` names where the counts came from, since the two
#: paths do not mean quite the same thing (see :func:`count_rules`).
STATS_KEYS: Tuple[str, ...] = (
    "tool_version",
    "exit_code",
    "violations_parsed",
    "rules_evaluated",
    "rules_passed",
    "rules_not_applicable",
    "rules_evaluated_source",
)

#: ``stats["rules_evaluated_source"]`` when cfn-guard's own output reported which
#: rules it evaluated.
RULES_COUNT_FROM_OUTPUT = "cfn-guard output"

#: ``stats["rules_evaluated_source"]`` when the counts were derived by counting
#: rule declarations under the scanned rule directories instead.
RULES_COUNT_FROM_DECLARATIONS = "rule declarations"

# -- Finding text -----------------------------------------------------------

#: End of a sentence followed by whitespace. Used to take the first sentence of
#: a rule's ``<<...>>`` message for the ``Finding`` line, per design.md's
#: ``"[{rule_name}] {custom message の1文目}"``.
_SENTENCE_BOUNDARY = re.compile(r"(?<=[.!?])\s")

#: ``Finding`` text when the violated rule declares no ``<<...>>`` message. The
#: field is ``minLength: 1``, and a rule name alone would read as a fragment.
FINDING_FALLBACK_TEXT = (
    "cfn-guard reported a policy violation; the rule declares no message."
)

#: ``WhyItMatters`` when the ``_meta.json`` entry states none.
WHY_IT_MATTERS_FALLBACK = (
    "cfn-guard rule {rule_name} encodes a policy this plugin classifies as "
    "FindingType {finding_type} and Severity {severity}."
)

#: ``Recommendation`` when neither the sidecar nor the rule's own message offers
#: wording.
RECOMMENDATION_FALLBACK = (
    "Change the template so that it satisfies the cfn-guard rule {rule_name}, "
    "then run the review again."
)

#: Value part of the Evidence detail when the queried property is absent, so no
#: comparison ran. Says "not present" rather than "provided: null", which would
#: be indistinguishable from a property explicitly set to null.
VALUE_ABSENT_TEXT = "the queried property is not present in the template"

#: Value part when the template's value and the value compared against are the
#: same. See :func:`_value_detail` for why that means the clause was negated.
VALUE_REJECTED_TEXT = "provided: {provided}, which the check requires it not to be"

#: Value part for an ordinary failed comparison (design.md's
#: ``"provided: <v>, expected: <e>"``).
VALUE_COMPARED_TEXT = "provided: {provided}, expected: {expected}"

#: Value part when cfn-guard reported the template's value but nothing to
#: compare it against.
VALUE_PROVIDED_ONLY_TEXT = "provided: {provided}"

# -- interpretation kinds ---------------------------------------------------

KIND_TIMEOUT = "timeout"
KIND_ALL_PASSED = "all_passed"
KIND_VIOLATIONS = "violations"
KIND_TOOL_ERROR = "tool_error"

#: The closed set of :attr:`GuardInterpretation.kind` values. Callers may switch
#: on these strings exhaustively.
INTERPRETATION_KINDS: Tuple[str, ...] = (
    KIND_TIMEOUT,
    KIND_ALL_PASSED,
    KIND_VIOLATIONS,
    KIND_TOOL_ERROR,
)

# -- output vocabulary ------------------------------------------------------

#: Wrapper around a leaf check inside ``Rule.checks[]``.
CLAUSE_KEY = "Clause"

#: Wrapper around a nested rule inside ``Rule.checks[]``. cfn-guard emits this
#: when a rule's body names another rule, and the inner ``checks`` carry the
#: actual clauses.
NESTED_RULE_KEY = "Rule"

#: Clause arities cfn-guard reports. Both carry the same ``context`` /
#: ``messages`` / ``check`` wrapper, so the wrapper is read identically; the
#: arity says whether the rule compared against a literal, which the Finding does
#: not record. It does decide the shape of a ``Resolved`` check, though -- see
#: :data:`CHECK_KINDS`.
CLAUSE_KINDS: FrozenSet[str] = frozenset({"Unary", "Binary"})

#: The tagged union inside a clause's ``check``.
#:
#: ``Resolved``
#:     The queried property exists and its value failed the comparison. A
#:     ``Binary`` clause carries ``from`` (the template's value) and ``to`` (the
#:     value compared against); a ``Unary`` clause carries a single ``value``,
#:     because an operator such as ``empty`` or ``exists`` compares against
#:     nothing.
#: ``UnResolved``
#:     The queried property is absent, so there was nothing to compare. Carries
#:     the struct traversal stopped at plus the remaining query.
#: ``UnResolvedContext``
#:     A rule this rule depends on did not pass. A plain string naming it, with
#:     no template location of its own.
CHECK_KINDS: FrozenSet[str] = frozenset(
    {"Resolved", "UnResolved", "UnResolvedContext"}
)

#: Key holding the template's value in a ``Binary`` ``Resolved`` check. Its
#: presence is what tells the two ``Resolved`` shapes apart.
RESOLVED_FROM_KEY = "from"

#: Key holding the template's value in a ``Unary`` ``Resolved`` check.
RESOLVED_UNARY_VALUE_KEY = "value"

#: Cap on how deep nested ``Rule`` wrappers are followed. Depth is bounded so
#: that a hand-edited or hostile payload cannot drive unbounded recursion; no
#: real rule set nests anywhere near this far.
MAX_CHECK_DEPTH = 32


# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RawResult:
    """One violated cfn-guard check, reduced to the fields the Source consumes.

    A faithful capture of cfn-guard's own vocabulary, deliberately not a
    :class:`~iacreview.finding.Finding`: FindingType, Severity and
    Normalized_Category come from the ``_meta.json`` sidecars, which
    ``run_and_normalize`` resolves. Keeping the two apart is what lets the
    parsing contract be tested against a captured fixture with no rule set
    involved.

    Attributes:
        rule_name: The violated rule, for example
            ``"security_group_open_ingress"``. The lookup key into
            ``_meta.json`` and the Evidence ``RuleId``.
        resource: Logical resource ID the violation belongs to, extracted from
            the property path. ``None`` when the path does not point into the
            Resources section, which happens for a dependent-rule failure that
            has no template location of its own.
        template_path: The property path split into segments, for example
            ``("Resources", "OpenSg", "Properties", "SecurityGroupIngress",
            0, "CidrIp")``. Empty when cfn-guard reported no path. Sequence
            indices are ``int``, not the strings cfn-guard writes them as: the
            canonical ``TemplatePath`` form is shared with every other Source
            (see :func:`iacreview.finding.canonical_template_path`), and
            keeping cfn-guard's spelling would make one position look like two
            when Sources are compared.
        provided_value: The template's value, rendered as text, or ``None``
            when the property is absent. ``None`` therefore means "nothing was
            there", never "cfn-guard did not say".
        expected_value: The value the rule compared against, rendered as text,
            or ``None`` when the payload carries none. Absent for a missing
            property, because a comparison never ran.
        custom_message: The rule's ``<<...>>`` message, stripped of the padding
            cfn-guard adds. ``None`` when the rule declares none. This is the
            remediation guidance Requirement 5 AC3 asks for; when it is ``None``
            the caller falls back to the sidecar's ``recommendation``.
        error_message: cfn-guard's own explanation of the failure. Retained as
            Evidence of what the tool actually asserted.
        context: The rule clause as cfn-guard printed it, for example
            ``"%s3_buckets[*].Properties.BucketEncryption EXISTS"``. Evidence of
            *what was checked*, which the clause text states and the rule name
            only implies.
    """

    rule_name: str
    resource: Optional[str]
    template_path: Tuple[TemplatePathItem, ...]
    provided_value: Optional[str]
    expected_value: Optional[str]
    custom_message: Optional[str]
    error_message: Optional[str]
    context: Optional[str]


@dataclass(frozen=True)
class GuardRecord:
    """One cfn-guard output record: the outcome of evaluating one rule file.

    cfn-guard emits one of these per rule file, so a run against a directory of
    eleven ``.guard`` files produces eleven records regardless of how many
    contained violations.

    ``compliant`` and ``not_applicable`` are what let ``rules_evaluated`` and
    ``rules_passed`` (Requirement 5 AC4) be counted from the tool's own output
    rather than estimated. A record that omits them yields empty tuples, which
    is the signal for the caller to fall back to counting ``rule`` declarations
    under ``rules/``.

    Attributes:
        name: The ``name`` field, normally the data file cfn-guard evaluated.
            ``None`` when absent. Not used for Finding construction; the caller
            already knows which template it submitted.
        status: ``"PASS"``, ``"FAIL"``, ``"SKIP"``, or whatever a future version
            reports. Not used to decide whether violations exist: ``violations``
            being non-empty is the direct evidence, and trusting a status string
            would add a second, redundant source of truth.
        violations: One :class:`RawResult` per violated check in this record.
        compliant: Rule names that passed.
        not_applicable: Rule names whose ``when`` guard did not match, so they
            were never evaluated against this template.
    """

    name: Optional[str]
    status: Optional[str]
    violations: Tuple[RawResult, ...]
    compliant: Tuple[str, ...]
    not_applicable: Tuple[str, ...]


@dataclass(frozen=True)
class GuardInterpretation:
    """What one cfn-guard execution meant.

    Attributes:
        kind: One of :data:`INTERPRETATION_KINDS`.
        payload: The parsed violations, set only when ``kind`` is
            ``"violations"``. ``None`` on every other kind, including
            ``"all_passed"``: exit 0 is cfn-guard's own guarantee that nothing
            failed, so the caller reaches for :func:`parse_records` when it
            wants the pass and skip counts from that stdout.
        exit_code: The observed exit status, set on ``"violations"`` and
            ``"tool_error"``. Recorded so it reaches
            ``StructuredError.exit_code`` (Requirement 15 AC7), not so that
            anything branches on it.
        stderr_head: First :data:`~iacreview.errors.STDERR_HEAD_MAX_LINES`
            lines of stderr, set on ``"tool_error"``. The cap bounds how much
            untrusted tool output, which may quote the reviewed template,
            reaches the report.
    """

    kind: str
    payload: Optional[Tuple[RawResult, ...]] = None
    exit_code: Optional[int] = None
    stderr_head: Tuple[str, ...] = ()


@dataclass(frozen=True)
class RuleMeta:
    """Metadata resolved for one Guard rule.

    Every field is populated: resolution walks
    ``rules[<rule_name>].<field>`` -> ``default.<field>`` -> a hardcoded
    fallback, so a caller never has to decide what to do about a gap.

    Attributes:
        rule_name: The rule this describes.
        category: Name of the directory the rule was found in, for example
            ``"public-access"``. ``None`` for a rule that appears in cfn-guard's
            output but not under any scanned rules directory, which happens when
            a caller passes ``--rules`` pointing somewhere the loader was not
            given.
        finding_type: One of :data:`~iacreview.finding.FINDING_TYPES`.
        severity: One of :data:`~iacreview.finding.SEVERITIES`.
        normalized_category: A member of the closed Normalized_Category set.
        why_it_matters: Explanation text, or ``""`` when the sidecar states
            none. Empty rather than ``None`` so a caller can format without a
            null check; the Source supplies its own wording in that case.
        recommendation: Remediation text, or ``""``. Used when the rule's
            ``<<...>>`` custom message is absent.
        from_sidecar: ``True`` when a valid ``_meta.json`` supplied at least the
            category defaults. ``False`` means every value above came from the
            hardcoded fallback, which is worth distinguishing in a report from a
            sidecar that deliberately chose the same values.
    """

    rule_name: str
    category: Optional[str]
    finding_type: str
    severity: str
    normalized_category: str
    why_it_matters: str
    recommendation: str
    from_sidecar: bool


@dataclass(frozen=True)
class CategoryMeta:
    """One category directory's ``_meta.json``, or the fallback stand-in for it.

    Attributes:
        category: The directory name. Authoritative over the sidecar's own
            ``category`` field, which is documentation: the directory is where
            cfn-guard actually found the rule.
        normalized_category: Category-wide Normalized_Category, or ``None`` when
            the sidecar declares none.
        default_finding_type: ``default.finding_type``.
        default_severity: ``default.severity``.
        rules: Validated per-rule entries, keyed by rule name.
        is_fallback: ``True`` when the sidecar was missing or unusable and these
            values are the hardcoded defaults.
    """

    category: str
    normalized_category: Optional[str]
    default_finding_type: str
    default_severity: str
    rules: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    is_fallback: bool = False


# ---------------------------------------------------------------------------
# parse_failure construction
# ---------------------------------------------------------------------------


def _parse_failure(
    field_path: str,
    reason: str,
    *,
    error_type: str = PARSE_ERROR_TYPE,
    line: Optional[int] = None,
    column: Optional[int] = None,
    remediation: Optional[str] = None,
) -> TemplateParseError:
    """Build the ``parse_failure`` reported for unusable cfn-guard output.

    :class:`~iacreview.errors.TemplateParseError` is reused because its
    ``error_class`` is ``parse_failure``, which is what design.md's Error
    Handling table specifies for a tool output structure mismatch, and because
    it is the one error type carrying ``error_type`` / ``line`` / ``column`` for
    a JSON syntax error. ``tool`` is ``cfn-guard`` so the StructuredError names
    the tool whose output failed rather than reading as a template parse error.

    Args:
        field_path: Path into the payload, for example
            ``"[3].not_compliant[0].Rule.name"``.
        reason: What was wrong with it.
        error_type: Category of parse failure.
        line: 1-based line in the payload, for a JSON syntax error.
        column: 1-based column, for a JSON syntax error.
        remediation: Override for the default remediation text.

    Returns:
        The exception, not raised. ``field`` and ``reason`` attributes are set
        on it so a caller can report the offending path without re-parsing.
    """
    error = TemplateParseError(
        "cfn-guard JSON output at {0}: {1}".format(field_path, reason),
        error_type=error_type,
        line=line,
        column=column,
        tool=CFN_GUARD,
        remediation=(
            remediation
            or "Check that cfn-guard supports --output-format json and meets "
            "the minimum supported version."
        ),
    )
    error.field = field_path
    error.reason = reason
    return error


def _type_name(value: object) -> str:
    return type(value).__name__


# ---------------------------------------------------------------------------
# Structural helpers
# ---------------------------------------------------------------------------


def _require_object(field_path: str, value: object) -> Dict[str, Any]:
    """Require a JSON object with string keys."""
    if not isinstance(value, dict):
        raise _parse_failure(
            field_path, "expected an object, got {0}".format(_type_name(value))
        )
    for key in value:
        if not isinstance(key, str):
            raise _parse_failure(
                field_path, "keys must be strings, got {0}".format(_type_name(key))
            )
    return value


def _require_list(field_path: str, value: object) -> List[Any]:
    if not isinstance(value, list):
        raise _parse_failure(
            field_path, "expected a list, got {0}".format(_type_name(value))
        )
    return value


def _optional_list(field_path: str, value: object) -> List[Any]:
    """Read a list that a future cfn-guard version might omit.

    Absent and ``null`` both read as empty. Applied to ``compliant`` and
    ``not_applicable``, whose absence means the counts must be derived some
    other way, not that the payload is broken.
    """
    if value is None:
        return []
    return _require_list(field_path, value)


def _require_text(field_path: str, value: object) -> str:
    """Require a non-empty string.

    Empty is rejected for ``Rule.name``, the one field this is applied to,
    because it is the metadata lookup key: an empty rule name would silently
    take the fallback Severity and produce a Finding attributed to no rule.
    """
    if not isinstance(value, str):
        raise _parse_failure(
            field_path, "expected a string, got {0}".format(_type_name(value))
        )
    if not value:
        raise _parse_failure(field_path, "must not be empty")
    return value


def _optional_text(field_path: str, value: object) -> Optional[str]:
    """Accept a missing key, ``null``, or any string."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise _parse_failure(
            field_path,
            "expected a string or null, got {0}".format(_type_name(value)),
        )
    return value


def _require_string_list(field_path: str, value: object) -> Tuple[str, ...]:
    """Read a list of rule names."""
    items: List[str] = []
    for index, item in enumerate(_optional_list(field_path, value)):
        items.append(_require_text("{0}[{1}]".format(field_path, index), item))
    return tuple(items)


def _message(field_path: str, payload: Dict[str, Any], key: str) -> Optional[str]:
    """Read one entry of a clause's ``messages`` object.

    cfn-guard pads a ``<<...>>`` custom message with a leading and trailing
    space and writes ``""`` when a rule inherits no message, so the value is
    stripped and an empty result becomes ``None``. Folding ``""`` into ``None``
    is safe here because an empty remediation string and an absent one call for
    the same behaviour downstream: fall back to the sidecar's
    ``recommendation``.
    """
    text = _optional_text("{0}.{1}".format(field_path, key), payload.get(key))
    if text is None:
        return None
    stripped = text.strip()
    return stripped or None


def _render_value(value: object) -> str:
    """Render a template value as text for the Evidence detail.

    Strings pass through unquoted, which is what reads naturally in
    ``provided: 0.0.0.0/0``. Everything else, including the structs cfn-guard
    reports when it stopped part-way through a traversal, is serialized as
    compact JSON with sorted keys so the rendering is byte-stable across runs
    (Requirement 16 AC11).
    """
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _split_path(raw_path: str) -> Tuple[str, ...]:
    """Split a cfn-guard property path into segments.

    cfn-guard writes an absolute, ``/``-separated JSON pointer style path
    (``/Resources/OpenSg/Properties/SecurityGroupIngress/0/CidrIp``). design.md
    describes splitting on ``.``, which is the separator cfn-guard uses inside a
    *remaining query* fragment rather than in a resolved path; both are handled,
    so a version that switches notation still yields the same segments.

    Empty segments are dropped, which is what turns the leading ``/`` into no
    segment at all and makes ``""`` an empty tuple.

    Segments stay strings here. Typing sequence indices as ``int`` is
    :func:`iacreview.finding.canonical_template_path`'s job and happens once,
    in :func:`_parse_clause`, on the fully assembled path.
    """
    segments: List[str] = []
    for chunk in raw_path.replace(".", "/").split("/"):
        if chunk:
            segments.append(chunk)
    return tuple(segments)


def resource_from_path(path: Optional[Sequence[TemplatePathItem]]) -> Optional[str]:
    """Extract the logical resource ID a cfn-guard property path points into.

    cfn-guard's JSON output has no dedicated logical-resource-name field even
    with ``--type CFNTemplate``; the name appears only as the second segment of
    the property path. design.md anticipates exactly this fallback ("取得できない
    場合は property path から ``Resources.<id>`` を抽出").

    Args:
        path: Canonical ``TemplatePath`` segments, such as
            ``("Resources", "OpenSg", "Properties")``. ``None`` and an empty
            sequence both mean "no path".

    Returns:
        The logical ID when the path starts with ``Resources`` followed by
        another segment, otherwise ``None``. A path into ``Parameters`` or
        ``Outputs`` yields ``None``, as does a dependent-rule failure with no
        path at all.

    Note:
        ``None`` does not match another ``None``. Requirement 14 AC5 keys
        deduplication on logical ID and Category, and two findings that carry no
        resource are not thereby the same finding.
    """
    if not path:
        return None
    if len(path) < 2 or path[0] != RESOURCES_SECTION:
        return None
    logical_id = path[1]
    # A logical ID is a mapping key, which canonicalization guarantees stays a
    # string; anything else here is not a resource name.
    if isinstance(logical_id, str) and logical_id:
        return logical_id
    return None


# ---------------------------------------------------------------------------
# Clause parsing
# ---------------------------------------------------------------------------


def _parse_resolved(
    field_path: str, payload: Dict[str, Any]
) -> Tuple[Tuple[str, ...], Optional[str], Optional[str]]:
    """Read a ``Resolved`` check: the property exists and compared unfavourably.

    Two shapes reach here, decided by the clause's arity rather than by a tag
    inside the check:

    ``Binary``
        ``from`` holds the template's value and ``to`` the value it was compared
        against. ``to.path`` is ignored: cfn-guard leaves it empty when the rule
        compared against a literal, and when it is a query the value it resolved
        to is already in ``to.value``.
    ``Unary``
        A single ``value``, because an operator such as ``empty``, ``!empty`` or
        ``exists`` compares against nothing. There is therefore no expected
        value to report; the operator itself is in ``comparison`` and is spelled
        out in the ``error_message`` cfn-guard supplies.

    A ``Unary`` clause only reaches this branch when the query *did* resolve --
    ``rules/iam/iam_policy_no_star_star.guard`` asking whether a filtered
    ``Statement`` list is ``empty`` is the case in the bundled rule set, and
    ``benchmark/cases/case-001-iam-wildcard`` is the case that measures it. A
    ``Unary`` clause over an absent property produces ``UnResolved`` instead, and
    that is why the bundled ``exists`` rules never took this path.
    """
    if RESOLVED_UNARY_VALUE_KEY in payload and RESOLVED_FROM_KEY not in payload:
        subject = _require_object(
            "{0}.{1}".format(field_path, RESOLVED_UNARY_VALUE_KEY),
            payload.get(RESOLVED_UNARY_VALUE_KEY),
        )
        raw_path = _require_text(
            "{0}.{1}.path".format(field_path, RESOLVED_UNARY_VALUE_KEY),
            subject.get("path"),
        )
        provided = (
            None if "value" not in subject else _render_value(subject["value"])
        )
        return _split_path(raw_path), provided, None

    source = _require_object("{0}.from".format(field_path), payload.get("from"))
    target = _require_object("{0}.to".format(field_path), payload.get("to"))
    raw_path = _require_text("{0}.from.path".format(field_path), source.get("path"))
    provided = (
        None if "value" not in source else _render_value(source["value"])
    )
    expected = None if "value" not in target else _render_value(target["value"])
    return _split_path(raw_path), provided, expected


def _parse_unresolved(
    field_path: str, payload: Dict[str, Any]
) -> Tuple[Tuple[str, ...], Optional[str], Optional[str]]:
    """Read an ``UnResolved`` check: the queried property is absent.

    The full path is reassembled from where traversal stopped plus what was
    left to look up, so ``/Resources/PlainBucket/Properties`` +
    ``VersioningConfiguration.Status`` becomes the five segments the rule
    actually asked about. Without that, every missing-property violation would
    report the same path as its resource's ``Properties`` block.

    Returns:
        ``(template_path, None, None)``. ``provided_value`` is ``None`` because
        nothing was there, and ``expected_value`` is ``None`` because no
        comparison ran; the struct traversal stopped at is recorded in the
        ``error_message`` cfn-guard supplies.
    """
    value = _require_object("{0}.value".format(field_path), payload.get("value"))
    traversed = _require_object(
        "{0}.value.traversed_to".format(field_path), value.get("traversed_to")
    )
    raw_path = _require_text(
        "{0}.value.traversed_to.path".format(field_path), traversed.get("path")
    )
    remaining = _optional_text(
        "{0}.value.remaining_query".format(field_path), value.get("remaining_query")
    )
    segments = _split_path(raw_path)
    if remaining:
        segments = segments + _split_path(remaining)
    return segments, None, None


def _parse_clause(
    field_path: str, rule_name: str, clause_kind: str, payload: Dict[str, Any]
) -> RawResult:
    """Build one :class:`RawResult` from one leaf clause.

    ``Unary`` and ``Binary`` share this path: both carry ``context``,
    ``messages`` and ``check``, and the arity says only whether the rule
    compared against a literal, which the Finding does not record.
    """
    clause_path = "{0}.{1}".format(field_path, clause_kind)
    check = _require_object("{0}.check".format(clause_path), payload.get("check"))
    present = [key for key in sorted(check) if key in CHECK_KINDS]
    if len(present) != 1:
        raise _parse_failure(
            "{0}.check".format(clause_path),
            "expected exactly one of {0}, got {1}".format(
                sorted(CHECK_KINDS), sorted(check)
            ),
        )
    check_kind = present[0]
    check_path = "{0}.check.{1}".format(clause_path, check_kind)

    if check_kind == "Resolved":
        raw_path, provided, expected = _parse_resolved(
            check_path, _require_object(check_path, check[check_kind])
        )
    elif check_kind == "UnResolved":
        raw_path, provided, expected = _parse_unresolved(
            check_path, _require_object(check_path, check[check_kind])
        )
    else:  # UnResolvedContext: a dependent rule failed, with no template path.
        _require_text(check_path, check[check_kind])
        raw_path, provided, expected = (), None, None

    # Canonicalized once, on the assembled path. Doing it inside _split_path
    # would mis-place the exempt logical-ID position for an UnResolved check,
    # whose path is two fragments joined after splitting.
    template_path = tuple(canonical_template_path(raw_path))

    messages = _require_object(
        "{0}.messages".format(clause_path), payload.get("messages", {})
    )
    return RawResult(
        rule_name=rule_name,
        resource=resource_from_path(template_path),
        template_path=template_path,
        provided_value=provided,
        expected_value=expected,
        custom_message=_message(
            "{0}.messages".format(clause_path), messages, "custom_message"
        ),
        error_message=_message(
            "{0}.messages".format(clause_path), messages, "error_message"
        ),
        context=_message(clause_path, payload, "context"),
    )


def _parse_checks(
    field_path: str, rule_name: str, checks: List[Any], depth: int
) -> List[RawResult]:
    """Walk a ``checks`` array, flattening nested rules onto the outer rule.

    A nested ``Rule`` wrapper appears when a rule's body names another rule. Its
    clauses are attributed to ``rule_name``, the rule the Finding is reported
    against, because that is the rule the user's policy set names and the one
    the ``_meta.json`` sidecar describes.

    Raises:
        TemplateParseError: A check carries neither a ``Clause`` nor a nested
            ``Rule``, its clause arity is unknown, or nesting exceeds
            :data:`MAX_CHECK_DEPTH`. An unrecognized wrapper is a genuinely
            unknown structure, not an extra field to ignore, so the payload is
            discarded rather than silently under-reported.
    """
    if depth > MAX_CHECK_DEPTH:
        raise _parse_failure(
            field_path,
            "nested checks exceed the maximum depth of {0}".format(MAX_CHECK_DEPTH),
        )
    results: List[RawResult] = []
    for index, element in enumerate(checks):
        check_path = "{0}[{1}]".format(field_path, index)
        entry = _require_object(check_path, element)
        if CLAUSE_KEY in entry:
            clause = _require_object(
                "{0}.{1}".format(check_path, CLAUSE_KEY), entry[CLAUSE_KEY]
            )
            arities = [key for key in sorted(clause) if key in CLAUSE_KINDS]
            if len(arities) != 1:
                raise _parse_failure(
                    "{0}.{1}".format(check_path, CLAUSE_KEY),
                    "expected exactly one of {0}, got {1}".format(
                        sorted(CLAUSE_KINDS), sorted(clause)
                    ),
                )
            arity = arities[0]
            results.append(
                _parse_clause(
                    "{0}.{1}".format(check_path, CLAUSE_KEY),
                    rule_name,
                    arity,
                    _require_object(
                        "{0}.{1}.{2}".format(check_path, CLAUSE_KEY, arity),
                        clause[arity],
                    ),
                )
            )
        elif NESTED_RULE_KEY in entry:
            nested = _require_object(
                "{0}.{1}".format(check_path, NESTED_RULE_KEY), entry[NESTED_RULE_KEY]
            )
            results.extend(
                _parse_checks(
                    "{0}.{1}.checks".format(check_path, NESTED_RULE_KEY),
                    rule_name,
                    _require_list(
                        "{0}.{1}.checks".format(check_path, NESTED_RULE_KEY),
                        nested.get("checks", []),
                    ),
                    depth + 1,
                )
            )
        else:
            raise _parse_failure(
                check_path,
                "expected a {0!r} or {1!r} entry, got {2}".format(
                    CLAUSE_KEY, NESTED_RULE_KEY, sorted(entry)
                ),
            )
    return results


def _parse_violation(field_path: str, payload: Dict[str, Any]) -> List[RawResult]:
    """Read one ``not_compliant[]`` entry into its violated checks."""
    rule = _require_object(
        "{0}.{1}".format(field_path, NESTED_RULE_KEY), payload.get(NESTED_RULE_KEY)
    )
    rule_path = "{0}.{1}".format(field_path, NESTED_RULE_KEY)
    rule_name = _require_text("{0}.name".format(rule_path), rule.get("name"))
    return _parse_checks(
        "{0}.checks".format(rule_path),
        rule_name,
        _require_list("{0}.checks".format(rule_path), rule.get("checks", [])),
        depth=0,
    )


def _parse_record(field_path: str, payload: Dict[str, Any]) -> GuardRecord:
    """Read one cfn-guard output record.

    Unknown keys are ignored: cfn-guard may add fields, and refusing output that
    carries more than we need would break the Source on a tool upgrade that
    broke nothing. ``not_compliant`` must be present as a list, because its
    absence would make "no violations" indistinguishable from "a structure we do
    not recognize".
    """
    if "not_compliant" not in payload:
        raise _parse_failure(
            "{0}.not_compliant".format(field_path), "required field is missing"
        )
    violations: List[RawResult] = []
    for index, element in enumerate(
        _require_list("{0}.not_compliant".format(field_path), payload["not_compliant"])
    ):
        entry_path = "{0}.not_compliant[{1}]".format(field_path, index)
        violations.extend(_parse_violation(entry_path, _require_object(entry_path, element)))
    return GuardRecord(
        name=_optional_text("{0}.name".format(field_path), payload.get("name")),
        status=_optional_text("{0}.status".format(field_path), payload.get("status")),
        violations=tuple(violations),
        compliant=_require_string_list(
            "{0}.compliant".format(field_path), payload.get("compliant")
        ),
        not_applicable=_require_string_list(
            "{0}.not_applicable".format(field_path), payload.get("not_applicable")
        ),
    )


# ---------------------------------------------------------------------------
# Top-level output parsing
# ---------------------------------------------------------------------------


def _iter_json_values(raw: str) -> Iterator[Any]:
    """Decode a concatenated stream of JSON values.

    cfn-guard writes one pretty-printed object per rule file with no separator
    and no enclosing array, which ``json.loads`` rejects. ``raw_decode``
    consumes one value at a time and reports where it stopped, so the stream is
    read without guessing at object boundaries by counting braces, which would
    be defeated by a brace inside a string.

    Raises:
        TemplateParseError: A value is not valid JSON, or trailing bytes cannot
            begin one.
    """
    decoder = json.JSONDecoder()
    index = 0
    length = len(raw)
    while True:
        while index < length and raw[index].isspace():
            index += 1
        if index >= length:
            return
        try:
            value, index = decoder.raw_decode(raw, index)
        except ValueError as exc:
            # json.JSONDecodeError subclasses ValueError and carries
            # lineno/colno; a plain ValueError from a non-standard decoder
            # would not, hence getattr.
            raise _parse_failure(
                "<stdout>",
                str(exc),
                error_type=type(exc).__name__,
                line=getattr(exc, "lineno", None),
                column=getattr(exc, "colno", None),
            ) from exc
        yield value


def parse_records(raw: str) -> List[GuardRecord]:
    """Parse cfn-guard ``--output-format json`` stdout into records.

    Pure: no process, no filesystem, no rule set. Feed it a string literal or a
    captured fixture and every branch below is reachable.

    Args:
        raw: Captured stdout. Either a concatenated stream of record objects, as
            cfn-guard 3.2.1 emits, or a single JSON array of them.

    Returns:
        One :class:`GuardRecord` per evaluated rule file, in the order cfn-guard
        emitted them. Order is preserved rather than sorted: report ordering is
        Requirement 7 AC15's job and applies to the merged Finding list, not to
        one Source's output.

    Raises:
        TemplateParseError: ``raw`` is not text, holds nothing but whitespace,
            is not valid JSON, or holds a value that does not match the expected
            record structure. ``error_class`` is ``parse_failure`` and ``tool``
            is ``cfn-guard``. Nothing partial is returned: one unusable record
            discards the whole payload, because there is no way to tell which of
            the remaining ones mean what their keys suggest.

            Whitespace-only input is a failure rather than zero records. Silent
            stdout is what cfn-guard produces when a rule file fails to parse,
            writing its explanation to stderr; reading it as a clean review
            would turn that failure into a false all-clear. Zero violations
            already has an unambiguous representation, exit 0, which
            :func:`interpret_guard_result` handles before reaching here.
    """
    if not isinstance(raw, str):
        raise _parse_failure(
            "<stdout>", "expected text, got {0}".format(_type_name(raw))
        )
    if not raw.strip():
        raise _parse_failure(
            "<stdout>",
            "is empty; cfn-guard writes at least one record per rule file when "
            "it evaluates any",
            remediation=(
                "Check stderr: cfn-guard reports a rule file that fails to "
                "parse there and leaves stdout empty."
            ),
        )

    values = list(_iter_json_values(raw))
    # A single top-level array is read as the sequence of records it holds, so a
    # version that wraps the stream in `[...]` needs no separate branch below.
    if len(values) == 1 and isinstance(values[0], list):
        values = values[0]

    records: List[GuardRecord] = []
    for index, value in enumerate(values):
        field_path = "[{0}]".format(index)
        records.append(_parse_record(field_path, _require_object(field_path, value)))
    return records


def parse_output(raw: str) -> List[RawResult]:
    """Parse cfn-guard stdout into one result per violated check.

    The flattened view of :func:`parse_records`, and what Finding construction
    consumes. A caller that also needs the pass and skip counts for
    ``rules_evaluated`` / ``rules_passed`` uses :func:`parse_records` instead and
    flattens it itself.

    Args:
        raw: Captured stdout, as described in :func:`parse_records`.

    Returns:
        One :class:`RawResult` per violated check, across every record, in the
        order cfn-guard emitted them. Empty when cfn-guard evaluated rules and
        none of them failed.

    Raises:
        TemplateParseError: As :func:`parse_records`.
    """
    results: List[RawResult] = []
    for record in parse_records(raw):
        results.extend(record.violations)
    return results


def try_parse_guard_json(raw: str) -> Optional[Tuple[RawResult, ...]]:
    """Parse stdout, returning ``None`` instead of raising on failure.

    The predicate :func:`interpret_guard_result` uses to decide violations
    against tool error. Separated from :func:`parse_output` so that the
    classification reads as the design pseudocode does, and so that a caller who
    wants the reason for the failure can still call :func:`parse_output` and
    catch the exception.

    Args:
        raw: Captured stdout.

    Returns:
        The parsed violations, possibly empty, or ``None`` when ``raw`` is not
        the expected structure. An empty tuple therefore means "the output was
        readable and reported no violated checks", which is distinct from
        ``None``.
    """
    try:
        return tuple(parse_output(raw))
    except TemplateParseError:
        return None


def interpret_guard_result(result: ProcResult) -> GuardInterpretation:
    """Classify one cfn-guard execution (design.md, Exit code の曖昧性への対処).

    The order of the checks is the contract, not an implementation detail:

    1. A timeout is decided before anything else, because a killed process's
       exit status and partial stdout describe the kill, not the review.
    2. Exit 0 is the one status cfn-guard documents, and it means every rule
       passed. stdout is not consulted.
    3. Any other status is resolved by whether stdout parses as the expected
       result structure: it does, so these are rule violations; it does not, so
       the tool failed (Requirement 5 AC7).

    Step 3 is why 19 and 5 and 255 need no entry anywhere in this module. The
    observed value is recorded for the report and never branched on, so a
    cfn-guard release that renumbers its failure codes changes nothing here.

    Args:
        result: The completed execution. A timeout is expressed as a
            :class:`~iacreview.proc.ProcResult` with ``timed_out=True``, which
            the caller constructs after catching
            :class:`~iacreview.errors.ToolTimeoutError`.

    Returns:
        A :class:`GuardInterpretation`. ``"violations"`` may carry an empty
        payload: a non-zero status with readable output and no failed check is
        contradictory, and reporting it as violations with nothing in them keeps
        the caller's handling of readable output in one place rather than
        inventing a fifth kind for it.

    Raises:
        InvalidArgumentsError: ``result.exit_code`` is not an integer. Treating
            a caller's bug as a tool error would hide it behind a plausible
            ``tool_error`` in the report.
    """
    if result.timed_out:
        return GuardInterpretation(kind=KIND_TIMEOUT)
    exit_code = result.exit_code
    if isinstance(exit_code, bool) or not isinstance(exit_code, int):
        raise InvalidArgumentsError(
            "cfn-guard exit code must be an integer, got {0}".format(
                _type_name(exit_code)
            )
        )
    if exit_code == 0:
        return GuardInterpretation(kind=KIND_ALL_PASSED)
    parsed = try_parse_guard_json(result.stdout)
    if parsed is not None:
        # The expected JSON structure was obtained -> treat as rule violations.
        return GuardInterpretation(
            kind=KIND_VIOLATIONS, payload=parsed, exit_code=exit_code
        )
    # No usable JSON -> treat as a tool error.
    return GuardInterpretation(
        kind=KIND_TOOL_ERROR,
        exit_code=exit_code,
        stderr_head=tuple((result.stderr or "").splitlines()[:STDERR_HEAD_MAX_LINES]),
    )


# ---------------------------------------------------------------------------
# _meta.json loading
# ---------------------------------------------------------------------------

_META_TOP_LEVEL_KEYS: Tuple[str, ...] = (
    "schema_version",
    "category",
    "normalized_category",
    "default",
    "rules",
)
_META_DEFAULT_KEYS: Tuple[str, ...] = ("finding_type", "severity")
_META_RULE_KEYS: Tuple[str, ...] = (
    "severity",
    "finding_type",
    "normalized_category",
    "why_it_matters",
    "recommendation",
)


class _MetaError(Exception):
    """A ``_meta.json`` is unusable. Internal; never escapes this module.

    Raised while validating one sidecar and caught by
    :func:`_load_category_meta`, which converts it into a ``parse_failure``
    StructuredError and a fallback :class:`CategoryMeta`. It is not an
    :class:`~iacreview.errors.IacReviewError` because it must not be able to
    propagate: a broken sidecar downgrades one category, it does not stop the
    review (design.md: "rule 実行そのものは継続する").
    """

    def __init__(self, field_path: str, reason: str) -> None:
        super().__init__("{0}: {1}".format(field_path, reason))
        self.field = field_path
        self.reason = reason


def _meta_text(field_path: str, value: object) -> str:
    if not isinstance(value, str) or not value:
        raise _MetaError(field_path, "expected a non-empty string")
    return value


def _meta_enum(field_path: str, value: object, permitted: Sequence[str]) -> str:
    text = _meta_text(field_path, value)
    if text not in permitted:
        raise _MetaError(
            field_path, "{0!r} is not one of {1}".format(text, list(permitted))
        )
    return text


def _meta_object(field_path: str, value: object) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise _MetaError(field_path, "expected an object")
    for key in value:
        if not isinstance(key, str):
            raise _MetaError(field_path, "keys must be strings")
    return value


def _meta_reject_unknown(
    field_path: str, payload: Mapping[str, Any], permitted: Sequence[str]
) -> None:
    """Reject a key outside ``permitted``.

    A misspelled ``normalised_category`` would otherwise leave the rule on its
    category default without any signal, which is exactly the kind of mistake
    that never shows up in output. Rejecting it downgrades the category and
    records a ``parse_failure``, which a contributor sees.
    """
    for key in sorted(payload):
        if key not in permitted:
            raise _MetaError(
                "{0}.{1}".format(field_path, key) if field_path else key,
                "is not one of the permitted fields {0}".format(list(permitted)),
            )


def _meta_category_name(field_path: str, value: object) -> str:
    """Require a member of the closed Normalized_Category set.

    Validated against ``category_map.json``, which owns the vocabulary
    (Requirement 14 AC1). A sidecar naming something outside it cannot be
    honoured, because the Finding would fail schema validation later, where the
    cause would be far harder to trace back to this file.
    """
    text = _meta_text(field_path, value)
    if not categories.load_map().is_valid_category(text):
        raise _MetaError(
            field_path,
            "{0!r} is not a declared Normalized_Category".format(text),
        )
    return text


def _meta_schema_version(value: object) -> None:
    version = _meta_text("schema_version", value)
    try:
        major = int(version.split(".", 1)[0])
    except ValueError:
        raise _MetaError(
            "schema_version", "expected a semver string, got {0!r}".format(version)
        ) from None
    if major != SUPPORTED_META_SCHEMA_MAJOR:
        raise _MetaError(
            "schema_version",
            "MAJOR version {0} is not supported (expected {1})".format(
                major, SUPPORTED_META_SCHEMA_MAJOR
            ),
        )


def _fallback_category_meta(category: str) -> CategoryMeta:
    """The stand-in used when a category's sidecar is missing or unusable."""
    return CategoryMeta(
        category=category,
        normalized_category=None,
        default_finding_type=FALLBACK_FINDING_TYPE,
        default_severity=FALLBACK_SEVERITY,
        rules={},
        is_fallback=True,
    )


def _validate_meta_document(category: str, document: object) -> CategoryMeta:
    """Validate one parsed ``_meta.json`` into a :class:`CategoryMeta`.

    Raises:
        _MetaError: Any structural problem. The caller downgrades the whole
            category rather than salvaging the entries that happened to
            validate, because a sidecar that is wrong in one place gives no
            reason to trust the Severity it states elsewhere.
    """
    payload = _meta_object("<root>", document)
    _meta_reject_unknown("", payload, _META_TOP_LEVEL_KEYS)
    for required in ("schema_version", "default"):
        if required not in payload:
            raise _MetaError(required, "required field is missing")
    _meta_schema_version(payload["schema_version"])

    defaults = _meta_object("default", payload["default"])
    _meta_reject_unknown("default", defaults, _META_DEFAULT_KEYS)
    for required in _META_DEFAULT_KEYS:
        if required not in defaults:
            raise _MetaError("default.{0}".format(required), "required field is missing")

    normalized = payload.get("normalized_category")
    rules_payload = _meta_object("rules", payload.get("rules", {}))
    validated: Dict[str, Dict[str, Any]] = {}
    for rule_name in sorted(rules_payload):
        rule_path = "rules.{0}".format(rule_name)
        if not rule_name:
            raise _MetaError("rules", "rule name keys must not be empty")
        entry = _meta_object(rule_path, rules_payload[rule_name])
        _meta_reject_unknown(rule_path, entry, _META_RULE_KEYS)
        if "severity" in entry:
            _meta_enum(
                "{0}.severity".format(rule_path), entry["severity"], SEVERITIES
            )
        if "finding_type" in entry:
            _meta_enum(
                "{0}.finding_type".format(rule_path),
                entry["finding_type"],
                FINDING_TYPES,
            )
        if "normalized_category" in entry:
            _meta_category_name(
                "{0}.normalized_category".format(rule_path),
                entry["normalized_category"],
            )
        for key in ("why_it_matters", "recommendation"):
            if key in entry:
                _meta_text("{0}.{1}".format(rule_path, key), entry[key])
        validated[rule_name] = dict(entry)

    return CategoryMeta(
        category=category,
        normalized_category=(
            None
            if normalized is None
            else _meta_category_name("normalized_category", normalized)
        ),
        default_finding_type=_meta_enum(
            "default.finding_type", defaults["finding_type"], FINDING_TYPES
        ),
        default_severity=_meta_enum(
            "default.severity", defaults["severity"], SEVERITIES
        ),
        rules=validated,
        is_fallback=False,
    )


def _load_category_meta(
    directory: Path,
) -> Tuple[CategoryMeta, Optional[TemplateParseError]]:
    """Load one category directory's sidecar, falling back on any problem.

    Returns:
        ``(meta, error)``. ``error`` is ``None`` on success; otherwise ``meta``
        is the fallback stand-in and ``error`` is the ``parse_failure`` to record
        in ``errors[]`` (design.md: "そのカテゴリ全体を fallback 値で処理し、
        ``errors[]`` に ``error_class: "parse_failure"`` を記録する").
    """
    category = directory.name
    sidecar = directory / META_FILENAME
    try:
        text = sidecar.read_text(encoding="utf-8")
    except OSError as exc:
        return (
            _fallback_category_meta(category),
            _meta_parse_failure(
                sidecar,
                "<file>",
                "cannot be read ({0})".format(os_error_detail(exc)),
            ),
        )
    except ValueError as exc:  # UnicodeDecodeError
        return (
            _fallback_category_meta(category),
            _meta_parse_failure(sidecar, "<file>", "is not valid UTF-8 ({0})".format(exc)),
        )

    try:
        document = json.loads(text)
    except ValueError as exc:
        return (
            _fallback_category_meta(category),
            _meta_parse_failure(
                sidecar,
                "<file>",
                "is not valid JSON ({0})".format(exc),
                error_type=type(exc).__name__,
                line=getattr(exc, "lineno", None),
                column=getattr(exc, "colno", None),
            ),
        )

    try:
        return _validate_meta_document(category, document), None
    except _MetaError as exc:
        return (
            _fallback_category_meta(category),
            _meta_parse_failure(sidecar, exc.field, exc.reason),
        )


def _meta_parse_failure(
    sidecar: Path,
    field_path: str,
    reason: str,
    *,
    error_type: str = "cfn-guard rule metadata",
    line: Optional[int] = None,
    column: Optional[int] = None,
) -> TemplateParseError:
    """Build the ``parse_failure`` recorded for an unusable sidecar.

    The sidecar is named as ``<category>/_meta.json`` rather than by its full
    path. This error lands in ``errors[]`` on stdout (see
    :attr:`RuleMetadata.errors`), and for the bundled rule set the full path is
    the plugin's install directory -- an absolute host path Requirement 16 AC11
    keeps out of stdout. The category directory plus the file name is what a
    contributor needs in order to find it, and it is the same string whichever
    machine reported it.
    """
    location = "{0}/{1}".format(sidecar.parent.name, sidecar.name)
    error = TemplateParseError(
        "{0}: {1}: {2}".format(location, field_path, reason),
        error_type=error_type,
        line=line,
        column=column,
        tool=CFN_GUARD,
        remediation=(
            "Rules in the {0} category fall back to {1} / {2}. Fix {3} to "
            "restore the category's own values.".format(
                sidecar.parent.name, FALLBACK_FINDING_TYPE, FALLBACK_SEVERITY, location
            )
        ),
    )
    error.field = field_path
    error.reason = reason
    return error


class RuleMetadata:
    """Rule metadata for every ``.guard`` file under the scanned directories.

    Produced by :func:`load_rule_metadata`, never constructed from raw JSON by
    callers: the constructor takes already-validated pieces, so
    :meth:`for_rule` can read them without re-checking types.

    A rule's metadata comes from the ``_meta.json`` sitting *next to it*, and
    lookups are keyed on that directory rather than on its name. So two scanned
    roots may each hold an ``encryption/`` directory and each rule still
    resolves against the sidecar beside it. Keying on the name would have made
    one sidecar silently govern rules in the other directory.

    That single rule covers both the bundled layout, where each category is its
    own directory, and a flat user-supplied directory, whose own name becomes
    the category. It is also what Requirement 5 AC8 asks for: adding a rule
    touches one new ``.guard`` file and one entry in one sidecar, both inside a
    single directory, so contributors working on different categories never edit
    the same file.
    """

    def __init__(
        self,
        *,
        meta_by_directory: Mapping[Path, CategoryMeta],
        directory_of_rule: Mapping[str, Path],
        errors: Sequence[Dict[str, object]],
    ) -> None:
        self._meta_by_directory = dict(meta_by_directory)
        self._directory_of_rule = dict(directory_of_rule)
        self._errors = tuple(errors)

    @property
    def errors(self) -> Tuple[Dict[str, object], ...]:
        """StructuredError dicts for every sidecar that could not be used.

        Goes straight into ``SourceResult.errors``. Empty when every scanned
        directory had a usable ``_meta.json``.
        """
        return self._errors

    @property
    def rule_count(self) -> int:
        """Number of distinct ``.guard`` rules discovered.

        The fallback for ``stats.rules_evaluated`` when cfn-guard's own output
        does not report the counts (Requirement 5 AC4).
        """
        return len(self._directory_of_rule)

    def rule_names(self) -> Tuple[str, ...]:
        """Every discovered rule name, sorted.

        Sorted so that the order does not depend on the order the directories
        were passed in or on filesystem iteration order (Requirement 16 AC11).
        """
        return tuple(sorted(self._directory_of_rule))

    def category_names(self) -> Tuple[str, ...]:
        """Every scanned category directory name, sorted and deduplicated."""
        return tuple(
            sorted({directory.name for directory in self._meta_by_directory})
        )

    def category_meta(self, category: str) -> Optional[CategoryMeta]:
        """The :class:`CategoryMeta` for a category *name*, or ``None``.

        A convenience for tests and reports. When two scanned roots each hold a
        directory of that name, the one whose path sorts first is returned;
        :meth:`for_rule` does not go through here and is unaffected, because it
        resolves through the directory the rule was actually found in.
        """
        for directory in sorted(self._meta_by_directory, key=lambda path: str(path)):
            if directory.name == category:
                return self._meta_by_directory[directory]
        return None

    def for_rule(self, rule_name: str) -> RuleMeta:
        """Resolve the metadata for one rule.

        Resolution order per field is ``rules[<rule_name>].<field>`` ->
        ``default.<field>`` -> hardcoded fallback, exactly as design.md
        specifies. ``normalized_category`` has one extra step before the
        fallback: the sidecar's category-wide ``normalized_category``, so a
        category states its Category once and only an exception like
        ``security_group_open_ingress`` -> ``NetworkSecurity`` repeats it.

        The last resort for ``normalized_category`` is
        :meth:`~iacreview.categories.CategoryMap.for_guard_rule`, which knows
        ``cfnguard.rule_categories`` and ends at ``Other``. The sidecar is
        consulted first, per design.md's "``_meta.json`` を優先".

        Args:
            rule_name: Name as it appears in cfn-guard's output.

        Returns:
            A fully populated :class:`RuleMeta`. A rule name that matched no
            ``.guard`` file still resolves, with ``category=None`` and the
            fallback values, because cfn-guard reporting a rule this loader
            never saw is a reason to classify conservatively rather than to fail
            the review.
        """
        directory = self._directory_of_rule.get(rule_name)
        meta = self._meta_by_directory.get(directory) if directory is not None else None
        category = meta.category if meta is not None else None
        entry: Mapping[str, Any] = meta.rules.get(rule_name, {}) if meta else {}

        finding_type = entry.get("finding_type") or (
            meta.default_finding_type if meta else FALLBACK_FINDING_TYPE
        )
        severity = entry.get("severity") or (
            meta.default_severity if meta else FALLBACK_SEVERITY
        )
        normalized = entry.get("normalized_category") or (
            meta.normalized_category if meta else None
        )
        if normalized is None:
            normalized = categories.load_map().for_guard_rule(
                rule_name, category
            ).category
        return RuleMeta(
            rule_name=rule_name,
            category=category,
            finding_type=finding_type,
            severity=severity,
            normalized_category=normalized,
            why_it_matters=entry.get("why_it_matters", ""),
            recommendation=entry.get("recommendation", ""),
            from_sidecar=bool(meta is not None and not meta.is_fallback),
        )


def _discover_rule_files(roots: Iterable[Path]) -> List[Path]:
    """Find every ``.guard`` file under ``roots``, deterministically ordered.

    Each root is walked recursively, so both the bundled
    ``rules/<category>/*.guard`` layout and a flat directory of ``.guard`` files
    are handled by the same code. Results are sorted by resolved path, which
    removes any dependence on filesystem iteration order and, together with the
    first-wins rule in :func:`load_rule_metadata`, makes the outcome independent
    of the order the roots were supplied in.

    A root that is a single ``.guard`` file is accepted too, since cfn-guard's
    ``--rules`` takes either.
    """
    found: List[Path] = []
    for root in roots:
        if root.is_file():
            if root.suffix == GUARD_RULE_SUFFIX:
                found.append(root)
            continue
        if not root.is_dir():
            continue
        found.extend(
            path
            for path in root.rglob("*{0}".format(GUARD_RULE_SUFFIX))
            if path.is_file()
        )
    return sorted(set(found), key=lambda path: str(path))


def load_rule_metadata(
    rules_dirs: Optional[Sequence[Path]] = None,
) -> RuleMetadata:
    """Load the ``_meta.json`` sidecars covering the given rule directories.

    cfn-guard has no notion of severity, so the FindingType, Severity and
    Normalized_Category of every Guard Finding come from here (design.md,
    Severity の付与方式, 案 C).

    A missing or unusable sidecar is not a failure. Its whole category falls
    back to :data:`FALLBACK_FINDING_TYPE` / :data:`FALLBACK_SEVERITY`, a
    ``parse_failure`` lands in :attr:`RuleMetadata.errors`, and rule execution
    continues. The rules themselves are still valid; only their classification
    is degraded, and reporting a violation at MEDIUM is better than not
    reporting it.

    Args:
        rules_dirs: Directories, or individual ``.guard`` files, to scan.
            ``None`` means the bundled ``rules/`` tree, resolved through
            :func:`iacreview.pathguard.resolve_plugin_owned`. A caller passing
            user-supplied paths must resolve them through
            :func:`iacreview.pathguard.resolve_within` first; this function does
            no containment checking of its own.

    Returns:
        A :class:`RuleMetadata`. When two directories declare the same rule
        name, the one whose path sorts first wins, so the result does not depend
        on the order ``rules_dirs`` was given in.

    Raises:
        MappingFileError: ``rules_dirs`` is ``None`` and the bundled ``rules/``
            directory is missing, which means a broken installation. Also raised
            if ``category_map.json`` itself is unreadable, since the closed
            Normalized_Category vocabulary is validated against it.
    """
    if rules_dirs is None:
        roots: List[Path] = [
            pathguard.resolve_plugin_owned(DEFAULT_RULES_RELATIVE_PATH)
        ]
    else:
        roots = [Path(entry) for entry in rules_dirs]

    directory_of_rule: Dict[str, Path] = {}
    for rule_file in _discover_rule_files(roots):
        rule_name = rule_file.stem
        if rule_name in directory_of_rule:
            continue  # First in sorted order wins; see the docstring.
        directory_of_rule[rule_name] = rule_file.parent

    meta_by_directory: Dict[Path, CategoryMeta] = {}
    errors: List[Dict[str, object]] = []
    for directory in sorted(set(directory_of_rule.values()), key=lambda path: str(path)):
        meta, error = _load_category_meta(directory)
        meta_by_directory[directory] = meta
        if error is not None:
            errors.append(error.to_structured_error(source=SOURCE_NAME))

    return RuleMetadata(
        meta_by_directory=meta_by_directory,
        directory_of_rule=directory_of_rule,
        errors=errors,
    )

# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def resolve_rules_dirs(
    rules_dirs: Optional[Sequence[Union[str, Path]]], workspace_root: Path
) -> List[Path]:
    """Decide which rule directories one run evaluates (design.md, O-10).

    The bundled rule set is always first and always present, which is what keeps
    the Source working with no configuration at all (Requirement 10 AC1).
    ``rules_dirs`` *adds* to it; it does not replace it.

    Args:
        rules_dirs: User-supplied directories, or individual ``.guard`` files.
            Each is resolved through
            :func:`iacreview.pathguard.resolve_within`, so a path outside the
            workspace is rejected rather than handed to the tool
            (Requirement 15 AC3). ``None`` and an empty sequence both mean
            "bundled rules only".
        workspace_root: Containment root for those paths.

    Returns:
        The bundled rules root, followed by the resolved user directories
        deduplicated and sorted by path. Sorted because ``--rules`` order
        decides the order cfn-guard emits its records in, and two callers who
        named the same directories in a different order must get byte-identical
        output (Requirement 10 AC3). Sorting the command line is half of that;
        :func:`sort_results` is the other half, and it is the load-bearing one,
        since only it also covers a version that reorders records on its own.
        A directory that is the bundled root, or a duplicate of another entry,
        appears once: cfn-guard evaluates a rule once per ``--rules`` occurrence,
        so a repeat would report the same violation twice.

    Raises:
        UnsafeArgumentError: An entry contains a shell metacharacter.
        InvalidArgumentsError: An entry is empty or cannot be normalized.
        PathContainmentError: An entry resolves outside ``workspace_root``.
        InputNotFoundError: An entry does not exist. Reported rather than
            skipped: a rule directory the user named and that is not there means
            the review would silently apply fewer policies than asked for.
        MappingFileError: The bundled ``rules/`` directory is missing, which
            means a broken installation.
    """
    bundled = pathguard.resolve_plugin_owned(DEFAULT_RULES_RELATIVE_PATH)
    extra: List[Path] = []
    for entry in rules_dirs or ():
        resolved = pathguard.resolve_within(str(entry), workspace_root)
        if resolved != bundled:
            extra.append(resolved)
    return [bundled] + sorted(set(extra), key=str)


def build_argv(
    template_path: Union[str, Path],
    rules_dirs: Sequence[Union[str, Path]],
    executable: str = CFN_GUARD,
) -> List[str]:
    """Build the cfn-guard command line (design.md, cfn-guard Integration).

    Every flag is fixed; only the Template path and the rule directories vary.
    Three flags carry the weight:

    ``--type CFNTemplate``
        Makes cfn-guard read the input as a CloudFormation Template, which is
        what puts the logical resource name in the property path. Without it the
        output carries raw paths only and Requirement 5 AC3's "logical resource
        identifier" would be unobtainable.

    ``--output-format json``
        The default is ``single-line-summary``, which is written for people. See
        ``tests/fixtures/tool_output/cfnguard_malformed.txt`` for what that looks
        like, and why it must never be parsed.

    ``--show-summary none``
        Suppresses the summary block so stdout is records only.

    ``--structured`` (absent)
        Deliberately not used: ``--output-format json`` with
        ``--show-summary none`` already yields everything the Source needs, and
        ``--structured`` conflicts with the summary and verbosity flags.

    Argument safety has three layers and no shell in any of them
    (Requirement 9 AC4, AC5): :mod:`iacreview.proc` runs with ``shell=False``,
    :func:`iacreview.pathguard.resolve_within` has already rejected shell
    metacharacters, and the paths it returns are absolute, so no value here can
    begin with ``-`` and be re-read as a flag. cfn-guard has no ``--``
    end-of-options marker to rely on, which is why the third layer matters.

    Args:
        template_path: The Template to review, already resolved and contained.
        rules_dirs: Rule directories, normally the output of
            :func:`resolve_rules_dirs`. Each becomes its own ``--rules``
            occurrence, in the order given.
        executable: What to place in ``argv[0]``. Defaults to the bare name for
            readability in tests; :func:`run_and_normalize` passes
            :attr:`~iacreview.toolcheck.ToolInfo.path` so that the binary whose
            version was checked is the binary that runs.

    Returns:
        A fresh list, safe for the caller to keep or log.

    Raises:
        InvalidArgumentsError: ``rules_dirs`` is empty. cfn-guard requires at
            least one ``--rules``, and letting it fail on its own would report a
            usage error as a tool failure (Requirement 16 AC7).
    """
    roots = list(rules_dirs)
    if not roots:
        raise InvalidArgumentsError(
            "cfn-guard requires at least one rules directory; got none"
        )
    argv = [executable, "validate", "--data", str(template_path)]
    for directory in roots:
        argv.extend(["--rules", str(directory)])
    argv.extend(
        [
            "--output-format",
            "json",
            "--type",
            "CFNTemplate",
            "--show-summary",
            "none",
        ]
    )
    return argv


def initial_stats() -> Dict[str, Any]:
    """Return the :data:`STATS_KEYS` dict for a run that has not started.

    Every key is present from the outset, so a result from a Source that failed
    before starting the tool has the same shape as one from a complete run. The
    counters are ``None`` rather than ``0``, because "cfn-guard never ran" and
    "cfn-guard evaluated no rules" are different claims and only the second one
    is a number. ``violations_parsed`` is the exception: it counts what this
    Source parsed, and it parsed nothing.
    """
    return {
        "tool_version": None,
        "exit_code": None,
        "violations_parsed": 0,
        "rules_evaluated": None,
        "rules_passed": None,
        "rules_not_applicable": None,
        "rules_evaluated_source": None,
    }


# ---------------------------------------------------------------------------
# Rule counting (Requirement 5 AC4)
# ---------------------------------------------------------------------------


def count_rules(
    records: Sequence[GuardRecord],
) -> Optional[Tuple[int, int, int]]:
    """Count evaluated, passed and skipped rules from cfn-guard's own output.

    cfn-guard names the rules it has something to say about: ``compliant`` for
    the ones that passed, ``not_applicable`` for the ones whose ``when`` guard
    did not match, and one ``not_compliant`` entry per violated rule. The union
    of those three names is the set of rules that were evaluated, so the counts
    are read off the output rather than estimated. On the bundled rule set that
    union comes to eleven, matching the eleven ``.guard`` files, which is the
    check that this reading is the right one.

    Args:
        records: Output of :func:`parse_records`. Empty is accepted and yields
            ``None``.

    Returns:
        ``(evaluated, passed, not_applicable)``, or ``None`` when the output
        carried no ``compliant`` or ``not_applicable`` list at all. Both fields
        are optional in :func:`parse_records`, and a version that omits them
        leaves only the violated names visible -- from which ``evaluated`` would
        come out equal to the number of failures, i.e. "every rule failed",
        which is exactly the kind of confident wrong number this returns
        ``None`` to avoid. The caller then falls back to counting rule
        declarations.
    """
    reported = False
    compliant: set = set()
    not_applicable: set = set()
    violated: set = set()
    for record in records:
        if record.compliant or record.not_applicable:
            reported = True
        compliant.update(record.compliant)
        not_applicable.update(record.not_applicable)
        violated.update(result.rule_name for result in record.violations)
    if not reported:
        return None
    evaluated = len(compliant | not_applicable | violated)
    return evaluated, len(compliant), len(not_applicable)


def _record_counts(
    stats: Dict[str, Any],
    records: Sequence[GuardRecord],
    metadata: RuleMetadata,
) -> None:
    """Fill the four rule counters in ``stats``, from output or by counting rules.

    The fallback is design.md's: count the ``rule`` declarations under the
    scanned rule directories and take ``rules_passed = rules_evaluated -
    violated``. :attr:`RuleMetadata.rule_count` is that declaration count -- one
    per discovered ``.guard`` file, which is exact for this rule set because
    ``tests/unit/test_guard_rules.py`` asserts one ``rule`` declaration per file
    and a name matching the filename.

    The two paths do not mean quite the same thing, which is why
    ``rules_evaluated_source`` records which one produced the numbers. From the
    output, a skipped rule is counted under ``rules_not_applicable`` and not
    under ``rules_passed``. From the declaration count, skipped rules are
    invisible, so they land in ``rules_passed`` and ``rules_not_applicable``
    stays ``None`` rather than claiming zero. Task 26.1 records this in
    ``docs/architecture.md``.
    """
    violated = {
        result.rule_name for record in records for result in record.violations
    }
    counted = count_rules(records)
    if counted is not None:
        evaluated, passed, not_applicable = counted
        stats["rules_not_applicable"] = not_applicable
        stats["rules_evaluated_source"] = RULES_COUNT_FROM_OUTPUT
    else:
        evaluated = metadata.rule_count
        # max(): a rule name cfn-guard reported that no scanned directory
        # declares would otherwise drive the count of passed rules negative.
        passed = max(evaluated - len(violated), 0)
        stats["rules_not_applicable"] = None
        stats["rules_evaluated_source"] = RULES_COUNT_FROM_DECLARATIONS
    stats["rules_evaluated"] = evaluated
    stats["rules_passed"] = passed


# ---------------------------------------------------------------------------
# Finding construction
# ---------------------------------------------------------------------------


def _first_sentence(text: str) -> str:
    """First sentence of a rule's custom message, or all of it if it is one."""
    return _SENTENCE_BOUNDARY.split(text.strip(), 1)[0]


def _finding_text(result: RawResult) -> str:
    """``Finding``: ``"[{rule_name}] {first sentence of the custom message}"``.

    Only the first sentence, because the rest of a ``<<...>>`` message is
    remediation advice, which belongs in ``SuggestedRemediation`` and is carried
    there in full.
    """
    message = (
        _first_sentence(result.custom_message)
        if result.custom_message
        else FINDING_FALLBACK_TEXT
    )
    return "[{0}] {1}".format(result.rule_name, message)


def _value_detail(result: RawResult) -> str:
    """The provided / expected part of the Evidence detail.

    design.md specifies ``"provided: <v>, expected: <e>"``, which reads correctly
    for a positive comparison such as ``StorageEncrypted == true``: cfn-guard
    reports ``from.value`` ``false`` against ``to.value`` ``true``.

    A negated clause needs different wording. ``security_group_open_ingress``
    asserts ``CidrIp != "0.0.0.0/0"``, and the violation cfn-guard reports for it
    carries ``from.value`` and ``to.value`` both equal to ``"0.0.0.0/0"``; the
    plain form would render "provided: 0.0.0.0/0, expected: 0.0.0.0/0", which
    states the opposite of what the rule requires.

    Equality of the two values is a sound signal here, not a guess: a check that
    *failed* while the template's value equals the value compared against can
    only have been comparing for inequality, since an equality comparison
    between equal values passes. So that case is rendered as "which the check
    requires it not to be". The clause text cfn-guard printed is in
    :attr:`RawResult.context`, which :func:`_evidence_detail` includes verbatim,
    so the negation is also visible in the operator the tool itself reported
    (``not EQUALS``) rather than resting on this inference alone.
    """
    if result.provided_value is None:
        return VALUE_ABSENT_TEXT
    if result.expected_value is None:
        return VALUE_PROVIDED_ONLY_TEXT.format(provided=result.provided_value)
    if result.provided_value == result.expected_value:
        return VALUE_REJECTED_TEXT.format(provided=result.provided_value)
    return VALUE_COMPARED_TEXT.format(
        provided=result.provided_value, expected=result.expected_value
    )


def _evidence_detail(result: RawResult) -> str:
    """``Evidence[0].Detail``: the clause that failed and the value it saw.

    The clause text is included because it is what cfn-guard actually checked,
    stated in the tool's own words, and a rule name only implies it.
    ``error_message`` is not appended: it restates these same facts and embeds
    the whole struct cfn-guard traversed, which for a missing property is the
    entire ``Properties`` block of the resource. Evidence is not the place to
    reproduce arbitrary template content, and the property path in
    ``Location.TemplatePath`` already points a reader at it.
    """
    detail = "cfn-guard rule {0} reported a violation".format(result.rule_name)
    if result.context:
        detail = "{0} of the check {1}".format(detail, result.context)
    return "{0}. {1}.".format(detail, _value_detail(result))


def _why_it_matters(result: RawResult, meta: RuleMeta) -> str:
    """``WhyItMatters``: the sidecar's wording, else a statement of the mapping.

    cfn-guard says nothing about consequence -- a rule is a comparison -- so
    unlike the cfn-lint Source there is no tool-supplied middle option here. A
    rule with no ``why_it_matters`` entry is a gap in the rule set, and the
    fallback says only what can be said without inventing a rationale.
    """
    return meta.why_it_matters or WHY_IT_MATTERS_FALLBACK.format(
        rule_name=result.rule_name,
        finding_type=meta.finding_type,
        severity=meta.severity,
    )


def _recommendation(result: RawResult, meta: RuleMeta) -> str:
    """``Recommendation``: sidecar entry, else the rule's message, else generic.

    The sidecar comes first because it is wording a maintainer wrote for this
    plugin's report, whereas the ``<<...>>`` message is written for whoever runs
    cfn-guard directly. When the sidecar has none, the message is the better
    of the two remaining options.
    """
    return (
        meta.recommendation
        or result.custom_message
        or RECOMMENDATION_FALLBACK.format(rule_name=result.rule_name)
    )


def _suggested_remediation(result: RawResult, meta: RuleMeta) -> Optional[str]:
    """``SuggestedRemediation``: the rule's ``<<...>>`` message (design.md).

    This is the field Requirement 5 AC3's "remediation guidance statement" maps
    onto. The rule's own message wins here, the reverse of
    :func:`_recommendation`, because it was written against the specific clause
    that failed. ``None`` when neither source has wording, which the schema
    permits.
    """
    return result.custom_message or meta.recommendation or None


def _location(result: RawResult, template_file: str) -> Location:
    """Build ``Location``. ``Line`` and ``Column`` are always ``None``.

    cfn-guard does report positions, but only inside the prose of
    ``error_message`` (``[L:25,C:18]``), and only for some check shapes. Reading
    them out of an error string would make the position depend on a message
    format the tool does not treat as an interface, so design.md leaves both
    ``null`` and points a reader at ``TemplatePath`` instead
    (Requirement 7 AC1 requires a Location, not a line number).

    ``File`` is the reviewed Template, which is sound because this Source submits
    exactly one ``--data`` per run. ``TemplatePath`` is ``None`` rather than an
    empty list when cfn-guard reported no path at all, which happens for a
    dependent-rule failure that has no template location of its own.
    """
    return Location(
        File=template_file,
        Line=None,
        Column=None,
        TemplatePath=list(result.template_path) or None,
    )


def finding_from_result(
    result: RawResult,
    *,
    template_file: str,
    metadata: Optional[RuleMetadata] = None,
) -> Finding:
    """Build one Finding from one violated cfn-guard check (design.md table).

    All 13 fields are filled here. Three are constant for this Source:

    * ``Confidence`` is always ``Confirmed`` (Requirement 7 AC8): a rule either
      matched or it did not.
    * ``Source`` is always ``["cfn-guard"]``, built through
      :func:`iacreview.finding.sorted_sources` so the list satisfies the
      schema's ordering rule without this module knowing the order.
    * ``Evidence[0].Excerpt`` is always ``None``. Requirement 7 AC11 requires an
      excerpt only below ``Confirmed``; the clause that fired is the evidence,
      and quoting template text would reproduce untrusted content for no gain.

    ``FindingType``, ``Severity`` and ``Normalized_Category`` come from the
    ``_meta.json`` sidecars via :meth:`RuleMetadata.for_rule`, because cfn-guard
    has no concept of any of the three.

    ``ID`` is :data:`~iacreview.finding.UNASSIGNED_ID`. IDs are sequential over
    the sorted, deduplicated report (Requirement 7 AC1, AC15), which is decided
    long after this function runs, so a Finding returned from here does not pass
    :func:`iacreview.finding.validate` until the report assigns its ID.

    Args:
        result: One violated check, from :func:`parse_output`.
        template_file: Workspace-relative path of the reviewed Template.
        metadata: Loaded rule metadata. ``None`` loads the bundled rule set's
            sidecars; :func:`normalize_results` passes an already-loaded one so
            a payload of many violations reads the sidecars once.

    Returns:
        The Finding. Not validated here: see above on ``ID``.

    Raises:
        MappingFileError: ``metadata`` is ``None`` and the bundled ``rules/``
            directory or ``category_map.json`` is missing or corrupt.
    """
    if metadata is None:
        metadata = load_rule_metadata()
    meta = metadata.for_rule(result.rule_name)

    return Finding(
        ID=UNASSIGNED_ID,
        Normalized_Category=meta.normalized_category,
        FindingType=meta.finding_type,
        Severity=meta.severity,
        Confidence=CONFIRMED,
        Source=sorted_sources([SOURCE_NAME]),
        Resource=result.resource,
        Location=_location(result, template_file),
        Finding=_finding_text(result),
        WhyItMatters=_why_it_matters(result, meta),
        Evidence=[
            Evidence(
                Source=SOURCE_NAME,
                Detail=_evidence_detail(result),
                RuleId=result.rule_name,
                Excerpt=None,
            )
        ],
        Recommendation=_recommendation(result, meta),
        SuggestedRemediation=_suggested_remediation(result, meta),
    )


def sort_results(results: Sequence[RawResult]) -> List[RawResult]:
    """Order violated checks by rule name, then resource, then property path.

    This is what makes the Source's output independent of the ``--rules`` order
    (design.md, O-10). cfn-guard emits one record per rule file in the order it
    collected the files, so naming the same directories in a different order
    reorders the findings without changing them; sorting on the rule name
    removes that dependence at the point where it is observable.

    The tie-breakers matter for a rule that fires on several resources, such as
    ``required_tags``: rule name alone would leave those in filesystem order.
    The sort is stable, so any remaining tie keeps cfn-guard's own order.

    Unlike the cfn-lint Source, which preserves tool order, ordering here is not
    left to the report. Requirement 7 AC15 sorts by Severity and resource, which
    does not fully order two findings from different rules on the same resource
    at the same Severity.
    """
    return sorted(
        results,
        key=lambda result: (
            result.rule_name,
            result.resource or "",
            "/".join(str(segment) for segment in result.template_path),
            result.provided_value or "",
            result.expected_value or "",
        ),
    )


def normalize_results(
    results: Sequence[RawResult],
    *,
    template_file: str,
    metadata: Optional[RuleMetadata] = None,
) -> List[Finding]:
    """Build Findings for every violated check, in :func:`sort_results` order.

    Args:
        results: Output of :func:`parse_output`.
        template_file: Workspace-relative path of the reviewed Template.
        metadata: Loaded rule metadata. ``None`` loads the bundled rule set's
            sidecars once for the whole batch.

    Returns:
        One Finding per result, all carrying
        :data:`~iacreview.finding.UNASSIGNED_ID`.
    """
    if metadata is None:
        metadata = load_rule_metadata()
    return [
        finding_from_result(
            result, template_file=template_file, metadata=metadata
        )
        for result in sort_results(results)
    ]


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------


def _record(
    errors: List[StructuredError], exc: IacReviewError
) -> List[StructuredError]:
    """Append ``exc`` to ``errors`` as a StructuredError attributed to cfn-guard."""
    errors.append(exc.to_structured_error(source=SOURCE_NAME))
    return errors


def _execution_error(interpretation: GuardInterpretation) -> ToolExecutionError:
    """Build the ``tool_execution`` error for a run classified as a tool error.

    Reached when cfn-guard exited non-zero and its stdout was not the expected
    result structure: a missing rules directory, a ``.guard`` file that does not
    parse, a Template cfn-guard cannot read. The exit code is reported because
    Requirement 15 AC7 asks for it, not because anything read it; the stderr
    lines are what actually explain the failure, and they are already capped at
    :data:`~iacreview.errors.STDERR_HEAD_MAX_LINES`.
    """
    return ToolExecutionError(
        "cfn-guard exited with code {0} and its output was not a validation "
        "result, so the run failed rather than reporting violations".format(
            interpretation.exit_code
        ),
        tool=CFN_GUARD,
        tool_exit_code=interpretation.exit_code,
        stderr="\n".join(interpretation.stderr_head),
        remediation=(
            "Run cfn-guard on the template directly to see the full error. "
            "Check that every rules directory exists and that each .guard file "
            "parses."
        ),
    )


def run_and_normalize(
    template: Path,
    rules_dirs: Optional[Sequence[Path]] = None,
    tool: Optional[ToolInfo] = None,
    *,
    workspace_root: Optional[Path] = None,
    metadata: Optional[RuleMetadata] = None,
) -> SourceResult:
    """Run cfn-guard against one Template and return normalized Findings.

    The whole Source in one call: contain the paths, load the rule metadata,
    verify the tool, run it, classify the outcome, parse stdout, count the rules,
    build the Findings. A compliant Template yields ``findings=[]`` with the rule
    counts filled in, which is what Requirement 5 AC4 asks a clean run to report.

    Args:
        template: Path to the Template. Passed through
            :func:`iacreview.pathguard.resolve_within` before it reaches the
            command line, so containment holds even if the caller forgot
            (Requirement 9 AC4, AC5).
        rules_dirs: Additional rule directories, each contained in the same way.
            The bundled rule set is always evaluated as well; see
            :func:`resolve_rules_dirs`. Their order does not affect the result.
        tool: An already-verified cfn-guard. ``None`` verifies it here through
            :func:`iacreview.toolcheck.require_known_tool`, which is the normal
            path; an orchestrator reviewing many Templates passes one
            :class:`~iacreview.toolcheck.ToolInfo` so ``--version`` runs once.
        workspace_root: Containment root, and the root ``Location.File`` is
            relative to. Defaults to the current working directory, which is the
            workspace root for every entry point of this plugin.
        metadata: Pre-loaded rule metadata, for the same reason as ``tool``.
            ``None`` loads the sidecars of the directories this run evaluates.

    Returns:
        A :class:`~iacreview.source.SourceResult` whose ``source`` is always
        ``"cfn-guard"``. ``errors`` holds one entry for each of these:

        ==============================  =====================
        Situation                       ``error_class``
        ==============================  =====================
        cfn-guard absent from PATH      ``tool_unavailable``
        cfn-guard older than 3.0.0      ``tool_version``
        non-zero exit, unusable stdout  ``tool_execution``
        exceeded :data:`TIMEOUT_S`      ``tool_timeout``
        stdout did not match            ``parse_failure``
        a ``_meta.json`` is unusable    ``parse_failure``
        ==============================  =====================

        ``findings`` is empty for all but the last, which degrades one category
        of rules to the fallback FindingType and Severity and keeps going
        (design.md: "rule 実行そのものは継続する"). Sidecar errors are appended
        after any tool error, so :meth:`~iacreview.source.SourceResult.exit_status`
        reports the failure that actually stopped the review.

        On a tool error the rule counters stay ``None``: cfn-guard did not
        finish, and stating how many rules it evaluated would describe a run
        that did not happen.

    Raises:
        UnsafeArgumentError: A path contains a shell metacharacter.
        InvalidArgumentsError: A path is empty or cannot be normalized.
        PathContainmentError: A path resolves outside ``workspace_root``.
        InputNotFoundError: A path does not exist.
        MappingFileError: The bundled ``rules/`` tree or the category mapping is
            missing or corrupt.

        These are not folded into ``errors``: they mean the caller asked for
        something that cannot be reviewed, or that the installation is broken,
        and continuing would report a review that never happened.
    """
    root = Path.cwd() if workspace_root is None else Path(workspace_root)
    resolved = pathguard.resolve_within(str(template), root)
    # resolve_within guarantees containment, so this is relative; `.name` covers
    # only the degenerate case of the root itself being handed in.
    template_file = workspace_relative(str(resolved), root) or resolved.name
    roots = resolve_rules_dirs(rules_dirs, root)

    if metadata is None:
        metadata = load_rule_metadata(roots)
    sidecar_errors = list(metadata.errors)

    errors: List[StructuredError] = []
    stats = initial_stats()

    def finish(findings: List[Finding]) -> SourceResult:
        return SourceResult(
            source=SOURCE_NAME,
            findings=findings,
            errors=errors + sidecar_errors,
            stats=stats,
        )

    if tool is None:
        try:
            tool = require_known_tool(CFN_GUARD)
        except IacReviewError as exc:
            # tool_unavailable (Requirement 5 AC5) and tool_version. Reported,
            # not raised: the other Sources can still run.
            _record(errors, exc)
            return finish([])
    stats["tool_version"] = tool.version

    try:
        completed = proc.run(
            build_argv(resolved, roots, executable=tool.path), timeout_s=TIMEOUT_S
        )
    except IacReviewError as exc:
        # tool_timeout, or tool_execution / tool_unavailable if the binary became
        # unusable between the version check and now. A timeout is reported from
        # the exception, which carries the tool name and remediation;
        # interpret_guard_result's KIND_TIMEOUT serves a caller that holds a
        # ProcResult instead, such as one replaying a captured run.
        _record(errors, exc)
        return finish([])

    stats["exit_code"] = completed.exit_code
    interpretation = interpret_guard_result(completed)

    if interpretation.kind == KIND_TOOL_ERROR:
        # Requirement 5 AC6: report the failure with stderr and let the pipeline
        # continue with the remaining Skills.
        _record(errors, _execution_error(interpretation))
        return finish([])

    try:
        records = parse_records(completed.stdout)
    except TemplateParseError as exc:
        if interpretation.kind != KIND_ALL_PASSED:
            # A guard, not a reachable path today: on the violations path
            # interpret_guard_result has already parsed this same string. Kept so
            # that a future change there cannot turn a parse failure into a
            # silent all-clear.
            _record(errors, exc)
            return finish([])
        # Exit 0 is cfn-guard's own guarantee that every rule passed and is not
        # re-derived from stdout, so unreadable stdout here costs the counts and
        # nothing else. Reporting a parse_failure would turn a clean review into
        # a failed one; the fallback shows up in rules_evaluated_source instead.
        records = []

    violations = [result for record in records for result in record.violations]
    stats["violations_parsed"] = len(violations)
    _record_counts(stats, records, metadata)

    # On the all_passed path `violations` is normally empty. If a record on that
    # path does carry one, it is reported: exit 0 alongside a not_compliant entry
    # is a contradiction in the tool's own output, and dropping the entry would
    # be the one reading that loses information.
    return finish(
        normalize_results(
            violations, template_file=template_file, metadata=metadata
        )
    )
