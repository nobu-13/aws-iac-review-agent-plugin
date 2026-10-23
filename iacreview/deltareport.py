"""Output side of the v1.1 Delta_Tool: anonymize, assemble and serialize.

:func:`build_delta_report` turns the results of one Delta_Tool run (the
Semantic Diff, the Finding Delta, the per-side input metadata and the failures)
into the Delta_Report JSON object; :func:`render_delta_report` also serializes
it and enforces the output size limit. Both are pure: the only data read is the
Plugin's own category map, through ``categories.load_map`` as v1.0 does.

Every input-derived string goes through one decision (Design 10-1)
    A string taken from a Template or a Report is written in plain form only
    when it belongs to a closed, documented set at that position (a top-level
    section name, a Resource Attribute name, an Intrinsic Function name, an
    ``AWS::`` Resource Type of the documented form, a known Category, a known
    rule ID, a known tool name, a version of the documented form, ...). Every
    other string is replaced by an Identifier_Token. Template scalar values,
    Finding free text and the strings of input ``errors[]`` are never written.

Identifier_Tokens (Design 10-2)
    The strings replaced in one Delta_Report are collected first, sorted by
    Unicode code point and numbered ``id-000001``, ``id-000002``, ... in one
    namespace. The table depends only on that set, so it does not depend on
    input order or on the side a string came from. A Token holds neither the
    string nor a digest of it. With ``identifier_mode == "plain"`` the
    identifiers of Requirement 12 AC2 (path keys, Logical IDs, entry names,
    Finding ``Resource``, Resource Types) are written as they are; the other
    replaced strings (rule IDs, tool names and versions, Categories, error
    sources outside their closed sets) stay Tokens.

Keys that look like list indexes
    ``finding.canonical_template_path`` turns a digit-only mapping key below
    the entry level into an ``int``. For a Semantic Diff path the documents are
    walked along the path, so an ``int`` that names a mapping key is written as
    a Token of the original key and only a real list index is written as an
    integer. A Finding ``TemplatePath`` is walked the same way in the analyzed
    Template of its side; an ``int`` the walk cannot place under a list (the
    position is absent from that Template) is written as a Token. Without an
    analyzed Template for that side (a Report_Pair alone, or an unanalyzable
    Template) there is nothing to walk: an integer cannot be shown to be a list
    index, so every integer is written like a key, as the Token of its decimal
    string (the string itself in plain mode), and no list index is shown.

Order and bytes (Design 11-2)
    Change_Entries, uncompared paths and Delta_Entries are sorted by their
    output values (Tokens, not the original strings), integers before strings
    in a path. Serialization gives the characters of ``report.dump``, except
    that C1 controls and bidirectional controls and marks are written as JSON
    ``\\uXXXX`` escapes (D-14; the decoded value is the same). A
    serialized Delta_Report larger than ``deltaschema.MAX_OUTPUT_BYTES`` is
    replaced by the minimal Delta_Report: no Change_Entry and no Delta_Entry,
    every requested comparison ``unanalyzable``, and the
    ``output_size_limit_exceeded`` error.

Bounded work over the limit (RC Blocker P0)
    The limit is checked in stages so that an over-limit Delta_Report is never
    built in full: a request whose Change_Entries and uncompared paths alone
    need more bytes than the limit (a lower bound from path lengths) is not
    rendered, and serialization counts UTF-8 bytes chunk by chunk and stops at
    the first chunk over the limit. Neither check changes the result: the
    text of every Delta_Report within the limit, and the minimal Delta_Report,
    are the same bytes as when the whole text was built and then measured.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, Iterable, Iterator, List, Mapping, Optional, Sequence, Set, Tuple, Union

from iacreview import categories, deltaschema, finding, toolcheck, yamlcfn
from iacreview.delta import (
    REPORT_DECLARATIONS,
    TEMPLATE_DECLARATION,
    DeltaEntry,
    EvidenceDelta,
    EvidenceKey,
    FindingDeltaResult,
    FindingProjection,
)
from iacreview.deltaio import Failure, ParsedTemplate
from iacreview.errors import STRUCTURED_ERROR_KEYS
from iacreview.iam.detectors import SPECS as IAM_DETECTOR_SPECS
from iacreview.reportcheck import CheckedReport
from iacreview.semdiff import RESOURCE_ATTRIBUTES, ChangeEntry, SemanticDiffResult, UncomparedPath

__all__ = [
    "ENVELOPE_KEYS",
    "SIDE_INPUT_KEYS",
    "TEMPLATE_INPUT_KEYS",
    "REPORT_INPUT_KEYS",
    "SEMANTIC_DIFF_KEYS",
    "CHANGE_ENTRY_KEYS",
    "UNCOMPARED_PATH_KEYS",
    "FINDING_DELTA_KEYS",
    "DELTA_ENTRY_KEYS",
    "PROJECTION_KEYS",
    "EVIDENCE_KEYS",
    "EVIDENCE_DELTA_KEYS",
    "FAILURE_KEYS",
    "SUMMARY_KEYS",
    "SUMMARY_SEMANTIC_DIFF_KEYS",
    "SUMMARY_FINDING_DELTA_KEYS",
    "FORBIDDEN_KEYS",
    "TOP_LEVEL_SECTIONS",
    "RESOURCE_PLAIN_KEYS",
    "PARAMETER_ATTRIBUTES",
    "OUTPUT_ATTRIBUTES",
    "RULE_ATTRIBUTES",
    "INTRINSIC_NAMES",
    "PLAIN_TOOL_NAMES",
    "AWS_RESOURCE_TYPE_PATTERN",
    "CUSTOM_RESOURCE_PREFIX",
    "CFN_LINT_RULE_ID_PATTERN",
    "TOKEN_PREFIX",
    "TOKEN_MIN_WIDTH",
    "TemplateInput",
    "ReportInput",
    "FailureRecord",
    "DeltaRequest",
    "RenderedDeltaReport",
    "build_token_table",
    "failure_message",
    "structured_error",
    "build_delta_report",
    "render_delta_report",
    "dump",
]

# ---------------------------------------------------------------------------
# Key sets of the Delta_Report (Design 11-1, docs/delta-schema.md)
# ---------------------------------------------------------------------------

ENVELOPE_KEYS: Tuple[str, ...] = (
    "delta_schema_version",
    "scope",
    "identifier_mode",
    "inputs",
    "semantic_diff",
    "finding_delta",
    "errors",
    "summary",
)
SIDE_INPUT_KEYS: Tuple[str, ...] = ("template", "report")
TEMPLATE_INPUT_KEYS: Tuple[str, ...] = ("path", "format")
REPORT_INPUT_KEYS: Tuple[str, ...] = (
    "path",
    "sha256",
    "schema_version",
    "target",
    "sources_enabled",
    "tools",
    "error_summary",
)
SEMANTIC_DIFF_KEYS: Tuple[str, ...] = (
    "analysis_state",
    "observation",
    "structural_completeness",
    "semantic_limitations",
    "uncompared_paths",
    "changes",
    "failure",
)
CHANGE_ENTRY_KEYS: Tuple[str, ...] = (
    "section",
    "path",
    "change",
    "type_changed",
    "resource_type",
    "qualifiers",
    "hints",
)
UNCOMPARED_PATH_KEYS: Tuple[str, ...] = ("path", "reason")
FINDING_DELTA_KEYS: Tuple[str, ...] = (
    "analysis_state",
    "observation",
    "classification_completeness",
    "report_authenticity",
    "report_integrity",
    "input_declarations",
    "unverified_assumptions",
    "template_report_correspondence",
    "reviewed_template_path",
    "comparable",
    "entries",
    "failure",
)
DELTA_ENTRY_KEYS: Tuple[str, ...] = (
    "observation",
    "classification",
    "reasons",
    "missing_declarations",
    "key",
    "match_stage",
    "base",
    "head",
    "changes",
    "evidence_absent_in_head",
    "evidence_absent_in_base",
)
PROJECTION_KEYS: Tuple[str, ...] = (
    "ID",
    "File",
    "Resource",
    "Normalized_Category",
    "FindingType",
    "Severity",
    "Confidence",
    "Source",
    "TemplatePath",
    "Evidence",
)
EVIDENCE_KEYS: Tuple[str, ...] = ("Source", "RuleId")
EVIDENCE_DELTA_KEYS: Tuple[str, ...] = ("Source", "RuleId", "source_comparable")
FAILURE_KEYS: Tuple[str, ...] = ("side", "input", "code", "error_index")
SUMMARY_KEYS: Tuple[str, ...] = ("semantic_diff", "finding_delta", "errors")
SUMMARY_SEMANTIC_DIFF_KEYS: Tuple[str, ...] = (
    "changes",
    "by_change_kind",
    "by_qualifier",
    "by_hint",
    "by_semantic_limitation",
    "uncompared_paths",
    "by_uncompared_reason",
)
SUMMARY_FINDING_DELTA_KEYS: Tuple[str, ...] = (
    "entries",
    "by_classification",
    "by_observation",
    "by_reason",
    "by_match_stage",
)

#: Keys the Delta_Report never has: it asserts no improvement, safety, fix or
#: pass (Requirement 7 AC7), uses no comparison-level ``unchanged`` status
#: (Requirement 5 AC8) and labels no Evidence difference ``resolved``
#: (Requirement 6 AC14).
FORBIDDEN_KEYS: Tuple[str, ...] = (
    "improved",
    "fixed",
    "passed",
    "passed_all_checks",
    "safe",
    "secure",
    "resolved",
    "unchanged",
    "verified",
)

# ---------------------------------------------------------------------------
# Strings written in plain form (Design 10-1)
# ---------------------------------------------------------------------------

#: Top-level section names, plain at path position 0.
TOP_LEVEL_SECTIONS: Tuple[str, ...] = (
    "AWSTemplateFormatVersion",
    "Description",
    "Metadata",
    "Parameters",
    "Rules",
    "Mappings",
    "Conditions",
    "Transform",
    "Resources",
    "Outputs",
)

#: Keys plain directly under a Resource (path position 2 below ``Resources``).
RESOURCE_PLAIN_KEYS: Tuple[str, ...] = ("Type", "Properties") + RESOURCE_ATTRIBUTES

#: Keys plain directly under a Parameter (path position 2 below ``Parameters``).
PARAMETER_ATTRIBUTES: Tuple[str, ...] = (
    "AllowedPattern",
    "AllowedValues",
    "ConstraintDescription",
    "Default",
    "Description",
    "MaxLength",
    "MaxValue",
    "MinLength",
    "MinValue",
    "NoEcho",
    "Type",
)

#: Keys plain directly under an Output (path position 2 below ``Outputs``).
OUTPUT_ATTRIBUTES: Tuple[str, ...] = ("Condition", "Description", "Export", "Value")

#: Keys plain directly under a Rule (path position 2 below ``Rules``).
RULE_ATTRIBUTES: Tuple[str, ...] = ("Assertions", "RuleCondition")

#: Intrinsic Function names (long form of ``yamlcfn.SHORT_TAGS``), plain at
#: path position 2 and below.
INTRINSIC_NAMES: Tuple[str, ...] = tuple(sorted({yamlcfn.long_form_key(tag) for tag in yamlcfn.SHORT_TAGS}))

#: ``tools[].name`` values written in plain form.
PLAIN_TOOL_NAMES: Tuple[str, ...] = ("cfn-lint", "cfn-guard", "cdk")

#: A Resource Type written in plain form as a whole.
AWS_RESOURCE_TYPE_PATTERN = re.compile(r"AWS::[A-Za-z0-9]+::[A-Za-z0-9]+")

#: A Resource Type with this prefix keeps the prefix; the name is replaced.
CUSTOM_RESOURCE_PREFIX = "Custom::"

#: A cfn-lint rule ID written in plain form (Evidence ``Source`` ``cfn-lint``).
CFN_LINT_RULE_ID_PATTERN = re.compile(r"[EWI][0-9]{4}")

#: Identifier_Token format: prefix and the minimum number of digits.
TOKEN_PREFIX = "id-"
TOKEN_MIN_WIDTH = 6

_PARAMETERS, _OUTPUTS, _RULES, _RESOURCES = "Parameters", "Outputs", "Rules", "Resources"
_POSITION_2_PLAIN: Mapping[str, FrozenSet[str]] = {
    _RESOURCES: frozenset(RESOURCE_PLAIN_KEYS),
    _PARAMETERS: frozenset(PARAMETER_ATTRIBUTES),
    _OUTPUTS: frozenset(OUTPUT_ATTRIBUTES),
    _RULES: frozenset(RULE_ATTRIBUTES),
}
_TOP_LEVEL: FrozenSet[str] = frozenset(TOP_LEVEL_SECTIONS)
_INTRINSICS: FrozenSet[str] = frozenset(INTRINSIC_NAMES)
_IAM_DETECTORS: FrozenSet[str] = frozenset(IAM_DETECTOR_SPECS)
_SOURCES: FrozenSet[str] = frozenset(finding.SOURCES)

_CLASSIFICATION_INDEX = {code: n for n, code in enumerate(deltaschema.DELTA_CLASSIFICATIONS)}
_OBSERVATION_INDEX = {code: n for n, code in enumerate(deltaschema.ENTRY_OBSERVATIONS)}
_CHANGE_INDEX = {code: n for n, code in enumerate(deltaschema.CHANGE_KINDS)}
_INPUT_RANK = {"template": 0, "report": 1, "output": 2}
_SIDE_RANK = {"base": 0, "head": 1, None: 2}

#: Remediation text per failure Code; built from fixed text only.
_REMEDIATION: Mapping[str, str] = {
    "invalid_arguments": "Check the command-line arguments; see --help.",
    "input_not_found": "Give the path of an existing regular file inside the workspace.",
    "path_violation": "Give a path to a regular file that stays inside the workspace.",
    "template_too_large": "Give a Template no larger than the limit.",
    "report_too_large": "Give a Review_Report no larger than the limit.",
    "report_finding_limit_exceeded": "Give a Review_Report with no more Findings than the limit.",
    "template_node_limit_exceeded": "Reduce the Template, including subtrees shared through YAML aliases.",
    "template_depth_limit_exceeded": "Reduce the nesting depth of the Template.",
    "change_entry_limit_exceeded": "Compare Templates with fewer differences.",
    "output_size_limit_exceeded": "Compare smaller inputs.",
    "template_parse_failure": "Fix the Template syntax at the reported position.",
    "template_encoding_failure": "Save the Template as UTF-8.",
    "template_alias_cycle": "Remove the YAML alias that makes the document refer to itself.",
    "template_not_reviewable": "Give a CloudFormation Template with a Resources mapping.",
    "report_parse_failure": "Give a Review_Report in strict JSON.",
    "report_duplicate_json_key": "Give a Review_Report whose JSON objects have unique keys.",
    "report_schema_violation": "Give a JSON Review_Report as produced by run_iac_review.py.",
    "parser_divergence": "Report this as a defect of the Delta_Tool.",
    "unexpected": "Report this as a defect of the Delta_Tool.",
}

_INPUT_LABEL = {"template": "template", "report": "report", "output": "output"}


# ---------------------------------------------------------------------------
# Request and result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TemplateInput:
    """One side of a Template_Pair.

    Attributes:
        path: Workspace-relative ``/``-separated path, or ``None`` when the
            argument did not resolve inside the workspace.
        parsed: The checked Template, or ``None`` when it is unanalyzable.
    """

    path: Optional[str]
    parsed: Optional[ParsedTemplate]


@dataclass(frozen=True)
class ReportInput:
    """One side of a Report_Pair.

    Attributes:
        path: Workspace-relative path, or ``None`` when it did not resolve.
        sha256: Digest of the bytes read, or ``None`` when nothing was read.
        checked: The schema-checked Report, or ``None`` when it was rejected.
    """

    path: Optional[str]
    sha256: Optional[str]
    checked: Optional[CheckedReport]


@dataclass(frozen=True)
class FailureRecord:
    """A failure and the schema-derived field path it names, if any."""

    failure: Failure
    field: Optional[str] = None


@dataclass(frozen=True)
class DeltaRequest:
    """Everything one Delta_Report is built from.

    Attributes:
        templates: ``(base, head)``, or ``None`` without a Template_Pair.
        reports: ``(base, head)``, or ``None`` without a Report_Pair.
        semantic_diff: The analyzed Semantic Diff, or ``None`` when it was not
            requested or is unanalyzable (then a template failure exists).
        finding_delta: The analyzed Finding Delta, or ``None`` likewise.
        failures: Every failure. Ordered here as Base Template, Head Template,
            Template comparison, Base Report, Head Report, output.
        declarations: Input_Declaration codes given on the command line.
        guard_rule_names: Names of the bundled Guard rules (plain RuleIds).
        reviewed_template_path: The normalized ``--reviewed-template-path``
            (H-M1-1 approved), or ``None`` when not declared. Recorded as
            ``declared_not_verified``; it is not verified.
    """

    templates: Optional[Tuple[TemplateInput, TemplateInput]]
    reports: Optional[Tuple[ReportInput, ReportInput]]
    semantic_diff: Optional[SemanticDiffResult]
    finding_delta: Optional[FindingDeltaResult]
    failures: Tuple[FailureRecord, ...] = ()
    declarations: FrozenSet[str] = frozenset()
    guard_rule_names: FrozenSet[str] = frozenset()
    reviewed_template_path: Optional[str] = None


@dataclass(frozen=True)
class RenderedDeltaReport:
    """The serialized Delta_Report and the failures it records, in exit order."""

    text: str
    failures: Tuple[FailureRecord, ...]

    @property
    def exit_code(self) -> int:
        """Exit code of the first failure, or 0 when every comparison is analyzed."""
        return self.failures[0].failure.exit_code if self.failures else 0


# ---------------------------------------------------------------------------
# Identifier_Tokens (Design 10-2)
# ---------------------------------------------------------------------------


def build_token_table(strings: Iterable[str]) -> Dict[str, str]:
    """Number the distinct ``strings`` in Unicode code point order."""
    ids = sorted(set(strings))
    width = max(TOKEN_MIN_WIDTH, len(str(len(ids))))
    return {text: TOKEN_PREFIX + str(n + 1).zfill(width) for n, text in enumerate(ids)}


class _Names:
    """How each input-derived string is written in one rendering pass.

    In the collecting pass (``table`` is ``None``) every string to be replaced
    is recorded and returned unchanged; the final pass looks it up.
    """

    def __init__(self, plain_identifiers: bool, table: Optional[Mapping[str, str]]) -> None:
        self._plain = plain_identifiers
        self._table = table
        self.collected: Set[str] = set()

    @property
    def collecting(self) -> bool:
        """``True`` in the collecting pass, whose rendered object is discarded."""
        return self._table is None

    def identifier(self, text: str) -> str:
        """An identifier of Requirement 12 AC2 (plain on request)."""
        return text if self._plain else self._token(text)

    def outside_closed_set(self, text: str) -> str:
        """A string outside its closed set: always a Token."""
        return self._token(text)

    def _token(self, text: str) -> str:
        if self._table is None:
            self.collected.add(text)
            return text
        return self._table[text]


# ---------------------------------------------------------------------------
# Failures and StructuredErrors (Design 10-4)
# ---------------------------------------------------------------------------


def _limit_of(code: str) -> Optional[int]:
    for name, limit_code in deltaschema.LIMIT_FAILURE_CODES.items():
        if limit_code == code:
            value = getattr(deltaschema, name)
            return value if isinstance(value, int) else None
    return None


def failure_message(record: FailureRecord) -> str:
    """The message of a failure, built from closed-set values and integers only.

    Example: ``head template: template_parse_failure at line 7, column 1``.
    """
    failure = record.failure
    label = _INPUT_LABEL[failure.input]
    subject = label if failure.side is None else "{0} {1}".format(failure.side, label)
    if failure.side is None and failure.input == "template":
        subject = "template comparison"
    parts = ["{0}: {1}".format(subject, failure.code)]
    if failure.line is not None:
        parts.append(" at line {0}".format(failure.line))
        if failure.column is not None:
            parts.append(", column {0}".format(failure.column))
    if record.field is not None:
        parts.append(" at field {0}".format(record.field))
    limit = _limit_of(failure.code)
    if limit is not None:
        parts.append(" (limit {0})".format(limit))
    return "".join(parts)


def structured_error(record: FailureRecord) -> Dict[str, Any]:
    """A v1.0 StructuredError (9 keys) for ``record``. No input content."""
    error: Dict[str, Any] = {
        "error_class": record.failure.error_class,
        "source": None,
        "tool": None,
        "exit_code": None,
        "message": failure_message(record),
        "required_min_version": None,
        "detected_version": None,
        "remediation": _REMEDIATION[record.failure.code],
        "stderr_head": [],
    }
    assert tuple(error) == STRUCTURED_ERROR_KEYS
    return error


def _ordered_failures(failures: Iterable[FailureRecord]) -> Tuple[FailureRecord, ...]:
    """Base Template, Head Template, comparison, Base Report, Head Report, output."""
    return tuple(
        sorted(failures, key=lambda r: (_INPUT_RANK[r.failure.input], _SIDE_RANK[r.failure.side]))
    )


# ---------------------------------------------------------------------------
# Sort keys over output values (Design 11-2)
# ---------------------------------------------------------------------------


def _optional(value: Optional[str]) -> Tuple[int, str]:
    return (0, "") if value is None else (1, value)


def _path_key(path: Optional[Sequence[Any]]) -> Tuple[Any, ...]:
    """Sort key of a rendered path: integers before strings, item by item.

    Each item contributes three values, ``(0, int, "")`` or ``(1, 0, str)``,
    concatenated into one flat tuple. Comparing the flat tuples orders paths
    exactly as comparing tuples of those triples would (fixed width 3, so a
    shorter prefix still sorts first), with one tuple per path instead of one
    per item: the keys of every entry are held at once while sorting.
    """
    if path is None:
        return (0,)
    flat: List[Any] = [1]
    for item in path:
        if isinstance(item, int):
            flat.extend((0, item, ""))
        else:
            flat.extend((1, 0, item))
    return tuple(flat)


def _change_sort_key(entry: Dict[str, Any]) -> Tuple[Any, ...]:
    types = entry["resource_type"]
    return (
        entry["section"],
        _path_key(entry["path"]),
        _CHANGE_INDEX[entry["change"]],
        entry["type_changed"],
        (0,) if types is None else (1, _optional(types["base"]), _optional(types["head"])),
        tuple(entry["qualifiers"]),
        tuple(entry["hints"]),
    )


def _evidence_sort_key(item: Dict[str, Any]) -> Tuple[Any, ...]:
    return (item["Source"], _optional(item["RuleId"]), item.get("source_comparable", False))


def _fingerprint_key(projection: Optional[Dict[str, Any]]) -> Tuple[Any, ...]:
    if projection is None:
        return (0,)
    return (
        1,
        projection["FindingType"],
        _path_key(projection["TemplatePath"]),
        tuple(_evidence_sort_key(item) for item in projection["Evidence"]),
    )


def _entry_sort_key(entry: Dict[str, Any]) -> Tuple[Any, ...]:
    key = entry["key"]
    base, head = entry["base"], entry["head"]
    return (
        _CLASSIFICATION_INDEX[entry["classification"]],
        _OBSERVATION_INDEX[entry["observation"]],
        key["File"],
        _optional(key["Resource"]),
        key["Normalized_Category"],
        _fingerprint_key(base),
        _fingerprint_key(head),
        0 if base is None else base["ID"],
        0 if head is None else head["ID"],
        json.dumps(entry, sort_keys=True, ensure_ascii=False),
    )


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


class _Missing:
    __slots__ = ()


_MISSING = _Missing()


def _original_keys(path: Sequence[Any], docs: Sequence[Any]) -> Optional[List[Optional[str]]]:
    """For each ``int`` of ``path`` not shown to be a list index, the key it stands for.

    Returns ``None`` when ``path`` has no ``int``. Otherwise a list parallel to
    ``path``: ``None`` where an ``int`` is an index inside a list of ``docs``
    at that position (and at non-``int`` positions), the digit-only string key
    elsewhere (RC Blocker D-13: an index outside every list, or a position no
    document reaches, cannot be shown to be a list index). Walks at most
    ``len(path)`` steps per document.
    """
    if not any(isinstance(item, int) and not isinstance(item, bool) for item in path):
        return None
    keys: List[Optional[str]] = []
    current: List[Any] = list(docs)
    for item in path:
        original: Optional[str] = None
        if isinstance(item, int) and not isinstance(item, bool):
            if not any(isinstance(node, (list, tuple)) and 0 <= item < len(node) for node in current):
                original = _digit_key(item, current)
        keys.append(original)
        current = [_step(node, item, original) for node in current]
    return keys


def _digit_key(index: int, nodes: Sequence[Any]) -> str:
    """The digit-only mapping key that canonicalizes to ``index``."""
    wanted = str(index)
    candidates: Set[str] = set()
    for node in nodes:
        if isinstance(node, dict):
            if wanted in node:
                return wanted
            candidates.update(
                key for key in node if isinstance(key, str) and key.isdecimal() and int(key) == index
            )
    return min(candidates) if candidates else wanted


def _step(node: Any, item: Any, original: Optional[str]) -> Any:
    if isinstance(node, dict):
        return node.get(original if original is not None else item, _MISSING)
    if isinstance(node, (list, tuple)) and isinstance(item, int) and 0 <= item < len(node):
        return node[item]
    return _MISSING


class _Renderer:
    """Builds the Delta_Report for one request with one :class:`_Names`."""

    def __init__(
        self,
        request: DeltaRequest,
        names: _Names,
        identifier_mode: str,
        category_map: categories.CategoryMap,
    ) -> None:
        self._request = request
        self._names = names
        self._mode = identifier_mode
        self._categories = category_map
        docs: List[Any] = []
        side_docs: Dict[str, List[Any]] = {side: [] for side in deltaschema.SIDES}
        if request.templates is not None:
            docs = [side.parsed.doc for side in request.templates if side.parsed is not None]
            for side, template in zip(deltaschema.SIDES, request.templates):
                if template.parsed is not None:
                    side_docs[side] = [template.parsed.doc]
        self._docs = docs
        self._side_docs = side_docs
        # The path a Finding must be in for its TemplatePath to be walked in
        # the Template of its side (D-13): the declared path, else the
        # workspace-relative path of that Template.
        side_paths: Dict[str, Optional[str]] = {side: None for side in deltaschema.SIDES}
        if request.templates is not None:
            for side, template in zip(deltaschema.SIDES, request.templates):
                side_paths[side] = (
                    request.reviewed_template_path if request.reviewed_template_path is not None else template.path
                )
        self._side_paths = side_paths

    # -- strings -----------------------------------------------------------

    def _path_item(self, position: int, section: Any, text: str) -> str:
        if position == 0:
            return text if text in _TOP_LEVEL else self._names.identifier(text)
        if position == 1:
            return self._names.identifier(text)
        if position == 2 and isinstance(section, str) and text in _POSITION_2_PLAIN.get(section, frozenset()):
            return text
        if text in _INTRINSICS:
            return text
        return self._names.identifier(text)

    def _path(self, path: Sequence[Any], docs: Sequence[Any]) -> List[Union[str, int]]:
        """Render ``path``; an ``int`` naming a mapping key of ``docs`` is a Token.

        Without ``docs`` a list index cannot be told from a digit-only key, so
        no integer is shown to be an index: each is written like a key, as the
        Token of its decimal string (the string itself in plain mode).
        """
        originals = _original_keys(path, docs) if docs else None
        section = path[0] if path else None
        rendered: List[Union[str, int]] = []
        for position, item in enumerate(path):
            original = None if originals is None else originals[position]
            if original is not None:
                rendered.append(self._path_item(position, section, original))
            elif isinstance(item, int) and not isinstance(item, bool) and docs:
                rendered.append(item)
            else:
                rendered.append(self._path_item(position, section, str(item)))
        return rendered

    def _resource_type(self, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        if AWS_RESOURCE_TYPE_PATTERN.fullmatch(value):
            return value
        if value.startswith(CUSTOM_RESOURCE_PREFIX):
            return CUSTOM_RESOURCE_PREFIX + self._names.identifier(value[len(CUSTOM_RESOURCE_PREFIX) :])
        return self._names.identifier(value)

    def _optional_identifier(self, value: Optional[str]) -> Optional[str]:
        return None if value is None else self._names.identifier(value)

    def _category(self, value: str) -> str:
        return value if self._categories.is_valid_category(value) else self._names.outside_closed_set(value)

    def _rule_id(self, source: str, rule_id: Optional[str]) -> Optional[str]:
        if rule_id is None:
            return None
        if source == "cfn-lint" and CFN_LINT_RULE_ID_PATTERN.fullmatch(rule_id):
            return rule_id
        if source == "cfn-guard" and rule_id in self._request.guard_rule_names:
            return rule_id
        if source == "IAM Review" and rule_id in _IAM_DETECTORS:
            return rule_id
        return self._names.outside_closed_set(rule_id)

    def _source(self, value: Optional[str]) -> Optional[str]:
        if value is None or value in _SOURCES:
            return value
        return self._names.outside_closed_set(value)

    def _tool_name(self, value: str) -> str:
        return value if value in PLAIN_TOOL_NAMES else self._names.outside_closed_set(value)

    def _tool_version(self, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        if value.isascii() and toolcheck.VERSION_PATTERN.fullmatch(value):
            return value
        return self._names.outside_closed_set(value)

    # -- inputs ------------------------------------------------------------

    def _template_input(self, side: Optional[TemplateInput]) -> Optional[Dict[str, Any]]:
        if side is None:
            return None
        return {"path": side.path, "format": None if side.parsed is None else side.parsed.fmt}

    def _report_input(self, side: Optional[ReportInput]) -> Optional[Dict[str, Any]]:
        if side is None:
            return None
        checked = side.checked
        if checked is None:
            return {
                "path": side.path,
                "sha256": side.sha256,
                "schema_version": None,
                "target": None,
                "sources_enabled": None,
                "tools": None,
                "error_summary": None,
            }
        return {
            "path": side.path,
            "sha256": side.sha256,
            "schema_version": checked.schema_version,
            "target": {
                "files": list(checked.files),
                "cdk": {
                    "detected": checked.cdk_detected,
                    "synthesis": checked.cdk_synthesis,
                    "synthesized_templates": list(checked.synthesized_templates),
                },
            },
            "sources_enabled": list(checked.sources_enabled),
            "tools": [
                {
                    "name": self._tool_name(tool.name),
                    "available": tool.available,
                    "version": self._tool_version(tool.version),
                }
                for tool in checked.tools
            ],
            "error_summary": [
                {"error_class": error.error_class, "source": self._source(error.source)}
                for error in checked.errors
            ],
        }

    def _inputs(self) -> Dict[str, Any]:
        request = self._request
        result: Dict[str, Any] = {}
        for index, side in enumerate(deltaschema.SIDES):
            template = None if request.templates is None else request.templates[index]
            report_side = None if request.reports is None else request.reports[index]
            result[side] = {
                "template": self._template_input(template),
                "report": self._report_input(report_side),
            }
        return result

    # -- Semantic Diff -----------------------------------------------------

    def _change(self, change: ChangeEntry) -> Dict[str, Any]:
        types = change.resource_type
        return {
            "section": self._path_item(0, change.section, change.section),
            "path": self._path(change.path, self._docs),
            "change": change.change,
            "type_changed": change.type_changed,
            "resource_type": None
            if types is None
            else {"base": self._resource_type(types.base), "head": self._resource_type(types.head)},
            "qualifiers": list(change.qualifiers),
            "hints": list(change.hints),
        }

    def _uncompared(self, item: UncomparedPath) -> Dict[str, Any]:
        return {"path": self._path(item.path, self._docs), "reason": item.reason}

    def _semantic_diff(
        self, result: Optional[SemanticDiffResult], failure: Optional[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        if self._request.templates is None:
            return None
        if result is None or failure is not None:
            return {
                "analysis_state": "unanalyzable",
                "observation": None,
                "structural_completeness": None,
                "semantic_limitations": [],
                "uncompared_paths": [],
                "changes": [],
                "failure": failure,
            }
        changes: List[Dict[str, Any]] = []
        uncompared: List[Dict[str, Any]] = []
        if self._names.collecting:
            # Same calls as the final pass, so the same strings are collected;
            # nothing is kept or sorted because this pass's object is discarded.
            for change in result.changes:
                self._change(change)
            for item in result.uncompared_paths:
                self._uncompared(item)
        else:
            changes = sorted((self._change(c) for c in result.changes), key=_change_sort_key)
            uncompared = sorted(
                (self._uncompared(u) for u in result.uncompared_paths),
                key=lambda item: (_path_key(item["path"]), item["reason"]),
            )
        return {
            "analysis_state": result.analysis_state,
            "observation": result.observation,
            "structural_completeness": result.structural_completeness,
            "semantic_limitations": list(result.semantic_limitations),
            "uncompared_paths": uncompared,
            "changes": changes,
            "failure": None,
        }

    # -- Finding Delta -----------------------------------------------------

    def _evidence(self, items: Sequence[EvidenceKey]) -> List[Dict[str, Any]]:
        rendered = [{"Source": e.Source, "RuleId": self._rule_id(e.Source, e.RuleId)} for e in items]
        return sorted(rendered, key=_evidence_sort_key)

    def _evidence_deltas(self, items: Sequence[EvidenceDelta]) -> List[Dict[str, Any]]:
        rendered = [
            {
                "Source": e.Source,
                "RuleId": self._rule_id(e.Source, e.RuleId),
                "source_comparable": e.source_comparable,
            }
            for e in items
        ]
        return sorted(rendered, key=_evidence_sort_key)

    def _projection(self, projection: Optional[FindingProjection], side: str) -> Optional[Dict[str, Any]]:
        """A Finding_Projection; ``TemplatePath`` is walked in the Template of
        ``side`` only when the Finding is in that Template's comparison path (D-13)."""
        if projection is None:
            return None
        docs = self._side_docs[side] if projection.File == self._side_paths[side] else []
        return {
            "ID": projection.ID,
            "File": projection.File,
            "Resource": self._optional_identifier(projection.Resource),
            "Normalized_Category": self._category(projection.Normalized_Category),
            "FindingType": projection.FindingType,
            "Severity": projection.Severity,
            "Confidence": projection.Confidence,
            "Source": list(projection.Source),
            "TemplatePath": None
            if projection.TemplatePath is None
            else self._path(projection.TemplatePath, docs),
            "Evidence": self._evidence(projection.Evidence),
        }

    def _entry(self, entry: DeltaEntry) -> Dict[str, Any]:
        return {
            "observation": entry.observation,
            "classification": entry.classification,
            "reasons": list(entry.reasons),
            "missing_declarations": list(entry.missing_declarations),
            "key": {
                "File": entry.key.File,
                "Resource": self._optional_identifier(entry.key.Resource),
                "Normalized_Category": self._category(entry.key.Normalized_Category),
            },
            "match_stage": entry.match_stage,
            "base": self._projection(entry.base, "base"),
            "head": self._projection(entry.head, "head"),
            "changes": list(entry.changes),
            "evidence_absent_in_head": self._evidence_deltas(entry.evidence_absent_in_head),
            "evidence_absent_in_base": self._evidence_deltas(entry.evidence_absent_in_base),
        }

    def _declarations(self) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
        required = REPORT_DECLARATIONS
        if self._request.templates is not None:
            required = required + (TEMPLATE_DECLARATION,)
        declared = tuple(c for c in deltaschema.DECLARATION_CODES if c in self._request.declarations)
        return declared, tuple(c for c in required if c not in self._request.declarations)

    def _unverified_assumptions(self) -> List[str]:
        """Always listed in full; ``reports_match_templates`` only with a
        Template_Pair (Requirement 8 AC3)."""
        return [
            code
            for code in deltaschema.UNVERIFIED_ASSUMPTIONS
            if code != TEMPLATE_DECLARATION or self._request.templates is not None
        ]

    def _reviewed_template_path(self) -> Optional[Dict[str, str]]:
        """The declared Template path (H-M1-1 approved); a declaration, not a check."""
        path = self._request.reviewed_template_path
        if path is None:
            return None
        return {"path": path, "status": deltaschema.INPUT_DECLARATION_STATUSES[0]}

    def _finding_delta(
        self, result: Optional[FindingDeltaResult], failure: Optional[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        if self._request.reports is None:
            return None
        declared, missing = self._declarations()
        declarations = {
            "declared": list(declared),
            "missing": list(missing),
            "status": deltaschema.INPUT_DECLARATION_STATUSES[0],
        }
        reviewed_path = self._reviewed_template_path()
        if result is None or failure is not None:
            return {
                "analysis_state": "unanalyzable",
                "observation": None,
                "classification_completeness": None,
                "report_authenticity": deltaschema.REPORT_AUTHENTICITY,
                "report_integrity": None,
                "input_declarations": declarations,
                "unverified_assumptions": self._unverified_assumptions(),
                "template_report_correspondence": None,
                "reviewed_template_path": reviewed_path,
                "comparable": None,
                "entries": [],
                "failure": failure,
            }
        entries: List[Dict[str, Any]] = []
        if self._names.collecting:
            for entry in result.entries:  # collected, not kept (see _semantic_diff)
                self._entry(entry)
        else:
            entries = sorted((self._entry(e) for e in result.entries), key=_entry_sort_key)
        return {
            "analysis_state": result.analysis_state,
            "observation": result.observation,
            "classification_completeness": result.classification_completeness,
            "report_authenticity": result.report_authenticity,
            "report_integrity": {
                "base": {"failed_checks": list(result.report_integrity.base)},
                "head": {"failed_checks": list(result.report_integrity.head)},
            },
            "input_declarations": declarations,
            "unverified_assumptions": self._unverified_assumptions(),
            "template_report_correspondence": result.template_report_correspondence,
            "reviewed_template_path": reviewed_path,
            "comparable": result.comparable,
            "entries": entries,
            "failure": None,
        }

    # -- envelope ----------------------------------------------------------

    def render(self, failures: Tuple[FailureRecord, ...], output_failed: bool) -> Dict[str, Any]:
        request = self._request
        errors = [structured_error(record) for record in failures]
        diff_failure = _first_failure(failures, ("template",) + (("output",) if output_failed else ()))
        delta_failure = _first_failure(failures, ("report",) + (("output",) if output_failed else ()))
        if request.templates is not None and request.semantic_diff is None and diff_failure is None:
            raise ValueError("a Template_Pair without a Semantic Diff needs a template failure")
        if request.reports is not None and request.finding_delta is None and delta_failure is None:
            raise ValueError("a Report_Pair without a Finding Delta needs a report failure")
        semantic_diff = self._semantic_diff(request.semantic_diff, diff_failure)
        finding_delta = self._finding_delta(request.finding_delta, delta_failure)
        return {
            "delta_schema_version": deltaschema.DELTA_SCHEMA_VERSION,
            "scope": deltaschema.SCOPE,
            "identifier_mode": self._mode,
            "inputs": self._inputs(),
            "semantic_diff": semantic_diff,
            "finding_delta": finding_delta,
            "errors": errors,
            "summary": _summary(semantic_diff, finding_delta, len(errors)),
        }


def _first_failure(
    failures: Sequence[FailureRecord], inputs: Tuple[str, ...]
) -> Optional[Dict[str, Any]]:
    for index, record in enumerate(failures):
        if record.failure.input in inputs:
            return {
                "side": record.failure.side,
                "input": record.failure.input,
                "code": record.failure.code,
                "error_index": index,
            }
    return None


def _zero(codes: Iterable[Any]) -> Dict[str, int]:
    return {str(code): 0 for code in codes}


def _summary(
    semantic_diff: Optional[Dict[str, Any]], finding_delta: Optional[Dict[str, Any]], errors: int
) -> Dict[str, Any]:
    """Counts per closed-set value, every value present (Requirement 9 AC8)."""
    by_kind = _zero(deltaschema.CHANGE_KINDS)
    by_qualifier = _zero(deltaschema.CHANGE_QUALIFIERS)
    by_hint = _zero(deltaschema.CHANGE_HINTS)
    by_limitation = _zero(deltaschema.SEMANTIC_LIMITATIONS)
    by_uncompared = _zero(deltaschema.UNCOMPARED_REASONS)
    changes: List[Dict[str, Any]] = [] if semantic_diff is None else semantic_diff["changes"]
    uncompared: List[Dict[str, Any]] = [] if semantic_diff is None else semantic_diff["uncompared_paths"]
    for change in changes:
        by_kind[change["change"]] += 1
        for code in change["qualifiers"]:
            by_qualifier[code] += 1
        for code in change["hints"]:
            by_hint[code] += 1
    for code in [] if semantic_diff is None else semantic_diff["semantic_limitations"]:
        by_limitation[code] += 1
    for item in uncompared:
        by_uncompared[item["reason"]] += 1

    by_classification = _zero(deltaschema.DELTA_CLASSIFICATIONS)
    by_observation = _zero(deltaschema.ENTRY_OBSERVATIONS)
    by_reason = _zero(deltaschema.AMBIGUOUS_REASONS + deltaschema.UNCONFIRMED_REASONS)
    by_stage = _zero(deltaschema.MATCH_STAGES)
    entries: List[Dict[str, Any]] = [] if finding_delta is None else finding_delta["entries"]
    for entry in entries:
        by_classification[entry["classification"]] += 1
        by_observation[entry["observation"]] += 1
        for code in entry["reasons"]:
            by_reason[code] += 1
        if entry["match_stage"] is not None:
            by_stage[str(entry["match_stage"])] += 1
    return {
        "semantic_diff": {
            "changes": len(changes),
            "by_change_kind": by_kind,
            "by_qualifier": by_qualifier,
            "by_hint": by_hint,
            "by_semantic_limitation": by_limitation,
            "uncompared_paths": len(uncompared),
            "by_uncompared_reason": by_uncompared,
        },
        "finding_delta": {
            "entries": len(entries),
            "by_classification": by_classification,
            "by_observation": by_observation,
            "by_reason": by_reason,
            "by_match_stage": by_stage,
        },
        "errors": errors,
    }


def _render(
    request: DeltaRequest,
    identifier_mode: str,
    failures: Tuple[FailureRecord, ...],
    output_failed: bool,
) -> Dict[str, Any]:
    """Two passes: collect the strings to replace, then render with Tokens."""
    if identifier_mode not in deltaschema.IDENTIFIER_MODES:
        raise ValueError("unknown identifier mode")
    category_map = categories.load_map()
    plain = identifier_mode == "plain"
    collector = _Names(plain, None)
    _Renderer(request, collector, identifier_mode, category_map).render(failures, output_failed)
    names = _Names(plain, build_token_table(collector.collected))
    return _Renderer(request, names, identifier_mode, category_map).render(failures, output_failed)


# ---------------------------------------------------------------------------
# Serialization under the output size limit (Design 11-2, 12-1)
# ---------------------------------------------------------------------------

#: The ``json.dumps`` arguments of ``report.dump``, pinned the same way. With
#: ``indent`` set, ``JSONEncoder.encode`` is ``"".join`` of ``iterencode``
#: (the C encoder is used only without ``indent``), so consuming
#: ``iterencode`` gives the same characters as ``report.dump``.
_ENCODER = json.JSONEncoder(sort_keys=True, ensure_ascii=False, indent=2, separators=(",", ": "))

#: Chunks of ``iterencode`` joined into one block at a time; bounds the
#: number of small strings alive while serializing.
_CHUNKS_PER_BLOCK = 4096


def _bounded_text(chunks: Iterable[str], limit: Optional[int]) -> Optional[str]:
    """``"".join(chunks) + "\\n"``, or ``None`` once it exceeds ``limit`` UTF-8 bytes.

    Bytes are counted as the chunks arrive; the first chunk that takes the
    total (with the final newline) over ``limit`` stops the consumption, so
    an over-limit text is never built in full. ``limit`` ``None`` means no
    limit.
    """
    blocks: List[str] = []
    pending: List[str] = []
    size = 1  # the final "\n"
    for chunk in chunks:
        size += len(chunk) if chunk.isascii() else len(chunk.encode("utf-8"))
        if limit is not None and size > limit:
            return None
        pending.append(chunk)
        if len(pending) >= _CHUNKS_PER_BLOCK:
            blocks.append("".join(pending))
            pending = []
    blocks.append("".join(pending))
    blocks.append("\n")
    return "".join(blocks)


#: Code points a terminal or UI may interpret, written as JSON ``\\uXXXX``
#: escapes (RC Blocker D-14, Requirement 11 AC2, Design 10-3): C1 controls,
#: the bidirectional embeddings, overrides and isolates, and the LRM, RLM
#: and ALM marks. Lowercase hex, the form ``json`` uses with ``ensure_ascii``.
DISPLAY_ESCAPED_CODE_POINTS: FrozenSet[int] = frozenset(
    list(range(0x0080, 0x00A0))
    + list(range(0x202A, 0x202F))
    + list(range(0x2066, 0x206A))
    + [0x200E, 0x200F, 0x061C]
)
_DISPLAY_ESCAPES: Dict[int, str] = {code: "\\u{0:04x}".format(code) for code in DISPLAY_ESCAPED_CODE_POINTS}


def _display_escaped(chunks: Iterable[str]) -> Iterator[str]:
    """``chunks`` with the D-14 code points written as ``\\uXXXX``.

    The encoder writes every structural character in ASCII and escapes ``"``,
    ``\\`` and C0 inside strings, so a non-ASCII character only ever occurs in
    a string literal and never right after an unpaired escape backslash. A
    per-character replacement there keeps the text valid JSON with the same
    decoded value.
    """
    for chunk in chunks:
        yield chunk if chunk.isascii() else chunk.translate(_DISPLAY_ESCAPES)


def _serialize(delta_report: Dict[str, Any], limit: Optional[int]) -> Optional[str]:
    """The ``report.dump`` text of ``delta_report`` with the D-14 escapes, or
    ``None`` over ``limit`` bytes (counted after escaping)."""
    return _bounded_text(_display_escaped(_ENCODER.iterencode(delta_report)), limit)


def dump(delta_report: Dict[str, Any]) -> str:
    """Serialize as ``report.dump`` does (Requirement 11 AC2), with the D-14
    code points written as ``\\uXXXX``; identical to ``report.dump`` for a
    value without them, and equal to it after ``json.loads`` for any value."""
    text = _serialize(delta_report, None)
    assert text is not None
    return text


def _over_limit(text: str) -> bool:
    """Whether ``text`` exceeds the output limit (kept for ``tests/perf/measure_m1.py``)."""
    return len(text.encode("utf-8")) > deltaschema.MAX_OUTPUT_BYTES


def _member_bytes(key: str, min_value: int) -> int:
    """Fewest bytes of one member of a Change_Entry or an uncompared path:
    newline, 8 spaces of indent, the quoted key, ``": "`` and the value."""
    return 1 + 8 + len(key) + 2 + 2 + min_value


#: Fewest bytes a path item adds to its entry, over the ``[]`` of an empty
#: path. Path items are at indent 10: each is a newline, 10 spaces and a value
#: of at least 1 byte (an integer digit; a string has 2 quotes), and all but
#: the first are preceded by ``,``. A non-empty path also replaces ``[]`` by
#: ``[`` ... newline, 8 spaces, ``]`` (8 more bytes, not counted). So n items
#: add at least ``13 * n`` bytes.
_PATH_ITEM_MIN_BYTES = 13

#: Fewest bytes of a Change_Entry with an empty path, at its position in the
#: ``changes`` array (indent 6): ``{`` and ``}`` each on their own line
#: (newline, 6 spaces, brace), 7 members, 6 commas. Every value at its
#: shortest: the shortest Change kind quoted, ``[]`` for ``hints``, ``path`` and
#: ``qualifiers``, ``null`` for ``resource_type``, ``""`` for ``section`` and
#: ``true`` for ``type_changed``. The ``,`` between array elements is not
#: counted.
_CHANGE_ENTRY_MIN_BYTES = (
    2 * (1 + 6 + 1)
    + (len(CHANGE_ENTRY_KEYS) - 1)
    + _member_bytes("change", 2 + min(len(code) for code in deltaschema.CHANGE_KINDS))
    + _member_bytes("hints", 2)
    + _member_bytes("path", 2)
    + _member_bytes("qualifiers", 2)
    + _member_bytes("resource_type", 4)
    + _member_bytes("section", 2)
    + _member_bytes("type_changed", 4)
)

#: Fewest bytes of an uncompared path with an empty path, likewise.
_UNCOMPARED_MIN_BYTES = (
    2 * (1 + 6 + 1)
    + (len(UNCOMPARED_PATH_KEYS) - 1)
    + _member_bytes("path", 2)
    + _member_bytes("reason", 2 + min(len(code) for code in deltaschema.UNCOMPARED_REASONS))
)


def _output_lower_bound(request: DeltaRequest, failures: Sequence[FailureRecord]) -> int:
    """A number of bytes the serialized Delta_Report of ``request`` cannot be below.

    Counts only the Change_Entries and uncompared paths of an analyzed
    Semantic Diff, each at its fewest bytes for its path length (the values,
    Tokens and the identifier mode only make it longer); everything else
    counts 0. Returns 0 when the Semantic Diff would not be written (no
    Template_Pair or a template failure) or when the request lacks a result
    without a failure, so that rendering reports that programming error as
    before.
    """
    result = request.semantic_diff
    if request.templates is None or result is None:
        return 0
    if _first_failure(failures, ("template",)) is not None:
        return 0
    if request.reports is not None and request.finding_delta is None and _first_failure(failures, ("report",)) is None:
        return 0
    total = 0
    for change in result.changes:
        total += _CHANGE_ENTRY_MIN_BYTES + _PATH_ITEM_MIN_BYTES * len(change.path)
    for item in result.uncompared_paths:
        total += _UNCOMPARED_MIN_BYTES + _PATH_ITEM_MIN_BYTES * len(item.path)
    return total


def _within_limit(request: DeltaRequest, identifier_mode: str, failures: Tuple[FailureRecord, ...]) -> Optional[str]:
    """The serialized Delta_Report, or ``None`` when it exceeds the output limit.

    Two staged checks, neither of which changes a byte of the result: a
    request whose lower bound already exceeds the limit is not rendered, and
    the serialization stops at the first chunk over the limit.
    """
    if identifier_mode not in deltaschema.IDENTIFIER_MODES:
        raise ValueError("unknown identifier mode")
    limit = deltaschema.MAX_OUTPUT_BYTES
    if _output_lower_bound(request, failures) > limit:
        return None
    return _serialize(_render(request, identifier_mode, failures, output_failed=False), limit)


def build_delta_report(
    request: DeltaRequest, identifier_mode: str = "anonymized"
) -> Union[Dict[str, Any], Failure]:
    """The Delta_Report object, or ``output_size_limit_exceeded``.

    Args:
        request: The results and metadata of one run.
        identifier_mode: ``anonymized`` (default) or ``plain``.

    Returns:
        The Delta_Report as a JSON-ready dict, or a :class:`Failure` when its
        serialization is larger than ``deltaschema.MAX_OUTPUT_BYTES``.
    """
    failures = _ordered_failures(request.failures)
    if identifier_mode not in deltaschema.IDENTIFIER_MODES:
        raise ValueError("unknown identifier mode")
    limit = deltaschema.MAX_OUTPUT_BYTES
    if _output_lower_bound(request, failures) > limit:
        return Failure("output_size_limit_exceeded", None, "output")
    built = _render(request, identifier_mode, failures, output_failed=False)
    if _serialize(built, limit) is None:
        return Failure("output_size_limit_exceeded", None, "output")
    return built


def render_delta_report(request: DeltaRequest, identifier_mode: str = "anonymized") -> RenderedDeltaReport:
    """The serialized Delta_Report, falling back to the minimal one over the limit.

    The minimal Delta_Report keeps ``inputs`` and every error, adds the
    ``output_size_limit_exceeded`` error, and holds no Change_Entry or
    Delta_Entry: each requested comparison is ``unanalyzable``. It is written
    whatever its size.
    """
    failures = _ordered_failures(request.failures)
    text = _within_limit(request, identifier_mode, failures)
    if text is not None:
        return RenderedDeltaReport(text=text, failures=failures)
    failures = failures + (FailureRecord(Failure("output_size_limit_exceeded", None, "output")),)
    minimal = _render(request, identifier_mode, failures, output_failed=True)
    return RenderedDeltaReport(text=dump(minimal), failures=failures)
