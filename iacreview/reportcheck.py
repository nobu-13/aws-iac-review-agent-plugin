"""Review_Report checks of the v1.1 Delta_Tool (Design 9-1 to 9-4).

Three questions about a Review_Report that was parsed as JSON:

1. **Schema** -- :func:`check_report`. Is it the 7-key Review_Report envelope
   of schema MAJOR 1, in the shapes ``report.build_report`` produces, with at
   most ``deltaschema.MAX_REPORT_FINDINGS`` Findings that each pass
   ``finding.from_dict``? A violation makes the Finding Delta unanalyzable.
2. **Internal consistency** -- also :func:`check_report`. Does rebuilding the
   Report with ``report.build_report`` give the same bytes
   (``rebuild_mismatch``: ID numbering, Finding order, summary), and is no
   dedup-eligible Identity_Key repeated (``dedup_invariant_violated``)? A
   failure is recorded and stops New / Resolved, but the comparison goes on.
   These checks are not tamper detection.
3. **Comparability** -- :func:`comparable_reasons`, :func:`summary_comparable`
   and :func:`correspondence`. Did a Source run under the same recorded
   conditions on both sides for a Template file, and do the Templates and the
   Reports name each other?

Untrusted input, no echo
    Reports are untrusted (Requirement 8 AC1). A rejection carries a field path
    built only from schema field names and list indexes, never a key or value
    taken from the input (Requirement 2 AC7, Requirement 12). The free-text
    fields of ``errors[]`` are read to rebuild the Report and then dropped:
    :class:`CheckedReport` keeps only each error's ``error_class`` and
    ``source`` (Requirement 8 AC7).
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Sequence, Tuple, Union

from iacreview import deltaschema, finding, report
from iacreview.deltaio import Failure, ParsedTemplate
from iacreview.errors import ERROR_CLASSES, STRUCTURED_ERROR_KEYS, MappingFileError, SchemaViolationError
from iacreview.finding import Finding

__all__ = [
    "SOURCE_TOOL_DEPENDENCIES",
    "ToolRecord",
    "ErrorRecord",
    "CheckedReport",
    "ReportRejection",
    "check_report",
    "comparable_reasons",
    "summary_comparable",
    "correspondence",
]

#: Source -> ``tools[].name`` entries it depends on (Design 9-3). The Plugin's
#: own Sources depend on no external tool; their version is covered by the
#: ``same_plugin_version`` declaration. ``Agent Review`` is judged separately
#: (``non_deterministic_source``). A Source missing here is never Comparable.
SOURCE_TOOL_DEPENDENCIES: Mapping[str, Tuple[str, ...]] = MappingProxyType(
    {
        "cfn-lint": ("cfn-lint",),
        "cfn-guard": ("cfn-guard",),
        "IAM Review": (),
        "Network Review": (),
        "Secret Review": (),
        "Quality Review": (),
        "Agent Review": (),
    }
)

#: The tool whose version matters for CDK-synthesized Templates.
CDK_TOOL = "cdk"

_SCHEMA_MAJOR = 1
_SCHEMA_VERSION_PATTERN = re.compile(r"^([0-9]+)\.([0-9]+)\.([0-9]+)$")

_TARGET_KEYS: Tuple[str, ...] = ("files", "cdk")
_CDK_KEYS: Tuple[str, ...] = ("detected", "synthesis", "synthesized_templates")

#: Field names a Finding rejection may quote, all from the Finding schema.
_FINDING_FIELD_NAMES: FrozenSet[str] = frozenset(
    finding.FINDING_FIELDS + finding.LOCATION_FIELDS + finding.EVIDENCE_FIELDS
)
_FIELD_SEGMENT = re.compile(r"^([A-Za-z_]+)((?:\[[0-9]+\])*)$")

_SOURCE_NOT_COMPARABLE = "source_not_comparable"
_TOOL_VERSION_MISMATCH = "tool_version_mismatch"
_TEMPLATE_NOT_REVIEWED = "template_not_reviewed"
_REASON_ORDER = {code: index for index, code in enumerate(deltaschema.AMBIGUOUS_REASONS)}


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ToolRecord:
    """One ``tools[]`` entry."""

    name: str
    available: bool
    version: Optional[str]


@dataclass(frozen=True)
class ErrorRecord:
    """What the Delta_Tool keeps of one input ``errors[]`` entry: no free text."""

    error_class: str
    source: Optional[str]


@dataclass(frozen=True)
class CheckedReport:
    """A Review_Report that passed the schema checks.

    Attributes:
        schema_version: The Report's ``schema_version``.
        files: ``target.files``.
        synthesized_templates: ``target.cdk.synthesized_templates``.
        cdk_detected: ``target.cdk.detected``.
        cdk_synthesis: ``target.cdk.synthesis``.
        sources_enabled: ``sources_enabled``.
        tools: ``tools[]``.
        errors: ``error_class`` and ``source`` of each ``errors[]`` entry.
        findings: The validated Findings, in Report order.
        integrity_failures: Failed internal-consistency checks, in the order of
            ``deltaschema.REPORT_INTEGRITY_CHECKS``. Empty when consistent.
    """

    schema_version: str
    files: Tuple[str, ...]
    synthesized_templates: Tuple[str, ...]
    cdk_detected: bool
    cdk_synthesis: str
    sources_enabled: Tuple[str, ...]
    tools: Tuple[ToolRecord, ...]
    errors: Tuple[ErrorRecord, ...]
    findings: Tuple[Finding, ...]
    integrity_failures: Tuple[str, ...]

    def tool(self, name: str) -> Optional[ToolRecord]:
        """The ``tools[]`` entry named ``name``, if any."""
        for entry in self.tools:
            if entry.name == name:
                return entry
        return None

    def reviewed(self, path: str) -> bool:
        """Whether ``path`` is in ``target.files`` or the synthesized Templates."""
        return path in self.files or path in self.synthesized_templates


@dataclass(frozen=True)
class ReportRejection:
    """Why a Report cannot be compared.

    Attributes:
        failure: ``report_schema_violation`` or ``report_finding_limit_exceeded``.
        field: Schema-derived path of the offending field (for example
            ``"findings[3].Evidence[0].Source"``), or ``None`` for the Report
            object itself. Never contains input content.
    """

    failure: Failure
    field: Optional[str]


class _Violation(Exception):
    """A schema violation at a schema-derived field path."""

    def __init__(self, field: Optional[str], code: str = "report_schema_violation") -> None:
        super().__init__(field)
        self.field = field
        self.code = code


# ---------------------------------------------------------------------------
# Schema (Design 9-1)
# ---------------------------------------------------------------------------


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _require_dict(value: Any, field: Optional[str], keys: Sequence[str]) -> Dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(keys):
        raise _Violation(field)
    return value


def _require_list(value: Any, field: str) -> List[Any]:
    if not isinstance(value, list):
        raise _Violation(field)
    return value


def _check_relative_path(value: Any, field: str) -> str:
    """A workspace-relative path as ``report.normalize_output_path`` requires."""
    if not isinstance(value, str):
        raise _Violation(field)
    try:
        report.normalize_output_path(value, field)
    except SchemaViolationError:
        raise _Violation(field) from None
    return value


def _check_schema_version(value: Any) -> str:
    if not isinstance(value, str):
        raise _Violation("schema_version")
    match = _SCHEMA_VERSION_PATTERN.match(value)
    if match is None or int(match.group(1)) != _SCHEMA_MAJOR:
        raise _Violation("schema_version")
    return value


def _check_path_list(value: Any, field: str) -> Tuple[str, ...]:
    items = _require_list(value, field)
    return tuple(
        _check_relative_path(item, "{0}[{1}]".format(field, index))
        for index, item in enumerate(items)
    )


def _check_target(value: Any) -> Tuple[Tuple[str, ...], Tuple[str, ...], bool, str]:
    target = _require_dict(value, "target", _TARGET_KEYS)
    files = _check_path_list(target["files"], "target.files")
    cdk = _require_dict(target["cdk"], "target.cdk", _CDK_KEYS)
    if not isinstance(cdk["detected"], bool):
        raise _Violation("target.cdk.detected")
    synthesis = cdk["synthesis"]
    if not isinstance(synthesis, str) or synthesis not in report.CDK_SYNTHESIS_OUTCOMES:
        raise _Violation("target.cdk.synthesis")
    synthesized = _check_path_list(cdk["synthesized_templates"], "target.cdk.synthesized_templates")
    return files, synthesized, cdk["detected"], synthesis


def _check_sources(value: Any) -> Tuple[str, ...]:
    items = _require_list(value, "sources_enabled")
    for index, item in enumerate(items):
        if not isinstance(item, str) or item not in finding.SOURCES:
            raise _Violation("sources_enabled[{0}]".format(index))
    if len(set(items)) != len(items):
        raise _Violation("sources_enabled")
    return tuple(items)


def _optional_str(value: Any) -> bool:
    return value is None or isinstance(value, str)


def _check_tools(value: Any) -> Tuple[ToolRecord, ...]:
    items = _require_list(value, "tools")
    records: List[ToolRecord] = []
    for index, item in enumerate(items):
        field = "tools[{0}]".format(index)
        entry = _require_dict(item, field, report.TOOL_KEYS)
        if not isinstance(entry["name"], str) or not entry["name"]:
            raise _Violation(field + ".name")
        if not isinstance(entry["available"], bool):
            raise _Violation(field + ".available")
        if not _optional_str(entry["version"]):
            raise _Violation(field + ".version")
        records.append(ToolRecord(entry["name"], entry["available"], entry["version"]))
    if len({record.name for record in records}) != len(records):
        raise _Violation("tools")
    return tuple(records)


def _check_errors(value: Any) -> Tuple[List[Dict[str, Any]], Tuple[ErrorRecord, ...]]:
    items = _require_list(value, "errors")
    records: List[ErrorRecord] = []
    for index, item in enumerate(items):
        field = "errors[{0}]".format(index)
        entry = _require_dict(item, field, STRUCTURED_ERROR_KEYS)
        if not isinstance(entry["error_class"], str) or entry["error_class"] not in ERROR_CLASSES:
            raise _Violation(field + ".error_class")
        if not isinstance(entry["message"], str):
            raise _Violation(field + ".message")
        for key in ("source", "tool", "required_min_version", "detected_version", "remediation"):
            if not _optional_str(entry[key]):
                raise _Violation("{0}.{1}".format(field, key))
        if entry["exit_code"] is not None and not _is_int(entry["exit_code"]):
            raise _Violation(field + ".exit_code")
        head = entry["stderr_head"]
        if not isinstance(head, list) or not all(isinstance(line, str) for line in head):
            raise _Violation(field + ".stderr_head")
        records.append(ErrorRecord(entry["error_class"], entry["source"]))
    return items, tuple(records)


def _safe_finding_field(raw: Any) -> Optional[str]:
    """``raw`` if every segment is a Finding schema field (with indexes), else ``None``.

    ``finding.from_dict`` names an unknown key by the key itself, which is
    input content; such a path is dropped rather than quoted.
    """
    if not isinstance(raw, str) or not raw:
        return None
    for segment in raw.split("."):
        match = _FIELD_SEGMENT.match(segment)
        if match is None or match.group(1) not in _FINDING_FIELD_NAMES:
            return None
    return raw


def _check_findings(value: Any) -> Tuple[Finding, ...]:
    items = _require_list(value, "findings")
    if len(items) > deltaschema.MAX_REPORT_FINDINGS:
        raise _Violation("findings", "report_finding_limit_exceeded")
    checked: List[Finding] = []
    for index, item in enumerate(items):
        field = "findings[{0}]".format(index)
        try:
            parsed = finding.from_dict(item)
        except MappingFileError:
            raise  # a broken installation, not bad input
        except SchemaViolationError as exc:
            inner = _safe_finding_field(getattr(exc, "field", None))
            raise _Violation(field if inner is None else "{0}.{1}".format(field, inner)) from None
        except Exception:  # noqa: BLE001 - untrusted input must fail closed, not crash
            raise _Violation(field) from None
        # Requirement 2 AC9: ``..`` and drive paths, which validate() lets through.
        _check_relative_path(parsed.Location.File, field + ".Location.File")
        checked.append(parsed)
    return tuple(checked)


# ---------------------------------------------------------------------------
# Internal consistency (Design 9-2)
# ---------------------------------------------------------------------------


def _rebuild_matches(
    obj: Dict[str, Any],
    findings: Sequence[Finding],
    errors: Sequence[Dict[str, Any]],
    tools: Sequence[ToolRecord],
) -> bool:
    target = obj["target"]
    meta = report.ReportMeta(
        files=tuple(target["files"]),
        sources_enabled=tuple(obj["sources_enabled"]),
        tools=tuple(report.ToolStatus(t.name, t.available, t.version) for t in tools),
        cdk_detected=target["cdk"]["detected"],
        synthesized_templates=tuple(target["cdk"]["synthesized_templates"]),
        cdk_synthesis=target["cdk"]["synthesis"],
    )
    try:
        rebuilt = report.build_report(list(findings), list(errors), meta)
        return report.dump(rebuilt) == report.dump(obj)
    except MappingFileError:
        raise
    except Exception:  # noqa: BLE001 - a Report build_report rejects is not consistent
        return False


def _identity_key(f: Finding) -> Tuple[str, Optional[str], str]:
    return (f.Location.File, f.Resource, f.Normalized_Category)


def _dedup_invariant_holds(findings: Sequence[Finding]) -> bool:
    counts = Counter(_identity_key(f) for f in findings if finding.is_dedup_eligible(f))
    return all(count == 1 for count in counts.values())


def check_report(obj: Any, side: Optional[str] = None) -> Union[CheckedReport, ReportRejection]:
    """Check a parsed Review_Report (Design 9-1, 9-2).

    Args:
        obj: The JSON value of the Report. Untrusted.
        side: ``"base"`` or ``"head"``, recorded in a rejection.

    Returns:
        A :class:`CheckedReport` (possibly with ``integrity_failures``), or a
        :class:`ReportRejection` for a schema violation or too many Findings.

    Raises:
        MappingFileError: The Plugin's category data is unusable (a broken
            installation, reported as ``unexpected`` by the caller).
    """
    try:
        if not isinstance(obj, dict):
            raise _Violation(None)
        for key in report.REPORT_KEYS:
            if key not in obj:
                raise _Violation(key)
        if len(obj) != len(report.REPORT_KEYS):
            raise _Violation(None)
        schema_version = _check_schema_version(obj["schema_version"])
        files, synthesized, cdk_detected, cdk_synthesis = _check_target(obj["target"])
        sources = _check_sources(obj["sources_enabled"])
        tools = _check_tools(obj["tools"])
        raw_errors, errors = _check_errors(obj["errors"])
        findings = _check_findings(obj["findings"])
        if not isinstance(obj["summary"], dict):
            raise _Violation("summary")
    except _Violation as violation:
        return ReportRejection(Failure(violation.code, side, "report"), violation.field)

    failures: List[str] = []
    if not _rebuild_matches(obj, findings, raw_errors, tools):
        failures.append("rebuild_mismatch")
    if not _dedup_invariant_holds(findings):
        failures.append("dedup_invariant_violated")
    return CheckedReport(
        schema_version=schema_version,
        files=files,
        synthesized_templates=synthesized,
        cdk_detected=cdk_detected,
        cdk_synthesis=cdk_synthesis,
        sources_enabled=sources,
        tools=tools,
        errors=errors,
        findings=findings,
        integrity_failures=tuple(failures),
    )


# ---------------------------------------------------------------------------
# Comparability (Design 9-3, 7-3)
# ---------------------------------------------------------------------------


def _ordered_reasons(reasons: Sequence[str]) -> Tuple[str, ...]:
    return tuple(sorted(set(reasons), key=_REASON_ORDER.__getitem__))


def _usable(record: Optional[ToolRecord]) -> bool:
    return record is not None and record.available


def comparable_reasons(
    source: str, file: str, base: CheckedReport, head: CheckedReport
) -> Tuple[str, ...]:
    """Why Source ``source`` is not Comparable for Template ``file`` (Requirement 7 AC1).

    Returns:
        An empty tuple when Comparable. Otherwise ``source_not_comparable``,
        with ``template_not_reviewed`` when ``file`` is missing from a Report's
        ``target`` and ``tool_version_mismatch`` when a tool it depends on is
        available on both sides with different versions. Ordered as
        ``deltaschema.AMBIGUOUS_REASONS``.
    """
    reasons: List[str] = []
    dependencies = SOURCE_TOOL_DEPENDENCIES.get(source)
    if dependencies is None:
        return _ordered_reasons([_SOURCE_NOT_COMPARABLE])
    tools = list(dependencies)
    synthesized = file in base.synthesized_templates or file in head.synthesized_templates
    if synthesized:
        if base.cdk_synthesis != head.cdk_synthesis:
            reasons.append(_SOURCE_NOT_COMPARABLE)
        if base.tool(CDK_TOOL) is not None or head.tool(CDK_TOOL) is not None:
            tools.append(CDK_TOOL)
    for side in (base, head):
        if not side.reviewed(file):
            reasons.extend((_SOURCE_NOT_COMPARABLE, _TEMPLATE_NOT_REVIEWED))
        if source not in side.sources_enabled:
            reasons.append(_SOURCE_NOT_COMPARABLE)
        if not all(_usable(side.tool(name)) for name in tools):
            reasons.append(_SOURCE_NOT_COMPARABLE)
        if any(error.source is None or error.source == source for error in side.errors):
            reasons.append(_SOURCE_NOT_COMPARABLE)
    for name in tools:
        base_tool, head_tool = base.tool(name), head.tool(name)
        if (
            base_tool is not None
            and head_tool is not None
            and _usable(base_tool)
            and _usable(head_tool)
            and base_tool.version != head_tool.version
        ):
            reasons.extend((_SOURCE_NOT_COMPARABLE, _TOOL_VERSION_MISMATCH))
    return _ordered_reasons(reasons)


def summary_comparable(base: CheckedReport, head: CheckedReport) -> bool:
    """The ``comparable`` summary flag (Requirement 7 AC10, Design 7-3).

    True only when both ``errors[]`` are empty, every tool is available, and
    both Reports list the same tools with the same versions. Does not look at
    ``summary.passed_all_checks``.
    """
    if base.errors or head.errors:
        return False
    if not all(tool.available for tool in base.tools + head.tools):
        return False
    base_versions = {tool.name: tool.version for tool in base.tools}
    head_versions = {tool.name: tool.version for tool in head.tools}
    return base_versions == head_versions


# ---------------------------------------------------------------------------
# Template / Report correspondence (Design 9-4)
# ---------------------------------------------------------------------------


def _side_consistent(template: ParsedTemplate, path: str, checked: CheckedReport) -> bool:
    try:
        normalized = report.normalize_output_path(path)
    except SchemaViolationError:
        return False
    if not checked.reviewed(normalized):
        return False
    resources = template.doc.get("Resources")
    names = set(resources) if isinstance(resources, dict) else set()
    for f in checked.findings:
        if f.Location.File == normalized and f.Resource is not None and f.Resource not in names:
            return False
    return True


def correspondence(
    base_template: Union[ParsedTemplate, Failure, None],
    head_template: Union[ParsedTemplate, Failure, None],
    base_report: CheckedReport,
    head_report: CheckedReport,
    template_paths: Optional[Tuple[str, str]],
) -> str:
    """``template_report_correspondence`` (Requirement 8 AC6).

    Args:
        base_template: The Base Template, a failure if it is unanalyzable, or
            ``None`` without a Template_Pair.
        head_template: Likewise for the Head.
        base_report: The checked Base Report.
        head_report: The checked Head Report.
        template_paths: The comparison paths of the Base and Head sides, or
            ``None`` without a Template_Pair. Each is the declared
            ``--reviewed-template-path`` (the same for both sides, H-M1-1
            approved) or else that side's workspace-relative Template path. A
            declared path only replaces the compared path; the Logical ID
            check below still uses each side's own Template.

    Returns:
        ``not_applicable`` without a Template_Pair; ``unknown`` when a Template
        is unanalyzable; ``inconsistent`` when a Template's path is not in its
        own Report's ``target``, or a non-null ``Resource`` of a Finding on
        that path is not a Logical ID of the Template; otherwise
        ``consistent_by_name_only``. There is no ``verified``.
    """
    if template_paths is None or base_template is None or head_template is None:
        return "not_applicable"
    if not isinstance(base_template, ParsedTemplate) or not isinstance(head_template, ParsedTemplate):
        return "unknown"
    base_path, head_path = template_paths
    if _side_consistent(base_template, base_path, base_report) and _side_consistent(
        head_template, head_path, head_report
    ):
        return "consistent_by_name_only"
    return "inconsistent"
