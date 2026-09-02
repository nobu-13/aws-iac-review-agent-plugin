"""Assembly of the Review_Report: order, number, summarize, serialize.

Everything upstream of this module produces Findings without knowing about any
other Source's Findings. This module is where a set of Findings becomes *one
report*: it puts them in the order Requirement 7 AC15 defines, numbers them,
counts them (AC17), and renders the whole envelope as the byte-stable JSON
Requirement 16 AC11 requires. It is the last step before stdout, and the only
step that sees the report as a whole.

:func:`sort_findings`
    The report order of Requirement 7 AC15, made total.

:func:`assign_ids`
    Sequential ``ID`` from 1, over the sorted sequence (Requirement 7 AC1).

:func:`build_report`
    The whole envelope, from Findings, StructuredErrors, and a :class:`ReportMeta`.

:func:`dump`
    The one serialization of a report.

:func:`configure_stdout`
    Fixes the encoding and newline translation of the stream a report is written
    to, so that ``LANG`` / ``LC_ALL`` and the host platform cannot change the
    bytes.

Six decisions are worth reading before using the module.

**IDs come after ordering, not before.** Requirement 7 AC1 asks for a sequential
integer from 1, and AC15 fixes the sequence it counts along, so ``ID`` is a
property of a Finding's *position in this report* rather than an identity it
carries in from its Source. That is also why ``dedup`` leaves
:data:`~iacreview.finding.UNASSIGNED_ID` behind and why :func:`assign_ids` builds
new Findings instead of mutating the ones it was handed: an input Finding that
appears in two reports would otherwise end up with whichever number was written
last.

**The sort key has two components the requirement does not mention.**
Requirement 7 AC15 orders by Severity descending, then by resource logical ID
ascending -- which leaves the order of two Findings on one resource at one
Severity undefined, and an undefined order cannot be byte-identical across runs
(Requirement 16 AC11). design.md adds ``Normalized_Category`` and the Finding
description as tie-breakers; :func:`_sort_key` appends one more, the Finding's own
content rendered canonically, because ``(Resource, Category)`` is exactly the
dedup key: any two Findings still tied after three components are two Findings
that dedup deliberately did *not* merge (a ``Resource``-less pair, or an ``Other``
pair -- see :func:`iacreview.finding.is_dedup_eligible`) and that also share a
description. The last component is never consulted in a case the first three
decide, and two Findings with equal canonical forms are indistinguishable in the
report, so the order is total in the only sense that matters to output bytes.

**A Finding with no resource sorts first within its Severity.** design.md's key
substitutes ``""`` for a ``None`` ``Resource``, and the empty string sorts before
every logical ID. The substitution is unambiguous rather than a convention to
remember: a ``Resource`` that is present is a non-empty string
(``finding.validate`` rejects an empty one), so ``""`` cannot collide with a real
logical ID. Reading it as a report order: template-level problems (a malformed
section, an unused Parameter) come before per-resource problems of the same
Severity, which is also the order in which they have to be dealt with.

**Paths are normalized here, and absolute ones are refused rather than fixed.**
``Location.File``, ``target.files``, and the synthesized Template list are all
rewritten to ``/``-separated relative paths through :class:`~pathlib.PurePosixPath`
so a report generated on Windows and one generated on Linux are the same bytes
(design.md, Portability Design). What this module will not do is *relativize* an
absolute path: doing so needs the workspace root, which is an environment-dependent
value that has no place in report assembly. :func:`iacreview.source.workspace_relative`
is where that conversion belongs, at the Source that knew the root, so an absolute
path arriving here is a caller error and is reported as a schema violation.

**Findings are validated on the way out.** :func:`build_report` calls
:func:`iacreview.finding.validate` on every Finding after numbering it -- the
first moment in a Finding's life when it can pass, since ``validate`` requires
``ID >= 1``. This is the output boundary: a report that reaches a consumer has
been checked against the schema it claims to follow, and a Source bug becomes a
loud failure at serialization instead of a malformed entry someone reads as
fact.

**There is no ``stats`` section.** The report envelope is the seven keys design.md
lists, and per-Source counters are not among them. That is not an omission to fill
in later without thought: no ``stats`` key is common to all three deterministic
Sources (cfn-lint counts parsed results, cfn-guard counts parsed violations, IAM
Review counts nothing), and the values are not uniformly numeric -- cfn-guard
records how its rule count was arrived at as a string, IAM Review records a
message. Merging them into one flat dict would produce a section whose key set
depends on which Sources ran and whose values cannot be summed. If counters are
ever surfaced, they belong in a per-Source namespace, keyed by Source name.

The envelope being closed is what lets a Skill add a key *beside* it without
touching the shared schema, and design.md [Correction] C-10 pins when a Skill may:
only where an acceptance criterion makes a counter part of the *result* rather
than a diagnostic. One criterion does, Requirement 5 AC4, so
``skills/cfn-guard-review/scripts/run_cfn_guard.py`` adds a top-level ``stats``
object to what :func:`build_report` returned and no other entry point does. This
module stays unaware of that: it builds :data:`REPORT_KEYS` and nothing else, so a
consumer reading only those keys reads every Skill's stdout the same way.
"""

from __future__ import annotations

import copy
import json
import sys
from dataclasses import dataclass, field, replace
from pathlib import PurePath, PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Sequence, TextIO, Tuple, Union

from iacreview.finding import (
    FINDING_TYPES,
    SEVERITIES,
    SEVERITY_ORDER,
    SOURCES,
    Finding,
    schema_violation,
    sorted_sources,
    to_dict,
    validate,
)
from iacreview.source import PARENT_DIRECTORY, StructuredError

__all__ = [
    "SCHEMA_VERSION",
    "FIRST_ID",
    "STANDALONE_GROUP",
    "SYNTHESIZED_GROUP",
    "TEMPLATE_GROUPS",
    "REPORT_KEYS",
    "SUMMARY_KEYS",
    "TOOL_KEYS",
    "CDK_SYNTHESIS_NOT_APPLICABLE",
    "CDK_SYNTHESIS_SKIPPED_UNCONFIRMED",
    "CDK_SYNTHESIS_RAN",
    "CDK_SYNTHESIS_OUTCOMES",
    "ToolStatus",
    "ReportMeta",
    "normalize_output_path",
    "sort_findings",
    "assign_ids",
    "build_report",
    "dump",
    "configure_stdout",
]

#: Version of the report and Finding schema this module emits (design.md,
#: Review_Report schema). Bumped per semver on a breaking schema change, which
#: ``docs/`` and the CHANGELOG record; it is the only version-like value in the
#: output, and deliberately not a build or run identifier.
SCHEMA_VERSION = "1.0.0"

#: First ``ID`` assigned (Requirement 7 AC1: "starting from 1").
FIRST_ID = 1

#: ``summary.by_template_group`` key for a Template the user named directly.
STANDALONE_GROUP = "standalone"

#: ``summary.by_template_group`` key for a Template produced by ``cdk synth``.
SYNTHESIZED_GROUP = "synthesized"

#: Both groups of Requirement 8 AC10, in report order. Fixed, so the key set of
#: ``by_template_group`` does not depend on what the reviewed directory held.
TEMPLATE_GROUPS: Tuple[str, ...] = (STANDALONE_GROUP, SYNTHESIZED_GROUP)

#: Top-level report keys (design.md, Review_Report schema). Serialization sorts
#: keys alphabetically, so this tuple documents the schema rather than the
#: output order.
REPORT_KEYS: Tuple[str, ...] = (
    "schema_version",
    "target",
    "sources_enabled",
    "tools",
    "findings",
    "errors",
    "summary",
)

#: Keys of the ``summary`` object (Requirement 7 AC17 plus the two report-level
#: facts of AC16 and Requirement 8 AC10).
SUMMARY_KEYS: Tuple[str, ...] = (
    "total",
    "by_finding_type",
    "by_severity",
    "by_source",
    "by_template_group",
    "passed_all_checks",
)

#: Keys of one entry of ``tools``.
TOOL_KEYS: Tuple[str, ...] = ("name", "available", "version")

#: ``target.cdk.synthesis`` value when the target held no ``cdk.json``: there was
#: no CDK source to synthesize (Requirement 23 AC1).
CDK_SYNTHESIS_NOT_APPLICABLE = "not_applicable"

#: ``target.cdk.synthesis`` value when a CDK project was found but ``cdk synth``
#: was not run because ``--confirm-cdk-synth`` was absent (Requirement 8 AC5,
#: Requirement 23 AC1/AC5). Only already-synthesized templates, if any, were
#: reviewed; an empty finding set here is a skipped synthesis, not a clean
#: review.
CDK_SYNTHESIS_SKIPPED_UNCONFIRMED = "skipped_unconfirmed"

#: ``target.cdk.synthesis`` value when ``cdk synth`` ran (and succeeded, since a
#: failed synth aborts the review rather than falling back, Requirement 8 AC7).
CDK_SYNTHESIS_RAN = "ran"

#: The closed set of ``target.cdk.synthesis`` values, so a consumer may switch on
#: them. The value is a deterministic function of the target layout and the
#: confirmation flag (Requirement 23 AC3): no wall-clock, no host path.
CDK_SYNTHESIS_OUTCOMES: Tuple[str, ...] = (
    CDK_SYNTHESIS_NOT_APPLICABLE,
    CDK_SYNTHESIS_SKIPPED_UNCONFIRMED,
    CDK_SYNTHESIS_RAN,
)

# design.md pseudocode name for the Severity ranking. The same object as the
# definition in :mod:`iacreview.finding`, so merge order and report order cannot
# drift apart.
_SEV_ORDER = SEVERITY_ORDER

#: Path segment that would make a report name a file outside the workspace.
_PARENT_DIRECTORY = PARENT_DIRECTORY

#: Trailing character of a Windows drive segment (``"C:"`` in ``"C:/templates"``).
#: :class:`~pathlib.PurePosixPath` does not consider such a path absolute, so it
#: is detected structurally.
_DRIVE_SUFFIX = ":"

#: Path segments carrying no information, dropped during normalization so that
#: ``"./app.yaml"`` and ``"app.yaml"`` cannot appear as two spellings of one file.
_EMPTY_SEGMENTS = (".", "")


# ---------------------------------------------------------------------------
# Report metadata
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ToolStatus:
    """One entry of the report's ``tools`` array.

    Attributes:
        name: Executable name, for example ``"cfn-lint"``.
        available: Whether the tool was resolved and version-checked
            successfully. ``False`` is a normal outcome, not a failure of the
            review: a missing tool is reported and the remaining Sources run
            (Requirement 4 AC12, Requirement 5 AC6).
        version: Detected version, or ``None`` when the tool was unavailable or
            its banner was unparsable. Never a path: the resolved absolute
            location of a binary is environment-dependent and belongs on stderr
            (design.md, Determinism Design).
    """

    name: str
    available: bool
    version: Optional[str] = None


@dataclass(frozen=True)
class ReportMeta:
    """What the report says about the review, other than its Findings.

    Attributes:
        files: Templates reviewed as standalone input, as workspace-relative
            paths. Normalized and sorted by :func:`build_report`.
        sources_enabled: Sources the run was configured to use, whether or not
            each produced Findings. Ordered by
            :func:`~iacreview.finding.sorted_sources`, so the caller may pass any
            order.
        tools: One :class:`ToolStatus` per external tool the run considered.
        cdk_detected: Whether a ``cdk.json`` was found (Requirement 8 AC2).
        synthesized_templates: Templates reviewed from the CDK output directory,
            as workspace-relative paths. Kept separate from ``files`` because
            Requirement 8 AC10 asks for the two groups to be reported separately;
            the same split drives ``summary.by_template_group``. Its length is
            the count of synthesized templates reviewed (Requirement 23 AC2).
        cdk_synthesis: The synthesis outcome, one of
            :data:`CDK_SYNTHESIS_OUTCOMES` (Requirement 23 AC1). It lets a
            consumer tell "no CDK source" from "CDK source whose synthesis was
            skipped" from "synthesis ran", so an empty finding set from a skipped
            synthesis is not read as a clean review (AC5). Defaults to
            :data:`CDK_SYNTHESIS_NOT_APPLICABLE`, the outcome for the common case
            of a review with no CDK project involved. It is a deterministic
            function of the target layout and the confirmation flag (AC3), so it
            carries no environment-dependent value.

    Every field defaults to empty, so a report for a run that produced nothing
    but errors can be built without inventing values.
    """

    files: Sequence[Union[str, PurePath]] = field(default_factory=tuple)
    sources_enabled: Sequence[str] = field(default_factory=tuple)
    tools: Sequence[ToolStatus] = field(default_factory=tuple)
    cdk_detected: bool = False
    synthesized_templates: Sequence[Union[str, PurePath]] = field(default_factory=tuple)
    cdk_synthesis: str = CDK_SYNTHESIS_NOT_APPLICABLE


# ---------------------------------------------------------------------------
# Path normalization
# ---------------------------------------------------------------------------


def normalize_output_path(value: Union[str, PurePath], field_name: str = "path") -> str:
    """Render ``value`` as the ``/``-separated relative path a report may carry.

    Args:
        value: A path as some part of the pipeline recorded it. Accepts a
            :class:`~pathlib.PurePath` so a caller does not have to stringify
            first, and normalizes ``\\`` to ``/`` so a path recorded on Windows
            reads the same as one recorded on Linux.
        field_name: Report field the path belongs to, used in the failure
            message so a rejection names the field a reader can find.

    Returns:
        The path with separators normalized to ``/`` and uninformative segments
        (``.``, empty) removed.

    Raises:
        SchemaViolationError: ``value`` is absolute (including a Windows drive
            path), empty, or climbs out of the workspace through ``..``. Refused
            rather than repaired: see the module docstring on why relativizing
            belongs to the Source that knew the workspace root.
    """
    text = str(value).replace("\\", "/")
    candidate = PurePosixPath(text)
    segments = tuple(part for part in candidate.parts if part not in _EMPTY_SEGMENTS)

    if candidate.is_absolute() or (segments and segments[0].endswith(_DRIVE_SUFFIX)):
        raise schema_violation(
            field_name,
            "must be a workspace-relative path, got the absolute path {0!r}".format(text),
        )
    if not segments:
        raise schema_violation(field_name, "must not be empty")
    if _PARENT_DIRECTORY in segments:
        raise schema_violation(
            field_name,
            "must not leave the workspace through {0!r}, got {1!r}".format(
                _PARENT_DIRECTORY, text
            ),
        )
    return "/".join(segments)


def _normalize_path_list(
    values: Iterable[Union[str, PurePath]], field_name: str
) -> List[str]:
    """Normalize a report path array, de-duplicated and in ascending order.

    Sorting here rather than trusting the caller keeps ``target.files``
    independent of directory traversal order, and de-duplication keeps one
    Template from being listed twice when it was reached by two spellings of the
    same path.
    """
    normalized = {
        normalize_output_path(value, "{0}[{1}]".format(field_name, index))
        for index, value in enumerate(values)
    }
    return sorted(normalized)


def _with_normalized_location(f: Finding) -> Finding:
    """Return ``f`` with ``Location.File`` normalized, or ``f`` if it already is.

    A new Finding when anything changed: the input Findings belong to their
    Sources, and a report must not rewrite them in place.
    """
    normalized = normalize_output_path(f.Location.File, "Location.File")
    if normalized == f.Location.File:
        return f
    return replace(f, Location=replace(f.Location, File=normalized))


# ---------------------------------------------------------------------------
# Ordering and numbering
# ---------------------------------------------------------------------------


def _severity_rank(f: Finding) -> int:
    """Rank of ``f``'s Severity, or a schema violation naming the bad value.

    ``SEVERITY_ORDER[f.Severity]`` would raise ``KeyError`` here, which reads as
    an internal fault rather than as "this Finding is not schema-valid". Sorting
    happens before ``validate`` can run (it needs the ``ID`` that sorting
    decides), so this is the first place a bad Severity can be reported at all.
    """
    try:
        return _SEV_ORDER[f.Severity]
    except (KeyError, TypeError):
        raise schema_violation(
            "Severity", "{0!r} is not one of {1}".format(f.Severity, list(SEVERITIES))
        ) from None


def _content_key(f: Finding) -> str:
    """``f``'s content as one canonical string, excluding ``ID``.

    The last-resort sort component (see the module docstring). ``ID`` is left out
    on purpose: it is what sorting is about to decide, so letting an incoming
    value influence the order would make the result depend on how the Findings
    happened to be numbered before.
    """
    payload = to_dict(f)
    payload.pop("ID", None)
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _sort_key(f: Finding) -> Tuple[int, str, str, str, str]:
    """Report order of Requirement 7 AC15, made total (design.md pseudocode)."""
    return (
        -_severity_rank(f),  # Severity descending (Requirement 7 AC15)
        f.Resource or "",  # logical ID ascending; None sorts first
        f.Normalized_Category,  # tie-breaker for determinism
        f.Finding,  # tie-breaker for determinism
        _content_key(f),  # last resort, see module docstring
    )


def sort_findings(findings: Sequence[Finding]) -> List[Finding]:
    """Order ``findings`` for the report (Requirement 7 AC15).

    Args:
        findings: Findings from every Source, deduplicated, in any order.

    Returns:
        A new list holding the same Finding objects, ordered by Severity
        descending, then resource logical ID ascending, then the two tie-breakers
        design.md defines, then canonical content. The order is a function of the
        Findings' contents alone, so two permutations of one input sort the same
        way.

    Raises:
        SchemaViolationError: A Finding carries a Severity outside
            :data:`~iacreview.finding.SEVERITIES`.
    """
    return sorted(findings, key=_sort_key)


def assign_ids(findings: Sequence[Finding]) -> List[Finding]:
    """Number ``findings`` sequentially from :data:`FIRST_ID` (Requirement 7 AC1).

    Args:
        findings: Findings in report order. Numbering an unsorted sequence
            produces IDs that are stable only if that sequence is, which is why
            :func:`build_report` always sorts first.

    Returns:
        A new list of new Findings, each a copy of its input with ``ID`` set.
        The input Findings are untouched (see the module docstring).
    """
    return [replace(f, ID=index) for index, f in enumerate(findings, start=FIRST_ID)]


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


def _template_group(f: Finding, synthesized: Sequence[str]) -> str:
    """Which group of Requirement 8 AC10 ``f``'s Template belongs to.

    A Finding is synthesized output only if its ``Location.File`` is one of the
    Templates the run listed as synthesized; everything else counts as
    standalone. The default matters for a Finding whose file is in neither list
    -- one raised against a Template that could not be listed, for instance --
    and standalone is the honest answer there: it is what the user pointed at,
    and claiming CDK provenance for it would be a stronger statement than the
    evidence supports.
    """
    return SYNTHESIZED_GROUP if f.Location.File in synthesized else STANDALONE_GROUP


def _summary(findings: Sequence[Finding], synthesized: Sequence[str]) -> Dict[str, Any]:
    """Build the ``summary`` object (Requirement 7 AC16, AC17).

    Every count dict is pre-filled with zeros for its whole closed value set, so
    the key set of the summary is the same in every report: a consumer can index
    ``by_severity["CRITICAL"]`` without an existence check, and a report with no
    ``CRITICAL`` Findings differs from one with two only in the number.

    ``by_source`` counts a Finding once per Source that detected it, so its
    values sum to more than ``total`` as soon as one Finding was merged from two
    Sources (Requirement 14 AC12). That is intended and documented in
    ``docs/finding-schema.md``; ``by_finding_type`` and ``by_severity`` do sum to
    ``total``, since those fields hold one value each.
    """
    by_finding_type = {name: 0 for name in FINDING_TYPES}
    by_severity = {name: 0 for name in SEVERITIES}
    by_source = {name: 0 for name in SOURCES}
    by_template_group = {name: 0 for name in TEMPLATE_GROUPS}

    synthesized_files = frozenset(synthesized)
    for f in findings:
        by_finding_type[f.FindingType] = by_finding_type.get(f.FindingType, 0) + 1
        by_severity[f.Severity] = by_severity.get(f.Severity, 0) + 1
        for source in f.Source:
            by_source[source] = by_source.get(source, 0) + 1
        group = _template_group(f, synthesized_files)
        by_template_group[group] += 1

    return {
        "total": len(findings),
        "by_finding_type": by_finding_type,
        "by_severity": by_severity,
        "by_source": by_source,
        "by_template_group": by_template_group,
        # Requirement 7 AC16: an empty findings list is what "passed all checks"
        # means. Errors are reported separately and do not make this false: a
        # run in which cfn-guard was unavailable found no issues, which is not
        # the same claim as "there are none", and the ``errors`` array is what
        # tells a reader which is which.
        "passed_all_checks": not findings,
    }


# ---------------------------------------------------------------------------
# Envelope
# ---------------------------------------------------------------------------


def _tool_entries(tools: Sequence[ToolStatus]) -> List[Dict[str, Any]]:
    """Render ``tools`` as the report's ``tools`` array, ordered by name.

    Sorted by name rather than kept in the caller's order so the array is a
    function of its contents; there is no meaningful priority among tools that a
    fixed order would express.

    Raises:
        SchemaViolationError: An entry is not a :class:`ToolStatus`, or two
            entries name the same tool, which would leave a consumer looking up
            a tool by name with two answers.
    """
    entries: List[Dict[str, Any]] = []
    seen = set()
    for index, tool in enumerate(tools):
        field_name = "tools[{0}]".format(index)
        if not isinstance(tool, ToolStatus):
            raise schema_violation(
                field_name, "expected a ToolStatus, got {0}".format(type(tool).__name__)
            )
        if tool.name in seen:
            raise schema_violation(
                field_name, "{0!r} is already listed".format(tool.name)
            )
        seen.add(tool.name)
        entries.append(
            {"name": tool.name, "available": bool(tool.available), "version": tool.version}
        )
    return sorted(entries, key=lambda entry: entry["name"])


def build_report(
    findings: Sequence[Finding],
    errors: Sequence[StructuredError],
    meta: ReportMeta,
) -> Dict[str, Any]:
    """Assemble the Review_Report (design.md, Review_Report schema).

    Args:
        findings: Deduplicated Findings from every Source, in any order. Their
            ``ID`` values are ignored and replaced.
        errors: StructuredErrors from Sources that failed, in the order the
            orchestrator collected them. Copied, and otherwise passed through:
            the orchestrator's Source order is already fixed, and an error's
            position carries information (the first one is the failure that
            stopped its Source) that sorting would destroy.
        meta: What the report says about the review itself.

    Returns:
        A JSON-serializable dict with exactly the keys of :data:`REPORT_KEYS`,
        whose ``findings`` are sorted and numbered. Nothing in it aliases the
        inputs, so a caller may keep both.

    Raises:
        SchemaViolationError: A Finding does not satisfy the Finding schema once
            numbered, a path is absolute or leaves the workspace, a Source name
            is outside :data:`~iacreview.finding.SOURCES`, or ``tools`` is
            malformed. Findings are validated here because this is the output
            boundary (see the module docstring).
        MappingFileError: The category mapping file is present but unusable, so
            ``Normalized_Category`` cannot be checked.
    """
    numbered = assign_ids(sort_findings([_with_normalized_location(f) for f in findings]))
    for f in numbered:
        validate(f)

    files = _normalize_path_list(meta.files, "target.files")
    synthesized = _normalize_path_list(
        meta.synthesized_templates, "target.cdk.synthesized_templates"
    )
    if meta.cdk_synthesis not in CDK_SYNTHESIS_OUTCOMES:
        raise schema_violation(
            "target.cdk.synthesis",
            "must be one of {0}, got {1!r}".format(
                list(CDK_SYNTHESIS_OUTCOMES), meta.cdk_synthesis
            ),
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "target": {
            "files": files,
            "cdk": {
                "detected": bool(meta.cdk_detected),
                "synthesis": meta.cdk_synthesis,
                "synthesized_templates": synthesized,
            },
        },
        "sources_enabled": sorted_sources(meta.sources_enabled),
        "tools": _tool_entries(meta.tools),
        "findings": [to_dict(f) for f in numbered],
        "errors": [copy.deepcopy(dict(error)) for error in errors],
        "summary": _summary(numbered, synthesized),
    }


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def dump(report: Dict[str, Any]) -> str:
    """Serialize ``report`` as the report JSON text (design.md, 出力の直列化).

    Args:
        report: A report as :func:`build_report` returned it.

    Returns:
        The JSON text, with a trailing newline so the output is a well-formed
        text file and appending to it starts on a new line.

    Note:
        Every argument to :func:`json.dumps` is pinned rather than left to the
        default: ``sort_keys`` makes key order independent of insertion order and
        of ``PYTHONHASHSEED``; ``ensure_ascii=False`` keeps non-ASCII Template
        content (a Japanese Tag value) readable instead of ``\\uXXXX``-escaped;
        ``separators`` is stated even though it matches the ``indent`` default,
        so a future change to that default cannot change the bytes.
    """
    return (
        json.dumps(
            report,
            sort_keys=True,
            ensure_ascii=False,
            indent=2,
            separators=(",", ": "),
        )
        + "\n"
    )


def configure_stdout(stream: Optional[TextIO] = None) -> bool:
    """Pin ``stream``'s encoding to UTF-8 and its newline to ``\\n``.

    :func:`dump` decides the characters; this decides the bytes. Without it,
    ``ensure_ascii=False`` output would be encoded with whatever locale
    ``LANG`` / ``LC_ALL`` implies, and on Windows ``\\n`` would be translated to
    ``\\r\\n`` -- either of which breaks Requirement 16 AC11 for a report that is
    otherwise identical.

    Args:
        stream: Text stream to configure. Defaults to :data:`sys.stdout`, read at
            call time so a caller that replaced it is honored.

    Returns:
        ``True`` when the stream was reconfigured, ``False`` when it does not
        support reconfiguration -- an :class:`io.StringIO` a test captures output
        in, or a stream some host runtime substituted. ``False`` is not an error:
        such a stream has no encoding step of its own to get wrong, and refusing
        to write to it would make the report unavailable to the runtime that
        asked for it.
    """
    target = sys.stdout if stream is None else stream
    reconfigure = getattr(target, "reconfigure", None)
    if reconfigure is None:
        return False
    reconfigure(encoding="utf-8", newline="\n")
    return True
