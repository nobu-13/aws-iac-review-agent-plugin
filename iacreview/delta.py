"""Finding Delta of two checked Review_Reports (v1.1 Delta_Tool, Design 6 and 7).

:func:`match_and_classify` pairs the Findings of a Base and a Head Report with a
fixed, ordered procedure and classifies every Finding exactly once. It is a
pure function over :class:`iacreview.reportcheck.CheckedReport` values.

Matching pairs only what is unique (Requirement 6)
    Findings are grouped by Identity_Key ``(Location.File, Resource,
    Normalized_Category)``; nothing is paired across groups.

    * Stage 1: a dedup-eligible group with exactly one Finding on each side is
      matched, whatever else differs.
    * Stage 2: a Base and a Head Finding with equal Fingerprints are matched
      when that Fingerprint occurs once on each side of the group.
    * There is no stage 3 (D-H13): no similarity, no partial-field matching.

    What is left is ``Ambiguous`` (``unmatched``) when the group still has
    unmatched Findings on both sides (``identity_undetermined``) or the
    Fingerprint repeats on its side (``duplicate_fingerprint``). Only a Finding
    with no candidate at all on the other side becomes ``head_only`` /
    ``base_only``, so New / Resolved can be under-reported by a mis-pairing but
    never over-reported (Design 6-4, 6-5).

Classification never resolves what cannot be checked (Requirement 7)
    A ``head_only`` / ``base_only`` Finding is ``Ambiguous`` with every reason
    that applies -- a Source that is not Comparable (missing tool, Source not
    run, Template not reviewed, tool version mismatch, a Source error), only
    Agent Review, a possible Logical ID rename, a failed internal-consistency
    check, or Templates and Reports that do not correspond. Declarations do not
    override any of these. Otherwise it is ``Unconfirmed`` while a required
    Input_Declaration is missing, and only then ``New`` / ``Resolved``.

Evidence differences are observations
    A matched pair lists the differing fields and the ``(Source, RuleId)``
    elements present on one side only, each with whether its Source is
    Comparable. No classification is attached to them: a vanished Evidence
    element is not a resolved problem (Requirement 6 AC14).

No free text is returned
    Entries carry :class:`FindingProjection` values: identifiers, closed-set
    values, the TemplatePath and the ``(Source, RuleId)`` pairs. The Finding
    text, Evidence ``Detail`` / ``Excerpt`` and Template values are not part of
    the result (Requirement 16 AC3).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Sequence, Set, Tuple

from iacreview import deltaschema
from iacreview.finding import AGENT_SOURCE, Finding, is_dedup_eligible
from iacreview.reportcheck import CheckedReport, comparable_reasons, summary_comparable
from iacreview.semdiff import canonical_path

__all__ = [
    "IdentityKey",
    "EvidenceKey",
    "EvidenceDelta",
    "FindingProjection",
    "DeltaEntry",
    "ReportIntegrity",
    "InputDeclarations",
    "FindingDeltaResult",
    "REPORT_DECLARATIONS",
    "TEMPLATE_DECLARATION",
    "CHANGE_FIELDS",
    "identity_key",
    "fingerprint",
    "project",
    "required_declarations",
    "match_and_classify",
]

#: Declarations every New / Resolved needs (Requirement 8 AC4).
REPORT_DECLARATIONS: Tuple[str, ...] = tuple(
    code for code in deltaschema.DECLARATION_CODES if code != "reports_match_templates"
)

#: The declaration needed in addition when a Template_Pair is given.
TEMPLATE_DECLARATION = "reports_match_templates"

#: Fields compared for a matched pair, in this order (Requirement 6 AC13).
CHANGE_FIELDS: Tuple[str, ...] = (
    "Severity",
    "FindingType",
    "Confidence",
    "Source",
    "Location.TemplatePath",
    "Evidence",
)

_NOT_APPLICABLE = "not_applicable"
_MISMATCHED_CORRESPONDENCE: FrozenSet[str] = frozenset(("inconsistent", "unknown"))
_AMBIGUOUS_ORDER = {code: index for index, code in enumerate(deltaschema.AMBIGUOUS_REASONS)}
_CLASSIFICATION_ORDER = {code: index for index, code in enumerate(deltaschema.DELTA_CLASSIFICATIONS)}
_OBSERVATION_ORDER = {code: index for index, code in enumerate(deltaschema.ENTRY_OBSERVATIONS)}

#: A TemplatePath element.
_PathItem = Any


# ---------------------------------------------------------------------------
# Keys and projections (Design 6-1)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IdentityKey:
    """``(Location.File, Resource, Normalized_Category)``; ``Resource`` may be ``None``."""

    File: str
    Resource: Optional[str]
    Normalized_Category: str

    def sort_key(self) -> Tuple[Any, ...]:
        return (self.File, self.Resource is not None, self.Resource or "", self.Normalized_Category)


@dataclass(frozen=True)
class EvidenceKey:
    """The part of one Evidence entry that matching looks at."""

    Source: str
    RuleId: Optional[str]

    def sort_key(self) -> Tuple[Any, ...]:
        return (self.Source, self.RuleId is not None, self.RuleId or "")


@dataclass(frozen=True)
class EvidenceDelta:
    """An Evidence element present on one side of a matched pair only."""

    Source: str
    RuleId: Optional[str]
    source_comparable: bool


#: ``(Identity_Key, FindingType, TemplatePath, sorted Evidence multiset)``.
Fingerprint = Tuple[IdentityKey, str, Optional[Tuple[_PathItem, ...]], Tuple[EvidenceKey, ...]]


@dataclass(frozen=True)
class FindingProjection:
    """The free-text-free part of a Finding (Finding_Projection).

    ``TemplatePath`` is canonical (``semdiff.canonical_path``) and
    ``Evidence`` is sorted, so a projection does not depend on input order.
    """

    ID: int
    File: str
    Resource: Optional[str]
    Normalized_Category: str
    FindingType: str
    Severity: str
    Confidence: str
    Source: Tuple[str, ...]
    TemplatePath: Optional[Tuple[_PathItem, ...]]
    Evidence: Tuple[EvidenceKey, ...]

    @property
    def key(self) -> IdentityKey:
        return IdentityKey(self.File, self.Resource, self.Normalized_Category)

    @property
    def fingerprint(self) -> Fingerprint:
        return (self.key, self.FindingType, self.TemplatePath, self.Evidence)


def _sortable(value: Any) -> Tuple[Any, ...]:
    """A total order over the values found in keys and fingerprints."""
    if value is None:
        return (0,)
    if isinstance(value, bool):
        return (1, int(value))
    if isinstance(value, int):
        return (2, value)
    if isinstance(value, str):
        return (3, value)
    if isinstance(value, (IdentityKey, EvidenceKey)):
        return (4, value.sort_key())
    if isinstance(value, tuple):
        return (5, tuple(_sortable(item) for item in value))
    return (6, repr(value))


def project(f: Finding) -> FindingProjection:
    """The Finding_Projection of a validated Finding."""
    template_path = f.Location.TemplatePath
    evidence = sorted(
        (EvidenceKey(entry.Source, entry.RuleId) for entry in f.Evidence),
        key=EvidenceKey.sort_key,
    )
    return FindingProjection(
        ID=f.ID,
        File=f.Location.File,
        Resource=f.Resource,
        Normalized_Category=f.Normalized_Category,
        FindingType=f.FindingType,
        Severity=f.Severity,
        Confidence=f.Confidence,
        Source=tuple(f.Source),
        TemplatePath=None if template_path is None else canonical_path(template_path),
        Evidence=tuple(evidence),
    )


def identity_key(f: Finding) -> IdentityKey:
    """Identity_Key of a Finding (Requirement 6 AC1)."""
    return IdentityKey(f.Location.File, f.Resource, f.Normalized_Category)


def fingerprint(f: Finding) -> Fingerprint:
    """Fingerprint of a Finding (Requirement 6 AC2, AC3)."""
    return project(f).fingerprint


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DeltaEntry:
    """One Delta_Entry. ``base`` / ``head`` is ``None`` on a side without a Finding."""

    observation: str
    classification: str
    reasons: Tuple[str, ...]
    missing_declarations: Tuple[str, ...]
    key: IdentityKey
    match_stage: Optional[int]
    base: Optional[FindingProjection]
    head: Optional[FindingProjection]
    changes: Tuple[str, ...]
    evidence_absent_in_head: Tuple[EvidenceDelta, ...]
    evidence_absent_in_base: Tuple[EvidenceDelta, ...]

    @property
    def base_fingerprint(self) -> Optional[Fingerprint]:
        return None if self.base is None else self.base.fingerprint

    @property
    def head_fingerprint(self) -> Optional[Fingerprint]:
        return None if self.head is None else self.head.fingerprint

    def sort_key(self) -> Tuple[Any, ...]:
        return (
            _CLASSIFICATION_ORDER[self.classification],
            _OBSERVATION_ORDER[self.observation],
            self.key.sort_key(),
            _sortable(self.base_fingerprint),
            _sortable(self.head_fingerprint),
            0 if self.base is None else self.base.ID,
            0 if self.head is None else self.head.ID,
        )


@dataclass(frozen=True)
class ReportIntegrity:
    """Failed internal-consistency checks per side (Requirement 2 AC11)."""

    base: Tuple[str, ...]
    head: Tuple[str, ...]


@dataclass(frozen=True)
class InputDeclarations:
    """What the user declared and what is still missing (Requirement 8 AC5)."""

    declared: Tuple[str, ...]
    missing: Tuple[str, ...]

    @property
    def status(self) -> str:
        return deltaschema.INPUT_DECLARATION_STATUSES[0]


@dataclass(frozen=True)
class FindingDeltaResult:
    """The analyzed Finding Delta. The state fields follow from the content."""

    entries: Tuple[DeltaEntry, ...]
    report_integrity: ReportIntegrity
    input_declarations: InputDeclarations
    template_report_correspondence: str
    comparable: bool

    @property
    def analysis_state(self) -> str:
        return "analyzed"

    @property
    def observation(self) -> str:
        for entry in self.entries:
            if entry.observation != "matched" or entry.changes:
                return "changes_observed"
        return "no_changes_observed"

    @property
    def classification_completeness(self) -> str:
        decided = ("New", "Resolved", "Unchanged")
        return "complete" if all(e.classification in decided for e in self.entries) else "partial"

    @property
    def report_authenticity(self) -> str:
        return deltaschema.REPORT_AUTHENTICITY

    @property
    def unverified_assumptions(self) -> Tuple[str, ...]:
        """Always the full set, whatever was declared (Requirement 8 AC3)."""
        return deltaschema.UNVERIFIED_ASSUMPTIONS


# ---------------------------------------------------------------------------
# Matching (Design 6-2)
# ---------------------------------------------------------------------------


def _ordered(codes: Iterable[str], order: Sequence[str]) -> Tuple[str, ...]:
    present = set(codes)
    return tuple(code for code in order if code in present)


def required_declarations(correspondence: str) -> Tuple[str, ...]:
    """Declarations New / Resolved need (Requirement 8 AC4)."""
    if correspondence == _NOT_APPLICABLE:
        return REPORT_DECLARATIONS
    return REPORT_DECLARATIONS + (TEMPLATE_DECLARATION,)


def _evidence_deltas(
    present: Sequence[EvidenceKey],
    other: Sequence[EvidenceKey],
    file: str,
    base: CheckedReport,
    head: CheckedReport,
) -> Tuple[EvidenceDelta, ...]:
    """Elements of ``present`` missing from ``other``, counted as a multiset."""
    missing = Counter(present) - Counter(other)
    deltas: List[EvidenceDelta] = []
    for element in sorted(missing, key=EvidenceKey.sort_key):
        comparable = not comparable_reasons(element.Source, file, base, head)
        deltas.extend(
            EvidenceDelta(element.Source, element.RuleId, comparable) for _ in range(missing[element])
        )
    return tuple(deltas)


def _matched(
    stage: int,
    left: FindingProjection,
    right: FindingProjection,
    base: CheckedReport,
    head: CheckedReport,
) -> DeltaEntry:
    differs = {
        "Severity": left.Severity != right.Severity,
        "FindingType": left.FindingType != right.FindingType,
        "Confidence": left.Confidence != right.Confidence,
        "Source": left.Source != right.Source,
        "Location.TemplatePath": left.TemplatePath != right.TemplatePath,
        "Evidence": Counter(left.Evidence) != Counter(right.Evidence),
    }
    return DeltaEntry(
        observation="matched",
        classification="Unchanged",
        reasons=(),
        missing_declarations=(),
        key=left.key,
        match_stage=stage,
        base=left,
        head=right,
        changes=tuple(name for name in CHANGE_FIELDS if differs[name]),
        evidence_absent_in_head=_evidence_deltas(left.Evidence, right.Evidence, left.File, base, head),
        evidence_absent_in_base=_evidence_deltas(right.Evidence, left.Evidence, left.File, base, head),
    )


def _one_sided(
    observation: str,
    classification: str,
    reasons: Iterable[str],
    missing: Iterable[str],
    projection: FindingProjection,
    is_head: bool,
) -> DeltaEntry:
    return DeltaEntry(
        observation=observation,
        classification=classification,
        reasons=_ordered(reasons, deltaschema.AMBIGUOUS_REASONS + deltaschema.UNCONFIRMED_REASONS),
        missing_declarations=_ordered(missing, deltaschema.DECLARATION_CODES),
        key=projection.key,
        match_stage=None,
        base=None if is_head else projection,
        head=projection if is_head else None,
        changes=(),
        evidence_absent_in_head=(),
        evidence_absent_in_base=(),
    )


class _Classifier:
    """The judgement table of Design 7-1 for one comparison."""

    def __init__(
        self,
        base: CheckedReport,
        head: CheckedReport,
        declarations: FrozenSet[str],
        correspondence: str,
        rename_hints: FrozenSet[str],
    ) -> None:
        self._base = base
        self._head = head
        self._missing = tuple(
            code for code in required_declarations(correspondence) if code not in declarations
        )
        self._integrity_failed = bool(base.integrity_failures or head.integrity_failures)
        self._mismatch = correspondence in _MISMATCHED_CORRESPONDENCE
        self._rename_hints = rename_hints

    def ambiguous_reasons(self, projection: FindingProjection) -> List[str]:
        """Rule 1 of the table: every reason that holds (Requirement 7 AC2)."""
        reasons: List[str] = []
        for source in projection.Source:
            reasons.extend(comparable_reasons(source, projection.File, self._base, self._head))
        if all(source == AGENT_SOURCE for source in projection.Source):
            reasons.append("non_deterministic_source")
        if projection.Resource is not None and projection.Resource in self._rename_hints:
            reasons.append("possible_logical_id_rename")
        if self._integrity_failed:
            reasons.append("report_integrity_failed")
        if self._mismatch:
            reasons.append("template_report_mismatch")
        return reasons

    def classify(self, projection: FindingProjection, is_head: bool) -> DeltaEntry:
        observation = "head_only" if is_head else "base_only"
        reasons = self.ambiguous_reasons(projection)
        if reasons:
            return _one_sided(observation, "Ambiguous", reasons, (), projection, is_head)
        if self._missing:
            return _one_sided(
                observation,
                "Unconfirmed",
                ("input_declaration_absent",),
                self._missing,
                projection,
                is_head,
            )
        return _one_sided(observation, "New" if is_head else "Resolved", (), (), projection, is_head)


def _match_group(
    left: List[FindingProjection],
    right: List[FindingProjection],
    dedup_eligible: bool,
    classifier: _Classifier,
    base: CheckedReport,
    head: CheckedReport,
) -> List[DeltaEntry]:
    """Stages 1 and 2 and the residual rule for one Identity_Key group."""
    if dedup_eligible and len(left) == 1 and len(right) == 1:
        return [_matched(1, left[0], right[0], base, head)]

    entries: List[DeltaEntry] = []
    left_counts = Counter(p.fingerprint for p in left)
    right_counts = Counter(p.fingerprint for p in right)
    # Position of each Fingerprint that occurs once on its side: one pass per
    # side, so the group costs O(n log n) however many Findings share the key.
    left_single = {p.fingerprint: n for n, p in enumerate(left) if left_counts[p.fingerprint] == 1}
    right_single = {p.fingerprint: n for n, p in enumerate(right) if right_counts[p.fingerprint] == 1}
    matched_left: Set[int] = set()
    matched_right: Set[int] = set()
    for print_ in sorted(set(left_single) & set(right_single), key=_sortable):
        i, j = left_single[print_], right_single[print_]
        matched_left.add(i)
        matched_right.add(j)
        entries.append(_matched(2, left[i], right[j], base, head))
    rest_left = [p for n, p in enumerate(left) if n not in matched_left]
    rest_right = [p for n, p in enumerate(right) if n not in matched_right]
    both_sides = bool(rest_left) and bool(rest_right)
    for rest, counts, is_head in ((rest_left, left_counts, False), (rest_right, right_counts, True)):
        for projection in rest:
            reasons: List[str] = []
            if both_sides:
                reasons.append("identity_undetermined")
            if counts[projection.fingerprint] > 1:
                reasons.append("duplicate_fingerprint")
            if reasons:
                entries.append(_one_sided("unmatched", "Ambiguous", reasons, (), projection, is_head))
            else:
                entries.append(classifier.classify(projection, is_head))
    return entries


def match_and_classify(
    base: CheckedReport,
    head: CheckedReport,
    *,
    declarations: FrozenSet[str],
    correspondence: str,
    rename_hints: FrozenSet[str] = frozenset(),
) -> FindingDeltaResult:
    """Match and classify every Finding of two checked Reports (Design 6-2, 7-1).

    Args:
        base: The checked Base Report.
        head: The checked Head Report.
        declarations: Input_Declaration codes the user gave.
        correspondence: The ``template_report_correspondence`` value;
            ``not_applicable`` means there is no Template_Pair.
        rename_hints: Logical IDs the Semantic Diff marked with
            ``possible_logical_id_rename``.

    Returns:
        The :class:`FindingDeltaResult`. Every Finding of both Reports appears
        in exactly one entry. Entries are in a fixed order derived from their
        content, independent of input order.

    Raises:
        ValueError: An unknown declaration or correspondence value.
    """
    unknown = set(declarations) - set(deltaschema.DECLARATION_CODES)
    if unknown:
        raise ValueError("unknown declaration code")
    if correspondence not in deltaschema.TEMPLATE_REPORT_CORRESPONDENCE:
        raise ValueError("unknown correspondence value")

    classifier = _Classifier(base, head, frozenset(declarations), correspondence, rename_hints)
    groups: Dict[IdentityKey, Tuple[List[FindingProjection], List[FindingProjection]]] = {}
    eligible: Dict[IdentityKey, bool] = {}
    for findings, index in ((base.findings, 0), (head.findings, 1)):
        for f in findings:
            projection = project(f)
            groups.setdefault(projection.key, ([], []))[index].append(projection)
            # Eligibility depends on Identity_Key fields only, so one Finding
            # of the group decides it for all.
            eligible[projection.key] = is_dedup_eligible(f)

    entries: List[DeltaEntry] = []
    for key in sorted(groups, key=IdentityKey.sort_key):
        left, right = groups[key]
        left.sort(key=lambda p: (_sortable(p.fingerprint), p.ID))
        right.sort(key=lambda p: (_sortable(p.fingerprint), p.ID))
        entries.extend(_match_group(left, right, eligible[key], classifier, base, head))
    entries.sort(key=DeltaEntry.sort_key)

    required = required_declarations(correspondence)
    return FindingDeltaResult(
        entries=tuple(entries),
        report_integrity=ReportIntegrity(base.integrity_failures, head.integrity_failures),
        input_declarations=InputDeclarations(
            declared=_ordered(declarations, deltaschema.DECLARATION_CODES),
            missing=tuple(code for code in required if code not in declarations),
        ),
        template_report_correspondence=correspondence,
        comparable=summary_comparable(base, head),
    )
