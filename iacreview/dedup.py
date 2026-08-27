"""Consolidation of equivalent Findings into one entry per real issue.

Four Sources review the same Template independently, so one misconfiguration
routinely produces several Findings. Requirement 14 AC5 defines when two of them
are the same issue -- same resource logical ID *and* same ``Normalized_Category``
-- and AC8-AC13 define what the merged entry says. This module is that
definition, and nothing else: it neither sorts nor assigns IDs, both of which
belong to :mod:`iacreview.report` (Requirement 7 AC1, AC15).

:func:`dedup_key`
    The equivalence key, or ``None`` for a Finding that matches nothing.

:func:`deduplicate`
    The whole operation: group, merge, return.

Five things are worth knowing before reading the code.

**The key is deliberately coarse.** ``(Resource, Normalized_Category)`` means
cfn-lint's "invalid IAM action name" and IAM Review's "Action ``*`` on Resource
``*``" merge into one entry when they land on the same role, even though they are
different problems. design.md records this as intended: all Evidence survives, so
nothing is lost except the count. The consequence for a reader -- one Finding is
one resource x one category, not one root cause -- is what
``docs/finding-schema.md`` and ``benchmark/README.md`` have to state, because the
benchmark's expected Finding counts are only meaningful at this granularity
(Requirement 11 AC3).

**Two Findings that match nothing still differ from each other.** ``Other``
means "mapped to nothing in the closed set", so two ``Other`` Findings on one
resource have no shared subject (Requirement 14 AC3); a Finding with no
``Resource`` is template-level and has no key to match on (Requirement 14 AC6,
design.md [Correction] C-5). Both cases return ``None`` from :func:`dedup_key`
and pass through untouched. The predicate itself lives in
:func:`iacreview.finding.is_dedup_eligible`, next to the ``validate`` rule that
enforces it, so the exclusion has one definition.

**Merging is order-independent, and that is a property, not an accident.**
Requirement 16 AC11 wants byte-identical reports, and the Sources' Findings reach
this module in whatever order the orchestrator happened to run them. So every
choice made here is a function of the group's *contents*: groups are processed in
``sorted(groups)`` order, and within a group the Findings are put in a total
order before anything reads "the first one". design.md's tie-breaker is
``(Source order, Finding text)``; :func:`_order_key` appends the Finding's own
canonical JSON as a last resort, because checkpoint 12 turned up a real group of
11 IAM Review Findings on one resource -- one per detector, all the same Source,
all the same ``TemplatePath`` -- and two of those could in principle share a
description while differing elsewhere. The extra component never changes the
outcome in a case the design's two components already decide.

**``Confidence`` is capped, not just maximized.** Requirement 14 AC9 takes the
maximum and AC12 takes the Source union; applied together to a ``Confirmed``
deterministic Finding and a ``Likely`` agent Finding, they produce ``Confirmed``
with ``Agent Review`` in ``Source``, which Requirement 7 AC10 forbids and
:func:`iacreview.finding.validate` rejects. The maximum is therefore taken as
AC9 says and then capped at :data:`~iacreview.finding.AGENT_MAX_CONFIDENCE` when
the union contains :data:`~iacreview.finding.AGENT_SOURCE`. design.md's worked
example showed the illegal combination and is corrected there as [Correction]
C-8. The schema constraint is not weakened: a claim resting partly on agent
reasoning does not get to call itself confirmed, and the deterministic Evidence
that justified ``Confirmed`` is still in the merged entry for a reader to weigh.

**Merged Findings carry ``ID`` = 0.** :data:`~iacreview.finding.UNASSIGNED_ID`,
because IDs are sequential over the *sorted* report and sorting has not happened
yet. A merged Finding therefore does not pass ``validate`` until
:mod:`iacreview.report` numbers it; that is the intended lifecycle, described in
``finding``'s module docstring.
"""

from __future__ import annotations

import json
from typing import Dict, List, Optional, Sequence, Tuple

from iacreview.finding import (
    AGENT_MAX_CONFIDENCE,
    AGENT_SOURCE,
    CONFIDENCE_ORDER,
    FINDING_TYPE_ORDER,
    SEVERITY_ORDER,
    SOURCE_ORDER,
    UNASSIGNED_ID,
    Evidence,
    Finding,
    is_dedup_eligible,
    sorted_sources,
    to_dict,
)

__all__ = [
    "DedupKey",
    "dedup_key",
    "deduplicate",
]

# design.md pseudocode names for the four orderings. Same objects as the
# definitions in :mod:`iacreview.finding`, so the pseudocode transcribes
# literally without introducing a second copy of any ranking.
_SEV_ORDER = SEVERITY_ORDER
_CONF_ORDER = CONFIDENCE_ORDER
_TYPE_ORDER = FINDING_TYPE_ORDER
_SOURCE_ORDER = SOURCE_ORDER

#: The equivalence key of Requirement 14 AC5: ``(Resource, Normalized_Category)``.
DedupKey = Tuple[str, str]


# ---------------------------------------------------------------------------
# Equivalence
# ---------------------------------------------------------------------------


def dedup_key(f: Finding) -> Optional[DedupKey]:
    """Return the key ``f`` is matched on, or ``None`` if it matches nothing.

    Args:
        f: Any Finding. Not validated: ``dedup`` runs on Source output that has
            already been through its Source's own checks.

    Returns:
        ``(Resource, Normalized_Category)`` (Requirement 14 AC5), or ``None``
        when ``f`` is excluded from matching -- ``Normalized_Category`` is
        ``Other`` (Requirement 14 AC3) or ``Resource`` is ``None``
        (Requirement 14 AC6). A ``None`` key means the Finding reaches the report
        unmodified (Requirement 14 AC13); in particular ``None`` does not match
        another ``None``.
    """
    # The local Resource check exists only to bind a non-optional name for the
    # key; the exclusion rule itself stays defined once, in is_dedup_eligible.
    resource = f.Resource
    if resource is None or not is_dedup_eligible(f):
        return None
    return (resource, f.Normalized_Category)


# ---------------------------------------------------------------------------
# Deterministic ordering within a group
# ---------------------------------------------------------------------------


def _primary_source(f: Finding) -> str:
    """The Source that speaks for ``f`` when Sources are ranked.

    ``Source`` is kept in :data:`~iacreview.finding.SOURCE_ORDER` order by the
    schema, so the first entry is the highest-ranked one. For the single-Source
    Findings a Source produces this is simply that Source; for an already-merged
    Finding it is the most deterministic Source that detected it, which is the
    same thing the ranking is for.
    """
    return f.Source[0]


def _canonical_form(f: Finding) -> str:
    """A total-order tie-breaker: ``f``'s content as one canonical string.

    Only reached when two Findings in a group share a Source rank *and* a
    description. Two Findings with equal canonical forms are indistinguishable,
    so their relative order cannot affect the merged result -- which is exactly
    what makes this a sufficient last component (see the module docstring).
    """
    return json.dumps(
        to_dict(f), sort_keys=True, ensure_ascii=False, separators=(",", ":")
    )


def _order_key(f: Finding) -> Tuple[int, str, str]:
    """Sort key placing a group's Findings in a content-determined total order.

    design.md specifies the first two components: Source rank, then the
    description. The third is the safety net described in the module docstring.
    """
    return (_SOURCE_ORDER[_primary_source(f)], f.Finding, _canonical_form(f))


def _location_primary(ordered: Sequence[Finding]) -> Finding:
    """The Finding whose ``Location`` the merged entry adopts.

    One ``Location`` has to be chosen, and the most useful one is the most
    precise: a ``Line`` makes the Finding clickable in an editor, and only
    cfn-lint reports one (cfn-guard leaves it ``null`` by design, IAM Review
    works on the parsed document). Failing that, the first Finding in
    ``ordered``, which is the highest-ranked Source's.

    Requirement 14 does not legislate ``Location``; this is the design judgement
    recorded in design.md's merge table.
    """
    for f in ordered:
        if f.Location.Line is not None:
            return f
    return ordered[0]


# ---------------------------------------------------------------------------
# Field-by-field merge (design.md merge table, Requirement 14 AC8-AC12)
# ---------------------------------------------------------------------------


def _merged_evidence(ordered: Sequence[Finding]) -> List[Evidence]:
    """Every Source's Evidence, concatenated in Source order (AC11).

    ``sorted`` is stable, so entries sharing a Source keep the order they had in
    the concatenation, which for single-Source inputs is their order inside their
    own Finding. Sorting the concatenation rather than each Finding separately
    also gives the right answer when an input Finding carries Evidence from more
    than one Source, which an already-merged Finding does.
    """
    concatenated = [entry for f in ordered for entry in f.Evidence]
    return sorted(concatenated, key=lambda entry: _SOURCE_ORDER[entry.Source])


def _merged_confidence(ordered: Sequence[Finding], sources: Sequence[str]) -> str:
    """The maximum Confidence (AC9), capped for agent involvement (AC10).

    See the module docstring for why the cap exists and why the schema rule it
    protects is not relaxed instead. ``Contextual`` is already below the ceiling
    and passes through, so the cap only ever weakens a ``Confirmed``.
    """
    highest = max(ordered, key=lambda f: _CONF_ORDER[f.Confidence]).Confidence
    if AGENT_SOURCE not in sources:
        return highest
    if _CONF_ORDER[highest] <= _CONF_ORDER[AGENT_MAX_CONFIDENCE]:
        return highest
    return AGENT_MAX_CONFIDENCE


def _merge_group(group: Sequence[Finding]) -> Finding:
    """Merge two or more equivalent Findings into one (Requirement 14 AC7).

    Args:
        group: Findings sharing a :func:`dedup_key`, in any order. Two or more;
            a group of one is returned untouched by :func:`deduplicate` and
            never reaches here.

    Returns:
        One Finding carrying the strongest classification and every Source's
        Evidence, with ``ID`` = :data:`~iacreview.finding.UNASSIGNED_ID`.

    Note:
        ``max()`` returns the *first* maximal element, so every use of it below
        resolves ties by ``ordered``'s position -- which is content-determined,
        making the whole function independent of ``group``'s order.
    """
    ordered = sorted(group, key=_order_key)
    primary = _location_primary(ordered)
    representative = ordered[0]
    sources = sorted_sources(source for f in ordered for source in f.Source)
    return Finding(
        ID=UNASSIGNED_ID,
        # Both are part of the equivalence key, so every member agrees.
        Normalized_Category=representative.Normalized_Category,
        Resource=representative.Resource,
        FindingType=max(ordered, key=lambda f: _TYPE_ORDER[f.FindingType]).FindingType,
        Severity=max(ordered, key=lambda f: _SEV_ORDER[f.Severity]).Severity,
        Confidence=_merged_confidence(ordered, sources),
        Source=sources,
        Location=primary.Location,
        # One Source's wording represents the merged entry, and it is the
        # highest-ranked Source's: deterministic phrasing over agent phrasing,
        # which also keeps the text byte-stable (Requirement 16 AC11). The three
        # fields are taken from the same Finding so the description, its
        # rationale and its advice stay consistent with each other.
        Finding=representative.Finding,
        WhyItMatters=representative.WhyItMatters,
        Recommendation=representative.Recommendation,
        Evidence=_merged_evidence(ordered),
        SuggestedRemediation=next(
            (f.SuggestedRemediation for f in ordered if f.SuggestedRemediation is not None),
            None,
        ),
    )


# ---------------------------------------------------------------------------
# The operation
# ---------------------------------------------------------------------------


def deduplicate(findings: Sequence[Finding]) -> List[Finding]:
    """Consolidate equivalent Findings (Requirement 14 AC5-AC13).

    Args:
        findings: Findings from every Source, in any order.

    Returns:
        A new list: one entry per :func:`dedup_key`, followed by every Finding
        that matches nothing. A Finding alone in its group, and a Finding with no
        key, are the same objects that came in (Requirement 14 AC13); merged
        entries are new Findings with ``ID`` =
        :data:`~iacreview.finding.UNASSIGNED_ID`.

        The order is a function of the input's *contents*, not its sequence, so
        two permutations of one input produce the same list. Report order is
        decided later, by ``report.sort_findings``.

    Note:
        Idempotent: re-running on the output changes nothing, because each key is
        then held by exactly one Finding and single-Finding groups are passed
        through rather than re-merged.
    """
    groups: Dict[DedupKey, List[Finding]] = {}
    unmatched: List[Finding] = []
    for f in findings:
        key = dedup_key(f)
        if key is None:
            unmatched.append(f)
        else:
            groups.setdefault(key, []).append(f)

    merged: List[Finding] = []
    for key in sorted(groups):  # Deterministic group processing order.
        group = groups[key]
        if len(group) == 1:
            merged.append(group[0])  # Requirement 14 AC13: unmodified.
            continue
        merged.append(_merge_group(group))

    # design.md writes ``merged + singles`` with the unmatched Findings left in
    # input order. Sorting them by the same content-determined key instead is
    # what makes the *whole* returned list permutation-invariant: report sorting
    # is stable, so two unmatched Findings that tie on every report sort key
    # would otherwise reach the report in an order that depended on which Source
    # ran first.
    return merged + sorted(unmatched, key=_order_key)
