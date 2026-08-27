"""Property 5: the join laws of :func:`iacreview.dedup.deduplicate`'s merge.

Requirement 14 AC8-AC12 describe a merge as five independent joins over one
group of equivalent Findings: a maximum on ``Severity``, a maximum on
``Confidence``, a precedence maximum on ``FindingType``, a union on ``Source``,
and a Source-ordered concatenation on ``Evidence``. ``tests/unit/test_dedup.py``
pins each of them on design.md's worked example and on hand-built groups; this
file asserts the same five laws over every group the generators can produce, in
one test, as design.md's Correctness Properties section specifies (1 property =
1 test function).

**The cap is part of law 2, not an exception to it.** design.md
[Correction] C-8: AC9's maximum together with AC12's union would let a
``Confirmed`` deterministic Finding and a ``Likely`` agent Finding merge into a
``Confirmed`` Finding whose ``Source`` names ``Agent Review``, which
Requirement 7 AC10 forbids and :func:`iacreview.finding.validate` rejects. The
merge therefore takes the maximum and then caps it at
:data:`iacreview.finding.AGENT_MAX_CONFIDENCE` when the union contains the agent.
:func:`_assert_confidence_is_the_capped_maximum` states the law in that form. An
unconditional maximum is not what the implementation provides and asserting it
would fail; dropping the maximum and asserting only "some legal Confidence"
would make the law vacuous.

Because the cap is conditional, one drawn group only exercises one branch of it.
The test therefore draws three groups per example -- an unconstrained one, one no
agent contributed to, and one where a ``Confirmed`` deterministic Finding meets
an agent Finding -- and checks all five laws on each. The last two are the two
branches, and the test asserts that the third really is the branch where the cap
changes the answer, so a generator drifting away from that shape shows up as a
failure rather than as silent loss of coverage.

The orderings the laws are stated in terms of are imported from
:mod:`iacreview.finding`; ``tests/property/`` restates no vocabulary.
"""

from __future__ import annotations

from typing import Any, Dict, List, Sequence

from hypothesis import given, settings
from hypothesis import strategies as st

import strategies as S
from iacreview.dedup import deduplicate
from iacreview.finding import (
    AGENT_MAX_CONFIDENCE,
    AGENT_SOURCE,
    CONFIDENCE_ORDER,
    CONFIRMED,
    FINDING_TYPE_ORDER,
    OTHER_CATEGORY,
    SEVERITY_ORDER,
    SOURCE_ORDER,
    Finding,
    sorted_sources,
)

# ---------------------------------------------------------------------------
# Groups with a controlled Source union
# ---------------------------------------------------------------------------


def _has_agent(f: Finding) -> bool:
    """Whether ``Agent Review`` is among ``f``'s Sources."""
    return AGENT_SOURCE in f.Source


def _members(draw: Any) -> st.SearchStrategy[Finding]:
    """Findings that all share one dedup key (Requirement 14 AC5).

    One non-``Other`` ``Normalized_Category`` and one non-null ``Resource``,
    drawn once and then fixed -- the same key
    :func:`strategies.mergeable_finding_groups` fixes, so the two forced variants
    below draw from the same space as the unconstrained group.
    """
    category = S.categories_pool().filter(lambda name: name != OTHER_CATEGORY)
    resource = st.sampled_from(
        tuple(name for name in S.RESOURCE_POOL if name is not None)
    )
    return S.findings(
        resource=st.just(draw(resource)), category=st.just(draw(category))
    )


@st.composite
def _agent_free_groups(draw: Any) -> List[Finding]:
    """A mergeable group no agent contributed to: law 2 without the cap.

    Each member is filtered individually rather than filtering whole groups,
    which would reject most of what it draws once a group holds four Findings.
    """
    deterministic = _members(draw).filter(lambda f: not _has_agent(f))
    return draw(st.lists(deterministic, min_size=2, max_size=4))


@st.composite
def _mixed_groups(draw: Any) -> List[Finding]:
    """A mergeable group in which the cap of law 2 changes the answer.

    A deterministic Finding is ``Confirmed`` (Requirement 7 AC9), so a group
    holding one of those and one agent Finding has maximum ``Confidence``
    ``Confirmed`` and a union containing ``Agent Review`` -- exactly the
    combination [Correction] C-8 exists for. The remaining members are
    unconstrained, so the case covers groups of two to four.
    """
    member = _members(draw)
    return [
        draw(member.filter(lambda f: not _has_agent(f))),
        draw(member.filter(_has_agent)),
    ] + draw(st.lists(member, max_size=2))


# ---------------------------------------------------------------------------
# The five laws
# ---------------------------------------------------------------------------


def _merge_of(group: Sequence[Finding]) -> Finding:
    """The single Finding ``group`` merges into.

    Every member shares a dedup key, so ``deduplicate`` returns one entry. The
    unpacking is how the merged Finding is obtained; that a mergeable group
    yields exactly one is the generators' contract, checked in
    ``test_strategies_smoke.py``.
    """
    (merged,) = deduplicate(list(group))
    return merged


def _highest(group: Sequence[Finding], field: str, order: Dict[str, int]) -> str:
    """The highest value of ``field`` across ``group`` under ``order``."""
    return max((getattr(f, field) for f in group), key=order.__getitem__)


def _assert_severity_is_the_maximum(group: Sequence[Finding], merged: Finding) -> None:
    """Law 1 (Requirement 14 AC8): ``CRITICAL > HIGH > MEDIUM > LOW > INFO``."""
    assert merged.Severity == _highest(group, "Severity", SEVERITY_ORDER)


def _assert_confidence_is_the_capped_maximum(
    group: Sequence[Finding], merged: Finding
) -> None:
    """Law 2 (Requirement 14 AC9), capped by Requirement 7 AC10.

    The maximum under ``Confirmed > Likely > Contextual``, lowered to
    :data:`~iacreview.finding.AGENT_MAX_CONFIDENCE` when the union names the
    agent ([Correction] C-8). The cap is a ceiling, not a replacement: a maximum
    already at or below it passes through, which is why it is expressed as a
    minimum of the two ranks rather than as an assignment.
    """
    expected = _highest(group, "Confidence", CONFIDENCE_ORDER)
    if AGENT_SOURCE in merged.Source:
        expected = min(expected, AGENT_MAX_CONFIDENCE, key=CONFIDENCE_ORDER.__getitem__)
    assert merged.Confidence == expected


def _assert_finding_type_is_the_precedence_maximum(
    group: Sequence[Finding], merged: Finding
) -> None:
    """Law 3 (Requirement 14 AC10): ``Security > Validity > BestPractice > Informational``."""
    assert merged.FindingType == _highest(group, "FindingType", FINDING_TYPE_ORDER)


def _assert_source_is_the_union(group: Sequence[Finding], merged: Finding) -> None:
    """Law 4 (Requirement 14 AC12): every detecting Source, once, in Source order.

    Membership is asserted as a set equality so the law does not depend on the
    helper that produces the order, and the order is asserted separately.
    """
    assert set(merged.Source) == {name for f in group for name in f.Source}
    assert merged.Source == sorted_sources(merged.Source)


def _assert_evidence_source_rank_is_non_decreasing(merged: Finding) -> None:
    """Law 5 (Requirement 14 AC11): ``cfn-lint``, ``cfn-guard``, ``IAM Review``, ``Agent Review``.

    Stated as monotonicity of the rank sequence rather than as an expected list,
    because a group may contribute several Evidence entries per Source and AC11
    constrains only the order between Sources.
    """
    ranks = [SOURCE_ORDER[entry.Source] for entry in merged.Evidence]
    assert ranks == sorted(ranks)


def _assert_join_laws(group: Sequence[Finding]) -> Finding:
    """All five laws on one group. Returns the merged Finding for further checks."""
    merged = _merge_of(group)
    _assert_severity_is_the_maximum(group, merged)
    _assert_confidence_is_the_capped_maximum(group, merged)
    _assert_finding_type_is_the_precedence_maximum(group, merged)
    _assert_source_is_the_union(group, merged)
    _assert_evidence_source_rank_is_non_decreasing(merged)
    return merged


# Feature: aws-iac-review-agent-plugin, Property 5: Merge join laws -- *For any*
# group of two or more Findings sharing the same non-`Other` `Normalized_Category`
# and the same non-null `Resource`, the merged Finding satisfies all of the
# following: its `Severity` equals the maximum input `Severity` under the ordering
# `CRITICAL > HIGH > MEDIUM > LOW > INFO`; its `Confidence` equals the maximum
# input `Confidence` under `Confirmed > Likely > Contextual`; its `FindingType`
# equals the highest-precedence input `FindingType` under
# `Security > Validity > BestPractice > Informational`; its `Source` list equals
# the union of the input `Source` lists; and the sequence of `Evidence[].Source`
# rank values is non-decreasing in the order `cfn-lint`, `cfn-guard`,
# `IAM Review`, `Agent Review`.
@settings(max_examples=100, deadline=None)
@given(
    group=S.mergeable_finding_groups(),
    agent_free_group=_agent_free_groups(),
    mixed_group=_mixed_groups(),
)
def test_merge_join_laws(
    group: List[Finding],
    agent_free_group: List[Finding],
    mixed_group: List[Finding],
) -> None:
    """The five joins of Requirement 14 AC8-AC12, with law 2 capped by C-8.

    **Validates: Requirements 14.8, 14.9, 14.10, 14.11, 14.12**
    """
    _assert_join_laws(group)
    agent_free_merged = _assert_join_laws(agent_free_group)
    mixed_merged = _assert_join_laws(mixed_group)

    # Both branches of law 2's cap are exercised by every example: the first
    # group has no agent in the union, so the maximum stands, and the second has
    # a Confirmed maximum that the cap has to lower. Without these two the cap
    # could go untested on a run where every drawn group happened to be
    # agent-free, and the test would report success anyway.
    assert AGENT_SOURCE not in agent_free_merged.Source
    assert agent_free_merged.Confidence == CONFIRMED
    assert _highest(mixed_group, "Confidence", CONFIDENCE_ORDER) == CONFIRMED
    assert mixed_merged.Confidence == AGENT_MAX_CONFIDENCE
