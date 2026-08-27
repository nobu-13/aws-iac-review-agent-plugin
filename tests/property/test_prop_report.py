"""Properties 12 and 13: the order of a report and the arithmetic of its summary.

``tests/unit/test_report.py`` pins both claims on Findings written by hand:
``test_findings_are_ordered_by_severity_descending``,
``test_equal_severity_is_ordered_by_resource_ascending`` and
``test_a_resourceless_finding_leads_its_severity_run`` walk the ordering key one
component at a time, and ``test_summary_totals_match_the_findings_array``,
``test_summary_counts_each_group_exactly`` and
``test_by_source_sums_above_total_for_a_merged_finding`` do the same for the
counters. Those cases are readable: a reviewer can see the expected sequence in
the source. What they cannot say is that the order and the counts hold for
*whatever* the four Sources produced, which is what a report consumer relies on
when it reads the first entry as the most urgent one and the summary as a count
of the array below it. That universal statement is what the two tests here add.

**One pipeline, two questions.** Both tests run
``deduplicate`` then :func:`iacreview.report.build_report` and assert on the
serialized report, not on the ``Finding`` objects it was built from: the ordering
and the counters are claims about what a consumer reads. Dedup is in the path
because ``build_report``'s input is by contract a deduplicated list, and because a
merged entry is where the two properties get their teeth: it raises a Finding's
Severity to the maximum of its inputs, which is what decides where the entry lands
in the order, and it unions their ``Source`` lists, which is what makes
``by_source`` count one Finding twice.

**What the generated space reaches.** Measured over 400 draws of
:func:`_report_inputs` (``@seed(20250826)``, the seed the smoke tests use):

* 84% of reports hold at least one Finding; an empty report satisfies both
  properties trivially, and is a legal review outcome that has to stay in the
  space.
* 60% hold at least one adjacent pair of equal Severity, so Property 12's second
  clause is checked rather than skipped, and 54% hold such a pair whose two
  ``Resource`` values differ -- the pairs that would catch a broken logical-ID
  comparison rather than pass on a tie.
* 41% hold a ``Resource``-less Finding somewhere other than the head of the
  array, which is the ``None``-reads-as-``""`` substitution applied inside a
  Severity run rather than trivially at the top.
* 72% hold a Finding whose ``Source`` list has two or more entries, so
  ``by_source`` sums above ``total`` on nearly three draws in four; Property 13
  states that inequality rather than the equality the other two counters satisfy.
* 28% count Findings under both keys of ``by_template_group``, and 36% carry at
  least one StructuredError alongside their Findings.

**by_source does not conserve, and that is the point.** Requirement 14 AC12 makes
one merged Finding a member of two Sources' counts, so
``sum(by_source.values())`` exceeds ``total`` exactly when some Finding names more
than one Source. Property 13 therefore states ``by_source`` per source name
instead of as a sum, and the test asserts the inequality *and* the condition for
equality, so a report that quietly counted a merged Finding once would fail here.
``by_finding_type`` and ``by_severity`` do conserve: those fields hold one value
each.

Severity ranking comes from :data:`iacreview.finding.SEVERITY_ORDER` and the
vocabularies from :mod:`iacreview.finding`, so nothing here restates an ordering
that ``report`` and ``dedup`` share; ``"CRITICAL"`` appears in neither test.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Dict, List, Tuple

from hypothesis import given, settings
from hypothesis import strategies as st

import strategies as S
from iacreview.dedup import deduplicate
from iacreview.finding import (
    FINDING_TYPES,
    SEVERITIES,
    SEVERITY_ORDER,
    SOURCES,
    Finding,
)
from iacreview.report import SUMMARY_KEYS, TEMPLATE_GROUPS, ReportMeta, build_report

#: ``Resource`` value the report order substitutes for a template-level Finding's
#: ``None`` (design.md's sort key, and Property 12's "null treated as the empty
#: string"). Named rather than left as a bare ``""`` in :func:`_resource_key`,
#: where it would read as a fallback for missing data rather than as the value the
#: order is defined to compare.
NO_RESOURCE = ""


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------


def _at_file(f: Finding, file_name: str) -> Finding:
    """``f`` relocated to ``file_name``, without touching the input Finding."""
    return replace(f, Location=replace(f.Location, File=file_name))


@st.composite
def _one_severity_pair(draw: Any) -> List[Finding]:
    """Two Findings of one Severity on two different resources.

    Property 12's second clause is about a run of equal Severity, and a run needs
    two Findings that tie. A plain ``finding_lists()`` draw ties on Severity often
    enough to reach the clause but not often enough to make it the common case (see
    the module docstring for the measured rate), so this pair is appended to half
    the examples.

    The second member is a copy of the first with a different ``Resource``, which
    is how the shared Severity is arranged without touching it: setting a Severity
    could raise a Finding to ``CRITICAL`` without the deployment-blocking rule ID
    Requirement 7 AC6 asks for, and ``build_report`` would reject the Finding
    rather than order it. ``None`` is among the replacement values, so the pair
    also reaches the case where the ``""`` substitution is compared against a real
    logical ID *inside* a Severity run rather than at the head of the array.
    """
    resources = tuple(name for name in S.RESOURCE_POOL if name is not None)
    first = draw(S.findings(resource=st.sampled_from(resources)))
    second = draw(
        st.sampled_from(tuple(name for name in S.RESOURCE_POOL if name != first.Resource))
    )
    return [first, replace(first, Resource=second)]


@st.composite
def _report_inputs(draw: Any) -> Tuple[List[Finding], List[Dict[str, Any]], ReportMeta]:
    """Everything :func:`iacreview.report.build_report` takes, in one draw.

    Four additions to a plain ``finding_lists()`` draw, each for a case one of
    the two properties would otherwise reach rarely or never:

    A ``mergeable_finding_groups()`` draw is appended to half the examples.
    ``finding_lists()`` alone collides on the dedup key often enough to merge
    sometimes; the appended group shares one non-``Other`` category and one
    non-null ``Resource``, so it always merges. Merged entries are what give
    ``by_source`` a value above one and what shorten the array a Severity run is
    read from.

    A :func:`_one_severity_pair` draw is appended to half the examples, for the
    Severity run Property 12's second clause reads.

    Some Findings are relocated to the Template ``report_metas()`` listed as
    synthesized. ``strategies`` draws ``Location.File`` from
    :data:`strategies.TEMPLATE_FILES` and the synthesized Template from a
    different pool, so without this step every Finding would be counted as
    ``standalone`` and ``by_template_group`` would be a constant. The path is read
    off the drawn :class:`~iacreview.report.ReportMeta` rather than written here,
    so the two cannot disagree about the spelling of the file.

    StructuredErrors are drawn too. Neither property mentions them, which is the
    reason to include them: ``summary`` must count Findings and nothing else, and
    ``passed_all_checks`` must describe the ``findings`` array whether or not a
    Source failed (Requirement 7 AC16).
    """
    meta = draw(S.report_metas())
    items: List[Finding] = list(draw(S.finding_lists()))
    if draw(st.booleans()):
        items += list(draw(S.mergeable_finding_groups()))
    if draw(st.booleans()):
        items += draw(_one_severity_pair())

    synthesized = list(meta.synthesized_templates)
    if synthesized and items:
        relocate = draw(
            st.lists(st.booleans(), min_size=len(items), max_size=len(items)),
            label="relocate to the synthesized template",
        )
        items = [
            _at_file(f, str(synthesized[0])) if flag else f
            for f, flag in zip(items, relocate)
        ]

    structured = draw(st.lists(S.structured_errors(), max_size=2))
    return items, structured, meta


def _review_report(
    items: List[Finding], structured: List[Dict[str, Any]], meta: ReportMeta
) -> Dict[str, Any]:
    """The report the deterministic pipeline produces from one drawn example."""
    return build_report(deduplicate(items), structured, meta)


def _resource_key(payload: Dict[str, Any]) -> str:
    """The ``Resource`` component of the report order, with ``None`` as ``""``.

    The substitution cannot collide with a real logical ID: a ``Resource`` that is
    present is a non-empty string, which ``iacreview.finding.validate`` enforces
    and ``build_report`` has already checked by the time a report exists.
    """
    return payload["Resource"] or NO_RESOURCE


# ---------------------------------------------------------------------------
# Property 12
# ---------------------------------------------------------------------------


# Feature: aws-iac-review-agent-plugin, Property 12: Report ordering
#
# *For any* Review_Report, every adjacent pair of Findings in the `findings`
# array is non-increasing in `Severity` rank, and within any run of equal
# `Severity` the sequence of `Resource` values (with null treated as the empty
# string) is non-decreasing in ascending alphabetical order.
#
# Validates: Requirements 7.15
@settings(max_examples=100)
@given(_report_inputs())
def test_property_12_report_findings_are_ordered_by_severity_then_resource(
    example: Tuple[List[Finding], List[Dict[str, Any]], ReportMeta]
) -> None:
    """Both clauses, over adjacent pairs of the serialized ``findings`` array.

    Adjacent pairs are the whole statement: "non-increasing in Severity rank" over
    every adjacent pair is transitively the descending order of Requirement 7
    AC15, and a run of equal Severity is a maximal stretch of pairs whose ranks
    are equal, so the second clause reduces to the ``Resource`` comparison inside
    exactly those pairs. Iterating pairs rather than reconstructing runs keeps the
    test from re-implementing the grouping that ``sort_findings`` performs.

    Rank comes from :data:`~iacreview.finding.SEVERITY_ORDER`, the object
    ``report`` sorts by and ``dedup`` takes its maxima under. Comparing the
    Severity *strings* would need a second copy of the ranking, and a report
    ordered by a ranking the merge step disagreed with would still pass.

    The array is asserted to be a permutation of the deduplicated input, so an
    implementation that produced a correctly ordered *subset* -- dropping the
    Findings it could not place -- fails here rather than reading as sorted.
    """
    items, structured, meta = example

    report = _review_report(items, structured, meta)
    payloads = report["findings"]

    assert len(payloads) == len(deduplicate(items))

    for previous, current in zip(payloads, payloads[1:]):
        previous_rank = SEVERITY_ORDER[previous["Severity"]]
        current_rank = SEVERITY_ORDER[current["Severity"]]
        assert previous_rank >= current_rank, (previous, current)
        if previous_rank == current_rank:
            assert _resource_key(previous) <= _resource_key(current), (previous, current)


# ---------------------------------------------------------------------------
# Property 13
# ---------------------------------------------------------------------------


# Feature: aws-iac-review-agent-plugin, Property 13: Summary conservation
#
# *For any* Review_Report, the sum of the values in `summary.by_finding_type`
# equals `summary.total`, the sum of the values in `summary.by_severity` equals
# `summary.total`, `summary.total` equals the length of the `findings` array, and
# for every source name `s`, `summary.by_source[s]` equals the number of Findings
# whose `Source` list contains `s`.
#
# Validates: Requirements 7.17
@settings(max_examples=100)
@given(_report_inputs())
def test_property_13_summary_counts_conserve_the_findings_array(
    example: Tuple[List[Finding], List[Dict[str, Any]], ReportMeta]
) -> None:
    """The four clauses, over the key sets that give the sums their meaning.

    The key sets are asserted first. A sum over ``by_severity.values()`` only says
    what the property means if the keys are the closed vocabulary: a report that
    counted two Findings under a sixth, invented Severity would still satisfy "the
    values sum to ``total``" while telling a consumer that indexes
    :data:`~iacreview.finding.SEVERITIES` it had none.

    ``by_source`` is stated per source name because it does not conserve --
    Requirement 14 AC12 counts a merged Finding under each Source that detected
    it. The inequality and its equality condition are both asserted, so neither a
    report that lost a Source from a merged Finding's count nor one that counted
    every Finding once regardless would pass.

    Two counters the property does not name are checked as the same conservation
    claim rather than as new properties. ``by_template_group`` partitions the
    array by Template origin (Requirement 8 AC10) and so must sum to ``total``.
    ``passed_all_checks`` is the summary's one-bit answer for the same array, and
    the generated example carries StructuredErrors: the equivalence asserted here
    is with an empty ``findings`` array alone, which is what Requirement 7 AC16
    says and the reason a run whose Sources all failed does not claim the Template
    is clean.
    """
    items, structured, meta = example

    report = _review_report(items, structured, meta)
    payloads = report["findings"]
    summary = report["summary"]
    total = summary["total"]

    assert set(summary) == set(SUMMARY_KEYS)
    assert set(summary["by_finding_type"]) == set(FINDING_TYPES)
    assert set(summary["by_severity"]) == set(SEVERITIES)
    assert set(summary["by_source"]) == set(SOURCES)
    assert set(summary["by_template_group"]) == set(TEMPLATE_GROUPS)

    assert total == len(payloads)
    assert sum(summary["by_finding_type"].values()) == total
    assert sum(summary["by_severity"].values()) == total

    for name in SOURCES:
        detected_by = [payload for payload in payloads if name in payload["Source"]]
        assert summary["by_source"][name] == len(detected_by)

    source_total = sum(summary["by_source"].values())
    single_source = all(len(payload["Source"]) == 1 for payload in payloads)
    assert source_total >= total
    assert (source_total == total) is single_source

    assert sum(summary["by_template_group"].values()) == total
    assert summary["passed_all_checks"] is (total == 0)
