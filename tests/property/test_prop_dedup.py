"""Properties 3, 4 and 11: the algebra of :func:`iacreview.dedup.deduplicate`.

``tests/unit/test_dedup.py`` pins the three claims on hand-written inputs: the
worked example, a mixed list of 11 Findings shuffled 200 times, and four
parametrized pass-through cases. Those examples say *that* the algorithm behaved
on the inputs a reader can check by eye. The properties here say *why* the report
is stable: whatever Findings the four Sources produce, in whatever order the
orchestrator collected them, re-running dedup changes nothing (Property 3), the
arrival order is invisible (Property 4), and a Finding that matched nothing is
the Finding that came in (Property 11).

The generated space is what makes this more than a repetition of the unit tests.
``strategies.finding_lists()`` draws ``Resource`` from a four-value pool and
``Normalized_Category`` from the closed set, so a list of up to six Findings
collides on the dedup key often enough to reach the merge path without being
steered there, and :func:`_dedup_inputs` raises that rate for the two properties
whose subject is the merge. ``strategies.findings()`` also produces multi-Source
Findings whose Evidence is already in Source order -- indistinguishable from the
output of an earlier merge, which is exactly the input Property 3's second
application receives.
``test_strategies_smoke.py`` asserts that merges do occur and that both
exclusions from matching (``Other``, and ``Resource`` null) are reached, so none
of the three tests below can pass by never taking the path it is about.

Findings are compared through :func:`iacreview.finding.to_dict`: it renders all
13 fields, so the comparison is as strong as dataclass equality, and a
counterexample prints as a dict diff rather than as a ``repr`` of nested
dataclasses.

Vocabularies and the dedup key both come from :mod:`iacreview` -- no test here
restates ``"Other"`` or re-implements ``(Resource, Normalized_Category)``, so a
change to Requirement 14's matching rule surfaces as a failure rather than as two
definitions drifting apart.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from hypothesis import given, settings
from hypothesis import strategies as st

import strategies as S
from iacreview.dedup import DedupKey, dedup_key, deduplicate
from iacreview.finding import Finding, to_dict


def _payloads(items: List[Finding]) -> List[Dict[str, Any]]:
    """``items`` as report-shaped dicts, in list order."""
    return [to_dict(f) for f in items]


def _content_fingerprint(f: Finding) -> str:
    """``f``'s fields except ``ID``, as one canonical string.

    Property 11 excludes ``ID`` because dedup does not own it: numbering happens
    in :func:`iacreview.report.assign_ids`, after sorting. Everything else has to
    survive untouched.

    Canonical JSON rather than the Finding itself, because the fingerprints are
    counted and a Finding holds lists and nested dataclasses. Counting matters:
    two Sources can report identical template-level Findings, and the property has
    to hold for both of them rather than for one representative.
    """
    payload = to_dict(f)
    del payload["ID"]
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _dedup_inputs() -> st.SearchStrategy[List[Finding]]:
    """Lists of schema-valid Findings, half of them guaranteed to merge.

    Both branches are "a list of schema-valid Findings", which is all Properties
    3 and 4 quantify over. The second exists for density. ``finding_lists()``
    alone holds a mergeable pair in roughly one draw in nine, so a 100-example run
    would take the merge path about a dozen times; appending a
    ``mergeable_finding_groups()`` draw -- one shared non-``Other`` category and
    one shared non-null ``Resource``, so it always merges -- raises that to about
    two draws in three while keeping the unmatched Findings that come with a plain
    list in the same example. Both halves of the returned value matter to
    Property 4: the merged entries test the merge operation's commutativity, and
    the unmatched ones test that dedup's own output order does not depend on which
    Source ran first.

    Property 11 uses ``finding_lists()`` directly instead: its subject is the
    Findings that match nothing, and appending a group that always merges would
    only dilute them.
    """
    return st.one_of(
        S.finding_lists(),
        st.builds(
            lambda base, group: list(base) + list(group),
            S.finding_lists(),
            S.mergeable_finding_groups(),
        ),
    )


def _unique_keys(items: List[Finding]) -> Dict[Optional[DedupKey], int]:
    """How many Findings in ``items`` carry each dedup key."""
    counts: Dict[Optional[DedupKey], int] = {}
    for f in items:
        key = dedup_key(f)
        counts[key] = counts.get(key, 0) + 1
    return counts


# Feature: aws-iac-review-agent-plugin, Property 3: *For any* list of schema-valid Findings, applying deduplication twice produces the same result as applying it once: `deduplicate(deduplicate(x)) == deduplicate(x)`.
@settings(max_examples=100)
@given(_dedup_inputs())
def test_deduplication_is_idempotent(items: List[Finding]) -> None:
    """One application reaches the fixed point.

    The second pass is not a no-op by construction: it re-derives every key, and
    a merged entry it produced holds a multi-Source ``Source`` list and
    concatenated Evidence. If merging were not idempotent -- if it re-sorted
    Evidence differently on a merged input, or re-applied the Confidence cap to a
    different maximum -- the two lists would differ here.
    """
    once = deduplicate(items)
    twice = deduplicate(once)

    assert _payloads(twice) == _payloads(once)


# Feature: aws-iac-review-agent-plugin, Property 4: *For any* list of schema-valid Findings and *for any* permutation of that list, deduplication produces the same result. This subsumes commutativity and associativity of the merge operation over `Severity`, `Confidence`, `FindingType`, `Source`, and `Evidence`.
@settings(max_examples=100)
@given(items=_dedup_inputs(), data=st.data())
def test_deduplication_is_permutation_invariant(
    items: List[Finding], data: st.DataObject
) -> None:
    """Arrival order is invisible in the output, including its ordering.

    Equality of the *lists*, not of their contents as sets: Requirement 16 AC11
    wants byte-identical reports, and report sorting is stable, so two entries
    that tie on every report sort key would carry an input-order dependence
    through to stdout if dedup's own output order were not content-determined.

    One drawn permutation per example rather than all of them: a ten-element list
    has over three million rearrangements, and Hypothesis shrinks a failing pair
    to a small list and a small rearrangement of it. ``tests/unit/test_metrics.py``
    exhausts
    ``itertools.permutations`` for the analogous claim about benchmark metrics,
    where the fixture is fixed and tiny.
    """
    permuted = data.draw(st.permutations(items), label="permutation")

    assert _payloads(deduplicate(permuted)) == _payloads(deduplicate(items))


# Feature: aws-iac-review-agent-plugin, Property 11: *For any* list of schema-valid Findings, every Finding whose deduplication key is unique in the list, whose `Normalized_Category` is `Other`, or whose `Resource` is null, appears in the deduplication output with every field except `ID` identical to its input value.
@settings(max_examples=100)
@given(S.finding_lists())
def test_findings_that_match_nothing_pass_through_unmodified(
    items: List[Finding]
) -> None:
    """Requirement 14 AC13, over the three ways of matching nothing.

    ``dedup_key`` returns ``None`` for the two exclusions -- ``Other``
    (Requirement 14 AC3) and no ``Resource`` (AC6) -- and a key held by exactly
    one Finding is the third case. All three are asked of the key function rather
    than re-derived here, so the test follows the definition of matching rather
    than duplicating it.

    Multiplicity is checked, not just membership: a list can hold two Findings
    with identical content and no key, and both have to reach the output. The
    comparison is one-directional (every pass-through appears at least as often
    as it did in the input) because the output also holds merged entries, which
    are new Findings and no input's image.

    The property permits ``ID`` to change, and the implementation is stronger than
    that: it returns the caller's object. That stronger claim belongs where it can
    be stated exactly, and ``tests/unit/test_dedup.py`` states it with ``is``.
    """
    key_counts = _unique_keys(items)
    expected: Dict[str, int] = {}
    for f in items:
        key = dedup_key(f)
        if key is not None and key_counts[key] > 1:
            continue  # Merged: Property 5's subject, not this one.
        fingerprint = _content_fingerprint(f)
        expected[fingerprint] = expected.get(fingerprint, 0) + 1

    produced: Dict[str, int] = {}
    for f in deduplicate(items):
        fingerprint = _content_fingerprint(f)
        produced[fingerprint] = produced.get(fingerprint, 0) + 1

    for fingerprint, count in expected.items():
        assert produced.get(fingerprint, 0) >= count
