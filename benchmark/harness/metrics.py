"""Comparison of review output against Ground_Truth, and the metrics over it.

This module is the whole of the benchmark's arithmetic. It takes two already
parsed documents -- one case's ``ground_truth.json`` and one Review_Report --
and returns counts, percentages and a pass/fail verdict. It runs no review,
reads no file, and spawns no process; ``run_benchmark.py`` (Task 21.6) does all
of that and calls in here for the numbers.

Seven decisions are worth reading before using the module.

**The match key is three fields, and severity is not one of them.** A reported
Finding counts as an expected one when the two agree on resource logical ID,
``FindingType`` and ``Normalized_Category`` (Requirement 11 AC9). Nothing else
is compared, and Finding text is never compared as a string: the wording of a
Finding is not part of what the benchmark measures, and pinning it would make
every rephrasing look like a regression. Severity is deliberately outside the
key. If a severity mismatch made a Finding count as missed, one mistake would
lower detection rate and severity accuracy at once; keeping severity out means
detection is about whether the problem was seen, and
:func:`compute`'s ``severity_accuracy`` is about whether it was rated right.

**A template-level expectation compares as the empty string.** design.md's
``match_key`` pseudocode wraps all three fields in ``str()``, which would turn a
``"resource": null`` expectation into the literal ``"None"``. The same section
states the rule that governs: a Finding with no ``Resource`` has the empty
string in the first position. This module implements the rule, not the
pseudocode's transcription of it -- ``"None"`` would still be self-consistent
across both sides and so would still match, but it would also collide with a
resource legitimately named ``None``.

**Matching is one to one, and its result cannot depend on report order.** Two
orderings are involved and they answer different questions. Expectations are
consumed in the order ``ground_truth.json`` writes them, which is what the
README promises and what makes duplicate match keys resolve predictably.
Candidate Findings within one match key are consumed in the order of their own
canonical JSON, *not* in report order, so that permuting the report changes no
metric. Report order is already deterministic (``report.sort_findings``), so
this costs nothing in practice; it matters because severity accuracy asks a
question about a *particular* matched Finding, and with two candidates sharing a
match key but differing in ``Severity``, "whichever came first in the report"
would make the metric an artefact of sort order. Input position survives only as
the final tie-break between entries whose canonical forms are equal, which are
indistinguishable and so cannot move any number.

**Percentages are strings, with one decimal place.** ``"66.7"``, not
``66.66666666666667``. Requirement 16 AC11 wants byte-identical output between
runs, and a float's repr is the one place where that can quietly fail to hold.
Where the denominator is zero the value is :data:`NOT_APPLICABLE`, which says
"this was not measured" -- distinct from ``"0.0"``, which says "measured, and
nothing was found".

**Detection Rate and Recall are numerically equal here.** ``FN`` is
``|E| - TP``, so ``TP / (TP + FN)`` and ``TP / |E|`` are the same number.
Requirement 11 AC5 asks for both, so :func:`compute` reports both, and the
equality is a consequence of the matching rule rather than a coincidence: it
would stop holding only under a definition that counted "detected, wrong
severity" as a false negative, which is exactly the double penalty the match key
avoids.

**Only ``deterministic`` expectations are held to a threshold.** A category
containing a ``deterministic`` expectation that was not detected is ``FAIL``
(Requirement 11 AC7) and makes the harness exit non-zero.
``agent-dependent`` expectations are measured and reported with no threshold
(Requirement 11 AC8): agent output is not deterministic, so a threshold on it
would make CI flaky rather than informative, and the category is reported
``INFO`` however low its detection rate.

**Nothing from ``iacreview`` is imported.** The module needs no vocabulary from
it: severity is compared for equality rather than ranked, categories are grouped
by whatever string they carry rather than validated, and every value the
benchmark constrains is already constrained by ``ground_truth.schema.json``,
whose enums are tested against ``iacreview`` in
``tests/unit/test_ground_truth.py``. What this module does own is the one thing
neither document can state alone: that ground truth spells a field
``normalized_category`` and a Finding spells it ``Normalized_Category``. That
mapping is :data:`FIELD_ALIASES`, and ``tests/unit/test_metrics.py`` checks both
sides of it against ``iacreview.finding.FINDING_FIELDS`` and against the schema,
so the mapping cannot drift from either without a test failing. Importing
``iacreview`` for constants that are not used would buy nothing and would make
the benchmark's arithmetic fail to import when the plugin does.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

__all__ = [
    "MetricsInputError",
    "Item",
    "MatchKey",
    "MatchResult",
    "FIELD_ALIASES",
    "DETECTION_CLASS_FIELD",
    "DETERMINISTIC",
    "AGENT_DEPENDENT",
    "DETECTION_CLASSES",
    "NOT_APPLICABLE",
    "STATUS_PASS",
    "STATUS_FAIL",
    "STATUS_INFO",
    "METRIC_KEYS",
    "CATEGORY_KEYS",
    "DEFERRED_METRICS",
    "match_key",
    "severity_of",
    "category_of",
    "detection_class_of",
    "sources_of",
    "filter_by_source",
    "filter_by_detection_class",
    "match",
    "percentage",
    "format_percentage",
    "compute",
    "category_status",
    "compute_by_category",
    "has_failure",
]


class MetricsInputError(ValueError):
    """An expectation or a Finding is missing a field the comparison needs.

    Raised rather than defaulted: a missing ``normalized_category`` would make an
    expectation match nothing at all, which would show up as a plausible-looking
    detection failure instead of as the malformed input it is. Both documents
    have schemas that require these fields, so reaching this exception means one
    of them was not validated.
    """


#: One expectation or one Finding, as parsed from JSON. A Mapping rather than a
#: dataclass because both documents arrive through ``json.load``; a caller
#: holding :class:`iacreview.finding.Finding` instances converts them with
#: ``finding.to_dict`` first.
Item = Mapping[str, Any]

#: ``(resource, finding_type, normalized_category)``. The order is design.md's.
MatchKey = Tuple[str, str, str]

#: How each field this module reads is spelled in each document: ground truth
#: first, Review_Report second. Ground truth is snake_case because it is a
#: hand-written benchmark document; a Finding uses the report schema's own
#: capitalization, which ``iacreview.finding`` keeps as literal JSON keys. An
#: item carrying both spellings is malformed rather than ambiguous, and the
#: ground-truth spelling wins, matching design.md's pseudocode.
FIELD_ALIASES: Dict[str, Tuple[str, str]] = {
    "resource": ("resource", "Resource"),
    "finding_type": ("finding_type", "FindingType"),
    "normalized_category": ("normalized_category", "Normalized_Category"),
    "severity": ("severity", "Severity"),
    # Expected Sources and reported Sources are the same vocabulary asked in
    # opposite directions: "who should find this" against "who did find it".
    # Both are lists, so one accessor serves both sides of a --mode filter.
    "sources": ("detected_by", "Source"),
}

#: Ground truth's own field, deliberately absent from :data:`FIELD_ALIASES`
#: because it has no counterpart in a Finding: a report states which Source found
#: something, not whether reaching it required reasoning. Every entry of
#: ``FIELD_ALIASES`` names a field both documents carry, and keeping this one out
#: is what lets the aliases be checked against the Finding schema field by field.
DETECTION_CLASS_FIELD = "detection_class"

#: ``detection_class`` of an expectation reachable without agent reasoning.
DETERMINISTIC = "deterministic"

#: ``detection_class`` of an expectation that needs agent reasoning.
AGENT_DEPENDENT = "agent-dependent"

#: The closed ``detection_class`` set (Requirement 11 AC4), in schema order.
DETECTION_CLASSES: Tuple[str, ...] = (DETERMINISTIC, AGENT_DEPENDENT)

#: Emitted in place of a percentage whose denominator is zero.
NOT_APPLICABLE = "N/A"

#: Every ``deterministic`` expectation in the category was detected.
STATUS_PASS = "PASS"

#: At least one ``deterministic`` expectation was missed (Requirement 11 AC7).
STATUS_FAIL = "FAIL"

#: Measured, with no threshold applied (Requirement 11 AC8).
STATUS_INFO = "INFO"

#: Keys of :func:`compute`'s result, in the order it inserts them. Named so that
#: a caller can assert the shape without restating the strings, and so that the
#: ``deterministic``-subset keys of :data:`CATEGORY_KEYS` can extend it.
#:
#: The counts are design.md's symbols: ``expected_count`` is ``|E|``,
#: ``actual_count`` is ``|A|``, ``matched_count`` is ``TP``,
#: ``false_negative_count`` is ``FN``, ``false_positive_count`` is ``FP``, and
#: ``severity_match_count`` is ``SM``. They are reported alongside the
#: percentages because a rate over three expectations and a rate over three
#: hundred read identically once formatted.
METRIC_KEYS: Tuple[str, ...] = (
    "expected_count",
    "actual_count",
    "matched_count",
    "false_negative_count",
    "false_positive_count",
    "severity_match_count",
    "detection_rate",
    "recall",
    "precision",
    "severity_accuracy",
)

#: Keys of one entry of :func:`compute_by_category`'s result. The four added to
#: :data:`METRIC_KEYS` are the pass/fail rule's inputs and its verdict. Only
#: detection numbers are restated for the ``deterministic`` subset: a precision
#: computed against a subset of the expectations would count every
#: agent-dependent detection as a false positive, which is not what the number
#: means anywhere else in this module.
CATEGORY_KEYS: Tuple[str, ...] = METRIC_KEYS + (
    "deterministic_expected_count",
    "deterministic_matched_count",
    "deterministic_detection_rate",
    "status",
)

#: Metrics that are defined but not computed in v0.1 (Requirement 11 AC13).
#: None of them needs a ground-truth field, which is why deferring them costs no
#: format change:
#:
#: ``Review Time``
#:     Wall-clock time to review one template, deterministic and agent phases
#:     separated. Measured at run time and environment-dependent, so it cannot
#:     enter output that has to stay byte-identical between runs
#:     (Requirement 16 AC11); implementing it means a second, separate output.
#:
#: ``Remediation Accuracy``
#:     Share of ``SuggestedRemediation`` values that, applied, clear their
#:     Finding without introducing a new one. Computable from the expectations
#:     that already exist, by patching the template and reviewing it again --
#:     that is, it needs a second review pass rather than new ground truth.
#:
#: ``Human Intervention Count``
#:     Number of human decisions needed to complete a review. A property of a
#:     review session, not of a case, so no case file can carry it.
#:
#: ``benchmark/README.md`` states the same three reasons; a test asserts the
#: names appear in both places.
DEFERRED_METRICS: Tuple[str, ...] = (
    "Review Time",
    "Remediation Accuracy",
    "Human Intervention Count",
)

#: Marker for "no default", so that ``None`` stays usable as a real default.
_MISSING = object()


# ---------------------------------------------------------------------------
# Field access across the two spellings
# ---------------------------------------------------------------------------


def _field(item: Item, logical_name: str, default: Any = _MISSING) -> Any:
    """Read ``logical_name`` from ``item`` under whichever spelling it uses.

    Args:
        item: One expectation or one Finding.
        logical_name: A key of :data:`FIELD_ALIASES`.
        default: Returned when neither spelling is present. Omit it to make an
            absent field an error.

    Raises:
        MetricsInputError: Neither spelling is present and no default was given.
    """
    for name in FIELD_ALIASES[logical_name]:
        if name in item:
            return item[name]
    if default is not _MISSING:
        return default
    raise MetricsInputError(
        "item carries neither spelling of {0} ({1}); keys present: {2}".format(
            logical_name,
            " or ".join(FIELD_ALIASES[logical_name]),
            sorted(item),
        )
    )


def _as_key_text(value: Any) -> str:
    """Coerce one match-key component to text, mapping ``None`` to ``""``.

    ``None`` is the ``resource`` of a template-level expectation and the
    ``Resource`` of a template-level Finding, and both sides go through here, so
    the two agree by construction rather than by both happening to stringify the
    same way. See the module docstring on why ``str(None)`` is not used.
    """
    if value is None:
        return ""
    return value if isinstance(value, str) else str(value)


def match_key(item: Item) -> MatchKey:
    """Return the three fields ``item`` is compared on.

    Applies to expectations and to Findings alike, and to every
    ``detection_class`` alike (Requirement 11 AC9 legislates the rule for
    ``agent-dependent`` expectations; design.md applies it to all of them, so
    there is one notion of "the same finding" in the benchmark).

    Args:
        item: One expectation or one Finding, in either spelling.

    Returns:
        ``(resource, finding_type, normalized_category)``, with the empty string
        in the first position for a template-level item.

    Raises:
        MetricsInputError: Any of the three fields is absent under both
            spellings. ``resource`` must be *present*; only its value may be
            ``null``.
    """
    return (
        _as_key_text(_field(item, "resource")),
        _as_key_text(_field(item, "finding_type")),
        _as_key_text(_field(item, "normalized_category")),
    )


def severity_of(item: Item) -> str:
    """Return ``item``'s expected or reported ``Severity``.

    Compared for equality only. Severity is comparable across Findings only
    within one ``FindingType`` (Requirement 7 AC5), and the match key already
    fixes ``FindingType``, so a matched pair is always comparable -- but nothing
    here needs a ranking, and introducing one would invite "close enough"
    scoring, which severity accuracy is not.

    Raises:
        MetricsInputError: The field is absent under both spellings.
    """
    return _as_key_text(_field(item, "severity"))


def category_of(item: Item) -> str:
    """Return the ``Normalized_Category`` ``item`` is grouped under.

    The third component of :func:`match_key`, read through the same accessor so
    that grouping and matching cannot disagree about which category an item is
    in.
    """
    return _as_key_text(_field(item, "normalized_category"))


def detection_class_of(item: Item) -> str:
    """Return ``item``'s ``detection_class``.

    Defined for expectations only: a report says which Source found a Finding,
    not whether reaching it required reasoning. An expectation with no
    ``detection_class`` is malformed against the schema, so this raises rather
    than assuming either class -- assuming ``deterministic`` would invent a CI
    failure, and assuming ``agent-dependent`` would silence a real one.

    Raises:
        MetricsInputError: The field is absent.
    """
    if DETECTION_CLASS_FIELD not in item:
        raise MetricsInputError(
            "expectation carries no {0}; keys present: {1}".format(
                DETECTION_CLASS_FIELD, sorted(item)
            )
        )
    return _as_key_text(item[DETECTION_CLASS_FIELD])


def sources_of(item: Item) -> List[str]:
    """Return the Sources ``item`` names: ``detected_by``, or a Finding's ``Source``.

    Returns:
        A new list, in the document's own order. Empty when the field is absent,
        which for the ``--mode`` filters means "names no Source" and so is
        excluded from every single-Source mode -- the safe direction, since the
        alternative would silently count such an item in every mode.
    """
    value = _field(item, "sources", None)
    if isinstance(value, str):
        # A single Source written as a bare string rather than a one-item list.
        # Neither schema permits it; accepting it costs nothing and keeps a
        # hand-edited fixture from filtering to nothing without explanation.
        return [value]
    if not isinstance(value, (list, tuple)):
        return []
    return [_as_key_text(entry) for entry in value]


# ---------------------------------------------------------------------------
# Filters the --mode option drives (Requirement 11 AC10, AC11)
# ---------------------------------------------------------------------------


def filter_by_source(items: Iterable[Item], source: Optional[str]) -> List[Item]:
    """Keep the items naming ``source``, or all of them when ``source`` is ``None``.

    One function for both sides of a single-Source mode, because both sides ask
    the same question of the same vocabulary: an expectation keeps its place when
    ``detected_by`` names the Source, and a Finding keeps its place when
    ``Source`` does. A merged Finding carries every Source that reached it
    (Requirement 11 AC10), so it survives filtering to any one of them.

    Args:
        items: Expectations or Findings.
        source: A Source name, or ``None`` for the ``combined`` mode, which
            filters nothing.

    Returns:
        A new list in input order.
    """
    if source is None:
        return list(items)
    return [item for item in items if source in sources_of(item)]


def filter_by_detection_class(
    expected: Iterable[Item], detection_class: str
) -> List[Item]:
    """Keep the expectations classified ``detection_class``.

    Args:
        expected: Expectations. Findings have no ``detection_class`` and passing
            them here raises.
        detection_class: One of :data:`DETECTION_CLASSES`. Any other value
            selects nothing rather than raising: the schema closes the set, so an
            unknown class cannot come from a valid case.

    Returns:
        A new list in input order, which for the ``deterministic`` subset keeps
        ground truth's tie-break order intact.
    """
    return [item for item in expected if detection_class_of(item) == detection_class]


# ---------------------------------------------------------------------------
# One-to-one matching
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MatchResult:
    """Which expectations were met, by which Findings, and what was left over.

    Indices rather than items, so a caller can reach either document's entry --
    severity accuracy needs both halves of a pair, and a human-readable report
    of what was missed needs the expectation's ``note``.

    Attributes:
        pairs: ``(expected index, actual index)``, ascending by expected index.
        unmatched_expected: Expectation indices no Finding matched. The false
            negatives.
        unmatched_actual: Finding indices no expectation claimed, ascending. The
            false positives.
    """

    pairs: Tuple[Tuple[int, int], ...]
    unmatched_expected: Tuple[int, ...]
    unmatched_actual: Tuple[int, ...]


def _canonical_form(item: Item) -> str:
    """``item`` as one canonical string, for ordering candidates by content.

    Only ever compared, never parsed. ``sort_keys`` makes it independent of key
    order, and ``default=repr`` keeps a value ``json`` cannot serialize from
    raising here: this is a tie-break, and a crash in a tie-break would be a
    strange way to fail a benchmark run.
    """
    return json.dumps(
        item, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=repr
    )


def match(expected: Sequence[Item], actual: Sequence[Item]) -> MatchResult:
    """Pair expectations with Findings, one to one, on :func:`match_key`.

    Args:
        expected: Expectations, in the order ``ground_truth.json`` writes them.
            That order is the tie-break: when several expectations share a match
            key, the earlier one is served first, so the outcome does not depend
            on the order the review emitted its Findings in.
        actual: Findings from the report.

    Returns:
        A :class:`MatchResult`. Every metric in :func:`compute` is a count over
        it.

    Note:
        Permuting ``actual`` changes ``MatchResult.pairs``' second components,
        because they are positions in the list that was permuted, and changes
        nothing else: which *Findings* are matched, and therefore every metric,
        is decided by :func:`_canonical_form` rather than by position. See the
        module docstring.
    """
    candidates: Dict[MatchKey, List[int]] = {}
    for index, item in enumerate(actual):
        candidates.setdefault(match_key(item), []).append(index)
    for indices in candidates.values():
        indices.sort(key=lambda index: (_canonical_form(actual[index]), index))

    pairs: List[Tuple[int, int]] = []
    unmatched_expected: List[int] = []
    consumed = set()
    for expected_index, item in enumerate(expected):
        queue = candidates.get(match_key(item))
        if not queue:
            unmatched_expected.append(expected_index)
            continue
        actual_index = queue.pop(0)
        pairs.append((expected_index, actual_index))
        consumed.add(actual_index)

    unmatched_actual = [index for index in range(len(actual)) if index not in consumed]
    return MatchResult(
        pairs=tuple(pairs),
        unmatched_expected=tuple(unmatched_expected),
        unmatched_actual=tuple(unmatched_actual),
    )


# ---------------------------------------------------------------------------
# Percentages
# ---------------------------------------------------------------------------


def percentage(numerator: int, denominator: int) -> Optional[float]:
    """Return ``numerator / denominator`` as a percentage, or ``None``.

    Args:
        numerator: Count of the cases that held.
        denominator: Count of the cases examined.

    Returns:
        The percentage, or ``None`` when ``denominator`` is zero -- nothing was
        measured, which is not the same fact as ``0.0``. The float exists for
        :func:`category_status`, which compares against 100; every value that
        reaches output goes through :func:`format_percentage` first.
    """
    if denominator == 0:
        return None
    return numerator / denominator * 100.0


def format_percentage(value: Optional[float]) -> str:
    """Render a percentage for output: one decimal place, or :data:`NOT_APPLICABLE`.

    A string, not a number, so that no float repr reaches the report and two
    runs cannot differ in their last digit (Requirement 16 AC11).
    ``"{:.1f}"`` rounds half to even at a boundary such as ``12.25``; that is
    stated in ``docs/benchmark-methodology.md`` rather than corrected here,
    because a metric's third decimal place is not information the benchmark
    claims to carry.
    """
    if value is None:
        return NOT_APPLICABLE
    return "{0:.1f}".format(value)


# ---------------------------------------------------------------------------
# The metrics
# ---------------------------------------------------------------------------


def compute(expected: Sequence[Item], actual: Sequence[Item]) -> Dict[str, Any]:
    """Compare one evaluated expectation set with one evaluated Finding set.

    Both arguments are already filtered: ``--mode`` narrows them by Source, and
    :func:`compute_by_category` narrows them by category. This function measures
    exactly what it is given.

    Args:
        expected: Expectations, in ground truth order.
        actual: Findings.

    Returns:
        A new dict with exactly the keys of :data:`METRIC_KEYS`, in that order.
        Counts are ``int``; the four rates are strings, either one decimal place
        or :data:`NOT_APPLICABLE`. Nothing aliases the inputs.

    Raises:
        MetricsInputError: An item is missing a match-key field, or a matched
            item is missing its severity.
    """
    expected_list = list(expected)
    actual_list = list(actual)
    result = match(expected_list, actual_list)

    matched = len(result.pairs)
    false_negatives = len(result.unmatched_expected)
    false_positives = len(result.unmatched_actual)
    severity_matches = sum(
        1
        for expected_index, actual_index in result.pairs
        if severity_of(expected_list[expected_index])
        == severity_of(actual_list[actual_index])
    )

    return {
        "expected_count": len(expected_list),
        "actual_count": len(actual_list),
        "matched_count": matched,
        "false_negative_count": false_negatives,
        "false_positive_count": false_positives,
        "severity_match_count": severity_matches,
        "detection_rate": format_percentage(percentage(matched, len(expected_list))),
        # Written as TP / (TP + FN) because that is Recall's definition, even
        # though TP + FN is |E| by construction and the two rates are therefore
        # equal. See the module docstring.
        "recall": format_percentage(percentage(matched, matched + false_negatives)),
        # TP / (TP + FP), and TP + FP is |A| for the same reason.
        "precision": format_percentage(percentage(matched, matched + false_positives)),
        "severity_accuracy": format_percentage(percentage(severity_matches, matched)),
    }


def category_status(
    detection_rate: Optional[float], has_deterministic: bool
) -> str:
    """Return the pass/fail verdict for one category.

    Args:
        detection_rate: Detection rate **of the category's ``deterministic``
            expectations**, as :func:`percentage` returns it. Not the
            category's overall rate: mixing agent-dependent expectations into
            the threshold is precisely what Requirement 11 AC8 rules out.
        has_deterministic: Whether the category holds any ``deterministic``
            expectation at all.

    Returns:
        :data:`STATUS_FAIL` when a ``deterministic`` expectation was missed
        (Requirement 11 AC7), :data:`STATUS_PASS` when all of them were
        detected, and :data:`STATUS_INFO` when there is no threshold to apply --
        either because the category is entirely ``agent-dependent``
        (Requirement 11 AC8) or because nothing was measured. A caller that
        passes ``has_deterministic=True`` with ``detection_rate=None`` has
        contradicted itself; ``INFO`` is the answer that neither invents a CI
        failure nor claims a pass.
    """
    if not has_deterministic:
        return STATUS_INFO
    if detection_rate is None:
        return STATUS_INFO
    return STATUS_PASS if detection_rate >= 100.0 else STATUS_FAIL


def compute_by_category(
    expected: Sequence[Item], actual: Sequence[Item]
) -> Dict[str, Dict[str, Any]]:
    """Compute metrics and a verdict per ``Normalized_Category``.

    Partitioning by category loses nothing, because ``Normalized_Category`` is
    part of the match key: an expectation and a Finding in different categories
    could never have matched, so matching each category separately gives the
    same pairs as matching everything at once.

    Args:
        expected: Expectations, in ground truth order.
        actual: Findings.

    Returns:
        Category name -> a dict with exactly the keys of :data:`CATEGORY_KEYS`.
        Categories are keyed in sorted order, so serializing the result is
        byte-stable however the two documents were ordered. A category appears
        when either document mentions it: one with expectations and no Findings
        is a detection failure, and one with Findings and no expectations is
        where false positives live.
    """
    expected_list = list(expected)
    actual_list = list(actual)
    names = sorted(
        {category_of(item) for item in expected_list}
        | {category_of(item) for item in actual_list}
    )

    per_category: Dict[str, Dict[str, Any]] = {}
    for name in names:
        category_expected = [item for item in expected_list if category_of(item) == name]
        category_actual = [item for item in actual_list if category_of(item) == name]
        deterministic = filter_by_detection_class(category_expected, DETERMINISTIC)
        # Matched against the category's whole Finding set, not a subset of it:
        # nothing marks a Finding as deterministically reached, and the question
        # asked is whether the problem was reported at all.
        deterministic_matched = len(match(deterministic, category_actual).pairs)
        deterministic_rate = percentage(deterministic_matched, len(deterministic))

        entry = compute(category_expected, category_actual)
        entry["deterministic_expected_count"] = len(deterministic)
        entry["deterministic_matched_count"] = deterministic_matched
        entry["deterministic_detection_rate"] = format_percentage(deterministic_rate)
        entry["status"] = category_status(deterministic_rate, bool(deterministic))
        per_category[name] = entry
    return per_category


def has_failure(per_category: Mapping[str, Mapping[str, Any]]) -> bool:
    """Whether any category in :func:`compute_by_category`'s result is ``FAIL``.

    The harness's exit code is this predicate: a missed ``deterministic``
    expectation is a regression CI has to notice, and every other outcome is
    reported without failing the run.
    """
    return any(entry.get("status") == STATUS_FAIL for entry in per_category.values())
