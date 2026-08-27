"""Properties 30 and 31: the shape of the benchmark's numbers, and its verdict.

:mod:`benchmark.harness.metrics` is the whole of the benchmark's arithmetic and
:mod:`benchmark.harness.run_benchmark` turns its verdict into a process status.
Two things about that pair have to hold for every case anyone ever adds, not only
for the cases in ``benchmark/cases/``:

**Nothing but a well-formed percentage reaches output.** Every rate is a string
with exactly one decimal place, or :data:`~benchmark.harness.metrics.NOT_APPLICABLE`
where the denominator was zero -- ``"N/A"`` says "not measured", which is a
different fact from ``"0.0"``. Strings rather than floats because Requirement 16
AC11 wants byte-identical output between runs and a float's repr is where that
quietly stops holding (Property 30).

**CI fails for one reason only.** A category is ``FAIL`` exactly when a
``deterministic`` expectation in it was missed (Requirement 11 AC7). A category
made only of ``agent-dependent`` expectations is measured and reported with no
threshold at all (Requirement 11 AC8): agent output is not deterministic, so a
threshold on it would make CI flaky rather than informative (Property 31).

``tests/unit/test_metrics.py`` (80 checks) and ``tests/unit/test_run_benchmark.py``
already pin both claims on fixtures a reader can verify by eye: the worked
percentages, ``"N/A"`` where nothing was measured, severity staying outside the
match key, one-to-one matching resolved in ground truth order, invariance under
every ``itertools.permutations`` of one Finding list, and the five fixed
``(expected, actual)`` shapes for which the reported status and the exit-code rule
have to agree. None of that is repeated here. What these two tests add is the
quantifier: over generated expectation sets and generated Finding sets, in every
``--mode``, per case and pooled across cases, no percentage is malformed and no
category fails for any other reason.

**The oracles share no arithmetic with the module under test.** Property 30's
oracle is a regular expression plus a bound, applied to whichever values in the
result are strings -- so a metric renamed or added is either checked or makes the
test fail, never silently skipped. Property 31's oracle decides "detected" by
match-key membership, computed here as a set, rather than by reading
``matched_count`` back out of the result it is meant to be checking. That reading
is sound because ``strategies.expected_actual_pairs`` draws expectations
``unique_by`` match key: with no two expectations sharing a key, one-to-one
matching can never starve one, so "the key appears among the Findings" and "the
expectation was matched" are the same statement.

**Two facts worth stating rather than rediscovering.** Detection Rate and Recall
are numerically equal under these definitions, because ``FN`` is ``|E| - TP`` and
so ``TP / (TP + FN)`` is ``TP / |E|``; both are reported because Requirement 11
AC5 asks for both, and the equality is a consequence of the matching rule. And
:func:`~benchmark.harness.metrics.format_percentage` uses ``"{:.1f}"``, which
rounds half to even; Property 31 therefore compares the *float* rate against 100
rather than the formatted string, so no assertion here depends on the rounding of
a third decimal place that the benchmark does not claim to carry.

Non-vacuity of the generators is asserted in ``test_strategies_smoke.py``: that
the ``exact`` branch really is exact, that the inexact branch reaches matched
pairs, false negatives and false positives, and that
``strategies.detection_rates()`` produces ``None``, values below 100, and exactly
``100.0`` -- the boundary Property 31's rule turns at.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple

from hypothesis import given, settings
from hypothesis import strategies as st

import strategies as S
from benchmark.harness import metrics, run_benchmark

#: An ``(expected, actual)`` pair as the strategy returns it.
Pair = Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]

#: A percentage as it appears in output: digits, a point, one digit. Sign
#: deliberately unmatched -- no percentage the harness computes can be negative,
#: and ``"-0.0"`` is a value this would have to reject.
ONE_DECIMAL = re.compile(r"^[0-9]+\.[0-9]$")

#: Two case IDs, to pool the same pair as if it came from two cases. ``::`` is
#: :data:`~benchmark.harness.run_benchmark.CASE_SEPARATOR`'s business; only the
#: prefixes differ here, which is what keeps one case's Finding from satisfying
#: another case's expectation in the aggregate.
CASE_IDS: Tuple[str, str] = ("case-001-alpha", "case-002-beta")


def _percentage_keys(keys: Tuple[str, ...]) -> Tuple[str, ...]:
    """The keys of a metrics result that hold a percentage.

    Derived from :data:`~benchmark.harness.metrics.METRIC_KEYS` and
    :data:`~benchmark.harness.metrics.CATEGORY_KEYS` rather than listed, so a
    metric added to either tuple is checked without this file being edited. The
    counts are the keys ending in ``_count`` and ``status`` is the verdict; what
    is left is percentages.
    """
    return tuple(
        key for key in keys if not key.endswith("_count") and key != "status"
    )


#: Percentage keys of :func:`benchmark.harness.metrics.compute`'s result.
METRIC_PERCENTAGES: Tuple[str, ...] = _percentage_keys(metrics.METRIC_KEYS)

#: Percentage keys of one :func:`benchmark.harness.metrics.compute_by_category`
#: entry.
CATEGORY_PERCENTAGES: Tuple[str, ...] = _percentage_keys(metrics.CATEGORY_KEYS)


def _assert_well_formed(
    result: Mapping[str, Any],
    keys: Tuple[str, ...],
    percentage_keys: Tuple[str, ...],
    label: str,
) -> None:
    """Assert every percentage in ``result`` is ``"N/A"`` or a one-decimal ``[0, 100]``.

    Also asserts, in the other direction, that no *other* string value is hiding
    in the result: a percentage this file failed to select would show up as an
    unexpected string rather than as a value nobody looked at. ``status`` is the
    one string that is not a percentage, and it is Property 31's subject.

    Args:
        result: One :func:`~benchmark.harness.metrics.compute` result or one
            :func:`~benchmark.harness.metrics.compute_by_category` entry.
        keys: The keys the result must carry, in order.
        percentage_keys: The subset of ``keys`` holding percentages.
        label: Which measurement this is, for the failure message.
    """
    assert tuple(result) == keys, label
    for key, value in result.items():
        if isinstance(value, str) and key != "status":
            assert key in percentage_keys, "{0}: unchecked string {1}".format(
                label, key
            )
    for key in percentage_keys:
        value = result[key]
        if value == metrics.NOT_APPLICABLE:
            continue
        assert isinstance(value, str), "{0}: {1} is not a string".format(label, key)
        assert ONE_DECIMAL.match(value), "{0}: {1} is {2!r}".format(label, key, value)
        assert 0.0 <= float(value) <= 100.0, "{0}: {1} is {2!r}".format(
            label, key, value
        )


def _views(
    expected: List[Dict[str, Any]],
    actual: List[Dict[str, Any]],
    source: Optional[str],
) -> Tuple[Tuple[str, List[Dict[str, Any]], List[Dict[str, Any]]], ...]:
    """Every ``(expected, actual)`` pair the harness measures, for one mode.

    Two of them. ``per-case`` is the pair narrowed to the mode's Source, which is
    what a single case reports (Requirement 11 AC10, AC11): both documents are
    filtered through one function, because an expectation's ``detected_by`` and a
    Finding's ``Source`` are the same vocabulary asked in opposite directions.
    ``aggregate`` pools that pair as if two cases had produced it, through
    :func:`~benchmark.harness.run_benchmark.namespaced`, which is where the run
    summary's percentages come from.

    Args:
        expected: Ground-truth entries.
        actual: Report Findings.
        source: The mode's Source, or ``None`` for ``combined``.

    Returns:
        ``(label, expected, actual)`` triples.
    """
    case_expected = metrics.filter_by_source(expected, source)
    case_actual = metrics.filter_by_source(actual, source)
    pooled_expected = [
        run_benchmark.namespaced(item, case_id)
        for case_id in CASE_IDS
        for item in case_expected
    ]
    pooled_actual = [
        run_benchmark.namespaced(item, case_id)
        for case_id in CASE_IDS
        for item in case_actual
    ]
    return (
        ("per-case", list(case_expected), list(case_actual)),
        ("aggregate", pooled_expected, pooled_actual),
    )


def _pairs_with_exactness() -> st.SearchStrategy[Tuple[bool, Pair]]:
    """An ``(is_exact, pair)`` draw covering both halves of Property 30.

    The flag is carried alongside rather than recovered from the pair, because
    the property's second clause is a statement about how the pair was *built*
    ("the actual set matches the expected set exactly under the match key"), and
    an inexact draw can coincidentally be exact -- every expectation detected,
    no unrelated Finding added -- which is fine and simply does not trigger the
    clause.

    The exact branch takes ``min_size=1``: with no expectations at all every rate
    is ``"N/A"``, which is correct and is checked by the first clause, but is not
    the ``"100.0"`` the second clause talks about.
    """
    return st.one_of(
        S.expected_actual_pairs(exact=False).map(lambda pair: (False, pair)),
        S.expected_actual_pairs(exact=True, min_size=1).map(lambda pair: (True, pair)),
    )


def _missed_deterministic_keys(
    expected: List[Dict[str, Any]], actual: List[Dict[str, Any]]
) -> Set[metrics.MatchKey]:
    """Match keys of ``deterministic`` expectations no Finding reports.

    The independent half of Property 31's oracle. ``Normalized_Category`` is part
    of the match key, so a key that appears among the Findings appears in the
    same category as the expectation -- there is no need to group before asking.

    Args:
        expected: Ground-truth entries, with distinct match keys (see the module
            docstring on why that makes membership equivalent to matching).
        actual: Report Findings.
    """
    reported = {metrics.match_key(item) for item in actual}
    return {
        metrics.match_key(item)
        for item in expected
        if metrics.detection_class_of(item) == metrics.DETERMINISTIC
        and metrics.match_key(item) not in reported
    }


# Feature: aws-iac-review-agent-plugin, Property 30: Benchmark metric well-formedness
#
# *For any* expected finding set and *for any* actual finding set, every
# percentage metric produced by the benchmark harness is either the string
# `"N/A"` or a string that parses to a float in the closed interval `[0, 100]`
# with exactly one digit after the decimal point; and when the actual set matches
# the expected set exactly under the match key, Detection Rate, Precision, and
# Recall are all `"100.0"` and the false positive count is `0`.
@settings(max_examples=100)
@given(_pairs_with_exactness(), st.sampled_from(run_benchmark.MODE_NAMES))
def test_every_percentage_is_n_a_or_a_one_decimal_rate_in_range(
    drawn: Tuple[bool, Pair], mode_name: str
) -> None:
    """**Validates: Requirements 11.5, 11.6**

    Both clauses, over every measurement one run produces: the overall metrics
    and each per-category entry, per case and pooled across two cases, narrowed
    to each ``--mode``'s Source.

    The exact clause survives filtering and pooling, which is the point of
    checking it there. A derived Finding carries the expectation's own
    ``detected_by`` as its ``Source``, so a single-Source mode narrows both
    documents in lockstep and what remains is still an exact match; and
    ``namespaced`` prefixes both sides with the same case ID, so two pooled cases
    cannot cross-match. Where a mode filters everything away the clause has
    nothing to say -- every rate is then ``"N/A"``, which the first clause
    covers -- so it is asserted only where expectations survive.
    """
    is_exact, (expected, actual) = drawn
    source = run_benchmark.MODES[mode_name].source

    for label, view_expected, view_actual in _views(expected, actual, source):
        where = "{0}/{1}".format(mode_name, label)
        overall = metrics.compute(view_expected, view_actual)
        _assert_well_formed(
            overall, metrics.METRIC_KEYS, METRIC_PERCENTAGES, where
        )

        per_category = metrics.compute_by_category(view_expected, view_actual)
        for name, entry in per_category.items():
            _assert_well_formed(
                entry,
                metrics.CATEGORY_KEYS,
                CATEGORY_PERCENTAGES,
                "{0}/{1}".format(where, name),
            )

        if not (is_exact and view_expected):
            continue
        for scope, result in [(where, overall)] + [
            ("{0}/{1}".format(where, name), entry)
            for name, entry in per_category.items()
        ]:
            assert result["detection_rate"] == "100.0", scope
            assert result["recall"] == "100.0", scope
            assert result["precision"] == "100.0", scope
            assert result["false_positive_count"] == 0, scope


# Feature: aws-iac-review-agent-plugin, Property 31: Benchmark pass/fail threshold
#
# *For any* computed Detection Rate value, the category status is `FAIL` if and
# only if the category contains at least one expected Finding classified as
# `deterministic` and the Detection Rate for those Findings is below 100 percent.
@settings(max_examples=100)
@given(S.detection_rates(), st.booleans(), S.expected_actual_pairs())
def test_fail_holds_exactly_when_a_deterministic_expectation_was_missed(
    rate: Optional[float], has_deterministic: bool, pair: Pair
) -> None:
    """**Validates: Requirements 11.7, 11.8**

    The equivalence is asserted at all three levels it has to hold at.

    *The rule itself*, over any detection rate a category could compute --
    including exactly ``100.0``, the boundary it turns at, and ``None``, which
    means nothing was measured. ``has_deterministic=True`` with ``rate=None`` is
    a contradiction no category can produce (a rate over zero expectations is
    ``None``); the caller that passes it has contradicted itself, and ``INFO`` is
    the answer that neither invents a CI failure nor claims a pass, so the oracle
    reads the same way.

    *The categories of a generated pair*, against an oracle built from match-key
    membership rather than from the counts under test. The float rate is compared
    against 100 rather than the formatted string: ``"{:.1f}"`` rounds half to
    even, and the verdict must not depend on a decimal place the benchmark does
    not claim to carry.

    *The run's verdict*, since a status only matters because CI acts on it.
    :func:`~benchmark.harness.run_benchmark.case_status` pools the same
    deterministic counts across categories and must agree with
    :func:`~benchmark.harness.metrics.has_failure`, which is the predicate
    ``Benchmark.exit_code`` returns
    :data:`~benchmark.harness.run_benchmark.BENCHMARK_FAILURE` for.
    """
    status = metrics.category_status(rate, has_deterministic)
    should_fail = has_deterministic and rate is not None and rate < 100.0
    assert (status == metrics.STATUS_FAIL) is should_fail
    assert status in (metrics.STATUS_PASS, metrics.STATUS_FAIL, metrics.STATUS_INFO)
    assert (status == metrics.STATUS_PASS) is (
        has_deterministic and rate is not None and rate >= 100.0
    )

    expected, actual = pair
    missed = _missed_deterministic_keys(expected, actual)
    per_category = metrics.compute_by_category(expected, actual)
    for name, entry in per_category.items():
        category_missed = {key for key in missed if key[2] == name}
        assert (entry["status"] == metrics.STATUS_FAIL) is bool(
            category_missed
        ), name

        deterministic_expected = int(entry["deterministic_expected_count"])
        deterministic_matched = int(entry["deterministic_matched_count"])
        if deterministic_expected == 0:
            # Requirement 11 AC8: nothing to hold to a threshold, so the category
            # is reported however low its agent-dependent detection rate is.
            assert entry["status"] == metrics.STATUS_INFO, name
            assert entry["deterministic_detection_rate"] == metrics.NOT_APPLICABLE, name
            continue
        computed = metrics.percentage(deterministic_matched, deterministic_expected)
        assert computed is not None, name
        assert (entry["status"] == metrics.STATUS_FAIL) is (computed < 100.0), name

    assert (
        run_benchmark.case_status(per_category) == metrics.STATUS_FAIL
    ) is metrics.has_failure(per_category)
