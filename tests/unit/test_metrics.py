"""Checks for ``benchmark/harness/metrics.py``.

The benchmark's numbers are only worth reading if the arithmetic behind them is
pinned, so this file asserts the behaviour ``benchmark/README.md`` promises
rather than the implementation's incidentals. Five of the checks are load-bearing
and easy to lose in a refactor:

**Severity stays outside the match key.** A Finding reported with the wrong
severity is a detection, not a miss (Requirement 11 AC6). One test asserts both
halves of that at once: detection rate stays at ``"100.0"`` while severity
accuracy falls.

**Matching is one to one, resolved in ground truth order.** With two
expectations sharing a match key and one Finding to satisfy them, the
*first-written* expectation is the one served, so reordering the expectations
changes which severity is compared. Both orders are asserted.

**No metric depends on report order.** Every permutation of one Finding list is
computed and compared, because severity accuracy asks about a particular matched
Finding and would otherwise be an artefact of sort order.

**Percentages are strings.** ``"66.7"``, and ``"N/A"`` rather than ``"0.0"``
where nothing was measured. A float leaking into the output would break
Requirement 16 AC11's byte-identical guarantee without breaking any assertion
about the value.

**The field mapping cannot drift.** ``metrics.FIELD_ALIASES`` is the only place
that knows ground truth spells a field ``normalized_category`` and a Finding
spells it ``Normalized_Category``. Both sides are checked against their owners:
the report side against ``iacreview.finding.FINDING_FIELDS``, the ground-truth
side against ``benchmark/ground_truth.schema.json``. A field renamed in either
place fails here instead of silently making every expectation unmatchable.

Fixtures are built in this file rather than read from ``benchmark/cases/``. The
cases exist to measure the review; these tests measure the arithmetic, and
depending on real cases would make an intentional change to a case look like a
regression in ``metrics.py``.
"""

from __future__ import annotations

import itertools
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import pytest

from benchmark.harness import metrics
from iacreview.finding import FINDING_FIELDS

# tests/unit/test_metrics.py -> tests/unit -> tests -> plugin root
PLUGIN_ROOT: Path = Path(__file__).resolve().parents[2]
SCHEMA_PATH: Path = PLUGIN_ROOT / "benchmark" / "ground_truth.schema.json"
README_PATH: Path = PLUGIN_ROOT / "benchmark" / "README.md"


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------


def expectation(
    resource: Optional[str] = "DataBucket",
    normalized_category: str = "Encryption",
    finding_type: str = "Security",
    severity: str = "HIGH",
    detection_class: str = metrics.DETERMINISTIC,
    detected_by: Sequence[str] = ("cfn-guard",),
    note: str = "Server-side encryption is not configured.",
) -> Dict[str, Any]:
    """One ``expected_findings`` entry, in ground truth's snake_case spelling."""
    return {
        "resource": resource,
        "normalized_category": normalized_category,
        "finding_type": finding_type,
        "severity": severity,
        "detection_class": detection_class,
        "detected_by": list(detected_by),
        "note": note,
    }


def finding(
    resource: Optional[str] = "DataBucket",
    normalized_category: str = "Encryption",
    finding_type: str = "Security",
    severity: str = "HIGH",
    source: Sequence[str] = ("cfn-guard",),
    identifier: int = 1,
    text: str = "The bucket does not configure server-side encryption.",
) -> Dict[str, Any]:
    """One report Finding, carrying all 13 fields in the schema's spelling.

    Built in full rather than reduced to the four fields the comparison reads, so
    that the fixtures are the shape ``metrics`` actually receives and so that
    :func:`metrics._canonical_form`'s tie-break is exercised on realistic input.
    """
    return {
        "ID": identifier,
        "Normalized_Category": normalized_category,
        "FindingType": finding_type,
        "Severity": severity,
        "Confidence": "Confirmed",
        "Source": list(source),
        "Resource": resource,
        "Location": {"File": "template.yaml", "Line": None, "Column": None,
                     "TemplatePath": ["Resources", resource] if resource else None},
        "Finding": text,
        "WhyItMatters": "Unencrypted objects are readable from a stolen copy.",
        "Evidence": [{"Source": list(source)[0], "Detail": "rule fired",
                      "RuleId": "S3_BUCKET_SSE_ENABLED", "Excerpt": None}],
        "Recommendation": "Set BucketEncryption.",
        "SuggestedRemediation": None,
    }


# ---------------------------------------------------------------------------
# match_key
# ---------------------------------------------------------------------------


def test_match_key_reads_both_spellings_identically() -> None:
    # The point of the module: two documents, one comparison.
    assert metrics.match_key(expectation()) == metrics.match_key(finding())


def test_match_key_is_resource_type_category_in_that_order() -> None:
    key = metrics.match_key(
        expectation(resource="AdminRole", finding_type="Security", normalized_category="IAM")
    )
    assert key == ("AdminRole", "Security", "IAM")


def test_match_key_maps_a_null_resource_to_the_empty_string() -> None:
    # A template-level finding, on both sides. "None" would collide with a
    # resource legitimately named None; "" cannot be a logical ID.
    assert metrics.match_key(expectation(resource=None))[0] == ""
    assert metrics.match_key(finding(resource=None))[0] == ""


def test_match_key_ignores_severity() -> None:
    # The whole reason a severity mismatch is measured separately.
    assert metrics.match_key(expectation(severity="CRITICAL")) == metrics.match_key(
        expectation(severity="LOW")
    )


@pytest.mark.parametrize(
    "field", ["resource", "normalized_category", "finding_type"]
)
def test_match_key_rejects_an_item_missing_a_key_field(field: str) -> None:
    item = expectation()
    del item[field]
    # Not defaulted: a missing category would look like a detection failure
    # rather than like malformed input.
    with pytest.raises(metrics.MetricsInputError):
        metrics.match_key(item)


def test_a_present_but_null_resource_is_not_a_missing_field() -> None:
    assert metrics.match_key(expectation(resource=None)) == ("", "Security", "Encryption")


def test_severity_of_rejects_an_item_without_severity() -> None:
    item = expectation()
    del item["severity"]
    with pytest.raises(metrics.MetricsInputError):
        metrics.severity_of(item)


def test_detection_class_of_rejects_an_expectation_without_one() -> None:
    item = expectation()
    del item["detection_class"]
    with pytest.raises(metrics.MetricsInputError):
        metrics.detection_class_of(item)


# ---------------------------------------------------------------------------
# compute: the four rates and the three counts
# ---------------------------------------------------------------------------


def test_exact_match_scores_everything_at_100_with_no_false_positives() -> None:
    expected = [expectation(resource="A"), expectation(resource="B")]
    actual = [finding(resource="A"), finding(resource="B")]
    result = metrics.compute(expected, actual)
    assert result["matched_count"] == 2
    assert result["false_negative_count"] == 0
    assert result["false_positive_count"] == 0
    assert result["detection_rate"] == "100.0"
    assert result["recall"] == "100.0"
    assert result["precision"] == "100.0"
    assert result["severity_accuracy"] == "100.0"


def test_a_severity_mismatch_is_a_detection_and_not_a_miss() -> None:
    # Requirement 11 AC6: detection asks whether the problem was seen, severity
    # accuracy asks whether it was rated right. One mistake, one penalty.
    expected = [expectation(severity="CRITICAL")]
    actual = [finding(severity="MEDIUM")]
    result = metrics.compute(expected, actual)
    assert result["detection_rate"] == "100.0"
    assert result["recall"] == "100.0"
    assert result["precision"] == "100.0"
    assert result["false_negative_count"] == 0
    assert result["severity_match_count"] == 0
    assert result["severity_accuracy"] == "0.0"


def test_an_undetected_expectation_is_a_false_negative() -> None:
    expected = [expectation(resource="A"), expectation(resource="B")]
    actual = [finding(resource="A")]
    result = metrics.compute(expected, actual)
    assert result["matched_count"] == 1
    assert result["false_negative_count"] == 1
    assert result["false_positive_count"] == 0
    assert result["detection_rate"] == "50.0"
    assert result["recall"] == "50.0"
    assert result["precision"] == "100.0"


def test_a_finding_matching_no_expectation_is_a_false_positive() -> None:
    expected = [expectation(resource="A")]
    actual = [finding(resource="A"), finding(resource="B", identifier=2)]
    result = metrics.compute(expected, actual)
    assert result["matched_count"] == 1
    assert result["false_positive_count"] == 1
    assert result["detection_rate"] == "100.0"
    assert result["precision"] == "50.0"


def test_a_differing_category_on_the_same_resource_is_not_a_match() -> None:
    # The report emits one finding per resource per category, so two categories
    # on one resource are two independent expectations.
    expected = [expectation(resource="A", normalized_category="Encryption")]
    actual = [finding(resource="A", normalized_category="PublicAccess")]
    result = metrics.compute(expected, actual)
    assert result["matched_count"] == 0
    assert result["false_negative_count"] == 1
    assert result["false_positive_count"] == 1
    assert result["detection_rate"] == "0.0"


def test_finding_text_is_never_compared() -> None:
    expected = [expectation(note="wording that appears nowhere in the report")]
    actual = [finding(text="completely different wording")]
    assert metrics.compute(expected, actual)["detection_rate"] == "100.0"


def test_a_template_level_expectation_matches_a_template_level_finding() -> None:
    expected = [expectation(resource=None, normalized_category="TemplateQuality")]
    actual = [finding(resource=None, normalized_category="TemplateQuality")]
    result = metrics.compute(expected, actual)
    assert result["matched_count"] == 1
    assert result["false_positive_count"] == 0


def test_a_template_level_finding_does_not_match_a_resource_expectation() -> None:
    expected = [expectation(resource="A", normalized_category="TemplateQuality")]
    actual = [finding(resource=None, normalized_category="TemplateQuality")]
    result = metrics.compute(expected, actual)
    assert result["matched_count"] == 0
    assert result["false_negative_count"] == 1
    assert result["false_positive_count"] == 1


# ---------------------------------------------------------------------------
# One-to-one matching and its tie-break
# ---------------------------------------------------------------------------


def test_one_finding_cannot_satisfy_two_expectations() -> None:
    expected = [expectation(severity="HIGH"), expectation(severity="HIGH")]
    actual = [finding(severity="HIGH")]
    result = metrics.compute(expected, actual)
    assert result["matched_count"] == 1
    assert result["false_negative_count"] == 1
    assert result["detection_rate"] == "50.0"


def test_duplicate_match_keys_are_served_in_ground_truth_order() -> None:
    # The first-written expectation gets the single available Finding, so which
    # severity is compared follows the order ground truth declares -- not the
    # order the review emitted anything in.
    actual = [finding(severity="LOW")]

    high_first = metrics.compute(
        [expectation(severity="HIGH"), expectation(severity="LOW")], actual
    )
    assert high_first["matched_count"] == 1
    assert high_first["severity_match_count"] == 0
    assert high_first["severity_accuracy"] == "0.0"

    low_first = metrics.compute(
        [expectation(severity="LOW"), expectation(severity="HIGH")], actual
    )
    assert low_first["matched_count"] == 1
    assert low_first["severity_match_count"] == 1
    assert low_first["severity_accuracy"] == "100.0"


def test_match_pairs_the_first_expectation_with_the_only_candidate() -> None:
    result = metrics.match(
        [expectation(severity="HIGH"), expectation(severity="LOW")],
        [finding(severity="LOW")],
    )
    assert result.pairs == ((0, 0),)
    assert result.unmatched_expected == (1,)
    assert result.unmatched_actual == ()


def test_surplus_candidates_become_false_positives_not_second_matches() -> None:
    result = metrics.match([expectation()], [finding(identifier=1), finding(identifier=2)])
    assert len(result.pairs) == 1
    assert len(result.unmatched_actual) == 1


# ---------------------------------------------------------------------------
# Permutation invariance
# ---------------------------------------------------------------------------


Case = Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]


def _mixed_case() -> Case:
    """An expectation set and a Finding set exercising every outcome at once.

    Holds a duplicate match key with differing severities, a missed expectation,
    and a false positive, so a permutation that changed any metric would change
    this one.
    """
    expected = [
        expectation(resource="A", severity="HIGH"),
        expectation(resource="A", severity="LOW"),
        expectation(resource="B", severity="MEDIUM"),
        expectation(resource="C", severity="HIGH", normalized_category="IAM",
                    detection_class=metrics.AGENT_DEPENDENT,
                    detected_by=("Agent Review",)),
    ]
    actual = [
        finding(resource="A", severity="HIGH", identifier=1, text="first on A"),
        finding(resource="A", severity="LOW", identifier=2, text="second on A"),
        finding(resource="B", severity="CRITICAL", identifier=3),
        finding(resource="D", severity="LOW", identifier=4, normalized_category="Logging"),
    ]
    return expected, actual


def test_no_metric_depends_on_the_order_findings_arrive_in() -> None:
    expected, actual = _mixed_case()
    baseline = metrics.compute(expected, actual)
    for permutation in itertools.permutations(actual):
        assert metrics.compute(expected, list(permutation)) == baseline


def test_per_category_metrics_do_not_depend_on_finding_order() -> None:
    expected, actual = _mixed_case()
    baseline = metrics.compute_by_category(expected, actual)
    for permutation in itertools.permutations(actual):
        assert metrics.compute_by_category(expected, list(permutation)) == baseline


def test_severity_accuracy_does_not_depend_on_which_duplicate_came_first() -> None:
    # Two candidates share a match key and differ in severity; both expectations
    # can be satisfied, so the pairing has to reach the severity-consistent one
    # regardless of report order.
    expected = [expectation(severity="HIGH"), expectation(severity="LOW")]
    actual = [
        finding(severity="HIGH", identifier=1, text="alpha"),
        finding(severity="LOW", identifier=2, text="beta"),
    ]
    forward = metrics.compute(expected, actual)
    reverse = metrics.compute(expected, list(reversed(actual)))
    assert forward == reverse
    assert forward["severity_accuracy"] == "100.0"


# ---------------------------------------------------------------------------
# Zero denominators
# ---------------------------------------------------------------------------


def test_no_expectations_and_no_findings_measures_nothing() -> None:
    result = metrics.compute([], [])
    assert result["detection_rate"] == metrics.NOT_APPLICABLE
    assert result["recall"] == metrics.NOT_APPLICABLE
    assert result["precision"] == metrics.NOT_APPLICABLE
    assert result["severity_accuracy"] == metrics.NOT_APPLICABLE
    assert result["false_positive_count"] == 0


def test_no_expectations_still_counts_false_positives() -> None:
    # A clean case that produced a finding: detection rate is unmeasurable,
    # precision is 0.0, and the false positive is visible.
    result = metrics.compute([], [finding()])
    assert result["detection_rate"] == metrics.NOT_APPLICABLE
    assert result["recall"] == metrics.NOT_APPLICABLE
    assert result["precision"] == "0.0"
    assert result["false_positive_count"] == 1


def test_no_findings_leaves_precision_unmeasured() -> None:
    # TP + FP == 0: nothing was reported, so nothing can be said about how much
    # of the report was right. Detection rate is 0.0, which is measured.
    result = metrics.compute([expectation()], [])
    assert result["detection_rate"] == "0.0"
    assert result["recall"] == "0.0"
    assert result["precision"] == metrics.NOT_APPLICABLE
    assert result["severity_accuracy"] == metrics.NOT_APPLICABLE


def test_nothing_matched_leaves_severity_accuracy_unmeasured() -> None:
    # TP == 0 with findings present: precision is measured at 0.0, severity
    # accuracy is not measurable because no pair exists to compare.
    result = metrics.compute([expectation(resource="A")], [finding(resource="B")])
    assert result["detection_rate"] == "0.0"
    assert result["precision"] == "0.0"
    assert result["severity_accuracy"] == metrics.NOT_APPLICABLE


def test_not_applicable_is_distinct_from_zero() -> None:
    unmeasured = metrics.compute([], [])["detection_rate"]
    measured_zero = metrics.compute([expectation()], [])["detection_rate"]
    assert unmeasured == "N/A"
    assert measured_zero == "0.0"
    assert unmeasured != measured_zero


# ---------------------------------------------------------------------------
# Percentage formatting
# ---------------------------------------------------------------------------


def test_percentage_returns_none_only_for_a_zero_denominator() -> None:
    assert metrics.percentage(0, 0) is None
    assert metrics.percentage(0, 1) == 0.0
    assert metrics.percentage(1, 2) == 50.0


@pytest.mark.parametrize(
    "value,rendered",
    [
        (None, "N/A"),
        (0.0, "0.0"),
        (100.0, "100.0"),
        (1 / 3 * 100, "33.3"),
        (2 / 3 * 100, "66.7"),
        (1 / 8 * 100, "12.5"),
    ],
)
def test_format_percentage_emits_one_decimal_place(
    value: Optional[float], rendered: str
) -> None:
    assert metrics.format_percentage(value) == rendered


@pytest.mark.parametrize(
    "matched,total,rendered",
    [(1, 3, "33.3"), (2, 3, "66.7"), (1, 8, "12.5"), (5, 6, "83.3"), (7, 7, "100.0")],
)
def test_detection_rate_is_rendered_to_one_decimal_place(
    matched: int, total: int, rendered: str
) -> None:
    expected = [expectation(resource="R{0}".format(index)) for index in range(total)]
    actual = [finding(resource="R{0}".format(index)) for index in range(matched)]
    assert metrics.compute(expected, actual)["detection_rate"] == rendered


def test_every_rate_is_a_string() -> None:
    # A float here would still satisfy an equality assertion on its value while
    # breaking byte-identical output.
    result = metrics.compute([expectation()], [finding()])
    for key in ("detection_rate", "recall", "precision", "severity_accuracy"):
        assert isinstance(result[key], str), key


# ---------------------------------------------------------------------------
# category_status
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "detection_rate,has_deterministic,status",
    [
        (100.0, True, metrics.STATUS_PASS),
        (99.9, True, metrics.STATUS_FAIL),
        (50.0, True, metrics.STATUS_FAIL),
        (0.0, True, metrics.STATUS_FAIL),
        # No deterministic expectation: measured and reported, never failed.
        (0.0, False, metrics.STATUS_INFO),
        (100.0, False, metrics.STATUS_INFO),
        (None, False, metrics.STATUS_INFO),
        # Contradictory input: neither a pass nor an invented CI failure.
        (None, True, metrics.STATUS_INFO),
    ],
)
def test_category_status(
    detection_rate: Optional[float], has_deterministic: bool, status: str
) -> None:
    assert metrics.category_status(detection_rate, has_deterministic) == status


# ---------------------------------------------------------------------------
# compute_by_category and the pass/fail rule
# ---------------------------------------------------------------------------


def test_a_missed_deterministic_expectation_fails_its_category() -> None:
    expected = [
        expectation(resource="A", normalized_category="IAM"),
        expectation(resource="B", normalized_category="IAM"),
    ]
    actual = [finding(resource="A", normalized_category="IAM")]
    per_category = metrics.compute_by_category(expected, actual)
    entry = per_category["IAM"]
    assert entry["deterministic_expected_count"] == 2
    assert entry["deterministic_matched_count"] == 1
    assert entry["deterministic_detection_rate"] == "50.0"
    assert entry["status"] == metrics.STATUS_FAIL
    assert metrics.has_failure(per_category) is True


def test_a_missed_agent_dependent_expectation_does_not_fail_its_category() -> None:
    # Requirement 11 AC8: agent output is not deterministic, so a threshold on it
    # would make CI flaky rather than informative.
    expected = [
        expectation(
            resource="A",
            normalized_category="IAM",
            detection_class=metrics.AGENT_DEPENDENT,
            detected_by=("Agent Review",),
        )
    ]
    per_category = metrics.compute_by_category(expected, [])
    entry = per_category["IAM"]
    assert entry["detection_rate"] == "0.0"
    assert entry["deterministic_expected_count"] == 0
    assert entry["deterministic_detection_rate"] == metrics.NOT_APPLICABLE
    assert entry["status"] == metrics.STATUS_INFO
    assert metrics.has_failure(per_category) is False


def test_a_mixed_category_passes_on_its_deterministic_expectations_alone() -> None:
    expected = [
        expectation(resource="A", normalized_category="IAM"),
        expectation(
            resource="B",
            normalized_category="IAM",
            detection_class=metrics.AGENT_DEPENDENT,
            detected_by=("Agent Review",),
        ),
    ]
    actual = [finding(resource="A", normalized_category="IAM")]
    entry = metrics.compute_by_category(expected, actual)["IAM"]
    assert entry["detection_rate"] == "50.0"  # the agent expectation was missed
    assert entry["deterministic_detection_rate"] == "100.0"
    assert entry["status"] == metrics.STATUS_PASS


def test_every_category_passes_when_everything_was_detected() -> None:
    expected = [
        expectation(resource="A", normalized_category="IAM"),
        expectation(resource="B", normalized_category="Encryption"),
    ]
    actual = [
        finding(resource="A", normalized_category="IAM"),
        finding(resource="B", normalized_category="Encryption"),
    ]
    per_category = metrics.compute_by_category(expected, actual)
    assert sorted(per_category) == ["Encryption", "IAM"]
    assert all(entry["status"] == metrics.STATUS_PASS for entry in per_category.values())
    assert metrics.has_failure(per_category) is False


def test_a_category_only_the_report_mentions_still_appears() -> None:
    # Where false positives live: no expectation names Logging at all.
    per_category = metrics.compute_by_category(
        [expectation(normalized_category="IAM")],
        [finding(normalized_category="Logging")],
    )
    assert sorted(per_category) == ["IAM", "Logging"]
    logging_entry = per_category["Logging"]
    assert logging_entry["false_positive_count"] == 1
    assert logging_entry["detection_rate"] == metrics.NOT_APPLICABLE
    assert logging_entry["status"] == metrics.STATUS_INFO


def test_categories_are_keyed_in_sorted_order() -> None:
    expected = [
        expectation(resource="A", normalized_category="Tagging"),
        expectation(resource="B", normalized_category="IAM"),
        expectation(resource="C", normalized_category="Encryption"),
    ]
    assert list(metrics.compute_by_category(expected, [])) == [
        "Encryption",
        "IAM",
        "Tagging",
    ]


def test_partitioning_by_category_preserves_the_global_totals() -> None:
    # Category is part of the match key, so matching per category and matching
    # everything at once cannot disagree.
    expected, actual = _mixed_case()
    overall = metrics.compute(expected, actual)
    per_category = metrics.compute_by_category(expected, actual)
    for key in ("matched_count", "false_negative_count", "false_positive_count"):
        assert sum(entry[key] for entry in per_category.values()) == overall[key], key


def test_has_failure_is_false_for_an_empty_result() -> None:
    assert metrics.has_failure({}) is False


# ---------------------------------------------------------------------------
# --mode filtering (Requirement 11 AC10, AC11)
# ---------------------------------------------------------------------------


def test_expectations_are_filtered_by_detected_by() -> None:
    expected = [
        expectation(resource="A", detected_by=("cfn-guard",)),
        expectation(resource="B", detected_by=("IAM Review",)),
    ]
    kept = metrics.filter_by_source(expected, "cfn-guard")
    assert [item["resource"] for item in kept] == ["A"]


def test_findings_are_filtered_by_their_source_list() -> None:
    actual = [
        finding(resource="A", source=("cfn-lint",)),
        finding(resource="B", source=("cfn-guard",)),
    ]
    kept = metrics.filter_by_source(actual, "cfn-lint")
    assert [item["Resource"] for item in kept] == ["A"]


def test_an_item_naming_several_sources_survives_each_single_source_mode() -> None:
    # A merged Finding carries every Source that reached it, and ground truth
    # names every Source expected to reach it. Both stay in scope either way.
    pair = [expectation(detected_by=("IAM Review", "cfn-guard")),
            finding(source=("cfn-guard", "IAM Review"))]
    for source in ("cfn-guard", "IAM Review"):
        assert len(metrics.filter_by_source(pair, source)) == 2


def test_combined_mode_filters_nothing() -> None:
    expected = [expectation(resource="A"), expectation(resource="B")]
    assert metrics.filter_by_source(expected, None) == expected


def test_filtering_narrows_the_metrics_to_the_selected_source() -> None:
    # The whole point of the mode: cfn-lint is not blamed for what cfn-guard
    # was expected to find.
    expected = [
        expectation(resource="A", detected_by=("cfn-lint",)),
        expectation(resource="B", detected_by=("cfn-guard",)),
    ]
    actual = [finding(resource="A", source=("cfn-lint",))]
    lint_only = metrics.compute(
        metrics.filter_by_source(expected, "cfn-lint"),
        metrics.filter_by_source(actual, "cfn-lint"),
    )
    assert lint_only["expected_count"] == 1
    assert lint_only["detection_rate"] == "100.0"
    assert lint_only["false_positive_count"] == 0


def test_an_item_naming_no_source_is_excluded_from_single_source_modes() -> None:
    item = expectation()
    del item["detected_by"]
    assert metrics.sources_of(item) == []
    assert metrics.filter_by_source([item], "cfn-guard") == []
    assert metrics.filter_by_source([item], None) == [item]


def test_a_source_written_as_a_bare_string_is_accepted() -> None:
    assert metrics.sources_of({"detected_by": "cfn-guard"}) == ["cfn-guard"]


def test_filter_by_detection_class_selects_only_that_class() -> None:
    expected = [
        expectation(resource="A", detection_class=metrics.DETERMINISTIC),
        expectation(resource="B", detection_class=metrics.AGENT_DEPENDENT),
    ]
    assert [
        item["resource"]
        for item in metrics.filter_by_detection_class(expected, metrics.DETERMINISTIC)
    ] == ["A"]
    assert [
        item["resource"]
        for item in metrics.filter_by_detection_class(expected, metrics.AGENT_DEPENDENT)
    ] == ["B"]


# ---------------------------------------------------------------------------
# Output shape and determinism
# ---------------------------------------------------------------------------


def test_compute_returns_exactly_the_declared_keys_in_order() -> None:
    assert list(metrics.compute([expectation()], [finding()])) == list(metrics.METRIC_KEYS)


def test_a_category_entry_returns_exactly_the_declared_keys_in_order() -> None:
    entry = metrics.compute_by_category([expectation()], [finding()])["Encryption"]
    assert list(entry) == list(metrics.CATEGORY_KEYS)


def test_category_keys_extend_metric_keys() -> None:
    assert metrics.CATEGORY_KEYS[: len(metrics.METRIC_KEYS)] == metrics.METRIC_KEYS


def test_the_serialized_result_is_byte_identical_between_calls() -> None:
    expected, actual = _mixed_case()

    def serialize() -> str:
        return json.dumps(
            {
                "overall": metrics.compute(expected, actual),
                "by_category": metrics.compute_by_category(expected, actual),
            },
            sort_keys=True,
        )

    assert serialize() == serialize()


def test_compute_does_not_mutate_its_inputs() -> None:
    expected, actual = _mixed_case()
    before = json.dumps([expected, actual], sort_keys=True)
    metrics.compute(expected, actual)
    metrics.compute_by_category(expected, actual)
    assert json.dumps([expected, actual], sort_keys=True) == before


def test_counts_are_integers() -> None:
    result = metrics.compute([expectation()], [finding()])
    for key in metrics.METRIC_KEYS:
        if key.endswith("_count"):
            assert isinstance(result[key], int), key


# ---------------------------------------------------------------------------
# The field mapping cannot drift from either document
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def schema() -> Dict[str, Any]:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def test_report_side_field_names_exist_in_the_finding_schema() -> None:
    # Renaming a Finding field in iacreview.finding has to fail here rather than
    # make every expectation silently unmatchable.
    report_side = {names[1] for names in metrics.FIELD_ALIASES.values()}
    assert report_side <= set(FINDING_FIELDS), sorted(report_side - set(FINDING_FIELDS))


def test_ground_truth_side_field_names_exist_in_the_case_schema(
    schema: Dict[str, Any]
) -> None:
    declared = set(schema["$defs"]["expectedFinding"]["properties"])
    ground_truth_side = {names[0] for names in metrics.FIELD_ALIASES.values()}
    assert ground_truth_side <= declared, sorted(ground_truth_side - declared)


def test_detection_class_is_a_ground_truth_only_field(schema: Dict[str, Any]) -> None:
    # It has no Finding counterpart, so it stays out of FIELD_ALIASES: a report
    # says which Source found something, not whether reasoning was needed.
    assert metrics.DETECTION_CLASS_FIELD in schema["$defs"]["expectedFinding"]["properties"]
    assert metrics.DETECTION_CLASS_FIELD not in FINDING_FIELDS
    assert metrics.DETECTION_CLASS_FIELD not in metrics.FIELD_ALIASES


def test_detection_class_vocabulary_matches_the_case_schema(
    schema: Dict[str, Any]
) -> None:
    entry = schema["$defs"]["expectedFinding"]["properties"]["detection_class"]
    assert tuple(entry["enum"]) == metrics.DETECTION_CLASSES


def test_the_match_key_uses_exactly_the_three_fields_the_schema_marks_as_such(
    schema: Dict[str, Any]
) -> None:
    # The schema says which fields are part of the match key, in prose, in each
    # field's description. Severity's description says the opposite.
    properties = schema["$defs"]["expectedFinding"]["properties"]
    for field in ("resource", "normalized_category", "finding_type"):
        assert "Part of the match key" in properties[field]["description"], field
    assert "not part of the match key" in properties["severity"]["description"]


# ---------------------------------------------------------------------------
# Deferred metrics stay documented rather than half-implemented
# ---------------------------------------------------------------------------


def test_deferred_metrics_are_not_computed() -> None:
    computed = set(metrics.METRIC_KEYS) | set(metrics.CATEGORY_KEYS)
    for name in metrics.DEFERRED_METRICS:
        key = name.lower().replace(" ", "_")
        assert key not in computed, name


def test_deferred_metrics_are_named_in_the_benchmark_readme() -> None:
    readme = README_PATH.read_text(encoding="utf-8")
    for name in metrics.DEFERRED_METRICS:
        assert name in readme, name


# ---------------------------------------------------------------------------
# compute_diagnostics (Requirement 19 AC3, AC6)
# ---------------------------------------------------------------------------
#
# Diagnostics are deterministic functions of ground truth that never bear on
# PASS or FAIL. A case declaring no expectation for a diagnostic records N/A
# rather than 0 or an absent key, so the block is the same shape whatever the
# case declared.


def test_diagnostics_return_exactly_the_declared_keys_in_order() -> None:
    result = metrics.compute_diagnostics([expectation()], [finding()], {})
    assert list(result) == list(metrics.DIAGNOSTIC_KEYS)


def test_a_case_declaring_no_expectation_records_not_applicable() -> None:
    # Requirement 19 AC6: not "0", which would say "measured, found nothing".
    result = metrics.compute_diagnostics([expectation()], [finding()], {})
    assert result["remediation_accuracy"] == metrics.NOT_APPLICABLE
    assert result["human_intervention_count"] == metrics.NOT_APPLICABLE


def test_human_intervention_count_is_echoed_when_declared() -> None:
    case = {metrics.HUMAN_INTERVENTION_EXPECTATION_FIELD: 3}
    result = metrics.compute_diagnostics([], [], case)
    assert result["human_intervention_count"] == 3


def test_a_boolean_human_intervention_declaration_is_not_a_count() -> None:
    # bool is an int in Python; a True must not read as 1.
    case = {metrics.HUMAN_INTERVENTION_EXPECTATION_FIELD: True}
    result = metrics.compute_diagnostics([], [], case)
    assert result["human_intervention_count"] == metrics.NOT_APPLICABLE


def test_remediation_accuracy_is_the_share_of_declared_remediations_cleared() -> None:
    first = expectation(resource="A")
    first[metrics.REMEDIATION_EXPECTATION_FIELD] = "enable encryption"
    second = expectation(resource="B")
    second[metrics.REMEDIATION_EXPECTATION_FIELD] = "add a bucket policy"
    expected = [first, second]
    actual = [
        finding(resource="A", text="A"),
        finding(resource="B", text="B"),
    ]
    # Only A's matched finding suggests the expected remediation.
    actual[0]["SuggestedRemediation"] = "Please enable encryption on the bucket."
    actual[1]["SuggestedRemediation"] = "Restrict public access."
    result = metrics.compute_diagnostics(expected, actual, {})
    assert result["remediation_accuracy"] == "50.0"


def test_remediation_accuracy_is_not_applicable_without_a_declaration() -> None:
    # No expectation declares a remediation, so there is nothing to measure.
    result = metrics.compute_diagnostics([expectation()], [finding()], {})
    assert result["remediation_accuracy"] == metrics.NOT_APPLICABLE


def test_review_time_remains_the_only_deferred_metric() -> None:
    # v0.8.0 implemented the other two; Review Time stays deferred because it is
    # environment-dependent and cannot enter a byte-identical document.
    assert metrics.DEFERRED_METRICS == ("Review Time",)
    computed = set(metrics.METRIC_KEYS) | set(metrics.CATEGORY_KEYS) | set(
        metrics.DIAGNOSTIC_KEYS
    )
    for name in metrics.DEFERRED_METRICS:
        assert name.lower().replace(" ", "_") not in computed, name


def test_the_implemented_diagnostics_are_no_longer_deferred() -> None:
    for key in metrics.DIAGNOSTIC_KEYS:
        readable = key.replace("_", " ").title()
        assert readable not in metrics.DEFERRED_METRICS, key
