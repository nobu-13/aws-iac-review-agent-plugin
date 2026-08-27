"""Checks for the parts of ``benchmark/harness/run_benchmark.py`` that need no review.

The harness has two halves. One reads case files, resolves paths, filters by mode
and shapes the output; the other starts the review. This file covers the first
half, plus the failure branches of the second using a stand-in orchestrator, so
the expensive question -- does a real review report what a case expects -- is
left to ``tests/integration/test_benchmark_harness.py``.

Four things here are load-bearing and easy to lose:

**The plugin root is two levels up, not three.** The harness is not a Skill entry
point, so ``bootstrap.SCRIPT_DEPTH_TO_PLUGIN_ROOT`` does not apply to it. Both
depths are asserted, and asserted to differ, so a refactor that "unifies" them
fails here rather than deriving the directory above the plugin at run time.

**The mode table maps mode names to the plugin's Source names.**
``metrics.filter_by_source`` takes a Source name as an argument and knows nothing
about ``--mode``; the mapping is this module's, and it is checked against
``iacreview``'s own constants rather than against string literals.

**Aggregate numbers do not cross-match between cases.** Two cases may use the
same logical ID for the same kind of problem. The namespacing that keeps them
apart is asserted on the pooled metrics directly, because the failure it prevents
is silent: a case's missed expectation satisfied by another case's finding.

**A broken case is one unevaluated case, not a dead run.** Every ``CaseError``
branch is exercised, since each is a way ``benchmark/cases/`` can be wrong while
the rest of it is fine.
"""

from __future__ import annotations

import dataclasses
import json
import os
import stat
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from benchmark.harness import metrics, run_benchmark
from iacreview import bootstrap, cfnguard, cfnlint, exitcodes, iam, pathguard
from iacreview.errors import MappingFileError, ToolTimeoutError

# tests/unit/test_run_benchmark.py -> tests/unit -> tests -> plugin root
PLUGIN_ROOT: Path = Path(__file__).resolve().parents[2]
HARNESS: Path = PLUGIN_ROOT / "benchmark" / "harness" / "run_benchmark.py"

#: A template whose single resource carries a defect the deterministic IAM
#: detectors reach: Action "*" on Resource "*". No external tool is involved, so
#: it works wherever Python does.
WILDCARD_TEMPLATE = """AWSTemplateFormatVersion: "2010-09-09"
Description: A synthetic template for the harness tests. Do not deploy.
Resources:
  AdminPolicy:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      Description: Grants every action on every resource.
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Sid: AllowEverything
            Effect: Allow
            Action: "*"
            Resource: "*"
"""


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------


def expectation(
    resource: Optional[str] = "AdminPolicy",
    normalized_category: str = "IAM",
    finding_type: str = "Security",
    severity: str = "CRITICAL",
    detection_class: str = metrics.DETERMINISTIC,
    detected_by: Any = ("IAM Review",),
) -> Dict[str, Any]:
    """One ``expected_findings`` entry."""
    return {
        "resource": resource,
        "normalized_category": normalized_category,
        "finding_type": finding_type,
        "severity": severity,
        "detection_class": detection_class,
        "detected_by": list(detected_by),
        "note": "A deliberate defect.",
    }


def finding(
    resource: Optional[str] = "AdminPolicy",
    normalized_category: str = "IAM",
    finding_type: str = "Security",
    severity: str = "CRITICAL",
    source: Any = ("IAM Review",),
) -> Dict[str, Any]:
    """One report Finding, in the report's own spelling."""
    return {
        "Resource": resource,
        "Normalized_Category": normalized_category,
        "FindingType": finding_type,
        "Severity": severity,
        "Source": list(source),
    }


def ground_truth(
    case_id: str = "case-001-example",
    template: str = "template.yaml",
    expectations: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """One ``ground_truth.json`` document."""
    entries = [expectation()] if expectations is None else expectations
    return {
        "schema_version": "1.0.0",
        "case_id": case_id,
        "template": template,
        "description": "A synthetic case for the harness tests.",
        "authored_before_review": True,
        "expected_finding_count": len(entries),
        "expected_findings": entries,
        "expected_findings_agent_only": [],
        "expected_findings_human_review": [],
    }


def write_case(
    cases_dir: Path,
    case_id: str,
    *,
    document: Optional[Any] = None,
    document_text: Optional[str] = None,
    template_text: Optional[str] = "Resources: {}\n",
) -> Path:
    """Create one case directory. Returns it.

    ``document_text`` writes the ground truth verbatim, for the malformed cases;
    ``template_text`` of ``None`` leaves the template out.
    """
    case_dir = cases_dir / case_id
    case_dir.mkdir(parents=True)
    if document_text is None:
        payload = ground_truth(case_id=case_id) if document is None else document
        document_text = json.dumps(payload)
    (case_dir / "ground_truth.json").write_text(document_text, encoding="utf-8")
    if template_text is not None:
        (case_dir / "template.yaml").write_text(template_text, encoding="utf-8")
    return case_dir


# ---------------------------------------------------------------------------
# The plugin root, at this script's depth
# ---------------------------------------------------------------------------


def test_the_harness_derives_the_plugin_root_two_levels_up() -> None:
    assert run_benchmark.PLUGIN_ROOT_DEPTH == 2
    assert run_benchmark.derive_plugin_root(HARNESS) == PLUGIN_ROOT


def test_the_harness_depth_is_not_the_skill_entry_point_depth() -> None:
    # The whole reason the constant is local. bootstrap's 3 would derive the
    # directory the plugin was unpacked into, which holds no plugin.json.
    assert run_benchmark.PLUGIN_ROOT_DEPTH != bootstrap.SCRIPT_DEPTH_TO_PLUGIN_ROOT
    assert bootstrap.derive_plugin_root(HARNESS) == PLUGIN_ROOT.parent


def test_the_harness_lives_where_that_depth_says_it_does() -> None:
    relative = HARNESS.relative_to(PLUGIN_ROOT)
    assert relative == Path("benchmark/harness/run_benchmark.py")
    assert len(relative.parts) == run_benchmark.PLUGIN_ROOT_DEPTH + 1


def test_verify_plugin_root_accepts_the_real_layout() -> None:
    assert run_benchmark.verify_plugin_root(HARNESS) == pathguard.plugin_root()


def test_verify_plugin_root_rejects_a_script_outside_the_plugin(tmp_path: Path) -> None:
    script = tmp_path / "benchmark" / "harness" / "run_benchmark.py"
    script.parent.mkdir(parents=True)
    script.write_text("", encoding="utf-8")
    # Derives tmp_path, which is not where the imported iacreview lives.
    with pytest.raises(MappingFileError) as caught:
        run_benchmark.verify_plugin_root(script)
    assert "plugin root mismatch" in str(caught.value)


def test_derive_plugin_root_rejects_a_path_too_close_to_the_filesystem_root() -> None:
    with pytest.raises(MappingFileError) as caught:
        run_benchmark.derive_plugin_root(Path(os.sep) / "run_benchmark.py")
    assert "cannot derive the plugin root" in str(caught.value)


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------


def test_the_benchmark_verdict_codes_are_outside_the_plugin_table() -> None:
    # tests/unit/test_exitcodes.py pins the plugin's table to nine values that
    # are part of its contract with host Agents. A benchmark regression is not
    # one of those failure classes, so it must not reuse one of their numbers.
    plugin_codes = set(exitcodes.EXIT_CODES.values())
    assert run_benchmark.BENCHMARK_FAILURE not in plugin_codes
    assert run_benchmark.CASE_NOT_EVALUATED not in plugin_codes


def test_every_harness_exit_code_is_distinct() -> None:
    values = list(run_benchmark.HARNESS_EXIT_CODES.values())
    assert len(set(values)) == len(values)


def test_harness_exit_codes_include_the_two_verdicts_and_ok() -> None:
    table = run_benchmark.HARNESS_EXIT_CODES
    assert table["OK"] == exitcodes.OK
    assert table["BENCHMARK_FAILURE"] == run_benchmark.BENCHMARK_FAILURE
    assert table["CASE_NOT_EVALUATED"] == run_benchmark.CASE_NOT_EVALUATED


# ---------------------------------------------------------------------------
# The --mode table
# ---------------------------------------------------------------------------


def test_the_four_modes_of_the_design_table_exist() -> None:
    assert run_benchmark.MODE_NAMES == (
        "cfn-guard-only",
        "cfn-lint-only",
        "combined",
        "iam-only",
    )
    assert run_benchmark.DEFAULT_MODE == "combined"


def test_combined_filters_nothing_and_restates_no_default() -> None:
    mode = run_benchmark.MODES["combined"]
    # None is what metrics.filter_by_source reads as "keep everything".
    assert mode.source is None
    # No --sources: the orchestrator's default is all three Sources, and a copy
    # of that default here could drift from it.
    assert mode.cli_sources == ()
    assert mode.sources_evaluated == run_benchmark.ALL_SOURCES


@pytest.mark.parametrize(
    "mode_name,source",
    [
        ("cfn-lint-only", cfnlint.SOURCE_NAME),
        ("cfn-guard-only", cfnguard.SOURCE_NAME),
        ("iam-only", iam.SOURCE_NAME),
    ],
)
def test_each_single_source_mode_filters_on_that_sources_canonical_name(
    mode_name: str, source: str
) -> None:
    # Compared against iacreview's constants, not literals: the name in
    # Finding.Source and in ground truth's detected_by is the same string, and
    # this is the only place a mode name is translated into it.
    mode = run_benchmark.MODES[mode_name]
    assert mode.source == source
    assert mode.sources_evaluated == (source,)


def test_the_iam_mode_passes_the_hyphenated_alias_to_the_orchestrator() -> None:
    # The canonical Source name contains a space; the orchestrator accepts this
    # alias for that reason. The alias must not reach metrics, which compares
    # against the canonical name.
    mode = run_benchmark.MODES["iam-only"]
    assert mode.cli_sources == (run_benchmark.IAM_SOURCE_CLI_ALIAS,)
    assert " " not in run_benchmark.IAM_SOURCE_CLI_ALIAS
    assert mode.source != run_benchmark.IAM_SOURCE_CLI_ALIAS


def test_every_mode_is_keyed_by_its_own_name() -> None:
    for name, mode in run_benchmark.MODES.items():
        assert mode.name == name


# ---------------------------------------------------------------------------
# --filter-only: the same mode, obtained the other way
# ---------------------------------------------------------------------------
#
# The flag acts in exactly one place, review_mode(), and only on which Sources the
# review is started with. What is compared afterwards is the mode as selected, so
# no test below has to check that the filter still happens: nothing downstream can
# see the flag.


@pytest.mark.parametrize("mode_name", sorted(run_benchmark.MODE_NAMES))
def test_without_the_flag_a_mode_is_reviewed_as_itself(mode_name: str) -> None:
    mode = run_benchmark.MODES[mode_name]
    assert run_benchmark.review_mode(mode, False) is mode


@pytest.mark.parametrize(
    "mode_name", ["cfn-lint-only", "cfn-guard-only", "iam-only"]
)
def test_the_flag_clears_the_source_disabling_and_keeps_the_filter(
    mode_name: str,
) -> None:
    # The whole of --filter-only: the review is asked for every Source, and the
    # Source the numbers are about is unchanged, so the comparison is the same
    # comparison.
    mode = run_benchmark.MODES[mode_name]
    reviewed = run_benchmark.review_mode(mode, True)

    assert reviewed.cli_sources == ()
    assert reviewed.source == mode.source
    assert reviewed.sources_evaluated == mode.sources_evaluated
    assert reviewed.name == mode.name
    # A copy, so the mode table cannot be mutated by a run.
    assert run_benchmark.MODES[mode_name].cli_sources == mode.cli_sources


def test_the_flag_changes_nothing_for_combined() -> None:
    # combined already runs every Source, so the flag is redundant rather than
    # wrong. Accepted, not refused: a sweep over the modes would otherwise have to
    # special-case one of them, and that sweep is what the flag is for.
    mode = run_benchmark.MODES["combined"]
    assert run_benchmark.review_mode(mode, True) == mode


def test_the_flag_is_the_only_difference_between_the_two_review_modes() -> None:
    for name in run_benchmark.MODE_NAMES:
        mode = run_benchmark.MODES[name]
        default = run_benchmark.review_mode(mode, False)
        filtered = run_benchmark.review_mode(mode, True)
        differing = {
            field.name
            for field in dataclasses.fields(mode)
            if getattr(default, field.name) != getattr(filtered, field.name)
        }
        assert differing <= {"cli_sources"}, name


def test_only_the_sources_needing_an_external_tool_are_in_the_tool_table() -> None:
    # Read to explain an empty --filter-only measurement. The IAM Source needs no
    # tool, so an iam-only run has nothing to explain.
    assert dict(run_benchmark.TOOL_BY_SOURCE) == {
        cfnlint.SOURCE_NAME: "cfn-lint",
        cfnguard.SOURCE_NAME: "cfn-guard",
    }
    assert iam.SOURCE_NAME not in run_benchmark.TOOL_BY_SOURCE
    # Every key is a Source some mode measures, so the lookup cannot silently
    # miss.
    measured = {mode.source for mode in run_benchmark.MODES.values()}
    assert set(run_benchmark.TOOL_BY_SOURCE) <= measured


# ---------------------------------------------------------------------------
# Case discovery
# ---------------------------------------------------------------------------


def test_cases_are_discovered_from_the_filesystem_in_sorted_order(
    tmp_path: Path,
) -> None:
    # Created out of order on purpose: the aggregate consumes cases in this
    # order, so it must not depend on how the filesystem lists them.
    for name in ("case-003-c", "case-001-a", "case-002-b"):
        write_case(tmp_path, name)
    assert run_benchmark.discover_cases(tmp_path) == [
        "case-001-a",
        "case-002-b",
        "case-003-c",
    ]


def test_a_case_appearing_later_needs_no_edit_here(tmp_path: Path) -> None:
    write_case(tmp_path, "case-001-a")
    before = run_benchmark.discover_cases(tmp_path)
    write_case(tmp_path, "case-002-b")
    assert run_benchmark.discover_cases(tmp_path) == before + ["case-002-b"]


def test_a_directory_without_ground_truth_is_not_a_case(tmp_path: Path) -> None:
    # A partially created case, or a directory of shared fixtures. Refusing to
    # run at all would make every other case unmeasurable.
    (tmp_path / "notes").mkdir()
    (tmp_path / "notes" / "README.md").write_text("", encoding="utf-8")
    write_case(tmp_path, "case-001-a")
    assert run_benchmark.discover_cases(tmp_path) == ["case-001-a"]


def test_a_loose_file_is_not_a_case(tmp_path: Path) -> None:
    (tmp_path / "ground_truth.json").write_text("{}", encoding="utf-8")
    assert run_benchmark.discover_cases(tmp_path) == []


def test_an_empty_cases_directory_discovers_nothing(tmp_path: Path) -> None:
    assert run_benchmark.discover_cases(tmp_path) == []


# ---------------------------------------------------------------------------
# Reading ground truth
# ---------------------------------------------------------------------------


def test_a_well_formed_ground_truth_loads(tmp_path: Path) -> None:
    case_dir = write_case(tmp_path, "case-001-a")
    document = run_benchmark.load_ground_truth(case_dir / "ground_truth.json")
    assert document["case_id"] == "case-001-a"


@pytest.mark.parametrize(
    "text,reason",
    [
        ("{", "truncated JSON"),
        ("", "empty file"),
        ("[]", "a JSON array where an object is required"),
        ('"text"', "a JSON string where an object is required"),
        ("null", "JSON null"),
    ],
)
def test_malformed_ground_truth_is_one_case_error(
    tmp_path: Path, text: str, reason: str
) -> None:
    path = tmp_path / "ground_truth.json"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(run_benchmark.CaseError) as caught:
        run_benchmark.load_ground_truth(path)
    assert caught.value.reason == run_benchmark.MALFORMED_GROUND_TRUTH, reason


def test_ground_truth_that_is_not_utf8_is_one_case_error(tmp_path: Path) -> None:
    # Untrusted input: binary content must fail safely, not raise out of the run.
    path = tmp_path / "ground_truth.json"
    path.write_bytes(b"\xff\xfe\x00{")
    with pytest.raises(run_benchmark.CaseError) as caught:
        run_benchmark.load_ground_truth(path)
    assert caught.value.reason == run_benchmark.MALFORMED_GROUND_TRUTH


def test_an_unreadable_ground_truth_is_one_case_error(tmp_path: Path) -> None:
    path = tmp_path / "ground_truth.json"
    path.write_text("{}", encoding="utf-8")
    path.chmod(0)
    if os.access(str(path), os.R_OK):  # pragma: no cover - running as root
        pytest.skip("the current user can read a mode 0 file")
    try:
        with pytest.raises(run_benchmark.CaseError) as caught:
            run_benchmark.load_ground_truth(path)
    finally:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    assert caught.value.reason == run_benchmark.MALFORMED_GROUND_TRUTH


# ---------------------------------------------------------------------------
# Which expectations are evaluated
# ---------------------------------------------------------------------------


def test_only_expected_findings_are_evaluated() -> None:
    # The reserved arrays exist so a future mode needs no format change
    # (Requirement 11 AC12). Evaluating them in v0.1 would score a review
    # against expectations it was never asked to produce.
    document = ground_truth(expectations=[expectation(resource="A")])
    document["expected_findings_agent_only"] = [expectation(resource="B")]
    document["expected_findings_human_review"] = [expectation(resource="C")]
    assert [
        item["resource"] for item in run_benchmark.expectations_of(document)
    ] == ["A"]


def test_expectations_keep_ground_truth_order() -> None:
    # metrics resolves duplicate match keys in this order, so it is part of the
    # measurement rather than a detail.
    entries = [expectation(resource="B"), expectation(resource="A")]
    assert run_benchmark.expectations_of(ground_truth(expectations=entries)) == entries


def test_an_empty_expectation_set_is_legal() -> None:
    # A clean case: nothing is expected, and any finding is a false positive.
    assert run_benchmark.expectations_of(ground_truth(expectations=[])) == []


@pytest.mark.parametrize(
    "value", [None, {}, "expected", 3, [1], ["text"], [None]]
)
def test_unreadable_expectations_are_not_an_empty_expectation_set(value: Any) -> None:
    # The distinction matters: an empty set scores a perfect run, so a broken
    # array must be an error rather than a pass.
    document = ground_truth()
    document["expected_findings"] = value
    with pytest.raises(run_benchmark.CaseError) as caught:
        run_benchmark.expectations_of(document)
    assert caught.value.reason == run_benchmark.MALFORMED_GROUND_TRUTH


# ---------------------------------------------------------------------------
# The template a case names
# ---------------------------------------------------------------------------


def test_the_named_template_resolves_inside_the_case_directory(tmp_path: Path) -> None:
    case_dir = write_case(tmp_path, "case-001-a")
    resolved = run_benchmark.template_path(case_dir, ground_truth())
    assert resolved == (case_dir / "template.yaml").resolve()


@pytest.mark.parametrize(
    "name",
    [
        "../../etc/passwd",
        "../template.yaml",
        "sub/template.yaml",
        "/etc/passwd",
        ".",
        "..",
        "",
    ],
)
def test_a_template_field_that_is_not_a_plain_file_name_is_refused(
    tmp_path: Path, name: str
) -> None:
    # The field is untrusted input, like the template it names. Path traversal is
    # rejected before any filesystem access.
    case_dir = write_case(tmp_path, "case-001-a")
    with pytest.raises(run_benchmark.CaseError) as caught:
        run_benchmark.template_path(case_dir, ground_truth(template=name))
    assert caught.value.reason == run_benchmark.MALFORMED_GROUND_TRUTH


@pytest.mark.parametrize("name", [None, 3, [], {"file": "template.yaml"}])
def test_a_template_field_that_is_not_a_string_is_refused(
    tmp_path: Path, name: Any
) -> None:
    case_dir = write_case(tmp_path, "case-001-a")
    with pytest.raises(run_benchmark.CaseError) as caught:
        run_benchmark.template_path(case_dir, ground_truth(template=name))
    assert caught.value.reason == run_benchmark.MALFORMED_GROUND_TRUTH


def test_a_template_name_carrying_a_shell_metacharacter_is_refused(
    tmp_path: Path,
) -> None:
    case_dir = write_case(tmp_path, "case-001-a")
    with pytest.raises(run_benchmark.CaseError) as caught:
        run_benchmark.template_path(case_dir, ground_truth(template="t;rm -rf.yaml"))
    assert caught.value.reason == run_benchmark.MALFORMED_GROUND_TRUTH


def test_an_absent_template_is_reported_as_missing(tmp_path: Path) -> None:
    case_dir = write_case(tmp_path, "case-001-a", template_text=None)
    with pytest.raises(run_benchmark.CaseError) as caught:
        run_benchmark.template_path(case_dir, ground_truth())
    assert caught.value.reason == run_benchmark.MISSING_TEMPLATE


def test_a_template_that_is_a_directory_is_reported_as_missing(
    tmp_path: Path,
) -> None:
    case_dir = write_case(tmp_path, "case-001-a", template_text=None)
    (case_dir / "template.yaml").mkdir()
    with pytest.raises(run_benchmark.CaseError) as caught:
        run_benchmark.template_path(case_dir, ground_truth())
    assert caught.value.reason == run_benchmark.MISSING_TEMPLATE


def test_a_template_symlinked_out_of_the_case_directory_is_refused(
    tmp_path: Path,
) -> None:
    # A name check cannot see this one: the name is plain, the target is not.
    outside = tmp_path / "outside.yaml"
    outside.write_text("Resources: {}\n", encoding="utf-8")
    case_dir = write_case(tmp_path / "cases", "case-001-a", template_text=None)
    (case_dir / "template.yaml").symlink_to(outside)
    with pytest.raises(run_benchmark.CaseError) as caught:
        run_benchmark.template_path(case_dir, ground_truth())
    assert caught.value.reason == run_benchmark.MALFORMED_GROUND_TRUTH


# ---------------------------------------------------------------------------
# Aggregation across cases
# ---------------------------------------------------------------------------


def test_namespacing_prefixes_the_resource_under_the_documents_own_spelling() -> None:
    prefixed_expectation = run_benchmark.namespaced(expectation(resource="A"), "case-1")
    prefixed_finding = run_benchmark.namespaced(finding(resource="A"), "case-1")
    assert prefixed_expectation["resource"] == "case-1::A"
    assert prefixed_finding["Resource"] == "case-1::A"
    # Still one comparable pair: both sides were prefixed the same way.
    assert metrics.match_key(prefixed_expectation) == metrics.match_key(
        prefixed_finding
    )


def test_namespacing_keeps_a_template_level_item_template_level() -> None:
    prefixed = run_benchmark.namespaced(expectation(resource=None), "case-1")
    assert prefixed["resource"] == "case-1::"
    assert metrics.match_key(prefixed)[0] == "case-1::"


def test_namespacing_does_not_mutate_its_input() -> None:
    item = expectation(resource="A")
    before = json.dumps(item, sort_keys=True)
    run_benchmark.namespaced(item, "case-1")
    assert json.dumps(item, sort_keys=True) == before


def test_namespacing_leaves_an_item_with_no_resource_field_to_metrics() -> None:
    item = expectation()
    del item["resource"]
    prefixed = run_benchmark.namespaced(item, "case-1")
    with pytest.raises(metrics.MetricsInputError):
        metrics.match_key(prefixed)


def test_pooling_two_cases_does_not_let_one_satisfy_the_other() -> None:
    # The failure this prevents is silent: both cases use the logical ID "Shared"
    # in the same category, one was detected and one was not. Pooled without a
    # prefix, the single finding would satisfy both expectations and the miss
    # would disappear.
    expected = [
        run_benchmark.namespaced(expectation(resource="Shared"), "case-001"),
        run_benchmark.namespaced(expectation(resource="Shared"), "case-002"),
    ]
    actual = [run_benchmark.namespaced(finding(resource="Shared"), "case-001")]
    pooled = metrics.compute(expected, actual)
    assert pooled["matched_count"] == 1
    assert pooled["false_negative_count"] == 1
    assert pooled["detection_rate"] == "50.0"


def test_the_pooled_numbers_are_the_sum_of_the_per_case_numbers() -> None:
    per_case = [
        ("case-001", [expectation(resource="A")], [finding(resource="A")]),
        ("case-002", [expectation(resource="A")], []),
    ]
    pooled_expected: List[Dict[str, Any]] = []
    pooled_actual: List[Dict[str, Any]] = []
    totals = {"matched_count": 0, "false_negative_count": 0, "expected_count": 0}
    for case_id, expected, actual in per_case:
        measured = metrics.compute(expected, actual)
        for key in totals:
            totals[key] += measured[key]
        pooled_expected.extend(
            run_benchmark.namespaced(item, case_id) for item in expected
        )
        pooled_actual.extend(
            run_benchmark.namespaced(item, case_id) for item in actual
        )

    pooled = metrics.compute(pooled_expected, pooled_actual)
    for key, value in totals.items():
        assert pooled[key] == value, key


# ---------------------------------------------------------------------------
# One verdict per case and per run
# ---------------------------------------------------------------------------


def test_a_case_passes_when_every_deterministic_expectation_was_detected() -> None:
    per_category = metrics.compute_by_category(
        [expectation(resource="A")], [finding(resource="A")]
    )
    assert run_benchmark.case_status(per_category) == metrics.STATUS_PASS


def test_a_case_fails_on_a_missed_deterministic_expectation() -> None:
    per_category = metrics.compute_by_category([expectation(resource="A")], [])
    assert run_benchmark.case_status(per_category) == metrics.STATUS_FAIL


def test_a_case_fails_when_one_of_several_categories_missed_something() -> None:
    expected = [
        expectation(resource="A", normalized_category="IAM"),
        expectation(resource="B", normalized_category="Encryption"),
    ]
    actual = [finding(resource="A", normalized_category="IAM")]
    per_category = metrics.compute_by_category(expected, actual)
    assert run_benchmark.case_status(per_category) == metrics.STATUS_FAIL


def test_an_agent_dependent_only_case_is_informational() -> None:
    # Requirement 11 AC8: measured, with no threshold. An undetected agent
    # expectation is not a CI failure.
    per_category = metrics.compute_by_category(
        [
            expectation(
                resource="A",
                detection_class=metrics.AGENT_DEPENDENT,
                detected_by=("Agent Review",),
            )
        ],
        [],
    )
    assert run_benchmark.case_status(per_category) == metrics.STATUS_INFO


def test_a_case_with_nothing_measured_is_informational() -> None:
    assert run_benchmark.case_status({}) == metrics.STATUS_INFO


@pytest.mark.parametrize(
    "expected,actual",
    [
        ([expectation(resource="A")], [finding(resource="A")]),
        ([expectation(resource="A")], []),
        ([], [finding(resource="A")]),
        ([], []),
        (
            [
                expectation(
                    resource="A",
                    detection_class=metrics.AGENT_DEPENDENT,
                    detected_by=("Agent Review",),
                )
            ],
            [],
        ),
    ],
)
def test_the_reported_status_and_the_exit_code_rule_agree(
    expected: List[Dict[str, Any]], actual: List[Dict[str, Any]]
) -> None:
    # The status string and the process exit code must never disagree: the first
    # is what a reader sees, the second is what CI acts on.
    per_category = metrics.compute_by_category(expected, actual)
    status = run_benchmark.case_status(per_category)
    assert (status == metrics.STATUS_FAIL) == metrics.has_failure(per_category)


# ---------------------------------------------------------------------------
# The output shape
# ---------------------------------------------------------------------------


def test_the_summary_carries_every_declared_key_even_with_no_cases() -> None:
    # A consumer never has to test for a key's existence, including in a run
    # where nothing was evaluated.
    summary = run_benchmark.Benchmark().summary()
    assert list(summary) == list(run_benchmark.SUMMARY_KEYS)


def test_an_empty_run_measures_nothing_rather_than_reporting_zero() -> None:
    summary = run_benchmark.Benchmark().summary()
    assert summary["metrics"]["detection_rate"] == metrics.NOT_APPLICABLE
    assert summary["categories"] == {}
    assert summary["status"] == metrics.STATUS_INFO
    assert summary["errors"] == []


def test_the_summary_metrics_are_exactly_the_metrics_modules_keys() -> None:
    summary = run_benchmark.Benchmark().summary()
    assert list(summary["metrics"]) == list(metrics.METRIC_KEYS)


def test_an_unevaluated_case_entry_has_the_same_keys_as_an_evaluated_one() -> None:
    entry = run_benchmark.Benchmark._unevaluated_entry(
        "case-001-a", "template.yaml", run_benchmark.REVIEW_FAILED
    )
    assert list(entry) == list(run_benchmark.CASE_KEYS)
    assert entry["evaluated"] is False
    assert entry["metrics"] is None
    assert entry["status"] is None


def test_the_summary_names_the_mode_and_the_sources_it_measured() -> None:
    benchmark = run_benchmark.Benchmark()
    benchmark.mode = run_benchmark.MODES["cfn-guard-only"]
    summary = benchmark.summary()
    assert summary["mode"] == "cfn-guard-only"
    assert summary["sources_evaluated"] == [cfnguard.SOURCE_NAME]
    # Fixed per mode, so the key does not describe which tools the host installed.
    assert summary["agent_findings_supplied"] is False


@pytest.mark.parametrize("filter_only", [False, True])
def test_the_summary_records_which_path_produced_the_numbers(
    filter_only: bool,
) -> None:
    # How the measurement was obtained, like agent_findings_supplied beside it. A
    # stored single-Source summary cannot be read without it: the filtered path can
    # report an empty measurement for an absent tool where the default path would
    # have reported an unevaluated case.
    benchmark = run_benchmark.Benchmark()
    benchmark.mode = run_benchmark.MODES["cfn-lint-only"]
    benchmark.filter_only = filter_only

    assert benchmark.summary()["filter_only"] is filter_only


def test_the_default_path_is_source_disabling() -> None:
    # design.md: "既定は実行時無効化". A fresh run measures the isolated Source.
    assert run_benchmark.Benchmark().filter_only is False
    assert run_benchmark.Benchmark().summary()["filter_only"] is False


def test_the_summary_states_no_value_the_host_decides() -> None:
    # filter_only comes from argv, so it does not weaken Requirement 16 AC11: one
    # invocation still prints the same bytes every time. A key derived from the
    # environment would not, which is why the absent-tool note goes to stderr.
    summary = run_benchmark.Benchmark().summary()
    assert isinstance(summary["filter_only"], bool)
    assert "tools" not in summary


def test_the_summary_carries_no_timing_field() -> None:
    # Review Time is a deferred metric, and an environment-dependent value in
    # stdout would break Requirement 16 AC11. It is not measured at all.
    text = json.dumps(run_benchmark.Benchmark().summary())
    for name in metrics.DEFERRED_METRICS:
        assert name.lower().replace(" ", "_") not in text


def test_every_case_reason_is_a_short_stable_token() -> None:
    # The reason is the only part of a failure that reaches stdout: a message
    # would carry host paths and tool wording into output that has to stay
    # byte-identical.
    for reason in run_benchmark.CASE_REASONS:
        assert reason == reason.lower()
        assert " " not in reason
        assert os.sep not in reason


def test_the_case_reason_vocabulary_is_closed() -> None:
    assert set(run_benchmark.CASE_REASONS) == {
        run_benchmark.UNSAFE_CASE_PATH,
        run_benchmark.MALFORMED_GROUND_TRUTH,
        run_benchmark.MISSING_TEMPLATE,
        run_benchmark.REVIEW_FAILED,
    }


# ---------------------------------------------------------------------------
# review(): the failure branches, against a stand-in orchestrator
# ---------------------------------------------------------------------------
#
# A script that behaves like the orchestrator only in the ways that matter here:
# it is started with an argv array and it writes to stdout. Using one keeps these
# branches testable without cfn-lint, cfn-guard, or a real template.


def fake_orchestrator(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "fake_orchestrator.py"
    path.write_text(body, encoding="utf-8")
    return path


def test_a_review_that_exits_non_zero_is_a_review_failure(tmp_path: Path) -> None:
    script = fake_orchestrator(
        tmp_path,
        "import sys\nsys.stderr.write('tool_unavailable\\n')\nsys.exit(5)\n",
    )
    with pytest.raises(run_benchmark.CaseError) as caught:
        run_benchmark.review(
            script, "template.yaml", run_benchmark.MODES["combined"], None, verbose=False
        )
    assert caught.value.reason == run_benchmark.REVIEW_FAILED
    assert "exited 5" in str(caught.value)


def test_a_review_printing_no_json_is_a_review_failure(tmp_path: Path) -> None:
    script = fake_orchestrator(tmp_path, "print('not json')\n")
    with pytest.raises(run_benchmark.CaseError) as caught:
        run_benchmark.review(
            script, "template.yaml", run_benchmark.MODES["combined"], None, verbose=False
        )
    assert caught.value.reason == run_benchmark.REVIEW_FAILED


def test_a_review_printing_a_document_that_is_not_a_report_is_a_failure(
    tmp_path: Path,
) -> None:
    script = fake_orchestrator(tmp_path, "print('{\"findings\": []}')\n")
    with pytest.raises(run_benchmark.CaseError) as caught:
        run_benchmark.review(
            script, "template.yaml", run_benchmark.MODES["combined"], None, verbose=False
        )
    assert caught.value.reason == run_benchmark.REVIEW_FAILED
    assert "Review_Report" in str(caught.value)


def test_a_report_whose_findings_are_not_an_array_is_a_failure(
    tmp_path: Path,
) -> None:
    envelope: Dict[str, Any] = {
        "schema_version": "1.0.0",
        "target": {},
        "sources_enabled": [],
        "tools": [],
        "errors": [],
        "summary": {},
        "findings": {},
    }
    script = fake_orchestrator(
        tmp_path,
        "import sys\nsys.stdout.write({0!r})\n".format(json.dumps(envelope)),
    )
    with pytest.raises(run_benchmark.CaseError) as caught:
        run_benchmark.review(
            script, "template.yaml", run_benchmark.MODES["combined"], None, verbose=False
        )
    assert caught.value.reason == run_benchmark.REVIEW_FAILED
    assert "findings" in str(caught.value)


def test_the_mode_and_the_fixture_become_arguments_in_the_argv_array(
    tmp_path: Path,
) -> None:
    # Passed as an array and never joined into a string (Requirement 16 AC6), so
    # the child can record them verbatim.
    record = tmp_path / "argv.json"
    script = fake_orchestrator(
        tmp_path,
        "import json, sys\n"
        "open({0!r}, 'w').write(json.dumps(sys.argv[1:]))\n".format(str(record)),
    )
    with pytest.raises(run_benchmark.CaseError):
        # The child prints nothing, so the review fails; the argv it recorded is
        # what this test is about.
        run_benchmark.review(
            script,
            "cases/case-001/template.yaml",
            run_benchmark.MODES["iam-only"],
            "fixtures/case-001.json",
            verbose=False,
        )

    assert json.loads(record.read_text(encoding="utf-8")) == [
        "--target",
        "cases/case-001/template.yaml",
        "--sources",
        run_benchmark.IAM_SOURCE_CLI_ALIAS,
        "--agent-findings",
        "fixtures/case-001.json",
    ]


def test_combined_mode_passes_no_sources_argument(tmp_path: Path) -> None:
    record = tmp_path / "argv.json"
    script = fake_orchestrator(
        tmp_path,
        "import json, sys\n"
        "open({0!r}, 'w').write(json.dumps(sys.argv[1:]))\n".format(str(record)),
    )
    with pytest.raises(run_benchmark.CaseError):
        run_benchmark.review(
            script, "template.yaml", run_benchmark.MODES["combined"], None, verbose=False
        )

    assert json.loads(record.read_text(encoding="utf-8")) == [
        "--target",
        "template.yaml",
    ]


def test_filter_only_drops_the_sources_argument_from_the_argv_array(
    tmp_path: Path,
) -> None:
    """The two paths differ in the child's argv and nowhere else.

    Same mode, same target, same fixture: without the flag the review is asked for
    one Source, with it the review is asked for all of them and the filter does the
    narrowing afterwards.
    """
    record = tmp_path / "argv.json"
    script = fake_orchestrator(
        tmp_path,
        "import json, sys\n"
        "open({0!r}, 'w').write(json.dumps(sys.argv[1:]))\n".format(str(record)),
    )
    mode = run_benchmark.MODES["cfn-guard-only"]

    recorded = {}
    for filter_only in (False, True):
        with pytest.raises(run_benchmark.CaseError):
            # The child prints nothing, so the review fails; the argv it recorded
            # is what this test is about.
            run_benchmark.review(
                script,
                "cases/case-001/template.yaml",
                run_benchmark.review_mode(mode, filter_only),
                None,
                verbose=False,
            )
        recorded[filter_only] = json.loads(record.read_text(encoding="utf-8"))

    assert recorded[False] == [
        "--target",
        "cases/case-001/template.yaml",
        "--sources",
        cfnguard.SOURCE_NAME,
    ]
    # The same argv combined is reviewed with, which is why one review per case can
    # serve every mode under this flag.
    assert recorded[True] == ["--target", "cases/case-001/template.yaml"]
    assert run_benchmark.review_mode(mode, True).cli_sources == (
        run_benchmark.MODES["combined"].cli_sources
    )


def test_a_review_that_times_out_is_one_unevaluated_case(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A hung review costs its case, not the run.

    ``proc.run`` kills the child and raises, so what reaches the harness is an
    exception rather than a stuck process; it becomes the same recorded failure as
    any other way a review can fail to produce a report.
    """

    def timeout(argv: List[str], timeout_s: int) -> Any:
        raise ToolTimeoutError(
            "the review exceeded its {0}s timeout".format(timeout_s),
            tool="python",
        )

    monkeypatch.setattr(run_benchmark.proc, "run", timeout)
    with pytest.raises(run_benchmark.CaseError) as caught:
        run_benchmark.review(
            Path("orchestrator.py"),
            "template.yaml",
            run_benchmark.MODES["combined"],
            None,
            verbose=False,
        )
    assert caught.value.reason == run_benchmark.REVIEW_FAILED
    assert "tool_timeout" in str(caught.value)


def test_the_timeout_is_bounded_and_generous() -> None:
    # Bounded so a hung review cannot stall CI; generous because a slow machine
    # running two external tools over a large template is not a failure.
    assert 60 <= run_benchmark.REVIEW_TIMEOUT_S <= 3600


# ---------------------------------------------------------------------------
# What a degraded review does to a case
# ---------------------------------------------------------------------------


def test_a_review_reporting_a_tool_failure_still_measures_the_case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    """An unavailable tool is a warning on stderr, not an unevaluated case.

    The review completed; some findings are missing because a Source could not
    run, and those show up as missed expectations. Copying the message into stdout
    instead would put the host's installed tools into output that has to stay
    byte-identical between runs.
    """
    write_case(tmp_path / "cases", "case-001-a")

    def degraded(*args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            "findings": [finding()],
            # A non-dict entry among them: malformed, and skipped rather than
            # raising out of a diagnostic.
            "errors": [
                {
                    "error_class": "tool_unavailable",
                    "message": "cfn-lint was not found on PATH",
                },
                "not an object",
            ],
        }

    monkeypatch.setattr(run_benchmark, "review", degraded)
    monkeypatch.chdir(tmp_path)

    benchmark = run_benchmark.Benchmark()
    benchmark.cases_dir = (tmp_path / "cases").resolve()
    benchmark.orchestrator = pathguard.resolve_plugin_owned(run_benchmark.ORCHESTRATOR)
    entry = benchmark._evaluate("case-001-a", verbose=False)
    captured = capsys.readouterr()

    assert entry["evaluated"] is True
    assert entry["status"] == metrics.STATUS_PASS
    assert benchmark.errors == []
    assert "tool_unavailable" in captured.err
    assert "tool_unavailable" not in json.dumps(benchmark.summary())


def degraded_report(available: bool) -> Dict[str, Any]:
    """A combined report in which cfn-guard did or did not run.

    ``tools`` is what the review says about the executables it looked for, and the
    only place a report distinguishes "this Source found nothing" from "this Source
    could not run".
    """
    return {
        "findings": [],
        "errors": []
        if available
        else [
            {
                "error_class": "tool_unavailable",
                "message": "cfn-guard was not found on PATH",
            }
        ],
        "tools": [
            {"name": "cfn-lint", "available": True, "version": "1.0.0"},
            {"name": "cfn-guard", "available": available, "version": None},
        ],
    }


@pytest.mark.parametrize(
    "filter_only,available,warned",
    [
        (True, False, True),
        (True, True, False),
        (False, False, False),
    ],
    ids=["filtered and absent", "filtered and present", "default path"],
)
def test_an_absent_tool_is_named_when_filtering_hid_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
    filter_only: bool,
    available: bool,
    warned: bool,
) -> None:
    """The one way the two paths are not interchangeable.

    Without the flag, an absent cfn-guard leaves a ``cfn-guard-only`` review with no
    Source able to run, the orchestrator fails, and the case is recorded
    unevaluated -- attributed to the environment. With the flag the combined review
    succeeds on whatever is installed and the filter finds nothing, which reads
    exactly like a review that stopped detecting anything. So the harness says
    which it is, on stderr, where an environment-dependent fact belongs.
    """
    write_case(tmp_path / "cases", "case-001-a")
    monkeypatch.setattr(
        run_benchmark, "review", lambda *a, **k: degraded_report(available)
    )
    monkeypatch.chdir(tmp_path)

    benchmark = run_benchmark.Benchmark()
    benchmark.cases_dir = (tmp_path / "cases").resolve()
    benchmark.orchestrator = pathguard.resolve_plugin_owned(run_benchmark.ORCHESTRATOR)
    benchmark.mode = run_benchmark.MODES["cfn-guard-only"]
    benchmark.filter_only = filter_only
    benchmark._evaluate("case-001-a", verbose=False)
    captured = capsys.readouterr()

    assert ("--filter-only" in captured.err) is warned
    # Never in stdout: which tools the host installed is not part of what the
    # benchmark measures (Requirement 16 AC11).
    assert "cfn-guard was not found" not in json.dumps(benchmark.summary())


def test_a_source_needing_no_tool_has_nothing_to_explain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    """An ``iam-only`` measurement cannot be empty because a tool was missing."""
    write_case(tmp_path / "cases", "case-001-a")
    monkeypatch.setattr(run_benchmark, "review", lambda *a, **k: degraded_report(False))
    monkeypatch.chdir(tmp_path)

    benchmark = run_benchmark.Benchmark()
    benchmark.cases_dir = (tmp_path / "cases").resolve()
    benchmark.orchestrator = pathguard.resolve_plugin_owned(run_benchmark.ORCHESTRATOR)
    benchmark.mode = run_benchmark.MODES["iam-only"]
    benchmark.filter_only = True
    benchmark._evaluate("case-001-a", verbose=False)

    assert "--filter-only" not in capsys.readouterr().err


def test_a_report_with_a_malformed_tools_array_does_not_break_the_diagnostic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    """A diagnostic must not be the thing that takes a run down."""
    write_case(tmp_path / "cases", "case-001-a")
    document: Dict[str, Any] = {
        "findings": [],
        "errors": [],
        "tools": ["cfn-guard", {"name": "cfn-guard"}, {}],
    }
    monkeypatch.setattr(run_benchmark, "review", lambda *a, **k: document)
    monkeypatch.chdir(tmp_path)

    benchmark = run_benchmark.Benchmark()
    benchmark.cases_dir = (tmp_path / "cases").resolve()
    benchmark.orchestrator = pathguard.resolve_plugin_owned(run_benchmark.ORCHESTRATOR)
    benchmark.mode = run_benchmark.MODES["cfn-guard-only"]
    benchmark.filter_only = True
    entry = benchmark._evaluate("case-001-a", verbose=False)

    assert entry["evaluated"] is True
    assert "--filter-only" not in capsys.readouterr().err


def test_a_review_of_a_real_template_returns_a_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The one non-failure path of review(): the real orchestrator, one Source
    # that needs no external tool, one template with a defect in it.
    (tmp_path / "template.yaml").write_text(WILDCARD_TEMPLATE, encoding="utf-8")
    orchestrator = pathguard.resolve_plugin_owned(run_benchmark.ORCHESTRATOR)

    # The orchestrator's workspace root is its working directory, so the target
    # is given relative to it and no host path enters the report.
    monkeypatch.chdir(tmp_path)
    document = run_benchmark.review(
        orchestrator,
        "template.yaml",
        run_benchmark.MODES["iam-only"],
        None,
        verbose=False,
    )

    assert document["errors"] == []
    assert [entry["Resource"] for entry in document["findings"]] == ["AdminPolicy"]
