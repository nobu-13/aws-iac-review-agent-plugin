"""Tests for :mod:`iacreview.report`.

The eight cases Task 16.1 asks for, in order: report ordering, a ``Resource``-less
Finding leading its Severity run, sequential IDs, summary counts, a merged Finding
making ``by_source`` exceed ``total``, ``passed_all_checks`` only for an empty
findings list, byte-identical repeated serialization, and the absence of any
absolute path or timestamp in the output.

Two supporting groups follow them. Path normalization is what keeps the output
free of host paths in the first place, and the ``tools`` / ``sources_enabled``
arrays are the parts of the envelope whose order a caller could otherwise
influence.

Findings are built through :func:`make_finding` rather than
``finding.from_dict``, which enforces ``ID >= 1``: a Finding on its way into a
report carries :data:`~iacreview.finding.UNASSIGNED_ID`, because the ID is what
the report is about to assign.
"""

from __future__ import annotations

import io
import json
import random
import re
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any, Dict, List, Optional, Sequence

import pytest

from iacreview.dedup import deduplicate
from iacreview.errors import SchemaViolationError
from iacreview.finding import (
    FINDING_TYPES,
    SEVERITIES,
    SOURCES,
    UNASSIGNED_ID,
    Evidence,
    Finding,
    Location,
)
from iacreview.report import (
    FIRST_ID,
    REPORT_KEYS,
    SCHEMA_VERSION,
    STANDALONE_GROUP,
    SUMMARY_KEYS,
    SYNTHESIZED_GROUP,
    ReportMeta,
    ToolStatus,
    assign_ids,
    build_report,
    configure_stdout,
    dump,
    normalize_output_path,
    sort_findings,
)

TEMPLATE_FILE = "templates/app.yaml"
SYNTHESIZED_FILE = "cdk.out/AppStack.template.json"

#: An ISO-8601 date-time, in any of the spellings a timestamp would be written
#: in. Requirement 16 AC11 forbids all of them in stdout.
ISO_8601 = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}")

#: The prefix of a macOS home directory, the absolute path this repository's own
#: test runs would leak if one reached the report.
HOST_PATH_PREFIX = "/Users/"


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def make_finding(
    *,
    severity: str = "MEDIUM",
    resource: Optional[str] = "AppBucket",
    category: str = "Encryption",
    finding_type: str = "Security",
    confidence: str = "Confirmed",
    sources: Sequence[str] = ("cfn-guard",),
    text: str = "[s3_bucket_encryption] Default encryption is not configured.",
    file: str = TEMPLATE_FILE,
    line: Optional[int] = None,
    excerpt: Optional[str] = None,
    detail: str = "provided: absent, expected: present",
    finding_id: int = UNASSIGNED_ID,
) -> Finding:
    """A schema-valid Finding, varying only in what a test is about."""
    return Finding(
        ID=finding_id,
        Normalized_Category=category,
        FindingType=finding_type,
        Severity=severity,
        Confidence=confidence,
        Source=list(sources),
        Resource=resource,
        Location=Location(File=file, Line=line, Column=None, TemplatePath=None),
        Finding=text,
        WhyItMatters="Unencrypted objects are readable from a raw storage copy.",
        Evidence=[
            Evidence(
                Source=sources[0],
                Detail=detail,
                RuleId="s3_bucket_encryption",
                Excerpt=excerpt,
            )
        ],
        Recommendation="Configure BucketEncryption on the bucket.",
        SuggestedRemediation=None,
    )


def agent_finding(**overrides: Any) -> Finding:
    """An agent Finding: never ``Confirmed``, and always carrying an Excerpt."""
    defaults: Dict[str, Any] = {
        "confidence": "Likely",
        "sources": ("Agent Review",),
        "finding_type": "BestPractice",
        "text": "The bucket may hold data that policy requires to be encrypted.",
        "excerpt": "AppBucket:\n  Type: AWS::S3::Bucket",
    }
    defaults.update(overrides)
    return make_finding(**defaults)


def meta(**overrides: Any) -> ReportMeta:
    defaults: Dict[str, Any] = {
        "files": (TEMPLATE_FILE,),
        "sources_enabled": ("cfn-lint", "cfn-guard", "IAM Review"),
        "tools": (
            ToolStatus(name="cfn-lint", available=True, version="1.22.3"),
            ToolStatus(name="cfn-guard", available=False, version=None),
        ),
    }
    defaults.update(overrides)
    return ReportMeta(**defaults)


def report_of(
    findings: Sequence[Finding],
    errors: Sequence[Dict[str, Any]] = (),
    **meta_overrides: Any,
) -> Dict[str, Any]:
    return build_report(findings, list(errors), meta(**meta_overrides))


# ---------------------------------------------------------------------------
# (a) report ordering
# ---------------------------------------------------------------------------


def test_findings_are_ordered_by_severity_descending() -> None:
    """Requirement 7 AC15, first key: CRITICAL, HIGH, MEDIUM, LOW, INFO."""
    findings = [make_finding(severity=severity) for severity in reversed(SEVERITIES)]

    ordered = sort_findings(findings)

    assert [f.Severity for f in ordered] == list(SEVERITIES)


def test_equal_severity_is_ordered_by_resource_ascending() -> None:
    """Requirement 7 AC15, second key: logical ID alphabetically ascending."""
    findings = [
        make_finding(resource=name) for name in ["WebBucket", "AppBucket", "DataBucket"]
    ]

    ordered = sort_findings(findings)

    assert [f.Resource for f in ordered] == ["AppBucket", "DataBucket", "WebBucket"]


def test_resource_ordering_does_not_cross_severity_boundaries() -> None:
    """Severity dominates: a LOW ``AaaBucket`` still follows a HIGH ``ZzzBucket``."""
    findings = [
        make_finding(severity="LOW", resource="AaaBucket"),
        make_finding(severity="HIGH", resource="ZzzBucket"),
    ]

    ordered = sort_findings(findings)

    assert [(f.Severity, f.Resource) for f in ordered] == [
        ("HIGH", "ZzzBucket"),
        ("LOW", "AaaBucket"),
    ]


def test_one_resource_at_one_severity_is_ordered_by_category_then_text() -> None:
    """The two tie-breakers design.md adds, in that precedence."""
    findings = [
        make_finding(category="Logging", text="B logging is off."),
        make_finding(category="Encryption", text="B encryption is off."),
        make_finding(category="Encryption", text="A encryption is weak."),
    ]

    ordered = sort_findings(findings)

    assert [(f.Normalized_Category, f.Finding) for f in ordered] == [
        ("Encryption", "A encryption is weak."),
        ("Encryption", "B encryption is off."),
        ("Logging", "B logging is off."),
    ]


def test_findings_tied_on_every_documented_key_still_have_a_fixed_order() -> None:
    """The last-resort component: order must not depend on arrival order.

    Two ``Other`` Findings on one resource sharing a description are the case
    dedup deliberately leaves separate, so the report is where their order has to
    be decided.
    """
    first = agent_finding(category="Other", text="Unmapped.", detail="First reading.")
    second = agent_finding(category="Other", text="Unmapped.", detail="Second reading.")

    forward = [f.Evidence[0].Detail for f in sort_findings([first, second])]
    backward = [f.Evidence[0].Detail for f in sort_findings([second, first])]

    assert forward == backward


def test_permuting_the_input_does_not_change_the_report() -> None:
    """Requirement 16 AC11: order in, no influence on order out."""
    findings = mixed_findings()
    expected = dump(report_of(findings))
    rng = random.Random(20240116)

    for _ in range(50):
        shuffled = list(findings)
        rng.shuffle(shuffled)
        assert dump(report_of(shuffled)) == expected


# ---------------------------------------------------------------------------
# (b) Resource: null
# ---------------------------------------------------------------------------


def test_a_resourceless_finding_leads_its_severity_run() -> None:
    """``None`` reads as ``""``, which precedes every logical ID."""
    findings = [
        make_finding(resource="AaaBucket"),
        make_finding(resource=None, text="[E0000] Template section Outputs is malformed."),
        make_finding(resource="ZzzBucket"),
    ]

    ordered = sort_findings(findings)

    assert [f.Resource for f in ordered] == [None, "AaaBucket", "ZzzBucket"]


def test_a_resourceless_finding_does_not_lead_the_whole_report() -> None:
    """It leads its own Severity run, not every run above it."""
    findings = [
        make_finding(severity="MEDIUM", resource=None, text="[W2001] Unused Parameter."),
        make_finding(severity="CRITICAL", resource="AppRole", category="IAM"),
    ]

    ordered = sort_findings(findings)

    assert [(f.Severity, f.Resource) for f in ordered] == [
        ("CRITICAL", "AppRole"),
        ("MEDIUM", None),
    ]


# ---------------------------------------------------------------------------
# (c) sequential IDs
# ---------------------------------------------------------------------------


def test_ids_are_sequential_from_one_in_report_order() -> None:
    """Requirement 7 AC1."""
    report = report_of(mixed_findings())

    ids = [entry["ID"] for entry in report["findings"]]
    assert ids == list(range(FIRST_ID, FIRST_ID + len(ids)))


def test_ids_are_assigned_after_sorting_not_before() -> None:
    """The highest Severity holds ID 1, whatever order it arrived in."""
    report = report_of(
        [
            make_finding(severity="LOW", resource="AaaBucket"),
            make_finding(severity="CRITICAL", resource="ZzzBucket", category="IAM"),
        ]
    )

    assert [(e["ID"], e["Severity"]) for e in report["findings"]] == [
        (1, "CRITICAL"),
        (2, "LOW"),
    ]


def test_numbering_leaves_the_input_findings_untouched() -> None:
    """A Finding may appear in two reports; neither may rewrite it."""
    findings = [make_finding(), make_finding(resource="OtherBucket")]

    build_report(findings, [], meta())

    assert [f.ID for f in findings] == [UNASSIGNED_ID, UNASSIGNED_ID]


def test_assign_ids_numbers_an_empty_sequence_to_nothing() -> None:
    assert assign_ids([]) == []


# ---------------------------------------------------------------------------
# (d) summary counts
# ---------------------------------------------------------------------------


def mixed_findings() -> List[Finding]:
    """Findings spanning several Severities, types, Sources and both groups."""
    return [
        make_finding(severity="CRITICAL", resource="AppRole", category="IAM"),
        make_finding(
            severity="HIGH",
            resource="AppBucket",
            category="PublicAccess",
            sources=("cfn-lint",),
            finding_type="Validity",
            text="[E3002] Invalid Property Resources/AppBucket/Properties/Encryped.",
        ),
        make_finding(severity="MEDIUM"),
        make_finding(
            severity="LOW",
            resource=None,
            category="TemplateQuality",
            sources=("cfn-lint",),
            finding_type="Informational",
            text="[W2001] Parameter Unused is not used.",
        ),
        agent_finding(severity="INFO", resource="LogGroup", category="Logging"),
        make_finding(
            severity="HIGH",
            resource="SynthBucket",
            category="Encryption",
            file=SYNTHESIZED_FILE,
        ),
    ]


def test_summary_totals_match_the_findings_array() -> None:
    """Requirement 7 AC17, and Property 13's conservation laws."""
    report = report_of(mixed_findings(), synthesized_templates=(SYNTHESIZED_FILE,))
    summary = report["summary"]
    findings = report["findings"]

    assert summary["total"] == len(findings)
    assert sum(summary["by_finding_type"].values()) == summary["total"]
    assert sum(summary["by_severity"].values()) == summary["total"]
    assert sum(summary["by_template_group"].values()) == summary["total"]


def test_summary_counts_each_group_exactly() -> None:
    report = report_of(mixed_findings(), synthesized_templates=(SYNTHESIZED_FILE,))
    summary = report["summary"]

    assert summary["by_severity"] == {
        "CRITICAL": 1,
        "HIGH": 2,
        "MEDIUM": 1,
        "LOW": 1,
        "INFO": 1,
    }
    assert summary["by_finding_type"] == {
        "Validity": 1,
        "Security": 3,
        "BestPractice": 1,
        "Informational": 1,
    }
    assert summary["by_source"] == {
        "cfn-lint": 2,
        "cfn-guard": 3,
        "IAM Review": 0,
        "Network Review": 0,
        "Secret Review": 0,
        "Quality Review": 0,
        "Agent Review": 1,
    }
    assert summary["by_template_group"] == {STANDALONE_GROUP: 5, SYNTHESIZED_GROUP: 1}


def test_summary_key_sets_are_fixed_even_when_every_count_is_zero() -> None:
    """A consumer indexes without existence checks (Requirement 16 AC11)."""
    summary = report_of([])["summary"]

    assert tuple(sorted(summary)) == tuple(sorted(SUMMARY_KEYS))
    assert sorted(summary["by_finding_type"]) == sorted(FINDING_TYPES)
    assert sorted(summary["by_severity"]) == sorted(SEVERITIES)
    assert sorted(summary["by_source"]) == sorted(SOURCES)
    assert summary["by_template_group"] == {STANDALONE_GROUP: 0, SYNTHESIZED_GROUP: 0}


def test_a_finding_on_an_unlisted_template_counts_as_standalone() -> None:
    """The documented default for a file in neither target list."""
    report = report_of(
        [make_finding(file="templates/unlisted.yaml")], files=(TEMPLATE_FILE,)
    )

    assert report["summary"]["by_template_group"] == {
        STANDALONE_GROUP: 1,
        SYNTHESIZED_GROUP: 0,
    }


# ---------------------------------------------------------------------------
# (e) by_source exceeding total after a merge
# ---------------------------------------------------------------------------


def test_by_source_sums_above_total_for_a_merged_finding() -> None:
    """Requirement 14 AC12: one merged Finding is counted under every Source.

    Run through ``deduplicate`` rather than hand-built, so the case the summary
    is asked to describe is one the pipeline actually produces.
    """
    merged = deduplicate(
        [
            make_finding(sources=("cfn-guard",)),
            make_finding(
                sources=("cfn-lint",),
                text="[W3045] Both AccessControl and BucketPolicy are configured.",
            ),
            agent_finding(),
        ]
    )
    assert len(merged) == 1

    summary = report_of(merged)["summary"]

    assert summary["total"] == 1
    assert summary["by_source"] == {
        "cfn-lint": 1,
        "cfn-guard": 1,
        "IAM Review": 0,
        "Network Review": 0,
        "Secret Review": 0,
        "Quality Review": 0,
        "Agent Review": 1,
    }
    assert sum(summary["by_source"].values()) == 3
    assert sum(summary["by_severity"].values()) == summary["total"]


# ---------------------------------------------------------------------------
# (f) passed_all_checks
# ---------------------------------------------------------------------------


def test_passed_all_checks_is_true_only_for_an_empty_findings_list() -> None:
    """Requirement 7 AC16."""
    empty = report_of([])

    assert empty["findings"] == []
    assert empty["summary"]["total"] == 0
    assert empty["summary"]["passed_all_checks"] is True


def test_passed_all_checks_is_false_for_a_single_informational_finding() -> None:
    """Any Finding at all, including the lowest Severity, clears the flag."""
    report = report_of(
        [make_finding(severity="INFO", finding_type="Informational")]
    )

    assert report["summary"]["passed_all_checks"] is False


def test_passed_all_checks_stays_true_when_a_source_failed() -> None:
    """Errors are reported separately; the flag describes findings only."""
    report = report_of([], errors=[tool_unavailable_error()])

    assert report["summary"]["passed_all_checks"] is True
    assert len(report["errors"]) == 1


# ---------------------------------------------------------------------------
# (g) byte-identical serialization
# ---------------------------------------------------------------------------


def tool_unavailable_error() -> Dict[str, Any]:
    """A StructuredError as ``errors.py`` renders one."""
    return {
        "error_class": "tool_unavailable",
        "source": "cfn-guard",
        "tool": "cfn-guard",
        "exit_code": None,
        "message": "cfn-guard was not found on the system PATH.",
        "required_min_version": "3.0.0",
        "detected_version": None,
        "remediation": "Install cfn-guard.",
        "stderr_head": [],
    }


def test_dumping_the_same_report_twice_is_byte_identical() -> None:
    """Task 16.1 completion condition."""
    report = report_of(mixed_findings(), errors=[tool_unavailable_error()])

    first = dump(report)
    second = dump(report)

    assert first == second
    assert first.encode("utf-8") == second.encode("utf-8")


def test_building_and_dumping_twice_is_byte_identical() -> None:
    """Assembly is deterministic too, not only serialization."""
    findings = mixed_findings()
    errors = [tool_unavailable_error()]

    assert dump(report_of(findings, errors=errors)) == dump(
        report_of(findings, errors=errors)
    )


def test_dump_ends_with_exactly_one_newline() -> None:
    text = dump(report_of([]))

    assert text.endswith("}\n")
    assert not text.endswith("\n\n")


def test_dump_sorts_object_keys_and_indents_by_two() -> None:
    text = dump(report_of([]))

    assert text.splitlines()[0] == "{"
    assert text.splitlines()[1].startswith('  "errors"')
    assert json.loads(text)["schema_version"] == SCHEMA_VERSION


def test_dump_keeps_non_ascii_content_unescaped() -> None:
    """``ensure_ascii=False``: a Japanese Tag value stays readable."""
    text = dump(
        report_of([make_finding(detail="Tag Owner の値が設定されていない")])
    )

    assert "Tag Owner の値が設定されていない" in text
    assert "\\u" not in text


def test_the_report_carries_exactly_the_schema_keys() -> None:
    report = report_of([])

    assert tuple(sorted(report)) == tuple(sorted(REPORT_KEYS))
    assert sorted(report["target"]) == ["cdk", "files"]
    assert sorted(report["target"]["cdk"]) == ["detected", "synthesized_templates"]


# ---------------------------------------------------------------------------
# (h) no absolute path, no timestamp
# ---------------------------------------------------------------------------


def test_the_output_contains_no_host_path_and_no_timestamp() -> None:
    """Requirement 16 AC11, on a report holding every kind of content."""
    text = dump(
        report_of(
            mixed_findings(),
            errors=[tool_unavailable_error()],
            synthesized_templates=(SYNTHESIZED_FILE,),
        )
    )

    assert HOST_PATH_PREFIX not in text
    assert ISO_8601.search(text) is None


def test_no_finding_location_is_an_absolute_path() -> None:
    report = report_of(mixed_findings(), synthesized_templates=(SYNTHESIZED_FILE,))

    for entry in report["findings"]:
        assert not entry["Location"]["File"].startswith("/")


@pytest.mark.parametrize(
    "absolute",
    ["/Users/reviewer/workspace/templates/app.yaml", "C:/workspace/templates/app.yaml"],
    ids=["posix", "windows-drive"],
)
def test_an_absolute_location_is_refused_rather_than_emitted(absolute: str) -> None:
    """Relativizing needs the workspace root, which the report does not have."""
    with pytest.raises(SchemaViolationError) as raised:
        report_of([make_finding(file=absolute)])

    assert "Location.File" in str(raised.value)


def test_an_absolute_target_file_is_refused() -> None:
    with pytest.raises(SchemaViolationError) as raised:
        report_of([], files=("/Users/reviewer/workspace/templates/app.yaml",))

    assert "target.files[0]" in str(raised.value)


# ---------------------------------------------------------------------------
# Path normalization
# ---------------------------------------------------------------------------


def test_a_windows_location_is_normalized_to_forward_slashes() -> None:
    """design.md, Portability Design: one spelling per file, on every platform."""
    report = report_of(
        [make_finding(file="templates\\nested\\app.yaml")],
        files=(PureWindowsPath("templates/nested/app.yaml"),),
    )

    assert report["findings"][0]["Location"]["File"] == "templates/nested/app.yaml"
    assert report["target"]["files"] == ["templates/nested/app.yaml"]


def test_a_dot_prefixed_path_normalizes_to_the_bare_path() -> None:
    assert normalize_output_path("./templates/app.yaml") == "templates/app.yaml"
    assert normalize_output_path(PurePosixPath("templates/app.yaml")) == TEMPLATE_FILE


@pytest.mark.parametrize(
    "value", ["", ".", "../outside/app.yaml", "templates/../../app.yaml"]
)
def test_an_unusable_path_is_refused(value: str) -> None:
    with pytest.raises(SchemaViolationError):
        normalize_output_path(value, "target.files[0]")


def test_target_paths_are_sorted_and_deduplicated() -> None:
    report = report_of(
        [],
        files=("templates/web.yaml", "./templates/app.yaml", "templates/app.yaml"),
    )

    assert report["target"]["files"] == ["templates/app.yaml", "templates/web.yaml"]


# ---------------------------------------------------------------------------
# Envelope metadata
# ---------------------------------------------------------------------------


def test_sources_enabled_is_ordered_canonically_whatever_the_caller_passed() -> None:
    report = report_of([], sources_enabled=("IAM Review", "cfn-lint"))

    assert report["sources_enabled"] == ["cfn-lint", "IAM Review"]


def test_an_unknown_source_name_is_refused() -> None:
    with pytest.raises(SchemaViolationError):
        report_of([], sources_enabled=("cfn-lint", "tfsec"))


def test_tools_are_ordered_by_name_and_carry_a_fixed_key_set() -> None:
    report = report_of([])

    assert report["tools"] == [
        {"name": "cfn-guard", "available": False, "version": None},
        {"name": "cfn-lint", "available": True, "version": "1.22.3"},
    ]


def test_a_duplicated_tool_entry_is_refused() -> None:
    with pytest.raises(SchemaViolationError):
        report_of(
            [],
            tools=(
                ToolStatus(name="cfn-lint", available=True, version="1.22.3"),
                ToolStatus(name="cfn-lint", available=False, version=None),
            ),
        )


def test_cdk_detection_is_reported_with_its_synthesized_templates() -> None:
    report = report_of(
        [], cdk_detected=True, synthesized_templates=(SYNTHESIZED_FILE,)
    )

    assert report["target"]["cdk"] == {
        "detected": True,
        "synthesized_templates": [SYNTHESIZED_FILE],
    }


def test_errors_are_copied_rather_than_aliased() -> None:
    """Mutating the report must not reach the orchestrator's error list."""
    error = tool_unavailable_error()
    report = report_of([], errors=[error])

    report["errors"][0]["message"] = "rewritten"
    report["errors"][0]["stderr_head"].append("rewritten")

    assert error["message"] == "cfn-guard was not found on the system PATH."
    assert error["stderr_head"] == []


def test_a_report_with_no_findings_and_no_metadata_is_still_well_formed() -> None:
    report = build_report([], [], ReportMeta())

    assert json.loads(dump(report)) == report


# ---------------------------------------------------------------------------
# stdout configuration
# ---------------------------------------------------------------------------


def test_configure_stdout_pins_encoding_and_newline() -> None:
    stream = io.TextIOWrapper(io.BytesIO(), encoding="latin-1", newline="\r\n")

    assert configure_stdout(stream) is True
    assert stream.encoding == "utf-8"

    stream.write(dump(report_of([])))
    stream.flush()
    assert b"\r\n" not in stream.buffer.getvalue()


def test_configure_stdout_reports_a_stream_it_cannot_pin() -> None:
    """A captured :class:`io.StringIO` has no encoding step to get wrong."""
    assert configure_stdout(io.StringIO()) is False


def test_configure_stdout_defaults_to_the_current_stdout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = io.TextIOWrapper(io.BytesIO(), encoding="latin-1")
    monkeypatch.setattr("sys.stdout", stream)

    assert configure_stdout() is True
    assert stream.encoding == "utf-8"
