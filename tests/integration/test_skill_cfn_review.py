"""Integration tests for the ``cloudformation-review`` Skill (Task 18.5).

``skills/cloudformation-review/scripts/extract_facts.py`` is run as a real
subprocess, the way a host Agent runs it, so what is asserted is the Skill's
contract rather than the behaviour of an imported function: the key structure of
the facts JSON, the correctness of the ``Ref`` / ``Fn::GetAtt`` reference graph,
byte-identical output for identical input (Requirement 16 AC11), and the presence
of ``deterministic_findings_summary``, which is what keeps the Agent from
restating findings the deterministic Sources already reported (Requirement 2
AC14, AC15).

The expected key sets are written out literally instead of imported from the
script. Importing them would make these tests agree with the implementation by
construction; spelling them out means a renamed or dropped key fails a test.

Every run uses the plugin root as the working directory, because that is the
workspace root the script contains paths against, and passes the Template as a
workspace-relative path.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence

import pytest

SCRIPT = Path("skills") / "cloudformation-review" / "scripts" / "extract_facts.py"

#: Fixture wiring three resources together; its header documents every fact the
#: extractor is expected to find, written before this test was run.
RELATIONS = "tests/fixtures/valid/cross_resource_relations.yaml"

#: JSON Template, to confirm the format is detected from content.
JSON_TEMPLATE = "tests/fixtures/valid/minimal_template.json"

#: Template whose IAM policies are intentionally dangerous, so the deterministic
#: IAM Source has Security findings to summarize.
DANGEROUS_IAM = "tests/fixtures/security/iam_dangerous_policies.yaml"

#: Parses, but has no ``Resources`` mapping.
NOT_REVIEWABLE = "tests/fixtures/invalid/no_resources.yaml"

FACTS_KEYS = [
    "conditions",
    "depends_on",
    "deterministic_findings_summary",
    "deterministic_reports",
    "deterministic_sources",
    "parameters",
    "references",
    "resources",
    "schema_version",
    "target",
]
TARGET_KEYS = ["description", "file", "format"]
RESOURCE_KEYS = ["availability", "condition", "logical_id", "properties", "type"]
AVAILABILITY_KEYS = ["item_count", "json_path", "property", "value"]
REFERENCE_KEYS = ["attribute", "from", "json_path", "kind", "to"]
DEPENDS_ON_KEYS = ["from", "to"]
PARAMETER_KEYS = [
    "allowed_values",
    "default",
    "has_default",
    "name",
    "no_echo",
    "referenced_by",
    "type",
]
CONDITION_KEYS = ["definition", "name"]
SUMMARY_KEYS = ["category", "resource", "rule", "severity", "source"]
SOURCE_COVERAGE_KEYS = ["computed_in_process", "findings_summarized", "name"]

#: Exit codes of design.md's failure matrix that this Skill can return.
EXIT_OK = 0
EXIT_INVALID_ARGUMENTS = 2
EXIT_PARSE_FAILURE = 4
EXIT_PATH_VIOLATION = 7
EXIT_NOT_REVIEWABLE = 8


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(
    plugin_root: Path, *arguments: str
) -> "subprocess.CompletedProcess[bytes]":
    """Run the Skill's script with ``arguments`` from the plugin root."""
    return subprocess.run(
        [sys.executable, str(plugin_root / SCRIPT), *arguments],
        cwd=str(plugin_root),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=120,
        check=False,
    )


def _facts(plugin_root: Path, *arguments: str) -> Dict[str, Any]:
    """Run the script, require success, and return the parsed facts."""
    completed = _run(plugin_root, *arguments)
    assert completed.returncode == EXIT_OK, completed.stderr.decode(
        "utf-8", "replace"
    )
    parsed = json.loads(completed.stdout.decode("utf-8"))
    assert isinstance(parsed, dict)
    return parsed


@pytest.fixture(scope="module")
def relations_facts(plugin_root: Path) -> Dict[str, Any]:
    return _facts(plugin_root, "--target", RELATIONS)


@pytest.fixture
def reports_dir(plugin_root: Path) -> Iterator[Path]:
    """A scratch directory *inside* the workspace root, removed afterwards.

    ``pytest``'s ``tmp_path`` cannot be used for a ``--deterministic-report``:
    the script contains every path it is given inside the workspace root, and
    refuses one outside it with exit 7 (Requirement 9 AC5). That refusal is
    correct and is asserted separately, so a report written for these tests has
    to live where a real caller would put it.
    """
    directory = Path(
        tempfile.mkdtemp(dir=str(plugin_root), prefix=".tmp-cfn-review-")
    )
    try:
        yield directory
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def _resource(facts: Dict[str, Any], logical_id: str) -> Dict[str, Any]:
    matches = [
        entry for entry in facts["resources"] if entry["logical_id"] == logical_id
    ]
    assert len(matches) == 1, "expected exactly one {0}".format(logical_id)
    return matches[0]


def _parameter(facts: Dict[str, Any], name: str) -> Dict[str, Any]:
    matches = [entry for entry in facts["parameters"] if entry["name"] == name]
    assert len(matches) == 1, "expected exactly one {0}".format(name)
    return matches[0]


def _edges(facts: Dict[str, Any]) -> List[Sequence[Optional[str]]]:
    return [
        (entry["from"], entry["to"], entry["kind"], entry["attribute"])
        for entry in facts["references"]
    ]


def _write_report(
    directory: Path, name: str, findings: List[Dict[str, Any]], plugin_root: Path
) -> str:
    """Write a report envelope and return its workspace-relative path."""
    path = directory / name
    path.write_text(
        json.dumps({"schema_version": "1.0.0", "findings": findings}),
        encoding="utf-8",
    )
    return path.relative_to(plugin_root).as_posix()


def _deterministic_finding(
    source: str, rule: str, resource: str, category: str, severity: str
) -> Dict[str, Any]:
    """A report entry shaped like the ones the deterministic Skills emit."""
    return {
        "ID": 1,
        "Normalized_Category": category,
        "FindingType": "Security",
        "Severity": severity,
        "Confidence": "Confirmed",
        "Source": [source],
        "Resource": resource,
        "Location": {"File": RELATIONS, "Line": 1, "Column": 1, "TemplatePath": None},
        "Finding": "irrelevant to the summary",
        "WhyItMatters": "irrelevant to the summary",
        "Evidence": [
            {"Source": source, "Detail": "detail", "RuleId": rule, "Excerpt": None}
        ],
        "Recommendation": "irrelevant to the summary",
        "SuggestedRemediation": None,
    }


# ---------------------------------------------------------------------------
# (a) Key structure of the facts JSON
# ---------------------------------------------------------------------------


def test_facts_document_carries_every_documented_top_level_key(
    relations_facts: Dict[str, Any]
) -> None:
    assert sorted(relations_facts) == FACTS_KEYS


def test_target_names_the_template_relative_to_the_workspace(
    relations_facts: Dict[str, Any]
) -> None:
    target = relations_facts["target"]
    assert sorted(target) == TARGET_KEYS
    assert target["file"] == RELATIONS
    assert target["format"] == "yaml"
    # The Template's own Description: the usual evidence for intended
    # environment, which contextual severity assessment works from.
    assert "facts-extraction test data" in target["description"]


def test_json_template_is_reported_as_json(plugin_root: Path) -> None:
    facts = _facts(plugin_root, "--target", JSON_TEMPLATE)
    assert facts["target"]["format"] == "json"
    assert [entry["logical_id"] for entry in facts["resources"]] == ["DataBucket"]


def test_resources_are_listed_in_template_order_with_the_documented_keys(
    relations_facts: Dict[str, Any]
) -> None:
    assert [entry["logical_id"] for entry in relations_facts["resources"]] == [
        "DataBucket",
        "AppExecutionRole",
        "AppFunction",
    ]
    for entry in relations_facts["resources"]:
        assert sorted(entry) == RESOURCE_KEYS
        assert isinstance(entry["properties"], dict)


def test_resource_records_its_type_and_condition(
    relations_facts: Dict[str, Any]
) -> None:
    function = _resource(relations_facts, "AppFunction")
    assert function["type"] == "AWS::Lambda::Function"
    assert function["condition"] == "IsProduction"
    assert _resource(relations_facts, "DataBucket")["condition"] is None


def test_properties_keep_intrinsic_functions_unresolved(
    relations_facts: Dict[str, Any]
) -> None:
    # Requirement 16 AC1: nothing in the Template is evaluated. The Agent must
    # see that Role came from an Fn::GetAtt rather than a value the script
    # invented.
    role = _resource(relations_facts, "AppFunction")["properties"]["Role"]
    assert role == {"Fn::GetAtt": ["AppExecutionRole", "Arn"]}


def test_availability_properties_are_reported_with_their_item_count(
    relations_facts: Dict[str, Any]
) -> None:
    availability = _resource(relations_facts, "AppFunction")["availability"]
    assert len(availability) == 1
    entry = availability[0]
    assert sorted(entry) == AVAILABILITY_KEYS
    assert entry["property"] == "SubnetIds"
    assert entry["json_path"] == "Resources.AppFunction.Properties.VpcConfig.SubnetIds"
    # One subnet is the single-Availability-Zone signal; judging it is the
    # Agent's job, not this script's.
    assert entry["item_count"] == 1
    assert _resource(relations_facts, "DataBucket")["availability"] == []


def test_parameters_carry_defaults_and_the_resources_that_use_them(
    relations_facts: Dict[str, Any]
) -> None:
    assert [entry["name"] for entry in relations_facts["parameters"]] == [
        "EnvironmentName",
        "LogBucketName",
        "DatabasePassword",
        "AppSubnetId",
    ]
    for entry in relations_facts["parameters"]:
        assert sorted(entry) == PARAMETER_KEYS

    log_bucket = _parameter(relations_facts, "LogBucketName")
    assert log_bucket["default"] == "app-access-logs"
    assert log_bucket["has_default"] is True
    assert log_bucket["referenced_by"] == ["DataBucket"]

    subnet = _parameter(relations_facts, "AppSubnetId")
    assert subnet["has_default"] is False
    assert subnet["default"] is None
    assert subnet["referenced_by"] == ["AppFunction"]

    # Referenced only from Conditions, which is not a resource body.
    assert _parameter(relations_facts, "EnvironmentName")["referenced_by"] == []


def test_noecho_parameter_default_is_redacted(
    relations_facts: Dict[str, Any]
) -> None:
    # steering/security.md: a value the Template author marked sensitive is not
    # copied into the plugin's output, while has_default still reports the fact.
    password = _parameter(relations_facts, "DatabasePassword")
    assert password["no_echo"] is True
    assert password["has_default"] is True
    assert "replace-before-deploying" not in json.dumps(relations_facts)
    assert "redacted" in password["default"]
    assert "redacted" in password["allowed_values"]


def test_conditions_are_reproduced_unevaluated(
    relations_facts: Dict[str, Any]
) -> None:
    assert len(relations_facts["conditions"]) == 1
    condition = relations_facts["conditions"][0]
    assert sorted(condition) == CONDITION_KEYS
    assert condition["name"] == "IsProduction"
    assert condition["definition"] == {
        "Fn::Equals": [{"Ref": "EnvironmentName"}, "production"]
    }


def test_deterministic_source_coverage_is_stated_per_source(
    relations_facts: Dict[str, Any]
) -> None:
    coverage = relations_facts["deterministic_sources"]
    assert [entry["name"] for entry in coverage] == [
        "cfn-lint",
        "cfn-guard",
        "IAM Review",
    ]
    for entry in coverage:
        assert sorted(entry) == SOURCE_COVERAGE_KEYS
    in_process = {
        entry["name"]: entry["computed_in_process"] for entry in coverage
    }
    # Only the IAM Source runs here, so only its zero would mean "clean".
    assert in_process == {
        "cfn-lint": False,
        "cfn-guard": False,
        "IAM Review": True,
    }


# ---------------------------------------------------------------------------
# (b) The Ref / Fn::GetAtt reference graph
# ---------------------------------------------------------------------------


def test_reference_graph_holds_exactly_the_resource_to_resource_edges(
    relations_facts: Dict[str, Any]
) -> None:
    # From the fixture header: the three edges the Template writes, and nothing
    # else. Parameter references, the pseudo parameter AWS::AccountId, and the
    # Conditions section are all excluded from the graph.
    assert _edges(relations_facts) == [
        ("AppExecutionRole", "DataBucket", "Fn::Sub", "Arn"),
        ("AppFunction", "DataBucket", "Ref", None),
        ("AppFunction", "AppExecutionRole", "Fn::GetAtt", "Arn"),
    ]
    for entry in relations_facts["references"]:
        assert sorted(entry) == REFERENCE_KEYS


def test_each_edge_points_at_the_property_that_holds_the_intrinsic(
    relations_facts: Dict[str, Any]
) -> None:
    paths = {
        (entry["from"], entry["to"]): entry["json_path"]
        for entry in relations_facts["references"]
    }
    assert paths[("AppFunction", "AppExecutionRole")] == (
        "Resources.AppFunction.Properties.Role"
    )
    assert paths[("AppFunction", "DataBucket")] == (
        "Resources.AppFunction.Properties.Environment.Variables.BUCKET_NAME"
    )
    assert paths[("AppExecutionRole", "DataBucket")] == (
        "Resources.AppExecutionRole.Properties.Policies.0.PolicyDocument"
        ".Statement.0.Resource"
    )


def test_depends_on_edges_are_reported_separately(
    relations_facts: Dict[str, Any]
) -> None:
    assert relations_facts["depends_on"] == [
        {"from": "AppFunction", "to": "DataBucket"}
    ]
    for entry in relations_facts["depends_on"]:
        assert sorted(entry) == DEPENDS_ON_KEYS


def test_a_template_without_relationships_has_empty_graphs(
    plugin_root: Path
) -> None:
    facts = _facts(plugin_root, "--target", JSON_TEMPLATE)
    # The one Ref in that Template is in Outputs, which is not a resource body.
    assert facts["references"] == []
    assert facts["depends_on"] == []


# ---------------------------------------------------------------------------
# (c) Determinism
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("target", [RELATIONS, JSON_TEMPLATE, DANGEROUS_IAM])
def test_two_runs_produce_byte_identical_output(
    plugin_root: Path, target: str
) -> None:
    first = _run(plugin_root, "--target", target)
    second = _run(plugin_root, "--target", target)
    assert first.returncode == second.returncode == EXIT_OK
    assert first.stdout == second.stdout


def test_verbose_changes_stderr_but_not_stdout(plugin_root: Path) -> None:
    quiet = _run(plugin_root, "--target", RELATIONS)
    verbose = _run(plugin_root, "--target", RELATIONS, "--verbose")
    assert verbose.returncode == EXIT_OK
    assert verbose.stdout == quiet.stdout
    assert len(verbose.stderr) > len(quiet.stderr)


def test_report_option_order_does_not_show_through(
    plugin_root: Path, reports_dir: Path
) -> None:
    lint = _write_report(
        reports_dir,
        "cfn-lint.json",
        [
            _deterministic_finding(
                "cfn-lint", "E3002", "AppFunction", "TemplateQuality", "HIGH"
            )
        ],
        plugin_root,
    )
    guard = _write_report(
        reports_dir,
        "cfn-guard.json",
        [
            _deterministic_finding(
                "cfn-guard", "s3_encryption", "DataBucket", "Encryption", "MEDIUM"
            )
        ],
        plugin_root,
    )

    forward = _run(
        plugin_root,
        "--target",
        RELATIONS,
        "--deterministic-report",
        lint,
        "--deterministic-report",
        guard,
    )
    reversed_order = _run(
        plugin_root,
        "--target",
        RELATIONS,
        "--deterministic-report",
        guard,
        "--deterministic-report",
        lint,
    )
    assert forward.returncode == reversed_order.returncode == EXIT_OK
    assert forward.stdout == reversed_order.stdout


# ---------------------------------------------------------------------------
# (d) The deterministic findings summary
# ---------------------------------------------------------------------------


def test_summary_is_present_and_summarizes_the_in_process_iam_source(
    relations_facts: Dict[str, Any]
) -> None:
    summary = relations_facts["deterministic_findings_summary"]
    assert isinstance(summary, list)
    for entry in summary:
        assert sorted(entry) == SUMMARY_KEYS
        assert entry["source"] == "IAM Review"
    # The fixture header states the one deterministic IAM finding it produces.
    assert [entry["rule"] for entry in summary] == ["unresolvable_value"]
    assert summary[0]["resource"] == "AppExecutionRole"
    assert summary[0]["severity"] == "INFO"


def test_summary_reports_the_dangerous_iam_findings_of_a_security_fixture(
    plugin_root: Path
) -> None:
    facts = _facts(plugin_root, "--target", DANGEROUS_IAM)
    summary = facts["deterministic_findings_summary"]
    rules = {entry["rule"] for entry in summary}
    # Two of the rules that fixture's header documents. Their presence is what
    # tells the Agent these are taken (Requirement 2 AC14, AC15).
    assert {"star_action_star_resource", "principal_star"} <= rules
    assert {entry["source"] for entry in summary} == {"IAM Review"}
    assert {entry["category"] for entry in summary} == {"IAM"}

    coverage = {
        entry["name"]: entry["findings_summarized"]
        for entry in facts["deterministic_sources"]
    }
    assert coverage["IAM Review"] == len(summary)


def test_supplied_reports_extend_the_summary(
    plugin_root: Path, reports_dir: Path
) -> None:
    report = _write_report(
        reports_dir,
        "report.json",
        [
            _deterministic_finding(
                "cfn-lint", "W3011", "DataBucket", "TemplateQuality", "MEDIUM"
            ),
            _deterministic_finding(
                "cfn-guard", "s3_logging", "DataBucket", "Logging", "LOW"
            ),
            # Agent output is not a deterministic finding and must not be fed
            # back as one.
            {
                **_deterministic_finding(
                    "cfn-lint", "ignored", "DataBucket", "Other", "LOW"
                ),
                "Source": ["Agent Review"],
                "Confidence": "Likely",
            },
        ],
        plugin_root,
    )
    facts = _facts(
        plugin_root, "--target", RELATIONS, "--deterministic-report", report
    )

    summary = facts["deterministic_findings_summary"]
    by_source = {entry["source"] for entry in summary}
    assert by_source == {"cfn-lint", "cfn-guard", "IAM Review"}
    assert {entry["rule"] for entry in summary} == {
        "W3011",
        "s3_logging",
        "unresolvable_value",
    }
    coverage = {
        entry["name"]: entry["findings_summarized"]
        for entry in facts["deterministic_sources"]
    }
    assert coverage == {"cfn-lint": 1, "cfn-guard": 1, "IAM Review": 1}
    # Recorded as a workspace-relative path, never as an absolute host path
    # (Requirement 16 AC11).
    assert facts["deterministic_reports"] == [report]


def test_the_same_report_supplied_twice_is_summarized_once(
    plugin_root: Path, reports_dir: Path
) -> None:
    report = _write_report(
        reports_dir,
        "report.json",
        [
            _deterministic_finding(
                "cfn-lint", "E3002", "AppFunction", "TemplateQuality", "HIGH"
            )
        ],
        plugin_root,
    )
    once = _facts(
        plugin_root, "--target", RELATIONS, "--deterministic-report", report
    )
    twice = _facts(
        plugin_root,
        "--target",
        RELATIONS,
        "--deterministic-report",
        report,
        "--deterministic-report",
        report,
    )
    assert (
        once["deterministic_findings_summary"]
        == twice["deterministic_findings_summary"]
    )


# ---------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------


def test_missing_target_is_an_argument_error_with_empty_stdout(
    plugin_root: Path
) -> None:
    completed = _run(plugin_root)
    assert completed.returncode == EXIT_INVALID_ARGUMENTS
    assert completed.stdout == b""
    assert b"--target" in completed.stderr


def test_a_target_outside_the_workspace_is_refused(plugin_root: Path) -> None:
    completed = _run(plugin_root, "--target", "../")
    assert completed.returncode == EXIT_PATH_VIOLATION
    assert completed.stdout == b""


def test_a_file_without_resources_is_not_reviewable(plugin_root: Path) -> None:
    completed = _run(plugin_root, "--target", NOT_REVIEWABLE)
    assert completed.returncode == EXIT_NOT_REVIEWABLE
    assert completed.stdout == b""


def test_a_report_that_is_not_a_findings_document_is_refused(
    plugin_root: Path, reports_dir: Path
) -> None:
    report = reports_dir / "not-a-report.json"
    report.write_text('{"unexpected": true}', encoding="utf-8")
    relative = report.relative_to(plugin_root).as_posix()
    completed = _run(
        plugin_root, "--target", RELATIONS, "--deterministic-report", relative
    )
    assert completed.returncode == EXIT_PARSE_FAILURE
    assert completed.stdout == b""
    assert b"findings" in completed.stderr
