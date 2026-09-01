"""Tests for the SARIF 2.1.0 converter (:mod:`iacreview.sarif`).

The converter is a pure, deterministic transform: Review_Report in, SARIF out.
It runs no review and reads no file. What these tests lock:

* the envelope is well-formed SARIF 2.1.0 (version, schema, one run, a driver);
* every Finding becomes one result, attributed to a stable rule id;
* Severity maps to the right SARIF level and security-severity bucket;
* the plugin's Confidence, category and merged Source list survive in
  properties;
* the file and the logical-ID breadcrumb reach the location;
* the same report always produces the same SARIF.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

import pytest

from iacreview import sarif


def _finding(**overrides: Any) -> Dict[str, Any]:
    base: Dict[str, Any] = {
        "ID": 1,
        "Normalized_Category": "IAM",
        "FindingType": "Security",
        "Severity": "CRITICAL",
        "Confidence": "Confirmed",
        "Source": ["IAM Review"],
        "Resource": "AdminRole",
        "Location": {
            "File": "templates/app.yaml",
            "Line": None,
            "Column": None,
            "TemplatePath": ["Resources", "AdminRole", "Properties"],
        },
        "Finding": "[star_action_star_resource] Action and Resource are both \"*\".",
        "WhyItMatters": "Grants everything.",
        "Evidence": [
            {"Source": "IAM Review", "Detail": "d", "RuleId": "star_action_star_resource", "Excerpt": None}
        ],
        "Recommendation": "Scope it.",
        "SuggestedRemediation": None,
    }
    base.update(overrides)
    return base


def _report(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {"schema_version": "1.0.0", "findings": findings}


# ---------------------------------------------------------------------------
# Envelope
# ---------------------------------------------------------------------------


def test_envelope_is_sarif_210() -> None:
    doc = sarif.to_sarif(_report([]))
    assert doc["version"] == "2.1.0"
    assert doc["$schema"] == sarif.SARIF_SCHEMA_URI
    assert isinstance(doc["runs"], list) and len(doc["runs"]) == 1


def test_driver_names_the_tool() -> None:
    doc = sarif.to_sarif(_report([]))
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == sarif.TOOL_NAME


def test_tool_version_is_recorded_when_supplied() -> None:
    doc = sarif.to_sarif(_report([]), tool_version="0.7.0")
    assert doc["runs"][0]["tool"]["driver"]["version"] == "0.7.0"


def test_tool_version_is_omitted_when_absent() -> None:
    doc = sarif.to_sarif(_report([]))
    assert "version" not in doc["runs"][0]["tool"]["driver"]


def test_empty_report_yields_no_results() -> None:
    doc = sarif.to_sarif(_report([]))
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []


def test_missing_findings_key_is_tolerated() -> None:
    doc = sarif.to_sarif({"schema_version": "1.0.0"})
    assert doc["runs"][0]["results"] == []


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------


def test_each_finding_becomes_one_result() -> None:
    doc = sarif.to_sarif(_report([_finding(), _finding(Resource="Other")]))
    assert len(doc["runs"][0]["results"]) == 2


def test_result_is_attributed_to_the_rule_id() -> None:
    doc = sarif.to_sarif(_report([_finding()]))
    assert doc["runs"][0]["results"][0]["ruleId"] == "star_action_star_resource"


def test_rule_id_falls_back_to_source_when_no_rule() -> None:
    finding = _finding(
        Source=["Agent Review"],
        Evidence=[{"Source": "Agent Review", "Detail": "d", "RuleId": None, "Excerpt": "x"}],
    )
    doc = sarif.to_sarif(_report([finding]))
    assert doc["runs"][0]["results"][0]["ruleId"] == "Agent Review"


def test_message_is_the_finding_text() -> None:
    doc = sarif.to_sarif(_report([_finding()]))
    assert "Action and Resource" in doc["runs"][0]["results"][0]["message"]["text"]


# ---------------------------------------------------------------------------
# Level and severity mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("severity", "level"),
    [
        ("CRITICAL", "error"),
        ("HIGH", "error"),
        ("MEDIUM", "warning"),
        ("LOW", "note"),
        ("INFO", "note"),
    ],
)
def test_severity_maps_to_level(severity: str, level: str) -> None:
    assert sarif.level_for(severity, "Security") == level
    doc = sarif.to_sarif(_report([_finding(Severity=severity)]))
    assert doc["runs"][0]["results"][0]["level"] == level


def test_security_severity_bucket_is_set() -> None:
    doc = sarif.to_sarif(_report([_finding(Severity="CRITICAL")]))
    props = doc["runs"][0]["results"][0]["properties"]
    assert props["security-severity"] == "9.5"


# ---------------------------------------------------------------------------
# Properties preserve what SARIF has no native field for
# ---------------------------------------------------------------------------


def test_properties_preserve_confidence_and_category() -> None:
    doc = sarif.to_sarif(_report([_finding(Confidence="Likely", Normalized_Category="Availability")]))
    props = doc["runs"][0]["results"][0]["properties"]
    assert props["confidence"] == "Likely"
    assert props["category"] == "Availability"


def test_properties_preserve_the_merged_source_list() -> None:
    finding = _finding(Source=["cfn-lint", "cfn-guard"])
    doc = sarif.to_sarif(_report([finding]))
    assert doc["runs"][0]["results"][0]["properties"]["sources"] == ["cfn-lint", "cfn-guard"]


# ---------------------------------------------------------------------------
# Location
# ---------------------------------------------------------------------------


def test_location_carries_the_file() -> None:
    doc = sarif.to_sarif(_report([_finding()]))
    loc = doc["runs"][0]["results"][0]["locations"][0]
    assert loc["physicalLocation"]["artifactLocation"]["uri"] == "templates/app.yaml"


def test_location_omits_region_when_no_line() -> None:
    doc = sarif.to_sarif(_report([_finding()]))
    loc = doc["runs"][0]["results"][0]["locations"][0]
    assert "region" not in loc["physicalLocation"]


def test_location_includes_region_when_line_present() -> None:
    finding = _finding(Location={"File": "t.yaml", "Line": 12, "Column": 3, "TemplatePath": None})
    doc = sarif.to_sarif(_report([finding]))
    region = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region == {"startLine": 12, "startColumn": 3}


def test_logical_location_carries_the_resource_breadcrumb() -> None:
    doc = sarif.to_sarif(_report([_finding()]))
    logical = doc["runs"][0]["results"][0]["locations"][0]["logicalLocations"][0]
    assert logical["name"] == "AdminRole"
    assert logical["fullyQualifiedName"] == "Resources/AdminRole/Properties"


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


def test_one_rule_per_distinct_rule_id() -> None:
    findings = [_finding(), _finding(Resource="Other"), _finding(
        Evidence=[{"Source": "IAM Review", "Detail": "d", "RuleId": "wildcard_action", "Excerpt": None}]
    )]
    doc = sarif.to_sarif(_report(findings))
    rule_ids = [r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]]
    assert rule_ids == ["star_action_star_resource", "wildcard_action"]


# ---------------------------------------------------------------------------
# Determinism and serializability
# ---------------------------------------------------------------------------


def test_conversion_is_deterministic() -> None:
    report = _report([_finding(), _finding(Resource="B", Severity="LOW")])
    assert sarif.to_sarif(report) == sarif.to_sarif(report)


def test_output_is_json_serializable() -> None:
    doc = sarif.to_sarif(_report([_finding()]))
    json.dumps(doc)  # raises if anything is not serializable
