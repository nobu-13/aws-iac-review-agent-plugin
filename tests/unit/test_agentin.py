"""Agent findings input boundary: acceptance, correction, and per-entry drops.

Locks what :mod:`iacreview.agentin` guarantees about a file the host agent wrote
(design.md, Components and Interfaces / ``iacreview.agentin``; Requirement 7
AC10, AC11; Requirement 14 AC3):

* a well-formed file loads with no errors,
* ``Confidence: "Confirmed"`` is demoted to ``Likely`` and warned about on
  stderr instead of being rejected,
* a Category outside the closed set becomes ``Other``,
* an Evidence entry with no ``Excerpt`` costs that Finding,
* a file that is not an agent findings file raises,
* and one bad entry never costs a good one.

Findings are written as JSON-shaped dicts, the way the agent produces them,
rather than as :class:`~iacreview.finding.Finding` objects: the contract under
test is the JSON boundary.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

from iacreview import agentin
from iacreview.errors import InputNotFoundError, SchemaViolationError
from iacreview.finding import OTHER_CATEGORY, UNASSIGNED_ID, Finding


def agent_entry(**overrides: Any) -> Dict[str, Any]:
    """One valid agent finding, as JSON. Mirrors design.md's Layer 2 output."""
    entry: Dict[str, Any] = {
        "Normalized_Category": "IAM",
        "FindingType": "BestPractice",
        "Severity": "MEDIUM",
        "Confidence": "Likely",
        "Source": ["Agent Review"],
        "Resource": "AppExecutionRole",
        "Location": {
            "File": "templates/app.yaml",
            "Line": None,
            "Column": None,
            "TemplatePath": ["Resources", "AppExecutionRole", "Properties", "Policies", 0],
        },
        "Finding": "The role may grant broader access than AppFunction requires.",
        "WhyItMatters": "Excess permissions increase the blast radius of a compromise.",
        "Evidence": [
            {
                "Source": "Agent Review",
                "Detail": "AppExecutionRole is referenced by AppFunction.Properties.Role",
                "RuleId": None,
                "Excerpt": 'Action: ["s3:*"]',
            }
        ],
        "Recommendation": "Scope the policy to the actions the function performs.",
        "SuggestedRemediation": "Replace s3:* with the specific object actions used.",
    }
    entry.update(overrides)
    return entry


def envelope(*entries: Dict[str, Any]) -> Dict[str, Any]:
    """The object form of the file, as design.md's report envelope spells it."""
    return {"schema_version": "1.0.0", "findings": list(entries)}


def write(tmp_path: Path, payload: Any, name: str = "agent-findings.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# (a) a well-formed file
# ---------------------------------------------------------------------------


def test_valid_agent_findings_load_with_no_errors(tmp_path: Path) -> None:
    path = write(tmp_path, envelope(agent_entry()))

    findings, errors = agentin.load_agent_findings(path)

    assert errors == []
    assert len(findings) == 1
    f = findings[0]
    assert isinstance(f, Finding)
    assert f.Normalized_Category == "IAM"
    assert f.Confidence == "Likely"
    assert f.Source == ["Agent Review"]
    assert f.Resource == "AppExecutionRole"
    assert f.Evidence[0].Excerpt == 'Action: ["s3:*"]'
    assert f.Location.TemplatePath == [
        "Resources",
        "AppExecutionRole",
        "Properties",
        "Policies",
        0,
    ]


def test_loaded_findings_carry_no_assigned_id(tmp_path: Path) -> None:
    """IDs belong to the sorted, deduplicated report, not to the agent."""
    path = write(tmp_path, envelope(agent_entry(ID=99), agent_entry()))

    findings, errors = agentin.load_agent_findings(path)

    assert errors == []
    assert [f.ID for f in findings] == [UNASSIGNED_ID, UNASSIGNED_ID]


def test_bare_array_is_accepted_and_nullable_fields_may_be_omitted() -> None:
    entry = agent_entry()
    del entry["Resource"]
    del entry["SuggestedRemediation"]

    findings, errors = agentin.findings_from_payload([entry])

    assert errors == []
    assert findings[0].Resource is None
    assert findings[0].SuggestedRemediation is None


def test_source_may_be_omitted_and_defaults_to_agent_review() -> None:
    entry = agent_entry()
    del entry["Source"]
    del entry["Evidence"][0]["Source"]

    findings, errors = agentin.findings_from_payload([entry])

    assert errors == []
    assert findings[0].Source == ["Agent Review"]
    assert findings[0].Evidence[0].Source == "Agent Review"


def test_payload_is_not_modified_by_validation() -> None:
    payload = envelope(agent_entry())
    before = copy.deepcopy(payload)

    agentin.findings_from_payload(payload)

    assert payload == before


def test_empty_findings_list_is_a_valid_file() -> None:
    assert agentin.findings_from_payload({"findings": []}) == ([], [])


# ---------------------------------------------------------------------------
# (b) Confirmed is demoted, with a warning on stderr
# ---------------------------------------------------------------------------


def test_confirmed_is_demoted_to_likely_with_a_stderr_warning(
    capsys: pytest.CaptureFixture[str],
) -> None:
    findings, errors = agentin.findings_from_payload([agent_entry(Confidence="Confirmed")])

    assert errors == []
    assert findings[0].Confidence == agentin.DEMOTED_CONFIDENCE == "Likely"
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Confirmed" in captured.err
    assert "findings[0]" in captured.err


def test_agent_confidences_exclude_confirmed() -> None:
    assert agentin.AGENT_CONFIDENCES == ("Likely", "Contextual")


@pytest.mark.parametrize("confidence", ["Likely", "Contextual"])
def test_permitted_confidences_pass_through_unchanged(confidence: str) -> None:
    findings, errors = agentin.findings_from_payload([agent_entry(Confidence=confidence)])

    assert errors == []
    assert findings[0].Confidence == confidence


# ---------------------------------------------------------------------------
# (c) an unmappable Category falls back to Other
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "category",
    ["CostOptimization", "iam", "", "Anything The Closed Set Does Not Name"],
)
def test_category_outside_the_closed_set_becomes_other(category: str) -> None:
    findings, errors = agentin.findings_from_payload(
        [agent_entry(Normalized_Category=category)]
    )

    assert errors == []
    assert findings[0].Normalized_Category == OTHER_CATEGORY


def test_missing_category_becomes_other() -> None:
    entry = agent_entry()
    del entry["Normalized_Category"]

    findings, errors = agentin.findings_from_payload([entry])

    assert errors == []
    assert findings[0].Normalized_Category == OTHER_CATEGORY


def test_non_string_category_is_a_violation_not_a_fallback() -> None:
    findings, errors = agentin.findings_from_payload(
        [agent_entry(Normalized_Category={"name": "IAM"})]
    )

    assert findings == []
    assert len(errors) == 1
    assert "findings[0].Normalized_Category" in errors[0]["message"]


# ---------------------------------------------------------------------------
# (d) a missing Excerpt drops the Finding and records one error
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("excerpt", [None, ""])
def test_evidence_without_an_excerpt_drops_the_finding(excerpt: Any) -> None:
    entry = agent_entry()
    entry["Evidence"][0]["Excerpt"] = excerpt

    findings, errors = agentin.findings_from_payload([entry])

    assert findings == []
    assert len(errors) == 1
    error = errors[0]
    assert error["error_class"] == "schema_violation"
    assert error["source"] == "Agent Review"
    assert "findings[0].Evidence[0].Excerpt" in error["message"]


def test_every_evidence_entry_needs_its_own_excerpt() -> None:
    """Stricter than the schema minimum: design.md Layer 2 constraint 3."""
    entry = agent_entry()
    entry["Evidence"].append(
        {
            "Source": "Agent Review",
            "Detail": "AppFunction has no reserved concurrency",
            "RuleId": None,
            "Excerpt": None,
        }
    )

    findings, errors = agentin.findings_from_payload([entry])

    assert findings == []
    assert "findings[0].Evidence[1].Excerpt" in errors[0]["message"]


# ---------------------------------------------------------------------------
# (e) the file as a whole is unusable
# ---------------------------------------------------------------------------


def test_invalid_json_raises_schema_violation(tmp_path: Path) -> None:
    path = tmp_path / "agent-findings.json"
    path.write_text('{"findings": [', encoding="utf-8")

    with pytest.raises(SchemaViolationError) as excinfo:
        agentin.load_agent_findings(path)

    assert "not valid JSON" in str(excinfo.value)


@pytest.mark.parametrize(
    "payload",
    [
        "a bare string",
        42,
        None,
        {"findings": {"0": "not an array"}},
        {"finding": []},
        {"findings": [], "unexpected": 1},
        {"findings": [], "schema_version": "2.0.0"},
        {"findings": [], "schema_version": 1},
        {},
    ],
    ids=[
        "string",
        "number",
        "null",
        "findings-not-an-array",
        "misspelled-envelope-key",
        "unknown-envelope-key",
        "unsupported-major",
        "non-string-schema-version",
        "no-findings-key",
    ],
)
def test_payload_that_is_not_an_agent_findings_file_raises(payload: Any) -> None:
    with pytest.raises(SchemaViolationError):
        agentin.findings_from_payload(payload)


def test_whole_file_failure_exits_with_the_parse_failure_code() -> None:
    """design.md's failure matrix assigns 4 to a wholly invalid agent file."""
    with pytest.raises(SchemaViolationError) as excinfo:
        agentin.findings_from_payload("not an agent findings file")

    assert excinfo.value.exit_code == 4


def test_missing_file_reports_input_not_found(tmp_path: Path) -> None:
    with pytest.raises(InputNotFoundError):
        agentin.load_agent_findings(tmp_path / "absent.json")


def test_directory_in_place_of_a_file_reports_input_not_found(tmp_path: Path) -> None:
    with pytest.raises(InputNotFoundError):
        agentin.load_agent_findings(tmp_path)


# ---------------------------------------------------------------------------
# (f) one bad entry does not cost the others
# ---------------------------------------------------------------------------


def test_a_dropped_finding_leaves_the_others_loaded(tmp_path: Path) -> None:
    good_first = agent_entry(Resource="FirstRole")
    broken = agent_entry(Resource="BrokenRole", Severity="SEVERE")
    good_last = agent_entry(Resource="LastRole")
    path = write(tmp_path, envelope(good_first, broken, good_last))

    findings, errors = agentin.load_agent_findings(path)

    assert [f.Resource for f in findings] == ["FirstRole", "LastRole"]
    assert len(errors) == 1
    assert "findings[1].Severity" in errors[0]["message"]


def test_each_dropped_finding_records_its_own_error() -> None:
    entries: List[Dict[str, Any]] = [
        agent_entry(),
        {"not": "a finding object"},
        [],
        agent_entry(FindingType="Speculation"),
    ]

    findings, errors = agentin.findings_from_payload(entries)

    assert len(findings) == 1
    assert len(errors) == 3
    assert [error["error_class"] for error in errors] == ["schema_violation"] * 3
    assert all(error["source"] == "Agent Review" for error in errors)
    assert "findings[1]" in errors[0]["message"]
    assert "findings[2]" in errors[1]["message"]
    assert "findings[3].FindingType" in errors[2]["message"]


# ---------------------------------------------------------------------------
# Attribution: agent output cannot present itself as a deterministic Source
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "source",
    [
        ["cfn-lint"],
        ["cfn-guard"],
        ["IAM Review"],
        ["cfn-lint", "Agent Review"],
        "Agent Review",
        [],
    ],
    ids=["cfn-lint", "cfn-guard", "iam", "merged", "bare-string", "empty"],
)
def test_a_source_other_than_agent_review_is_rejected(source: Any) -> None:
    findings, errors = agentin.findings_from_payload([agent_entry(Source=source)])

    assert findings == []
    assert "findings[0].Source" in errors[0]["message"]


def test_evidence_attributed_to_a_deterministic_tool_is_rejected() -> None:
    entry = agent_entry()
    entry["Evidence"][0]["Source"] = "cfn-lint"

    findings, errors = agentin.findings_from_payload([entry])

    assert findings == []
    assert "findings[0].Evidence[0].Source" in errors[0]["message"]


def test_unknown_finding_field_is_rejected() -> None:
    findings, errors = agentin.findings_from_payload([agent_entry(Certainty="high")])

    assert findings == []
    assert "findings[0].Certainty" in errors[0]["message"]


def test_non_integer_id_is_rejected() -> None:
    findings, errors = agentin.findings_from_payload([agent_entry(ID="3")])

    assert findings == []
    assert "findings[0].ID" in errors[0]["message"]


def test_non_string_finding_key_is_rejected() -> None:
    """Unreachable through JSON, reachable through a hand-built payload."""
    findings, errors = agentin.findings_from_payload([{1: "IAM"}])

    assert findings == []
    assert "findings[0]" in errors[0]["message"]


def test_evidence_entry_that_is_not_an_object_is_rejected() -> None:
    entry = agent_entry()
    entry["Evidence"] = ["Action: [\"s3:*\"]"]

    findings, errors = agentin.findings_from_payload([entry])

    assert findings == []
    assert "findings[0].Evidence[0]" in errors[0]["message"]


def test_absolute_location_file_is_rejected() -> None:
    entry = agent_entry()
    entry["Location"] = {"File": "/Users/someone/templates/app.yaml"}

    findings, errors = agentin.findings_from_payload([entry])

    assert findings == []
    assert "findings[0].Location.File" in errors[0]["message"]
