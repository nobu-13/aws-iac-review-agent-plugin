"""Finding schema checks: round trip, closed value sets, structural constraints.

Locks the contract every Source normalizes onto (design.md, Data Models /
Finding schema (authoritative); Requirement 7 AC1-AC13):

* a valid Finding survives ``to_dict`` -> ``from_dict`` unchanged, in both
  directions, so a report can be written and read back,
* each of the 13 fields is genuinely required,
* values outside the closed sets are rejected,
* the four constraints JSON Schema cannot express are enforced,
* ``Source`` must arrive already in canonical order (Requirement 16 AC11).

Findings here use real ``Normalized_Category`` values, so the tests keep passing
once ``iacreview.categories`` exists and the category hook starts resolving
itself.
"""

from __future__ import annotations

import copy
import json
from typing import Any, Dict, Iterator, List, Optional

import pytest

from iacreview import finding as fmod
from iacreview.errors import SchemaViolationError
from iacreview.finding import Evidence, Finding, Location

# The 13 keys, written out rather than imported, so a change to the dataclass
# fails here instead of silently redefining the contract.
EXPECTED_FIELDS = (
    "ID",
    "Normalized_Category",
    "FindingType",
    "Severity",
    "Confidence",
    "Source",
    "Resource",
    "Location",
    "Finding",
    "WhyItMatters",
    "Evidence",
    "Recommendation",
    "SuggestedRemediation",
)


@pytest.fixture(autouse=True)
def reset_hooks() -> Iterator[None]:
    """Leave both validation hooks uninstalled around every test."""
    fmod.set_category_validator(None)
    fmod.set_blocks_deployment_resolver(None)
    yield
    fmod.set_category_validator(None)
    fmod.set_blocks_deployment_resolver(None)


def confirmed_finding(**overrides: Any) -> Finding:
    """A deterministic cfn-lint Finding, taken from the design worked example."""
    base: Dict[str, Any] = {
        "ID": 1,
        "Normalized_Category": "IAM",
        "FindingType": "Security",
        "Severity": "HIGH",
        "Confidence": "Confirmed",
        "Source": ["cfn-lint"],
        "Resource": "AppExecutionRole",
        "Location": Location(
            File="templates/app.yaml",
            Line=42,
            Column=9,
            TemplatePath=["Resources", "AppExecutionRole", "Properties", "Policies", 0],
        ),
        "Finding": '[W3037] IAM action "s3:GetObjects" is not a valid action.',
        "WhyItMatters": "An invalid IAM action does not grant the intended access.",
        "Evidence": [
            Evidence(
                Source="cfn-lint",
                Detail="Rule W3037",
                RuleId="W3037",
                Excerpt=None,
            )
        ],
        "Recommendation": "Correct the IAM action name to a valid service action.",
        "SuggestedRemediation": None,
    }
    base.update(overrides)
    return Finding(**base)


def agent_finding(**overrides: Any) -> Finding:
    """An agent Finding: not Confirmed, and carrying the required Excerpt."""
    base: Dict[str, Any] = {
        "ID": 2,
        "Normalized_Category": "IAM",
        "FindingType": "BestPractice",
        "Severity": "MEDIUM",
        "Confidence": "Likely",
        "Source": ["Agent Review"],
        "Resource": "AppExecutionRole",
        "Location": Location(File="templates/app.yaml", TemplatePath=None),
        "Finding": "The granted permissions may be broader than the function requires.",
        "WhyItMatters": "Excess permissions increase the blast radius.",
        "Evidence": [
            Evidence(
                Source="Agent Review",
                Detail="AppExecutionRole is referenced by AppFunction.Properties.Role",
                RuleId=None,
                Excerpt="Role: !GetAtt AppExecutionRole.Arn",
            )
        ],
        "Recommendation": "Scope the policy to the actions the runtime needs.",
        "SuggestedRemediation": "Replace the wildcard statement with least-privilege statements.",
    }
    base.update(overrides)
    return Finding(**base)


def validity_critical_finding(rule_id: Optional[str] = "E0000") -> Finding:
    return confirmed_finding(
        Normalized_Category="TemplateQuality",
        FindingType="Validity",
        Severity="CRITICAL",
        Finding="[E0000] Template is not valid YAML.",
        Evidence=[Evidence(Source="cfn-lint", Detail="Rule E0000", RuleId=rule_id)],
    )


# ---------------------------------------------------------------------------
# Shape and round trip
# ---------------------------------------------------------------------------


def test_field_set_is_the_thirteen_required_fields() -> None:
    assert fmod.FINDING_FIELDS == EXPECTED_FIELDS
    assert len(fmod.FINDING_FIELDS) == 13


def test_valid_finding_passes_validation() -> None:
    fmod.validate(confirmed_finding())


def test_to_dict_emits_every_key_including_the_null_ones() -> None:
    payload = fmod.to_dict(confirmed_finding())

    assert tuple(payload) == EXPECTED_FIELDS
    assert payload["SuggestedRemediation"] is None
    assert set(payload["Location"]) == set(fmod.LOCATION_FIELDS)
    assert set(payload["Evidence"][0]) == set(fmod.EVIDENCE_FIELDS)


@pytest.mark.parametrize(
    "builder", [confirmed_finding, agent_finding], ids=["confirmed", "agent"]
)
def test_round_trip_preserves_the_finding(builder: Any) -> None:
    original = builder()

    assert fmod.from_dict(fmod.to_dict(original)) == original


@pytest.mark.parametrize(
    "builder", [confirmed_finding, agent_finding], ids=["confirmed", "agent"]
)
def test_round_trip_preserves_the_dict(builder: Any) -> None:
    payload = fmod.to_dict(builder())

    assert fmod.to_dict(fmod.from_dict(payload)) == payload


def test_to_dict_output_is_json_serializable() -> None:
    payload = fmod.to_dict(confirmed_finding())

    assert json.loads(json.dumps(payload)) == payload


def test_to_dict_does_not_share_mutable_state_with_the_finding() -> None:
    original = confirmed_finding()
    payload = fmod.to_dict(original)

    payload["Source"].append("cfn-guard")
    payload["Location"]["TemplatePath"].append("injected")
    payload["Evidence"].append({"Source": "cfn-guard", "Detail": "x"})

    assert original.Source == ["cfn-lint"]
    assert original.Location.TemplatePath[-1] == 0
    assert len(original.Evidence) == 1


# ---------------------------------------------------------------------------
# Required fields and unknown fields
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("missing", EXPECTED_FIELDS)
def test_each_of_the_thirteen_fields_is_required(missing: str) -> None:
    payload = fmod.to_dict(confirmed_finding())
    del payload[missing]

    with pytest.raises(SchemaViolationError) as raised:
        fmod.from_dict(payload)

    assert raised.value.field == missing
    assert "required" in raised.value.reason


def test_unknown_top_level_field_is_rejected() -> None:
    payload = fmod.to_dict(confirmed_finding())
    payload["Priority"] = "high"

    with pytest.raises(SchemaViolationError) as raised:
        fmod.from_dict(payload)

    assert raised.value.field == "Priority"


@pytest.mark.parametrize(
    ("nested", "key", "expected_field"),
    [
        ("Location", "EndLine", "Location.EndLine"),
        ("Evidence", "Confidence", "Evidence[0].Confidence"),
    ],
    ids=["location", "evidence"],
)
def test_unknown_nested_field_is_rejected(nested: str, key: str, expected_field: str) -> None:
    payload = fmod.to_dict(confirmed_finding())
    target = payload[nested][0] if nested == "Evidence" else payload[nested]
    target[key] = 1

    with pytest.raises(SchemaViolationError) as raised:
        fmod.from_dict(payload)

    assert raised.value.field == expected_field


def test_location_file_is_required() -> None:
    payload = fmod.to_dict(confirmed_finding())
    del payload["Location"]["File"]

    with pytest.raises(SchemaViolationError) as raised:
        fmod.from_dict(payload)

    assert raised.value.field == "Location.File"


def test_non_object_input_is_rejected() -> None:
    with pytest.raises(SchemaViolationError) as raised:
        fmod.from_dict([])  # type: ignore[arg-type]

    assert raised.value.field == "Finding"


# ---------------------------------------------------------------------------
# Closed value sets
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("FindingType", "Vulnerability"),
        ("FindingType", "security"),
        ("Severity", "SEVERE"),
        ("Severity", "critical"),
        ("Confidence", "Certain"),
        ("Confidence", "confirmed"),
        ("FindingType", None),
        ("Severity", 4),
    ],
    ids=[
        "type-unknown",
        "type-wrong-case",
        "severity-unknown",
        "severity-wrong-case",
        "confidence-unknown",
        "confidence-wrong-case",
        "type-null",
        "severity-int",
    ],
)
def test_value_outside_the_closed_set_is_rejected(field: str, value: Any) -> None:
    payload = fmod.to_dict(confirmed_finding())
    payload[field] = value

    with pytest.raises(SchemaViolationError) as raised:
        fmod.from_dict(payload)

    assert raised.value.field == field


@pytest.mark.parametrize(
    ("source", "expected_field"),
    [
        (["cfn-lint", "cfn-guard", "IAM Review", "Agent Review"], None),
        ([], "Source"),
        (["cfn-lint", "cfn-lint"], "Source"),
        (["cfn-guard", "cfn-lint"], "Source"),
        (["IAM Review", "cfn-lint"], "Source"),
        (["cfn-lint", "Agent Review", "cfn-guard"], "Source"),
        ("cfn-lint", "Source"),
        (["CfnLint"], "Source[0]"),
    ],
    ids=[
        "sorted-union-ok",
        "empty",
        "duplicate",
        "unsorted-pair",
        "unsorted-alphabetical-trap",
        "unsorted-triple",
        "bare-string",
        "unknown-value",
    ],
)
def test_source_must_be_non_empty_unique_and_canonically_sorted(
    source: Any, expected_field: Optional[str]
) -> None:
    payload = fmod.to_dict(confirmed_finding(Confidence="Likely"))
    payload["Evidence"][0]["Excerpt"] = "Action: '*'"
    payload["Source"] = source

    if expected_field is None:
        assert fmod.from_dict(payload).Source == source
        return

    with pytest.raises(SchemaViolationError) as raised:
        fmod.from_dict(payload)

    assert raised.value.field == expected_field


@pytest.mark.parametrize(
    ("value", "reason_fragment"),
    [(0, "must be >="), (-1, "must be >="), (True, "integer"), ("1", "integer"), (1.0, "integer")],
    ids=["zero", "negative", "bool", "string", "float"],
)
def test_id_must_be_an_integer_of_at_least_one(value: Any, reason_fragment: str) -> None:
    payload = fmod.to_dict(confirmed_finding())
    payload["ID"] = value

    with pytest.raises(SchemaViolationError) as raised:
        fmod.from_dict(payload)

    assert raised.value.field == "ID"
    assert reason_fragment in raised.value.reason


def test_unassigned_id_does_not_validate() -> None:
    """dedup builds merged Findings with ID 0; report assigns the real ID."""
    with pytest.raises(SchemaViolationError) as raised:
        fmod.validate(confirmed_finding(ID=fmod.UNASSIGNED_ID))

    assert raised.value.field == "ID"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("Finding", ""),
        ("WhyItMatters", ""),
        ("Recommendation", ""),
        ("SuggestedRemediation", ""),
        ("Resource", ""),
        ("Finding", None),
        ("WhyItMatters", 7),
    ],
    ids=[
        "finding-empty",
        "why-empty",
        "recommendation-empty",
        "remediation-empty",
        "resource-empty",
        "finding-null",
        "why-int",
    ],
)
def test_text_fields_reject_empty_and_non_string_values(field: str, value: Any) -> None:
    payload = fmod.to_dict(confirmed_finding())
    payload[field] = value

    with pytest.raises(SchemaViolationError) as raised:
        fmod.from_dict(payload)

    assert raised.value.field == field


@pytest.mark.parametrize(
    ("field", "value"), [("Resource", None), ("SuggestedRemediation", None)], ids=["resource", "remediation"]
)
def test_nullable_fields_accept_null(field: str, value: Any) -> None:
    payload = fmod.to_dict(confirmed_finding())
    payload[field] = value

    assert getattr(fmod.from_dict(payload), field) is None


def test_evidence_must_not_be_empty() -> None:
    payload = fmod.to_dict(confirmed_finding())
    payload["Evidence"] = []

    with pytest.raises(SchemaViolationError) as raised:
        fmod.from_dict(payload)

    assert raised.value.field == "Evidence"


@pytest.mark.parametrize(
    ("key", "value", "expected_field"),
    [
        ("Source", "cfn-linter", "Evidence[0].Source"),
        ("Detail", "", "Evidence[0].Detail"),
        ("RuleId", "", "Evidence[0].RuleId"),
        ("Excerpt", "", "Evidence[0].Excerpt"),
    ],
    ids=["source", "detail", "ruleid", "excerpt"],
)
def test_evidence_entry_values_are_validated(key: str, value: Any, expected_field: str) -> None:
    payload = fmod.to_dict(confirmed_finding())
    payload["Evidence"][0][key] = value

    with pytest.raises(SchemaViolationError) as raised:
        fmod.from_dict(payload)

    assert raised.value.field == expected_field


@pytest.mark.parametrize(
    ("key", "value", "expected_field"),
    [
        ("File", "/Users/dev/templates/app.yaml", "Location.File"),
        ("File", "\\\\server\\share\\app.yaml", "Location.File"),
        ("File", "C:\\work\\app.yaml", "Location.File"),
        ("Line", 0, "Location.Line"),
        ("Column", 0, "Location.Column"),
        ("Line", "42", "Location.Line"),
        ("TemplatePath", "Resources.MyBucket", "Location.TemplatePath"),
        ("TemplatePath", [None], "Location.TemplatePath[0]"),
    ],
    ids=[
        "absolute-posix",
        "absolute-unc",
        "absolute-windows-drive",
        "line-zero",
        "column-zero",
        "line-string",
        "templatepath-string",
        "templatepath-null-item",
    ],
)
def test_location_values_are_validated(key: str, value: Any, expected_field: str) -> None:
    payload = fmod.to_dict(confirmed_finding())
    payload["Location"][key] = value

    with pytest.raises(SchemaViolationError) as raised:
        fmod.from_dict(payload)

    assert raised.value.field == expected_field


def test_location_line_and_column_may_be_null() -> None:
    payload = fmod.to_dict(confirmed_finding())
    payload["Location"]["Line"] = None
    payload["Location"]["Column"] = None

    result = fmod.from_dict(payload)

    assert (result.Location.Line, result.Location.Column) == (None, None)


# ---------------------------------------------------------------------------
# The four structural constraints
# ---------------------------------------------------------------------------


def test_confirmed_cannot_come_from_agent_review() -> None:
    """Constraint 1 (Requirement 7 AC10)."""
    with pytest.raises(SchemaViolationError) as raised:
        fmod.validate(agent_finding(Confidence="Confirmed"))

    assert raised.value.field == "Confidence"
    assert "Agent Review" in raised.value.reason


@pytest.mark.parametrize("confidence", ["Likely", "Contextual"])
def test_non_confirmed_finding_requires_an_excerpt(confidence: str) -> None:
    """Constraint 2 (Requirement 7 AC11)."""
    without_excerpt = agent_finding(
        Confidence=confidence,
        Evidence=[Evidence(Source="Agent Review", Detail="reasoning", Excerpt=None)],
    )

    with pytest.raises(SchemaViolationError) as raised:
        fmod.validate(without_excerpt)

    assert raised.value.field == "Evidence"
    assert "Excerpt" in raised.value.reason


def test_confirmed_finding_needs_no_excerpt() -> None:
    fmod.validate(confirmed_finding())


def test_validity_critical_without_a_rule_id_is_rejected() -> None:
    """Constraint 3 (Requirement 7 AC6): nothing could justify the CRITICAL."""
    with pytest.raises(SchemaViolationError) as raised:
        fmod.validate(validity_critical_finding(rule_id=None))

    assert raised.value.field == "Severity"


def test_validity_critical_is_rejected_when_the_rule_does_not_block_deployment() -> None:
    fmod.set_blocks_deployment_resolver(lambda rule_id: False)

    with pytest.raises(SchemaViolationError) as raised:
        fmod.validate(validity_critical_finding(rule_id="E3002"))

    assert raised.value.field == "Severity"
    assert "E3002" in raised.value.reason


def test_validity_critical_is_accepted_for_a_deployment_blocking_rule() -> None:
    fmod.set_blocks_deployment_resolver(lambda rule_id: rule_id == "E0000")

    fmod.validate(validity_critical_finding(rule_id="E0000"))


def test_validity_critical_stands_when_no_resolver_is_installed() -> None:
    """Without the mapping file hook the claim is left alone, not guessed at."""
    fmod.validate(validity_critical_finding(rule_id="E0000"))


def test_non_validity_critical_is_unrestricted() -> None:
    fmod.set_blocks_deployment_resolver(lambda rule_id: False)

    fmod.validate(confirmed_finding(Severity="CRITICAL"))


def test_other_category_cannot_carry_a_merged_source_list() -> None:
    """Constraint 4 (Requirement 14 AC3): ``Other`` is excluded from dedup."""
    merged = confirmed_finding(
        Normalized_Category="Other",
        Source=["cfn-lint", "cfn-guard"],
        Evidence=[
            Evidence(Source="cfn-lint", Detail="Rule W1234", RuleId="W1234"),
            Evidence(Source="cfn-guard", Detail="rule failed", RuleId="some_rule"),
        ],
    )

    with pytest.raises(SchemaViolationError) as raised:
        fmod.validate(merged)

    assert raised.value.field == "Normalized_Category"


def test_other_category_with_a_single_source_is_valid() -> None:
    fmod.validate(confirmed_finding(Normalized_Category="Other"))


@pytest.mark.parametrize(
    ("category", "resource", "eligible"),
    [
        ("IAM", "AppExecutionRole", True),
        ("Other", "AppExecutionRole", False),
        ("IAM", None, False),
        ("Other", None, False),
    ],
    ids=["closed-set-with-resource", "other", "template-level", "other-template-level"],
)
def test_is_dedup_eligible(category: str, resource: Optional[str], eligible: bool) -> None:
    f = confirmed_finding(Normalized_Category=category, Resource=resource)

    assert fmod.is_dedup_eligible(f) is eligible


# ---------------------------------------------------------------------------
# Category hook
# ---------------------------------------------------------------------------


def test_category_hook_rejects_a_value_outside_the_closed_set() -> None:
    fmod.set_category_validator(lambda name: name in {"IAM", "Other"})

    with pytest.raises(SchemaViolationError) as raised:
        fmod.validate(confirmed_finding(Normalized_Category="Encryptionn"))

    assert raised.value.field == "Normalized_Category"


def test_category_hook_accepts_a_value_inside_the_closed_set() -> None:
    fmod.set_category_validator(lambda name: name in {"IAM", "Other"})

    fmod.validate(confirmed_finding(Normalized_Category="IAM"))


def test_clearing_the_category_hook_stops_the_closed_set_check() -> None:
    fmod.set_category_validator(lambda name: False)
    fmod.set_category_validator(None)

    fmod.validate(confirmed_finding(Normalized_Category="IAM"))


def test_category_must_still_be_a_non_empty_string_without_a_hook() -> None:
    with pytest.raises(SchemaViolationError) as raised:
        fmod.validate(confirmed_finding(Normalized_Category=""))

    assert raised.value.field == "Normalized_Category"


# ---------------------------------------------------------------------------
# Shared orderings
# ---------------------------------------------------------------------------


def test_orderings_cover_exactly_their_closed_sets() -> None:
    assert set(fmod.SEVERITY_ORDER) == set(fmod.SEVERITIES)
    assert set(fmod.CONFIDENCE_ORDER) == set(fmod.CONFIDENCES)
    assert set(fmod.FINDING_TYPE_ORDER) == set(fmod.FINDING_TYPES)
    assert set(fmod.SOURCE_ORDER) == set(fmod.SOURCES)


def test_orderings_hold_the_documented_ranks() -> None:
    assert fmod.SEVERITY_ORDER == {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    assert fmod.CONFIDENCE_ORDER == {"Confirmed": 2, "Likely": 1, "Contextual": 0}
    assert fmod.FINDING_TYPE_ORDER == {
        "Security": 3,
        "Validity": 2,
        "BestPractice": 1,
        "Informational": 0,
    }
    assert fmod.SOURCE_ORDER == {"cfn-lint": 0, "cfn-guard": 1, "IAM Review": 2, "Network Review": 3, "Agent Review": 4}


def test_design_pseudocode_names_alias_the_same_objects() -> None:
    assert fmod._SEV_ORDER is fmod.SEVERITY_ORDER
    assert fmod._CONF_ORDER is fmod.CONFIDENCE_ORDER
    assert fmod._TYPE_ORDER is fmod.FINDING_TYPE_ORDER
    assert fmod._SOURCE_ORDER is fmod.SOURCE_ORDER


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        (["Agent Review", "cfn-lint"], ["cfn-lint", "Agent Review"]),
        (["IAM Review", "cfn-guard", "cfn-lint"], ["cfn-lint", "cfn-guard", "IAM Review"]),
        (["cfn-lint", "cfn-lint"], ["cfn-lint"]),
    ],
    ids=["two", "three", "duplicates-collapsed"],
)
def test_sorted_sources_returns_the_canonical_order(
    given: List[str], expected: List[str]
) -> None:
    assert fmod.sorted_sources(given) == expected


def test_sorted_sources_rejects_an_unknown_source() -> None:
    with pytest.raises(SchemaViolationError) as raised:
        fmod.sorted_sources(["cfn-lint", "trivy"])

    assert raised.value.field == "Source"


def test_source_lists_produced_by_sorted_sources_validate() -> None:
    """The helper and the validator agree on what "sorted" means."""
    f = confirmed_finding(
        Source=fmod.sorted_sources(["Agent Review", "IAM Review", "cfn-lint"]),
        Confidence="Likely",
        Evidence=[Evidence(Source="cfn-lint", Detail="Rule W3037", RuleId="W3037", Excerpt="x")],
    )

    fmod.validate(f)


# ---------------------------------------------------------------------------
# canonical_template_path
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "given, expected",
    [
        (
            ["Resources", "AppBucket", "Properties", "Tags", "0", "Key"],
            ["Resources", "AppBucket", "Properties", "Tags", 0, "Key"],
        ),
        # Already typed by the Source: unchanged, so the function is idempotent.
        (
            ["Resources", "AppBucket", "Properties", "Tags", 0, "Key"],
            ["Resources", "AppBucket", "Properties", "Tags", 0, "Key"],
        ),
        # Index 1 is a section member name. A digit-only logical ID is legal
        # CloudFormation and must stay a mapping key.
        (["Resources", "123", "Properties"], ["Resources", "123", "Properties"]),
        # Only whole digit runs are indices.
        (["Resources", "A", "Tags", "0a", "-1"], ["Resources", "A", "Tags", "0a", "-1"]),
        ([], []),
    ],
    ids=["string-index", "already-int", "numeric-logical-id", "not-an-index", "empty"],
)
def test_canonical_template_path(given: List[Any], expected: List[Any]) -> None:
    """Requirement 14 AC5 needs one spelling per position (design [Correction] C-9)."""
    assert fmod.canonical_template_path(given) == expected


def test_canonical_template_path_returns_a_new_list() -> None:
    """The caller may keep or mutate the result without touching the input."""
    given = ["Resources", "AppBucket", "Tags", "0"]
    canonical = fmod.canonical_template_path(given)
    canonical.append("Key")

    assert given == ["Resources", "AppBucket", "Tags", "0"]


def test_a_canonicalized_path_validates_inside_a_location() -> None:
    """``TemplatePath`` accepts both member types, so the output is legal."""
    f = confirmed_finding(
        Location=Location(
            File="templates/app.yaml",
            TemplatePath=fmod.canonical_template_path(
                ["Resources", "AppExecutionRole", "Properties", "Policies", "0"]
            ),
        )
    )

    fmod.validate(f)
    assert f.Location.TemplatePath[-1] == 0


# ---------------------------------------------------------------------------
# Failure reporting
# ---------------------------------------------------------------------------


def test_violation_carries_field_reason_and_the_structured_error_shape() -> None:
    error = fmod.schema_violation("Severity", "'SEVERE' is not permitted")

    assert isinstance(error, SchemaViolationError)
    assert (error.field, error.reason) == ("Severity", "'SEVERE' is not permitted")
    assert error.message == "Severity: 'SEVERE' is not permitted"
    structured = error.to_structured_error(source="Agent Review")
    assert structured["error_class"] == "schema_violation"
    assert "field" not in structured


def test_from_dict_does_not_mutate_its_input() -> None:
    payload = fmod.to_dict(confirmed_finding())
    before = copy.deepcopy(payload)

    fmod.from_dict(payload)

    assert payload == before
