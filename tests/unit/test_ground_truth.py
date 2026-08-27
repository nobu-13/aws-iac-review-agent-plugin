"""Checks for the benchmark Ground_Truth schema and the benchmark README.

``benchmark/ground_truth.schema.json`` is the contract every benchmark case is
written against (Requirement 11 AC3, AC12), and the harness reads those cases to
compute detection rate, precision, recall and severity accuracy. Two kinds of
breakage matter here and neither is visible from the schema alone:

**The schema can drift away from the Finding schema.** Ground truth states an
expected ``Normalized_Category``, ``FindingType``, ``Severity`` and
``Confidence``, and those vocabularies belong to ``iacreview`` -- to
``iacreview/finding.py`` and to the ``categories`` array of
``iacreview/category_map.json``. If a value is added there and not here, cases
can never express it; if one is removed there and left here, cases can express a
value the report will never emit, and the affected expectation silently becomes
unmatchable. The vocabulary tests below compare the schema against the modules
rather than against literals, so a change in ``iacreview`` fails this file
instead of quietly desynchronizing the benchmark.

**The reserved fields can lose their guarantee.** ``expected_findings_agent_only``
and ``expected_findings_human_review`` exist so that adding a benchmark mode does
not change the format of existing cases (Requirement 11 AC12). That only holds
while both stay ``required`` and neither is capped at zero items, so both
properties are asserted directly.

No JSON Schema validation library is used. The plugin's runtime dependency is
PyYAML alone, and a validator is not needed to run the benchmark, so
:func:`validation_errors` implements the subset of draft 2020-12 this schema
uses, on the standard library. It is exported rather than made private because
Tasks 21.2-21.4 validate each case's ``ground_truth.json`` with it, and a second
implementation would be a second definition of what the schema means.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Sequence

import pytest

from iacreview import categories as categories_module
from iacreview import template
from iacreview.finding import (
    AGENT_SOURCE,
    CONFIDENCES,
    CONFIRMED,
    FINDING_TYPES,
    SEVERITIES,
    SOURCES,
)

# tests/unit/test_ground_truth.py -> tests/unit -> tests -> plugin root
PLUGIN_ROOT: Path = Path(__file__).resolve().parents[2]
BENCHMARK: Path = PLUGIN_ROOT / "benchmark"
SCHEMA_PATH: Path = BENCHMARK / "ground_truth.schema.json"
README_PATH: Path = BENCHMARK / "README.md"

#: The draft this schema is written against. Stated in the schema, and repeated
#: here so that switching drafts is a deliberate, reviewed change: the checker
#: below implements this draft's semantics for the keywords in use.
DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"

#: Top-level fields, in the order design.md's Ground_Truth example declares them.
#: The last two are the reserved arrays of Requirement 11 AC12.
EXPECTED_CASE_FIELDS = [
    "schema_version",
    "case_id",
    "template",
    "description",
    "authored_before_review",
    "expected_finding_count",
    "expected_findings",
    "expected_findings_agent_only",
    "expected_findings_human_review",
]

RESERVED_CASE_FIELDS = [
    "expected_findings_agent_only",
    "expected_findings_human_review",
]

#: Fields every entry of ``expected_findings`` must carry.
EXPECTED_FINDING_REQUIRED_FIELDS = [
    "resource",
    "normalized_category",
    "finding_type",
    "severity",
    "detection_class",
    "detected_by",
    "note",
]

#: The one optional entry field. ``confidence`` follows from ``detection_class``
#: unless a case pins it, so requiring it would force every case to restate a
#: derivable value.
OPTIONAL_FINDING_FIELDS = ["confidence"]

DETECTION_CLASSES = ["deterministic", "agent-dependent"]

#: A case that exercises every required field, taken from design.md's
#: Ground_Truth example. Used as the positive instance for the checker: the
#: schema has to accept the document the design specifies.
VALID_CASE: Dict[str, Any] = {
    "schema_version": "1.0.0",
    "case_id": "case-001-iam-wildcard",
    "template": "template.yaml",
    "description": (
        'An IAM role with a policy granting Action "*" on Resource "*", plus an '
        "unrestricted iam:PassRole statement."
    ),
    "authored_before_review": True,
    "expected_finding_count": 2,
    "expected_findings": [
        {
            "resource": "AdminRole",
            "normalized_category": "IAM",
            "finding_type": "Security",
            "severity": "CRITICAL",
            "detection_class": "deterministic",
            "detected_by": ["IAM Review", "cfn-guard"],
            "note": 'Action "*" with Resource "*" in the inline policy.',
        },
        {
            "resource": "DeployRole",
            "normalized_category": "IAM",
            "finding_type": "Security",
            "severity": "CRITICAL",
            "detection_class": "deterministic",
            "detected_by": ["IAM Review"],
            "note": "iam:PassRole with Resource \"*\".",
        },
    ],
    "expected_findings_agent_only": [],
    "expected_findings_human_review": [],
}


# ---------------------------------------------------------------------------
# Schema access
# ---------------------------------------------------------------------------


def load_schema() -> Dict[str, Any]:
    """Return the parsed Ground_Truth schema."""
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def schema() -> Dict[str, Any]:
    return load_schema()


# ---------------------------------------------------------------------------
# A validator for the subset of draft 2020-12 this schema uses
# ---------------------------------------------------------------------------

_JSON_TYPE_CHECKS = {
    "object": lambda value: isinstance(value, dict),
    "array": lambda value: isinstance(value, list),
    "string": lambda value: isinstance(value, str),
    # ``bool`` is a subclass of ``int`` in Python but is not a JSON number, so it
    # is excluded explicitly. Without this, ``true`` would satisfy ``integer``.
    "integer": lambda value: isinstance(value, int) and not isinstance(value, bool),
    "number": lambda value: isinstance(value, (int, float)) and not isinstance(value, bool),
    "boolean": lambda value: isinstance(value, bool),
    "null": lambda value: value is None,
}

_REF_PREFIX = "#/$defs/"


def _resolve(schema: Dict[str, Any], root: Dict[str, Any]) -> Dict[str, Any]:
    """Follow a local ``$ref``, keeping any sibling keywords of the referrer."""
    ref = schema.get("$ref")
    if not isinstance(ref, str):
        return schema
    if not ref.startswith(_REF_PREFIX):
        raise AssertionError("only local $defs references are supported: {0}".format(ref))
    name = ref[len(_REF_PREFIX) :]
    target = root.get("$defs", {}).get(name)
    if not isinstance(target, dict):
        raise AssertionError("$ref points at a missing definition: {0}".format(ref))
    merged = dict(target)
    for key, value in schema.items():
        if key != "$ref":
            merged[key] = value
    return merged


def _check(
    value: object, schema: Dict[str, Any], root: Dict[str, Any], path: str, errors: List[str]
) -> None:
    schema = _resolve(schema, root)

    def fail(reason: str) -> None:
        errors.append("{0}: {1}".format(path or "$", reason))

    if "const" in schema and value != schema["const"]:
        fail("expected the constant {0!r}, got {1!r}".format(schema["const"], value))

    if "enum" in schema and value not in schema["enum"]:
        fail("{0!r} is not one of {1}".format(value, schema["enum"]))

    declared = schema.get("type")
    if declared is not None:
        permitted = [declared] if isinstance(declared, str) else list(declared)
        if not any(_JSON_TYPE_CHECKS[name](value) for name in permitted):
            fail("expected type {0}, got {1}".format(permitted, type(value).__name__))
            return

    if isinstance(value, str):
        pattern = schema.get("pattern")
        if isinstance(pattern, str) and re.search(pattern, value) is None:
            fail("{0!r} does not match {1}".format(value, pattern))
        minimum_length = schema.get("minLength")
        if isinstance(minimum_length, int) and len(value) < minimum_length:
            fail("shorter than minLength {0}".format(minimum_length))

    if isinstance(value, int) and not isinstance(value, bool):
        minimum = schema.get("minimum")
        if isinstance(minimum, int) and value < minimum:
            fail("{0} is below minimum {1}".format(value, minimum))

    if isinstance(value, list):
        minimum_items = schema.get("minItems")
        if isinstance(minimum_items, int) and len(value) < minimum_items:
            fail("has {0} items, minItems is {1}".format(len(value), minimum_items))
        maximum_items = schema.get("maxItems")
        if isinstance(maximum_items, int) and len(value) > maximum_items:
            fail("has {0} items, maxItems is {1}".format(len(value), maximum_items))
        if schema.get("uniqueItems") is True and len(value) != len({repr(v) for v in value}):
            fail("items are not unique")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                _check(item, item_schema, root, "{0}[{1}]".format(path, index), errors)

    if isinstance(value, dict):
        properties = schema.get("properties", {})
        for name in schema.get("required", []):
            if name not in value:
                fail("missing required property {0!r}".format(name))
        if schema.get("additionalProperties") is False:
            for name in value:
                if name not in properties:
                    fail("property {0!r} is not permitted".format(name))
        for name, sub_schema in properties.items():
            if name in value:
                _check(
                    value[name],
                    sub_schema,
                    root,
                    "{0}.{1}".format(path, name) if path else name,
                    errors,
                )


def validation_errors(instance: object, schema: Dict[str, Any]) -> List[str]:
    """Return the ways ``instance`` violates ``schema``; empty means valid.

    Implements the keywords ``ground_truth.schema.json`` uses: ``type``,
    ``enum``, ``const``, ``required``, ``properties``,
    ``additionalProperties: false``, ``items``, ``minItems``, ``maxItems``,
    ``uniqueItems``, ``minimum``, ``minLength``, ``pattern``, and local ``$ref``
    into ``$defs``. Any other keyword is ignored rather than approximated, so a
    keyword added to the schema without support here would weaken validation --
    which is why :func:`test_schema_uses_only_supported_keywords` fails on one.
    """
    errors: List[str] = []
    _check(instance, schema, schema, "", errors)
    return errors


#: Keywords the checker above implements, plus the annotations it may ignore
#: safely because they constrain nothing.
SUPPORTED_KEYWORDS = frozenset(
    (
        "$schema",
        "$defs",
        "$ref",
        "title",
        "description",
        "type",
        "enum",
        "const",
        "required",
        "properties",
        "additionalProperties",
        "items",
        "minItems",
        "maxItems",
        "uniqueItems",
        "minimum",
        "minLength",
        "pattern",
    )
)


def _walk_subschemas(node: object) -> List[Dict[str, Any]]:
    """Every schema object in the document, including the root."""
    found: List[Dict[str, Any]] = []
    if isinstance(node, dict):
        found.append(node)
        for key, value in node.items():
            if key in ("properties", "$defs") and isinstance(value, dict):
                for sub in value.values():
                    found.extend(_walk_subschemas(sub))
            elif key == "items":
                found.extend(_walk_subschemas(value))
    return found


# ---------------------------------------------------------------------------
# The schema file itself
# ---------------------------------------------------------------------------


def test_schema_file_exists() -> None:
    assert SCHEMA_PATH.is_file()


def test_schema_parses_as_json() -> None:
    # Reported separately from the structural checks so that a syntax error is
    # distinguishable from a content change.
    assert isinstance(load_schema(), dict)


def test_schema_declares_draft_2020_12(schema: Dict[str, Any]) -> None:
    assert schema["$schema"] == DRAFT_2020_12


def test_schema_describes_a_closed_object(schema: Dict[str, Any]) -> None:
    # Closed on purpose: a misspelled field name in a case has to be an error,
    # not an ignored extra key that leaves an expectation silently unstated.
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False


def test_schema_requires_every_case_field(schema: Dict[str, Any]) -> None:
    assert schema["required"] == EXPECTED_CASE_FIELDS


def test_schema_declares_exactly_the_required_case_fields(schema: Dict[str, Any]) -> None:
    # No optional top-level field exists: every case states all nine, so two
    # cases are always comparable.
    assert list(schema["properties"]) == EXPECTED_CASE_FIELDS


def test_reserved_fields_are_required(schema: Dict[str, Any]) -> None:
    # Requirement 11 AC12: present in every case, so a future mode does not
    # change the format of existing ones.
    for name in RESERVED_CASE_FIELDS:
        assert name in schema["required"]


@pytest.mark.parametrize("name", RESERVED_CASE_FIELDS)
def test_reserved_fields_are_arrays_of_expected_findings(
    schema: Dict[str, Any], name: str
) -> None:
    field = schema["properties"][name]
    assert field["type"] == "array"
    assert field["items"]["$ref"] == "#/$defs/expectedFinding"


@pytest.mark.parametrize("name", RESERVED_CASE_FIELDS)
def test_reserved_fields_are_not_capped_at_zero_items(
    schema: Dict[str, Any], name: str
) -> None:
    # design.md is explicit that no maxItems constraint is imposed: v0.1 leaves
    # them empty by convention, and a future mode has to be able to fill them
    # without a schema change.
    assert "maxItems" not in schema["properties"][name]


def test_authored_before_review_permits_only_true(schema: Dict[str, Any]) -> None:
    # The declaration that ground truth was written before any review was run.
    # ``false`` is not a state a committed case may record: expectations derived
    # from review output measure nothing.
    assert schema["properties"]["authored_before_review"]["const"] is True


def test_expected_finding_count_is_a_non_negative_integer(schema: Dict[str, Any]) -> None:
    field = schema["properties"]["expected_finding_count"]
    assert field["type"] == "integer"
    assert field["minimum"] == 0


def test_expected_finding_entry_is_closed_and_fully_required(schema: Dict[str, Any]) -> None:
    entry = schema["$defs"]["expectedFinding"]
    assert entry["type"] == "object"
    assert entry["additionalProperties"] is False
    assert entry["required"] == EXPECTED_FINDING_REQUIRED_FIELDS


def test_expected_finding_entry_declares_confidence_as_optional(
    schema: Dict[str, Any],
) -> None:
    entry = schema["$defs"]["expectedFinding"]
    for name in OPTIONAL_FINDING_FIELDS:
        assert name in entry["properties"]
        assert name not in entry["required"]


def test_expected_finding_entry_declares_no_unknown_fields(schema: Dict[str, Any]) -> None:
    entry = schema["$defs"]["expectedFinding"]
    assert set(entry["properties"]) == set(
        EXPECTED_FINDING_REQUIRED_FIELDS + OPTIONAL_FINDING_FIELDS
    )


def test_resource_admits_null_for_template_level_findings(schema: Dict[str, Any]) -> None:
    # A template-level finding has no logical ID; the harness compares it as the
    # empty string. Ground truth has to be able to state that case.
    resource = schema["$defs"]["expectedFinding"]["properties"]["resource"]
    assert resource["type"] == ["string", "null"]


def test_detection_class_vocabulary(schema: Dict[str, Any]) -> None:
    # Requirement 11 AC4, and the input to the pass/fail rule: only
    # ``deterministic`` expectations are held to a threshold.
    entry = schema["$defs"]["expectedFinding"]
    assert entry["properties"]["detection_class"]["enum"] == DETECTION_CLASSES


def test_detected_by_is_a_non_empty_unique_source_list(schema: Dict[str, Any]) -> None:
    field = schema["$defs"]["expectedFinding"]["properties"]["detected_by"]
    assert field["type"] == "array"
    assert field["minItems"] == 1
    assert field["uniqueItems"] is True
    assert field["items"]["$ref"] == "#/$defs/source"


def test_every_ref_resolves(schema: Dict[str, Any]) -> None:
    names = set(schema["$defs"])
    for sub in _walk_subschemas(schema):
        ref = sub.get("$ref")
        if ref is None:
            continue
        assert ref.startswith(_REF_PREFIX), ref
        assert ref[len(_REF_PREFIX) :] in names, ref


def test_schema_uses_only_supported_keywords(schema: Dict[str, Any]) -> None:
    # The checker in this module ignores keywords it does not implement, so an
    # unsupported keyword in the schema would be a constraint nothing enforces.
    for sub in _walk_subschemas(schema):
        unsupported = set(sub) - SUPPORTED_KEYWORDS
        assert not unsupported, "unsupported keywords: {0}".format(sorted(unsupported))


# ---------------------------------------------------------------------------
# Vocabularies stay identical to the ones iacreview defines
# ---------------------------------------------------------------------------


def _enum(schema: Dict[str, Any], definition: str) -> Sequence[str]:
    return schema["$defs"][definition]["enum"]


def test_normalized_category_enum_matches_the_closed_set(schema: Dict[str, Any]) -> None:
    # Read through the loader rather than from the JSON file so that the schema
    # is compared against the vocabulary the plugin actually validates against.
    assert tuple(_enum(schema, "normalizedCategory")) == categories_module.load_map().categories


def test_finding_type_enum_matches_iacreview(schema: Dict[str, Any]) -> None:
    assert tuple(_enum(schema, "findingType")) == FINDING_TYPES


def test_severity_enum_matches_iacreview(schema: Dict[str, Any]) -> None:
    assert tuple(_enum(schema, "severity")) == SEVERITIES


def test_confidence_enum_matches_iacreview(schema: Dict[str, Any]) -> None:
    assert tuple(_enum(schema, "confidence")) == CONFIDENCES


def test_source_enum_matches_iacreview(schema: Dict[str, Any]) -> None:
    assert tuple(_enum(schema, "source")) == SOURCES


# ---------------------------------------------------------------------------
# The schema accepts a well-formed case and rejects malformed ones
# ---------------------------------------------------------------------------


def test_design_example_case_validates(schema: Dict[str, Any]) -> None:
    assert validation_errors(VALID_CASE, schema) == []


def test_clean_case_with_no_expected_findings_validates(schema: Dict[str, Any]) -> None:
    # case-101 and case-102 are clean templates: zero expectations is legal, and
    # is what makes them usable as negative tests.
    case = json.loads(json.dumps(VALID_CASE))
    case["case_id"] = "case-101-clean-web-tier"
    case["expected_finding_count"] = 0
    case["expected_findings"] = []
    assert validation_errors(case, schema) == []


def test_template_level_expectation_validates(schema: Dict[str, Any]) -> None:
    case = json.loads(json.dumps(VALID_CASE))
    case["expected_findings"][0]["resource"] = None
    assert validation_errors(case, schema) == []


def test_pinned_confidence_validates(schema: Dict[str, Any]) -> None:
    case = json.loads(json.dumps(VALID_CASE))
    case["expected_findings"][0]["confidence"] = "Confirmed"
    case["expected_findings"][1]["confidence"] = "Contextual"
    assert validation_errors(case, schema) == []


def _mutate(**changes: Any) -> Dict[str, Any]:
    case = json.loads(json.dumps(VALID_CASE))
    case.update(changes)
    return case


def _mutate_finding(**changes: Any) -> Dict[str, Any]:
    case = json.loads(json.dumps(VALID_CASE))
    case["expected_findings"][0].update(changes)
    return case


def _without(key: str) -> Dict[str, Any]:
    case = json.loads(json.dumps(VALID_CASE))
    del case[key]
    return case


def _finding_without(key: str) -> Dict[str, Any]:
    case = json.loads(json.dumps(VALID_CASE))
    del case["expected_findings"][0][key]
    return case


@pytest.mark.parametrize(
    "instance,reason",
    [
        (_without("expected_findings_agent_only"), "reserved array omitted"),
        (_without("expected_findings_human_review"), "reserved array omitted"),
        (_without("authored_before_review"), "declaration omitted"),
        (_mutate(authored_before_review=False), "expectations derived from output"),
        (_mutate(schema_version="1.0"), "not a semver string"),
        (_mutate(case_id="001-iam-wildcard"), "case_id not prefixed with case-"),
        (_mutate(case_id="case-1-iam"), "case number not three digits"),
        (_mutate(template="../../etc/passwd"), "template escapes the case directory"),
        (_mutate(template="cases/template.yaml"), "template contains a path separator"),
        (_mutate(template="template.txt"), "template is not a CloudFormation file"),
        (_mutate(description=""), "empty description"),
        (_mutate(expected_finding_count=-1), "negative finding count"),
        (_mutate(expected_finding_count=True), "boolean where an integer is required"),
        (_mutate(expected_findings={}), "expected_findings is not an array"),
        (_mutate(unexpected_field=1), "unknown top-level field"),
        (_finding_without("resource"), "entry field omitted"),
        (_finding_without("detected_by"), "entry field omitted"),
        (_finding_without("note"), "entry field omitted"),
        (_mutate_finding(normalized_category="Networking"), "category outside the closed set"),
        (_mutate_finding(finding_type="Vulnerability"), "FindingType outside the closed set"),
        (_mutate_finding(severity="BLOCKER"), "Severity outside the closed set"),
        (_mutate_finding(confidence="Certain"), "Confidence outside the closed set"),
        (_mutate_finding(detection_class="agent"), "unknown detection class"),
        (_mutate_finding(detected_by=[]), "no expected Source"),
        (_mutate_finding(detected_by=["cfn-lint", "cfn-lint"]), "duplicate Source"),
        (_mutate_finding(detected_by=["cfn_lint"]), "Source outside the closed set"),
        (_mutate_finding(detected_by="cfn-lint"), "detected_by is not an array"),
        (_mutate_finding(note=""), "empty note"),
        (_mutate_finding(resource="My-Bucket"), "not a CloudFormation logical ID"),
        (_mutate_finding(unexpected_field=1), "unknown entry field"),
    ],
)
def test_malformed_case_is_rejected(
    schema: Dict[str, Any], instance: Dict[str, Any], reason: str
) -> None:
    assert validation_errors(instance, schema) != [], reason


# ---------------------------------------------------------------------------
# The README carries the rules that cannot live in the schema
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def readme() -> str:
    return README_PATH.read_text(encoding="utf-8")


def test_readme_exists() -> None:
    assert README_PATH.is_file()


def test_readme_is_english_ascii(readme: str) -> None:
    # Public documentation is English; ASCII-only is the mechanical proxy the
    # other documentation tests use.
    non_ascii = sorted({character for character in readme if ord(character) > 127})
    assert not non_ascii, "non-ASCII characters: {0}".format(non_ascii)


def test_readme_states_that_expected_values_are_defined_first(readme: str) -> None:
    # The rule that makes the benchmark meaningful: ground truth is authored from
    # the template's deliberate defects, not transcribed from a review run.
    assert "Expected values are defined first" in readme
    assert "never reverse-engineered" in readme
    assert "authored_before_review" in readme


def test_readme_states_the_finding_granularity_rule(readme: str) -> None:
    # Determines how one expected finding maps onto one reported finding: the
    # report merges on logical ID plus Normalized_Category, so ground truth is
    # counted at that granularity and not per underlying defect.
    assert "one finding per resource per" in readme
    assert "Normalized_Category" in readme
    assert "expected_finding_count" in readme


def test_readme_names_the_json_schema_draft(readme: str) -> None:
    assert "draft 2020-12" in readme


def test_readme_separates_benchmark_templates_from_examples(readme: str) -> None:
    # Defective templates must not be mistaken for the copyable samples in
    # examples/.
    assert "examples/" in readme
    assert "benchmark/cases/" in readme


def test_readme_documents_every_metric(readme: str) -> None:
    for metric in (
        "Detection Rate",
        "Precision",
        "Recall",
        "False Positive",
        "False Negative",
        "Severity Accuracy",
        "Review Time",
        "Remediation Accuracy",
        "Human Intervention Count",
    ):
        assert metric in readme, metric


# ---------------------------------------------------------------------------
# The cases themselves (Task 21.2 onwards)
# ---------------------------------------------------------------------------
#
# Everything below walks ``benchmark/cases/`` rather than naming cases one by
# one, so a case added by a later task is checked the moment it lands. Only the
# roster test names the expected set, and it is the one place a new case has to
# be declared.
#
# These checks are all about the *case files*: schema conformance, internal
# consistency, and the two rules that cannot be expressed in JSON Schema (no
# credential, no real account ID). Whether a review actually reports what a case
# expects is a different question, measured against the real tools in
# ``tests/integration/test_benchmark_cases.py``.

CASES_DIR: Path = BENCHMARK / "cases"

#: Case directories expected to exist, pinned so that a deleted or renamed case
#: is reported here instead of silently contributing no test cases. Tasks 21.3
#: and 21.4 extend this list; see ``.kiro/specs/.../tasks.md``.
EXPECTED_CASE_DIRECTORIES = [
    "case-001-iam-wildcard",
    "case-002-public-s3",
    "case-003-encryption-disabled",
    "case-004-logging-disabled",
    "case-005-permissive-sg",
    "case-006-missing-backup",
    "case-007-missing-tags",
    "case-008-unsafe-passrole",
    "case-009-public-database",
    "case-010-missing-deletion-protection",
    # Clean cases, numbered from 101. They expect nothing, which the checks
    # below allow for; Task 24.4 asserts the property they exist for.
    "case-101-clean-web-tier",
    "case-102-clean-data-tier",
]

#: The one account ID benchmark templates may contain, fixed by
#: ``benchmark/README.md``. It is AWS's own documentation placeholder, so it
#: names no real account.
PLACEHOLDER_ACCOUNT_ID = "123456789012"

#: Patterns that mark a credential written into a template. Matched
#: case-insensitively.
#:
#: Each is anchored on a word boundary, which is what lets ``MasterUserPassword``
#: be rejected while ``ManageMasterUserPassword`` -- the property that tells RDS
#: to create and rotate the password in Secrets Manager, storing nothing in the
#: template -- is accepted. The two differ by a prefix, and the case that needs a
#: database uses the safe one.
CREDENTIAL_PATTERNS = [
    r"\baws_secret_access_key\b",
    r"\baws_access_key_id\b",
    r"\bmasteruserpassword\s*:",
    r"\bsecretaccesskey\s*:",
    r"-----begin [a-z ]*private key-----",
    # An AWS access key ID: AKIA or ASIA followed by sixteen base32 characters.
    r"\b(?:akia|asia)[a-z2-7]{16}\b",
]


def case_directories() -> List[Path]:
    """Every case directory, sorted. Used to parametrize the checks below."""
    if not CASES_DIR.is_dir():
        return []
    return sorted(path for path in CASES_DIR.iterdir() if path.is_dir())


def case_ids() -> List[str]:
    """Directory names, which are also the pytest parameter IDs and the case IDs."""
    return [path.name for path in case_directories()]


def load_case(name: str) -> Dict[str, Any]:
    """Return the parsed ``ground_truth.json`` of one case."""
    text = (CASES_DIR / name / "ground_truth.json").read_text(encoding="utf-8")
    return json.loads(text)


def test_the_expected_cases_are_present() -> None:
    assert case_ids() == EXPECTED_CASE_DIRECTORIES


def test_no_defective_template_lives_under_examples() -> None:
    """The templates here carry deliberate defects and must not be copyable.

    ``examples/`` is what a reader is invited to copy, so a defective template
    that drifted into it would be a template someone deploys. The check is the
    cheap direction of that rule: no case template is also present under
    ``examples/``.
    """
    example_templates = {
        path.read_text(encoding="utf-8")
        for path in (PLUGIN_ROOT / "examples").rglob("*.yaml")
    }

    for name in case_ids():
        case = load_case(name)
        text = (CASES_DIR / name / case["template"]).read_text(encoding="utf-8")
        assert text not in example_templates, name


@pytest.mark.parametrize("name", case_ids())
def test_case_ground_truth_validates_against_the_schema(
    schema: Dict[str, Any], name: str
) -> None:
    assert validation_errors(load_case(name), schema) == []


@pytest.mark.parametrize("name", case_ids())
def test_case_id_equals_the_directory_name(name: str) -> None:
    # The harness reports per case ID and reads per directory. If the two can
    # disagree, a result can be attributed to the wrong case.
    assert load_case(name)["case_id"] == name


@pytest.mark.parametrize("name", case_ids())
def test_case_declares_that_it_was_authored_before_review(name: str) -> None:
    # Requirement 11 AC14, AC15. The schema already pins the value to ``true``;
    # this asserts the field is really carried by every case, which is the part
    # the harness and a reviewer rely on.
    assert load_case(name)["authored_before_review"] is True


@pytest.mark.parametrize("name", case_ids())
def test_case_reserved_arrays_are_present_and_empty(name: str) -> None:
    # Requirement 11 AC12: present so a future mode needs no format change, and
    # empty in v0.1 because no mode populates them yet.
    case = load_case(name)
    for field in RESERVED_CASE_FIELDS:
        assert case[field] == [], field


@pytest.mark.parametrize("name", case_ids())
def test_case_finding_count_matches_the_expectations_listed(name: str) -> None:
    # The count is stated redundantly on purpose: an expectation dropped by a
    # careless edit shows up here rather than as an improved detection rate.
    case = load_case(name)
    assert case["expected_finding_count"] == len(case["expected_findings"])


@pytest.mark.parametrize("name", case_ids())
def test_case_expectations_are_one_per_resource_and_category(name: str) -> None:
    """The granularity rule, checked mechanically.

    Deduplication merges on logical ID plus ``Normalized_Category``, so the
    report can never emit two findings for one such pair. Two expectations
    sharing a pair would therefore make a correct review look as though it had
    missed one.
    """
    pairs = [
        (entry["resource"], entry["normalized_category"])
        for entry in load_case(name)["expected_findings"]
        # ``Other`` and template-level findings are exempt from merging, so
        # several entries may legitimately share those pairs.
        if entry["resource"] is not None and entry["normalized_category"] != "Other"
    ]

    assert len(pairs) == len(set(pairs)), pairs


@pytest.mark.parametrize("name", case_ids())
def test_case_template_exists_and_loads_and_is_reviewable(name: str) -> None:
    # The completion condition of Task 21.2: a case whose template the plugin
    # cannot load measures nothing.
    case = load_case(name)
    path = CASES_DIR / name / case["template"]
    assert path.is_file()

    loaded = template.load_template(path)

    assert loaded.fmt == "yaml"
    assert template.is_reviewable(loaded.doc)
    assert loaded.doc["Resources"]


@pytest.mark.parametrize("name", case_ids())
def test_case_expectations_name_resources_the_template_declares(name: str) -> None:
    """An expectation on a resource that does not exist can never be matched.

    ``resource`` is the first element of the harness's match key, so a typo in a
    logical ID would present as a permanently missed detection and, for a
    deterministic expectation, as a permanent CI failure with a misleading cause.
    """
    case = load_case(name)
    loaded = template.load_template(CASES_DIR / name / case["template"])
    declared = set(loaded.doc["Resources"])

    for entry in case["expected_findings"]:
        if entry["resource"] is not None:
            assert entry["resource"] in declared, entry["resource"]


@pytest.mark.parametrize("name", case_ids())
def test_case_template_names_no_account_id_other_than_the_placeholder(
    name: str,
) -> None:
    """Security steering rule: no real account ID in a published template.

    A 12-digit literal is also what ``cross_account_principal`` looks for, so one
    that arrived by accident would change what the case measures.
    """
    text = (CASES_DIR / name / load_case(name)["template"]).read_text(encoding="utf-8")

    for token in re.findall(r"\d{12,}", text):
        assert token == PLACEHOLDER_ACCOUNT_ID, "{0}: {1}".format(name, token)


@pytest.mark.parametrize("name", case_ids())
def test_case_template_carries_no_credential(name: str) -> None:
    """Security steering rule: no credential in a template, benchmark included.

    Benchmark templates are published and are read by contributors looking for a
    pattern to copy. A defect case is allowed to be insecure by design; it is not
    allowed to demonstrate a hardcoded secret.
    """
    lowered = (
        (CASES_DIR / name / load_case(name)["template"])
        .read_text(encoding="utf-8")
        .lower()
    )

    for pattern in CREDENTIAL_PATTERNS:
        assert re.search(pattern, lowered) is None, "{0}: {1}".format(name, pattern)


@pytest.mark.parametrize("name", case_ids())
def test_defect_case_expects_at_least_one_finding(name: str) -> None:
    """A ``case-0NN`` directory is a defect case, so it has to expect something.

    Clean cases are numbered from 101 and are the ones allowed to expect nothing;
    a defect case with no expectation would pass every metric while measuring
    nothing at all.
    """
    number = int(name.split("-")[1])
    if number >= 100:
        pytest.skip("{0} is a clean case; emptiness is its point".format(name))

    assert load_case(name)["expected_findings"], name


@pytest.mark.parametrize("name", case_ids())
def test_deterministic_expectations_name_only_deterministic_sources(name: str) -> None:
    """``deterministic`` is a claim about reachability, held to 100% detection.

    An expectation classed ``deterministic`` but attributed to ``Agent Review``
    would put an agent's non-determinism behind a CI gate that fails the build.
    """
    for entry in load_case(name)["expected_findings"]:
        if entry["detection_class"] == "deterministic":
            assert AGENT_SOURCE not in entry["detected_by"], entry
            assert entry.get("confidence", CONFIRMED) == CONFIRMED, entry


# ---------------------------------------------------------------------------
# The defect cases cover design.md's ten categories (Task 21.3)
# ---------------------------------------------------------------------------
#
# design.md's *Benchmark case の網羅* table names ten defect categories and the
# case that covers each. The table is prose; the mechanical form of the same
# claim is the ``Normalized_Category`` each case declares an expectation in.
# Asserting it here means a case that is renamed, deleted, or quietly rewritten
# to be about something else stops covering its category loudly rather than
# silently.

#: design.md's table, as case ID -> the Normalized_Category that case exists to
#: cover. Two categories are covered twice on purpose: ``IAM`` by the wildcard
#: case and the PassRole case, ``PublicAccess`` by the bucket case and the
#: database case, ``Backup`` by the retention case and the deletion protection
#: case. Each pair measures a different rule, which is why the table lists them
#: as separate rows.
DESIGN_DEFECT_CASE_CATEGORIES = {
    "case-001-iam-wildcard": "IAM",
    "case-002-public-s3": "PublicAccess",
    "case-003-encryption-disabled": "Encryption",
    "case-004-logging-disabled": "Logging",
    "case-005-permissive-sg": "NetworkSecurity",
    "case-006-missing-backup": "Backup",
    "case-007-missing-tags": "Tagging",
    "case-008-unsafe-passrole": "IAM",
    "case-009-public-database": "PublicAccess",
    "case-010-missing-deletion-protection": "Backup",
}

#: The case design.md attributes to the IAM detectors alone, because no bundled
#: cfn-guard rule reaches an unsafe ``iam:PassRole``: ``iam_policy_no_star_star``
#: matches only ``Action "*"`` with ``Resource "*"``.
IAM_ONLY_CASE = "case-008-unsafe-passrole"

IAM_SOURCE = "IAM Review"


def test_all_ten_design_defect_cases_exist() -> None:
    assert sorted(DESIGN_DEFECT_CASE_CATEGORIES) == [
        name for name in EXPECTED_CASE_DIRECTORIES if int(name.split("-")[1]) < 100
    ]


@pytest.mark.parametrize("name", sorted(DESIGN_DEFECT_CASE_CATEGORIES))
def test_design_defect_case_expects_the_category_it_covers(name: str) -> None:
    expected_category = DESIGN_DEFECT_CASE_CATEGORIES[name]

    declared = {
        entry["normalized_category"] for entry in load_case(name)["expected_findings"]
    }

    assert expected_category in declared, "{0}: {1}".format(name, sorted(declared))


def test_every_design_category_is_covered_by_at_least_one_case() -> None:
    """The completion condition of Task 21.3, stated as one assertion.

    Read from the cases rather than from the table above, so that a case whose
    expectations move to another category fails this even if the table is left
    untouched.
    """
    covered = {
        entry["normalized_category"]
        for name in DESIGN_DEFECT_CASE_CATEGORIES
        for entry in load_case(name)["expected_findings"]
    }

    assert set(DESIGN_DEFECT_CASE_CATEGORIES.values()) <= covered


def test_the_passrole_case_is_attributed_to_the_iam_detectors_alone() -> None:
    """design.md's table gives ``case-008`` one expected Source: IAM Review.

    The case earns its place by measuring what no ``.guard`` rule reaches, so an
    expectation there that also named cfn-guard would mean the case had drifted
    into measuring the rule set again. Asserted on every expectation rather than
    on their union, because one cfn-guard attribution would be enough to lose the
    property.
    """
    for entry in load_case(IAM_ONLY_CASE)["expected_findings"]:
        assert entry["detected_by"] == [IAM_SOURCE], entry
