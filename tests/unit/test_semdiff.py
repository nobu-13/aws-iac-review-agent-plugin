"""Unit tests for the structural comparison of :mod:`iacreview.semdiff` (v1.1 Task 6).

The Task 2 Template fixtures carry hand-written expected values (written before
the implementation, Requirements R15.3); every case is run through the same
pipeline the CLI uses -- parse the Base, then the Head, then compare -- and the
four state fields, the failure, the Change_Entries and the uncompared paths
are checked against them. The remaining tests pin the normalization table
(Design 2-4), the comparison units (Design 3-1), the Change_Entry limit, the
per-path comparison of alias-shared subtrees, CDK-generated content, and that
only structure-checked documents are accepted.
"""

from __future__ import annotations

import dataclasses
import json
import sys
import traceback
from pathlib import Path
from typing import Any, Dict, List, Union

import pytest

from iacreview import deltaio, deltaschema, semdiff
from iacreview.deltaio import Failure, ParsedTemplate
from iacreview.semdiff import ChangeEntry, ResourceTypes, SemanticDiffResult

REPO_ROOT = Path(__file__).resolve().parents[2]
DELTA_TEMPLATES = REPO_ROOT / "tests" / "fixtures" / "delta" / "templates"
PATH = Path("semdiff.yaml")
CASES = sorted(path.name for path in DELTA_TEMPLATES.iterdir() if path.is_dir())


def _parse(text: str, side: str) -> Union[ParsedTemplate, Failure]:
    return deltaio.parse_template(text, PATH, side)


def _ok(text: str, side: str) -> ParsedTemplate:
    parsed = _parse(text, side)
    assert isinstance(parsed, ParsedTemplate), parsed
    return parsed


def _diff(base: str, head: str) -> SemanticDiffResult:
    result = semdiff.diff(_ok(base, "base"), _ok(head, "head"))
    assert isinstance(result, SemanticDiffResult), result
    return result


def _expected(name: str) -> Dict[str, Any]:
    return json.loads((DELTA_TEMPLATES / name / "expected.json").read_text(encoding="utf-8"))


def _side_text(name: str, case: Dict[str, Any], side: str) -> str:
    inputs = case["inputs"]
    if side == "head" and "head_ref" in inputs:
        return (REPO_ROOT / inputs["head_ref"]).read_text(encoding="utf-8")
    return (DELTA_TEMPLATES / name / inputs[side]).read_text(encoding="utf-8")


def _run_case(name: str, monkeypatch: pytest.MonkeyPatch) -> Dict[str, Any]:
    """The CLI's order: Base Template, Head Template, then the comparison."""
    case = _expected(name)
    for constant, value in case["limits"].items():
        monkeypatch.setattr(deltaschema, constant, value)
    base = _parse(_side_text(name, case, "base"), "base")
    head = _parse(_side_text(name, case, "head"), "head")
    failure = base if isinstance(base, Failure) else head if isinstance(head, Failure) else None
    if failure is not None:
        return _unanalyzable(failure)
    assert isinstance(base, ParsedTemplate) and isinstance(head, ParsedTemplate)
    result = semdiff.diff(base, head)
    if isinstance(result, Failure):
        return _unanalyzable(result)
    return {
        "analysis_state": result.analysis_state,
        "observation": result.observation,
        "structural_completeness": result.structural_completeness,
        "semantic_limitations": sorted(result.semantic_limitations),
        "failure": None,
        "changes": sorted(_change_json(change) for change in result.changes),
        "uncompared_paths": sorted(
            json.dumps({"path": list(item.path), "reason": item.reason}, sort_keys=True)
            for item in result.uncompared_paths
        ),
    }


def _unanalyzable(failure: Failure) -> Dict[str, Any]:
    return {
        "analysis_state": "unanalyzable",
        "observation": None,
        "structural_completeness": None,
        "semantic_limitations": [],
        "failure": {"side": failure.side, "input": failure.input, "code": failure.code},
        "changes": [],
        "uncompared_paths": [],
    }


def _change_json(change: ChangeEntry) -> str:
    resource_type = change.resource_type
    return json.dumps(
        {
            "section": change.section,
            "path": list(change.path),
            "change": change.change,
            "type_changed": change.type_changed,
            "resource_type": None
            if resource_type is None
            else {"base": resource_type.base, "head": resource_type.head},
            "qualifiers": sorted(change.qualifiers),
            "hints": sorted(change.hints),
        },
        sort_keys=True,
    )


def _normalized_expected(expected: Dict[str, Any]) -> Dict[str, Any]:
    changes = [
        json.dumps(
            dict(change, qualifiers=sorted(change["qualifiers"]), hints=sorted(change["hints"])),
            sort_keys=True,
        )
        for change in expected["changes"]
    ]
    return {
        "analysis_state": expected["analysis_state"],
        "observation": expected["observation"],
        "structural_completeness": expected["structural_completeness"],
        "semantic_limitations": sorted(expected["semantic_limitations"]),
        "failure": expected["failure"],
        "changes": sorted(changes),
        "uncompared_paths": sorted(json.dumps(item, sort_keys=True) for item in expected["uncompared_paths"]),
    }


# ---------------------------------------------------------------------------
# Task 2 fixtures (R15.4)
# ---------------------------------------------------------------------------


def test_every_template_case_is_run() -> None:
    assert len(CASES) == 45


@pytest.mark.parametrize("name", CASES)
def test_template_fixture_matches_expected(name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """R3, R4.10-R4.14, R5.1, R5.3, R5.4, R5.6: the hand-written expected values."""
    assert _run_case(name, monkeypatch) == _normalized_expected(_expected(name)["expected"])


@pytest.mark.parametrize("name", CASES)
def test_state_fields_are_consistent(name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """R5.3, R5.4, R5.6: observation and completeness follow from the content."""
    got = _run_case(name, monkeypatch)
    if got["analysis_state"] == "unanalyzable":
        assert got["observation"] is None and got["structural_completeness"] is None
        assert got["changes"] == [] and got["uncompared_paths"] == []
        return
    assert got["observation"] == ("changes_observed" if got["changes"] else "no_changes_observed")
    assert got["structural_completeness"] == ("partial" if got["uncompared_paths"] else "complete")


# ---------------------------------------------------------------------------
# Comparison units (Design 3-1)
# ---------------------------------------------------------------------------

_BUCKET = "Resources:\n  B:\n    Type: AWS::S3::Bucket\n"


def test_identical_documents_have_no_change() -> None:
    result = _diff(_BUCKET, _BUCKET)
    assert result.changes == ()
    assert (result.analysis_state, result.observation, result.structural_completeness) == (
        "analyzed",
        "no_changes_observed",
        "complete",
    )


def test_type_change_reports_one_entry_and_pairs_nothing_below() -> None:
    """R3.2"""
    base = _BUCKET + "    Properties: {A: 1, B: 2}\n"
    head = "Resources:\n  B:\n    Type: AWS::SQS::Queue\n    Properties: {A: 9, C: 3}\n"
    (change,) = _diff(base, head).changes
    assert change.path == ("Resources", "B") and change.change == "modified" and change.type_changed
    assert change.resource_type == ResourceTypes("AWS::S3::Bucket", "AWS::SQS::Queue")


def test_type_added_on_one_side_is_a_type_change() -> None:
    base = "Resources:\n  B:\n    Properties: {A: 1}\n"
    (change,) = _diff(base, _BUCKET + "    Properties: {A: 1}\n").changes
    assert change.type_changed and change.resource_type == ResourceTypes(None, "AWS::S3::Bucket")


def test_unknown_key_under_a_resource_is_opaque() -> None:
    """Design 3-1: reported at the key, not below it."""
    base = _BUCKET + "    Extra: {a: {b: 1}}\n"
    head = _BUCKET + "    Extra: {a: {b: 2}}\n"
    (change,) = _diff(base, head).changes
    assert change.path == ("Resources", "B", "Extra") and change.change == "modified"


def test_properties_and_attributes_are_compared_path_by_path() -> None:
    """R3.3"""
    base = _BUCKET + "    Properties: {A: {x: 1}}\n    UpdatePolicy: {P: {q: 1}}\n    CreationPolicy: {C: 1}\n"
    head = _BUCKET + "    Properties: {A: {x: 2}}\n    UpdatePolicy: {P: {q: 2}}\n    CreationPolicy: {C: 2}\n"
    paths = {change.path for change in _diff(base, head).changes}
    assert paths == {
        ("Resources", "B", "Properties", "A", "x"),
        ("Resources", "B", "UpdatePolicy", "P", "q"),
        ("Resources", "B", "CreationPolicy", "C"),
    }


def test_section_level_value_is_reported_at_the_section() -> None:
    """R3.5: Transform and Metadata at section level, even when nested."""
    base = "Transform: [A]\nMetadata: {x: {y: 1}}\n" + _BUCKET
    head = "Transform: [B]\nMetadata: {x: {y: 2}}\n" + _BUCKET
    paths = sorted(change.path for change in _diff(base, head).changes)
    assert paths == [("Metadata",), ("Transform",)]


def test_unknown_top_level_key_is_opaque() -> None:
    """R3.6"""
    (change,) = _diff("Custom: {a: [1]}\n" + _BUCKET, "Custom: {a: [2]}\n" + _BUCKET).changes
    assert change.path == ("Custom",) and change.section == "Custom"


def test_missing_entry_section_is_added_at_section_level() -> None:
    head = "Parameters:\n  P: {Type: String}\n" + _BUCKET
    (change,) = _diff(_BUCKET, head).changes
    assert (change.path, change.change, change.resource_type) == (("Parameters",), "added", None)


def test_entry_sections_are_compared_by_entry() -> None:
    """R3.4: added / removed entries and paths inside a modified entry."""
    base = "Rules:\n  R1: {Assertions: [{Assert: x}]}\n  R2: {}\n" + _BUCKET
    head = "Rules:\n  R1: {Assertions: [{Assert: y}]}\n  R3: {}\n" + _BUCKET
    got = {(change.path, change.change) for change in _diff(base, head).changes}
    assert got == {
        (("Rules", "R1", "Assertions", 0, "Assert"), "modified"),
        (("Rules", "R2"), "removed"),
        (("Rules", "R3"), "added"),
    }


def test_change_entry_exposes_section_and_entry() -> None:
    """R16.4: addressable by section, entry name and path."""
    (change,) = _diff(_BUCKET + "    Properties: {A: 1}\n", _BUCKET + "    Properties: {A: 2}\n").changes
    assert (change.section, change.entry) == ("Resources", "B")
    (top,) = _diff("Description: a\n" + _BUCKET, "Description: b\n" + _BUCKET).changes
    assert top.entry is None


def test_list_is_compared_by_position() -> None:
    """R3.12: a longer list adds at the new index, a reorder is modified."""
    base = _BUCKET + "    Properties: {L: [a, b]}\n"
    head = _BUCKET + "    Properties: {L: [b, a, c]}\n"
    got = sorted((change.path[-1], change.change) for change in _diff(base, head).changes)
    assert got == [(0, "modified"), (1, "modified"), (2, "added")]


def test_mapping_against_scalar_is_modified_at_that_position() -> None:
    base = _BUCKET + "    Properties: {A: {x: 1}}\n"
    head = _BUCKET + "    Properties: {A: text}\n"
    (change,) = _diff(base, head).changes
    assert change.path == ("Resources", "B", "Properties", "A") and change.change == "modified"


def test_resource_that_is_not_a_mapping_is_compared_as_a_value() -> None:
    base = "Resources:\n  B: one\n  C: {Type: AWS::S3::Bucket}\n"
    head = "Resources:\n  B: two\n  C: {Type: AWS::S3::Bucket}\n"
    (change,) = _diff(base, head).changes
    assert change.path == ("Resources", "B") and not change.type_changed
    assert change.resource_type == ResourceTypes(None, None)


def test_path_is_canonical() -> None:
    """R3.7: a digit-only key below the entry becomes an int, the entry name does not."""
    base = "Resources:\n  '1':\n    Type: AWS::S3::Bucket\n    Properties: {'7': a}\n"
    head = "Resources:\n  '1':\n    Type: AWS::S3::Bucket\n    Properties: {'7': b}\n"
    (change,) = _diff(base, head).changes
    assert change.path == ("Resources", "1", "Properties", 7)


# ---------------------------------------------------------------------------
# Normalization (Design 2-4)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "left,right",
    [
        ("80", "'80'"),
        ("true", "'true'"),
        ("true", "1"),
        ("1", "1.0"),
        ("0", "false"),
        ("null", "''"),
        ("1.5", "'1.5'"),
    ],
)
def test_scalar_types_are_not_coerced(left: str, right: str) -> None:
    """R3.11, N-6"""
    base = _BUCKET + "    Properties: {{P: {0}}}\n".format(left)
    head = _BUCKET + "    Properties: {{P: {0}}}\n".format(right)
    (change,) = _diff(base, head).changes
    assert change.change == "modified"


@pytest.mark.parametrize("value", ["1.5", ".nan", ".inf", "-.inf", "0x10", "yes", "~"])
def test_equal_scalars_are_equal(value: str) -> None:
    """N-6: NaN equals NaN; resolved YAML 1.1 forms compare as their value."""
    doc = _BUCKET + "    Properties: {{P: {0}}}\n".format(value)
    assert _diff(doc, doc).changes == ()


def test_hex_int_equals_decimal_int() -> None:
    """N-1: compared after parsing."""
    base = _BUCKET + "    Properties: {P: 0x10}\n"
    head = _BUCKET + "    Properties: {P: 16}\n"
    assert _diff(base, head).changes == ()


def test_unquoted_date_equals_its_string() -> None:
    """N-3"""
    base = "AWSTemplateFormatVersion: 2010-09-09\n" + _BUCKET
    head = 'AWSTemplateFormatVersion: "2010-09-09"\n' + _BUCKET
    result = _diff(base, head)
    assert result.changes == () and result.structural_completeness == "complete"


def test_different_dates_are_modified() -> None:
    base = _BUCKET + "    Metadata: {D: 2020-01-01}\n"
    head = _BUCKET + "    Metadata: {D: 2020-01-02}\n"
    (change,) = _diff(base, head).changes
    assert change.path == ("Resources", "B", "Metadata", "D")


def test_timestamp_is_not_compared_even_if_equal() -> None:
    """N-4: an identical timestamp still cannot be shown unchanged."""
    doc = _BUCKET + "    Metadata: {T: 2020-01-01T00:00:00Z}\n"
    result = _diff(doc, doc)
    assert result.changes == ()
    assert [(u.path, u.reason) for u in result.uncompared_paths] == [
        (("Resources", "B", "Metadata", "T"), "yaml_timestamp")
    ]
    assert result.structural_completeness == "partial"


def test_timestamp_against_string_is_not_reported_as_unchanged() -> None:
    base = _BUCKET + "    Metadata: {T: 2020-01-01T00:00:00Z}\n"
    head = _BUCKET + "    Metadata: {T: '2020-01-01T00:00:00Z'}\n"
    result = _diff(base, head)
    assert result.changes == () and result.structural_completeness == "partial"


def test_non_string_key_mapping_is_not_compared_and_siblings_are() -> None:
    """N-5"""
    base = _BUCKET + "    Metadata: {M: {1: a}, S: x}\n"
    head = _BUCKET + "    Metadata: {M: {1: b}, S: y}\n"
    result = _diff(base, head)
    assert [change.path for change in result.changes] == [("Resources", "B", "Metadata", "S")]
    assert [(u.path, u.reason) for u in result.uncompared_paths] == [
        (("Resources", "B", "Metadata", "M"), "non_string_key")
    ]


def test_non_string_top_level_key_records_the_root() -> None:
    base = "1: x\n" + _BUCKET
    head = "1: y\nDescription: d\n" + _BUCKET
    result = _diff(base, head)
    assert [change.path for change in result.changes] == [("Description",)]
    assert [(u.path, u.reason) for u in result.uncompared_paths] == [((), "non_string_key")]


def test_notation_only_differences_are_not_changes() -> None:
    """R3.8, R3.9"""
    base = "# c\nResources:\n  B:\n    Type: 'AWS::S3::Bucket'\n    Properties:\n      N: !Sub '${AWS::Region}'\n      R: !Ref P\n"
    head = '{"Resources": {"B": {"Properties": {"R": {"Ref": "P"}, "N": {"Fn::Sub": "${AWS::Region}"}}, "Type": "AWS::S3::Bucket"}}}'
    assert _diff(base, head).changes == ()


def test_pairs_tuples_are_compared_by_position() -> None:
    """``!!pairs`` builds (key, value) tuples; they are compared like lists."""
    base = _BUCKET + "    Metadata: {P: !!pairs [a: 1, b: 2]}\n"
    head = _BUCKET + "    Metadata: {P: !!pairs [a: 1, b: 3]}\n"
    (change,) = _diff(base, head).changes
    assert change.path == ("Resources", "B", "Metadata", "P", 1, 1)


def test_pairs_against_list_is_modified() -> None:
    base = _BUCKET + "    Metadata: {P: !!pairs [a: 1]}\n"
    head = _BUCKET + "    Metadata: {P: [[a, 1]]}\n"
    (change,) = _diff(base, head).changes
    assert change.path == ("Resources", "B", "Metadata", "P", 0)


def test_binary_and_set_scalars() -> None:
    doc = _BUCKET + "    Metadata: {B: !!binary aGVsbG8=, S: !!set {a, b}}\n"
    assert _diff(doc, doc).changes == ()
    other = _BUCKET + "    Metadata: {B: !!binary aGVsbG9v, S: !!set {a, c}}\n"
    assert len(_diff(doc, other).changes) == 2


# ---------------------------------------------------------------------------
# Duplicate keys (R2.5, Design 5)
# ---------------------------------------------------------------------------


def test_duplicate_mapping_is_left_out_and_the_rest_compared() -> None:
    base = _BUCKET + "    Properties: {A: 1, A: 2}\n  Q:\n    Type: AWS::SQS::Queue\n    Properties: {N: a}\n"
    head = _BUCKET + "    Properties: {A: 1, A: 3}\n  Q:\n    Type: AWS::SQS::Queue\n    Properties: {N: b}\n"
    result = _diff(base, head)
    assert [change.path for change in result.changes] == [("Resources", "Q", "Properties", "N")]
    assert [(u.path, u.reason) for u in result.uncompared_paths] == [
        (("Resources", "B", "Properties"), "duplicate_key")
    ]
    assert (result.observation, result.structural_completeness) == ("changes_observed", "partial")


def test_duplicate_on_one_side_only_is_not_compared() -> None:
    base = _BUCKET + "    Properties: {A: 1}\n"
    head = _BUCKET + "    Properties: {A: 1, A: 1}\n"
    result = _diff(base, head)
    assert result.changes == () and result.structural_completeness == "partial"


# ---------------------------------------------------------------------------
# Alias sharing: every path is compared (Design 3-2)
# ---------------------------------------------------------------------------


def test_alias_shared_subtree_is_compared_at_every_path() -> None:
    template = (
        "Metadata:\n  Shared: &s {{Key: env, Value: {v}}}\n"
        "Resources:\n"
        "  A:\n    Type: AWS::S3::Bucket\n    Properties: {{Tags: [*s]}}\n"
        "  B:\n    Type: AWS::S3::Bucket\n    Properties: {{Tags: [*s]}}\n"
    )
    result = _diff(template.format(v="dev"), template.format(v="prod"))
    paths = sorted(change.path for change in result.changes if change.section == "Resources")
    assert paths == [
        ("Resources", "A", "Properties", "Tags", 0, "Value"),
        ("Resources", "B", "Properties", "Tags", 0, "Value"),
    ]
    assert [change.path for change in result.changes if change.section == "Metadata"] == [("Metadata",)]


def test_alias_on_one_side_and_copy_on_the_other_is_equal() -> None:
    base = "Metadata: {X: &x [1, 2]}\nResources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties: {L: *x}\n"
    head = "Metadata: {X: [1, 2]}\nResources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties: {L: [1, 2]}\n"
    assert _diff(base, head).changes == ()


# ---------------------------------------------------------------------------
# Limits (R14.6)
# ---------------------------------------------------------------------------


def _many(count: int, value: str) -> str:
    props = ", ".join("P{0}: {1}".format(index, value) for index in range(count))
    return _BUCKET + "    Properties: {" + props + "}\n"


def test_change_entries_at_the_limit_are_returned(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(deltaschema, "MAX_CHANGE_ENTRIES", 3)
    assert len(_diff(_many(3, "a"), _many(3, "b")).changes) == 3


def test_change_entries_above_the_limit_fail_without_partial_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R14.6, D-H15: no partial list, a Code naming the limit."""
    monkeypatch.setattr(deltaschema, "MAX_CHANGE_ENTRIES", 3)
    result = semdiff.diff(_ok(_many(4, "a"), "base"), _ok(_many(4, "b"), "head"))
    assert isinstance(result, Failure)
    assert (result.code, result.side, result.input) == ("change_entry_limit_exceeded", None, "template")
    assert (result.error_class, result.exit_code) == ("input_too_large", 3)


def test_opaque_differences_count_once(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(deltaschema, "MAX_CHANGE_ENTRIES", 1)
    base = "Metadata: {" + ", ".join("k{0}: a".format(i) for i in range(10)) + "}\n" + _BUCKET
    head = "Metadata: {" + ", ".join("k{0}: b".format(i) for i in range(10)) + "}\n" + _BUCKET
    assert len(_diff(base, head).changes) == 1


def test_shipped_change_entry_limit_is_the_approved_value() -> None:
    assert deltaschema.MAX_CHANGE_ENTRIES == 200000


def _checked(doc: Any) -> ParsedTemplate:
    """A ParsedTemplate for a document built in Python, after the structure check."""
    shape = deltaio.check_structure(doc)
    assert isinstance(shape, deltaio.Shape), shape
    return ParsedTemplate(doc=doc, fmt="json", marked=deltaio.MarkedObjects(), duplicate_sections=(), shape=shape)


def test_deep_document_is_compared_without_recursion(monkeypatch: pytest.MonkeyPatch) -> None:
    """R14.5: a chain far deeper than the current stack allows recursion for."""
    monkeypatch.setattr(deltaschema, "MAX_TEMPLATE_DEPTH", 10 ** 6)
    depth = 3000
    nested_a: Any = "a"
    nested_b: Any = "b"
    for _ in range(depth):
        nested_a, nested_b = {"n": nested_a}, {"n": nested_b}
    base = _checked({"Resources": {"B": {"Type": "AWS::S3::Bucket", "Properties": nested_a}}})
    head = _checked({"Resources": {"B": {"Type": "AWS::S3::Bucket", "Properties": nested_b}}})
    limit = sys.getrecursionlimit()
    sys.setrecursionlimit(len(traceback.extract_stack()) + 40)
    try:
        result = semdiff.diff(base, head)
    finally:
        sys.setrecursionlimit(limit)
    assert isinstance(result, SemanticDiffResult)
    (change,) = result.changes
    assert len(change.path) == 3 + depth and change.change == "modified"


# ---------------------------------------------------------------------------
# CDK-generated content is compared, not dropped (R4.14)
# ---------------------------------------------------------------------------


def test_cdk_generated_elements_are_compared() -> None:
    template = (
        "Parameters:\n  BootstrapVersion: {{Type: 'AWS::SSM::Parameter::Value<String>', Default: {v}}}\n"
        "Resources:\n"
        "  Bucket83908E77:\n    Type: AWS::S3::Bucket\n    Metadata: {{aws:cdk:path: {p}}}\n"
        "  CDKMetadata:\n    Type: AWS::CDK::Metadata\n    Properties: {{Analytics: {a}}}\n"
        "Rules:\n  CheckBootstrapVersion: {{Assertions: [{{AssertDescription: {d}}}]}}\n"
    )
    base = template.format(v="/cdk/v1", p="Stack/Bucket/Resource", a="v2:deflate64:A", d="one")
    head = template.format(v="/cdk/v2", p="Stack/Bucket2/Resource", a="v2:deflate64:B", d="two")
    paths = {change.path for change in _diff(base, head).changes}
    assert paths == {
        ("Parameters", "BootstrapVersion", "Default"),
        ("Resources", "Bucket83908E77", "Metadata", "aws:cdk:path"),
        ("Resources", "CDKMetadata", "Properties", "Analytics"),
        ("Rules", "CheckBootstrapVersion", "Assertions", 0, "AssertDescription"),
    }


# ---------------------------------------------------------------------------
# Hints (R4.13)
# ---------------------------------------------------------------------------


def test_rename_hint_only_for_matching_types() -> None:
    base = "Resources:\n  Old: {Type: AWS::S3::Bucket}\n  Gone: {Type: AWS::SNS::Topic}\n"
    head = "Resources:\n  New: {Type: AWS::S3::Bucket}\n  Fresh: {Type: AWS::SQS::Queue}\n"
    result = _diff(base, head)
    hints = {change.path[1]: change.hints for change in result.changes}
    assert hints == {
        "Old": ("possible_logical_id_rename",),
        "New": ("possible_logical_id_rename",),
        "Gone": (),
        "Fresh": (),
    }
    assert result.rename_hints == frozenset({"Old", "New"})


def test_no_hint_without_both_added_and_removed() -> None:
    result = _diff(_BUCKET, "Resources:\n  B: {Type: AWS::S3::Bucket}\n  C: {Type: AWS::S3::Bucket}\n")
    (change,) = result.changes
    assert change.hints == () and result.rename_hints == frozenset()
    assert result.uncompared_rename_candidates == ()


_OLD_BUCKET = "Resources:\n  Old: {Type: AWS::S3::Bucket, Properties: {BucketName: a}}\n"
_NEW_DUPLICATED = (
    "Resources:\n  New:\n    Type: AWS::S3::Bucket\n"
    "    Properties: {BucketName: a}\n    Properties: {BucketName: b}\n"
)


def test_rename_hint_reaches_an_uncompared_one_sided_resource() -> None:
    """Regression: a one-sided Resource with a duplicate key is still a rename end.

    The Head Resource is not compared (its Type may be hidden by the
    duplicate), so it pairs with the removed Resource of any Type.
    """
    result = _diff(_OLD_BUCKET, _NEW_DUPLICATED)
    (change,) = result.changes
    assert change.path == ("Resources", "Old") and change.change == "removed"
    assert change.hints == ("possible_logical_id_rename",)
    assert [(u.path, u.reason) for u in result.uncompared_paths] == [
        (("Resources", "New"), "duplicate_key")
    ]
    assert result.uncompared_rename_candidates == ("New",)
    assert result.rename_hints == frozenset({"Old", "New"})


def test_rename_hint_reaches_an_uncompared_base_resource() -> None:
    base = (
        "Resources:\n  Old:\n    Type: AWS::S3::Bucket\n"
        "    Properties: {BucketName: a}\n    Properties: {BucketName: b}\n"
    )
    head = "Resources:\n  New: {Type: AWS::SQS::Queue}\n"
    result = _diff(base, head)
    (change,) = result.changes
    assert change.path == ("Resources", "New") and change.hints == ("possible_logical_id_rename",)
    assert result.rename_hints == frozenset({"Old", "New"})


def test_uncompared_resource_with_reliable_type_pairs_by_type() -> None:
    """A non-string key leaves the Resource mapping itself unmarked: its Type is used."""
    head_queue = "Resources:\n  New:\n    Type: AWS::SQS::Queue\n    1: x\n"
    result = _diff(_OLD_BUCKET, head_queue)
    (change,) = result.changes
    assert change.hints == () and result.rename_hints == frozenset()
    head_bucket = "Resources:\n  New:\n    Type: AWS::S3::Bucket\n    1: x\n"
    result = _diff(_OLD_BUCKET, head_bucket)
    (change,) = result.changes
    assert change.hints == ("possible_logical_id_rename",)
    assert result.rename_hints == frozenset({"Old", "New"})


def test_uncompared_resource_without_counterpart_is_not_a_candidate() -> None:
    base = "Resources:\n  Keep: {Type: AWS::S3::Bucket}\n"
    head = base + _NEW_DUPLICATED[len("Resources:\n"):]
    result = _diff(base, head)
    assert result.changes == ()
    assert result.uncompared_rename_candidates == () and result.rename_hints == frozenset()


def test_uncompared_resources_section_makes_one_sided_ids_candidates() -> None:
    """Regression: a duplicate ``Resources`` section leaves every one-sided ID open."""
    base = "Resources:\n  Old: {Type: AWS::S3::Bucket}\n  Keep: {Type: AWS::SNS::Topic}\n"
    head = (
        "Resources:\n  Ignored: {Type: AWS::S3::Bucket}\n"
        "Resources:\n  New: {Type: AWS::SQS::Queue}\n  Keep: {Type: AWS::SNS::Topic}\n"
    )
    result = _diff(base, head)
    assert result.changes == ()
    assert [(u.path, u.reason) for u in result.uncompared_paths] == [(("Resources",), "duplicate_key")]
    assert result.uncompared_rename_candidates == ("New", "Old")
    assert result.rename_hints == frozenset({"Old", "New"})


def test_duplicate_logical_id_makes_one_sided_ids_candidates() -> None:
    """A duplicate key in the ``Resources`` mapping leaves the section uncompared."""
    base = "Resources:\n  Old: {Type: AWS::S3::Bucket}\n"
    head = "Resources:\n  New: {Type: AWS::S3::Bucket}\n  New: {Type: AWS::SQS::Queue}\n"
    result = _diff(base, head)
    assert result.changes == ()
    assert result.rename_hints == frozenset({"Old", "New"})


# ---------------------------------------------------------------------------
# Interface (R16.1, R16.3)
# ---------------------------------------------------------------------------


def test_only_structure_checked_documents_are_accepted() -> None:
    parsed = _ok(_BUCKET, "base")
    document = deltaio.parse_document(_BUCKET, PATH, "base")
    for bad in ({"Resources": {"B": {}}}, document, None):
        with pytest.raises(TypeError):
            semdiff.diff(bad, parsed)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            semdiff.diff(parsed, bad)  # type: ignore[arg-type]


def test_result_is_frozen() -> None:
    result = _diff(_BUCKET + "    Properties: {A: 1}\n", _BUCKET + "    Properties: {A: 2}\n")
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.changes = ()  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.changes[0].path = ()  # type: ignore[misc]


def _scalars(value: Any) -> List[Any]:
    found: List[Any] = []
    stack = [value]
    while stack:
        current = stack.pop()
        if dataclasses.is_dataclass(current):
            stack.extend(getattr(current, f.name) for f in dataclasses.fields(current))
        elif isinstance(current, (tuple, list)):
            stack.extend(current)
        else:
            found.append(current)
    return found


def test_result_holds_no_template_value() -> None:
    """R16.3: identifiers and codes only; scalar values never leave the module."""
    base = _BUCKET + "    Properties: {Label: CanaryValueBase1, L: [CanaryItemBase2]}\n    Extra: CanaryOpaqueBase3\n"
    head = _BUCKET + "    Properties: {Label: CanaryValueHead1, L: [CanaryItemHead2, x]}\n    Extra: CanaryOpaqueHead3\n"
    result = _diff(base, head)
    assert len(result.changes) == 4
    text = repr(result)
    for canary in ("CanaryValue", "CanaryItem", "CanaryOpaque"):
        assert canary not in text
    allowed = {"Resources", "B", "Properties", "Label", "L", "Extra", "AWS::S3::Bucket"}
    for scalar in _scalars(result):
        assert scalar is None or isinstance(scalar, (bool, int)) or scalar in allowed or scalar in (
            deltaschema.CHANGE_KINDS + deltaschema.CHANGE_QUALIFIERS + deltaschema.CHANGE_HINTS
        )


def test_same_input_gives_equal_results() -> None:
    base = _BUCKET + "    Properties: {A: 1, B: [1, 2], C: {d: 1}}\n"
    head = _BUCKET + "    Properties: {C: {d: 2}, B: [2], A: 1}\n"
    first, second = _diff(base, head), _diff(base, head)
    assert first == second
    assert [change.path for change in first.changes] == [
        ("Resources", "B", "Properties", "B", 0),
        ("Resources", "B", "Properties", "B", 1),
        ("Resources", "B", "Properties", "C", "d"),
    ]


def test_swapping_sides_swaps_added_and_removed() -> None:
    base = _BUCKET + "    Properties: {A: 1}\n"
    head = _BUCKET + "    Properties: {B: 1}\n"
    forward = {(c.path, c.change) for c in _diff(base, head).changes}
    backward = {(c.path, c.change) for c in _diff(head, base).changes}
    swap = {"added": "removed", "removed": "added", "modified": "modified"}
    assert backward == {(path, swap[kind]) for path, kind in forward}


# ---------------------------------------------------------------------------
# A-3b: digit characters that ``int()`` refuses (R10.4, R3.7)
# ---------------------------------------------------------------------------

SUPERSCRIPT_TWO = "\u00b2"  # ``isdigit()`` is true, ``int()`` raises ValueError
ARABIC_INDIC_123 = "\u0661\u0662\u0663"  # ``isdecimal()``: ``int()`` gives 123


def test_canonical_path_keeps_non_decimal_digit_keys_as_strings() -> None:
    path = ["Resources", "1", "Properties", SUPERSCRIPT_TWO, "0", ARABIC_INDIC_123, "1" + SUPERSCRIPT_TWO]
    assert semdiff.canonical_path(path) == (
        "Resources",
        "1",
        "Properties",
        SUPERSCRIPT_TWO,
        0,
        123,
        "1" + SUPERSCRIPT_TWO,
    )


def test_canonical_path_agrees_with_v1_0_rule_on_ordinary_paths() -> None:
    from iacreview.finding import canonical_template_path

    for path in (
        ["Resources", "123", "Properties", "Tags", "0", "Key"],
        ["Mappings", "M", "123456789012", "K"],
        ["Outputs", "O", "Value", 3],
        [],
    ):
        assert semdiff.canonical_path(path) == tuple(canonical_template_path(path))


def test_non_decimal_digit_key_change_is_compared() -> None:
    base = _BUCKET + '    Metadata:\n      "{0}": a\n      "{1}": b\n'.format(SUPERSCRIPT_TWO, ARABIC_INDIC_123)
    head = _BUCKET + '    Metadata:\n      "{0}": z\n      "{1}": b\n'.format(SUPERSCRIPT_TWO, ARABIC_INDIC_123)
    result = _diff(base, head)
    assert result.analysis_state == "analyzed"
    assert [(c.path, c.change) for c in result.changes] == [
        (("Resources", "B", "Metadata", SUPERSCRIPT_TWO), "modified")
    ]


def test_decimal_unicode_key_still_canonicalizes_to_an_integer() -> None:
    base = _BUCKET + '    Metadata:\n      "{0}": a\n      "{1}": b\n'.format(SUPERSCRIPT_TWO, ARABIC_INDIC_123)
    head = _BUCKET + '    Metadata:\n      "{0}": a\n      "{1}": c\n'.format(SUPERSCRIPT_TWO, ARABIC_INDIC_123)
    result = _diff(base, head)
    assert result.analysis_state == "analyzed"
    assert [c.path for c in result.changes] == [("Resources", "B", "Metadata", 123)]
