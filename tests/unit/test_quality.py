"""Tests for the deterministic template-quality Source (:mod:`iacreview.quality`).

This is the v0.6.0 sixth deterministic Source. It reasons about the structure of
a template -- Conditions, Parameters, the dependency graph -- to find logic
mistakes and dead configuration. What these tests lock:

* each detector fires on its positive case and stays silent on its negative;
* the condition-logic heuristic flags a name/value contradiction but not a
  neutral or correct condition;
* cycle detection finds a real cycle and passes an acyclic graph;
* every finding is Confidence: Confirmed with Source ["Quality Review"];
* the Source is deterministic and safe on a template with no quality issues.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Dict, List

import pytest

from iacreview import quality
from iacreview.finding import CONFIRMED, validate


def _doc(**sections: Any) -> Dict[str, Any]:
    return {k: v for k, v in sections.items()}


def _rules(findings: List[Any]) -> set:
    out = set()
    for f in findings:
        t = f.Finding
        if t.startswith("[") and "]" in t:
            out.add(t[1:t.index("]")])
    return out


# ---------------------------------------------------------------------------
# Condition name / logic mismatch
# ---------------------------------------------------------------------------


def test_condition_named_production_testing_staging_is_flagged() -> None:
    doc = _doc(Conditions={
        "IsProduction": {"Fn::Equals": [{"Ref": "Env"}, "staging"]},
    })
    findings = quality.review(doc, template_file="t.yaml")
    assert "condition_name_logic_mismatch" in _rules(findings)


def test_condition_named_production_testing_production_is_not_flagged() -> None:
    doc = _doc(Conditions={
        "IsProduction": {"Fn::Equals": [{"Ref": "Env"}, "production"]},
    })
    findings = quality.review(doc, template_file="t.yaml")
    assert "condition_name_logic_mismatch" not in _rules(findings)


def test_neutrally_named_condition_is_not_flagged() -> None:
    doc = _doc(Conditions={
        "EnableFeature": {"Fn::Equals": [{"Ref": "Env"}, "staging"]},
    })
    findings = quality.review(doc, template_file="t.yaml")
    assert "condition_name_logic_mismatch" not in _rules(findings)


def test_condition_with_intrinsic_operands_only_is_not_flagged() -> None:
    doc = _doc(Conditions={
        "IsProduction": {"Fn::Equals": [{"Ref": "A"}, {"Ref": "B"}]},
    })
    findings = quality.review(doc, template_file="t.yaml")
    assert "condition_name_logic_mismatch" not in _rules(findings)


# ---------------------------------------------------------------------------
# Unused parameter
# ---------------------------------------------------------------------------


def test_unreferenced_parameter_is_flagged() -> None:
    doc = _doc(Parameters={"Unused": {"Type": "String"}}, Resources={})
    findings = quality.review(doc, template_file="t.yaml")
    assert "unused_parameter" in _rules(findings)


def test_referenced_parameter_is_not_flagged() -> None:
    doc = _doc(
        Parameters={"VpcCidr": {"Type": "String"}},
        Resources={"Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": {"Ref": "VpcCidr"}}}},
    )
    findings = quality.review(doc, template_file="t.yaml")
    assert "unused_parameter" not in _rules(findings)


def test_parameter_referenced_only_in_sub_is_not_flagged() -> None:
    doc = _doc(
        Parameters={"Name": {"Type": "String"}},
        Resources={"B": {"Type": "AWS::S3::Bucket", "Properties": {
            "BucketName": {"Fn::Sub": "${Name}-bucket"}}}},
    )
    findings = quality.review(doc, template_file="t.yaml")
    assert "unused_parameter" not in _rules(findings)


# ---------------------------------------------------------------------------
# Unused condition
# ---------------------------------------------------------------------------


def test_unused_condition_is_flagged() -> None:
    doc = _doc(
        Conditions={"Never": {"Fn::Equals": [{"Ref": "Env"}, "x"]}},
        Resources={},
    )
    findings = quality.review(doc, template_file="t.yaml")
    assert "unused_condition" in _rules(findings)


def test_condition_used_by_resource_is_not_flagged() -> None:
    doc = _doc(
        Conditions={"Enable": {"Fn::Equals": [{"Ref": "Env"}, "prod"]}},
        Resources={"B": {"Type": "AWS::S3::Bucket", "Condition": "Enable", "Properties": {}}},
    )
    findings = quality.review(doc, template_file="t.yaml")
    assert "unused_condition" not in _rules(findings)


def test_condition_used_in_fn_if_is_not_flagged() -> None:
    doc = _doc(
        Conditions={"Enable": {"Fn::Equals": [{"Ref": "Env"}, "prod"]}},
        Resources={"B": {"Type": "AWS::S3::Bucket", "Properties": {
            "BucketName": {"Fn::If": ["Enable", "a", "b"]}}}},
    )
    findings = quality.review(doc, template_file="t.yaml")
    assert "unused_condition" not in _rules(findings)


# ---------------------------------------------------------------------------
# Circular dependency
# ---------------------------------------------------------------------------


def test_circular_dependency_is_flagged() -> None:
    doc = _doc(Resources={
        "A": {"Type": "AWS::X::Y", "Properties": {}, "DependsOn": "B"},
        "B": {"Type": "AWS::X::Y", "Properties": {}, "DependsOn": "A"},
    })
    findings = quality.review(doc, template_file="t.yaml")
    assert "circular_dependency" in _rules(findings)


def test_acyclic_graph_is_not_flagged() -> None:
    doc = _doc(Resources={
        "A": {"Type": "AWS::X::Y", "Properties": {}},
        "B": {"Type": "AWS::X::Y", "Properties": {"Ref": "A"}},
        "C": {"Type": "AWS::X::Y", "Properties": {"Ref": "B"}},
    })
    findings = quality.review(doc, template_file="t.yaml")
    assert "circular_dependency" not in _rules(findings)


def test_self_reference_is_not_treated_as_edge() -> None:
    """A resource cannot depend on itself in the graph, so no false cycle."""
    doc = _doc(Resources={
        "A": {"Type": "AWS::X::Y", "Properties": {"Ref": "A"}},
    })
    findings = quality.review(doc, template_file="t.yaml")
    assert "circular_dependency" not in _rules(findings)


# ---------------------------------------------------------------------------
# AllowedValues mixed types
# ---------------------------------------------------------------------------


def test_mixed_type_allowed_values_is_flagged() -> None:
    doc = _doc(Parameters={
        "Env": {"Type": "String", "AllowedValues": ["prod", "staging", 123]},
    })
    findings = quality.review(doc, template_file="t.yaml")
    assert "allowed_values_mixed_types" in _rules(findings)


def test_consistent_allowed_values_is_not_flagged() -> None:
    doc = _doc(Parameters={
        "Env": {"Type": "String", "AllowedValues": ["prod", "staging", "dev"]},
    })
    findings = quality.review(doc, template_file="t.yaml")
    assert "allowed_values_mixed_types" not in _rules(findings)


# ---------------------------------------------------------------------------
# Finding contract
# ---------------------------------------------------------------------------


def test_every_finding_is_confirmed_and_valid() -> None:
    doc = _doc(
        Parameters={"Env": {"Type": "String", "AllowedValues": ["prod", 1]}, "Unused": {"Type": "String"}},
        Conditions={"IsProduction": {"Fn::Equals": [{"Ref": "Env"}, "staging"]}},
        Resources={},
    )
    findings = quality.review(doc, template_file="t.yaml")
    assert findings
    for f in findings:
        assert f.Confidence == CONFIRMED
        assert f.Source == ["Quality Review"]
        assert f.Normalized_Category == "TemplateQuality"
        validate(dataclasses.replace(f, ID=1))


def test_clean_template_produces_no_findings() -> None:
    doc = _doc(
        Parameters={"VpcCidr": {"Type": "String", "AllowedValues": ["10.0.0.0/16", "10.1.0.0/16"]}},
        Conditions={"IsProd": {"Fn::Equals": [{"Ref": "VpcCidr"}, "10.0.0.0/16"]}},
        Resources={"Vpc": {"Type": "AWS::EC2::VPC", "Condition": "IsProd", "Properties": {"CidrBlock": {"Ref": "VpcCidr"}}}},
    )
    assert quality.review(doc, template_file="t.yaml") == []


def test_empty_template_is_safe() -> None:
    assert quality.review({"Resources": {}}, template_file="t.yaml") == []


def test_review_is_deterministic() -> None:
    doc = _doc(
        Conditions={"IsProduction": {"Fn::Equals": [{"Ref": "Env"}, "staging"]}},
        Resources={},
    )
    first = [f.Finding for f in quality.review(doc, template_file="t.yaml")]
    second = [f.Finding for f in quality.review(doc, template_file="t.yaml")]
    assert first == second


def test_run_and_normalize_returns_a_quality_source_result(tmp_path) -> None:
    template = tmp_path / "t.yaml"
    template.write_text(
        "Parameters:\n"
        "  Env:\n"
        "    Type: String\n"
        "Conditions:\n"
        "  IsProduction:\n"
        "    !Equals [!Ref Env, staging]\n"
        "Resources:\n"
        "  B:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Properties: {}\n",
        encoding="utf-8",
    )
    result = quality.run_and_normalize(str(template), workspace_root=tmp_path)
    assert result.source == "Quality Review"
    assert result.errors == []
    assert "condition_name_logic_mismatch" in _rules(result.findings)
