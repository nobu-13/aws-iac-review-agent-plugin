"""Unit tests for Change_Qualifiers and Semantic_Limitations (v1.1 Task 7).

Each Code is shown to appear when its condition holds and to be absent when it
does not (Requirement 4 AC15), on small hand-written Templates. The tests also
pin that neither Qualifiers nor Limitations change ``structural_completeness``
(R4.9), that ``pre_transform`` is attached to every Change_Entry exactly when
``transform_not_expanded`` applies (R4.7), and that the Limitation walk visits
each shared object once (Design 2-5-3).
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest

from iacreview import deltaio, deltaschema, semdiff
from iacreview.deltaio import ParsedTemplate
from iacreview.semdiff import ChangeEntry, SemanticDiffResult

PATH = Path("qualifiers.yaml")


def _ok(text: str, side: str) -> ParsedTemplate:
    parsed = deltaio.parse_template(text, PATH, side)
    assert isinstance(parsed, ParsedTemplate), parsed
    return parsed


def _diff(base: str, head: str) -> SemanticDiffResult:
    result = semdiff.diff(_ok(base, "base"), _ok(head, "head"))
    assert isinstance(result, SemanticDiffResult), result
    return result


def _by_path(result: SemanticDiffResult) -> Dict[Tuple[Any, ...], ChangeEntry]:
    return {change.path: change for change in result.changes}


def _one(base: str, head: str) -> ChangeEntry:
    (change,) = _diff(base, head).changes
    return change


def _resource(props: str, extra: str = "") -> str:
    return "Resources:\n  B:\n    Type: AWS::S3::Bucket\n" + extra + "    Properties:\n" + props


# ---------------------------------------------------------------------------
# expression_unevaluated (R4.3)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "base,head",
    [
        ("      N: !Sub '${A}-x'\n", "      N: !Sub '${A}-y'\n"),  # change inside Fn::Sub
        ("      N: plain\n", "      N: !Ref P\n"),  # Ref on the Head side only
        ("      N: !Join ['', [a]]\n", "      N: plain\n"),  # Fn:: on the Base side only
        ("      N: {Fn::If: [C, a, b]}\n", "      N: {Fn::If: [C, a, c]}\n"),
        ("      N: [{Condition: C}]\n", "      N: [{Condition: D}]\n"),  # the Condition function
        ("      N: {X: [!GetAtt R.Arn]}\n", "      N: {X: [!GetAtt R.Id]}\n"),
    ],
)
def test_expression_unevaluated_present(base: str, head: str) -> None:
    change = _one(_resource(base), _resource(head))
    assert "expression_unevaluated" in change.qualifiers


def test_expression_unevaluated_absent_for_literals() -> None:
    change = _one(_resource("      N: {a: [1, x]}\n"), _resource("      N: {a: [1, y]}\n"))
    assert change.qualifiers == ()


def test_condition_attribute_is_not_an_intrinsic() -> None:
    """The Resource ``Condition`` attribute is not the ``Condition`` function."""
    base = "Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Condition: IsProd\n"
    head = "Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Condition: IsDev\n"
    change = _one(base, head)
    assert change.path == ("Resources", "B", "Condition")
    assert change.qualifiers == ("conditional",)


_IAM_POLICY = (
    "Resources:\n  P:\n    Type: AWS::IAM::ManagedPolicy\n    Properties:\n"
    "      PolicyDocument:\n        Statement:\n"
    "          - Effect: Allow\n            Action: s3:GetObject\n            Resource: '*'\n"
    "            Condition:\n              StringEquals:\n"
    "                aws:SourceAccount: '{account}'\n"
)


def test_iam_condition_block_is_not_an_intrinsic() -> None:
    """Regression: an IAM Statement ``Condition`` block is data (R4.3, R4.15)."""
    change = _one(
        _IAM_POLICY.format(account="111111111111"), _IAM_POLICY.format(account="222222222222")
    )
    assert change.path == (
        "Resources", "P", "Properties", "PolicyDocument", "Statement", 0,
        "Condition", "StringEquals", "aws:SourceAccount",
    )
    assert change.qualifiers == ()


def test_iam_condition_block_added_is_not_an_intrinsic() -> None:
    """The subtree scan of an added ``Condition`` block finds no intrinsic."""
    base = _resource("      Policy: {Effect: Allow}\n")
    head = _resource("      Policy: {Effect: Allow, Condition: {Bool: {aws:SecureTransport: 'true'}}}\n")
    change = _one(base, head)
    assert change.change == "added" and change.qualifiers == ()


def test_condition_key_with_siblings_is_not_the_function() -> None:
    """``{Condition: <str>, ...}`` with other keys is not the Condition function."""
    change = _one(
        _resource("      N: {Condition: a, Other: x}\n"), _resource("      N: {Condition: b, Other: x}\n")
    )
    assert change.qualifiers == ()


@pytest.mark.parametrize("function", ["Fn::If", "Fn::And"])
def test_condition_function_inside_condition_functions(function: str) -> None:
    """The Condition function nested in ``Fn::If`` / ``Fn::And`` is an intrinsic."""
    template = (
        "Resources:\n  B: {{Type: AWS::S3::Bucket}}\n"
        "Conditions:\n  Both:\n    Fn::And:\n      - {{Condition: {name}}}\n      - {{Condition: Other}}\n"
        if function == "Fn::And"
        else "Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties:\n"
        "      N: {{Fn::If: [{{Condition: {name}}}, a, b]}}\n"
    )
    change = _one(template.format(name="IsProd"), template.format(name="IsDev"))
    assert change.path[-1] == "Condition"
    assert "expression_unevaluated" in change.qualifiers


def test_condition_function_scanned_in_an_added_subtree() -> None:
    """No ``Fn::`` key around it: the Condition function alone qualifies."""
    base = "Resources:\n  B: {Type: AWS::S3::Bucket}\nConditions:\n  Both: {Fn::Equals: [a, b]}\n"
    head = base + "  Alias: {Condition: Both}\n"
    change = _one(base, head)
    assert change.path == ("Conditions", "Alias")
    assert change.change == "added" and change.qualifiers == ("expression_unevaluated",)


def test_added_resource_with_condition_attribute() -> None:
    base = "Resources:\n  A: {Type: AWS::SQS::Queue}\n"
    head = base + "  B:\n    Type: AWS::S3::Bucket\n    Condition: IsProd\n    Properties: {N: x}\n"
    change = _one(base, head)
    assert change.change == "added" and change.qualifiers == ("conditional",)


def test_added_resource_with_intrinsic_inside() -> None:
    base = "Resources:\n  A: {Type: AWS::SQS::Queue}\n"
    head = base + "  B:\n    Type: AWS::S3::Bucket\n    Properties: {N: !Ref P}\n"
    assert _one(base, head).qualifiers == ("expression_unevaluated",)


# ---------------------------------------------------------------------------
# conditional (R4.4)
# ---------------------------------------------------------------------------


def test_conditional_from_resource_condition_on_one_side() -> None:
    base = _resource("      N: a\n", "    Condition: IsProd\n")
    head = _resource("      N: b\n")
    changes = _by_path(_diff(base, head))
    assert set(changes) == {("Resources", "B", "Condition"), ("Resources", "B", "Properties", "N")}
    assert changes[("Resources", "B", "Properties", "N")].qualifiers == ("conditional",)
    assert changes[("Resources", "B", "Condition")].change == "removed"


def test_conditional_from_output_condition() -> None:
    base = _resource("      N: a\n") + "Outputs:\n  O: {Condition: C, Value: a}\n"
    head = _resource("      N: a\n") + "Outputs:\n  O: {Condition: C, Value: b}\n"
    assert _one(base, head).qualifiers == ("conditional",)


def test_conditional_from_fn_if_ancestor() -> None:
    change = _one(
        _resource("      N: !If [C, {X: a}, b]\n"),
        _resource("      N: !If [C, {X: z}, b]\n"),
    )
    assert change.path[-3:] == ("Fn::If", 1, "X")
    assert change.qualifiers == ("expression_unevaluated", "conditional")


def test_not_conditional_without_condition_or_fn_if() -> None:
    assert "conditional" not in _one(_resource("      N: a\n"), _resource("      N: b\n")).qualifiers


def test_change_in_conditions_section_is_not_conditional() -> None:
    base = "Conditions:\n  C: !Equals [a, b]\n" + _resource("      N: a\n")
    head = "Conditions:\n  C: !Equals [a, c]\n" + _resource("      N: a\n")
    change = _one(base, head)
    assert change.section == "Conditions" and "conditional" not in change.qualifiers


def test_fn_if_only_in_a_sibling_does_not_qualify() -> None:
    base = _resource("      N: a\n      M: !If [C, x, y]\n")
    head = _resource("      N: b\n      M: !If [C, x, y]\n")
    assert _one(base, head).qualifiers == ()


# ---------------------------------------------------------------------------
# dynamic_reference_unresolved (R4.5)
# ---------------------------------------------------------------------------


def test_dynamic_reference_qualifier_present() -> None:
    change = _one(
        _resource("      P: '{{resolve:ssm:/a}}'\n"),
        _resource("      P: '{{resolve:ssm:/b}}'\n"),
    )
    assert change.qualifiers == ("dynamic_reference_unresolved",)


def test_dynamic_reference_qualifier_from_one_side_inside_sub() -> None:
    change = _one(
        _resource("      P: plain\n"),
        _resource("      P: !Sub 'x-{{resolve:secretsmanager:s}}'\n"),
    )
    assert change.qualifiers == ("expression_unevaluated", "dynamic_reference_unresolved")


def test_dynamic_reference_elsewhere_gives_the_limitation_only() -> None:
    base = _resource("      P: '{{resolve:ssm:/a}}'\n      N: a\n")
    head = _resource("      P: '{{resolve:ssm:/a}}'\n      N: b\n")
    result = _diff(base, head)
    (change,) = result.changes
    assert change.qualifiers == ()
    assert result.semantic_limitations == ("dynamic_reference_unresolved",)


# ---------------------------------------------------------------------------
# external_value (R4.6)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "base,head",
    [
        ("      N: !ImportValue A\n", "      N: !ImportValue B\n"),
        ("      N: plain\n", "      N: !Select [0, !GetAZs '']\n"),
        ("      N: !Ref AWS::Region\n", "      N: !Ref AWS::AccountId\n"),
        ("      N: !Ref AWS::Region\n", "      N: plain\n"),
    ],
)
def test_external_value_present(base: str, head: str) -> None:
    assert "external_value" in _one(_resource(base), _resource(head)).qualifiers


@pytest.mark.parametrize(
    "base,head",
    [
        ("      N: !Ref ParamA\n", "      N: !Ref ParamB\n"),
        ("      N: !Sub '${AWS::Region}-a'\n", "      N: !Sub '${AWS::Region}-b'\n"),
        ("      N: AWS::Region\n", "      N: AWS::AccountId\n"),
    ],
)
def test_external_value_absent(base: str, head: str) -> None:
    assert "external_value" not in _one(_resource(base), _resource(head)).qualifiers


def test_external_value_from_import_value_ancestor() -> None:
    change = _one(
        _resource("      N: !ImportValue {Fn::Sub: 'a-${X}'}\n"),
        _resource("      N: !ImportValue {Fn::Sub: 'b-${X}'}\n"),
    )
    assert change.path[-2:] == ("Fn::ImportValue", "Fn::Sub")
    assert change.qualifiers == ("expression_unevaluated", "external_value")


# ---------------------------------------------------------------------------
# Limitations (R4.8) and pre_transform (R4.7)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "prefix,props",
    [
        ("Transform: AWS::Serverless-2016-10-31\n", "      N: {v}\n"),
        ("", "      N: {v}\n      Fn::Transform: {{Name: X, Parameters: {{}}}}\n"),
        ("", "      N: {v}\n      I: {{Name: AWS::Include}}\n"),
    ],
)
def test_transform_limitation_and_pre_transform(prefix: str, props: str) -> None:
    base = prefix + _resource(props.format(v="a")) + "Outputs:\n  O: {Value: a}\n"
    head = prefix + _resource(props.format(v="b")) + "Outputs:\n  O: {Value: b}\n"
    result = _diff(base, head)
    assert "transform_not_expanded" in result.semantic_limitations
    assert len(result.changes) == 2
    assert all(change.qualifiers[-1] == "pre_transform" for change in result.changes)


def test_transform_on_one_side_only() -> None:
    base = _resource("      N: a\n")
    head = "Transform: AWS::Serverless-2016-10-31\n" + _resource("      N: b\n")
    result = _diff(base, head)
    assert "transform_not_expanded" in result.semantic_limitations
    assert all("pre_transform" in change.qualifiers for change in result.changes)


def test_no_transform_no_pre_transform() -> None:
    result = _diff(_resource("      N: a\n"), _resource("      N: b\n"))
    assert result.semantic_limitations == ()
    assert all("pre_transform" not in change.qualifiers for change in result.changes)


def test_transform_without_change_is_still_reported() -> None:
    doc = "Transform: X\n" + _resource("      N: a\n")
    result = _diff(doc, doc)
    assert result.changes == () and result.semantic_limitations == ("transform_not_expanded",)
    assert result.structural_completeness == "complete"


@pytest.mark.parametrize("section", ["Parameters", "Mappings", "Conditions"])
def test_indirect_effects_present(section: str) -> None:
    base = "{0}:\n  E: {{X: a}}\n".format(section) + _resource("      N: a\n")
    head = "{0}:\n  E: {{X: b}}\n".format(section) + _resource("      N: a\n")
    assert _diff(base, head).semantic_limitations == ("indirect_effects_not_evaluated",)


@pytest.mark.parametrize("section", ["Outputs", "Rules", "Metadata"])
def test_indirect_effects_absent(section: str) -> None:
    base = "{0}:\n  E: {{X: a}}\n".format(section) + _resource("      N: a\n")
    head = "{0}:\n  E: {{X: b}}\n".format(section) + _resource("      N: a\n")
    assert _diff(base, head).semantic_limitations == ()


def test_unchanged_parameters_give_no_indirect_effects() -> None:
    params = "Parameters:\n  P: {Type: String}\n"
    result = _diff(params + _resource("      N: a\n"), params + _resource("      N: b\n"))
    assert len(result.changes) == 1 and result.semantic_limitations == ()


def test_nested_stack_present_and_absent() -> None:
    stack = "Resources:\n  S:\n    Type: AWS::CloudFormation::Stack\n    Properties: {TemplateURL: u}\n"
    result = _diff(stack, stack)
    assert result.changes == () and result.semantic_limitations == ("nested_stack_not_compared",)
    assert _diff(_resource("      N: a\n"), _resource("      N: a\n")).semantic_limitations == ()


def test_nested_stack_on_one_side_only() -> None:
    base = _resource("      N: a\n")
    head = base + "  S:\n    Type: AWS::CloudFormation::Stack\n"
    assert "nested_stack_not_compared" in _diff(base, head).semantic_limitations


def test_dynamic_reference_limitation_absent_without_resolve() -> None:
    doc = _resource("      P: '{{other}}'\n")
    assert _diff(doc, doc).semantic_limitations == ()


def test_limitations_are_in_documented_order() -> None:
    doc = (
        "Transform: X\nParameters:\n  P: {{Default: {v}}}\n"
        "Resources:\n  S:\n    Type: AWS::CloudFormation::Stack\n    Properties: {{U: '{{{{resolve:ssm:p}}}}'}}\n"
    )
    result = _diff(doc.format(v="a"), doc.format(v="b"))
    assert result.semantic_limitations == deltaschema.SEMANTIC_LIMITATIONS


def test_qualifiers_and_limitations_do_not_change_completeness() -> None:
    """R4.9"""
    base = "Transform: X\n" + _resource("      N: !ImportValue '{{resolve:ssm:a}}'\n", "    Condition: C\n")
    head = "Transform: X\n" + _resource("      N: !ImportValue '{{resolve:ssm:b}}'\n", "    Condition: C\n")
    result = _diff(base, head)
    (change,) = result.changes
    assert change.qualifiers == deltaschema.CHANGE_QUALIFIERS
    assert result.structural_completeness == "complete"
    assert result.observation == "changes_observed"


def test_scope_is_the_declared_template() -> None:
    """R4.1: the only scope the Delta_Tool records."""
    assert deltaschema.SCOPE == "declared_template"


def test_all_codes_are_from_the_closed_sets() -> None:
    base = "Transform: X\nParameters:\n  P: {Default: a}\n" + _resource("      N: !If [C, !Ref AWS::Region, a]\n")
    head = "Transform: X\nParameters:\n  P: {Default: b}\n" + _resource("      N: !If [C, !Ref AWS::NoValue, b]\n")
    result = _diff(base, head)
    for change in result.changes:
        assert set(change.qualifiers) <= set(deltaschema.CHANGE_QUALIFIERS)
        assert set(change.hints) <= set(deltaschema.CHANGE_HINTS)
    assert set(result.semantic_limitations) <= set(deltaschema.SEMANTIC_LIMITATIONS)


# ---------------------------------------------------------------------------
# The Limitation walk visits each object once (Design 2-5-3)
# ---------------------------------------------------------------------------


def test_limitation_scan_does_not_expand_shared_objects() -> None:
    """A DAG standing for 2**60 leaves is scanned in its 61 containers."""
    shared: List[Any] = ["{{resolve:ssm:x}}"]
    for _ in range(60):
        shared = [shared, shared]
    start = time.perf_counter()
    found = semdiff._scan_limitations({"Resources": {"R": {"Type": "AWS::S3::Bucket", "P": shared}}})
    assert time.perf_counter() - start < 1.0
    assert found == {"dynamic_reference_unresolved"}


def test_qualifier_scan_is_bounded_by_the_change_subtree() -> None:
    """Only the change position is scanned: a qualifier elsewhere does not leak in."""
    base = _resource("      A: !Ref X\n      B: a\n")
    head = _resource("      A: !Ref X\n      B: b\n")
    assert _by_path(_diff(base, head))[("Resources", "B", "Properties", "B")].qualifiers == ()
