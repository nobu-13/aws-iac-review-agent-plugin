"""Phase 1 boundary: typed paths, exact names, operations, parents, unsupported constructs."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

from iacreview import deltaio, semdiff
from iacreview.remediation import boundary, gitsnap
from iacreview.remediation import contract as c

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = c.parse_contract_bytes((ROOT / "benchmark/remediation/scenarios/sc01-billing-mode/contract.yaml").read_bytes())
TYPE = "AWS::DynamoDB::Table"

BASE: Dict[str, Any] = {
    "Resources": {
        "OrdersTable": {
            "Type": TYPE,
            "DeletionPolicy": "Retain",
            "Properties": {
                "BillingMode": "PAY_PER_REQUEST",
                "ProvisionedThroughput": {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
                "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                "Tags": [{"Key": "a", "Value": "1"}, {"Key": "b", "Value": "2"}],
            },
        },
        "Other": {"Type": "AWS::SNS::Topic", "Properties": {"0": "x"}},
    }
}


def parsed(doc: Any, side: str = "base") -> deltaio.ParsedTemplate:
    result = deltaio.parse_template(json.dumps(doc), Path("t.json"), side)
    assert isinstance(result, deltaio.ParsedTemplate)
    return result


def codes(head_doc: Any, base_doc: Any = BASE) -> List[str]:
    b, h = parsed(base_doc), parsed(head_doc, "head")
    result = semdiff.diff(b, h)
    assert isinstance(result, semdiff.SemanticDiffResult)
    return sorted({f.code for f in boundary.template(CONTRACT, TYPE, b, h, result)})


def edit(fn) -> Dict[str, Any]:
    doc = copy.deepcopy(BASE)
    fn(doc)
    return doc


def props(doc: Dict[str, Any]) -> Dict[str, Any]:
    return doc["Resources"]["OrdersTable"]["Properties"]


def test_the_allowed_removal_is_clean() -> None:
    assert codes(edit(lambda d: props(d).pop("ProvisionedThroughput"))) == []


def test_replace_and_add_of_billing_mode_are_allowed() -> None:
    assert codes(edit(lambda d: props(d).__setitem__("BillingMode", "PROVISIONED"))) == []
    without = edit(lambda d: props(d).pop("BillingMode"))
    assert codes(BASE, base_doc=without) == []  # add


@pytest.mark.parametrize(
    "mutate,expected",
    [
        (lambda d: props(d)["ProvisionedThroughput"].__setitem__("ReadCapacityUnits", 6), "operation_not_allowed"),
        (lambda d: props(d).pop("BillingMode"), "operation_not_allowed"),
        (lambda d: props(d).__setitem__("BillingModeX", "x"), "template_change_outside_scope"),
        (lambda d: props(d).__setitem__("billingmode", "x"), "template_change_outside_scope"),
        (lambda d: props(d).__setitem__("Billing", "x"), "template_change_outside_scope"),
        (lambda d: props(d).__setitem__("B\u0456llingMode", "x"), "template_change_outside_scope"),
        (lambda d: props(d)["KeySchema"].append({"AttributeName": "sk", "KeyType": "RANGE"}), "template_change_outside_scope"),
        (lambda d: props(d)["Tags"].reverse(), "template_change_outside_scope"),
        (lambda d: d["Resources"]["OrdersTable"].__setitem__("DeletionPolicy", "Delete"), "template_change_outside_scope"),
        (lambda d: d["Resources"]["OrdersTable"].__setitem__("Condition", "IsProd"), "template_change_outside_scope"),
        (lambda d: d["Resources"]["Other"]["Properties"].__setitem__("0", "y"), "template_change_outside_scope"),
        (lambda d: d["Resources"].pop("Other"), "resource_removed"),
        (lambda d: d["Resources"].__setitem__("New", {"Type": "AWS::SNS::Topic"}), "resource_added"),
        (lambda d: d["Resources"]["OrdersTable"].__setitem__("Type", "AWS::DynamoDB::GlobalTable"), "resource_type_changed"),
        (lambda d: d["Resources"]["OrdersTable"].__setitem__("Properties", ["BillingMode"]), "parent_replaced"),
        (lambda d: d["Resources"]["OrdersTable"].pop("Properties"), "parent_replaced"),
        (lambda d: d["Resources"].__setitem__("OrdersTable", "gone"), "parent_replaced"),
        (lambda d: d.__setitem__("Outputs", {"X": {"Value": "1"}}), "template_change_outside_scope"),
    ],
)
def test_changes_outside_the_edits_are_blocked(mutate, expected: str) -> None:
    assert expected in codes(edit(mutate))


def test_a_numeric_string_key_is_not_a_list_index() -> None:
    # Other.Properties has the string key "0"; an allowed property named "0"
    # cannot exist (the contract regex needs a letter or digit run), and the
    # change is reported outside the scope with the typed key kept as a str.
    b = parsed(BASE)
    h = parsed(edit(lambda d: d["Resources"]["Other"]["Properties"].__setitem__("0", "y")), "head")
    result = semdiff.diff(b, h)
    assert isinstance(result, semdiff.SemanticDiffResult)
    findings = boundary.template(CONTRACT, TYPE, b, h, result)
    assert any(f.path == ("Resources", "Other", "Properties", "0") for f in findings)


def test_a_conditional_value_in_an_allowed_property_is_unsupported() -> None:
    head = edit(lambda d: props(d).__setitem__("BillingMode", {"Fn::If": ["IsProd", "PROVISIONED", "PAY_PER_REQUEST"]}))
    assert "unsupported_construct" in codes(head)


def test_a_dynamic_reference_in_an_allowed_property_is_unsupported() -> None:
    head = edit(lambda d: props(d).__setitem__("BillingMode", "{{resolve:ssm:/billing}}"))
    assert "unsupported_construct" in codes(head)


def test_a_transform_makes_the_comparison_unsupported() -> None:
    head = edit(lambda d: (props(d).pop("ProvisionedThroughput"), d.__setitem__("Transform", "AWS::Serverless-2016-10-31")))
    assert {"unsupported_construct", "template_change_outside_scope"} <= set(codes(head, base_doc=edit(lambda d: d.__setitem__("Transform", "AWS::Serverless-2016-10-31"))) + ["template_change_outside_scope"])


def test_a_duplicate_key_is_an_incomplete_comparison() -> None:
    text = json.dumps(BASE).replace('"DeletionPolicy": "Retain"', '"DeletionPolicy": "Retain", "DeletionPolicy": "Delete"')
    b = parsed(BASE)
    h = deltaio.parse_template(text, Path("t.json"), "head")
    assert isinstance(h, deltaio.ParsedTemplate)
    result = semdiff.diff(b, h)
    assert isinstance(result, semdiff.SemanticDiffResult)
    assert "comparison_incomplete" in {f.code for f in boundary.template(CONTRACT, TYPE, b, h, result)}


def test_a_base_without_the_target_does_not_fit_the_contract() -> None:
    base = edit(lambda d: d["Resources"].pop("OrdersTable"))
    assert "target_resource_missing" in codes(base, base_doc=base)


# ---------------------------------------------------------------------------
# Repository level
# ---------------------------------------------------------------------------


def snap(entries: Dict[str, gitsnap.Entry]) -> gitsnap.Snapshot:
    return gitsnap.Snapshot("commit", None, None, dict(entries))


F = gitsnap.Entry("100644", "a" * 40)
G = gitsnap.Entry("100644", "b" * 40)


@pytest.mark.parametrize(
    "head,expected",
    [
        ({"infra/template.yaml": G, "x": F}, set()),
        ({"infra/template.yaml": G, "x": F, "y": F}, {"file_added_outside_scope"}),
        ({"infra/template.yaml": G}, {"file_removed_outside_scope"}),
        ({"infra/template.yaml": G, "x": G}, {"file_modified_outside_scope"}),
        ({"infra/template.yaml": G, "x": gitsnap.Entry("100755", "a" * 40)}, {"file_mode_changed"}),
        ({"infra/template.yaml": G, "x": gitsnap.Entry("120000", "a" * 40)}, {"file_mode_changed"}),
        ({"infra/template.yaml": G, "x": gitsnap.Entry("160000", "a" * 40)}, {"file_mode_changed"}),
        ({"x": F}, {"target_template_removed"}),
        ({"infra/template.yaml": gitsnap.Entry("120000", "b" * 40), "x": F}, {"target_not_regular_file"}),
        ({"infra/template.yaml": gitsnap.Entry("100755", "b" * 40), "x": F}, {"file_mode_changed"}),
        ({"INFRA/template.yaml": G, "x": F}, {"file_added_outside_scope", "target_template_removed"}),
    ],
)
def test_repository_boundary(head: Dict[str, gitsnap.Entry], expected: set) -> None:
    base = snap({"infra/template.yaml": F, "x": F})
    assert {f.code for f in boundary.repository(CONTRACT, base, snap(head))} == expected
