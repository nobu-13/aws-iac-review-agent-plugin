"""Tests for the deterministic network-design Source (:mod:`iacreview.netgraph`).

This is the v0.4.0 fourth deterministic Source. It reasons about relationships
between resources -- gateway attachment, default routes, reachability, orphaned
resources -- which single-resource cfn-guard rules cannot express. What these
tests lock:

* the reference graph is built from Ref / Fn::GetAtt / DependsOn, and skips
  pseudo-parameters;
* each detector fires on its positive case and stays silent on its negative;
* every finding is Confidence: Confirmed with Source ["Network Review"];
* the Source is deterministic and safe on templates with no network resources.
"""

from __future__ import annotations

from typing import Any, Dict, List

import pytest

from iacreview import netgraph
from iacreview.finding import CONFIRMED, validate


def _doc(resources: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    return {"Resources": resources}


def _rules(findings: List[Any]) -> set:
    """The rule ids of a list of findings."""
    out = set()
    for f in findings:
        text = f.Finding
        if text.startswith("[") and "]" in text:
            out.add(text[1:text.index("]")])
    return out


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------


def test_graph_records_ref_edges() -> None:
    doc = _doc({
        "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {}},
        "Subnet": {"Type": "AWS::EC2::Subnet", "Properties": {"VpcId": {"Ref": "Vpc"}}},
    })
    graph = netgraph.build_graph(doc)
    assert ("Subnet", "Vpc") in graph.edges


def test_graph_records_getatt_edges() -> None:
    doc = _doc({
        "Role": {"Type": "AWS::IAM::Role", "Properties": {}},
        "Fn": {"Type": "AWS::Lambda::Function", "Properties": {"Role": {"Fn::GetAtt": ["Role", "Arn"]}}},
    })
    graph = netgraph.build_graph(doc)
    assert ("Fn", "Role") in graph.edges


def test_graph_records_depends_on_edges() -> None:
    doc = _doc({
        "A": {"Type": "AWS::EC2::VPC", "Properties": {}},
        "B": {"Type": "AWS::EC2::Subnet", "Properties": {}, "DependsOn": "A"},
    })
    graph = netgraph.build_graph(doc)
    assert ("B", "A") in graph.edges


def test_graph_skips_pseudo_parameters() -> None:
    doc = _doc({
        "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": {"Ref": "AWS::Region"}}},
    })
    graph = netgraph.build_graph(doc)
    assert graph.edges == []


def test_graph_skips_reference_to_nonexistent_resource() -> None:
    doc = _doc({
        "Subnet": {"Type": "AWS::EC2::Subnet", "Properties": {"VpcId": {"Ref": "MissingVpc"}}},
    })
    graph = netgraph.build_graph(doc)
    assert graph.edges == []


# ---------------------------------------------------------------------------
# Detector: IGW not attached
# ---------------------------------------------------------------------------


def test_unattached_igw_is_flagged() -> None:
    doc = _doc({
        "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {}},
        "Igw": {"Type": "AWS::EC2::InternetGateway", "Properties": {}},
    })
    findings = netgraph.review(doc, template_file="t.yaml")
    assert "igw_not_attached" in _rules(findings)


def test_attached_igw_is_not_flagged() -> None:
    doc = _doc({
        "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {}},
        "Igw": {"Type": "AWS::EC2::InternetGateway", "Properties": {}},
        "Att": {"Type": "AWS::EC2::VPCGatewayAttachment", "Properties": {
            "VpcId": {"Ref": "Vpc"}, "InternetGatewayId": {"Ref": "Igw"}}},
    })
    findings = netgraph.review(doc, template_file="t.yaml")
    assert "igw_not_attached" not in _rules(findings)


# ---------------------------------------------------------------------------
# Detector: route table without default route
# ---------------------------------------------------------------------------


def test_route_table_without_default_route_is_flagged_when_igw_present() -> None:
    doc = _doc({
        "Igw": {"Type": "AWS::EC2::InternetGateway", "Properties": {}},
        "Rt": {"Type": "AWS::EC2::RouteTable", "Properties": {}},
    })
    findings = netgraph.review(doc, template_file="t.yaml")
    assert "route_table_no_default_route" in _rules(findings)


def test_route_table_with_default_route_is_not_flagged() -> None:
    doc = _doc({
        "Igw": {"Type": "AWS::EC2::InternetGateway", "Properties": {}},
        "Rt": {"Type": "AWS::EC2::RouteTable", "Properties": {}},
        "Route": {"Type": "AWS::EC2::Route", "Properties": {
            "RouteTableId": {"Ref": "Rt"}, "DestinationCidrBlock": "0.0.0.0/0",
            "GatewayId": {"Ref": "Igw"}}},
    })
    findings = netgraph.review(doc, template_file="t.yaml")
    assert "route_table_no_default_route" not in _rules(findings)


def test_route_table_not_flagged_without_igw() -> None:
    """A private route table in a template with no gateway is intentional."""
    doc = _doc({
        "Rt": {"Type": "AWS::EC2::RouteTable", "Properties": {}},
    })
    findings = netgraph.review(doc, template_file="t.yaml")
    assert "route_table_no_default_route" not in _rules(findings)


# ---------------------------------------------------------------------------
# Detector: RDS reachable from internet
# ---------------------------------------------------------------------------


def test_public_rds_with_igw_is_flagged() -> None:
    doc = _doc({
        "Igw": {"Type": "AWS::EC2::InternetGateway", "Properties": {}},
        "Db": {"Type": "AWS::RDS::DBInstance", "Properties": {"PubliclyAccessible": True}},
    })
    findings = netgraph.review(doc, template_file="t.yaml")
    assert "rds_reachable_from_internet" in _rules(findings)


def test_private_rds_is_not_flagged() -> None:
    doc = _doc({
        "Igw": {"Type": "AWS::EC2::InternetGateway", "Properties": {}},
        "Db": {"Type": "AWS::RDS::DBInstance", "Properties": {"PubliclyAccessible": False}},
    })
    findings = netgraph.review(doc, template_file="t.yaml")
    assert "rds_reachable_from_internet" not in _rules(findings)


def test_public_rds_without_igw_is_not_flagged_by_netgraph() -> None:
    """No internet path in the template, so the relationship check stays silent.

    The single-resource cfn-guard rule still flags the public flag; this Source
    only adds the relationship finding when an internet path exists.
    """
    doc = _doc({
        "Db": {"Type": "AWS::RDS::DBInstance", "Properties": {"PubliclyAccessible": True}},
    })
    findings = netgraph.review(doc, template_file="t.yaml")
    assert "rds_reachable_from_internet" not in _rules(findings)


# ---------------------------------------------------------------------------
# Detector: orphaned route table
# ---------------------------------------------------------------------------


def test_orphaned_route_table_is_flagged() -> None:
    doc = _doc({
        "Rt": {"Type": "AWS::EC2::RouteTable", "Properties": {}},
    })
    findings = netgraph.review(doc, template_file="t.yaml")
    assert "orphaned_route_table" in _rules(findings)


def test_associated_route_table_is_not_orphaned() -> None:
    doc = _doc({
        "Rt": {"Type": "AWS::EC2::RouteTable", "Properties": {}},
        "Assoc": {"Type": "AWS::EC2::SubnetRouteTableAssociation", "Properties": {
            "RouteTableId": {"Ref": "Rt"}, "SubnetId": {"Ref": "Subnet"}}},
        "Subnet": {"Type": "AWS::EC2::Subnet", "Properties": {}},
    })
    findings = netgraph.review(doc, template_file="t.yaml")
    assert "orphaned_route_table" not in _rules(findings)


# ---------------------------------------------------------------------------
# Finding shape and Source contract
# ---------------------------------------------------------------------------


def test_every_finding_is_confirmed_and_valid() -> None:
    doc = _doc({
        "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {}},
        "Igw": {"Type": "AWS::EC2::InternetGateway", "Properties": {}},
        "Rt": {"Type": "AWS::EC2::RouteTable", "Properties": {}},
    })
    findings = netgraph.review(doc, template_file="t.yaml")
    import dataclasses
    assert findings
    for f in findings:
        assert f.Confidence == CONFIRMED
        assert f.Source == ["Network Review"]
        # IDs are assigned by the report after every Source runs; validate a
        # copy with an assigned ID, the way the pipeline does.
        validate(dataclasses.replace(f, ID=1))


def test_empty_template_produces_no_findings() -> None:
    assert netgraph.review(_doc({}), template_file="t.yaml") == []


def test_non_network_template_produces_no_findings() -> None:
    doc = _doc({"Bucket": {"Type": "AWS::S3::Bucket", "Properties": {}}})
    assert netgraph.review(doc, template_file="t.yaml") == []


def test_review_is_deterministic() -> None:
    doc = _doc({
        "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {}},
        "Igw": {"Type": "AWS::EC2::InternetGateway", "Properties": {}},
    })
    first = [f.Finding for f in netgraph.review(doc, template_file="t.yaml")]
    second = [f.Finding for f in netgraph.review(doc, template_file="t.yaml")]
    assert first == second


# ---------------------------------------------------------------------------
# The Source wrapper
# ---------------------------------------------------------------------------


def test_run_and_normalize_returns_a_network_source_result(tmp_path) -> None:
    template = tmp_path / "t.yaml"
    template.write_text(
        "Resources:\n"
        "  Igw:\n"
        "    Type: AWS::EC2::InternetGateway\n"
        "    Properties: {}\n",
        encoding="utf-8",
    )
    result = netgraph.run_and_normalize(str(template), workspace_root=tmp_path)
    assert result.source == "Network Review"
    assert result.errors == []
    assert "igw_not_attached" in _rules(result.findings)
