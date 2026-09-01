"""Tests for the Agent review prompt builder (:mod:`iacreview.agentprompt`).

The prompt builder is the v0.3.0 bridge from deterministic facts to Agent
reasoning. It calls no model and makes no network request, so what these tests
lock is:

* determinism: the same facts produce byte-identical prompts and checklists;
* boundedness: the checklist is capped regardless of template size;
* the output contract text names the closed category set and the confidence
  rules the validator enforces;
* the checklist surfaces the design-level leads (network reachability,
  single-AZ stateful resources, unused parameters, condition intent) that no
  deterministic rule expresses;
* the closed category list stays in step with ``iacreview/category_map.json``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import pytest

from iacreview import agentprompt, categories


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _facts(**overrides: Any) -> Dict[str, Any]:
    """A minimal well-formed facts document, with overrides."""
    base: Dict[str, Any] = {
        "schema_version": "1.0.0",
        "target": {"file": "templates/app.yaml"},
        "parameters": [],
        "conditions": [],
        "resources": [],
        "references": [],
        "depends_on": [],
        "deterministic_reports": [],
        "deterministic_sources": [],
        "deterministic_findings_summary": [],
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_prompt_is_deterministic() -> None:
    """The same facts produce byte-identical prompts."""
    facts = _facts(
        resources=[
            {"logical_id": "Db", "type": "AWS::RDS::DBInstance"},
            {"logical_id": "Fn", "type": "AWS::Lambda::Function"},
        ]
    )
    assert agentprompt.build_prompt(facts) == agentprompt.build_prompt(facts)


def test_checklist_is_deterministic() -> None:
    facts = _facts(
        resources=[{"logical_id": "Db", "type": "AWS::RDS::DBInstance"}]
    )
    assert agentprompt.build_checklist(facts) == agentprompt.build_checklist(facts)


# ---------------------------------------------------------------------------
# Boundedness
# ---------------------------------------------------------------------------


def test_checklist_is_capped() -> None:
    """A huge template cannot produce an unbounded checklist."""
    resources = [
        {"logical_id": "Db{0}".format(i), "type": "AWS::RDS::DBInstance"}
        for i in range(500)
    ]
    facts = _facts(resources=resources)
    checklist = agentprompt.build_checklist(facts)
    assert len(checklist) <= agentprompt.MAX_CHECKLIST_ITEMS


# ---------------------------------------------------------------------------
# Output contract text
# ---------------------------------------------------------------------------


def test_prompt_names_every_closed_category() -> None:
    """The prompt lists the category set the validator will accept."""
    prompt = agentprompt.build_prompt(_facts())
    for category in agentprompt.CATEGORIES:
        assert category in prompt


def test_closed_categories_match_the_mapping_file() -> None:
    """The prompt's category list is the one the code enforces.

    Read from ``category_map.json`` rather than trusted as a literal, so the two
    cannot drift.
    """
    cmap = categories.load_map()
    assert set(agentprompt.CATEGORIES) == set(cmap.categories)


def test_prompt_states_confidence_rule() -> None:
    """The prompt tells the Agent Confirmed is closed to it."""
    prompt = agentprompt.build_prompt(_facts())
    assert "Confirmed" in prompt
    assert "Likely" in prompt and "Contextual" in prompt


def test_prompt_states_the_boundary() -> None:
    """The prompt tells the Agent what the deterministic sources own."""
    prompt = agentprompt.build_prompt(_facts())
    assert "cfn-lint" in prompt
    assert "cfn-guard" in prompt
    assert "iam-review" in prompt


def test_prompt_embeds_the_facts() -> None:
    """The facts are present verbatim so the Agent reasons over them."""
    facts = _facts(resources=[{"logical_id": "MyBucket", "type": "AWS::S3::Bucket"}])
    prompt = agentprompt.build_prompt(facts)
    assert "MyBucket" in prompt
    assert "AWS::S3::Bucket" in prompt


# ---------------------------------------------------------------------------
# Checklist leads
# ---------------------------------------------------------------------------


def test_checklist_flags_unattached_internet_gateway() -> None:
    facts = _facts(
        resources=[
            {"logical_id": "Vpc", "type": "AWS::EC2::VPC"},
            {"logical_id": "Igw", "type": "AWS::EC2::InternetGateway"},
        ]
    )
    checklist = agentprompt.build_checklist(facts)
    assert any("VPCGatewayAttachment" in item for item in checklist)


def test_checklist_does_not_flag_attached_internet_gateway() -> None:
    facts = _facts(
        resources=[
            {"logical_id": "Vpc", "type": "AWS::EC2::VPC"},
            {"logical_id": "Igw", "type": "AWS::EC2::InternetGateway"},
            {"logical_id": "Att", "type": "AWS::EC2::VPCGatewayAttachment"},
        ]
    )
    checklist = agentprompt.build_checklist(facts)
    assert not any("VPCGatewayAttachment" in item for item in checklist)


def test_checklist_flags_missing_default_route() -> None:
    facts = _facts(
        resources=[
            {"logical_id": "Vpc", "type": "AWS::EC2::VPC"},
            {"logical_id": "Rt", "type": "AWS::EC2::RouteTable"},
        ]
    )
    checklist = agentprompt.build_checklist(facts)
    assert any("default route" in item for item in checklist)


def test_checklist_flags_stateful_single_point_of_failure() -> None:
    facts = _facts(
        resources=[{"logical_id": "Db", "type": "AWS::RDS::DBInstance"}]
    )
    checklist = agentprompt.build_checklist(facts)
    assert any("single point of failure" in item and "Db" in item for item in checklist)


def test_checklist_flags_unused_parameter() -> None:
    facts = _facts(
        parameters=[{"name": "Unused", "referenced_by": []}]
    )
    checklist = agentprompt.build_checklist(facts)
    assert any("Unused" in item and "not referenced" in item for item in checklist)


def test_checklist_does_not_flag_used_parameter() -> None:
    facts = _facts(
        parameters=[{"name": "InUse", "referenced_by": ["SomeResource"]}]
    )
    checklist = agentprompt.build_checklist(facts)
    assert not any("InUse" in item and "not referenced" in item for item in checklist)


def test_checklist_flags_condition_intent() -> None:
    facts = _facts(
        conditions=[{"name": "IsProd", "definition": {}}]
    )
    checklist = agentprompt.build_checklist(facts)
    assert any("IsProd" in item and "logic matches its name" in item for item in checklist)


# ---------------------------------------------------------------------------
# Robustness against malformed facts
# ---------------------------------------------------------------------------


def test_checklist_tolerates_missing_sections() -> None:
    """A facts doc missing optional sections does not crash the builder."""
    assert agentprompt.build_checklist({}) == []


def test_prompt_tolerates_missing_target() -> None:
    prompt = agentprompt.build_prompt({"resources": []})
    assert "the template" in prompt


def test_checklist_ignores_malformed_resource_entries() -> None:
    facts = _facts(resources=["not a dict", {"logical_id": "Ok", "type": "AWS::RDS::DBInstance"}])
    checklist = agentprompt.build_checklist(facts)
    assert any("Ok" in item for item in checklist)


def test_checklist_reads_the_reference_graph() -> None:
    """A referenced resource is treated as wired, not orphaned.

    Exercises the reference-edge walk: an edge with a string ``to`` marks its
    target as referenced.
    """
    facts = _facts(
        resources=[{"logical_id": "Bucket", "type": "AWS::S3::Bucket"}],
        references=[{"from": "Policy", "to": "Bucket", "kind": "Ref"}],
    )
    # The reference walk runs without error and the stateful lead still appears.
    checklist = agentprompt.build_checklist(facts)
    assert any("Bucket" in item for item in checklist)


def test_checklist_ignores_malformed_reference_edges() -> None:
    """A non-dict edge, or one whose ``to`` is not a string, is skipped."""
    facts = _facts(
        resources=[{"logical_id": "Db", "type": "AWS::RDS::DBInstance"}],
        references=["not a dict", {"to": 123}, {"from": "X"}],
    )
    checklist = agentprompt.build_checklist(facts)
    assert any("Db" in item for item in checklist)


def test_parameter_cap_is_respected() -> None:
    """The parameter walk stops once the checklist is full.

    Fills the checklist with stateful resources, then adds many unused
    parameters; the total must still not exceed the cap.
    """
    resources = [
        {"logical_id": "Db{0}".format(i), "type": "AWS::RDS::DBInstance"}
        for i in range(agentprompt.MAX_CHECKLIST_ITEMS + 10)
    ]
    parameters = [
        {"name": "P{0}".format(i), "referenced_by": []} for i in range(20)
    ]
    facts = _facts(resources=resources, parameters=parameters)
    assert len(agentprompt.build_checklist(facts)) <= agentprompt.MAX_CHECKLIST_ITEMS


def test_condition_cap_is_respected() -> None:
    """The condition walk stops once the checklist is full."""
    resources = [
        {"logical_id": "Db{0}".format(i), "type": "AWS::RDS::DBInstance"}
        for i in range(agentprompt.MAX_CHECKLIST_ITEMS + 10)
    ]
    conditions = [{"name": "C{0}".format(i)} for i in range(20)]
    facts = _facts(resources=resources, conditions=conditions)
    assert len(agentprompt.build_checklist(facts)) <= agentprompt.MAX_CHECKLIST_ITEMS
