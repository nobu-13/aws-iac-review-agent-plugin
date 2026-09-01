"""Turn a facts JSON document into a deterministic Agent review prompt.

This is the v0.3.0 bridge between the deterministic ``extract_facts.py`` output
and a reasoning Agent. It performs *no review* and calls *no* language model: it
assembles a structured, bounded prompt string that a host Agent (Kiro, or an
MCP-connected model) reads to produce Agent Findings.

Why a prompt builder rather than a model call
    steering/tech.md keeps MCP and any language model out of the plugin's
    required dependencies, and the development principles separate deterministic
    processing from Agent judgement. This module lives entirely on the
    deterministic side: given the same facts it emits the same prompt, byte for
    byte. The judgement stays with whatever reads the prompt.

What the prompt contains
    The prompt restates, in a fixed order, exactly what ``SKILL.md`` asks the
    Agent to consider:

    1. the review scope (the four concerns Requirement 2 AC14 assigns to Agent
       reasoning) and the boundary it must not cross;
    2. the output contract the validator (:mod:`iacreview.agentin`) enforces,
       so the Agent writes findings that will not be dropped;
    3. the facts themselves, embedded verbatim as JSON;
    4. a checklist of design-level questions derived from the facts, so the
       Agent has concrete leads rather than a blank page. The checklist is the
       part that lifts the detection rate for the concerns no deterministic rule
       can express (network reachability, single-AZ design, unused parameters,
       cross-resource over-permissioning).

Everything is bounded and deterministic
    The facts document is already bounded by ``extract_facts.py``. This module
    adds no unbounded iteration: the checklist is generated from the facts with
    capped enumeration, and the whole prompt is a pure function of its input.

Nothing is executed
    The facts arrive as data. Intrinsic functions are already in long form. No
    value from the template is evaluated, and no network call is made.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Sequence, Tuple

__all__ = [
    "PROMPT_SCHEMA_VERSION",
    "MAX_CHECKLIST_ITEMS",
    "build_prompt",
    "build_checklist",
]

#: The prompt format version. Bumped when the structure changes in a way a
#: downstream consumer would need to know about.
PROMPT_SCHEMA_VERSION = "1.0.0"

#: Upper bound on generated checklist items, so a large template cannot produce
#: an unbounded prompt.
MAX_CHECKLIST_ITEMS = 60

#: The closed category set, restated for the prompt. Kept as a literal rather
#: than imported so the prompt text does not depend on load order; a test
#: asserts it matches ``iacreview/category_map.json``.
CATEGORIES: Tuple[str, ...] = (
    "IAM", "Encryption", "PublicAccess", "Logging", "Tagging", "Availability",
    "Backup", "NetworkSecurity", "DataProtection", "TemplateQuality", "Other",
)

# Resource types that commonly indicate a stateful or availability-sensitive
# resource, used to generate targeted checklist prompts.
_STATEFUL_TYPES = frozenset({
    "AWS::RDS::DBInstance",
    "AWS::RDS::DBCluster",
    "AWS::DynamoDB::Table",
    "AWS::ElastiCache::ReplicationGroup",
    "AWS::Redshift::Cluster",
    "AWS::EFS::FileSystem",
    "AWS::S3::Bucket",
})

_NETWORK_TYPES = frozenset({
    "AWS::EC2::VPC",
    "AWS::EC2::Subnet",
    "AWS::EC2::InternetGateway",
    "AWS::EC2::RouteTable",
    "AWS::EC2::Route",
    "AWS::EC2::NatGateway",
    "AWS::EC2::VPCGatewayAttachment",
})

_COMPUTE_TYPES = frozenset({
    "AWS::EC2::Instance",
    "AWS::Lambda::Function",
    "AWS::AutoScaling::AutoScalingGroup",
    "AWS::ECS::Service",
})


def _resource_index(facts: Dict[str, Any]) -> List[Tuple[str, str]]:
    """``(logical_id, type)`` pairs from the facts, in facts order."""
    out: List[Tuple[str, str]] = []
    for resource in facts.get("resources", []):
        if not isinstance(resource, dict):
            continue
        logical_id = resource.get("logical_id")
        rtype = resource.get("type")
        if isinstance(logical_id, str) and isinstance(rtype, str):
            out.append((logical_id, rtype))
    return out


def _referenced_ids(facts: Dict[str, Any]) -> set:
    """Every logical id that appears as the target of a reference edge."""
    referenced = set()
    for edge in facts.get("references", []):
        if isinstance(edge, dict):
            target = edge.get("to")
            if isinstance(target, str):
                referenced.add(target)
    return referenced


def build_checklist(facts: Dict[str, Any]) -> List[str]:
    """Design-level questions derived from the facts.

    Each item is a concrete lead for one of the concerns the Agent owns:
    cross-resource relationships, architectural risk, contextual severity, and
    best practice. The list is deterministic (facts order, capped) and never
    asserts a defect; it only points the Agent at something to examine.
    """
    items: List[str] = []
    resources = _resource_index(facts)
    types_present = {rtype for _, rtype in resources}
    referenced = _referenced_ids(facts)

    # Network reachability: if there is a VPC, is the path to the internet complete?
    if "AWS::EC2::VPC" in types_present:
        if "AWS::EC2::InternetGateway" in types_present and \
           "AWS::EC2::VPCGatewayAttachment" not in types_present:
            items.append(
                "An Internet Gateway is declared but no VPCGatewayAttachment is "
                "present. Check whether the gateway is actually attached to the VPC."
            )
        if "AWS::EC2::RouteTable" in types_present and \
           "AWS::EC2::Route" not in types_present:
            items.append(
                "A route table is declared but no Route resource. Check whether "
                "a default route (0.0.0.0/0) to the internet is missing."
            )

    # Single point of failure for stateful resources.
    for logical_id, rtype in resources:
        if rtype in _STATEFUL_TYPES and len(items) < MAX_CHECKLIST_ITEMS:
            items.append(
                "{0} ({1}) is a stateful resource. Assess whether it is placed "
                "in a single Availability Zone or otherwise a single point of "
                "failure in this template's design.".format(logical_id, rtype)
            )

    # Compute without an obvious execution role or in a single AZ.
    for logical_id, rtype in resources:
        if rtype in _COMPUTE_TYPES and len(items) < MAX_CHECKLIST_ITEMS:
            items.append(
                "{0} ({1}): assess whether its permissions and placement match "
                "its stated purpose, and whether any dependency it needs is "
                "missing from the template.".format(logical_id, rtype)
            )

    # Unused parameters.
    for parameter in facts.get("parameters", []):
        if not isinstance(parameter, dict):
            continue
        if len(items) >= MAX_CHECKLIST_ITEMS:
            break
        name = parameter.get("name")
        referenced_by = parameter.get("referenced_by")
        if isinstance(name, str) and isinstance(referenced_by, list) and not referenced_by:
            items.append(
                "Parameter {0} is not referenced by any resource. Confirm "
                "whether it is dead configuration or wired in a way the "
                "reference graph did not capture.".format(name)
            )

    # Conditions: check their intent matches their name.
    for condition in facts.get("conditions", []):
        if not isinstance(condition, dict):
            continue
        if len(items) >= MAX_CHECKLIST_ITEMS:
            break
        name = condition.get("name")
        if isinstance(name, str):
            items.append(
                "Condition {0}: check that its logic matches its name, and that "
                "it is actually used where the design intends.".format(name)
            )

    # Orphaned resources (declared but never referenced).
    for logical_id, rtype in resources:
        if len(items) >= MAX_CHECKLIST_ITEMS:
            break
        if logical_id not in referenced and rtype not in _NETWORK_TYPES:
            # A resource nothing references may be intentional (a top-level
            # bucket) or an orphan; the Agent decides.
            pass  # Too noisy to enumerate all; covered by the resource walk above.

    return items[:MAX_CHECKLIST_ITEMS]


def _scope_section() -> str:
    return (
        "# CloudFormation Design Review\n\n"
        "You are reviewing the DESIGN of a CloudFormation template. Reason only "
        "about these four concerns:\n\n"
        "1. Cross-resource relationships: risks that exist only in the relation "
        "between two or more resources.\n"
        "2. Architectural risk: single points of failure, single-AZ placement, "
        "missing redundancy, deployment ordering.\n"
        "3. Contextual severity: how much a condition matters in THIS template.\n"
        "4. Best-practice reasoning: AWS recommendations not encoded as a rule.\n\n"
        "Do NOT review syntax, resource property types, intrinsic functions, or "
        "deployability (cfn-lint owns these). Do NOT review organizational "
        "policy such as mandatory encryption, logging, tagging or backup "
        "(cfn-guard owns these). Do NOT perform IAM policy risk analysis "
        "(iam-review owns this). Never restate anything already listed in "
        "deterministic_findings_summary.\n"
    )


def _output_contract_section() -> str:
    return (
        "## Output contract\n\n"
        "Produce a JSON array of finding objects. Each finding MUST satisfy:\n\n"
        "- Confidence is \"Likely\" or \"Contextual\" (never \"Confirmed\").\n"
        "- Source is exactly [\"Agent Review\"].\n"
        "- Every Evidence entry has Source \"Agent Review\" and a non-empty "
        "Excerpt quoting the template content the conclusion rests on.\n"
        "- Finding text is phrased as a potential risk (\"may\", \"appears to\"), "
        "never an assertion that a vulnerability exists.\n"
        "- Normalized_Category is one of: " + ", ".join(CATEGORIES) + ".\n"
        "- FindingType is one of: Validity, Security, BestPractice, Informational.\n"
        "- Severity is one of: CRITICAL, HIGH, MEDIUM, LOW, INFO.\n"
        "- Location.File is the workspace-relative template path; "
        "Location.TemplatePath is the path to the property in question.\n\n"
        "Findings that fail these rules are dropped by the validator "
        "(iacreview/agentin.py).\n"
    )


def build_prompt(facts: Dict[str, Any]) -> str:
    """Assemble the full review prompt for one facts document.

    Args:
        facts: The parsed output of ``extract_facts.py``.

    Returns:
        A deterministic prompt string. The same facts always produce the same
        string.
    """
    target = facts.get("target", {})
    template_file = target.get("file", "the template") if isinstance(target, dict) else "the template"

    checklist = build_checklist(facts)
    checklist_text = (
        "## Leads to examine\n\n"
        + "\n".join("- {0}".format(item) for item in checklist)
        + "\n"
    ) if checklist else ""

    facts_json = json.dumps(facts, indent=2, sort_keys=True, ensure_ascii=False)

    return (
        _scope_section()
        + "\n"
        + _output_contract_section()
        + "\n"
        + "## Template facts for {0}\n\n".format(template_file)
        + "```json\n"
        + facts_json
        + "\n```\n\n"
        + checklist_text
    )
