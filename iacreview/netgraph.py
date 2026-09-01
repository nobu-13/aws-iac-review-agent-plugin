"""Deterministic network-design review over the resource relationship graph.

This is the v0.4.0 fourth deterministic Source. Where cfn-guard checks one
resource's properties in isolation, this module reasons about the *relations*
between resources: whether an Internet Gateway is attached to a VPC, whether a
public route table has a default route, whether a resource is reachable at all.
Those are facts a single-resource rule cannot express, and they were previously
left to Agent reasoning. Because they are decidable from the parsed template
alone, they belong on the deterministic side, and every Finding here carries
``Confidence: Confirmed``.

What it does NOT do
    It does not resolve intrinsic functions beyond the long forms
    :mod:`iacreview.yamlcfn` already produced, does not connect to AWS, and does
    not evaluate anything. A reference to a resource is read as an edge; a
    reference to a pseudo-parameter or an unresolved value is simply not an edge
    to a resource in this template, and the checks account for that rather than
    guessing.

Determinism
    Resources are walked in template order, edges are collected in a stable
    order, and findings are produced in a fixed detector order. The same
    template always yields the same findings.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple

from iacreview.source import SourceResult
from iacreview.template import LoadedTemplate
from iacreview.source import workspace_relative
from iacreview.finding import (
    CONFIRMED,
    UNASSIGNED_ID,
    Evidence,
    Finding,
    Location,
    sorted_sources,
)

__all__ = [
    "SOURCE_NAME",
    "DETECTORS",
    "review",
    "run_and_normalize",
    "build_graph",
    "ResourceGraph",
]

#: The Source name this module produces. Must be in ``iacreview.finding.SOURCES``.
SOURCE_NAME = "Network Review"

# Resource types this module reasons about.
_TYPE_VPC = "AWS::EC2::VPC"
_TYPE_SUBNET = "AWS::EC2::Subnet"
_TYPE_IGW = "AWS::EC2::InternetGateway"
_TYPE_IGW_ATTACHMENT = "AWS::EC2::VPCGatewayAttachment"
_TYPE_ROUTE_TABLE = "AWS::EC2::RouteTable"
_TYPE_ROUTE = "AWS::EC2::Route"
_TYPE_NAT_GATEWAY = "AWS::EC2::NatGateway"
_TYPE_RDS = "AWS::RDS::DBInstance"
_TYPE_SUBNET_ROUTE_ASSOC = "AWS::EC2::SubnetRouteTableAssociation"


class ResourceGraph:
    """The resources of one template and the reference edges between them.

    Attributes:
        resources: ``logical_id -> {"Type": str, "Properties": dict}``, in
            template order.
        edges: ``(from_id, to_id)`` pairs, one per Ref/GetAtt to another
            resource in this template. Deduplicated, in first-seen order.
    """

    def __init__(
        self,
        resources: Dict[str, Dict[str, Any]],
        edges: List[Tuple[str, str]],
    ) -> None:
        self.resources = resources
        self.edges = edges
        self._by_type: Dict[str, List[str]] = {}
        for logical_id, body in resources.items():
            rtype = body.get("Type")
            if isinstance(rtype, str):
                self._by_type.setdefault(rtype, []).append(logical_id)
        self._targets_from: Dict[str, set] = {}
        for source, target in edges:
            self._targets_from.setdefault(source, set()).add(target)

    def of_type(self, rtype: str) -> List[str]:
        """Logical ids of resources of ``rtype``, in template order."""
        return list(self._by_type.get(rtype, []))

    def properties(self, logical_id: str) -> Dict[str, Any]:
        """The Properties block of a resource, or an empty dict."""
        body = self.resources.get(logical_id, {})
        props = body.get("Properties")
        return props if isinstance(props, dict) else {}

    def references_from(self, logical_id: str) -> set:
        """Logical ids ``logical_id`` refers to via Ref/GetAtt."""
        return set(self._targets_from.get(logical_id, set()))

    def references_to(self, logical_id: str) -> List[str]:
        """Logical ids that refer to ``logical_id``."""
        return [source for source, target in self.edges if target == logical_id]


def _iter_refs(value: Any) -> List[str]:
    """Every logical id a value refers to via long-form Ref or Fn::GetAtt.

    Reads the long forms :mod:`iacreview.yamlcfn` produces. A ``Ref`` to a
    pseudo-parameter (``AWS::Region`` and the like) is not a resource reference
    and is skipped.
    """
    out: List[str] = []
    if isinstance(value, dict):
        for key, inner in value.items():
            if key == "Ref" and isinstance(inner, str):
                if not inner.startswith("AWS::"):
                    out.append(inner)
            elif key == "Fn::GetAtt":
                target = _getatt_target(inner)
                if target is not None:
                    out.append(target)
            else:
                out.extend(_iter_refs(inner))
    elif isinstance(value, list):
        for item in value:
            out.extend(_iter_refs(item))
    return out


def _getatt_target(value: Any) -> Optional[str]:
    """The logical id named by an ``Fn::GetAtt`` argument."""
    if isinstance(value, str):
        return value.split(".", 1)[0] or None
    if isinstance(value, list) and value and isinstance(value[0], str):
        return value[0]
    return None


def build_graph(doc: Any) -> ResourceGraph:
    """Build the resource graph from a parsed template document."""
    resources: Dict[str, Dict[str, Any]] = {}
    section = doc.get("Resources") if isinstance(doc, dict) else None
    if isinstance(section, dict):
        for logical_id, body in section.items():
            if isinstance(logical_id, str) and isinstance(body, dict):
                resources[logical_id] = body

    edges: List[Tuple[str, str]] = []
    seen = set()
    for logical_id, body in resources.items():
        for target in _iter_refs(body.get("Properties")):
            if target in resources and target != logical_id:
                edge = (logical_id, target)
                if edge not in seen:
                    seen.add(edge)
                    edges.append(edge)
        # DependsOn is a relationship too.
        depends = body.get("DependsOn")
        depends_ids = (
            [depends] if isinstance(depends, str)
            else depends if isinstance(depends, list)
            else []
        )
        for target in depends_ids:
            if isinstance(target, str) and target in resources and target != logical_id:
                edge = (logical_id, target)
                if edge not in seen:
                    seen.add(edge)
                    edges.append(edge)

    return ResourceGraph(resources, edges)


def _finding(
    *,
    logical_id: Optional[str],
    template_file: str,
    severity: str,
    category: str,
    finding_type: str,
    rule: str,
    text: str,
    why: str,
    recommendation: str,
    excerpt: str,
) -> Finding:
    """Build one Confirmed Network Review Finding."""
    return Finding(
        ID=UNASSIGNED_ID,
        Normalized_Category=category,
        FindingType=finding_type,
        Severity=severity,
        Confidence=CONFIRMED,
        Source=sorted_sources([SOURCE_NAME]),
        Resource=logical_id,
        Location=Location(
            File=template_file,
            Line=None,
            Column=None,
            TemplatePath=["Resources", logical_id] if logical_id else ["Resources"],
        ),
        Finding="[{0}] {1}".format(rule, text),
        WhyItMatters=why,
        Evidence=[
            Evidence(
                Source=SOURCE_NAME,
                Detail="Network Review rule {0}".format(rule),
                RuleId=rule,
                Excerpt=excerpt,
            )
        ],
        Recommendation=recommendation,
        SuggestedRemediation=None,
    )


# ---------------------------------------------------------------------------
# Detectors: each takes (graph, template_file) and returns a list of Findings.
# ---------------------------------------------------------------------------


def detect_igw_not_attached(graph: ResourceGraph, template_file: str) -> List[Finding]:
    """An Internet Gateway with no VPCGatewayAttachment referencing it."""
    findings: List[Finding] = []
    attachments = graph.of_type(_TYPE_IGW_ATTACHMENT)
    attached_igws = set()
    for attachment in attachments:
        attached_igws.update(graph.references_from(attachment))
    for igw in graph.of_type(_TYPE_IGW):
        if igw not in attached_igws:
            findings.append(_finding(
                logical_id=igw, template_file=template_file,
                severity="HIGH", category="NetworkSecurity", finding_type="Security",
                rule="igw_not_attached",
                text=(
                    "This Internet Gateway is not referenced by any "
                    "VPCGatewayAttachment, so it appears not to be attached to a VPC."
                ),
                why=(
                    "An unattached Internet Gateway gives its intended public "
                    "subnet no path to the internet, so public resources are "
                    "unreachable."
                ),
                recommendation=(
                    "Add an AWS::EC2::VPCGatewayAttachment that references this "
                    "gateway and the VPC."
                ),
                excerpt="{0}:\n  Type: {1}".format(igw, _TYPE_IGW),
            ))
    return findings


def detect_route_table_without_default_route(
    graph: ResourceGraph, template_file: str
) -> List[Finding]:
    """A route table with no AWS::EC2::Route creating a 0.0.0.0/0 route.

    Only fires when the template contains at least one Internet Gateway, so a
    deliberately private route table is not flagged.
    """
    findings: List[Finding] = []
    if not graph.of_type(_TYPE_IGW):
        return findings

    # Route tables that some Route resource targets with a default destination.
    tables_with_default_route = set()
    for route in graph.of_type(_TYPE_ROUTE):
        props = graph.properties(route)
        destination = props.get("DestinationCidrBlock")
        if destination == "0.0.0.0/0" or destination == "::/0":
            tables_with_default_route.update(graph.references_from(route))

    for table in graph.of_type(_TYPE_ROUTE_TABLE):
        if table not in tables_with_default_route:
            findings.append(_finding(
                logical_id=table, template_file=template_file,
                severity="MEDIUM", category="NetworkSecurity", finding_type="Security",
                rule="route_table_no_default_route",
                text=(
                    "This route table has no AWS::EC2::Route creating a default "
                    "(0.0.0.0/0) route, and the template declares an Internet "
                    "Gateway. A subnet using this table may have no path to the "
                    "internet."
                ),
                why=(
                    "Without a default route to the gateway, instances in the "
                    "associated subnet cannot reach or be reached from the internet."
                ),
                recommendation=(
                    "Add an AWS::EC2::Route with DestinationCidrBlock 0.0.0.0/0 "
                    "targeting the Internet Gateway (or a NAT Gateway for a "
                    "private subnet)."
                ),
                excerpt="{0}:\n  Type: {1}".format(table, _TYPE_ROUTE_TABLE),
            ))
    return findings


def detect_rds_public_subnet_exposure(
    graph: ResourceGraph, template_file: str
) -> List[Finding]:
    """An RDS instance that requests a public endpoint AND sits behind an IGW.

    This is a relationship the single-resource ``rds_publicly_accessible`` rule
    cannot see: it combines the instance's own flag with the presence of an
    internet path in the template.
    """
    findings: List[Finding] = []
    if not graph.of_type(_TYPE_IGW):
        return findings
    for rds in graph.of_type(_TYPE_RDS):
        props = graph.properties(rds)
        if props.get("PubliclyAccessible") is True:
            findings.append(_finding(
                logical_id=rds, template_file=template_file,
                severity="HIGH", category="NetworkSecurity", finding_type="Security",
                rule="rds_reachable_from_internet",
                text=(
                    "This RDS instance sets PubliclyAccessible: true and the "
                    "template declares an Internet Gateway, so the database may "
                    "be reachable from the internet by design."
                ),
                why=(
                    "A database with a public endpoint in a template that wires "
                    "an internet path is exposed to the entire internet, not "
                    "just the application tier."
                ),
                recommendation=(
                    "Set PubliclyAccessible to false and place the instance in a "
                    "private subnet reachable only from the application security "
                    "group."
                ),
                excerpt="{0}:\n  Properties:\n    PubliclyAccessible: true".format(rds),
            ))
    return findings


def detect_orphaned_network_resource(
    graph: ResourceGraph, template_file: str
) -> List[Finding]:
    """A subnet or route table that nothing references and that references no VPC.

    An orphaned network resource is usually a wiring mistake: a subnet that is
    never associated with a route table, or a route table nothing uses.
    """
    findings: List[Finding] = []
    # Subnet route table associations tell us which subnets/tables are wired.
    associations = graph.of_type(_TYPE_SUBNET_ROUTE_ASSOC)
    associated: set = set()
    for assoc in associations:
        associated.update(graph.references_from(assoc))

    for table in graph.of_type(_TYPE_ROUTE_TABLE):
        # A route table is used if a SubnetRouteTableAssociation references it
        # or a Route references it.
        referenced_by = set(graph.references_to(table))
        if table not in associated and not referenced_by:
            findings.append(_finding(
                logical_id=table, template_file=template_file,
                severity="LOW", category="NetworkSecurity", finding_type="BestPractice",
                rule="orphaned_route_table",
                text=(
                    "This route table is not associated with any subnet and no "
                    "route references it. It may be dead configuration."
                ),
                why=(
                    "An unused route table adds confusion about the intended "
                    "network topology and may indicate a missing association."
                ),
                recommendation=(
                    "Associate the route table with a subnet via "
                    "AWS::EC2::SubnetRouteTableAssociation, or remove it."
                ),
                excerpt="{0}:\n  Type: {1}".format(table, _TYPE_ROUTE_TABLE),
            ))
    return findings


#: The detectors, in the fixed order their findings are produced.
DETECTORS = (
    detect_igw_not_attached,
    detect_route_table_without_default_route,
    detect_rds_public_subnet_exposure,
    detect_orphaned_network_resource,
)


def review(doc: Any, *, template_file: str) -> List[Finding]:
    """Run every network detector over a parsed template.

    Args:
        doc: The parsed template document (from
            :func:`iacreview.template.load_template`).
        template_file: Workspace-relative path for ``Location.File``.

    Returns:
        Findings in detector order, all ``Confidence: Confirmed``. Empty when
        the template declares no network resources this module reasons about.
    """
    graph = build_graph(doc)
    findings: List[Finding] = []
    for detector in DETECTORS:
        findings.extend(detector(graph, template_file))
    return findings


def run_and_normalize(
    template_path: "Any",
    *,
    workspace_root: "Any" = None,
    loaded: "Optional[LoadedTemplate]" = None,
) -> SourceResult:
    """Run the network review as a Source, returning a :class:`SourceResult`.

    Mirrors the signature of the other deterministic Sources so the
    orchestration loop can bind and call it uniformly. Like the IAM Source, it
    reads the parsed template directly rather than shelling out, so it accepts
    an already-parsed ``loaded`` template to avoid parsing twice.

    Args:
        template_path: The template path (workspace-relative or absolute).
        workspace_root: The workspace root, used to render the path for
            ``Location.File``. Defaults to the current directory.
        loaded: An already-parsed template. Parsed here if not supplied.

    Returns:
        A ``SourceResult`` with ``source == "Network Review"``. Findings are all
        ``Confidence: Confirmed``; the network review has no external tool, so it
        produces no tool errors.
    """
    from pathlib import Path
    from iacreview.template import load_template

    root = Path(workspace_root) if workspace_root is not None else Path.cwd()
    path_obj = Path(template_path)
    if loaded is None:
        loaded = load_template(path_obj)

    template_file = workspace_relative(str(path_obj), root) or path_obj.name
    findings = review(loaded.doc, template_file=template_file)
    return SourceResult(source=SOURCE_NAME, findings=findings, errors=[], stats={})
