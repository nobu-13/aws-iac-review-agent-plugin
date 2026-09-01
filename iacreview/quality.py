"""Deterministic template-quality and logic review.

This is the v0.6.0 sixth deterministic Source, "Quality Review". It reasons
about the *structure* of a template -- its Conditions, Parameters, and the
dependency graph -- to find logic mistakes and dead configuration that no
single-resource rule and no cfn-lint check reliably reports:

* a Condition whose comparison value disagrees with its name (an ``IsProduction``
  that tests for ``staging``);
* a Parameter that nothing references (dead configuration);
* a Condition that nothing uses;
* a circular ``DependsOn`` dependency;
* an ``AllowedValues`` list that mixes types.

These are exactly the concerns v0.3.0 left to Agent reasoning. They are
decidable from the parsed template, so they belong on the deterministic side,
and every finding here is ``Confidence: Confirmed``.

What it does NOT do
    It does not resolve intrinsic functions, connect to AWS, or evaluate
    anything. It reads the parsed document as data. It deliberately does not
    re-implement cfn-lint's syntax and property checks; a Condition-logic
    heuristic is a judgement about naming, not a syntax rule.

Determinism
    Conditions, Parameters and resources are walked in template order, and
    findings are produced in a fixed detector order. The same template always
    yields the same findings.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from iacreview import netgraph
from iacreview.finding import (
    CONFIRMED,
    UNASSIGNED_ID,
    Evidence,
    Finding,
    Location,
    sorted_sources,
)
from iacreview.source import SourceResult, workspace_relative
from iacreview.template import LoadedTemplate

__all__ = [
    "SOURCE_NAME",
    "DETECTORS",
    "review",
    "run_and_normalize",
]

#: The Source name. Must be in ``iacreview.finding.SOURCES``.
SOURCE_NAME = "Quality Review"

# Names that assert a specific environment, mapped to the value a correctly
# written condition of that name compares against. Used only to flag a
# disagreement, never to rewrite; a mismatch is reported as something to check.
_ENVIRONMENT_NAME_HINTS: Tuple[Tuple[re.Pattern, str], ...] = (
    (re.compile(r"(?i)is[_-]?prod(uction)?\b"), "prod"),
    (re.compile(r"(?i)is[_-]?stag(ing|e)?\b"), "stag"),
    (re.compile(r"(?i)is[_-]?dev(elopment)?\b"), "dev"),
    (re.compile(r"(?i)is[_-]?test\b"), "test"),
)


def _section(doc: Any, name: str) -> Dict[str, Any]:
    section = doc.get(name) if isinstance(doc, dict) else None
    return section if isinstance(section, dict) else {}


def _equals_literal(definition: Any) -> Optional[str]:
    """The literal string an ``Fn::Equals`` condition compares against.

    Returns the literal (non-intrinsic) operand of a two-operand ``Fn::Equals``,
    or ``None`` when the definition is not a simple ``Fn::Equals`` or has no
    literal operand. A ``{"Ref": ...}`` operand is not a literal.
    """
    if not isinstance(definition, dict):
        return None
    equals = definition.get("Fn::Equals")
    if not isinstance(equals, list) or len(equals) != 2:
        return None
    for operand in equals:
        if isinstance(operand, str):
            return operand
    return None


def _condition_names_used(doc: Any) -> set:
    """Every condition name referenced by a resource, another condition, or Fn::If.

    A condition is used when a resource carries it as its top-level
    ``Condition``, when an ``Fn::If`` names it, or when another condition
    references it through ``Condition``/``Fn::And``/``Fn::Or``/``Fn::Not``.
    """
    used: set = set()

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for key, inner in value.items():
                if key == "Fn::If" and isinstance(inner, list) and inner:
                    if isinstance(inner[0], str):
                        used.add(inner[0])
                    for item in inner[1:]:
                        walk(item)
                elif key == "Condition" and isinstance(inner, str):
                    used.add(inner)
                else:
                    walk(inner)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    # Resource-level Condition keys and every property tree.
    for _, body in _section(doc, "Resources").items():
        if isinstance(body, dict):
            cond = body.get("Condition")
            if isinstance(cond, str):
                used.add(cond)
            walk(body.get("Properties"))
    # Conditions can reference other conditions.
    walk(_section(doc, "Conditions"))
    # Outputs can be gated on a condition.
    walk(_section(doc, "Outputs"))
    return used


def _finding(
    *,
    logical_id: Optional[str],
    template_file: str,
    template_path: List[str],
    rule: str,
    severity: str,
    finding_type: str,
    text: str,
    why: str,
    recommendation: str,
    excerpt: str,
) -> Finding:
    """One Confirmed Quality Review finding."""
    return Finding(
        ID=UNASSIGNED_ID,
        Normalized_Category="TemplateQuality",
        FindingType=finding_type,
        Severity=severity,
        Confidence=CONFIRMED,
        Source=sorted_sources([SOURCE_NAME]),
        Resource=logical_id,
        Location=Location(
            File=template_file, Line=None, Column=None, TemplatePath=template_path
        ),
        Finding="[{0}] {1}".format(rule, text),
        WhyItMatters=why,
        Evidence=[
            Evidence(
                Source=SOURCE_NAME,
                Detail="Quality Review rule {0}".format(rule),
                RuleId=rule,
                Excerpt=excerpt,
            )
        ],
        Recommendation=recommendation,
        SuggestedRemediation=None,
    )


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------


def detect_condition_name_logic_mismatch(doc: Any, template_file: str) -> List[Finding]:
    """A Condition whose name asserts an environment its test contradicts.

    Reports, for example, a Condition named ``IsProduction`` defined as
    ``Fn::Equals [EnvironmentType, "staging"]``: the name says production, the
    literal says staging. Only fires when the name matches a known environment
    hint and the compared literal names a *different* environment, so a
    condition named neutrally is never flagged.
    """
    findings: List[Finding] = []
    for name, definition in _section(doc, "Conditions").items():
        if not isinstance(name, str):
            continue
        literal = _equals_literal(definition)
        if literal is None:
            continue
        literal_lower = literal.lower()
        for pattern, expected_fragment in _ENVIRONMENT_NAME_HINTS:
            if not pattern.search(name):
                continue
            # The name asserts `expected_fragment`. If the literal names a
            # *different* known environment, that is the contradiction.
            other_fragments = [
                frag for _, frag in _ENVIRONMENT_NAME_HINTS if frag != expected_fragment
            ]
            names_other = any(frag in literal_lower for frag in other_fragments)
            names_expected = expected_fragment in literal_lower
            if names_other and not names_expected:
                findings.append(_finding(
                    logical_id=None, template_file=template_file,
                    template_path=["Conditions", name],
                    rule="condition_name_logic_mismatch",
                    severity="MEDIUM", finding_type="BestPractice",
                    text=(
                        "Condition {0} tests for the literal {1!r}, which does "
                        "not match what its name asserts. The name and the logic "
                        "appear to disagree.".format(name, literal)
                    ),
                    why=(
                        "A resource gated on this condition applies the wrong "
                        "branch to each environment, a defect that only surfaces "
                        "in the environment the name misdescribes."
                    ),
                    recommendation=(
                        "Change the compared value to match the name, or rename "
                        "the condition to describe what it actually tests."
                    ),
                    excerpt="{0}: {1}".format(name, literal),
                ))
            break
    return findings


def detect_unused_parameter(doc: Any, template_file: str) -> List[Finding]:
    """A Parameter no resource, condition, or output references."""
    findings: List[Finding] = []
    parameters = _section(doc, "Parameters")
    if not parameters:
        return findings

    # Collect every Ref target across the template.
    referenced: set = set()
    for section_name in ("Resources", "Conditions", "Outputs"):
        for ref in netgraph._iter_refs(_section(doc, section_name)):
            referenced.add(ref)
    # Fn::Sub variables also reference parameters.
    referenced |= _sub_referenced_names(doc)

    for name in parameters:
        if isinstance(name, str) and name not in referenced:
            findings.append(_finding(
                logical_id=None, template_file=template_file,
                template_path=["Parameters", name],
                rule="unused_parameter",
                severity="LOW", finding_type="Informational",
                text=(
                    "Parameter {0} is not referenced by any resource, condition "
                    "or output.".format(name)
                ),
                why=(
                    "A parameter that nothing consumes is dead configuration: it "
                    "misleads an operator about what is configurable and may hide "
                    "that the resource meant to use it is not wired in."
                ),
                recommendation=(
                    "Reference the parameter where it is intended to be used, or "
                    "remove it."
                ),
                excerpt="Parameters:\n  {0}: ...".format(name),
            ))
    return findings


def detect_unused_condition(doc: Any, template_file: str) -> List[Finding]:
    """A Condition nothing uses."""
    findings: List[Finding] = []
    conditions = _section(doc, "Conditions")
    if not conditions:
        return findings
    used = _condition_names_used(doc)
    for name in conditions:
        if isinstance(name, str) and name not in used:
            findings.append(_finding(
                logical_id=None, template_file=template_file,
                template_path=["Conditions", name],
                rule="unused_condition",
                severity="LOW", finding_type="Informational",
                text="Condition {0} is defined but never used.".format(name),
                why=(
                    "An unused condition is dead configuration and often the sign "
                    "of a resource that was meant to be gated on it but is not."
                ),
                recommendation=(
                    "Apply the condition where it is intended, or remove it."
                ),
                excerpt="Conditions:\n  {0}: ...".format(name),
            ))
    return findings


def detect_circular_dependency(doc: Any, template_file: str) -> List[Finding]:
    """A cycle in the resource dependency graph (Ref/GetAtt/DependsOn)."""
    findings: List[Finding] = []
    graph = netgraph.build_graph(doc)
    cycle = _find_cycle(graph)
    if cycle:
        findings.append(_finding(
            logical_id=cycle[0], template_file=template_file,
            template_path=["Resources", cycle[0]],
            rule="circular_dependency",
            severity="HIGH", finding_type="Validity",
            text=(
                "A circular dependency exists between resources: {0}. "
                "CloudFormation cannot order these for creation.".format(
                    " -> ".join(cycle)
                )
            ),
            why=(
                "A dependency cycle makes the stack undeployable: no resource in "
                "the cycle can be created before the others."
            ),
            recommendation=(
                "Break the cycle by removing an unnecessary Ref/GetAtt or "
                "DependsOn edge between the resources named above."
            ),
            excerpt=" -> ".join(cycle),
        ))
    return findings


def detect_allowed_values_mixed_types(doc: Any, template_file: str) -> List[Finding]:
    """A Parameter whose AllowedValues list mixes JSON types."""
    findings: List[Finding] = []
    for name, body in _section(doc, "Parameters").items():
        if not isinstance(name, str) or not isinstance(body, dict):
            continue
        allowed = body.get("AllowedValues")
        if not isinstance(allowed, list) or len(allowed) < 2:
            continue
        types = {type(v).__name__ for v in allowed}
        # bool is a subtype of int in Python; treat them together only if
        # actually mixed with strings.
        non_string = any(not isinstance(v, str) for v in allowed)
        has_string = any(isinstance(v, str) for v in allowed)
        if non_string and has_string:
            findings.append(_finding(
                logical_id=None, template_file=template_file,
                template_path=["Parameters", name, "AllowedValues"],
                rule="allowed_values_mixed_types",
                severity="LOW", finding_type="BestPractice",
                text=(
                    "Parameter {0} has an AllowedValues list mixing strings with "
                    "non-string values.".format(name)
                ),
                why=(
                    "A parameter is typed String; a numeric entry in its "
                    "AllowedValues is coerced or rejected inconsistently across "
                    "tools, so the constraint does not mean what it appears to."
                ),
                recommendation=(
                    "Use values of a single, consistent type in AllowedValues."
                ),
                excerpt="{0}.AllowedValues".format(name),
            ))
    return findings


def _sub_referenced_names(doc: Any) -> set:
    """Parameter/resource names named inside every ``Fn::Sub`` in the template."""
    names: set = set()
    pattern = re.compile(r"\$\{([A-Za-z0-9:._-]+)\}")

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for key, inner in value.items():
                if key == "Fn::Sub":
                    body = inner[0] if isinstance(inner, list) and inner else inner
                    if isinstance(body, str):
                        for token in pattern.findall(body):
                            names.add(token.split(".", 1)[0])
                    if isinstance(inner, list):
                        for item in inner[1:]:
                            walk(item)
                else:
                    walk(inner)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(doc)
    return names


def _find_cycle(graph: "netgraph.ResourceGraph") -> Optional[List[str]]:
    """Return one dependency cycle as a list of logical ids, or ``None``.

    Depth-first search over the edge set. Returns the first cycle found, with
    the repeated node at both ends so the path reads as a loop.
    """
    adjacency: Dict[str, List[str]] = {}
    for source, target in graph.edges:
        adjacency.setdefault(source, []).append(target)

    WHITE, GREY, BLACK = 0, 1, 2
    color: Dict[str, int] = {node: WHITE for node in graph.resources}
    stack: List[str] = []

    def visit(node: str) -> Optional[List[str]]:
        color[node] = GREY
        stack.append(node)
        for neighbour in adjacency.get(node, []):
            if neighbour not in color:
                continue
            if color[neighbour] == GREY:
                # Found a back edge; extract the cycle from the stack.
                index = stack.index(neighbour)
                return stack[index:] + [neighbour]
            if color[neighbour] == WHITE:
                found = visit(neighbour)
                if found is not None:
                    return found
        color[node] = BLACK
        stack.pop()
        return None

    for node in graph.resources:
        if color[node] == WHITE:
            found = visit(node)
            if found is not None:
                return found
    return None


#: Detectors, in the fixed order their findings are produced.
DETECTORS = (
    detect_condition_name_logic_mismatch,
    detect_unused_parameter,
    detect_unused_condition,
    detect_circular_dependency,
    detect_allowed_values_mixed_types,
)


def review(doc: Any, *, template_file: str) -> List[Finding]:
    """Run every quality detector over a parsed template.

    Returns findings in detector order, all ``Confidence: Confirmed``. Empty
    when the template has no Conditions, Parameters, or dependency issues.
    """
    findings: List[Finding] = []
    for detector in DETECTORS:
        findings.extend(detector(doc, template_file))
    return findings


def run_and_normalize(
    template_path: Any,
    *,
    workspace_root: Any = None,
    loaded: Optional[LoadedTemplate] = None,
) -> SourceResult:
    """Run the quality review as a Source, returning a :class:`SourceResult`."""
    from pathlib import Path
    from iacreview.template import load_template

    root = Path(workspace_root) if workspace_root is not None else Path.cwd()
    path_obj = Path(template_path)
    if loaded is None:
        loaded = load_template(path_obj)

    template_file = workspace_relative(str(path_obj), root) or path_obj.name
    findings = review(loaded.doc, template_file=template_file)
    return SourceResult(source=SOURCE_NAME, findings=findings, errors=[], stats={})
