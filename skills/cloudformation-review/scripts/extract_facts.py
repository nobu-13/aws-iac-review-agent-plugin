#!/usr/bin/env python3
"""Extract the deterministic Template facts the ``cloudformation-review`` Agent reads.

This Skill is the one Agent-reasoning Source of the plugin, and this script is
the only code in it. It performs *no review*: it turns a Template into the
structured, bounded, deterministic set of facts design.md lists for
``skills/cloudformation-review``, and the host Agent reasons over that JSON
following ``SKILL.md``.

Why a facts file instead of handing the Agent the Template
    The four fact groups (a resource inventory, the ``Ref`` / ``Fn::GetAtt``
    reference graph, ``DependsOn`` edges, Parameters / Conditions, and the
    availability-related properties) are exactly the input needed for the
    concerns Requirement 2 AC14 assigns to Agent reasoning: cross-resource
    relationships, architectural risk, contextual severity, and best-practice
    judgement. Extracting them deterministically means the Agent never has to
    parse YAML, resolve a short-form intrinsic, or count list elements -- three
    things it would do less reliably than :mod:`iacreview.template` does, and
    whose failure would silently change what it reasoned about.

Why the deterministic findings are summarized in here
    ``deterministic_findings_summary`` is the structural support for
    Requirement 2 AC14 and AC15 (design.md, Requirement 対応表): an Agent that
    can see what cfn-lint, cfn-guard and the deterministic IAM checks already
    reported has no reason to restate it as a new Finding. The summary carries
    the rule identity, the resource, the category and the severity, and
    deliberately *not* the Finding prose -- reproducing the wording would invite
    paraphrasing it back.

    Two things feed it. The IAM Source is computed in process, because it is
    pure Python and therefore free of an external dependency and of any
    machine-to-machine variation. cfn-lint and cfn-guard are not run here: this
    Skill declares Python 3.9+ as its only dependency (design.md, Skill 一覧),
    and shelling out to a tool that may be absent would make the facts file
    depend on the host's installation, breaking the byte-identical guarantee of
    Requirement 16 AC11. Their findings enter through ``--deterministic-report``,
    which reads a Review_Report (or any ``{"findings": [...]}`` document) that
    ``cfn-lint-review``, ``cfn-guard-review`` or ``iac-review`` already produced.
    ``deterministic_sources`` states which Source each summary entry came from
    and how, so a zero count is never mistaken for "checked and clean".

Everything is bounded
    A Template is untrusted input, so every value that reaches the output goes
    through :func:`_summarize`: strings are truncated, sequences are capped,
    mappings are capped, and nesting stops at :data:`MAX_VALUE_DEPTH` with a
    placeholder that names what was left out. Both walks are depth-limited as
    well (:data:`MAX_WALK_DEPTH`), so a deeply nested document costs bounded
    work instead of a ``RecursionError``. Nothing in the Template is evaluated
    -- intrinsic functions arrive in long form from
    :mod:`iacreview.yamlcfn` and are read as data.

    A ``NoEcho`` Parameter's ``Default`` is replaced by
    :data:`~iacreview.finding.REDACTED_EXCERPT` before it can reach stdout
    (steering/security.md: no credential value in output), using the same
    Parameter set :mod:`iacreview.finding` redacts Excerpts against.

Output is deterministic
    Same Template plus same reports gives byte-identical stdout: resource order
    follows the Template, every derived list is either sorted or deduplicated in
    first-seen order, and serialization goes through
    :func:`iacreview.report.dump`, which sorts keys and pins encoding. Argument
    order of repeated ``--deterministic-report`` options cannot show through,
    because the summary is deduplicated and sorted.
"""

from __future__ import annotations

import sys
from pathlib import Path

# scripts/ -> skill dir -> skills/ -> plugin root
_PLUGIN_ROOT = Path(__file__).resolve().parents[3]
if str(_PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_ROOT))

import argparse  # noqa: E402  (import after the sys.path bootstrap above)
import json  # noqa: E402
import re  # noqa: E402
from typing import (  # noqa: E402
    Any,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Optional,
    Sequence,
    Tuple,
)

from iacreview import bootstrap, iam, netgraph, pathguard, secrets  # noqa: E402
from iacreview.errors import InputNotFoundError, SchemaViolationError  # noqa: E402
from iacreview.finding import (  # noqa: E402
    AGENT_SOURCE,
    REDACTED_EXCERPT,
    SOURCES,
    Evidence,
    Finding,
    noecho_parameter_names,
)
from iacreview.report import SCHEMA_VERSION, dump  # noqa: E402
from iacreview.source import workspace_relative  # noqa: E402
from iacreview.template import (  # noqa: E402
    RESOURCES_KEY,
    LoadedTemplate,
    load_template,
)

bootstrap.require_plugin_root(__file__)


# ---------------------------------------------------------------------------
# Output shape
# ---------------------------------------------------------------------------

#: Top-level keys of the facts JSON. Always all of them, whatever the Template
#: contained, so a consumer never has to test for a key's presence.
FACTS_KEYS: Tuple[str, ...] = (
    "schema_version",
    "target",
    "parameters",
    "conditions",
    "resources",
    "references",
    "depends_on",
    "deterministic_reports",
    "deterministic_sources",
    "deterministic_findings_summary",
)

#: Keys of the ``target`` object. ``description`` is included because the
#: Template's own description is often the only statement of intended
#: environment, which is what contextual severity assessment (design.md,
#: boundary row 16) has to work from.
TARGET_KEYS: Tuple[str, ...] = ("file", "format", "description")

#: Keys of one ``resources[]`` entry.
RESOURCE_KEYS: Tuple[str, ...] = (
    "logical_id",
    "type",
    "condition",
    "properties",
    "availability",
)

#: Keys of one ``resources[].availability[]`` entry.
AVAILABILITY_KEYS: Tuple[str, ...] = (
    "property",
    "json_path",
    "value",
    "item_count",
)

#: Keys of one ``references[]`` entry.
REFERENCE_KEYS: Tuple[str, ...] = ("from", "to", "kind", "attribute", "json_path")

#: Keys of one ``depends_on[]`` entry.
DEPENDS_ON_KEYS: Tuple[str, ...] = ("from", "to")

#: Keys of one ``parameters[]`` entry. ``has_default`` exists because ``default``
#: is ``null`` both for a Parameter without one and for a Parameter whose default
#: is JSON ``null``.
PARAMETER_KEYS: Tuple[str, ...] = (
    "name",
    "type",
    "default",
    "has_default",
    "no_echo",
    "allowed_values",
    "referenced_by",
)

#: Keys of one ``conditions[]`` entry.
CONDITION_KEYS: Tuple[str, ...] = ("name", "definition")

#: Keys of one ``deterministic_findings_summary[]`` entry. A superset of the IAM
#: Layer 2 summary (design.md: ``rule`` / ``resource`` / ``severity``) by
#: ``source`` and ``category``, because this summary mixes Sources and the Agent
#: needs the category to tell which of its own concerns is already covered.
SUMMARY_KEYS: Tuple[str, ...] = ("source", "rule", "resource", "category", "severity")

#: Keys of one ``deterministic_sources[]`` entry.
SOURCE_COVERAGE_KEYS: Tuple[str, ...] = (
    "name",
    "findings_summarized",
    "computed_in_process",
)

#: The Sources that are deterministic, in report order. ``Agent Review`` is
#: excluded: a previous Agent's output is not a deterministic finding, and
#: feeding it back as "already reported" would let one non-deterministic run
#: silence the next.
DETERMINISTIC_SOURCES: Tuple[str, ...] = tuple(
    name for name in SOURCES if name != AGENT_SOURCE
)

#: The Sources this script computes itself; see the module docstring. Both read
#: the parsed template directly (no external tool), so their zero counts mean
#: "checked and clean" rather than "never ran".
IN_PROCESS_SOURCES = frozenset({iam.SOURCE_NAME, netgraph.SOURCE_NAME, secrets.SOURCE_NAME})


# ---------------------------------------------------------------------------
# Template vocabulary
# ---------------------------------------------------------------------------

PARAMETERS_SECTION = "Parameters"
CONDITIONS_SECTION = "Conditions"
DESCRIPTION_KEY = "Description"
TYPE_KEY = "Type"
PROPERTIES_KEY = "Properties"
CONDITION_KEY = "Condition"
DEPENDS_ON_KEY = "DependsOn"
DEFAULT_KEY = "Default"
ALLOWED_VALUES_KEY = "AllowedValues"

REF = "Ref"
FN_GETATT = "Fn::GetAtt"
FN_SUB = "Fn::Sub"

#: The three reference forms that can name another resource. ``Fn::Sub`` is
#: included even though design.md names only ``Ref`` and ``Fn::GetAtt``: a
#: ``${Bucket.Arn}`` inside an ``Fn::Sub`` is the same cross-resource
#: relationship written differently, and omitting it would hide edges from the
#: one consumer whose whole job is to reason about them. The ``kind`` field says
#: which form each edge came from, so a reader can still tell them apart.
REFERENCE_KINDS: Tuple[str, ...] = (REF, FN_GETATT, FN_SUB)

#: Separator between the logical ID and the attribute in ``Fn::GetAtt`` and in an
#: ``Fn::Sub`` substitution (``"Bucket.Arn"``).
ATTRIBUTE_SEPARATOR = "."

#: One ``${Name}`` or ``${Name.Attr}`` substitution. ``!`` is excluded at the
#: first position so that the literal escape ``${!Literal}`` is not read as a
#: reference, and inner braces are excluded so a malformed string cannot make
#: the match run away.
SUB_REFERENCE = re.compile(r"\$\{([^{}!][^{}]*)\}")

#: Marks a pseudo parameter (``AWS::Region``) rather than a logical ID.
PSEUDO_PARAMETER_MARKER = "::"

#: Property names that decide, or evidence, how a resource is spread across
#: Availability Zones. Presence is the fact being reported (design.md: "AZ /
#: Subnet / Multi-AZ 関連 property の有無"); ``item_count`` then distinguishes one
#: subnet from three, which is what a single-AZ risk actually looks like.
#:
#: The list is intentionally property *names* rather than resource types: it
#: matches wherever the name occurs, so a resource type nobody thought of is
#: covered as long as it uses CloudFormation's usual naming. Judging whether a
#: given count is adequate is the Agent's job, not this script's.
AVAILABILITY_PROPERTY_NAMES: Tuple[str, ...] = (
    "AvailabilityZone",
    "AvailabilityZoneCount",
    "AvailabilityZones",
    "DBSubnetGroupName",
    "MultiAZ",
    "SubnetGroupName",
    "SubnetId",
    "SubnetIds",
    "SubnetMappings",
    "Subnets",
    "VPCZoneIdentifier",
)


# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

#: Longest string reproduced from the Template. Long enough for an ARN, a Sub
#: template or a description; short enough that a Template carrying an embedded
#: blob cannot dominate the facts file.
MAX_STRING_LENGTH = 200

#: Most sequence elements reproduced from one list.
MAX_SEQUENCE_ITEMS = 10

#: Most mapping keys reproduced from one mapping.
MAX_MAPPING_KEYS = 20

#: Nesting depth at which a value is replaced by a placeholder naming its shape.
#: Ten levels is set by the deepest thing a Template routinely declares: an
#: embedded policy document reaches nine at the ``Condition`` operator's value
#: (``Properties`` -> ``Policies`` -> element -> ``PolicyDocument`` ->
#: ``Statement`` -> element -> ``Condition`` -> operator -> key -> value). A
#: shallower bound replaced exactly the values a reader needs -- the intrinsic
#: function a property was set from -- with a placeholder.
MAX_VALUE_DEPTH = 10

#: Depth limit of the reference and availability walks over a resource body.
#: Bounded work on an adversarial Template rather than a ``RecursionError``;
#: matches the spirit of :data:`iacreview.iam.intrinsics.MAX_NESTING_DEPTH`.
MAX_WALK_DEPTH = 40

#: Appended to a string cut at :data:`MAX_STRING_LENGTH`.
TRUNCATED_TEXT_SUFFIX = "... [truncated]"

#: Placeholder element appended to a sequence cut at :data:`MAX_SEQUENCE_ITEMS`.
OMITTED_ITEMS = "... [omitted: {0} more]"

#: Key under which a mapping cut at :data:`MAX_MAPPING_KEYS` records the rest.
#: A reserved key rather than a dropped tail, so the omission is visible in the
#: output instead of having to be inferred from a count.
OMITTED_KEYS_MARKER = "__omitted__"

#: Value stored under :data:`OMITTED_KEYS_MARKER`.
OMITTED_KEYS = "[omitted: {0} more]"

#: Placeholders for a value that sits deeper than :data:`MAX_VALUE_DEPTH`.
OMITTED_MAPPING = "[omitted: mapping with {0}]"
OMITTED_SEQUENCE = "[omitted: sequence with {0}]"

#: Envelope key holding the findings array of a ``--deterministic-report`` file.
#: The same key in a Review_Report and in a single Source's output, which is why
#: one reader accepts both.
FINDINGS_KEY = "findings"


# ---------------------------------------------------------------------------
# Value summarization
# ---------------------------------------------------------------------------


def _key_text(key: Any) -> str:
    """Render a mapping key as the string the facts file will carry.

    YAML permits non-string scalar keys (``2010: value``). JSON serialization
    would coerce them anyway; doing it here means the coercion is visible and
    the same key cannot appear twice under two spellings.
    """
    return key if isinstance(key, str) else str(key)


def _truncate_text(value: str) -> str:
    """Cut ``value`` to :data:`MAX_STRING_LENGTH`, marking the cut."""
    if len(value) <= MAX_STRING_LENGTH:
        return value
    return value[:MAX_STRING_LENGTH] + TRUNCATED_TEXT_SUFFIX


def _counted(count: int, noun: str) -> str:
    """Render ``count`` with ``noun``, pluralized.

    The placeholders are read by a human and by an Agent, and "1 keys" reads as
    a defect in the tool rather than as a bound being reported.
    """
    return "{0} {1}".format(count, noun if count == 1 else noun + "s")


def _omitted(value: Any) -> Any:
    """Placeholder for a container reached past :data:`MAX_VALUE_DEPTH`.

    Names the shape and the size rather than dropping the value, so a reader can
    tell "there is more here" from "there is nothing here" -- a distinction the
    Agent would otherwise get wrong when judging whether a property was
    configured at all.
    """
    if isinstance(value, dict):
        return OMITTED_MAPPING.format(_counted(len(value), "key"))
    if isinstance(value, list):
        return OMITTED_SEQUENCE.format(_counted(len(value), "item"))
    return _summarize(value, MAX_VALUE_DEPTH)


def _summarize(value: Any, depth: int = 0) -> Any:
    """Reproduce ``value`` as a bounded, JSON-serializable excerpt.

    Args:
        value: Any parsed Template value, including an intrinsic function in its
            long form (``{"Ref": "X"}``). Untrusted.
        depth: Current nesting depth; callers start at ``0``.

    Returns:
        A value of the same shape as ``value`` wherever the bounds allow, with
        strings truncated, sequences and mappings capped, and anything deeper
        than :data:`MAX_VALUE_DEPTH` replaced by a placeholder string. Scalars
        pass through unchanged, so an intrinsic function stays recognizable and
        a boolean stays a boolean.

    Note:
        Intrinsic functions are summarized like any other mapping and are never
        resolved. That is the point: the Agent should see that a property is
        ``{"Ref": "SubnetIds"}`` rather than a value this script invented for it.
    """
    if isinstance(value, str):
        return _truncate_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, list):
        if depth >= MAX_VALUE_DEPTH:
            return _omitted(value)
        kept = [
            _summarize(element, depth + 1) for element in value[:MAX_SEQUENCE_ITEMS]
        ]
        remaining = len(value) - MAX_SEQUENCE_ITEMS
        if remaining > 0:
            kept.append(OMITTED_ITEMS.format(_counted(remaining, "item")))
        return kept
    if isinstance(value, dict):
        if depth >= MAX_VALUE_DEPTH:
            return _omitted(value)
        items = list(value.items())
        summary = {
            _key_text(key): _summarize(sub_value, depth + 1)
            for key, sub_value in items[:MAX_MAPPING_KEYS]
        }
        remaining = len(items) - MAX_MAPPING_KEYS
        if remaining > 0:
            summary[OMITTED_KEYS_MARKER] = OMITTED_KEYS.format(
                _counted(remaining, "key")
            )
        return summary
    # Anything else (a date PyYAML built from an unquoted timestamp, say) is
    # rendered as text: the facts file must be JSON, and the string form is
    # closer to what the Template said than dropping the value would be.
    return _truncate_text(str(value))


# ---------------------------------------------------------------------------
# Template sections
# ---------------------------------------------------------------------------


def _section(doc: Any, name: str) -> Dict[str, Any]:
    """Return top-level section ``name`` as a mapping, or an empty one.

    A section of the wrong type contributes nothing rather than raising: it is a
    Template defect, cfn-lint reports it, and this script's job is to keep going
    so the rest of the facts still reach the Agent.
    """
    if not isinstance(doc, dict):
        return {}
    section = doc.get(name)
    return section if isinstance(section, dict) else {}


def _resource_bodies(doc: Any) -> List[Tuple[str, Dict[str, Any]]]:
    """The Template's resources as ``(logical_id, body)``, in Template order.

    Entries whose logical ID is not a string or whose body is not a mapping are
    skipped: neither can be reasoned about, and both are cfn-lint findings.
    """
    return [
        (name, body)
        for name, body in _section(doc, RESOURCES_KEY).items()
        if isinstance(name, str) and isinstance(body, dict)
    ]


def _optional_text(value: Any) -> Optional[str]:
    """Return ``value`` if it is a string, else ``None``."""
    return _truncate_text(value) if isinstance(value, str) else None


def _target(loaded: LoadedTemplate, template_file: str) -> Dict[str, Any]:
    """Build the ``target`` object."""
    return {
        "file": template_file,
        "format": loaded.fmt,
        "description": _optional_text(loaded.doc.get(DESCRIPTION_KEY)),
    }


# ---------------------------------------------------------------------------
# Resources
# ---------------------------------------------------------------------------


def _properties(body: Dict[str, Any]) -> Dict[str, Any]:
    """Bounded excerpt of one resource's ``Properties``.

    Every declared property name is present, so the Agent can see what was
    configured and what was left out; the *values* are what the bounds apply to.
    Selecting a subset of "important" properties was the alternative and is
    rejected: the selection would be a review decision made in a script that is
    not supposed to review anything, and a property left out of the excerpt is
    invisible to the one consumer that might have cared about it.
    """
    properties = body.get(PROPERTIES_KEY)
    if not isinstance(properties, dict):
        return {}
    return {
        _key_text(name): _summarize(value, 1) for name, value in properties.items()
    }


def _availability_entry(
    name: str, value: Any, path: Tuple[str, ...]
) -> Dict[str, Any]:
    """One ``availability[]`` entry."""
    return {
        "property": name,
        "json_path": ".".join(path),
        "value": _summarize(value),
        "item_count": len(value) if isinstance(value, list) else None,
    }


def _collect_availability(
    value: Any, path: Tuple[str, ...], depth: int, out: List[Dict[str, Any]]
) -> None:
    """Record every :data:`AVAILABILITY_PROPERTY_NAMES` occurrence under ``value``.

    The whole resource body is searched, not just its top-level properties,
    because the properties that decide AZ spread are frequently nested (an
    ``AWS::ElasticLoadBalancingV2::LoadBalancer`` declares ``SubnetMappings``
    entries, an ``AWS::RDS::DBInstance`` nests nothing but an
    ``AWS::AutoScaling::AutoScalingGroup`` nests ``VPCZoneIdentifier`` beside
    conditionals).
    """
    if depth >= MAX_WALK_DEPTH:
        return
    if isinstance(value, list):
        for index, element in enumerate(value):
            _collect_availability(element, path + (str(index),), depth + 1, out)
        return
    if not isinstance(value, dict):
        return
    for key, sub_value in value.items():
        key_text = _key_text(key)
        sub_path = path + (key_text,)
        if key_text in AVAILABILITY_PROPERTY_NAMES:
            out.append(_availability_entry(key_text, sub_value, sub_path))
        _collect_availability(sub_value, sub_path, depth + 1, out)


def _availability(logical_id: str, body: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Availability-related properties of one resource, ordered by location."""
    found: List[Dict[str, Any]] = []
    _collect_availability(body, (RESOURCES_KEY, logical_id), 0, found)
    return sorted(found, key=lambda entry: (entry["json_path"], entry["property"]))


def _resources(doc: Any) -> List[Dict[str, Any]]:
    """The ``resources`` array, in Template order."""
    return [
        {
            "logical_id": logical_id,
            "type": _optional_text(body.get(TYPE_KEY)),
            "condition": _optional_text(body.get(CONDITION_KEY)),
            "properties": _properties(body),
            "availability": _availability(logical_id, body),
        }
        for logical_id, body in _resource_bodies(doc)
    ]


# ---------------------------------------------------------------------------
# The reference graph
# ---------------------------------------------------------------------------


def _edge(
    source: str,
    target: str,
    kind: str,
    attribute: Optional[str],
    path: Tuple[str, ...],
) -> Dict[str, Any]:
    """One raw reference edge, before targets are classified."""
    return {
        "from": source,
        "to": target,
        "kind": kind,
        "attribute": attribute,
        "json_path": ".".join(path),
    }


def _split_attribute(text: str) -> Tuple[str, Optional[str]]:
    """Split ``"Bucket.Arn"`` into its logical ID and its attribute path.

    Only the first separator splits: ``Fn::GetAtt`` attribute paths may
    themselves contain dots (``Outputs.NestedValue``), and those belong to the
    attribute rather than to the logical ID.
    """
    logical_id, separator, attribute = text.partition(ATTRIBUTE_SEPARATOR)
    return logical_id, attribute if separator else None


def _getatt_target(value: Any) -> Tuple[Optional[str], Optional[str]]:
    """Read ``Fn::GetAtt``'s target and attribute from either argument form.

    :mod:`iacreview.yamlcfn` normalizes ``!GetAtt A.Arn`` to the list form, but a
    JSON Template may spell either, so both are handled. A form whose first
    element is not a string (an intrinsic nested where CloudFormation does not
    allow one) yields no target; cfn-lint reports that.
    """
    if isinstance(value, str):
        return _split_attribute(value)
    if isinstance(value, list) and value and isinstance(value[0], str):
        rest = [element for element in value[1:] if isinstance(element, str)]
        return value[0], ATTRIBUTE_SEPARATOR.join(rest) or None
    return None, None


def _sub_targets(value: Any) -> List[Tuple[str, Optional[str]]]:
    """Read the names an ``Fn::Sub`` substitutes, in first-seen order.

    The long form's second element is a variable map whose *keys* are local
    names shadowing any logical ID of the same name, so a substitution of a
    shadowed name is not a reference to the resource. Its *values* are ordinary
    expressions and are walked separately by :func:`_collect_references`.
    """
    text = value[0] if isinstance(value, list) and value else value
    if not isinstance(text, str):
        return []
    shadowed: FrozenSet[str] = frozenset()
    if isinstance(value, list) and len(value) > 1 and isinstance(value[1], dict):
        shadowed = frozenset(_key_text(key) for key in value[1])

    targets: List[Tuple[str, Optional[str]]] = []
    seen = set()
    for name in SUB_REFERENCE.findall(text):
        if name in shadowed:
            continue
        logical_id, attribute = _split_attribute(name)
        if logical_id in shadowed or (logical_id, attribute) in seen:
            continue
        seen.add((logical_id, attribute))
        targets.append((logical_id, attribute))
    return targets


def _collect_references(
    source: str,
    value: Any,
    path: Tuple[str, ...],
    depth: int,
    out: List[Dict[str, Any]],
) -> None:
    """Collect every reference under ``value`` into ``out``.

    ``json_path`` records where the *intrinsic* sits (the property holding it),
    not the key of the intrinsic itself: ``Resources.App.Properties.Role`` is
    what a reader looks for, and ``...Properties.Role.Fn::GetAtt`` only adds the
    form, which the ``kind`` field already states.

    A mapping that is not one of the three reference functions is descended
    into, which is why ``Fn::If`` needs no case of its own: both alternatives are
    walked, and a resource named in either one is genuinely referenced.
    """
    if depth >= MAX_WALK_DEPTH:
        return
    if isinstance(value, list):
        for index, element in enumerate(value):
            _collect_references(source, element, path + (str(index),), depth + 1, out)
        return
    if not isinstance(value, dict):
        return
    for key, sub_value in value.items():
        key_text = _key_text(key)
        sub_path = path + (key_text,)
        if key_text == REF:
            if isinstance(sub_value, str):
                out.append(_edge(source, sub_value, REF, None, path))
        elif key_text == FN_GETATT:
            target, attribute = _getatt_target(sub_value)
            if target is not None:
                out.append(_edge(source, target, FN_GETATT, attribute, path))
        elif key_text == FN_SUB:
            for target, attribute in _sub_targets(sub_value):
                out.append(_edge(source, target, FN_SUB, attribute, path))
            if isinstance(sub_value, list) and len(sub_value) > 1:
                _collect_references(
                    source, sub_value[1], sub_path + ("1",), depth + 1, out
                )
        else:
            _collect_references(source, sub_value, sub_path, depth + 1, out)


def _reference_graph(
    doc: Any, parameter_names: Sequence[str]
) -> Tuple[List[Dict[str, Any]], Dict[str, List[str]]]:
    """Split every reference into resource edges and Parameter usage.

    Args:
        doc: A parsed Template. Untrusted.
        parameter_names: Declared Parameter names, in Template order.

    Returns:
        ``(references, referenced_by)``. ``references`` holds the resource ->
        resource edges, sorted by ``(from, json_path, to, kind)``; sorting rather
        than Template order makes the array a function of its contents, so the
        same Template written as YAML and as JSON produces the same bytes.
        ``referenced_by`` maps each Parameter name to the sorted logical IDs of
        the resources that use it.

    Note:
        A target that is neither a resource nor a Parameter is dropped: it is a
        pseudo parameter (``AWS::Region``), or a name that does not exist, and
        the latter is a cfn-lint finding rather than a relationship. A
        self-reference is dropped for the same reason -- CloudFormation rejects
        it, and it is not a cross-resource relationship.
    """
    resource_ids = {name for name, _ in _resource_bodies(doc)}
    parameters = set(parameter_names)

    raw: List[Dict[str, Any]] = []
    for logical_id, body in _resource_bodies(doc):
        _collect_references(logical_id, body, (RESOURCES_KEY, logical_id), 0, raw)

    references: List[Dict[str, Any]] = []
    seen = set()
    referenced_by: Dict[str, set] = {name: set() for name in parameter_names}
    for edge in raw:
        target = edge["to"]
        if target in resource_ids:
            if target == edge["from"]:
                continue
            key = tuple(edge[field] for field in REFERENCE_KEYS)
            if key in seen:
                continue
            seen.add(key)
            references.append(edge)
        elif target in parameters:
            referenced_by[target].add(edge["from"])

    references.sort(
        key=lambda entry: (
            entry["from"],
            entry["json_path"],
            entry["to"],
            entry["kind"],
            entry["attribute"] or "",
        )
    )
    return references, {name: sorted(ids) for name, ids in referenced_by.items()}


def _depends_on_names(value: Any) -> List[str]:
    """Read ``DependsOn``'s single-string and list forms, ignoring anything else."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [element for element in value if isinstance(element, str)]
    return []


def _depends_on(doc: Any) -> List[Dict[str, str]]:
    """The ``DependsOn`` edges, deduplicated and sorted.

    Only edges whose target is a resource of this Template are reported. A
    ``DependsOn`` naming something else is a cfn-lint finding (``E3005``), and
    reporting it here as a relationship would invite the Agent to reason about a
    dependency that cannot exist.
    """
    resource_ids = {name for name, _ in _resource_bodies(doc)}
    edges = {
        (name, target)
        for name, body in _resource_bodies(doc)
        for target in _depends_on_names(body.get(DEPENDS_ON_KEY))
        if target in resource_ids and target != name
    }
    return [{"from": source, "to": target} for source, target in sorted(edges)]


# ---------------------------------------------------------------------------
# Parameters and Conditions
# ---------------------------------------------------------------------------


def _parameters(doc: Any, referenced_by: Dict[str, List[str]]) -> List[Dict[str, Any]]:
    """The ``parameters`` array, in Template order.

    A ``NoEcho`` Parameter's ``Default`` is replaced by
    :data:`~iacreview.finding.REDACTED_EXCERPT`. ``NoEcho`` is the Template
    author's own statement that the value is sensitive, and a default is the one
    place a Parameter can carry a literal secret; the plugin must not copy it
    into its output (steering/security.md). ``has_default`` still reports that a
    default exists, which is the fact the Agent needs.
    """
    noecho = noecho_parameter_names(doc)
    entries: List[Dict[str, Any]] = []
    for name, spec in _section(doc, PARAMETERS_SECTION).items():
        if not isinstance(name, str):
            continue
        body = spec if isinstance(spec, dict) else {}
        has_default = DEFAULT_KEY in body
        redacted = name in noecho
        entries.append(
            {
                "name": name,
                "type": _optional_text(body.get(TYPE_KEY)),
                "default": (
                    REDACTED_EXCERPT
                    if redacted and has_default
                    else _summarize(body.get(DEFAULT_KEY))
                ),
                "has_default": has_default,
                "no_echo": redacted,
                "allowed_values": (
                    REDACTED_EXCERPT
                    if redacted and ALLOWED_VALUES_KEY in body
                    else _summarize(body.get(ALLOWED_VALUES_KEY))
                ),
                "referenced_by": referenced_by.get(name, []),
            }
        )
    return entries


def _conditions(doc: Any) -> List[Dict[str, Any]]:
    """The ``conditions`` array, in Template order.

    The definition is reproduced rather than evaluated: which branch a Condition
    selects depends on Parameter values supplied at deploy time, so an evaluated
    answer would be a guess. The Agent is being told what the Template makes
    conditional, which is what an architectural read needs.
    """
    return [
        {"name": name, "definition": _summarize(definition)}
        for name, definition in _section(doc, CONDITIONS_SECTION).items()
        if isinstance(name, str)
    ]


# ---------------------------------------------------------------------------
# The deterministic findings summary
# ---------------------------------------------------------------------------


def _summary_entry(
    source: str,
    rule: Optional[str],
    resource: Optional[str],
    category: Optional[str],
    severity: Optional[str],
) -> Dict[str, Any]:
    """One ``deterministic_findings_summary[]`` entry."""
    return {
        "source": source,
        "rule": rule,
        "resource": resource,
        "category": category,
        "severity": severity,
    }


def _rule_of(evidence: Iterable[Any]) -> Optional[str]:
    """The first ``RuleId`` recorded in an Evidence list, or ``None``.

    Accepts both :class:`~iacreview.finding.Evidence` objects (the in-process
    IAM Source) and the mappings a serialized report holds, because both arrive
    at this summary.
    """
    for entry in evidence:
        if isinstance(entry, Evidence):
            rule = entry.RuleId
        elif isinstance(entry, dict):
            rule = entry.get("RuleId")
        else:
            continue
        if isinstance(rule, str) and rule:
            return rule
    return None


def _summary_from_findings(findings: Sequence[Finding]) -> List[Dict[str, Any]]:
    """Summarize Findings this script computed in process."""
    return [
        _summary_entry(
            source,
            _rule_of(finding.Evidence),
            finding.Resource,
            finding.Normalized_Category,
            finding.Severity,
        )
        for finding in findings
        for source in finding.Source
        if source in DETERMINISTIC_SOURCES
    ]


def _summary_from_payload(payload: Any, path: Path) -> List[Dict[str, Any]]:
    """Summarize the findings of one ``--deterministic-report`` document.

    Args:
        payload: The parsed document: either an envelope with a
            :data:`FINDINGS_KEY` array (a Review_Report, or one Source's output)
            or a bare array of Findings.
        path: Where it came from, for the error message.

    Returns:
        One entry per (Finding, deterministic Source) pair. A Finding merged
        from two Sources therefore appears twice, which is what tells the Agent
        both Sources already covered it.

    Raises:
        SchemaViolationError: The document is neither shape.

    Note:
        A ``Source`` of ``Agent Review`` is skipped, and so is a Finding entry
        that is not a mapping or carries no recognizable Source. The file is a
        summarization input, not a report being validated: dropping an entry
        costs a "do not restate this" hint, while refusing the file would cost
        every hint in it.
    """
    if isinstance(payload, dict):
        entries = payload.get(FINDINGS_KEY)
    else:
        entries = payload
    if not isinstance(entries, list):
        raise SchemaViolationError(
            "deterministic report {0} is neither an object with a {1!r} array "
            "nor an array of findings".format(path, FINDINGS_KEY),
            remediation=(
                "Pass the stdout of run_cfn_lint.py, run_cfn_guard.py, "
                "run_iam_scan.py or run_iac_review.py."
            ),
        )

    summary: List[Dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        sources = entry.get("Source")
        sources = sources if isinstance(sources, list) else []
        evidence = entry.get("Evidence")
        rule = _rule_of(evidence if isinstance(evidence, list) else [])
        for source in sources:
            if source not in DETERMINISTIC_SOURCES:
                continue
            summary.append(
                _summary_entry(
                    source,
                    rule,
                    _optional_text(entry.get("Resource")),
                    _optional_text(entry.get("Normalized_Category")),
                    _optional_text(entry.get("Severity")),
                )
            )
    return summary


def _read_report(path: Path) -> Any:
    """Read and parse one ``--deterministic-report`` file.

    Raises:
        InputNotFoundError: The file cannot be read.
        SchemaViolationError: It is not UTF-8 text, or not valid JSON.
    """
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise InputNotFoundError(
            "cannot read deterministic report: {0} ({1})".format(path, exc)
        ) from exc
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise SchemaViolationError(
            "deterministic report {0} is not valid JSON: {1}".format(path, exc),
            remediation=(
                "Pass a JSON report produced by one of the plugin's review "
                "scripts."
            ),
        ) from exc


def _deduplicated_summary(entries: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicate and sort the summary.

    Both are what make repeated ``--deterministic-report`` options
    order-independent and a report supplied twice harmless: the same Finding
    summarized twice is one entry, and the array is a function of its contents
    rather than of the order the files were read (Requirement 16 AC11).
    """
    unique: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
    for entry in entries:
        unique[tuple(entry[field] for field in SUMMARY_KEYS)] = entry
    # Sorted on the string form of each key part, because a field may be None
    # (an unattributed rule, a template-level finding with no resource) and
    # ``None`` is not orderable against a string.
    ordered = sorted(unique, key=lambda key: tuple(str(part) for part in key))
    return [unique[key] for key in ordered]


def _source_coverage(summary: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """State, per deterministic Source, how the summary was arrived at.

    Without this, ``findings_summarized: 0`` would be ambiguous between "that
    Source found nothing" and "that Source never ran", and the second reading is
    the one that matters: this script does not execute cfn-lint or cfn-guard, so
    a zero there says nothing about the Template. ``computed_in_process`` marks
    the one Source whose zero does mean "checked and clean".
    """
    return [
        {
            "name": name,
            "findings_summarized": sum(
                1 for entry in summary if entry["source"] == name
            ),
            "computed_in_process": name in IN_PROCESS_SOURCES,
        }
        for name in DETERMINISTIC_SOURCES
    ]


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------


def build_facts(
    loaded: LoadedTemplate,
    *,
    template_file: str,
    reports: Sequence[Tuple[Path, str]] = (),
    iam_findings: Sequence[Finding] = (),
    network_findings: Sequence[Finding] = (),
    secret_findings: Sequence[Finding] = (),
) -> Dict[str, Any]:
    """Build the facts JSON for one Template.

    Args:
        loaded: The parsed Template, from :func:`iacreview.template.load_template`.
        template_file: Workspace-relative path of the Template, as it will
            appear in ``target.file`` (Requirement 16 AC11: never an absolute
            host path).
        reports: ``(resolved path, workspace-relative path)`` pairs for the
            ``--deterministic-report`` files, already contained by
            :func:`iacreview.pathguard.resolve_within`.
        iam_findings: Findings the in-process IAM Source produced for this
            Template.

    Returns:
        A JSON-serializable dict whose keys are exactly :data:`FACTS_KEYS`.
        Deterministic for the same inputs.

    Raises:
        InputNotFoundError: A report file cannot be read.
        SchemaViolationError: A report file is not JSON, or not a findings
            document.
    """
    doc = loaded.doc
    parameter_names = [
        name for name in _section(doc, PARAMETERS_SECTION) if isinstance(name, str)
    ]
    references, referenced_by = _reference_graph(doc, parameter_names)

    summary = list(_summary_from_findings(iam_findings))
    summary.extend(_summary_from_findings(network_findings))
    summary.extend(_summary_from_findings(secret_findings))
    for resolved, _ in reports:
        summary.extend(_summary_from_payload(_read_report(resolved), resolved))
    summary = _deduplicated_summary(summary)

    return {
        "schema_version": SCHEMA_VERSION,
        "target": _target(loaded, template_file),
        "parameters": _parameters(doc, referenced_by),
        "conditions": _conditions(doc),
        "resources": _resources(doc),
        "references": references,
        "depends_on": _depends_on(doc),
        "deterministic_reports": sorted(relative for _, relative in reports),
        "deterministic_sources": _source_coverage(summary),
        "deterministic_findings_summary": summary,
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build this script's argument parser."""
    parser = bootstrap.new_parser(
        Path(__file__).name,
        "Extract deterministic CloudFormation Template facts for Agent review.",
    )
    parser.add_argument(
        "--target",
        required=True,
        metavar="PATH",
        help=(
            "CloudFormation Template to extract facts from. Must resolve inside "
            "the workspace root (the current working directory). Exactly one "
            "Template per run: the output describes one Template."
        ),
    )
    parser.add_argument(
        "--deterministic-report",
        action="append",
        dest="deterministic_report",
        default=None,
        metavar="PATH",
        help=(
            "JSON report from a deterministic review Skill (cfn-lint-review, "
            "cfn-guard-review, iam-review or iac-review) whose findings are "
            "summarized into deterministic_findings_summary so the Agent does "
            "not restate them. May be given more than once; the order does not "
            "affect the output."
        ),
    )
    return parser


def _relative(path: Path, root: Path) -> str:
    """Render ``path`` relative to ``root`` for the output."""
    return workspace_relative(str(path), root) or path.name


def run(args: argparse.Namespace) -> Dict[str, Any]:
    """Extract the facts for ``args.target`` and return them for stdout.

    Path containment happens before anything is opened, and the Template is
    loaded before the IAM Source runs so a parse failure is reported as a parse
    failure rather than from inside a Source.
    """
    root = Path.cwd()
    template = pathguard.resolve_within(args.target, root)
    reports = [
        (resolved, _relative(resolved, root))
        for resolved in (
            pathguard.resolve_within(value, root)
            for value in (args.deterministic_report or [])
        )
    ]

    loaded = load_template(template)
    template_file = _relative(template, root)
    bootstrap.verbose_diagnostic(
        "extracting facts from {0} ({1}), {2} deterministic report(s)".format(
            template_file, loaded.fmt, len(reports)
        ),
        verbose=args.verbose,
    )

    iam_result = iam.run_and_normalize(template, workspace_root=root, loaded=loaded)
    network_result = netgraph.run_and_normalize(
        template, workspace_root=root, loaded=loaded
    )
    secret_result = secrets.run_and_normalize(
        template, workspace_root=root, loaded=loaded
    )
    bootstrap.verbose_diagnostic(
        "in-process IAM Source produced {0} finding(s)".format(
            len(iam_result.findings)
        ),
        verbose=args.verbose,
    )

    return build_facts(
        loaded,
        template_file=template_file,
        reports=reports,
        iam_findings=iam_result.findings,
        network_findings=network_result.findings,
        secret_findings=secret_result.findings,
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the script and return its exit code.

    Exit codes are the shared table (:mod:`iacreview.exitcodes`): 0 on success,
    2 for an invalid invocation, 3 for a missing file, 4 for a Template that
    does not parse or a report that is not a findings document, 5 for a YAML
    target when PyYAML is missing or too old, 7 for a path outside the
    workspace, 8 for a file that is not a reviewable Template, 1 for an
    internal error. Nothing but the facts JSON is ever written to stdout, and
    on failure stdout stays empty: a partial facts file would be
    indistinguishable from a Template that genuinely has fewer facts.
    """
    return bootstrap.run_entry_point(parser=build_parser(), run=run, argv=argv)


if __name__ == "__main__":
    raise SystemExit(main())
