"""Repository and Template boundary checks (Design 5).

Both functions return :class:`Finding` values with typed paths. Nothing here
formats a path for display; the report redacts untrusted keys.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple

from iacreview import semdiff
from iacreview.deltaio import ParsedTemplate
from iacreview.remediation import gitsnap
from iacreview.remediation.contract import Contract

#: Change_Qualifiers that make an allowed change unverifiable in Phase 1: the
#: value depends on a condition, a dynamic reference, a value outside the
#: Template or a Transform. ``expression_unevaluated`` alone (an ``Fn::Sub``
#: or ``Fn::GetAtt`` somewhere in the changed subtree) is not on the list: the
#: outcome rules and the statement comparison read the declared structure, and
#: a rule that needs a literal fails on an expression (fail closed).
UNSUPPORTED_QUALIFIERS = frozenset(("conditional", "dynamic_reference_unresolved", "external_value", "pre_transform"))
#: Semantic_Limitations that make the whole comparison unverifiable in Phase 1.
UNSUPPORTED_LIMITATIONS = frozenset(("transform_not_expanded",))


@dataclass(frozen=True)
class Finding:
    """One boundary result. ``path`` is a repository path or a Template path."""

    code: str
    scope: str  # "repository" or "template"
    path: Tuple[object, ...]
    detail: Optional[str] = None  # a closed-vocabulary word, never input text


def repository(contract: Contract, base: gitsnap.Snapshot, head: gitsnap.Snapshot) -> List[Finding]:
    """Every path other than the target must be unchanged, mode included."""
    findings: List[Finding] = []
    target = contract.template_path
    for path in sorted(set(base.entries) | set(head.entries)):
        b = base.entries.get(path)
        h = head.entries.get(path)
        if path == target:
            continue
        if b == h:
            continue
        if b is None:
            findings.append(Finding("file_added_outside_scope", "repository", (path,)))
        elif h is None:
            findings.append(Finding("file_removed_outside_scope", "repository", (path,)))
        elif b.mode != h.mode:
            findings.append(Finding("file_mode_changed", "repository", (path,)))
        else:
            findings.append(Finding("file_modified_outside_scope", "repository", (path,)))
    b = base.entries.get(target)
    h = head.entries.get(target)
    if b is None or b.mode not in gitsnap.REGULAR_MODES:
        # A Base without the regular target file cannot be a contract subject.
        findings.append(Finding("target_not_regular_file", "repository", (target,), "base"))
    if h is None:
        findings.append(Finding("target_template_removed", "repository", (target,)))
    elif h.mode not in gitsnap.REGULAR_MODES:
        findings.append(Finding("target_not_regular_file", "repository", (target,), "head"))
    elif b is not None and h.mode != b.mode:
        findings.append(Finding("file_mode_changed", "repository", (target,)))
    return findings


_MISSING = object()


def typed_path(path: Tuple[object, ...], base_doc: object, head_doc: object) -> Tuple[object, ...]:
    """Recover the key/index typing ``semdiff`` paths lose for digit keys.

    ``semdiff`` normalizes paths with ``finding.canonical_template_path``,
    which turns a mapping key such as ``"0"`` into the int ``0``. Walking the
    two documents tells which positions are mapping keys (always ``str``: a
    non-string key is never compared) and which are list indexes (``int``).
    """
    out: List[object] = []
    nodes = [base_doc, head_doc]
    for item in path:
        if any(isinstance(n, dict) for n in nodes):
            key: object = str(item)
            nodes = [n.get(key, _MISSING) if isinstance(n, dict) else _MISSING for n in nodes]
        elif any(isinstance(n, (list, tuple)) for n in nodes) and isinstance(item, int):
            key = item
            nodes = [n[item] if isinstance(n, (list, tuple)) and 0 <= item < len(n) else _MISSING for n in nodes]
        else:
            key = item
            nodes = [_MISSING, _MISSING]
        out.append(key)
    return tuple(out)


def _has_condition(value: object) -> bool:
    """Whether ``value`` holds an ``Fn::If`` anywhere (each object visited once)."""
    seen = set()
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, (dict, list, tuple)):
            if id(current) in seen:
                continue
            seen.add(id(current))
        if isinstance(current, dict):
            if "Fn::If" in current:
                return True
            stack.extend(current.values())
        elif isinstance(current, (list, tuple)):
            stack.extend(current)
    return False


def _property_value(doc: object, resource: str, prop: str) -> object:
    try:
        return doc["Resources"][resource]["Properties"].get(prop)  # type: ignore[index]
    except (KeyError, TypeError, AttributeError):
        return None


def _operation(base_doc: object, head_doc: object, resource: str, prop: str) -> str:
    def present(doc: object) -> bool:
        try:
            return prop in doc["Resources"][resource]["Properties"]  # type: ignore[index]
        except (KeyError, TypeError):
            return False

    b, h = present(base_doc), present(head_doc)
    if b and h:
        return "replace"
    return "add" if h else "remove"


def template(
    contract: Contract,
    resource_type: str,
    base: ParsedTemplate,
    head: ParsedTemplate,
    result: semdiff.SemanticDiffResult,
) -> List[Finding]:
    """Classify every Change_Entry against the allowed edits."""
    findings: List[Finding] = []
    resource = contract.resource
    for uncompared in result.uncompared_paths:
        findings.append(
            Finding("comparison_incomplete", "template", typed_path(uncompared.path, base.doc, head.doc), uncompared.reason)
        )
    for limitation in result.semantic_limitations:
        if limitation in UNSUPPORTED_LIMITATIONS:
            findings.append(Finding("unsupported_construct", "template", (), limitation))
    # The contract must fit Base: its Resource exists there with the profile's
    # Type. A Head without it is reported by the Change_Entries below
    # (resource_removed / resource_type_changed).
    resources = base.doc.get("Resources") if isinstance(base.doc, dict) else None
    target = resources.get(resource) if isinstance(resources, dict) else None
    if not (isinstance(target, dict) and target.get("Type") == resource_type):
        findings.append(Finding("target_resource_missing", "template", ("Resources", resource), "base"))
    for change in result.changes:
        path = typed_path(change.path, base.doc, head.doc)
        in_target = change.section == "Resources" and len(path) >= 2 and path[1] == resource and isinstance(path[1], str)
        if change.section == "Resources" and len(path) == 2:
            if change.type_changed:
                code = "resource_type_changed"
            elif change.change == "added":
                code = "resource_added"
            elif change.change == "removed":
                code = "resource_removed"
            else:
                code = "parent_replaced" if in_target else "template_change_outside_scope"
            findings.append(Finding(code, "template", path))
            continue
        if not in_target:
            findings.append(Finding("template_change_outside_scope", "template", path))
            continue
        if len(path) == 3 and path[2] == "Properties":
            findings.append(Finding("parent_replaced", "template", path))
            continue
        prop = path[3] if len(path) >= 4 and path[2] == "Properties" else None
        edit = contract.edit_for(prop) if isinstance(prop, str) else None
        if edit is None:
            findings.append(Finding("template_change_outside_scope", "template", path))
            continue
        op = _operation(base.doc, head.doc, resource, edit.property)
        if op not in edit.operations:
            findings.append(Finding("operation_not_allowed", "template", path[:4], op))
            continue
        bad = set(UNSUPPORTED_QUALIFIERS.intersection(change.qualifiers))
        if any(_has_condition(_property_value(doc, resource, edit.property)) for doc in (base.doc, head.doc)):
            bad.add("conditional")
        if bad:
            findings.append(Finding("unsupported_construct", "template", path[:4], sorted(bad)[0]))
    return _dedupe(findings)


def _dedupe(findings: List[Finding]) -> List[Finding]:
    seen = set()
    out = []
    for f in findings:
        key = (f.code, f.scope, f.path, f.detail)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out
