"""Strict loader and validator of the Remediation Contract (Design 2).

The contract is read from a trusted revision, but it is still parsed as
untrusted text: one YAML document, no anchors, aliases, tags or merge keys, no
duplicate keys, no unknown keys, and string scalars only. Errors carry a closed
reason code and a path made of schema field names; they never quote the input,
so a key or value in a malformed contract cannot reach the output.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Tuple

import yaml

from iacreview.remediation import rschema
from iacreview.remediation.profiles import KNOWN_CHECKS, Profile

_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_LOGICAL_ID = re.compile(r"^[A-Za-z0-9]{1,255}$")
_SEGMENT = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9._-]{0,254}$")
_TEMPLATE_SUFFIXES = (".yaml", ".yml", ".json", ".template")
_STR_TAG = "tag:yaml.org,2002:str"

_TOP_KEYS = (
    "contract_schema_version",
    "contract_id",
    "profile_id",
    "profile_version",
    "task_id",
    "target",
    "scope",
    "intent",
    "verification",
)
_TARGET_KEYS = ("template_path",)
_SCOPE_KEYS = ("allowed_edits",)
_EDIT_KEYS = ("resource", "property", "operations")
_INTENT_KEYS = ("required_outcomes", "preserve_invariants", "parameters")
_VERIFICATION_KEYS = ("required_checks",)


class ContractError(Exception):
    """The contract is invalid. ``reason`` is a closed code; ``field`` a schema path."""

    def __init__(self, reason: str, field: str, code: str = "contract_invalid") -> None:
        super().__init__("{0}: {1}".format(field, reason))
        self.reason = reason
        self.field = field
        self.code = code


@dataclass(frozen=True)
class AllowedEdit:
    resource: str
    property: str
    operations: FrozenSet[str]


@dataclass(frozen=True)
class Contract:
    contract_id: str
    profile_id: str
    profile_version: str
    task_id: str
    template_path: str
    allowed_edits: Tuple[AllowedEdit, ...]
    required_outcomes: Tuple[str, ...]
    preserve_invariants: Tuple[str, ...]
    parameters: Mapping[str, str]
    required_checks: Tuple[str, ...]

    @property
    def resource(self) -> str:
        """The single Logical ID every allowed edit names (Phase 1 limit)."""
        return self.allowed_edits[0].resource

    def edit_for(self, prop: str) -> Optional[AllowedEdit]:
        for edit in self.allowed_edits:
            if edit.property == prop:
                return edit
        return None


# ---------------------------------------------------------------------------
# Strict YAML
# ---------------------------------------------------------------------------


def _strict_load(text: str) -> Any:
    loader = yaml.SafeLoader
    documents = 0
    try:
        for event in yaml.parse(text, Loader=loader):
            if isinstance(event, yaml.AliasEvent):
                raise ContractError("alias_not_allowed", "<document>")
            if isinstance(event, yaml.DocumentStartEvent):
                documents += 1
            anchor = getattr(event, "anchor", None)
            tag = getattr(event, "tag", None)
            if anchor is not None:
                raise ContractError("anchor_not_allowed", "<document>")
            if tag is not None and not isinstance(event, (yaml.DocumentStartEvent, yaml.DocumentEndEvent)):
                raise ContractError("tag_not_allowed", "<document>")
        if documents != 1:
            raise ContractError("exactly_one_document_required", "<document>")
        node = yaml.compose(text, Loader=loader)
    except ContractError:
        raise
    except yaml.YAMLError:
        raise ContractError("yaml_parse_failure", "<document>") from None
    return _construct(node)


def _construct(root: Any) -> Any:
    # Iterative with an explicit depth bound; a contract is shallow.
    def build(node: Any, depth: int) -> Any:
        if depth > 8:
            raise ContractError("too_deep", "<document>")
        if isinstance(node, yaml.MappingNode):
            out: Dict[str, Any] = {}
            for key_node, value_node in node.value:
                if not isinstance(key_node, yaml.ScalarNode) or key_node.tag != _STR_TAG:
                    raise ContractError("non_string_key", "<document>")
                if key_node.value in out:
                    raise ContractError("duplicate_key", "<document>")
                out[key_node.value] = build(value_node, depth + 1)
            return out
        if isinstance(node, yaml.SequenceNode):
            return [build(item, depth + 1) for item in node.value]
        if isinstance(node, yaml.ScalarNode):
            if node.tag != _STR_TAG:
                raise ContractError("non_string_scalar", "<document>")
            return node.value
        raise ContractError("unsupported_node", "<document>")

    return build(root, 0)


# ---------------------------------------------------------------------------
# Field checks
# ---------------------------------------------------------------------------


def _mapping(value: Any, field: str, keys: Tuple[str, ...], optional: Tuple[str, ...] = ()) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError("mapping_required", field)
    unknown = set(value) - set(keys)
    if unknown:
        raise ContractError("unknown_key", field)
    missing = set(keys) - set(optional) - set(value)
    if missing:
        raise ContractError("missing_key:" + sorted(missing)[0], field)
    return value


def _string(value: Any, field: str, pattern: "re.Pattern[str]") -> str:
    if not isinstance(value, str) or pattern.match(value) is None:
        raise ContractError("invalid_value", field)
    return value


def _string_list(value: Any, field: str, pattern: "re.Pattern[str]") -> Tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ContractError("non_empty_list_required", field)
    items = tuple(_string(item, field, pattern) for item in value)
    if len(set(items)) != len(items):
        raise ContractError("duplicate_item", field)
    return items


def is_safe_relative_path(value: Any) -> bool:
    """A repository-relative POSIX path: no traversal, no absolute, no specials."""
    if not isinstance(value, str) or not 0 < len(value) <= 1024:
        return False
    return all(seg not in ("", ".", "..") and _SEGMENT.match(seg) is not None for seg in value.split("/"))


def validate_template_path(value: Any) -> str:
    """A safe relative path with a Template suffix."""
    if not is_safe_relative_path(value):
        raise ContractError("invalid_path", "target.template_path")
    if not value.lower().endswith(_TEMPLATE_SUFFIXES):
        raise ContractError("invalid_path", "target.template_path")
    return value


def parse_contract_bytes(raw: bytes) -> Contract:
    """Parse and validate the contract schema (not yet the profile)."""
    if len(raw) > rschema.MAX_CONTRACT_BYTES:
        raise ContractError("too_large", "<document>")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ContractError("not_utf8", "<document>") from None
    if text.startswith("\ufeff"):
        text = text[1:]
    if "\x00" in text:
        raise ContractError("nul_character", "<document>")
    doc = _mapping(_strict_load(text), "<root>", _TOP_KEYS)
    if doc["contract_schema_version"] != rschema.CONTRACT_SCHEMA_VERSION:
        raise ContractError("unsupported_schema_version", "contract_schema_version")
    target = _mapping(doc["target"], "target", _TARGET_KEYS)
    scope = _mapping(doc["scope"], "scope", _SCOPE_KEYS)
    intent = _mapping(doc["intent"], "intent", _INTENT_KEYS, optional=("parameters",))
    verification = _mapping(doc["verification"], "verification", _VERIFICATION_KEYS)

    edits_raw = scope["allowed_edits"]
    if not isinstance(edits_raw, list) or not edits_raw:
        raise ContractError("non_empty_list_required", "scope.allowed_edits")
    edits: List[AllowedEdit] = []
    for item in edits_raw:
        edit = _mapping(item, "scope.allowed_edits[]", _EDIT_KEYS)
        operations = _string_list(edit["operations"], "scope.allowed_edits[].operations", re.compile(r"^(add|replace|remove)$"))
        edits.append(
            AllowedEdit(
                resource=_string(edit["resource"], "scope.allowed_edits[].resource", _LOGICAL_ID),
                property=_string(edit["property"], "scope.allowed_edits[].property", _LOGICAL_ID),
                operations=frozenset(operations),
            )
        )
    if len({e.resource for e in edits}) != 1:
        raise ContractError("one_resource_per_contract", "scope.allowed_edits")
    if len({e.property for e in edits}) != len(edits):
        raise ContractError("duplicate_property", "scope.allowed_edits")

    params_raw = intent.get("parameters", {})
    if not isinstance(params_raw, dict):
        raise ContractError("mapping_required", "intent.parameters")
    parameters: Dict[str, str] = {}
    for name, value in params_raw.items():
        if not isinstance(value, str) or not re.match(r"^[a-z][a-z0-9_]{0,63}$", name):
            raise ContractError("invalid_value", "intent.parameters")
        parameters[name] = value

    return Contract(
        contract_id=_string(doc["contract_id"], "contract_id", _ID),
        profile_id=_string(doc["profile_id"], "profile_id", _ID),
        profile_version=_string(doc["profile_version"], "profile_version", re.compile(r"^[0-9]{1,6}$")),
        task_id=_string(doc["task_id"], "task_id", _ID),
        template_path=validate_template_path(target["template_path"]),
        allowed_edits=tuple(sorted(edits, key=lambda e: e.property)),
        required_outcomes=_string_list(intent["required_outcomes"], "intent.required_outcomes", _ID),
        preserve_invariants=_string_list(intent["preserve_invariants"], "intent.preserve_invariants", _ID),
        parameters=parameters,
        required_checks=_string_list(verification["required_checks"], "verification.required_checks", _ID),
    )


def bind_profile(contract: Contract, profiles: Mapping[str, Profile]) -> Profile:
    """Check the contract against its profile; the contract may only narrow it."""
    profile = profiles.get(contract.profile_id)
    if profile is None:
        raise ContractError("unknown_profile", "profile_id", code="profile_unknown")
    if contract.profile_version != profile.profile_version:
        raise ContractError("profile_version_mismatch", "profile_version")
    for edit in contract.allowed_edits:
        permitted = profile.allowed_properties.get(edit.property)
        if permitted is None or not edit.operations <= set(permitted):
            raise ContractError("edit_not_permitted_by_profile", "scope.allowed_edits")
    if not set(contract.required_outcomes) <= set(profile.outcomes):
        raise ContractError("unknown_outcome", "intent.required_outcomes")
    if not set(contract.preserve_invariants) <= set(profile.invariants):
        raise ContractError("unknown_invariant", "intent.preserve_invariants")
    mandatory = {iid for iid, inv in profile.invariants.items() if inv.mandatory}
    if not mandatory <= set(contract.preserve_invariants):
        raise ContractError("mandatory_invariant_missing", "intent.preserve_invariants")
    if set(contract.parameters) != set(profile.parameters):
        raise ContractError("parameters_do_not_match_profile", "intent.parameters")
    for name, pattern in profile.parameters.items():
        if re.match(pattern, contract.parameters[name]) is None:
            raise ContractError("invalid_value", "intent.parameters")
    if not set(contract.required_checks) <= set(KNOWN_CHECKS):
        raise ContractError("unknown_check", "verification.required_checks")
    if not set(profile.mandatory_checks) <= set(contract.required_checks):
        raise ContractError("mandatory_check_missing", "verification.required_checks")
    return profile


def render_contract(fields: Mapping[str, Any]) -> str:
    """Render a contract mapping as YAML with every scalar double-quoted.

    Used by ``init``. Values have already been validated against the schema
    regexes, so quoting with JSON string syntax (a YAML subset) is exact.
    """
    import json

    def q(value: str) -> str:
        return json.dumps(value, ensure_ascii=True)

    lines = [
        "# DRAFT remediation contract generated by `iacreview.remediation init`.",
        "# It is not approved: commit it to the protected configuration branch",
        "# through your normal review before `verify` can return VERIFIED.",
        "contract_schema_version: {0}".format(q(rschema.CONTRACT_SCHEMA_VERSION)),
        "contract_id: {0}".format(q(fields["contract_id"])),
        "profile_id: {0}".format(q(fields["profile_id"])),
        "profile_version: {0}".format(q(fields["profile_version"])),
        "task_id: {0}".format(q(fields["task_id"])),
        "target:",
        "  template_path: {0}".format(q(fields["template_path"])),
        "scope:",
        "  allowed_edits:",
    ]
    for edit in fields["allowed_edits"]:
        lines.append("    - resource: {0}".format(q(edit["resource"])))
        lines.append("      property: {0}".format(q(edit["property"])))
        lines.append("      operations: [{0}]".format(", ".join(q(op) for op in edit["operations"])))
    lines.append("intent:")
    lines.append("  required_outcomes:")
    lines.extend("    - {0}".format(q(o)) for o in fields["required_outcomes"])
    lines.append("  preserve_invariants:")
    lines.extend("    - {0}".format(q(i)) for i in fields["preserve_invariants"])
    params = fields["parameters"]
    if params:
        lines.append("  parameters:")
        lines.extend("    {0}: {1}".format(name, q(params[name])) for name in sorted(params))
    else:
        lines.append("  parameters: {}")
    lines.append("verification:")
    lines.append("  required_checks:")
    lines.extend("    - {0}".format(q(c)) for c in fields["required_checks"])
    return "\n".join(lines) + "\n"
