"""The Profiles shipped with the verifier, and their Guard rules.

A Profile is plugin-owned data under ``iacreview/remediation/profiles/<id>/``:
``profile.json`` (what a contract may allow, which outcomes and invariants
exist, which tool versions are pinned) and ``rules.guard``. Profiles are part
of the validator: a candidate repository cannot supply or change one, because
nothing here reads from the repository under verification.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Mapping, Optional, Tuple

from iacreview.remediation import rschema

PROFILES_DIR = Path(__file__).resolve().parent / "profiles"
PROFILE_FILE = "profile.json"
RULES_FILE = "rules.guard"

_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_RULE_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_PROFILE_KEYS = frozenset(
    (
        "profile_id",
        "profile_version",
        "title",
        "resource_type",
        "allowed_properties",
        "outcomes",
        "invariants",
        "parameters",
        "mandatory_checks",
        "tools",
        "init",
    )
)
KNOWN_CHECKS: Tuple[str, ...] = ("cfn-lint", "profile-guard")
INVARIANT_KINDS: Tuple[str, ...] = ("boundary", "statement")


class ProfileError(Exception):
    """A shipped profile is malformed. A validator defect, not a user error."""


@dataclass(frozen=True)
class Invariant:
    invariant_id: str
    kind: str
    guard_rule: Optional[str]
    mandatory: bool


@dataclass(frozen=True)
class Profile:
    profile_id: str
    profile_version: str
    title: str
    resource_type: str
    allowed_properties: Mapping[str, Tuple[str, ...]]
    outcomes: Mapping[str, str]  # outcome id -> guard rule name
    invariants: Mapping[str, Invariant]
    parameters: Mapping[str, str]  # parameter name -> regex
    mandatory_checks: Tuple[str, ...]
    tools: Mapping[str, str]  # tool -> pinned version
    init: Mapping[str, object]
    rules_path: Path
    profile_sha256: str
    rules_sha256: str

    @property
    def digest(self) -> str:
        """One digest over the profile document and its rule file."""
        return hashlib.sha256(
            "{0}\n{1}\n".format(self.profile_sha256, self.rules_sha256).encode("ascii")
        ).hexdigest()


def _need(cond: bool, message: str) -> None:
    if not cond:
        raise ProfileError(message)


def _load(directory: Path) -> Profile:
    profile_bytes = (directory / PROFILE_FILE).read_bytes()
    rules_bytes = (directory / RULES_FILE).read_bytes()
    doc = json.loads(profile_bytes.decode("utf-8"))
    _need(isinstance(doc, dict) and set(doc) == _PROFILE_KEYS, "profile keys")
    pid = doc["profile_id"]
    _need(isinstance(pid, str) and _ID.match(pid) is not None and pid == directory.name, "profile_id")
    allowed = doc["allowed_properties"]
    _need(isinstance(allowed, dict) and bool(allowed), "allowed_properties")
    for name, ops in allowed.items():
        _need(isinstance(ops, list) and bool(ops) and set(ops) <= set(rschema.OPERATIONS), name)
    outcomes = doc["outcomes"]
    _need(isinstance(outcomes, dict) and bool(outcomes), "outcomes")
    rules_text = rules_bytes.decode("utf-8")
    declared = set(re.findall(r"^rule\s+([a-z][a-z0-9_]*)\s*\{", rules_text, flags=re.M))
    outcome_rules: Dict[str, str] = {}
    for oid, spec in outcomes.items():
        rule = spec.get("guard_rule") if isinstance(spec, dict) else None
        if not (_ID.match(oid) is not None and isinstance(rule, str) and rule in declared):
            raise ProfileError(oid)
        outcome_rules[oid] = rule
    invariants: Dict[str, Invariant] = {}
    for iid, spec in doc["invariants"].items():
        _need(_ID.match(iid) is not None and isinstance(spec, dict), iid)
        kind = spec.get("kind")
        rule = spec.get("guard_rule")
        _need(kind in INVARIANT_KINDS, iid)
        _need((kind == "boundary") == (rule is None), iid)
        _need(rule is None or rule in declared, iid)
        invariants[iid] = Invariant(iid, kind, rule, bool(spec.get("mandatory")))
    _need(any(inv.kind == "boundary" and inv.mandatory for inv in invariants.values()), "boundary invariant")
    parameters = {}
    for name, spec in doc["parameters"].items():
        _need(_RULE_NAME.match(name) is not None and isinstance(spec.get("pattern"), str), name)
        parameters[name] = spec["pattern"]
    checks = tuple(doc["mandatory_checks"])
    _need(set(checks) == set(KNOWN_CHECKS), "mandatory_checks")
    tools = doc["tools"]
    _need(set(tools) == {"cfn-lint", "cfn-guard"}, "tools")
    return Profile(
        profile_id=pid,
        profile_version=str(doc["profile_version"]),
        title=str(doc["title"]),
        resource_type=str(doc["resource_type"]),
        allowed_properties={k: tuple(v) for k, v in sorted(allowed.items())},
        outcomes=outcome_rules,
        invariants=invariants,
        parameters=parameters,
        mandatory_checks=checks,
        tools=dict(tools),
        init=doc["init"],
        rules_path=directory / RULES_FILE,
        profile_sha256=hashlib.sha256(profile_bytes).hexdigest(),
        rules_sha256=hashlib.sha256(rules_bytes).hexdigest(),
    )


def load_all() -> Dict[str, Profile]:
    """Every shipped profile, by id. Raises ProfileError on a malformed one."""
    found: Dict[str, Profile] = {}
    for directory in sorted(p for p in PROFILES_DIR.iterdir() if p.is_dir() and not p.name.startswith("_")):
        if not (directory / PROFILE_FILE).is_file():
            continue
        try:
            profile = _load(directory)
        except (OSError, ValueError, KeyError, AttributeError, TypeError) as exc:
            raise ProfileError(directory.name) from exc
        found[profile.profile_id] = profile
    return found


def get(profile_id: str) -> Optional[Profile]:
    return load_all().get(profile_id)
