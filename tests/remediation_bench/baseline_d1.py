"""Configuration D1: the Phase 1 contract and evidence conditions, hand-built.

The comparison baseline asked for after the first evaluation: what a team has
to write to get the same acceptance conditions as Phase 1 from git, PyYAML,
cfn-lint and cfn-guard, with no line limit. It reads the same approved
contract from the same trusted revision and evaluates the same profile Guard
rules on the same projection. It does not import ``iacreview``.

Exit codes follow Phase 1 so the runner can compare them: 0 accept, 20 a
definite violation, 21 evidence missing or incomplete, 22 invalid input.

Conditions implemented (each is a Phase 1 condition):
 1. revisions resolve; config is an ancestor of Base; Base of Head
 2. contract read from the config revision only; strict YAML (no aliases,
    tags, duplicate keys, unknown keys); fields validated
 3. whole-tree comparison of (mode, object id) outside the target; target a
    regular non-executable file on both sides
 4. both Templates parsed with duplicate-key rejection (YAML and JSON),
    CloudFormation tags normalized to their long form
 5. Resource set, Types and everything outside the allowed properties equal;
    property-level operations checked against the contract; Fn::If in an
    allowed property, a Transform, or a contract Resource missing in Base is
    "incomplete"
 6. exact tool versions; per-call timeout and output limit
 7. cfn-lint on Head: JSON parsed, exit code consistent, Error = violation
 8. cfn-guard on Base and Head projections: one record, rule names per
    status, SKIP / not evaluated = incomplete
 9. outcome Base/Head, invariant Base/Head, required statement equality
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Tuple

import yaml

ACCEPT, VIOLATION, INCOMPLETE, INVALID = 0, 20, 21, 22
PROFILES = Path(__file__).resolve().parents[2] / "iacreview" / "remediation" / "profiles"
TOOLS = {"cfn-lint": "1.46.0", "cfn-guard": "3.2.1"}
TIMEOUT_S = 60
MAX_OUTPUT = 8 * 1024 * 1024
GIT = ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "protocol.allow=never", "--no-pager"]
#: The same per-profile facts Phase 1 ships (resource type, permitted
#: operations, rule names), written out by hand.
PROFILE = {
    "dynamodb-billing-mode-v1": {
        "type": "AWS::DynamoDB::Table",
        "ops": {"BillingMode": {"add", "replace"}, "ProvisionedThroughput": {"add", "replace", "remove"}},
        "outcomes": {"billing-mode-consistent": "billing_mode_consistent"},
        "invariants": {"outside-allowed-edits-unchanged": None},
        "params": {},
    },
    "iam-inline-policy-overbroad-v1": {
        "type": "AWS::IAM::Role",
        "ops": {"Policies": {"replace"}},
        "outcomes": {"no-overbroad-allow-statement": "no_overbroad_allow_statement"},
        "invariants": {"outside-allowed-edits-unchanged": None, "required-statement-preserved": "required_statement_present"},
        "params": {"required_statement_sid": r"^[A-Za-z0-9]{1,128}$"},
    },
}


class Stop(Exception):
    def __init__(self, code: int) -> None:
        super().__init__(code)
        self.code = code


# ---------------------------------------------------------------------------
# git
# ---------------------------------------------------------------------------


def git(repo: str, *args: str, ok: Tuple[int, ...] = (0,)) -> Tuple[int, bytes]:
    try:
        out = subprocess.run([*GIT, "-C", repo, *args], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=TIMEOUT_S, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Stop(INVALID) from None
    if out.returncode not in ok:
        raise Stop(INVALID)
    return out.returncode, out.stdout


def commit(repo: str, rev: str) -> str:
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._/@^~-]{0,254}$", rev) or ".." in rev:
        raise Stop(INVALID)
    return git(repo, "rev-parse", "--verify", "--quiet", "--end-of-options", rev + "^{commit}")[1].decode().strip()


def is_ancestor(repo: str, a: str, b: str) -> bool:
    return git(repo, "merge-base", "--is-ancestor", a, b, ok=(0, 1))[0] == 0


def tree(repo: str, rev: str) -> Dict[bytes, Tuple[bytes, bytes]]:
    entries = {}
    for rec in git(repo, "ls-tree", "-r", "-z", "--full-tree", rev)[1].split(b"\0"):
        if rec:
            head, _, path = rec.partition(b"\t")
            mode, _, oid = head.split(b" ")
            entries[path] = (mode, oid)
    return entries


def blob(repo: str, oid: bytes) -> bytes:
    return git(repo, "cat-file", "blob", oid.decode())[1]


# ---------------------------------------------------------------------------
# YAML with duplicate-key rejection and CloudFormation tags
# ---------------------------------------------------------------------------


class StrictLoader(yaml.SafeLoader):
    pass


def _mapping(loader: StrictLoader, node: yaml.MappingNode, deep: bool = False) -> Dict[Any, Any]:
    out: Dict[Any, Any] = {}
    for key_node, value_node in node.value:
        if key_node.tag == "tag:yaml.org,2002:merge":
            raise Stop(INCOMPLETE)
        key = loader.construct_object(key_node, deep=True)
        if not isinstance(key, str) or key in out:
            raise Stop(INCOMPLETE)
        out[key] = loader.construct_object(value_node, deep=True)
    return out


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def _cfn_tag(loader: StrictLoader, suffix: str, node: yaml.Node) -> Dict[str, Any]:
    name = "Ref" if suffix == "Ref" else "Fn::" + suffix
    if isinstance(node, yaml.ScalarNode):
        value: Any = loader.construct_scalar(node)
        if suffix == "GetAtt" and isinstance(value, str):
            value = value.split(".", 1)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    else:
        value = _mapping(loader, node)
    return {name: value}


StrictLoader.add_multi_constructor("!", _cfn_tag)


def load_template(data: bytes) -> Any:
    text = data.decode("utf-8")
    if text.lstrip().startswith("{"):
        def hook(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
            out: Dict[str, Any] = {}
            for k, v in pairs:
                if k in out:
                    raise Stop(INCOMPLETE)
                out[k] = v
            return out

        return json.loads(text, object_pairs_hook=hook)
    for event in yaml.parse(text, Loader=yaml.SafeLoader):
        if isinstance(event, yaml.AliasEvent):
            raise Stop(INCOMPLETE)  # no alias expansion: fan-out and cycles stop here
    return yaml.load(text, Loader=StrictLoader)


def canon(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str)


# ---------------------------------------------------------------------------
# Contract
# ---------------------------------------------------------------------------


def load_contract(raw: bytes) -> Dict[str, Any]:
    text = raw.decode("utf-8")
    for event in yaml.parse(text, Loader=yaml.SafeLoader):
        if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None) or (getattr(event, "tag", None) and not isinstance(event, yaml.DocumentStartEvent)):
            raise Stop(INVALID)
    try:
        doc = yaml.load(text, Loader=StrictLoader)
    except Stop:
        raise Stop(INVALID) from None
    top = {"contract_schema_version", "contract_id", "profile_id", "profile_version", "task_id", "target", "scope", "intent", "verification"}
    if not isinstance(doc, dict) or set(doc) != top or doc["contract_schema_version"] != "0.1.0":
        raise Stop(INVALID)
    prof = PROFILE.get(doc["profile_id"])
    path = doc["target"].get("template_path") if isinstance(doc["target"], dict) else None
    if prof is None or not isinstance(path, str) or any(seg in ("", ".", "..") for seg in path.split("/")) or path.startswith("/"):
        raise Stop(INVALID)
    edits = doc["scope"].get("allowed_edits") if isinstance(doc["scope"], dict) else None
    if not isinstance(edits, list) or not edits or len({e.get("resource") for e in edits}) != 1:
        raise Stop(INVALID)
    for e in edits:
        if set(e) != {"resource", "property", "operations"} or not set(e["operations"]) <= prof["ops"].get(e["property"], set()):
            raise Stop(INVALID)
    intent = doc["intent"]
    params = intent.get("parameters") or {}
    if set(params) != set(prof["params"]) or any(not re.match(prof["params"][k], v) for k, v in params.items()):
        raise Stop(INVALID)
    if not set(intent["required_outcomes"]) <= set(prof["outcomes"]) or not set(prof["invariants"]) <= set(intent["preserve_invariants"]):
        raise Stop(INVALID)
    if set(doc["verification"]["required_checks"]) != {"cfn-lint", "profile-guard"}:
        raise Stop(INVALID)
    doc["_profile"] = prof
    return doc


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


def tool(argv: List[str]) -> Tuple[int, bytes]:
    try:
        out = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, timeout=TIMEOUT_S, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Stop(INCOMPLETE) from None
    if len(out.stdout) + len(out.stderr) > MAX_OUTPUT or out.returncode < 0:
        raise Stop(INCOMPLETE)
    return out.returncode, out.stdout


def check_versions() -> None:
    for name, version in TOOLS.items():
        code, out = tool([name, "--version"])
        found = re.search(r"\d+\.\d+\.\d+", out.decode("utf-8", "replace"))
        if code != 0 or not found or found.group(0) != version:
            raise Stop(INCOMPLETE)


def lint(head: bytes) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "head.template"
        path.write_bytes(head)
        code, out = tool(["cfn-lint", "-f", "json", "-c", "I", "--", str(path)])
    if code not in (0, 2, 4, 6, 8, 10, 12, 14):
        raise Stop(INCOMPLETE)
    try:
        results = json.loads(out)
        levels = [r["Level"] for r in results]
    except (ValueError, KeyError, TypeError):
        raise Stop(INCOMPLETE) from None
    if bool(code & 2) != ("Error" in levels) or (code == 0) != (not results):
        raise Stop(INCOMPLETE)
    if "Error" in levels:
        raise Stop(VIOLATION)


def guard(rules: Path, doc: Any, resource: str, params: Dict[str, str], names: List[str]) -> Dict[str, str]:
    data = {"Params": params, "Target": (doc.get("Resources") or {}).get(resource, {})}
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "data.json"
        path.write_text(canon(data), encoding="utf-8")
        code, out = tool(["cfn-guard", "validate", "--data", str(path), "--rules", str(rules), "--output-format", "json", "--show-summary", "none"])
    if code not in (0, 19):
        raise Stop(INCOMPLETE)
    try:
        rec = json.loads(out)
        failed = {e["Rule"]["name"] for e in rec["not_compliant"]}
        passed, skipped = set(rec["compliant"]), set(rec["not_applicable"])
    except (ValueError, KeyError, TypeError):
        raise Stop(INCOMPLETE) from None
    if (code == 19) != bool(failed) or failed & passed or failed & skipped or passed & skipped:
        raise Stop(INCOMPLETE)
    return {n: "FAIL" if n in failed else "PASS" if n in passed else "SKIP" for n in names}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def has_if(value: Any) -> bool:
    if isinstance(value, dict):
        return "Fn::If" in value or any(has_if(v) for v in value.values())
    if isinstance(value, list):
        return any(has_if(v) for v in value)
    return False


def statements(doc: Any, resource: str, sid: str) -> List[str]:
    found = []
    try:
        policies = doc["Resources"][resource]["Properties"]["Policies"]
    except (KeyError, TypeError):
        return found
    for policy in policies if isinstance(policies, list) else []:
        stmts = (policy.get("PolicyDocument") or {}).get("Statement") if isinstance(policy, dict) else None
        for st in stmts if isinstance(stmts, list) else [stmts] if isinstance(stmts, dict) else []:
            if isinstance(st, dict) and st.get("Sid") == sid:
                found.append(canon(st))
    return found


def verify(a: argparse.Namespace) -> int:
    repo = a.repo
    base, head, config = commit(repo, a.base), commit(repo, a.head), commit(repo, a.config_rev)
    if not is_ancestor(repo, config, base) or not is_ancestor(repo, base, head):
        return INCOMPLETE
    ctree = tree(repo, config)
    entry = ctree.get(a.contract.encode())
    if entry is None or entry[0] != b"100644":
        return INVALID
    contract = load_contract(blob(repo, entry[1]))
    prof = contract["_profile"]
    target = contract["target"]["template_path"].encode()
    resource = contract["scope"]["allowed_edits"][0]["resource"]
    allowed = {e["property"]: set(e["operations"]) for e in contract["scope"]["allowed_edits"]}
    btree, htree = tree(repo, base), tree(repo, head)
    for path in set(btree) | set(htree):
        if path != target and btree.get(path) != htree.get(path):
            return VIOLATION
    if btree.get(target, (b"",))[0] != b"100644":
        return INVALID
    if htree.get(target, (b"",))[0] != b"100644":
        return VIOLATION
    base_bytes, head_bytes = blob(repo, btree[target][1]), blob(repo, htree[target][1])
    try:
        bdoc, hdoc = load_template(base_bytes), load_template(head_bytes)
    except (UnicodeDecodeError, ValueError, yaml.YAMLError):
        return INCOMPLETE
    if not (isinstance(bdoc, dict) and isinstance(hdoc, dict)) or "Transform" in bdoc or "Transform" in hdoc:
        return INCOMPLETE
    bres, hres = bdoc.get("Resources") or {}, hdoc.get("Resources") or {}
    if not isinstance(bres.get(resource), dict) or bres[resource].get("Type") != prof["type"]:
        return INCOMPLETE
    if set(bres) != set(hres) or any(canon(bres[k].get("Type")) != canon(hres[k].get("Type")) for k in bres if isinstance(hres.get(k), dict)):
        return VIOLATION
    stripped = []
    for doc in (bdoc, hdoc):
        doc = copy.deepcopy(doc)
        props = doc["Resources"][resource].get("Properties")
        if not isinstance(props, dict):
            return VIOLATION
        for prop in allowed:
            props.pop(prop, None)
        stripped.append(canon(doc))
    if stripped[0] != stripped[1]:
        return VIOLATION
    bprops, hprops = bres[resource]["Properties"], hres[resource]["Properties"]
    for prop, ops in allowed.items():
        b, h = prop in bprops, prop in hprops
        if not b and not h or (b and h and canon(bprops[prop]) == canon(hprops[prop])):
            continue
        op = "replace" if b and h else "add" if h else "remove"
        if op not in ops:
            return VIOLATION
        if has_if(bprops.get(prop)) or has_if(hprops.get(prop)):
            return INCOMPLETE
    check_versions()
    rules = PROFILES / contract["profile_id"] / "rules.guard"
    params = contract["intent"].get("parameters") or {}
    outcome_rules = [prof["outcomes"][o] for o in contract["intent"]["required_outcomes"]]
    inv_rules = [r for i, r in prof["invariants"].items() if r and i in contract["intent"]["preserve_invariants"]]
    names = outcome_rules + inv_rules
    bstate = guard(rules, bdoc, resource, params, names)
    hstate = guard(rules, hdoc, resource, params, names)
    lint(head_bytes)
    if any(s == "SKIP" for s in list(bstate.values()) + list(hstate.values())):
        return INCOMPLETE
    for rule in inv_rules:
        if bstate[rule] != "PASS":
            return INCOMPLETE
        sid = params.get("required_statement_sid", "")
        if hstate[rule] != "PASS" or statements(bdoc, resource, sid) != statements(hdoc, resource, sid) or len(statements(bdoc, resource, sid)) != 1:
            return VIOLATION
    if any(hstate[r] != "PASS" for r in outcome_rules):
        return VIOLATION
    return ACCEPT


def main() -> int:
    p = argparse.ArgumentParser()
    for name in ("--repo", "--base", "--head", "--config-rev", "--contract"):
        p.add_argument(name, required=True)
    try:
        return verify(p.parse_args())
    except Stop as stop:
        return stop.code
    except Exception:  # noqa: BLE001 - fail closed
        return INVALID


if __name__ == "__main__":
    sys.exit(main())
