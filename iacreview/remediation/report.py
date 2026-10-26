"""Remediation_Verification_Report: build, serialize, validate, summarize (Design 8).

The payload is deterministic: the same revisions, contract, profile, validator
and tool versions give the same bytes. Run metadata (time, run id, duration)
sits beside it and is never part of the payload digest.

Disclosure: one mode (redacted). A key or a repository path is written as it is
only when it is trusted (named by the contract, or a closed CloudFormation
vocabulary); anything else becomes ``k:`` / ``p:`` plus 12 hex digits of its
SHA-256. No Template value, tool output, traceback or contract text is written.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from iacreview.remediation import rschema
from iacreview.remediation.verify import Result

PAYLOAD_KEYS: Tuple[str, ...] = (
    "decision",
    "exit_code",
    "task_outcome",
    "next_action",
    "execution_mode",
    "enforcement_status",
    "runtime_validated",
    "preview_only",
    "stage_reached",
    "subject",
    "trust",
    "validator",
    "tools",
    "violations",
    "diagnostics",
    "outcomes",
    "invariants",
    "checks",
    "not_verified",
    "snapshot_notes",
)
REPORT_KEYS: Tuple[str, ...] = ("report_kind", "report_schema_version", "payload", "metadata")
METADATA_KEYS: Tuple[str, ...] = ("generated_at", "run_id", "duration_ms", "payload_sha256")

_PLUGIN_ROOT = Path(__file__).resolve().parents[2]


def _token(prefix: str, text: str) -> str:
    return prefix + hashlib.sha256(text.encode("utf-8", "surrogateescape")).hexdigest()[:12]


def _display_template_path(path: Sequence[object], trusted: frozenset) -> List[object]:
    out: List[object] = []
    for index, item in enumerate(path):
        if isinstance(item, int) and not isinstance(item, bool):
            out.append(item)
        elif isinstance(item, str) and (
            (index == 0 and item in rschema.DISPLAYABLE_SECTIONS)
            or (index == 2 and item in rschema.DISPLAYABLE_KEYS)
            or item in trusted
        ):
            out.append(item)
        else:
            out.append(_token("k:", str(item)))
    return out


def _display(finding_path: Sequence[object], scope: str, trusted: frozenset, target: Optional[str]) -> List[object]:
    if scope == "repository":
        return [p if p == target else _token("p:", str(p)) for p in finding_path]
    if scope == "template":
        return _display_template_path(finding_path, trusted)
    # verification / trust / check / outcome / invariant / contract / git paths
    # hold schema words or profile identifiers only.
    return [p for p in finding_path if isinstance(p, str) and re.match(r"^[A-Za-z0-9_.:<>\[\]-]{1,64}$", p)]


def validator_identity() -> Dict[str, Any]:
    """Digest of the validator code and data that decided (iacreview/**)."""
    root = _PLUGIN_ROOT / "iacreview"
    h = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix in (".py", ".json", ".guard") and "__pycache__" not in path.parts:
            rel = path.relative_to(_PLUGIN_ROOT).as_posix()
            h.update(rel.encode("utf-8") + b"\x00" + hashlib.sha256(path.read_bytes()).hexdigest().encode("ascii") + b"\n")
    version = None
    try:
        version = json.loads((_PLUGIN_ROOT / "plugin.json").read_text(encoding="utf-8")).get("version")
    except (OSError, ValueError):
        version = None
    return {
        "name": "aws-iac-review-agent-plugin/iacreview.remediation",
        "plugin_version": version if isinstance(version, str) else None,
        "source_sha256": h.hexdigest(),
        "python": "{0}.{1}".format(sys.version_info[0], sys.version_info[1]),
    }


def build_payload(res: Result) -> Dict[str, Any]:
    contract = res.contract
    profile = res.profile
    target = contract.template_path if contract else None
    trusted: frozenset = frozenset()
    if contract is not None:
        trusted = frozenset({contract.resource} | {e.property for e in contract.allowed_edits})
    violations: List[Dict[str, Any]] = []
    diagnostics: List[Dict[str, Any]] = []
    for f in res.findings:
        entry = {
            "code": f.code,
            "scope": f.scope,
            "path": _display(f.path, f.scope, trusted, target),
            "detail": f.detail if f.detail is None or re.match(r"^[a-z0-9_:]{1,64}$", f.detail) else None,
            "forces": rschema.CODES[f.code][0],
        }
        (violations if entry["forces"] == rschema.BLOCKED else diagnostics).append(entry)
    order = {code: i for i, code in enumerate(rschema.CODES)}

    def key(e: Dict[str, Any]) -> Tuple[int, str, str]:
        return (order[e["code"]], e["scope"], json.dumps(e["path"]))

    violations.sort(key=key)
    diagnostics.sort(key=key)
    trust: Dict[str, Any] = {
        "contract_source": res.contract_source,
        "approved": res.contract_source == "git_revision" and res.stage_reached not in ("start", "contract_loaded"),
        "approval_binding": "config_commit_is_ancestor_of_base" if res.contract_source == "git_revision" else None,
        "trusted_config_commit": res.config_commit,
        "contract_path": res.request.contract_path if res.contract_source == "git_revision" and contract else None,
        "contract_sha256": res.contract_sha256,
        "contract_id": contract.contract_id if contract else None,
        "task_id": contract.task_id if contract else None,
        "profile_id": profile.profile_id if profile else None,
        "profile_version": profile.profile_version if profile else None,
        "profile_sha256": profile.digest if profile else None,
        "rules": [{"file": profile.rules_path.name, "sha256": profile.rules_sha256}] if profile else [],
        "allowed_edits": [
            {"resource": e.resource, "property": e.property, "operations": sorted(e.operations)}
            for e in (contract.allowed_edits if contract else ())
        ],
    }
    subject = {
        "repository_id": res.request.repository_id,
        "base": {"commit": res.base.commit, "tree": res.base.tree, "snapshot_sha256": res.base.snapshot_sha256},
        "head": {
            "kind": res.head.kind,
            "commit": res.head.commit,
            "tree": res.head.tree,
            "snapshot_sha256": res.head.snapshot_sha256,
        },
        "target_template": {
            "path": target,
            "base_blob": res.base.blob,
            "head_blob": res.head.blob,
            "base_sha256": res.base.template_sha256,
            "head_sha256": res.head.template_sha256,
            "head_format": res.head.template_format,
        },
    }
    decision = res.decision
    return {
        "decision": decision,
        "exit_code": rschema.DECISION_EXIT_CODES[decision],
        "task_outcome": res.task_outcome,
        "next_action": rschema.NEXT_ACTIONS[decision],
        "execution_mode": res.request.execution_mode,
        "enforcement_status": "not_verified",
        "runtime_validated": False,
        "preview_only": res.contract_source != "git_revision",
        "stage_reached": res.stage_reached,
        "subject": subject,
        "trust": trust,
        "validator": validator_identity(),
        "tools": [t.as_dict() for t in res.tools],
        "violations": violations,
        "diagnostics": diagnostics,
        "outcomes": res.outcomes,
        "invariants": res.invariants,
        "checks": sorted((r.as_dict() for r in res.check_runs), key=lambda d: (d["check_id"], d["side"])),
        "not_verified": list(rschema.NOT_VERIFIED),
        "snapshot_notes": sorted(n for n in res.snapshot_notes if re.match(r"^[a-z_]+(:[0-9a-f]{40,64})?$", n)),
    }


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def build_report(res: Result, started: float) -> Dict[str, Any]:
    payload = build_payload(res)
    assert tuple(payload) == PAYLOAD_KEYS
    return {
        "report_kind": rschema.REPORT_KIND,
        "report_schema_version": rschema.REPORT_SCHEMA_VERSION,
        "payload": payload,
        "metadata": {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "run_id": os.environ.get("IACREVIEW_RUN_ID") if re.match(r"^[0-9]{1,20}(-[0-9]{1,6})?$", os.environ.get("IACREVIEW_RUN_ID", "")) else str(uuid.uuid4()),
            "duration_ms": int((time.monotonic() - started) * 1000),
            "payload_sha256": hashlib.sha256(canonical(payload)).hexdigest(),
        },
    }


def serialize(report: Mapping[str, Any]) -> str:
    return json.dumps(report, sort_keys=True, ensure_ascii=True, indent=2) + "\n"


# ---------------------------------------------------------------------------
# Validation (used by explain)
# ---------------------------------------------------------------------------


class ReportError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def validate(obj: Any) -> Dict[str, Any]:
    """Check the report shape. Shape only: it does not authenticate the report."""
    if not isinstance(obj, dict) or tuple(sorted(obj)) != tuple(sorted(REPORT_KEYS)):
        raise ReportError("report_keys")
    if obj["report_kind"] != rschema.REPORT_KIND or obj["report_schema_version"] != rschema.REPORT_SCHEMA_VERSION:
        raise ReportError("report_kind")
    payload, metadata = obj["payload"], obj["metadata"]
    if not isinstance(payload, dict) or sorted(payload) != sorted(PAYLOAD_KEYS):
        raise ReportError("payload_keys")
    if not isinstance(metadata, dict) or sorted(metadata) != sorted(METADATA_KEYS):
        raise ReportError("metadata_keys")
    if payload["decision"] not in rschema.DECISION_EXIT_CODES:
        raise ReportError("decision")
    if payload["exit_code"] != rschema.DECISION_EXIT_CODES[payload["decision"]]:
        raise ReportError("exit_code")
    if payload["task_outcome"] not in rschema.TASK_OUTCOMES or payload["execution_mode"] not in rschema.EXECUTION_MODES:
        raise ReportError("vocabulary")
    if payload["next_action"] != rschema.NEXT_ACTIONS[payload["decision"]] or payload["runtime_validated"] is not False:
        raise ReportError("vocabulary")
    for entry in list(payload["violations"]) + list(payload["diagnostics"]):
        if not isinstance(entry, dict) or entry.get("code") not in rschema.CODES:
            raise ReportError("codes")
    if hashlib.sha256(canonical(payload)).hexdigest() != metadata["payload_sha256"]:
        raise ReportError("payload_sha256")
    return obj


# ---------------------------------------------------------------------------
# Human Summary
# ---------------------------------------------------------------------------


def _path_text(path: Sequence[object]) -> str:
    return ".".join("[{0}]".format(p) if isinstance(p, int) else str(p) for p in path) or "-"


def summary(report: Mapping[str, Any]) -> str:
    p = report["payload"]
    lines = [
        "Remediation verification: {0}".format(p["decision"]),
        "  task outcome:      {0}".format(p["task_outcome"]),
        "  execution mode:    {0} (merge enforcement: {1})".format(p["execution_mode"], p["enforcement_status"]),
        "  contract:          {0} ({1}), profile {2}".format(
            p["trust"]["contract_id"], "approved revision" if p["trust"]["approved"] else "NOT approved", p["trust"]["profile_id"]
        ),
        "  base / head:       {0} / {1}".format(
            p["subject"]["base"]["commit"] or "-",
            p["subject"]["head"]["commit"] or ("worktree " + (p["subject"]["head"]["snapshot_sha256"] or "-")[:12]),
        ),
    ]
    if p["preview_only"]:
        lines.append("  NOTE: preview only. The contract was not read from a trusted revision; nothing below is a verdict.")
    if p["violations"]:
        lines.append("Violations (what is wrong):")
        for v in p["violations"]:
            lines.append("  - {0}: {1} at {2}".format(v["code"], rschema.CODES[v["code"]][1], _path_text(v["path"])))
    if p["diagnostics"]:
        lines.append("Missing or invalid evidence (what was not verified):")
        for d in p["diagnostics"]:
            where = _path_text(d["path"])
            lines.append("  - {0}: {1}{2}".format(d["code"], rschema.CODES[d["code"]][1], "" if where == "-" else " (" + where + ")"))
    if p["outcomes"]:
        lines.append("Outcomes (base -> head):")
        lines.extend("  - {0}: {1} -> {2}".format(o["outcome_id"], o["base"], o["head"]) for o in p["outcomes"])
    if p["invariants"]:
        lines.append("Invariants (base -> head):")
        lines.extend("  - {0}: {1} -> {2}".format(i["invariant_id"], i["base"], i["head"]) for i in p["invariants"])
    if p["checks"]:
        lines.append("Checks:")
        lines.extend("  - {0} [{1}]: {2}".format(c["check_id"], c["side"], c["state"]) for c in p["checks"])
    lines.append("Not verified by Phase 1: " + ", ".join(p["not_verified"]))
    lines.append("Next action ({0}): {1}".format(p["next_action"], rschema.NEXT_ACTION_TEXT[p["next_action"]]))
    lines.append("Paths shown as k:/p: plus 12 hex digits are redacted keys and file paths (SHA-256 prefix).")
    return "\n".join(lines) + "\n"
