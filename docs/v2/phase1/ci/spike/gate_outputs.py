#!/usr/bin/env python3
"""SPIKE PROTOTYPE (not deployed): turn the verifier's report into the verify job's outputs.

Runs in the verify job of ``remediation-gate-app.yml`` right after
``python3 -m iacreview.remediation verify``. The publisher job never reads the
report; it reads only the outputs written here, so these outputs must say
what the report says and nothing else.

The outputs are taken from the report, not from the workflow's own inputs:
the verified head is the report's ``subject.head.commit``, the decision and
exit code are the report's, and the digest is recomputed from the payload.
Then they are cross-checked against what the workflow asked for (base, head,
trusted contract path, ``trusted_ci``, git-revision contract) and against the
verifier's process exit status. Any disagreement, a missing or oversized
report, or invalid JSON writes **empty** outputs (the publisher then
publishes ``failure``) and exits 1.

Inputs (environment, all required):
    REPORT_PATH            the report written by ``verify --output``
    VERIFY_STATUS          the verifier's process exit status
    EXPECTED_BASE_SHA      github.event.pull_request.base.sha
    EXPECTED_HEAD_SHA      github.event.pull_request.head.sha
    EXPECTED_CONTRACT_PATH the trusted contract path
    GITHUB_OUTPUT          set by the runner

Outputs: ``exit_code``, ``decision``, ``head_sha``, ``payload_sha256``.

Exit status: the verifier's exit status when the report is consistent
(0 only for VERIFIED); 1 otherwise. Standard library only; it does not import
``iacreview`` so that the check does not depend on the code it checks.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, Tuple

# Always used with fullmatch: with re.match, "$" also accepts a trailing "\n".
SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
DECISION_EXIT_CODES = {"VERIFIED": 0, "BLOCKED": 20, "UNVERIFIED": 21, "ERROR": 22}
REPORT_KIND = "remediation_verification"
MAX_REPORT_BYTES = 8 * 1024 * 1024
OUTPUT_KEYS = ("exit_code", "decision", "head_sha", "payload_sha256")


def canonical(obj: Any) -> bytes:
    """Same serialization as ``iacreview.remediation.report.canonical``."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def _get(obj: Any, *path: str) -> Any:
    for key in path:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def load_report(path: str) -> Tuple[Dict[str, Any], List[str]]:
    if not path:
        return {}, ["REPORT_PATH not set"]
    p = Path(path)
    try:
        if p.is_symlink() or not p.is_file():
            return {}, ["report missing or not a regular file"]
        if p.stat().st_size > MAX_REPORT_BYTES:
            return {}, ["report larger than {0} bytes".format(MAX_REPORT_BYTES)]
        data = json.loads(p.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return {}, ["report unreadable or not JSON"]
    if not isinstance(data, dict):
        return {}, ["report is not a JSON object"]
    return data, []


def extract(env: Mapping[str, str]) -> Tuple[Dict[str, str], List[str], int]:
    """(outputs, problems, exit status). Outputs are empty when there is any problem."""
    report, problems = load_report(env.get("REPORT_PATH", ""))
    status = env.get("VERIFY_STATUS", "")
    if not re.fullmatch(r"^[0-9]{1,3}$", status):
        problems.append("VERIFY_STATUS missing or malformed")
    for name in ("EXPECTED_BASE_SHA", "EXPECTED_HEAD_SHA"):
        if not SHA.fullmatch(env.get(name, "")):
            problems.append("{0} missing or malformed".format(name))
    if not env.get("EXPECTED_CONTRACT_PATH"):
        problems.append("EXPECTED_CONTRACT_PATH not set")
    if report:
        payload = report.get("payload")
        if report.get("report_kind") != REPORT_KIND or not isinstance(payload, dict):
            problems.append("not a remediation verification report")
            payload = {}
        digest = _get(report, "metadata", "payload_sha256")
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
            problems.append("payload digest missing or malformed")
        elif hashlib.sha256(canonical(payload)).hexdigest() != digest:
            problems.append("payload digest does not match the payload")
        decision = payload.get("decision")
        if decision not in DECISION_EXIT_CODES:
            problems.append("decision missing or unknown")
        elif payload.get("exit_code") != DECISION_EXIT_CODES[decision]:
            problems.append("report exit_code does not match its decision")
        elif status != str(DECISION_EXIT_CODES[decision]):
            problems.append("verifier exit status {0} does not match the report's decision".format(status or "missing"))
        if payload.get("execution_mode") != "trusted_ci" or payload.get("preview_only") is not False:
            problems.append("report is not a trusted_ci run on a git-revision contract")
        if decision == "VERIFIED":
            # A VERIFIED report must be bound to exactly what was asked for.
            if _get(payload, "subject", "head", "kind") != "commit":
                problems.append("head is not a commit")
            if _get(payload, "subject", "head", "commit") != env.get("EXPECTED_HEAD_SHA"):
                problems.append("report head is not the event head")
            if _get(payload, "subject", "base", "commit") != env.get("EXPECTED_BASE_SHA"):
                problems.append("report base is not the event base")
            if _get(payload, "trust", "trusted_config_commit") != env.get("EXPECTED_BASE_SHA"):
                problems.append("contract not read from the base commit")
            if _get(payload, "trust", "contract_path") != env.get("EXPECTED_CONTRACT_PATH"):
                problems.append("report used another contract path")
    if problems:
        return {k: "" for k in OUTPUT_KEYS}, problems, 1
    head = _get(report["payload"], "subject", "head", "commit")
    outputs = {
        "exit_code": status,
        "decision": report["payload"]["decision"],
        # Non-VERIFIED reports may stop before the head is read; the
        # publisher then concludes failure whatever this says.
        "head_sha": head if isinstance(head, str) and SHA.fullmatch(head) else "",
        "payload_sha256": report["metadata"]["payload_sha256"],
    }
    return outputs, [], int(status)


def write_outputs(path: str, outputs: Mapping[str, str]) -> None:
    # Every value is either empty or matched a closed pattern above, so no
    # value can contain a newline or a heredoc delimiter.
    with open(path, "a", encoding="utf-8") as fh:
        for key in OUTPUT_KEYS:
            fh.write("{0}={1}\n".format(key, outputs.get(key, "")))


def main(env: Mapping[str, str]) -> int:
    outputs, problems, status = extract(env)
    out_path = env.get("GITHUB_OUTPUT", "")
    if not out_path:
        sys.stderr.write("gate-outputs: GITHUB_OUTPUT not set\n")
        return 1
    write_outputs(out_path, outputs)
    for problem in problems:
        sys.stderr.write("gate-outputs: {0}\n".format(problem))
    return status


if __name__ == "__main__":
    sys.exit(main(os.environ))
