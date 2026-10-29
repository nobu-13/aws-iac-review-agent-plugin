"""Final Report of one evaluation (Phase 2 M1 WP5-4).

    python3 -m iacreview.evidence.final_report RESULT.json

Source: the canonical evaluation result of :mod:`iacreview.evidence.evaluator` (``NATIVE_RAW_REPLAY`` or
``LEGACY_DERIVED_REEVALUATION``). Purpose: a short, canonical summary a reviewer can read, bound to the result by
its SHA-256, that keeps apart what the result can and cannot show:

* ``rules_implemented``: every criterion was judged by an implemented rule (``not_implemented_rules`` is empty)
* ``evidence_kind``: native raw evidence or the Phase 1 helper's derived fields
* ``evidence_recording``: S7-01 per scenario (raw API data stored and verified). PASS only if evaluated for at least
  one scenario and PASS for every one; an empty set is NOT_PROVEN
* ``capture_authenticity``: always ``NOT_PROVEN``. The store proves the bytes did not change after capture; it does
  not prove that they came from GitHub (``authenticity_verified`` is false for every envelope)
* ``independent_reproduction``: always ``NOT_PROVEN``. A report cannot show that someone else re-ran it

The report adds no judgement: every status is copied from the result. The input must be canonical bytes; anything
else is refused. Exit codes: 0 report written, 2 the input is not a canonical evaluation result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from iacreview.evidence import canonical, evaluator

REPORT_FORMAT = "iacreview.evidence.final_report/1"
STATUSES = ("PASS", "FAILED", "NOT_PROVEN")


class ReportInputError(ValueError):
    """The input is not a canonical evaluation result."""


def _parse(result_bytes: bytes) -> Dict[str, Any]:
    try:
        doc = json.loads(result_bytes.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        raise ReportInputError("the result is not ASCII JSON") from None
    if not isinstance(doc, dict) or doc.get("result_format") != evaluator.RESULT_FORMAT:
        raise ReportInputError("not an evaluation result of format {0}".format(evaluator.RESULT_FORMAT))
    if doc.get("mode") not in (evaluator.NATIVE, evaluator.LEGACY):
        raise ReportInputError("unknown evaluation mode")
    try:
        same = canonical.dumps(doc) == result_bytes
    except canonical.CanonicalError:
        same = False
    if not same:
        raise ReportInputError("the result is not in canonical form")
    return doc


def _count(values: Sequence[str]) -> Dict[str, int]:
    return {s: sum(1 for v in values if v == s) for s in STATUSES}


def _compose_s7_01(rows: Sequence[Dict[str, Any]]) -> str:
    """S7-01 over the report: PASS only if it was evaluated for at least one scenario and PASS for every one."""
    statuses = [r["status"] for r in rows]
    if "FAILED" in statuses:
        return "FAILED"
    return "PASS" if statuses and all(x == "PASS" for x in statuses) else "NOT_PROVEN"


def build(result_bytes: bytes) -> Dict[str, Any]:
    """The report for one canonical result. Raises ReportInputError."""
    doc = _parse(result_bytes)
    scenarios: List[Dict[str, Any]] = []
    for s in doc.get("scenarios") or []:
        scenarios.append({
            "scenario": s["scenario"], "s7_result": s["s7_result"], "phase2_result": s["phase2_result"], "axes": s["axes"],
            "not_pass": [{"criterion_id": c["criterion_id"], "status": c["status"], "reason_code": c["reason_code"]}
                         for c in s["criteria"] if c["status"] != "PASS"],
        })
    oq = doc.get("open_questions") or {}
    s7_01 = [{"scenario": s["scenario"], "status": c["status"], "reason_code": c["reason_code"]}
             for s in doc.get("scenarios") or [] for c in s["criteria"] if c["criterion_id"] == "S7-01"]
    return {
        "report_format": REPORT_FORMAT,
        "result_sha256": hashlib.sha256(result_bytes).hexdigest(),
        "mode": doc["mode"], "definition": doc["definition"], "evaluator": doc["evaluator"],
        "snapshot_sha256": doc.get("snapshot_sha256"),
        "assurance": {
            "rules_implemented": "PASS" if doc.get("not_implemented_rules") == [] else "NOT_PROVEN",
            "not_implemented_rules": doc.get("not_implemented_rules"),
            "evidence_kind": "NATIVE_RAW" if doc["mode"] == evaluator.NATIVE else "LEGACY_DERIVED",
            "capture_integrity": doc.get("capture_integrity"),
            "capture_authenticity": "NOT_PROVEN",
            "independent_reproduction": "NOT_PROVEN",
        },
        "counts": {"s7_result": _count([s["s7_result"] for s in scenarios]),
                   "phase2_result": _count([s["phase2_result"] for s in scenarios])},
        "scenarios": scenarios,
        "evidence_recording": {"criterion_id": "S7-01", "rule_id": "s7.evidence.raw_api_data_stored",
                               "status": _compose_s7_01(s7_01), "counts": _count([x["status"] for x in s7_01]), "scenarios": s7_01},
        "open_questions": {"status": oq.get("status", "NOT_PROVEN"), "reason_code": oq.get("reason_code", "open_questions_missing"),
                           "questions": [{k: q[k] for k in ("question_id", "state", "answer", "reason_code")}
                                         for q in oq.get("questions") or []]},
        "limits": doc.get("limits") or [],
    }


def report_bytes(result_bytes: bytes) -> bytes:
    return canonical.dumps(build(result_bytes))


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m iacreview.evidence.final_report")
    parser.add_argument("result")
    args = parser.parse_args(argv)
    try:
        out = report_bytes(Path(args.result).read_bytes())
    except (OSError, ReportInputError) as exc:
        sys.stderr.write("refused: {0}\n".format(exc if isinstance(exc, ReportInputError) else type(exc).__name__))
        return 2
    sys.stdout.buffer.write(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
