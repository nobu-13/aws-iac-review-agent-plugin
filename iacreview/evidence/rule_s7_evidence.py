"""Evaluator rule ``s7.evidence.raw_api_data_stored`` (criterion S7-01) — Phase 2 M1 WP2-5.

Source: ``docs/v2/phase1/app-demo-plan.md`` §7, first sentence: "Per scenario,
``app-evidence`` stores raw API data and classifies four parts." (quoted as
S7-01 in ``definitions/phase1-app-demo-s7.v1.json``). Purpose: decide, from a
verified Evidence Store, whether the evidence a scenario relies on is raw API
data. Phase 1 kept only transcribed fields (WP0 helper audit HA-3); this rule
is what would have flagged that.

Decision (expected_result of S7-01: satisfied PASS, violated FAILED, evidence
missing NOT_PROVEN):

* NOT_PROVEN: the store does not verify; no evidence is named; a named
  evidence id is not in the store; it is not API evidence; it is incomplete
  (an HTTP error, a missing response, a byte limit, unfinished pagination, a
  refused sibling page); or another page of the same capture is not named
* FAILED: an API evidence received a 200 response with no capture error, yet
  its raw bytes were not stored (metadata only: exactly what Phase 1 did)
* PASS: every named evidence is API evidence in a verified revision, its raw
  bytes match the recorded hash, it is COMPLETE, and every page of each
  capture is named

PASS concerns storage only. It says nothing about the authenticity of the
bytes (``authenticity_verified`` is always false) or about the other three
parts of section 7.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence, Tuple

from iacreview.evidence.store import StoreReport

RULE_ID = "s7.evidence.raw_api_data_stored"


@dataclass(frozen=True)
class RuleResult:
    rule_id: str
    status: str  # PASS, FAILED, NOT_PROVEN
    reason_code: str
    evidence_ids: Tuple[str, ...]


def _result(status: str, reason: str, ids: Sequence[str]) -> RuleResult:
    return RuleResult(RULE_ID, status, reason, tuple(sorted(ids)))


def raw_api_data_stored(report: StoreReport, evidence_ids: Sequence[str]) -> RuleResult:
    ids = list(evidence_ids)
    if not report.valid:
        return _result("NOT_PROVEN", "store_integrity_not_verified", ids)
    if not ids or len(set(ids)) != len(ids):
        return _result("NOT_PROVEN", "no_evidence_named" if not ids else "evidence_named_twice", ids)
    captures = set()
    not_proven = ""
    failed = False
    for eid in ids:
        found = report.find(eid)
        if found is None:
            not_proven = not_proven or "evidence_missing"
            continue
        envelope = found[1]
        if envelope["source_type"] != "API":
            not_proven = not_proven or "not_api_evidence"
        elif envelope["raw_content_sha256"] is None:
            if envelope["http_status"] == 200 and not envelope["capture_errors"]:
                failed = True  # a violation outranks missing evidence elsewhere
            else:
                not_proven = not_proven or "capture_incomplete"
        elif envelope["completeness_status"] != "COMPLETE":
            not_proven = not_proven or "capture_incomplete"
        else:
            captures.add(envelope["capture_id"])
    if failed:
        return _result("FAILED", "api_response_stored_without_raw_bytes", ids)
    if not_proven:
        return _result("NOT_PROVEN", not_proven, ids)
    for rev in report.revisions:
        for eid, envelope in rev.envelopes.items():
            if envelope["capture_id"] in captures and eid not in ids:
                return _result("NOT_PROVEN", "capture_pages_not_all_named", ids)
    return _result("PASS", "raw_api_bytes_stored_and_verified", ids)
