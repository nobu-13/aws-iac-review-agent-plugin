"""Evidence Integrity Validator: checks V1-V9 (WP0 baseline) and W1-W5 (WP3 additions) — Phase 2 M1 WP3-1.

Source: ``docs/v2/phase2/m1/wp0/m1-architecture-proposal.md`` §3-3 (V1-V9, the
baseline; their meaning is kept) and ``m1-acceptance-test-matrix.md`` M1-06.
Purpose: before any rule decides, say for a set of evidence ids whether the
evidence is intact, complete and usable, as machine-readable check results.

=====  ===========================================================================  =====================
Check  Meaning (WP0 text, kept)                                                     Implemented by
=====  ===========================================================================  =====================
V1     every manifest file exists and its SHA-256 and size match (manifest           store.verify findings
       structure and references included)
V2     no file outside the manifest in a revision (links, unexpected entries)        store.verify findings
V3     the manifest's own hash matches the revision chain (WP2 keeps the chain in   store.verify findings
       ``previous_manifest_sha256``; WP0 assumed a ``REVISIONS.json``: Gap G-1)
V4     the envelope's required fields are present and valid                         store.verify findings
V5     the collection is complete (pagination; every page of the capture named)    this module
V6     HTTP status is a success and the body parses as JSON (``text/plain``:      this module
       UTF-8 text; WP4 Gap G-6)
V7     the provenance required by the definition is met (source type)               this module
V8     no revoked / superseded evidence is used as current (WP3: quarantine)        store + this module
V9     sanitized evidence: the evaluator's fields are not affected by redaction     NOT_APPLICABLE: no
                                                                                    sanitized type (G-3)
W1     evidence ids: no duplicate in the store, no named id missing                 store + this module
W2     provenance and subject commit agree with the expected subject                this module
W3     no incomplete revision or interrupted write in the store                     store.verify findings
W4     the security gate, re-run on the stored raw bytes and envelope, still says   this module
       CLEAN, and agrees with the recorded ``security_scan_status``
W5     file and directory permissions are private                                   store.verify findings
=====  ===========================================================================  =====================

Status per check: PASS, FAILED (a violation was found), NOT_PROVEN (the check
could not be completed or the evidence is not usable for the purpose) and
NOT_APPLICABLE (with a reason). Overall: FAILED if any check FAILED, else
NOT_PROVEN if any is NOT_PROVEN, else PASS. NOT_PROVEN is never turned into
PASS. A store that does not verify makes every named evidence unusable: there
is no fallback to an older revision.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

from iacreview.evidence import envelope as env
from iacreview.evidence import secretgate
from iacreview.evidence.collector import is_text_body
from iacreview.evidence.store import EvidenceStore, StoreReport

VALIDATOR_VERSION = "iacreview.evidence.integrity/1"
CHECKS = ("V1", "V2", "V3", "V4", "V5", "V6", "V7", "V8", "V9", "W1", "W2", "W3", "W4", "W5")
TITLES = {
    "V1": "manifest files present, SHA-256 and size match", "V2": "no file outside the manifest",
    "V3": "revision chain (numbers, previous manifest hash)", "V4": "envelope schema",
    "V5": "collection complete (pagination, all pages named)", "V6": "HTTP success and JSON body",
    "V7": "required provenance", "V8": "no revoked or quarantined evidence used", "V9": "sanitized evidence",
    "W1": "evidence ids unique and present", "W2": "provenance and subject commit consistent",
    "W3": "no incomplete revision", "W4": "security gate agrees with stored content", "W5": "private permissions",
}
STORE_LEVEL = ("V1", "V2", "V3", "V4", "W1", "W3", "W5")


@dataclass(frozen=True)
class Requirement:
    """What the caller needs the evidence to be."""

    source_type: str = "API"
    subject_commit_sha: Optional[str] = None
    require_complete: bool = True


def _check(cid: str, status: str, reasons: Sequence[str], ids: Sequence[str], details: Sequence[str] = ()) -> Dict[str, Any]:
    return {"check_id": cid, "title": TITLES[cid], "status": status, "reason_codes": sorted(set(reasons)),
            "evidence_ids": sorted(set(ids)), "details": list(details)[:20]}


def validate(store: EvidenceStore, evidence_ids: Sequence[str], requirement: Requirement = Requirement(),
             report: Optional[StoreReport] = None) -> Dict[str, Any]:
    """Run every check for ``evidence_ids``. Returns a machine-readable result (no absolute path, no content)."""
    report = report or store.verify()
    ids = list(evidence_ids)
    checks: Dict[str, Dict[str, Any]] = {}

    # Store-level checks from the store's structured findings.
    # A QUARANTINED revision's own findings were acknowledged by a Human approval bound to its state; its evidence
    # stays unusable (V8) but its findings do not fail the rest of the store.
    all_findings = list(report.findings) + [f for r in report.revisions if r.status != "QUARANTINED" for f in r.all_findings]
    for cid in STORE_LEVEL:
        found = [f for f in all_findings if f.check_id == cid]  # an INCOMPLETE revision always carries a W3 finding
        checks[cid] = _check(cid, "FAILED" if found else "PASS", [f.code for f in found],
                             [f.evidence_id for f in found if f.evidence_id], [f.message for f in found])
    v8_store = [f for f in all_findings if f.check_id == "V8"]

    usable = report.valid
    located: Dict[str, Any] = {}
    missing: List[str] = []
    quarantined: List[str] = []
    for eid in ids:
        rev = report.located(eid)
        if rev is None:
            missing.append(eid)
        elif rev.status == "QUARANTINED":
            quarantined.append(eid)
        else:
            located[eid] = rev.envelopes[eid]

    # W1: duplicates (store) plus named ids that are absent.
    dup_named = sorted({e for e in ids if ids.count(e) > 1})
    if missing or dup_named or not ids:
        w1 = checks["W1"]
        status = "FAILED" if w1["status"] == "FAILED" else "NOT_PROVEN"
        reasons = w1["reason_codes"] + (["named_evidence_missing"] if missing else []) + (["evidence_named_twice"] if dup_named else []) \
            + (["no_evidence_named"] if not ids else [])
        checks["W1"] = _check("W1", status, reasons, w1["evidence_ids"] + missing + dup_named, w1["details"])

    # V8: quarantined evidence or invalid quarantine records.
    if quarantined or v8_store:
        checks["V8"] = _check("V8", "FAILED", (["quarantined_evidence_named"] if quarantined else []) + [f.code for f in v8_store],
                              quarantined, [f.message for f in v8_store])
    else:
        checks["V8"] = _check("V8", "PASS", [], [])

    # Evidence-level checks: only meaningful on a verified store.
    if not usable:
        for cid in ("V5", "V6", "V7", "W2", "W4"):
            checks[cid] = _check(cid, "NOT_PROVEN", ["store_integrity_not_verified"], ids)
    else:
        checks["V5"] = _v5(report, located, requirement)
        checks["V6"] = _v6(store, report, located)
        checks["V7"] = _v7(located, requirement)
        checks["W2"] = _w2(located, requirement)
        checks["W4"] = _w4(store, report, located)
    checks["V9"] = _check("V9", "NOT_APPLICABLE", ["no_sanitized_evidence_type"], [],
                          ["envelope schema 1 has no sanitized evidence type; sanitized artifacts are not stored (WP3 policy)"])

    statuses = [c["status"] for c in checks.values()]
    overall = "FAILED" if "FAILED" in statuses else ("NOT_PROVEN" if "NOT_PROVEN" in statuses or not ids else "PASS")
    usable_ids = sorted(located) if overall == "PASS" else []
    return {
        "validator": VALIDATOR_VERSION, "checked_at": report.verified_at,
        "revisions": [{"revision_id": r.revision_id, "status": r.status} for r in report.revisions],
        "requested_evidence_ids": sorted(set(ids)), "requirement": requirement.__dict__,
        "checks": [checks[c] for c in CHECKS], "overall_status": overall,
        "usable_evidence_ids": usable_ids, "unusable_evidence_ids": sorted(set(ids) - set(usable_ids)),
    }


def _v5(report: StoreReport, located: Dict[str, Any], req: Requirement) -> Dict[str, Any]:
    reasons, ids = [], []
    captures: Dict[str, set] = {}
    for eid, e in located.items():
        if e["source_type"] != "API":
            continue
        if e["pagination_complete"] is not True:
            reasons.append("pagination_incomplete")
            ids.append(eid)
        captures.setdefault(e["capture_id"], set()).add(eid)
    for cap, named in captures.items():
        pages = {eid: e for r in report.revisions if r.status == "VALID" for eid, e in r.envelopes.items() if e["capture_id"] == cap}
        indices = sorted(e["page"]["index"] for e in pages.values())
        if set(pages) - named:
            reasons.append("capture_pages_not_all_named")
            ids += sorted(set(pages) - named)
        if indices != list(range(1, len(indices) + 1)):
            reasons.append("capture_page_missing")
            ids += sorted(named)
        if pages and max(pages.values(), key=lambda e: e["page"]["index"])["page"]["has_next"]:
            reasons.append("last_page_has_next")
            ids += sorted(named)
    if not located:
        return _check("V5", "NOT_PROVEN", ["no_usable_evidence"], [])
    return _check("V5", "NOT_PROVEN" if reasons else "PASS", reasons, ids)


def _v6(store: EvidenceStore, report: StoreReport, located: Dict[str, Any]) -> Dict[str, Any]:
    reasons, ids, failed = [], [], False
    for eid, e in located.items():
        if e["source_type"] != "API":
            continue
        if e["http_status"] != 200:
            reasons.append("http_status_not_200")
            ids.append(eid)
            continue
        raw = store.read_raw(report, eid)
        if raw is None:
            reasons.append("raw_unavailable")
            ids.append(eid)
            continue
        try:
            if is_text_body(e["response_headers"].get("content-type")):
                raw.decode("utf-8")  # a text/plain body (job log) is checked as text (Gap G-6)
            else:
                json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            if not ({"body_not_json", "body_not_text"} & set(e["capture_errors"])):
                failed = True
                reasons.append("body_not_json_but_not_recorded")
            else:
                reasons.append("body_not_json")
            ids.append(eid)
    if not located:
        return _check("V6", "NOT_PROVEN", ["no_usable_evidence"], [])
    return _check("V6", "FAILED" if failed else ("NOT_PROVEN" if reasons else "PASS"), reasons, ids)


def _v7(located: Dict[str, Any], req: Requirement) -> Dict[str, Any]:
    if req.source_type not in env.SOURCE_TYPES:
        return _check("V7", "NOT_PROVEN", ["requirement_unknown_source_type"], [])
    wrong = sorted(eid for eid, e in located.items() if e["source_type"] != req.source_type)
    incomplete = sorted(eid for eid, e in located.items() if req.require_complete and e["completeness_status"] != "COMPLETE")
    if not located:
        return _check("V7", "NOT_PROVEN", ["no_usable_evidence"], [])
    reasons = (["source_type_not_" + req.source_type.lower()] if wrong else []) + (["evidence_incomplete"] if incomplete else [])
    return _check("V7", "NOT_PROVEN" if reasons else "PASS", reasons, wrong + incomplete)


def _w2(located: Dict[str, Any], req: Requirement) -> Dict[str, Any]:
    if not located:
        return _check("W2", "NOT_PROVEN", ["no_usable_evidence"], [])
    if req.subject_commit_sha is None:
        return _check("W2", "NOT_APPLICABLE", ["no_subject_commit_required"], [])
    mismatch = sorted(eid for eid, e in located.items() if e["subject_commit_sha"] not in (None, req.subject_commit_sha))
    absent = sorted(eid for eid, e in located.items() if e["subject_commit_sha"] is None)
    if mismatch:
        return _check("W2", "FAILED", ["subject_commit_mismatch"], mismatch)
    if absent:
        return _check("W2", "NOT_PROVEN", ["subject_commit_not_recorded"], absent)
    return _check("W2", "PASS", [], [])


def _w4(store: EvidenceStore, report: StoreReport, located: Dict[str, Any]) -> Dict[str, Any]:
    reasons, ids, failed = [], [], False
    for eid, e in located.items():
        scan = secretgate.scan(env.canonical_bytes(e))
        if not scan.storable:
            failed = True
            reasons.append("envelope_" + scan.status.lower())
            ids.append(eid)
        if e["raw_content_sha256"] is None:
            continue
        if e["security_scan_status"] != "CLEAN":
            failed = True
            reasons.append("raw_stored_without_clean_scan")
            ids.append(eid)
        raw = store.read_raw(report, eid)
        if raw is None:
            reasons.append("raw_unavailable")
            ids.append(eid)
            continue
        scan = secretgate.scan(raw)
        if not scan.storable:
            failed = True
            reasons.append("stored_raw_" + scan.status.lower())
            ids.append(eid)
    if not located:
        return _check("W4", "NOT_PROVEN", ["no_usable_evidence"], [])
    return _check("W4", "FAILED" if failed else ("NOT_PROVEN" if reasons else "PASS"), reasons, ids)
