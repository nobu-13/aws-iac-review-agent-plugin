"""Evidence Integrity Validator (V1-V9, W1-W5) and Revision Recovery (Phase 2 M1 WP3-1, WP3-4).

Stores live under pytest's tmp_path; evidence comes from synthetic responses.
Every abnormal case asserts that the validator refuses (FAILED or NOT_PROVEN),
never PASS.
"""

from __future__ import annotations

import datetime
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from iacreview.evidence import collector, envelope, integrity, secretgate, store

REPO = "synthetic-owner/synthetic-repo"
SHA = "d" * 40
T0 = datetime.datetime(2026, 10, 29, 3, 0, 0, 0, tzinfo=datetime.timezone.utc)
EP = "/repos/synthetic-owner/synthetic-repo/commits/" + SHA + "/check-runs?per_page=100"
_ids = iter(range(1, 100000))


def raw(n: int) -> bytes:
    return json.dumps({"total_count": n, "check_runs": []}).encode()


def response(data: bytes, nxt: Optional[int] = None, status: int = 200) -> collector.HttpResponse:
    headers = {"Content-Type": "application/json"}
    if nxt:
        headers["Link"] = '<{0}{1}&page={2}>; rel="next"'.format(collector.API_ROOT, EP, nxt)
    return collector.HttpResponse(status, headers, data)


def capture(responses: List[Any], subject: Optional[str] = SHA, max_pages: int = 50) -> collector.CaptureResult:
    queue = list(responses)
    c = collector.Collector(lambda r: queue.pop(0), REPO, now=lambda: T0, id_factory=lambda: "cap-{0:05d}".format(next(_ids)),
                            max_pages=max_pages)
    return c.capture("GET", EP, subject_commit_sha=subject)


@pytest.fixture()
def base(tmp_path: Path) -> Path:
    b = tmp_path / "work"
    b.mkdir()
    return b


@pytest.fixture()
def st(base: Path) -> store.EvidenceStore:
    return store.EvidenceStore(base / "evidence-store", base, now=lambda: T0)


def write(st: store.EvidenceStore, evidence: List[collector.CapturedEvidence]) -> None:
    w = st.begin_revision("synthetic")
    for e in evidence:
        w.add(e)
    w.seal()


def rev(st: store.EvidenceStore, n: int = 1) -> Path:
    return st.root / "rev-{0:04d}".format(n)


def checks(result: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {c["check_id"]: c for c in result["checks"]}


def run(st: store.EvidenceStore, ids: List[str], **req: Any) -> Dict[str, Any]:
    return integrity.validate(st, ids, integrity.Requirement(**req))


# ---------------------------------------------------------------------------
# Normal path and output format
# ---------------------------------------------------------------------------


def test_intact_complete_evidence_passes_every_check(st: store.EvidenceStore) -> None:
    cap = capture([response(raw(1), nxt=2), response(raw(2))])
    write(st, cap.evidence)
    result = run(st, [e.evidence_id for e in cap.evidence], subject_commit_sha=SHA)
    assert result["overall_status"] == "PASS", [c for c in result["checks"] if c["status"] not in ("PASS", "NOT_APPLICABLE")]
    c = checks(result)
    assert [x["check_id"] for x in result["checks"]] == list(integrity.CHECKS)
    assert all(c[k]["status"] == "PASS" for k in integrity.CHECKS if k != "V9")
    assert c["V9"]["status"] == "NOT_APPLICABLE" and c["V9"]["reason_codes"] == ["no_sanitized_evidence_type"]
    assert result["usable_evidence_ids"] == sorted(e.evidence_id for e in cap.evidence)
    assert set(c["V1"]) == {"check_id", "title", "status", "reason_codes", "evidence_ids", "details"}
    assert str(st.root) not in json.dumps(result)  # no host path in the output


def test_not_proven_is_never_reported_as_pass(st: store.EvidenceStore) -> None:
    cap = capture([response(raw(1), nxt=2), response(raw(2), nxt=3)], max_pages=2)
    write(st, cap.evidence)
    result = run(st, [e.evidence_id for e in cap.evidence])
    assert checks(result)["V5"]["status"] == "NOT_PROVEN" and result["overall_status"] == "NOT_PROVEN"
    assert result["usable_evidence_ids"] == []


# ---------------------------------------------------------------------------
# WP3-6 abnormal cases, store level (V1-V4, W1, W3, W5)
# ---------------------------------------------------------------------------


def _one(st: store.EvidenceStore) -> str:
    cap = capture([response(raw(1))])
    write(st, cap.evidence)
    return cap.evidence[0].evidence_id


def test_one_raw_byte_changed_fails_v1(st: store.EvidenceStore) -> None:
    eid = _one(st)
    path = rev(st) / (eid + ".raw")
    data = bytearray(path.read_bytes())
    data[-1] ^= 1
    path.write_bytes(bytes(data))
    result = run(st, [eid])
    assert checks(result)["V1"]["status"] == "FAILED" and "raw_hash_mismatch" in checks(result)["V1"]["reason_codes"]
    assert result["overall_status"] == "FAILED" and eid in result["unusable_evidence_ids"]


def test_envelope_changed_fails_v1(st: store.EvidenceStore) -> None:
    eid = _one(st)
    path = rev(st) / (eid + ".envelope.json")
    doc = json.loads(path.read_text())
    doc["subject_commit_sha"] = "e" * 40
    path.write_bytes(envelope.canonical_bytes(doc))
    result = run(st, [eid])
    assert "envelope_hash_mismatch" in checks(result)["V1"]["reason_codes"] and result["overall_status"] == "FAILED"


def test_envelope_schema_broken_fails_v4(st: store.EvidenceStore) -> None:
    eid = _one(st)
    path = rev(st) / (eid + ".envelope.json")
    doc = json.loads(path.read_text())
    doc["schema_version"] = 9
    data = envelope.canonical_bytes(doc)
    path.write_bytes(data)
    mpath = rev(st) / store.MANIFEST
    m = json.loads(mpath.read_text())
    m["entries"][0]["envelope_sha256"] = envelope.sha256_hex(data)
    m["entries"][0]["envelope_length"] = len(data)
    mpath.write_bytes(store.manifest_bytes(m))
    assert checks(run(st, [eid]))["V4"]["status"] == "FAILED"


def test_manifest_changed_fails(st: store.EvidenceStore) -> None:
    eid = _one(st)
    mpath = rev(st) / store.MANIFEST
    m = json.loads(mpath.read_text())
    m["entries"][0]["raw_length"] += 1
    mpath.write_bytes(store.manifest_bytes(m))
    result = run(st, [eid])
    assert checks(result)["V1"]["status"] == "FAILED" and result["overall_status"] == "FAILED"


def test_a_file_outside_the_manifest_fails_v2(st: store.EvidenceStore) -> None:
    eid = _one(st)
    (rev(st) / "planted.raw").write_bytes(b"{}")
    assert checks(run(st, [eid]))["V2"]["status"] == "FAILED"


def test_a_broken_chain_fails_v3(st: store.EvidenceStore) -> None:
    eid = _one(st)
    _one(st)
    mpath = rev(st, 1) / store.MANIFEST
    m = json.loads(mpath.read_text())
    m["reason"] = "rewritten"
    mpath.write_bytes(store.manifest_bytes(m))
    result = run(st, [eid])
    assert "previous_manifest_sha256_mismatch" in checks(result)["V3"]["reason_codes"]


def test_a_missing_revision_fails_v3(st: store.EvidenceStore) -> None:
    eid = _one(st)
    _one(st)
    third = _one(st)
    os.rename(rev(st, 2), st.root.parent / "moved-away")
    result = run(st, [eid, third])
    assert {"revision_gap", "previous_revision_mismatch"} <= set(checks(result)["V3"]["reason_codes"])
    assert result["overall_status"] == "FAILED"


def test_a_duplicate_evidence_id_fails_w1(st: store.EvidenceStore) -> None:
    eid = _one(st)
    e2 = _one(st)
    # Plant rev-0001's evidence again in rev-0002 by rewriting rev-0002's files and manifest consistently.
    r1, r2 = rev(st, 1), rev(st, 2)
    for suffix in (".raw", ".envelope.json"):
        (r2 / (eid + suffix)).write_bytes((r1 / (eid + suffix)).read_bytes())
        os.chmod(r2 / (eid + suffix), 0o600)
        (r2 / (e2 + suffix)).unlink()
    m2 = json.loads((r2 / store.MANIFEST).read_text())
    m1 = json.loads((r1 / store.MANIFEST).read_text())
    m2["entries"] = m1["entries"]
    (r2 / store.MANIFEST).write_bytes(store.manifest_bytes(m2))
    c = checks(run(st, [eid]))
    assert c["W1"]["status"] == "FAILED" and "duplicate_evidence_id" in c["W1"]["reason_codes"]


def test_a_named_evidence_id_that_does_not_exist_is_not_proven(st: store.EvidenceStore) -> None:
    eid = _one(st)
    result = run(st, [eid, "absent-0001"])
    assert checks(result)["W1"]["status"] == "NOT_PROVEN" and "named_evidence_missing" in checks(result)["W1"]["reason_codes"]
    assert result["overall_status"] == "NOT_PROVEN"
    assert run(st, [])["overall_status"] == "NOT_PROVEN"


def test_an_incomplete_bundle_fails_w3(st: store.EvidenceStore) -> None:
    eid = _one(st)
    w = st.begin_revision("interrupted")
    w.add(capture([response(raw(2))]).evidence[0])  # never sealed
    result = run(st, [eid])
    assert checks(result)["W3"]["status"] == "FAILED" and "manifest_missing" in checks(result)["W3"]["reason_codes"]
    assert w.path.exists()


def test_loose_permissions_fail_w5(st: store.EvidenceStore) -> None:
    eid = _one(st)
    os.chmod(rev(st) / (eid + ".raw"), 0o644)
    assert checks(run(st, [eid]))["W5"]["status"] == "FAILED"


# ---------------------------------------------------------------------------
# Evidence level (V5-V8, W2, W4)
# ---------------------------------------------------------------------------


def test_a_page_of_the_capture_not_named_is_not_proven_v5(st: store.EvidenceStore) -> None:
    cap = capture([response(raw(1), nxt=2), response(raw(2))])
    write(st, cap.evidence)
    c = checks(run(st, [cap.evidence[0].evidence_id]))
    assert c["V5"]["status"] == "NOT_PROVEN" and "capture_pages_not_all_named" in c["V5"]["reason_codes"]


def test_an_http_error_is_not_usable_v6(st: store.EvidenceStore) -> None:
    cap = capture([response(b'{"message": "Not Found"}', status=404)])
    write(st, cap.evidence)
    c = checks(run(st, [cap.evidence[0].evidence_id]))
    assert c["V6"]["status"] == "NOT_PROVEN" and c["V6"]["reason_codes"] == ["http_status_not_200"]


def test_the_wrong_provenance_is_not_proven_v7(st: store.EvidenceStore) -> None:
    human, _ = collector.non_api_evidence("HUMAN", "hum-0001", "hum-cap-1", "human report", b"BLOCKED seen\n", T0)
    assert human is not None
    write(st, [human])
    c = checks(run(st, ["hum-0001"], source_type="API"))
    assert c["V7"]["status"] == "NOT_PROVEN" and "source_type_not_api" in c["V7"]["reason_codes"]


def test_a_source_commit_mismatch_fails_w2(st: store.EvidenceStore) -> None:
    cap = capture([response(raw(1))], subject=SHA)
    write(st, cap.evidence)
    c = checks(run(st, [cap.evidence[0].evidence_id], subject_commit_sha="f" * 40))
    assert c["W2"]["status"] == "FAILED" and c["W2"]["reason_codes"] == ["subject_commit_mismatch"]
    cap2 = capture([response(raw(2))], subject=None)
    write(st, cap2.evidence)
    assert checks(run(st, [cap2.evidence[0].evidence_id], subject_commit_sha=SHA))["W2"]["status"] == "NOT_PROVEN"


def test_a_secret_gate_disagreement_with_stored_content_fails_w4(st: store.EvidenceStore, monkeypatch: pytest.MonkeyPatch) -> None:
    """Stored content that the gate (now stricter) refuses is not silently accepted: W4 FAILED."""
    eid = _one(st)
    real = secretgate.scan
    marker = "total_count"

    def stricter(content: bytes, max_bytes: int = secretgate.DEFAULT_MAX_SCAN_BYTES, rules: Any = None) -> secretgate.ScanResult:
        import re

        return real(content, max_bytes, rules=lambda: secretgate._all_rules() + [("synthetic_rule", re.compile(marker))])

    monkeypatch.setattr(secretgate, "scan", stricter)
    c = checks(integrity.validate(st, [eid]))
    assert c["W4"]["status"] == "FAILED" and "stored_raw_detected" in c["W4"]["reason_codes"]


# ---------------------------------------------------------------------------
# No fallback, diagnostics and recovery (WP3-4)
# ---------------------------------------------------------------------------


def test_a_broken_latest_revision_never_falls_back_to_an_older_one(st: store.EvidenceStore) -> None:
    old = _one(st)
    newer = _one(st)
    (rev(st, 2) / (newer + ".raw")).write_bytes(b"tampered")
    result = run(st, [old])  # the evidence itself is in the intact rev-0001
    assert result["overall_status"] == "FAILED" and result["usable_evidence_ids"] == []
    assert {checks(result)[k]["status"] for k in ("V5", "V6", "V7", "W4")} == {"NOT_PROVEN"}
    report = st.verify()
    assert st.read_raw(report, old) is None


def test_diagnose_is_read_only_and_lists_unusable_evidence(st: store.EvidenceStore, tmp_path: Path) -> None:
    eid = _one(st)
    w = st.begin_revision("interrupted")
    w.add(capture([response(raw(2))]).evidence[0])
    before = sorted((p.name, p.read_bytes()) for p in w.path.iterdir())
    diag = st.diagnose()
    assert diag["store_valid"] is False and diag["revisions"][-1]["status"] == "INCOMPLETE"
    assert eid in diag["unusable_evidence_ids"] and "Nothing is repaired" in diag["recommended_action"]
    assert sorted((p.name, p.read_bytes()) for p in w.path.iterdir()) == before
    assert st.diagnose()["diagnostic_sha256"] == diag["diagnostic_sha256"]
    out = tmp_path / "diag.json"
    st.write_diagnostic(diag, out)
    with pytest.raises(store.StoreError):
        st.write_diagnostic(diag, out)
    with pytest.raises(store.StoreError, match="never written inside the store"):
        st.write_diagnostic(diag, st.root / "diag.json")


def _approval(st: store.EvidenceStore, **over: str) -> store.QuarantineApproval:
    diag = st.diagnose()
    last = diag["revisions"][-1]
    values = {"quarantined_revision_id": last["revision_id"], "state_sha256": last["state_sha256"],
              "diagnostic_sha256": diag["diagnostic_sha256"], "approved_by_role": "human reviewer (synthetic)",
              "approval_statement": "reviewed the diagnostic; quarantine the interrupted revision"}
    values.update(over)
    return store.QuarantineApproval(**values)


def test_an_approved_quarantine_is_recorded_in_a_new_revision_and_nothing_is_deleted(st: store.EvidenceStore) -> None:
    eid = _one(st)
    w = st.begin_revision("interrupted")
    lost = capture([response(raw(2))]).evidence[0]
    w.add(lost)
    files_before = sorted(p.name for p in w.path.iterdir())
    st.quarantine_latest(_approval(st))
    report = st.verify()
    assert report.valid and [r.status for r in report.revisions] == ["VALID", "QUARANTINED", "VALID"]
    assert sorted(p.name for p in w.path.iterdir()) == files_before  # the broken revision is untouched
    assert report.find(lost.evidence_id) is None
    result = run(st, [eid])
    assert result["overall_status"] == "PASS"
    c = checks(run(st, [lost.evidence_id]))
    assert c["V8"]["status"] == "FAILED" and "quarantined_evidence_named" in c["V8"]["reason_codes"]
    write(st, capture([response(raw(3))]).evidence)  # the store accepts new revisions again
    assert st.verify().valid


@pytest.mark.parametrize("field,value", [("state_sha256", "0" * 64), ("diagnostic_sha256", "0" * 64), ("quarantined_revision_id", "rev-0001")])
def test_a_stale_or_mismatched_approval_is_refused(st: store.EvidenceStore, field: str, value: str) -> None:
    _one(st)
    st.begin_revision("interrupted").add(capture([response(raw(2))]).evidence[0])
    with pytest.raises(store.StoreError):
        st.quarantine_latest(_approval(st, **{field: value}))
    assert len(list(st.root.iterdir())) == 2


def test_a_quarantined_revision_changed_after_approval_breaks_the_store_again(st: store.EvidenceStore) -> None:
    _one(st)
    w = st.begin_revision("interrupted")
    w.add(capture([response(raw(2))]).evidence[0])
    st.quarantine_latest(_approval(st))
    (w.path / "late-addition.raw").write_bytes(b"x")
    report = st.verify()
    assert not report.valid and any(f.code == "quarantine_state_mismatch" for r in report.revisions for f in r.findings)


def test_only_the_latest_revision_can_be_quarantined(st: store.EvidenceStore) -> None:
    _one(st)
    _one(st)
    (rev(st, 1) / store.MANIFEST).unlink()
    with pytest.raises(store.StoreError):
        st.quarantine_latest(_approval(st))


def test_a_valid_store_has_nothing_to_quarantine(st: store.EvidenceStore) -> None:
    _one(st)
    with pytest.raises(store.StoreError, match="nothing to quarantine"):
        st.quarantine_latest(_approval(st))


def test_a_forged_quarantine_of_a_valid_revision_fails_v8(st: store.EvidenceStore) -> None:
    eid = _one(st)
    record = {"record_type": "revision_quarantine", "record_version": 1, "quarantined_revision_id": "rev-0001", "state_sha256": "0" * 64,
              "diagnostic_sha256": "0" * 64, "action": "QUARANTINE", "approved_by_role": "x", "approval_statement": "x",
              "approved_at": "2026-10-29T00:00:00.000000Z"}
    write(st, [store._human_record("quarantine-rev-0001", store.quarantine_record_bytes(record), "2026-10-29T00:00:00.000000Z", "rev-0001")])
    result = run(st, [eid])
    assert checks(result)["V8"]["status"] == "FAILED" and "quarantine_of_valid_revision" in checks(result)["V8"]["reason_codes"]


@pytest.mark.parametrize("stage", ["after_mkdir", "after_raw", "after_envelope", "after_tmp_manifest", "after_link_before_unlink"])
def test_every_crash_boundary_leaves_a_detected_unusable_revision(st: store.EvidenceStore, stage: str) -> None:
    """Simulated interruption at each write boundary of a revision: the store never verifies as valid."""
    eid = _one(st)
    w = st.begin_revision("crash test")
    e = capture([response(raw(2))]).evidence[0]
    fd = os.open(str(w.path), os.O_RDONLY)
    try:
        if stage != "after_mkdir":
            store._write_exclusive(fd, e.evidence_id + ".raw", e.raw or b"")
        if stage in ("after_envelope", "after_tmp_manifest", "after_link_before_unlink"):
            store._write_exclusive(fd, e.evidence_id + ".envelope.json", envelope.canonical_bytes(e.envelope))
        if stage in ("after_tmp_manifest", "after_link_before_unlink"):
            store._write_exclusive(fd, store.MANIFEST_TMP, b"{}")
        if stage == "after_link_before_unlink":
            os.link(store.MANIFEST_TMP, store.MANIFEST, src_dir_fd=fd, dst_dir_fd=fd)
    finally:
        os.close(fd)
    report = st.verify()
    assert not report.valid and report.revisions[-1].status in ("INCOMPLETE", "INVALID")
    assert run(st, [eid])["overall_status"] == "FAILED"
    with pytest.raises(store.StoreError):
        st.begin_revision("must not start")
