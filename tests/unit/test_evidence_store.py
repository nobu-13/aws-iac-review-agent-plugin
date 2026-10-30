"""Immutable Evidence Store, envelope validation and the S7-01 rule (Phase 2 M1 WP2-1, WP2-4, WP2-5).

All stores live under pytest's tmp_path. Evidence comes from the collector fed
with synthetic responses; nothing reaches GitHub.
"""

from __future__ import annotations

import copy
import datetime
import json
import os
import stat
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from iacreview.evidence import collector, envelope, rules, secretgate, store
from iacreview.evidence.rule_s7_evidence import raw_api_data_stored

REPO = "synthetic-owner/synthetic-repo"
SHA = "c" * 40
T0 = datetime.datetime(2026, 10, 29, 2, 0, 0, 1, tzinfo=datetime.timezone.utc)
EP = "/repos/synthetic-owner/synthetic-repo/commits/" + SHA + "/check-runs?per_page=100"


def raw(n: int) -> bytes:
    return json.dumps({"total_count": n, "check_runs": []}).encode()


def response(data: bytes, nxt: Optional[int] = None, status: int = 200) -> collector.HttpResponse:
    headers = {"Content-Type": "application/json"}
    if nxt:
        headers["Link"] = '<{0}{1}&page={2}>; rel="next"'.format(collector.API_ROOT, EP, nxt)
    return collector.HttpResponse(status, headers, data)


_ids = iter(range(1, 100000))


def capture(responses: List[Any], max_pages: int = 50) -> collector.CaptureResult:
    queue = list(responses)
    c = collector.Collector(lambda req: queue.pop(0), REPO, now=lambda: T0, id_factory=lambda: "cap-{0:05d}".format(next(_ids)),
                            max_pages=max_pages)
    return c.capture("GET", EP, subject_commit_sha=SHA)


@pytest.fixture()
def base(tmp_path: Path) -> Path:
    b = tmp_path / "work"
    b.mkdir()
    return b


@pytest.fixture()
def st(base: Path) -> store.EvidenceStore:
    return store.EvidenceStore(base / "evidence-store", base, now=lambda: T0)


def write(st: store.EvidenceStore, evidence: List[collector.CapturedEvidence], reason: str = "synthetic capture") -> store.RevisionWriter:
    w = st.begin_revision(reason)
    for e in evidence:
        w.add(e)
    w.seal()
    return w


def rev_dir(st: store.EvidenceStore, n: int = 1) -> Path:
    return st.root / "rev-{0:04d}".format(n)


def problems(st: store.EvidenceStore) -> List[str]:
    report = st.verify()
    return report.problems + [p for r in report.revisions for p in r.problems]


# ---------------------------------------------------------------------------
# Normal path
# ---------------------------------------------------------------------------


def test_a_sealed_revision_verifies_and_keeps_the_raw_bytes(st: store.EvidenceStore) -> None:
    cap = capture([response(raw(1))])
    write(st, cap.evidence)
    report = st.verify()
    assert report.valid and [r.status for r in report.revisions] == ["VALID"]
    eid = cap.evidence[0].evidence_id
    assert (rev_dir(st) / (eid + ".raw")).read_bytes() == raw(1)
    manifest = json.loads((rev_dir(st) / store.MANIFEST).read_text())
    assert manifest["entries"][0]["raw_sha256"] == envelope.sha256_hex(raw(1)) and manifest["previous_revision_id"] is None


def test_revisions_chain_to_the_previous_manifest(st: store.EvidenceStore) -> None:
    write(st, capture([response(raw(1))]).evidence)
    write(st, capture([response(raw(2))]).evidence)
    first = (rev_dir(st, 1) / store.MANIFEST).read_bytes()
    second = json.loads((rev_dir(st, 2) / store.MANIFEST).read_text())
    assert second["previous_revision_id"] == "rev-0001" and second["previous_manifest_sha256"] == envelope.sha256_hex(first)
    assert st.verify().valid


def test_files_and_directories_are_private(st: store.EvidenceStore) -> None:
    write(st, capture([response(raw(1))]).evidence)
    assert stat.S_IMODE(os.stat(st.root).st_mode) == 0o700 and stat.S_IMODE(os.stat(rev_dir(st)).st_mode) == 0o700
    assert {stat.S_IMODE(p.stat().st_mode) for p in rev_dir(st).iterdir()} == {0o600}


def test_verification_time_is_separate_from_capture_time(base: Path) -> None:
    later = datetime.datetime(2026, 11, 1, tzinfo=datetime.timezone.utc)
    s = store.EvidenceStore(base / "s", base, now=lambda: later)
    cap = capture([response(raw(1))])
    write(s, cap.evidence)
    report = s.verify()
    assert report.verified_at == "2026-11-01T00:00:00.000000Z"
    assert report.revisions[0].envelopes[cap.evidence[0].evidence_id]["captured_at"] == "2026-10-29T02:00:00.000001Z"


# ---------------------------------------------------------------------------
# WP2-6 abnormal cases
# ---------------------------------------------------------------------------


def test_one_changed_raw_byte_is_detected(st: store.EvidenceStore) -> None:
    cap = capture([response(raw(1))])
    write(st, cap.evidence)
    path = rev_dir(st) / (cap.evidence[0].evidence_id + ".raw")
    data = bytearray(path.read_bytes())
    data[0] ^= 1
    os.chmod(path, 0o600)
    path.write_bytes(bytes(data))
    assert any("raw content differs from the manifest" in p for p in problems(st)) and not st.verify().valid


def test_a_wrong_hash_in_the_envelope_is_refused_at_write(st: store.EvidenceStore) -> None:
    e = capture([response(raw(1))]).evidence[0]
    bad = collector.CapturedEvidence(dict(e.envelope, raw_content_sha256="0" * 64), e.raw)
    w = st.begin_revision("x")
    with pytest.raises(store.StoreError, match="sha256 differs"):
        w.add(bad)


def test_a_wrong_hash_in_the_manifest_is_detected(st: store.EvidenceStore) -> None:
    write(st, capture([response(raw(1))]).evidence)
    path = rev_dir(st) / store.MANIFEST
    m = json.loads(path.read_text())
    m["entries"][0]["raw_sha256"] = "0" * 64
    path.write_bytes(store.manifest_bytes(m))
    assert any("differs from the manifest" in p or "does not match its manifest entry" in p for p in problems(st))


def test_missing_content_is_detected(st: store.EvidenceStore) -> None:
    cap = capture([response(raw(1))])
    write(st, cap.evidence)
    (rev_dir(st) / (cap.evidence[0].evidence_id + ".raw")).unlink()
    assert any("raw content missing" in p for p in problems(st))


def test_missing_raw_bytes_are_refused_at_write(st: store.EvidenceStore) -> None:
    e = capture([response(raw(1))]).evidence[0]
    w = st.begin_revision("x")
    with pytest.raises(store.StoreError, match="raw content missing"):
        w.add(collector.CapturedEvidence(e.envelope, None))


def test_a_duplicate_evidence_id_is_refused_within_and_across_revisions(st: store.EvidenceStore) -> None:
    e = capture([response(raw(1))]).evidence[0]
    w = st.begin_revision("x")
    w.add(e)
    with pytest.raises(store.StoreError, match="duplicate evidence id"):
        w.add(e)
    w.seal()
    w2 = st.begin_revision("y")
    with pytest.raises(store.StoreError, match="duplicate evidence id"):
        w2.add(e)


def test_a_revision_is_never_overwritten(st: store.EvidenceStore) -> None:
    w = write(st, capture([response(raw(1))]).evidence)
    with pytest.raises(store.StoreError, match="sealed"):
        w.add(capture([response(raw(2))]).evidence[0])
    with pytest.raises(store.StoreError, match="already sealed"):
        w.seal()
    with pytest.raises(store.StoreError, match="refusing to overwrite revision rev-0001"):
        st._create_revision_dir(1)
    before = (rev_dir(st) / store.MANIFEST).read_bytes()
    fd = os.open(str(rev_dir(st)), os.O_RDONLY)
    try:
        with pytest.raises(store.StoreError, match="refusing to overwrite MANIFEST.json"):
            store._write_exclusive(fd, store.MANIFEST, b"{}")
    finally:
        os.close(fd)
    assert (rev_dir(st) / store.MANIFEST).read_bytes() == before


def test_a_seal_never_replaces_an_existing_manifest(st: store.EvidenceStore) -> None:
    w = st.begin_revision("x")
    w.add(capture([response(raw(1))]).evidence[0])
    (w.path / store.MANIFEST).write_bytes(b"{}")
    with pytest.raises(store.StoreError, match="refusing to overwrite MANIFEST.json"):
        w.seal()
    assert (w.path / store.MANIFEST).read_bytes() == b"{}"


def test_unfinished_pagination_is_stored_as_incomplete_evidence(st: store.EvidenceStore) -> None:
    cap = capture([response(raw(1), nxt=2), response(raw(2), nxt=3)], max_pages=2)
    write(st, cap.evidence)
    report = st.verify()
    assert report.valid
    assert {e["completeness_status"] for e in report.revisions[0].envelopes.values()} == {"INCOMPLETE"}


def test_a_claimed_complete_status_for_unfinished_pagination_is_refused(st: store.EvidenceStore) -> None:
    e = capture([response(raw(1), nxt=2), response(raw(2), nxt=3)], max_pages=2).evidence[0]
    forged = collector.CapturedEvidence(dict(e.envelope, completeness_status="COMPLETE"), e.raw)
    with pytest.raises(store.StoreError, match="claims COMPLETE"):
        st.begin_revision("x").add(forged)


def test_an_http_error_is_stored_as_incomplete_with_its_status(st: store.EvidenceStore) -> None:
    cap = capture([response(b'{"message": "Bad credentials"}', status=401)])
    write(st, cap.evidence)
    env = st.verify().revisions[0].envelopes[cap.evidence[0].evidence_id]
    assert env["http_status"] == 401 and env["capture_errors"] == ["http_error"] and env["completeness_status"] == "INCOMPLETE"


def test_a_capture_over_the_byte_limit_stores_no_partial_body(st: store.EvidenceStore) -> None:
    queue = [response(b"x" * 100)]
    c = collector.Collector(lambda r: queue.pop(0), REPO, now=lambda: T0, id_factory=lambda: "cap-limit-1", max_page_bytes=10)
    cap = c.capture("GET", EP)
    write(st, cap.evidence)
    assert not (rev_dir(st) / "cap-limit-1-p001.raw").exists()
    assert st.verify().revisions[0].envelopes["cap-limit-1-p001"]["capture_errors"] == ["byte_limit_exceeded"]


def test_secret_content_is_never_written(st: store.EvidenceStore) -> None:
    token = "gh" + "p_" + "Q7" * 18
    e = capture([response(raw(1))]).evidence[0]
    poisoned = collector.CapturedEvidence(dict(e.envelope, raw_content_sha256=envelope.sha256_hex(token.encode()),
                                               raw_content_length=len(token)), token.encode())
    w = st.begin_revision("x")
    with pytest.raises(secretgate.SecurityGateRefused) as err:
        w.add(poisoned)
    assert token not in str(err.value)
    assert list(w.path.iterdir()) == []


def test_a_secret_in_the_revision_reason_is_refused_at_seal(st: store.EvidenceStore) -> None:
    w = st.begin_revision("note " + "gh" + "p_" + "Q7" * 18)
    w.add(capture([response(raw(1))]).evidence[0])
    with pytest.raises(secretgate.SecurityGateRefused):
        w.seal()
    assert not (w.path / store.MANIFEST).exists()


def test_a_failing_scanner_refuses_the_write(st: store.EvidenceStore, monkeypatch: pytest.MonkeyPatch) -> None:
    e = capture([response(raw(1))]).evidence[0]
    real = secretgate.scan

    def broken(content: bytes, max_bytes: int = secretgate.DEFAULT_MAX_SCAN_BYTES, rules: Any = None) -> secretgate.ScanResult:
        return real(content, max_bytes, rules=lambda: (_ for _ in ()).throw(OSError("rules unreadable")))

    monkeypatch.setattr(secretgate, "scan", broken)
    w = st.begin_revision("x")
    with pytest.raises(secretgate.SecurityGateRefused, match="ERROR"):
        w.add(e)
    assert list(w.path.iterdir()) == []


def test_a_symlinked_store_root_is_refused(base: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (base / "link").symlink_to(outside, target_is_directory=True)
    with pytest.raises(store.StoreError, match="symbolic link"):
        store.EvidenceStore(base / "link", base)
    with pytest.raises(store.StoreError, match="symbolic link"):
        store.EvidenceStore(base / "link" / "inner", base)


@pytest.mark.parametrize("root", ["../escape", "/", "."])
def test_a_store_root_outside_or_equal_to_the_base_is_refused(base: Path, root: str) -> None:
    with pytest.raises(store.StoreError):
        store.EvidenceStore(Path(root) if root == "/" else base / root, base)


def test_a_revision_directory_swapped_for_a_link_is_refused(st: store.EvidenceStore, tmp_path: Path) -> None:
    w = st.begin_revision("x")
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    w.path.rmdir()
    w.path.symlink_to(outside, target_is_directory=True)
    with pytest.raises(store.StoreError, match="symbolic link is refused"):
        w.add(capture([response(raw(1))]).evidence[0])
    assert list(outside.iterdir()) == []
    assert any("symbolic link in the store root" in p for p in problems(st))


def test_a_file_replaced_by_a_link_is_detected(st: store.EvidenceStore, tmp_path: Path) -> None:
    cap = capture([response(raw(1))])
    write(st, cap.evidence)
    target = tmp_path / "copy.raw"
    target.write_bytes(raw(1))
    path = rev_dir(st) / (cap.evidence[0].evidence_id + ".raw")
    path.unlink()
    path.symlink_to(target)
    assert any("symbolic link" in p for p in problems(st))


@pytest.mark.parametrize("eid", ["../../etc-passwd", "a/b-c", "UPPER-case", "x"])
def test_an_evidence_id_that_could_traverse_is_refused(st: store.EvidenceStore, eid: str) -> None:
    e = capture([response(raw(1))]).evidence[0]
    w = st.begin_revision("x")
    with pytest.raises(store.StoreError, match="invalid id"):
        w.add(collector.CapturedEvidence(dict(e.envelope, evidence_id=eid), e.raw))


def test_a_crash_in_the_middle_leaves_a_detected_incomplete_bundle(st: store.EvidenceStore, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"n": 0}
    real = store._write_exclusive

    def crash_on_second(fd: int, name: str, data: bytes) -> None:
        calls["n"] += 1
        if calls["n"] == 2:
            raise KeyboardInterrupt("simulated crash")
        real(fd, name, data)

    w = st.begin_revision("x")
    monkeypatch.setattr(store, "_write_exclusive", crash_on_second)
    with pytest.raises(KeyboardInterrupt):
        w.add(capture([response(raw(1))]).evidence[0])
    monkeypatch.setattr(store, "_write_exclusive", real)
    report = st.verify()
    assert report.revisions[0].status == "INCOMPLETE" and not report.valid
    with pytest.raises(store.StoreError, match="does not verify"):
        st.begin_revision("next")


def test_an_interrupted_seal_is_detected(st: store.EvidenceStore) -> None:
    write(st, capture([response(raw(1))]).evidence)
    w = st.begin_revision("x")
    w.add(capture([response(raw(2))]).evidence[0])
    fd = os.open(str(w.path), os.O_RDONLY)
    try:
        store._write_exclusive(fd, store.MANIFEST_TMP, b"{")
    finally:
        os.close(fd)
    report = st.verify()
    assert report.revisions[1].status == "INCOMPLETE" and any("interrupted seal" in p for p in report.revisions[1].problems)


def test_a_schema_version_mismatch_is_refused(st: store.EvidenceStore) -> None:
    e = capture([response(raw(1))]).evidence[0]
    with pytest.raises(store.StoreError, match="schema_version"):
        st.begin_revision("x").add(collector.CapturedEvidence(dict(e.envelope, schema_version=2), e.raw))


def test_a_manifest_schema_version_mismatch_is_detected(st: store.EvidenceStore) -> None:
    write(st, capture([response(raw(1))]).evidence)
    path = rev_dir(st) / store.MANIFEST
    m = json.loads(path.read_text())
    m["manifest_schema_version"] = 2
    path.write_bytes(store.manifest_bytes(m))
    assert any("schema version 2" in p for p in problems(st))


@pytest.mark.parametrize("change,needle", [
    ({"source_type": "SCRAPED"}, "source_type: unknown"),
    ({"authenticity_verified": True}, "authenticity_verified: must be false"),
    ({"provenance_assurance": "AUTHENTICATED"}, "provenance_assurance"),
    ({"source_type": "HUMAN"}, "must be null for HUMAN evidence"),
    ({"api": None}, "API evidence needs exactly"),
    ({"api": {"endpoint": "https://api.github.com/x", "method": "GET", "version": "2022-11-28"}}, "api.endpoint"),
    ({"evaluated_at": "2026-10-29T00:00:00.000000Z"}, "unknown field(s) ['evaluated_at']"),
])
def test_invalid_provenance_is_refused(st: store.EvidenceStore, change: Dict[str, Any], needle: str) -> None:
    e = capture([response(raw(1))]).evidence[0]
    assert needle in "; ".join(envelope.envelope_problems(dict(e.envelope, **change), e.raw, raw_supplied=True))
    with pytest.raises(store.StoreError):
        st.begin_revision("p").add(collector.CapturedEvidence(dict(e.envelope, **change), e.raw))


@pytest.mark.parametrize("missing", sorted(envelope.ENVELOPE_KEYS))
def test_an_envelope_missing_any_required_field_is_not_complete(missing: str) -> None:
    e = capture([response(raw(1))]).evidence[0]
    broken = {k: v for k, v in e.envelope.items() if k != missing}
    assert not envelope.is_complete(broken, e.raw) and envelope.envelope_problems(broken, e.raw, raw_supplied=True)


def test_a_manifest_that_disagrees_with_its_content_is_detected(st: store.EvidenceStore) -> None:
    cap = capture([response(raw(1))])
    write(st, cap.evidence)
    eid = cap.evidence[0].evidence_id
    env_path = rev_dir(st) / (eid + ".envelope.json")
    env_doc = json.loads(env_path.read_text())
    env_doc["http_status"] = 404
    env_doc["capture_errors"] = ["http_error"]
    env_doc["completeness_status"] = "INCOMPLETE"
    env_path.write_bytes(envelope.canonical_bytes(env_doc))
    found = problems(st)
    assert any("envelope differs from the manifest" in p for p in found)
    assert any("completeness differ between envelope and manifest" in p for p in found)


def test_an_unlisted_file_in_a_revision_is_detected(st: store.EvidenceStore) -> None:
    write(st, capture([response(raw(1))]).evidence)
    (rev_dir(st) / "extra.raw").write_bytes(b"x")
    assert any("extra.raw: file not listed" in p for p in problems(st))


def test_a_broken_chain_is_detected(st: store.EvidenceStore) -> None:
    write(st, capture([response(raw(1))]).evidence)
    write(st, capture([response(raw(2))]).evidence)
    path = rev_dir(st, 1) / store.MANIFEST
    m = json.loads(path.read_text())
    m["reason"] = "rewritten later"
    path.write_bytes(store.manifest_bytes(m))
    assert any("previous manifest sha256 does not match rev-0001" in p for p in problems(st))


def test_a_gap_in_revision_numbers_is_detected(st: store.EvidenceStore) -> None:
    write(st, capture([response(raw(1))]).evidence)
    rev_dir(st, 1).rename(rev_dir(st, 2))
    assert any("not contiguous" in p for p in problems(st))


def test_looser_file_permissions_are_reported(st: store.EvidenceStore) -> None:
    cap = capture([response(raw(1))])
    write(st, cap.evidence)
    os.chmod(rev_dir(st) / (cap.evidence[0].evidence_id + ".raw"), 0o644)
    assert any("permissions wider than 0600" in p for p in problems(st))


def test_an_empty_revision_cannot_be_sealed(st: store.EvidenceStore) -> None:
    with pytest.raises(store.StoreError, match="empty revision"):
        st.begin_revision("x").seal()


# ---------------------------------------------------------------------------
# S7-01: s7.evidence.raw_api_data_stored
# ---------------------------------------------------------------------------


def test_s7_evidence_raw_api_data_stored(st: store.EvidenceStore, base: Path) -> None:
    """Rule behaviour test named by the Definition for criterion S7-01 (PASS / FAILED / NOT_PROVEN)."""
    assert rules.RULE_CATALOG["s7.evidence.raw_api_data_stored"].status == "IMPLEMENTED"
    assert rules.IMPLEMENTATIONS["s7.evidence.raw_api_data_stored"] is raw_api_data_stored

    two = capture([response(raw(1), nxt=2), response(raw(2))])
    unfinished = capture([response(raw(1), nxt=2), response(raw(2), nxt=3)], max_pages=2)
    error = capture([response(b'{"message": "Not Found"}', status=404)])
    meta_only_env = dict(capture([response(raw(9))]).evidence[0].envelope, raw_content_sha256=None, raw_content_length=None,
                         security_scan_status="NOT_SCANNED", completeness_status="INCOMPLETE")
    meta_only = collector.CapturedEvidence(meta_only_env, None)
    human, _ = collector.non_api_evidence("HUMAN", "hum-0001", "hum-cap-0001", "human report H02", b"BLOCKED seen in the UI\n", T0)
    assert human is not None
    write(st, two.evidence + unfinished.evidence + error.evidence + [meta_only, human])
    report = st.verify()
    assert report.valid
    ids = [e.evidence_id for e in two.evidence]

    def status(named: List[str], rep: store.StoreReport = report) -> str:
        return raw_api_data_stored(rep, named).status

    assert status(ids) == "PASS"
    assert raw_api_data_stored(report, ids).reason_code == "raw_api_bytes_stored_and_verified"
    assert status([meta_only.evidence_id]) == "FAILED"
    assert status(ids + [meta_only.evidence_id, "missing-0001"]) == "FAILED"  # a violation outranks missing evidence
    assert status(ids[:1]) == "NOT_PROVEN"                                    # a page of the capture not named
    assert status([e.evidence_id for e in unfinished.evidence]) == "NOT_PROVEN"
    assert status([e.evidence_id for e in error.evidence]) == "NOT_PROVEN"
    assert status(["hum-0001"]) == "NOT_PROVEN"
    assert status(["missing-0001"]) == "NOT_PROVEN"
    assert status([]) == "NOT_PROVEN"
    assert status(ids + ids) == "NOT_PROVEN"

    # A store that no longer verifies proves nothing, even for evidence that was fine.
    raw_path = rev_dir(st) / (ids[0] + ".raw")
    raw_path.write_bytes(raw_path.read_bytes() + b" ")
    assert raw_api_data_stored(st.verify(), ids).reason_code == "store_integrity_not_verified"


def test_the_rule_result_carries_no_evaluation_of_authenticity(st: store.EvidenceStore) -> None:
    cap = capture([response(raw(1))])
    write(st, cap.evidence)
    result = raw_api_data_stored(st.verify(), [cap.evidence[0].evidence_id])
    env = st.verify().revisions[0].envelopes[cap.evidence[0].evidence_id]
    assert result.status == "PASS" and env["authenticity_verified"] is False and env["provenance_assurance"] == "SELF_DECLARED"


def test_copy_of_an_envelope_is_independent() -> None:
    e = capture([response(raw(1))]).evidence[0]
    clone = copy.deepcopy(e.envelope)
    clone["api"]["method"] = "POST"
    assert e.envelope["api"]["method"] == "GET"
