"""Raw Evidence Security Policy on synthetic GitHub REST answers (Phase 2 M1 WP3-5, M1-08 regression).

Fixtures in ``tests/fixtures/evidence_raw/`` hold only safe or synthetic-PII
content. The secret-bearing and oversized cases are assembled at run time, so
no file in the repository holds a credential shape. Nothing reaches GitHub.
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Dict, List, Tuple

import pytest

from iacreview.evidence import collector, secretgate, store

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "evidence_raw"
T0 = datetime.datetime(2026, 10, 29, 5, 0, 0, tzinfo=datetime.timezone.utc)
EP = "/repos/synthetic-owner/synthetic-repo/pulls?per_page=2"

#: Fixture -> (expected gate status, storable, reason). Written before running the gate (policy, not observation).
EXPECTED: Dict[str, Tuple[str, bool, str]] = {
    "rest_check_runs_safe.json": ("CLEAN", True, "ordinary check-run answer"),
    "rest_installation_non_secret_urls.json": ("CLEAN", True, "access_tokens_url etc. are URL values, excluded from secret_assignment"),
    "rest_pulls_page1.json": ("CLEAN", True, "first page"),
    "rest_pulls_page2.json": ("CLEAN", True, "last page"),
    "rest_http_error_404.json": ("CLEAN", True, "error body; stored INCOMPLETE"),
    "rest_commit_with_email.json": ("DETECTED", False, "PII: commit author e-mail (true positive under the policy)"),
    "rest_noreply_email.json": ("DETECTED", False, "PII-like: noreply address carries the user id"),
    "job_log_masked_header.json": ("DETECTED", False, "false positive: AUTHORIZATION header with a masked value"),
}


def load(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def test_every_fixture_has_a_pre_stated_expectation() -> None:
    assert sorted(p.name for p in FIXTURES.glob("*.json")) == sorted(EXPECTED)


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_the_gate_classifies_each_fixture_as_stated(name: str) -> None:
    status, storable, _ = EXPECTED[name]
    result = secretgate.scan(load(name))
    assert result.status == status and result.storable is storable


def test_the_email_fixture_value_is_never_echoed() -> None:
    result = secretgate.scan(load("rest_commit_with_email.json"))
    assert "synthetic.person@" not in repr(result) and result.findings[0][0] == "pii_email_address"


def _secret_answer() -> bytes:
    token = "gh" + "s_" + "Q7" * 18
    return json.dumps({"token": token, "expires_at": "2026-10-29T06:00:00Z"}).encode()


def _prose_false_positive() -> bytes:
    return json.dumps({"output": {"summary": "Pass" + "word: MinimumLength12 is enforced by the template"}}).encode()


def test_a_secret_answer_and_a_prose_false_positive_are_both_refused() -> None:
    assert secretgate.scan(_secret_answer()).status == "DETECTED"
    assert secretgate.scan(_prose_false_positive()).status == "DETECTED"


def test_a_base64_contents_field_is_decoded_and_scanned() -> None:
    import base64

    inner = ("api" + "_key = " + "Q7" * 10 + "\n").encode()
    body = json.dumps({"type": "file", "encoding": "base64", "content": base64.b64encode(inner).decode()}).encode()
    assert secretgate.scan(body).status == "DETECTED"
    binary = json.dumps({"type": "file", "encoding": "base64", "content": base64.b64encode(b"\x00\xff").decode()}).encode()
    assert secretgate.scan(binary).status == "UNSCANNABLE"


def _collector(responses: List[collector.HttpResponse], **kw: int) -> collector.Collector:
    queue = list(responses)
    return collector.Collector(lambda r: queue.pop(0), "synthetic-owner/synthetic-repo", now=lambda: T0,
                               id_factory=lambda: "cap-policy-0001", **kw)


def _resp(data: bytes, link: str = "", status: int = 200) -> collector.HttpResponse:
    headers = {"Content-Type": "application/json"}
    if link:
        headers["Link"] = link
    return collector.HttpResponse(status, headers, data)


def test_a_paginated_answer_is_stored_complete_only_with_every_page(tmp_path: Path) -> None:
    nxt = '<{0}{1}&page=2>; rel="next"'.format(collector.API_ROOT, EP)
    cap = _collector([_resp(load("rest_pulls_page1.json"), nxt), _resp(load("rest_pulls_page2.json"))]).capture("GET", EP)
    assert cap.complete and len(cap.evidence) == 2
    base = tmp_path / "w"
    base.mkdir()
    st = store.EvidenceStore(base / "s", base, now=lambda: T0)
    w = st.begin_revision("policy")
    for e in cap.evidence:
        w.add(e)
    w.seal()
    assert st.verify().valid


def test_an_email_answer_is_refused_at_capture_and_never_stored(tmp_path: Path) -> None:
    cap = _collector([_resp(load("rest_commit_with_email.json"))]).capture("GET", "/repos/synthetic-owner/synthetic-repo/commits/" + "a" * 40)
    assert cap.evidence == [] and cap.refusals[0].result.status == "DETECTED"


def test_a_secret_answer_is_refused_at_capture() -> None:
    cap = _collector([_resp(_secret_answer())]).capture("GET", "/app/installations/1/access_tokens")
    assert cap.evidence == [] and cap.refusals and "gh" + "s_" not in repr(cap)


def test_an_http_error_fixture_is_stored_incomplete() -> None:
    cap = _collector([_resp(load("rest_http_error_404.json"), status=404)]).capture("GET", "/repos/synthetic-owner/synthetic-repo")
    assert cap.evidence[0].envelope["completeness_status"] == "INCOMPLETE" and "http_error" in cap.evidence[0].envelope["capture_errors"]


@pytest.mark.parametrize("size,limit", [(1025, 1024), (5000, 4096)])
def test_an_oversized_answer_is_dropped(size: int, limit: int) -> None:
    cap = _collector([_resp(b"[" + b"0," * (size // 2) + b"0]")], max_page_bytes=limit).capture("GET", EP)
    assert cap.evidence[0].raw is None and "byte_limit_exceeded" in cap.evidence[0].envelope["capture_errors"]
