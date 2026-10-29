"""Raw Evidence Collector with synthetic HTTP responses (Phase 2 M1 WP2-2).

No test reaches GitHub: every response comes from :class:`FakeTransport`.
"""

from __future__ import annotations

import datetime
import json
from typing import Dict, List, Optional

import pytest

from iacreview.evidence import collector, envelope

REPO = "synthetic-owner/synthetic-repo"
SHA = "a" * 40
T0 = datetime.datetime(2026, 10, 29, 1, 2, 3, 456789, tzinfo=datetime.timezone.utc)
ENDPOINT = "/repos/synthetic-owner/synthetic-repo/commits/" + SHA + "/check-runs?per_page=100"


def body(n: int = 1) -> bytes:
    return json.dumps({"total_count": n, "check_runs": [{"id": i, "name": "remediation-gate/verified"} for i in range(n)]},
                      sort_keys=True).encode("utf-8")


class FakeTransport:
    def __init__(self, responses: List[Optional[collector.HttpResponse]]) -> None:
        self.responses = list(responses)
        self.requests: List[collector.HttpRequest] = []

    def __call__(self, request: collector.HttpRequest) -> Optional[collector.HttpResponse]:
        self.requests.append(request)
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def ok(raw: bytes, headers: Optional[Dict[str, str]] = None, status: int = 200) -> collector.HttpResponse:
    return collector.HttpResponse(status, dict({"Content-Type": "application/json", "Content-Length": str(len(raw))}, **(headers or {})), raw)


def link(page: int) -> Dict[str, str]:
    return {"Link": '<{0}{1}&page={2}>; rel="next"'.format(collector.API_ROOT, ENDPOINT, page)}


def make(transport: FakeTransport, **kw: int) -> collector.Collector:
    counter = iter(range(1, 1000))
    return collector.Collector(transport, REPO, now=lambda: T0, id_factory=lambda: "cap-test-{0:03d}".format(next(counter)), **kw)


def capture(transport: FakeTransport, endpoint: str = ENDPOINT, **kw: int) -> collector.CaptureResult:
    return make(transport, **kw).capture("GET", endpoint, subject_commit_sha=SHA)


def test_a_single_page_is_captured_as_bytes_with_a_complete_envelope() -> None:
    raw = body() + b"\n  "  # trailing bytes a JSON round trip would drop
    result = capture(FakeTransport([ok(raw, {"Authorization": "x", "Set-Cookie": "y", "X-GitHub-Request-Id": "AB:CD"})]))
    assert result.complete and len(result.evidence) == 1 and not result.refusals
    ev = result.evidence[0]
    assert ev.raw == raw and ev.envelope["raw_content_sha256"] == envelope.sha256_hex(raw)
    assert ev.envelope["raw_content_length"] == len(raw)
    assert envelope.envelope_problems(ev.envelope, ev.raw, raw_supplied=True) == []
    e = ev.envelope
    assert e["evidence_id"] == "cap-test-001-p001" and e["capture_id"] == "cap-test-001" and e["source_type"] == "API"
    assert e["api"] == {"endpoint": ENDPOINT, "method": "GET", "version": collector.DEFAULT_API_VERSION}
    assert e["captured_at"] == "2026-10-29T01:02:03.456789Z" and "evaluated_at" not in e
    assert e["repository"] == REPO and e["subject_commit_sha"] == SHA and e["http_status"] == 200 and e["pagination_complete"] is True
    assert set(e["response_headers"]) == {"content-type", "content-length", "x-github-request-id"}  # body and metadata separate
    assert e["provenance_assurance"] == "SELF_DECLARED" and e["authenticity_verified"] is False


def test_the_hash_is_deterministic_and_depends_on_every_byte() -> None:
    a = capture(FakeTransport([ok(body())])).evidence[0].envelope["raw_content_sha256"]
    b = capture(FakeTransport([ok(body())])).evidence[0].envelope["raw_content_sha256"]
    changed = bytearray(body())
    changed[5] ^= 1
    c = capture(FakeTransport([ok(bytes(changed))])).evidence[0].envelope["raw_content_sha256"]
    assert a == b != c


def test_pages_are_followed_and_each_page_is_its_own_evidence() -> None:
    t = FakeTransport([ok(body(1), link(2)), ok(body(2), link(3)), ok(body(3))])
    result = capture(t)
    assert result.complete and [e.envelope["page"] for e in result.evidence] == [
        {"index": 1, "has_next": True}, {"index": 2, "has_next": True}, {"index": 3, "has_next": False}]
    assert [r.endpoint for r in t.requests][1].endswith("&page=2")
    assert all(e.envelope["pagination_complete"] is True for e in result.evidence)


def test_an_unfinished_pagination_is_never_complete() -> None:
    result = capture(FakeTransport([ok(body(1), link(2)), ok(body(2), link(3))]), max_pages=2)
    assert not result.complete
    assert all(e.envelope["pagination_complete"] is False and e.envelope["completeness_status"] == "INCOMPLETE" for e in result.evidence)
    assert "page_limit_reached" in result.evidence[-1].envelope["capture_errors"]


@pytest.mark.parametrize("url", ["https://evil.invalid/repos/x?page=2", collector.API_ROOT + "/repos/other/path?page=2",
                                 "http://api.github.com" + ENDPOINT + "&page=2"])
def test_a_next_link_outside_the_same_resource_is_not_followed(url: str) -> None:
    t = FakeTransport([ok(body(), {"Link": "<{0}>; rel=\"next\"".format(url)})])
    result = capture(t)
    assert len(t.requests) == 1 and not result.complete
    assert "pagination_next_refused" in result.evidence[0].envelope["capture_errors"]


@pytest.mark.parametrize("status", [401, 403, 404, 500, 302, 204])
def test_an_http_error_is_recorded_with_its_body_and_is_incomplete(status: int) -> None:
    raw = b'{"message": "Not Found"}'
    result = capture(FakeTransport([ok(raw, status=status)]))
    e = result.evidence[0].envelope
    assert e["http_status"] == status and "http_error" in e["capture_errors"] and e["completeness_status"] == "INCOMPLETE"
    assert result.evidence[0].raw == raw and not result.complete


def test_a_body_over_the_page_limit_is_dropped_not_truncated() -> None:
    result = capture(FakeTransport([ok(b"x" * 65)]), max_page_bytes=64)
    ev = result.evidence[0]
    assert ev.raw is None and ev.envelope["raw_content_sha256"] is None and "byte_limit_exceeded" in ev.envelope["capture_errors"]
    assert ev.envelope["completeness_status"] == "INCOMPLETE" and ev.envelope["security_scan_status"] == "NOT_SCANNED"


def test_the_total_byte_budget_spans_pages() -> None:
    t = FakeTransport([ok(body(1), link(2)), ok(body(1), link(3)), ok(body(1))])
    result = capture(t, max_total_bytes=len(body(1)) * 2 + 1)
    assert not result.complete and "byte_limit_exceeded" in result.evidence[-1].envelope["capture_errors"]
    assert t.requests[1].max_bytes == len(body(1)) + 1


@pytest.mark.parametrize("response,error", [
    (None, "response_missing"),
    (collector.HttpResponse(None, {}, b"{}"), "response_missing"),
    (collector.HttpResponse(200, {}, None), "body_missing"),
    (collector.TransportError("connection reset"), "transport_error"),
])
def test_a_missing_response_is_detected(response: object, error: str) -> None:
    result = capture(FakeTransport([response]))  # type: ignore[list-item]
    ev = result.evidence[0]
    assert error in ev.envelope["capture_errors"] and ev.raw is None and not result.complete
    assert envelope.envelope_problems(ev.envelope, None, raw_supplied=True) == []


def test_a_content_length_mismatch_is_a_truncated_body() -> None:
    result = capture(FakeTransport([collector.HttpResponse(200, {"Content-Length": "999"}, body())]))
    assert "body_truncated" in result.evidence[0].envelope["capture_errors"] and not result.complete


def test_a_non_json_body_is_kept_but_incomplete() -> None:
    result = capture(FakeTransport([ok(b"<html>not json</html>")]))
    assert result.evidence[0].raw == b"<html>not json</html>" and "body_not_json" in result.evidence[0].envelope["capture_errors"]


@pytest.mark.parametrize("doc,error", [
    ({"data": {"repository": {"pullRequest": {"commits": {"pageInfo": {"hasNextPage": True}}}}}}, "graphql_has_next_page"),
    ({"data": None, "errors": [{"message": "x"}]}, "graphql_errors"),
])
def test_graphql_pagination_and_errors_are_incomplete(doc: object, error: str) -> None:
    raw = json.dumps(doc).encode()
    result = make(FakeTransport([ok(raw)])).capture("POST", "graphql", body=b'{"query": "{}"}')
    assert error in result.evidence[0].envelope["capture_errors"] and not result.complete


def test_a_complete_graphql_answer_is_complete() -> None:
    raw = json.dumps({"data": {"x": {"pageInfo": {"hasNextPage": False}}}}).encode()
    assert make(FakeTransport([ok(raw)])).capture("POST", "graphql").complete


def test_a_secret_in_a_page_is_refused_and_the_capture_is_incomplete() -> None:
    token = "gh" + "p_" + "Q7" * 18
    t = FakeTransport([ok(body(1), link(2)), ok(json.dumps({"text": token}).encode())])
    result = capture(t)
    assert [r.evidence_id for r in result.refusals] == ["cap-test-001-p002"] and not result.complete
    assert [e.evidence_id for e in result.evidence] == ["cap-test-001-p001"]
    assert "sibling_page_refused" in result.evidence[0].envelope["capture_errors"]
    assert token not in repr(result)


def test_a_secret_in_a_kept_header_is_refused() -> None:
    token = "gh" + "p_" + "Q7" * 18
    result = capture(FakeTransport([ok(body(), {"Link": '<{0}/x?access_token={1}>; rel="prev"'.format(collector.API_ROOT, token)})]))
    assert result.refusals and result.refusals[0].what == "envelope" and not result.evidence


@pytest.mark.parametrize("method,endpoint", [("GET", "https://api.github.com/repos/x"), ("GET", "repos/x"), ("DELETE", "/repos/x"),
                                             ("POST", "/repos/x"), ("GET", "graphql"), ("GET", "/repos/x;rm -rf")])
def test_only_allowed_read_requests_are_made(method: str, endpoint: str) -> None:
    t = FakeTransport([ok(body())])
    with pytest.raises(ValueError):
        make(t).capture(method, endpoint)
    assert t.requests == []


def test_non_api_evidence_is_local_or_human_and_never_claims_api_fields() -> None:
    local, refusal = collector.non_api_evidence("LOCAL", "loc-0001", "loc-cap-1", "git cat-file blob " + "b" * 40, b"bytes\n", T0,
                                                repository=REPO, subject_commit_sha=SHA)
    assert refusal is None and local is not None and local.envelope["api"] is None and local.envelope["completeness_status"] == "COMPLETE"
    human, _ = collector.non_api_evidence("HUMAN", "hum-0001", "hum-cap-1", "human statement H02", b"PR #14 showed BLOCKED\n", T0)
    assert human is not None and human.envelope["provenance_assurance"] == "HUMAN_ATTESTED"
    with pytest.raises(ValueError):
        collector.non_api_evidence("API", "x-0001", "x-cap-1", "x", b"x", T0)
