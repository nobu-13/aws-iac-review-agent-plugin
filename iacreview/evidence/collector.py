"""Raw Evidence Collector: capture HTTP responses as bytes, with an envelope per page (Phase 2 M1 WP2-2).

Source: ``docs/v2/phase2/m1/wp0/m1-architecture-proposal.md`` §3-2, WP0 helper
audit HA-3 / HA-4 (Phase 1 parsed responses and kept only fields, and never
checked pagination). Purpose: keep the bytes GitHub returned, before any JSON
parse, and record every way a capture can be incomplete.

Scope (WP2): the collector and a :class:`Transport` interface. No transport
that reaches GitHub is implemented here; tests use synthetic responses.
A real transport needs its own approval and must honour the contract below.

Transport contract: ``fetch`` returns at most ``request.max_bytes + 1`` body
bytes (one more than allowed, so that an overflow is visible), the HTTP status
and the response headers, or raises :class:`TransportError`.

Behaviour, all fail-closed:

* body over the per-page or total byte limit: ``byte_limit_exceeded``; the
  bytes are dropped, never stored truncated
* HTTP status other than 200: ``http_error``; the body is still captured
* no response, no status, no body: ``response_missing`` / ``body_missing``
* ``Content-Length`` different from the bytes received: ``body_truncated``
* REST pagination by ``Link: rel="next"``; a next URL outside the same API
  resource is not followed (``pagination_next_refused``); stopping at the page
  limit is ``page_limit_reached``
* GraphQL: ``hasNextPage: true`` anywhere, or an ``errors`` member, makes the
  capture incomplete (cursors are not followed in WP2)
* a ``text/plain`` body (Actions job logs) must be UTF-8 text (``body_not_text``); any other body must
  be JSON (``body_not_json``)
* the body and the envelope are scanned by :mod:`iacreview.evidence.secretgate`
  before the evidence is returned; anything not ``CLEAN`` is refused and its
  bytes are dropped
* ``pagination_complete`` is true only if the last page fetched has no next
  page and nothing above happened; an envelope is ``COMPLETE`` only then

Headers are kept only from :data:`iacreview.evidence.envelope.KEPT_HEADERS`;
authorization, cookies and token scopes are never kept. The JSON parse done
for the completeness checks never replaces the raw bytes.
"""

from __future__ import annotations

import datetime
import json
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

from iacreview.evidence import envelope as env
from iacreview.evidence import secretgate

API_ROOT = "https://api.github.com"
DEFAULT_API_VERSION = "2022-11-28"
DEFAULT_MAX_PAGE_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_PAGES = 50

_LINK_NEXT = re.compile(r'<([^>]+)>\s*;\s*rel="next"')


class TransportError(Exception):
    """The transport could not deliver a response."""


@dataclass(frozen=True)
class HttpRequest:
    method: str
    endpoint: str
    api_version: str
    max_bytes: int
    body: Optional[bytes] = None


@dataclass(frozen=True)
class HttpResponse:
    status: Optional[int]
    headers: Mapping[str, str]
    body: Optional[bytes]


Transport = Callable[[HttpRequest], Optional[HttpResponse]]


@dataclass(frozen=True)
class CapturedEvidence:
    """One storable page: its envelope and its raw bytes (None when nothing was received)."""

    envelope: Dict[str, Any]
    raw: Optional[bytes]

    @property
    def evidence_id(self) -> str:
        return str(self.envelope["evidence_id"])


@dataclass(frozen=True)
class Refusal:
    """A page the security gate refused. Holds no content."""

    evidence_id: str
    what: str
    result: secretgate.ScanResult


@dataclass
class CaptureResult:
    capture_id: str
    evidence: List[CapturedEvidence] = field(default_factory=list)
    refusals: List[Refusal] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        """True only when every page is COMPLETE and nothing was refused."""
        return bool(self.evidence) and not self.refusals and all(e.envelope["completeness_status"] == "COMPLETE" for e in self.evidence)


def utc_stamp(now: datetime.datetime) -> str:
    return now.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _default_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _kept_headers(headers: Mapping[str, str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in (headers or {}).items():
        key = str(k).lower()
        if key in env.KEPT_HEADERS:
            out[key] = str(v)
    return out


def next_endpoint(link: Optional[str], current: str) -> Tuple[Optional[str], bool]:
    """(next relative endpoint, refused). A next URL must stay on the API root and the same resource path."""
    if not link:
        return None, False
    m = _LINK_NEXT.search(link)
    if not m:
        return None, False
    url = m.group(1)
    if not url.startswith(API_ROOT + "/"):
        return None, True
    rel = url[len(API_ROOT):]
    if not env.ENDPOINT.match(rel) or rel.split("?", 1)[0] != current.split("?", 1)[0]:
        return None, True
    return rel, False


def _graphql_flags(doc: Any) -> List[str]:
    errors = []
    if isinstance(doc, dict) and doc.get("errors"):
        errors.append("graphql_errors")
    stack = [doc]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            info = item.get("pageInfo")
            if isinstance(info, dict) and info.get("hasNextPage") is True:
                errors.append("graphql_has_next_page")
                break
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return errors


def is_text_body(content_type: Optional[str]) -> bool:
    """A ``text/plain`` body (Actions job logs) is checked as UTF-8 text; anything else as JSON (WP4, Gap G-6)."""
    return str(content_type or "").split(";")[0].strip().lower() == "text/plain"


def _parse_flags(body: bytes, graphql: bool, content_type: Optional[str] = None) -> List[str]:
    if is_text_body(content_type) and not graphql:
        try:
            body.decode("utf-8")
        except UnicodeDecodeError:
            return ["body_not_text"]
        return []
    try:
        doc = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return ["body_not_json"]
    return _graphql_flags(doc) if graphql else []


class Collector:
    """Captures one API resource (all of its pages) per :meth:`capture` call."""

    def __init__(self, transport: Transport, repository: str, now: Callable[[], datetime.datetime] = _default_now,
                 id_factory: Callable[[], str] = lambda: "cap-" + uuid.uuid4().hex[:24],
                 max_page_bytes: int = DEFAULT_MAX_PAGE_BYTES, max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
                 max_pages: int = DEFAULT_MAX_PAGES) -> None:
        if max_page_bytes <= 0 or max_total_bytes <= 0 or max_pages <= 0:
            raise ValueError("limits must be positive")
        self.transport = transport
        self.repository = repository
        self.now = now
        self.id_factory = id_factory
        self.max_page_bytes = max_page_bytes
        self.max_total_bytes = max_total_bytes
        self.max_pages = max_pages

    def capture(self, method: str, endpoint: str, subject_commit_sha: Optional[str] = None,
                api_version: str = DEFAULT_API_VERSION, body: Optional[bytes] = None) -> CaptureResult:
        if method not in env.API_METHODS or not env.ENDPOINT.match(endpoint) or (method == "POST") != (endpoint == "graphql"):
            raise ValueError("refusing request: method/endpoint not allowed")
        capture_id = self.id_factory()
        if not env.EVIDENCE_ID.match(capture_id) or len(capture_id) > 90:
            raise ValueError("invalid capture id")
        result = CaptureResult(capture_id)
        pages: List[Dict[str, Any]] = []  # pending page records, finalised once pagination is known
        total = 0
        current: Optional[str] = endpoint
        index = 0
        capture_errors: List[str] = []
        while current is not None:
            index += 1
            remaining = min(self.max_page_bytes, self.max_total_bytes - total)
            request = HttpRequest(method, current, api_version, max(remaining, 0), body)
            page: Dict[str, Any] = {"index": index, "endpoint": current, "status": None, "headers": {}, "raw": None,
                                    "errors": [], "has_next": False}
            pages.append(page)
            try:
                response = self.transport(request) if remaining > 0 else None
            except TransportError:
                response, page["errors"] = None, ["transport_error"]
            page["captured_at"] = utc_stamp(self.now())
            if remaining <= 0:
                page["errors"] = ["byte_limit_exceeded"]
                break
            if response is None or response.status is None:
                page["errors"] = page["errors"] or ["response_missing"]
                break
            page["status"] = response.status
            page["headers"] = _kept_headers(response.headers)
            if response.body is None:
                page["errors"] = ["body_missing"]
                break
            raw = bytes(response.body)
            if len(raw) > request.max_bytes:
                page["errors"] = ["byte_limit_exceeded"]
                break
            total += len(raw)
            page["raw"] = raw
            declared = page["headers"].get("content-length")
            if declared is not None and declared.strip() != str(len(raw)):
                page["errors"].append("body_truncated")
            if response.status != 200:
                page["errors"].append("http_error")
                break
            page["errors"] += _parse_flags(raw, endpoint == "graphql", page["headers"].get("content-type"))
            nxt, refused = (None, False) if endpoint == "graphql" else next_endpoint(page["headers"].get("link"), current)
            page["has_next"] = nxt is not None or refused
            if refused:
                capture_errors.append("pagination_next_refused")
                break
            if page["errors"]:
                break
            if nxt is not None and index >= self.max_pages:
                capture_errors.append("page_limit_reached")
                break
            current = nxt
        last = pages[-1]
        pagination_complete = not last["has_next"] and not capture_errors and not any(p["errors"] for p in pages)
        last["errors"] += capture_errors
        records = [self._record(result.capture_id, page, method, api_version, subject_commit_sha, pagination_complete)
                   for page in pages]
        kept: List[CapturedEvidence] = []
        for record, page in zip(records, pages):
            refusal = _gate(record, page["raw"], self.max_page_bytes)
            if refusal is not None:
                result.refusals.append(refusal)
            else:
                kept.append(CapturedEvidence(record, page["raw"]))
        if result.refusals:
            # A refused page leaves the capture incomplete: no sibling page may claim COMPLETE.
            kept = [_with_error(e, "sibling_page_refused") for e in kept]
        result.evidence.extend(kept)
        return result

    def _record(self, capture_id: str, page: Dict[str, Any], method: str, api_version: str,
                subject: Optional[str], pagination_complete: bool) -> Dict[str, Any]:
        raw: Optional[bytes] = page["raw"]
        record: Dict[str, Any] = {
            "schema_version": env.ENVELOPE_SCHEMA_VERSION, "evidence_id": "{0}-p{1:03d}".format(capture_id, page["index"]),
            "capture_id": capture_id, "source_type": "API", "source_locator": "{0} {1}".format(method, page["endpoint"]),
            "captured_at": page["captured_at"], "repository": self.repository, "subject_commit_sha": subject,
            "api": {"endpoint": page["endpoint"], "method": method, "version": api_version},
            "http_status": page["status"], "pagination_complete": pagination_complete,
            "page": {"index": page["index"], "has_next": page["has_next"]},
            "raw_content_sha256": env.sha256_hex(raw) if raw is not None else None,
            "raw_content_length": len(raw) if raw is not None else None,
            "response_headers": page["headers"], "capture_tool_version": env.CAPTURE_TOOL_VERSION,
            "provenance_assurance": env.PROVENANCE_ASSURANCE["API"], "authenticity_verified": False,
            "security_scan_status": "CLEAN" if raw is not None else "NOT_SCANNED",
            "capture_errors": sorted(set(page["errors"])), "completeness_status": "INCOMPLETE",
        }
        record["completeness_status"] = env.expected_completeness(record)
        return record


def _gate(record: Dict[str, Any], raw: Optional[bytes], max_bytes: int) -> Optional[Refusal]:
    """Scan the raw bytes and the envelope; a Refusal if either is not CLEAN."""
    if raw is not None:
        scan = secretgate.scan(raw, max_bytes=max_bytes)
        if not scan.storable:
            return Refusal(str(record["evidence_id"]), "raw content", scan)
    meta = secretgate.scan(env.canonical_bytes(record))
    if not meta.storable:
        return Refusal(str(record["evidence_id"]), "envelope", meta)
    return None


def _with_error(e: CapturedEvidence, error: str) -> CapturedEvidence:
    record = dict(e.envelope, capture_errors=sorted(set(e.envelope["capture_errors"]) | {error}))
    record["completeness_status"] = env.expected_completeness(record)
    return CapturedEvidence(record, e.raw)


def non_api_evidence(source_type: str, evidence_id: str, capture_id: str, source_locator: str, raw: bytes,
                     captured_at: datetime.datetime, repository: Optional[str] = None,
                     subject_commit_sha: Optional[str] = None) -> Tuple[Optional[CapturedEvidence], Optional[Refusal]]:
    """LOCAL (a file or git object read locally) or HUMAN (a statement typed by a person) evidence."""
    if source_type not in ("LOCAL", "HUMAN"):
        raise ValueError("source_type must be LOCAL or HUMAN")
    record: Dict[str, Any] = {
        "schema_version": env.ENVELOPE_SCHEMA_VERSION, "evidence_id": evidence_id, "capture_id": capture_id,
        "source_type": source_type, "source_locator": source_locator, "captured_at": utc_stamp(captured_at),
        "repository": repository, "subject_commit_sha": subject_commit_sha, "api": None, "http_status": None,
        "pagination_complete": None, "page": None, "raw_content_sha256": env.sha256_hex(raw), "raw_content_length": len(raw),
        "response_headers": {}, "capture_tool_version": env.CAPTURE_TOOL_VERSION,
        "provenance_assurance": env.PROVENANCE_ASSURANCE[source_type], "authenticity_verified": False,
        "security_scan_status": "CLEAN", "capture_errors": [], "completeness_status": "INCOMPLETE",
    }
    record["completeness_status"] = env.expected_completeness(record)
    refusal = _gate(record, raw, secretgate.DEFAULT_MAX_SCAN_BYTES)
    if refusal is not None:
        return None, refusal
    problems = env.envelope_problems(record, raw, raw_supplied=True)
    if problems:
        raise ValueError("invalid evidence: " + "; ".join(problems))
    return CapturedEvidence(record, raw), None
