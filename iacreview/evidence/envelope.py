"""Evidence Envelope: metadata of one captured piece of evidence (Phase 2 M1 WP2-1).

Source: ``docs/v2/phase2/m1/wp0/m1-architecture-proposal.md`` §4-2 and the WP2
instruction (field list). Purpose: Phase 1 kept only fields copied out of
GitHub's answers, with no capture time, no hash and no record of who or what
produced them (WP0 helper audit HA-3, HA-10). An envelope carries that
metadata next to the raw bytes, and :func:`envelope_problems` refuses any
envelope that is incomplete or inconsistent with its raw content.

Time: ``captured_at`` is when the bytes were received. Evaluation time is never
part of an envelope (``evaluated_at`` is an unknown field); verifiers and
evaluators record their own time in their own output.

Provenance: ``source_type`` says where the bytes came from (API / LOCAL /
HUMAN). For API evidence that is the collector's own statement:
``provenance_assurance`` is always ``SELF_DECLARED`` and
``authenticity_verified`` is always ``False``. GitHub signs no response, so
nothing here proves that the bytes came from GitHub or from an authenticated
call (WP0 architecture §5-7).

Standard library only. Pure functions; no I/O.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, FrozenSet, List, Mapping, Optional

ENVELOPE_SCHEMA_VERSION = 1

#: The capture code's own version, recorded in every envelope it writes.
CAPTURE_TOOL_VERSION = "iacreview.evidence.collector/1"

SOURCE_TYPES: FrozenSet[str] = frozenset({"API", "LOCAL", "HUMAN"})
API_METHODS: FrozenSet[str] = frozenset({"GET", "POST"})
SECURITY_SCAN_STATUSES: FrozenSet[str] = frozenset({"CLEAN", "DETECTED", "UNSCANNABLE", "ERROR", "NOT_SCANNED"})
COMPLETENESS_STATUSES: FrozenSet[str] = frozenset({"COMPLETE", "INCOMPLETE"})
PROVENANCE_ASSURANCE: Mapping[str, str] = {"API": "SELF_DECLARED", "LOCAL": "SELF_DECLARED", "HUMAN": "HUMAN_ATTESTED"}

#: Response headers an envelope may keep. Anything else (authorization, cookies, scopes) is dropped.
KEPT_HEADERS: FrozenSet[str] = frozenset({
    "content-type", "content-length", "etag", "link", "last-modified", "x-github-request-id",
    "x-github-api-version-selected", "date",
})

#: Closed vocabulary of capture errors.
CAPTURE_ERRORS: FrozenSet[str] = frozenset({
    "http_error", "response_missing", "body_missing", "body_truncated", "byte_limit_exceeded", "page_limit_reached",
    "pagination_next_refused", "graphql_errors", "graphql_has_next_page", "transport_error", "body_not_json",
    "sibling_page_refused", "body_not_text",
})

ENVELOPE_KEYS: FrozenSet[str] = frozenset({
    "schema_version", "evidence_id", "capture_id", "source_type", "source_locator", "captured_at", "repository",
    "subject_commit_sha", "api", "http_status", "pagination_complete", "page", "raw_content_sha256",
    "raw_content_length", "response_headers", "capture_tool_version", "provenance_assurance", "authenticity_verified",
    "security_scan_status", "capture_errors", "completeness_status",
})
API_KEYS: FrozenSet[str] = frozenset({"endpoint", "method", "version"})
PAGE_KEYS: FrozenSet[str] = frozenset({"index", "has_next"})

EVIDENCE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{2,95}$")
_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_SHA64 = re.compile(r"^[0-9a-f]{64}$")
_STAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$")
_REPO = re.compile(r"^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$")
#: API endpoint: a path relative to the API root, or "graphql". Never a scheme or a host.
ENDPOINT = re.compile(r"^(graphql|/[A-Za-z0-9._~/%-]{1,400}(\?[A-Za-z0-9._~=&%,-]{0,400})?)$")
_API_VERSION = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_bytes(envelope: Mapping[str, Any]) -> bytes:
    """The stored form of an envelope: sorted keys, ASCII, fixed separators, trailing newline."""
    return (json.dumps(envelope, sort_keys=True, ensure_ascii=True, indent=2) + "\n").encode("ascii")


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def expected_completeness(envelope: Mapping[str, Any]) -> str:
    """COMPLETE only for API evidence with HTTP 200, a complete pagination, raw content scanned CLEAN and no
    capture error. LOCAL and HUMAN evidence is COMPLETE when its raw content is present and CLEAN."""
    has_raw = envelope.get("raw_content_sha256") is not None
    clean = envelope.get("security_scan_status") == "CLEAN"
    if not has_raw or not clean or envelope.get("capture_errors"):
        return "INCOMPLETE"
    if envelope.get("source_type") == "API":
        if envelope.get("http_status") != 200 or envelope.get("pagination_complete") is not True:
            return "INCOMPLETE"
    return "COMPLETE"


def _provenance_problems(env: Mapping[str, Any]) -> List[str]:
    problems: List[str] = []
    st = env["source_type"]
    if st not in SOURCE_TYPES:
        return ["source_type: unknown {0!r}".format(st)]
    if env["provenance_assurance"] != PROVENANCE_ASSURANCE[st]:
        problems.append("provenance_assurance: must be {0!r} for {1} evidence".format(PROVENANCE_ASSURANCE[st], st))
    if env["authenticity_verified"] is not False:
        problems.append("authenticity_verified: must be false (no response is signed; origin is self-declared)")
    api = env["api"]
    if st == "API":
        if not isinstance(api, dict) or set(api) != API_KEYS:
            problems.append("api: API evidence needs exactly endpoint, method, version")
        else:
            if not (isinstance(api["endpoint"], str) and ENDPOINT.match(api["endpoint"])):
                problems.append("api.endpoint: must be an API-relative path or 'graphql'")
            if api["method"] not in API_METHODS:
                problems.append("api.method: must be GET or POST")
            elif (api["method"] == "POST") != (api.get("endpoint") == "graphql"):
                problems.append("api.method: POST only for graphql, GET otherwise")
            if not (isinstance(api["version"], str) and _API_VERSION.match(api["version"])):
                problems.append("api.version: must be the requested API version (YYYY-MM-DD)")
        if not (_is_int(env["http_status"]) or env["http_status"] is None):
            problems.append("http_status: integer or null")
        if not isinstance(env["pagination_complete"], bool):
            problems.append("pagination_complete: true or false for API evidence")
        if not (isinstance(env["repository"], str) and _REPO.match(env["repository"])):
            problems.append("repository: owner/name for API evidence")
    else:
        for key in ("api", "http_status", "pagination_complete", "page"):
            if env[key] is not None:
                problems.append("{0}: must be null for {1} evidence".format(key, st))
        if env["response_headers"] != {}:
            problems.append("response_headers: must be empty for {0} evidence".format(st))
        if env["repository"] is not None and not (isinstance(env["repository"], str) and _REPO.match(env["repository"])):
            problems.append("repository: owner/name or null")
    return problems


def envelope_problems(env: Any, raw: Optional[bytes] = None, raw_supplied: bool = False) -> List[str]:
    """Every problem with ``env``; empty means valid.

    With ``raw_supplied`` the raw bytes (or None for "no raw file") are checked against the recorded hash and length.
    """
    if not isinstance(env, dict):
        return ["envelope: must be an object"]
    missing = sorted(ENVELOPE_KEYS - set(env))
    unknown = sorted(set(env) - ENVELOPE_KEYS)
    if missing or unknown:
        return ["envelope: missing field(s) {0}, unknown field(s) {1}".format(missing, unknown)]
    problems: List[str] = []
    if env["schema_version"] != ENVELOPE_SCHEMA_VERSION or not _is_int(env["schema_version"]):
        problems.append("schema_version: must be {0}".format(ENVELOPE_SCHEMA_VERSION))
    for key in ("evidence_id", "capture_id"):
        if not (isinstance(env[key], str) and EVIDENCE_ID.match(env[key])):
            problems.append("{0}: invalid id".format(key))
    if not (isinstance(env["source_locator"], str) and env["source_locator"].strip() and len(env["source_locator"]) <= 500):
        problems.append("source_locator: non-empty string of at most 500 characters")
    if not (isinstance(env["captured_at"], str) and _STAMP.match(env["captured_at"])):
        problems.append("captured_at: UTC timestamp YYYY-MM-DDTHH:MM:SS.ffffffZ")
    if env["subject_commit_sha"] is not None and not (isinstance(env["subject_commit_sha"], str) and _SHA40.match(env["subject_commit_sha"])):
        problems.append("subject_commit_sha: 40 lowercase hex or null")
    if env["capture_tool_version"] != CAPTURE_TOOL_VERSION:
        problems.append("capture_tool_version: unknown {0!r}".format(env["capture_tool_version"]))
    if not isinstance(env["response_headers"], dict) or not all(
            isinstance(k, str) and k in KEPT_HEADERS and isinstance(v, str) for k, v in env["response_headers"].items()):
        problems.append("response_headers: only kept headers, string values")
    page = env["page"]
    if env["source_type"] == "API" and not (isinstance(page, dict) and set(page) == PAGE_KEYS and _is_int(page["index"])
                                             and page["index"] >= 1 and isinstance(page["has_next"], bool)):
        problems.append("page: {index >= 1, has_next} for API evidence")
    errors = env["capture_errors"]
    if not isinstance(errors, list) or any(e not in CAPTURE_ERRORS for e in errors) or errors != sorted(set(errors)):
        problems.append("capture_errors: sorted unique values from the closed set")
    if env["security_scan_status"] not in SECURITY_SCAN_STATUSES:
        problems.append("security_scan_status: unknown {0!r}".format(env["security_scan_status"]))
    if env["completeness_status"] not in COMPLETENESS_STATUSES:
        problems.append("completeness_status: unknown {0!r}".format(env["completeness_status"]))
    problems += _provenance_problems(env)
    sha, length = env["raw_content_sha256"], env["raw_content_length"]
    if sha is None:
        if length is not None:
            problems.append("raw_content_length: must be null when there is no raw content")
        if env["security_scan_status"] != "NOT_SCANNED":
            problems.append("security_scan_status: NOT_SCANNED when there is no raw content")
    else:
        if not (isinstance(sha, str) and _SHA64.match(sha)):
            problems.append("raw_content_sha256: 64 lowercase hex or null")
        if not (_is_int(length) and length >= 0):
            problems.append("raw_content_length: non-negative integer")
    if not problems and env["completeness_status"] != expected_completeness(env):
        problems.append("completeness_status: claims {0}, the metadata gives {1}".format(env["completeness_status"], expected_completeness(env)))
    if raw_supplied:
        if raw is None and sha is not None:
            problems.append("raw content missing (the envelope records sha256 {0}…)".format(str(sha)[:12]))
        elif raw is not None and sha is None:
            problems.append("raw content present but the envelope records none")
        elif raw is not None:
            if len(raw) != length:
                problems.append("raw content length {0} differs from the recorded {1}".format(len(raw), length))
            if sha256_hex(raw) != sha:
                problems.append("raw content sha256 differs from the recorded value")
    return problems


def is_complete(env: Any, raw: Optional[bytes]) -> bool:
    """True only for a valid envelope whose raw bytes match and whose status is COMPLETE."""
    return not envelope_problems(env, raw, raw_supplied=True) and env["completeness_status"] == "COMPLETE"


def parse_envelope_bytes(data: bytes) -> Dict[str, Any]:
    """Strict JSON (no duplicate keys, no NaN); raises ValueError."""

    def pairs(items: List[Any]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for k, v in items:
            if k in out:
                raise ValueError("duplicate key")
            out[k] = v
        return out

    def constant(name: str) -> Any:
        raise ValueError("non-standard constant")

    obj = json.loads(data.decode("ascii"), object_pairs_hook=pairs, parse_constant=constant)
    if not isinstance(obj, dict):
        raise ValueError("not an object")
    return obj
