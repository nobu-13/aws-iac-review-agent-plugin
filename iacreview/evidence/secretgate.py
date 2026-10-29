"""Pre-store Security Gate: refuse to store content that may hold a secret or PII (Phase 2 M1 WP2-3).

Source: ``docs/v2/phase2/m1/wp0/m1-architecture-proposal.md`` §5-1/§5-2 and the
WP2 instruction. Purpose: nothing reaches the Evidence Store unless this gate
says ``CLEAN``. Any other answer refuses the store.

Rules. Three credential shapes are reused unchanged from the plugin's Secret
Review (:data:`iacreview.secrets.SECRET_RULES`: AWS access key id, provider
token prefixes incl. GitHub ``gh[pousr]_``, PEM private key header). The CI
scanner ``.github/scripts/scan_secrets.py`` cannot be imported by the plugin
package and is not changed; ``tests/unit/test_evidence_secretgate.py`` checks
that every rule of that scanner, applied to a canary, is also caught here. The
rules added here cover what neither has: fine-grained GitHub PATs, the old
``v1.`` installation token, Authorization headers, Bearer values, JWTs,
environment-style and JSON secret assignments, URL credentials and e-mail
addresses.

Differences from the scanners, on purpose (fail-closed):

* No placeholder allowlist and no inline exemption marker. Captured content is
  untrusted; a word such as ``example`` next to a token must not exempt it.
* JSON content is also scanned after decoding, so a secret written with
  ``\\u`` escapes inside a JSON string is matched in its decoded form. A
  base64 ``content`` field (GitHub Contents API) is decoded and scanned too; one
  that does not decode to UTF-8 text makes the content ``UNSCANNABLE`` (WP3).
* Binary content (a NUL byte or invalid UTF-8) is ``UNSCANNABLE`` and refused,
  whatever it holds.
* Content over the size limit is ``UNSCANNABLE`` and refused.
* Any exception inside the scan is ``ERROR`` and refused.

Output never contains a matched value: a finding is a rule name, where it was
found (``raw`` or ``json_string``) and a count.

Limits. A pattern scan detects listed shapes only. ``CLEAN`` means no rule
matched; it does not prove that the content holds no secret, and it detects no
PII beyond e-mail addresses (names, logins, avatar URLs, addresses and phone
numbers are not detected).
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from typing import Any, Callable, Iterable, List, Optional, Pattern, Sequence, Tuple

from iacreview import secrets as plugin_secrets

CLEAN, DETECTED, UNSCANNABLE, ERROR = "CLEAN", "DETECTED", "UNSCANNABLE", "ERROR"

#: Largest content the gate scans; larger content is refused.
DEFAULT_MAX_SCAN_BYTES = 8 * 1024 * 1024

_NOT_URL = r"(?!https?://)"
_VALUE = r"[^\s\"'{}\[\],;]{8,}"

#: Rules added for captured evidence: (name, pattern). Matched per text, values never kept.
GATE_RULES: Tuple[Tuple[str, Pattern[str]], ...] = (
    ("github_fine_grained_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}")),
    ("github_v1_installation_token", re.compile(r"\bv1\.[0-9a-f]{40}\b")),
    ("authorization_header", re.compile(r"(?i)[\"']?\bauthorization[\"']?\s*[:=]\s*[\"']?\S{4,}")),
    ("bearer_token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}")),
    ("secret_assignment", re.compile(
        r"(?i)\b[A-Z0-9_.-]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|CLIENT[_-]?SECRET|ACCESS[_-]?KEY)"
        r"[A-Z0-9_-]*[\"']?\s*[=:]\s*[\"']?" + _NOT_URL + _VALUE)),
    ("url_credentials", re.compile(r"://[^\s/:@\"']+:[^\s/:@\"']{4,}@")),
    ("pii_email_address", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")),
)


def _all_rules() -> List[Tuple[str, Pattern[str]]]:
    reused = [(rule.name, rule.pattern) for rule in plugin_secrets.SECRET_RULES]
    return reused + list(GATE_RULES)


@dataclass(frozen=True)
class ScanResult:
    """The gate's answer. ``findings``: (rule, where, count), never a matched value."""

    status: str
    findings: Tuple[Tuple[str, str, int], ...] = ()
    reason: str = ""

    @property
    def storable(self) -> bool:
        return self.status == CLEAN


Rules = Callable[[], Sequence[Tuple[str, Pattern[str]]]]


def _match_texts(texts: Iterable[Tuple[str, str]], rules: Sequence[Tuple[str, Pattern[str]]]) -> List[Tuple[str, str, int]]:
    counts: dict = {}
    for where, text in texts:
        for name, pattern in rules:
            n = sum(1 for _ in pattern.finditer(text))
            if n:
                counts[(name, where)] = counts.get((name, where), 0) + n
    return sorted((name, where, n) for (name, where), n in counts.items())


class _Undecodable(Exception):
    """A base64 ``content`` field that does not decode to UTF-8 text: its bytes cannot be scanned."""


def _json_strings(value: Any) -> Iterable[str]:
    """Every key and string value of a parsed JSON document (iterative, so depth cannot exhaust the stack)."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            yield item
        elif isinstance(item, dict):
            for k, v in item.items():
                yield k
                stack.append(v)
            # GitHub's Contents API returns file bytes as base64: scan the decoded text too (WP3).
            if item.get("encoding") == "base64" and isinstance(item.get("content"), str):
                decoded = _b64_text(item["content"])
                if decoded is None:
                    raise _Undecodable()
                yield decoded
        elif isinstance(item, list):
            stack.extend(item)


def _b64_text(value: str) -> Optional[str]:
    try:
        data = base64.b64decode("".join(value.split()), validate=True)
    except (ValueError, binascii.Error):
        return None
    if b"\0" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _json_view(text: str) -> Optional[str]:
    """The decoded strings of ``text`` joined by newlines, or None if it is not JSON. Raises _Undecodable."""
    stripped = text.lstrip()
    if not stripped or stripped[0] not in "{[\"":
        return None
    try:
        doc = json.loads(text)
    except ValueError:
        return None
    return "\n".join(_json_strings(doc))


def scan(content: bytes, max_bytes: int = DEFAULT_MAX_SCAN_BYTES, rules: Optional[Rules] = None) -> ScanResult:
    """Scan ``content`` before it is stored. Only ``CLEAN`` may be stored."""
    try:
        if not isinstance(content, (bytes, bytearray)):
            return ScanResult(ERROR, reason="content is not bytes")
        if len(content) > max_bytes:
            return ScanResult(UNSCANNABLE, reason="content larger than {0} bytes".format(max_bytes))
        if b"\0" in content:
            return ScanResult(UNSCANNABLE, reason="binary content (NUL byte)")
        try:
            text = bytes(content).decode("utf-8")
        except UnicodeDecodeError:
            return ScanResult(UNSCANNABLE, reason="binary content (not UTF-8)")
        active = list((rules or _all_rules)())
        if not active:
            return ScanResult(ERROR, reason="no rules loaded")
        texts = [("raw", text)]
        try:
            decoded = _json_view(text)
        except _Undecodable:
            return ScanResult(UNSCANNABLE, reason="a base64 content field does not decode to text")
        if decoded is not None:
            texts.append(("json_string", decoded))
        findings = _match_texts(texts, active)
    except Exception as exc:  # noqa: BLE001 - any failure is a refusal; only the type name is kept
        return ScanResult(ERROR, reason="scanner raised {0}".format(type(exc).__name__))
    if findings:
        return ScanResult(DETECTED, tuple(findings), "{0} rule(s) matched; values not shown".format(len({f[0] for f in findings})))
    return ScanResult(CLEAN, reason="no rule matched (not a proof of absence)")


class SecurityGateRefused(Exception):
    """Raised by callers that must not continue: carries the result, never the content."""

    def __init__(self, what: str, result: ScanResult) -> None:
        super().__init__("{0}: security gate {1} ({2}; rules {3})".format(
            what, result.status, result.reason, sorted({f[0] for f in result.findings})))
        self.result = result
