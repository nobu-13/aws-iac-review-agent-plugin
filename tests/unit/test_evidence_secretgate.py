"""Pre-store Security Gate (Phase 2 M1 WP2-3).

Every canary is assembled at run time from fragments and is not a working
credential (repeated filler characters, an invalid JWT, an RFC 2606 e-mail
domain). No fixture file holds one, so the repository's own secret scan does not
match this file. Assertions check that a matched value never appears in the
gate's result, its reason or the raised message.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any, List

import pytest

from iacreview.evidence import secretgate

ROOT = Path(__file__).resolve().parents[2]

FILL = "Q7" * 20


def gh_token() -> str:
    return "gh" + "p_" + FILL[:36]


def fine_grained_pat() -> str:
    return "github" + "_pat_" + FILL[:30]


def pem() -> str:
    return "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIE" + "A" * 40 + "\n-----END RSA PRIVATE KEY-----"


def jwt() -> str:
    return "ey" + "JhbGciOiJub25lIn0" + "." + "eyJzdWIiOiJ4eHh4eHh4In0" + "." + "c2lnbmF0dXJl"


def bearer() -> str:
    return "Bear" + "er " + FILL[:24]


def auth_header() -> str:
    return "Author" + "ization: " + "Basic " + FILL[:16]


def env_secret() -> str:
    return "DB_PASS" + "WORD=" + FILL[:16]


def email() -> str:
    return "alice.synthetic" + "@" + "example.invalid"


CANARIES = {
    "github_token": (gh_token, "provider_token"),
    "fine_grained_pat": (fine_grained_pat, "github_fine_grained_pat"),
    "pem": (pem, "private_key_block"),
    "authorization_header": (auth_header, "authorization_header"),
    "bearer": (bearer, "bearer_token"),
    "jwt": (jwt, "jwt"),
    "env_secret": (env_secret, "secret_assignment"),
    "pii_email": (email, "pii_email_address"),
}


def leaked(result: secretgate.ScanResult, value: str) -> bool:
    return value in repr(result) or value in result.reason


@pytest.mark.parametrize("name", sorted(CANARIES))
def test_each_canary_shape_is_detected_and_never_echoed(name: str) -> None:
    make, rule = CANARIES[name]
    value = make()
    result = secretgate.scan(("prefix " + value + " suffix\n").encode("utf-8"))
    assert result.status == secretgate.DETECTED and not result.storable
    assert rule in {f[0] for f in result.findings}
    assert not leaked(result, value)


def test_a_secret_embedded_in_json_is_detected() -> None:
    doc = {"check_runs": [{"output": {"text": "log line " + gh_token()}}], "config": json.dumps({"tok" + "en": FILL[:20]})}
    result = secretgate.scan(json.dumps(doc).encode("utf-8"))
    assert result.status == secretgate.DETECTED
    assert {"provider_token", "secret_assignment"} <= {f[0] for f in result.findings}


def test_a_unicode_escaped_secret_inside_json_is_detected_after_decoding() -> None:
    escaped = "".join("\\u{0:04x}".format(ord(c)) for c in gh_token())
    data = ('{"note": "' + escaped + '"}').encode("ascii")
    assert gh_token().encode() not in data
    result = secretgate.scan(data)
    assert result.status == secretgate.DETECTED and ("provider_token", "json_string", 1) in result.findings


def test_synthetic_personal_data_in_a_user_object_is_detected() -> None:
    user = {"login": "synthetic-user", "id": 1, "email": email(), "name": "Synthetic Person"}
    result = secretgate.scan(json.dumps({"author": user}).encode("utf-8"))
    assert result.status == secretgate.DETECTED and "pii_email_address" in {f[0] for f in result.findings}
    assert not leaked(result, email())


def test_pii_beyond_email_is_not_claimed_to_be_detected() -> None:
    """Names and logins pass: the gate does not claim to find arbitrary PII (documented limit)."""
    result = secretgate.scan(json.dumps({"login": "synthetic-user", "name": "Synthetic Person"}).encode("utf-8"))
    assert result.status == secretgate.CLEAN and "not a proof of absence" in result.reason


@pytest.mark.parametrize("data", [b"\x00\x01binary", b"\xff\xfe\xfd", b"\x89PNG\r\n\x1a\n\x00"])
def test_binary_content_is_unscannable_and_refused(data: bytes) -> None:
    result = secretgate.scan(data)
    assert result.status == secretgate.UNSCANNABLE and not result.storable


def test_binary_content_hiding_a_token_is_refused_too() -> None:
    assert not secretgate.scan(b"\x00" + gh_token().encode() + b"\x00").storable


def test_content_over_the_size_limit_is_refused() -> None:
    result = secretgate.scan(b"a" * 101, max_bytes=100)
    assert result.status == secretgate.UNSCANNABLE and "larger than 100" in result.reason
    assert secretgate.scan(b"a" * 100, max_bytes=100).status == secretgate.CLEAN


def test_a_scanner_exception_is_an_error_and_refused() -> None:
    def broken() -> List[Any]:
        raise RuntimeError("boom " + gh_token())

    result = secretgate.scan(b"{}", rules=broken)
    assert result.status == secretgate.ERROR and not result.storable
    assert result.reason == "scanner raised RuntimeError" and not leaked(result, gh_token())


def test_no_rules_is_an_error() -> None:
    assert secretgate.scan(b"{}", rules=lambda: []).status == secretgate.ERROR


@pytest.mark.parametrize("value", [None, "text", 3])
def test_non_bytes_content_is_an_error(value: Any) -> None:
    assert secretgate.scan(value).status == secretgate.ERROR  # type: ignore[arg-type]


def test_placeholder_words_do_not_exempt_a_match() -> None:
    """Unlike the CI scanner, the gate has no allowlist: captured content is untrusted."""
    result = secretgate.scan(("example placeholder " + gh_token() + " secret-scan:allow").encode())
    assert result.status == secretgate.DETECTED


def test_the_refusal_exception_names_rules_but_not_values() -> None:
    result = secretgate.scan(gh_token().encode())
    message = str(secretgate.SecurityGateRefused("ev-1", result))
    assert "provider_token" in message and gh_token() not in message


def test_ordinary_github_api_json_is_clean() -> None:
    body = {"total_count": 1, "check_runs": [{"id": 900000001, "name": "remediation-gate/verified", "conclusion": "failure",
                                               "external_id": "900000002.1:" + "a" * 64, "head_sha": "b" * 40,
                                               "app": {"id": 1000001, "slug": "synthetic-app"},
                                               "html_url": "https://github.com/o/r/runs/1"}],
            "security_and_analysis": {"secret_scanning": {"status": "disabled"}}}
    assert secretgate.scan(json.dumps(body).encode()).status == secretgate.CLEAN


def _ci_scanner() -> Any:
    path = ROOT / ".github" / "scripts" / "scan_secrets.py"
    spec = importlib.util.spec_from_file_location("ci_script_scan_secrets_gate", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _ci_canary(rule_name: str) -> str:
    """One canary per CI scanner rule, built from fragments (rule names are joined too, so that no line of
    this file is itself a keyword followed by a value)."""
    table = [
        (("aws_access", "_key_id"), "AK" + "IA" + "Q7Q7Q7Q7Q7Q7Q7Q7"),
        (("aws_secret", "_access_key"), "aws_secret_" + "access_key = " + "Q7" * 20),
        (("aws_session", "_token"), "aws_session_" + "token = " + "Q7" * 30),
        (("private_key", "_block"), pem()),
        (("provider", "_token"), gh_token()),
        (("secret", "_assignment"), "pass" + 'word = "' + FILL[:12] + '"'),
        (("url", "_credentials"), "https://" + "user:" + FILL[:8] + "@" + "host.invalid/x"),
    ]
    return {"".join(parts): canary for parts, canary in table}[rule_name]


def test_every_ci_scanner_rule_is_also_caught_by_the_gate() -> None:
    """Parity with .github/scripts/scan_secrets.py (read-only): no shape it knows passes the gate."""
    scanner = _ci_scanner()
    names = [rule.name for rule in scanner.RULES]
    assert names, "the CI scanner has no rules"
    for name in names:
        canary = _ci_canary(name)
        assert scanner.scan_text("canary.txt", canary), (name, "canary does not match the CI rule")
        assert secretgate.scan(canary.encode()).status == secretgate.DETECTED, name


def test_gate_rule_names_are_unique() -> None:
    names = [n for n, _ in secretgate._all_rules()]
    assert len(names) == len(set(names)) and all(re.match(r"^[a-z0-9_]+$", n) for n in names)
