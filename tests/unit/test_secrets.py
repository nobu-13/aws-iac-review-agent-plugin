"""Tests for the deterministic secret-detection Source (:mod:`iacreview.secrets`).

This is the v0.5.0 fifth deterministic Source. It walks the value-bearing
locations where a credential ends up in cleartext -- Lambda environment
variables, EC2 UserData, and Parameter defaults -- and reports a finding when a
value has the shape of a secret and is not an obvious placeholder. What these
tests lock:

* each location type is scanned and its positive case fires;
* placeholders and unresolved references never fire (the false-positive guard);
* every finding is Confidence: Confirmed with a REDACTED excerpt -- never the
  value itself;
* the Source is deterministic and safe on templates with no secrets.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Dict, List

import pytest

from iacreview import secrets
from iacreview.finding import CONFIRMED, REDACTED_EXCERPT, validate


def _doc(resources: Dict[str, Dict[str, Any]], parameters: Dict[str, Any] = None) -> Dict[str, Any]:
    doc: Dict[str, Any] = {"Resources": resources}
    if parameters is not None:
        doc["Parameters"] = parameters
    return doc


def _rules(findings: List[Any]) -> set:
    out = set()
    for f in findings:
        t = f.Finding
        if t.startswith("[") and "]" in t:
            out.add(t[1:t.index("]")])
    return out


# ---------------------------------------------------------------------------
# looks_like_secret / entropy
# ---------------------------------------------------------------------------


def test_recognizes_aws_access_key() -> None:
    assert secrets.looks_like_secret("AKIA" + "IOSFODNN7ABCDEFG") == "aws_access_key_id"


def test_recognizes_provider_token() -> None:
    assert secrets.looks_like_secret("sk-" + "1234567890abcdef1234") == "provider_token"


def test_recognizes_private_key_header() -> None:
    assert secrets.looks_like_secret("-----BEGIN RSA PRIVATE KEY-----") == "private_key_block"


def test_placeholder_is_never_a_secret() -> None:
    assert secrets.looks_like_secret("AKIAIOSFODNN7EXAMPLE") is None  # contains EXAMPLE
    assert secrets.looks_like_secret("your-api-key-here") is None
    assert secrets.looks_like_secret("changeme") is None


def test_empty_or_non_string_is_not_a_secret() -> None:
    assert secrets.looks_like_secret("") is None
    assert secrets.looks_like_secret(None) is None  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Lambda environment variables
# ---------------------------------------------------------------------------


def test_lambda_env_high_entropy_secret_is_flagged() -> None:
    doc = _doc({
        "Fn": {"Type": "AWS::Lambda::Function", "Properties": {
            "Environment": {"Variables": {"DB_PASSWORD": "A7f9K2mQ8xLpZ3"}}}},
    })
    findings = secrets.review(doc, template_file="t.yaml")
    assert "lambda_env_plaintext_secret" in _rules(findings)


def test_lambda_env_aws_key_is_flagged() -> None:
    doc = _doc({
        "Fn": {"Type": "AWS::Lambda::Function", "Properties": {
            "Environment": {"Variables": {"KEY": "AKIA" + "IOSFODNN7ABCDEFG"}}}},
    })
    findings = secrets.review(doc, template_file="t.yaml")
    assert "lambda_env_plaintext_secret" in _rules(findings)


def test_lambda_env_placeholder_is_not_flagged() -> None:
    doc = _doc({
        "Fn": {"Type": "AWS::Lambda::Function", "Properties": {
            "Environment": {"Variables": {"DB_PASSWORD": "your-password-here"}}}},
    })
    findings = secrets.review(doc, template_file="t.yaml")
    assert "lambda_env_plaintext_secret" not in _rules(findings)


def test_lambda_env_intrinsic_value_is_not_flagged() -> None:
    """A Ref/GetAtt value is a dict, not a literal, so it is never a secret."""
    doc = _doc({
        "Fn": {"Type": "AWS::Lambda::Function", "Properties": {
            "Environment": {"Variables": {"DB_HOST": {"Fn::GetAtt": ["Db", "Endpoint.Address"]}}}}},
    })
    findings = secrets.review(doc, template_file="t.yaml")
    assert "lambda_env_plaintext_secret" not in _rules(findings)


def test_lambda_env_nonsecret_name_short_value_is_not_flagged() -> None:
    doc = _doc({
        "Fn": {"Type": "AWS::Lambda::Function", "Properties": {
            "Environment": {"Variables": {"LOG_LEVEL": "debug"}}}},
    })
    findings = secrets.review(doc, template_file="t.yaml")
    assert findings == []


# ---------------------------------------------------------------------------
# UserData
# ---------------------------------------------------------------------------


def test_userdata_plaintext_password_is_flagged() -> None:
    doc = _doc({
        "Ec2": {"Type": "AWS::EC2::Instance", "Properties": {
            "UserData": {"Fn::Base64": {"Fn::Sub": "#!/bin/bash\necho \"DB_PASSWORD=hunter2secret\" > /etc/app.conf\n"}}}},
    })
    findings = secrets.review(doc, template_file="t.yaml")
    assert "userdata_plaintext_secret" in _rules(findings)


def test_userdata_placeholder_is_not_flagged() -> None:
    doc = _doc({
        "Ec2": {"Type": "AWS::EC2::Instance", "Properties": {
            "UserData": {"Fn::Base64": {"Fn::Sub": "echo \"DB_PASSWORD=${DbPassword}\" > /etc/app.conf\n"}}}},
    })
    findings = secrets.review(doc, template_file="t.yaml")
    assert "userdata_plaintext_secret" not in _rules(findings)


def test_userdata_plain_string_is_scanned() -> None:
    doc = _doc({
        "Ec2": {"Type": "AWS::EC2::Instance", "Properties": {
            "UserData": "export API_KEY=abcd1234efgh5678"}},
    })
    findings = secrets.review(doc, template_file="t.yaml")
    assert "userdata_plaintext_secret" in _rules(findings)


def test_userdata_absent_is_safe() -> None:
    doc = _doc({"Ec2": {"Type": "AWS::EC2::Instance", "Properties": {"ImageId": "ami-x"}}})
    assert secrets.review(doc, template_file="t.yaml") == []


# ---------------------------------------------------------------------------
# Parameter defaults
# ---------------------------------------------------------------------------


def test_parameter_default_aws_key_is_flagged() -> None:
    doc = _doc({}, parameters={"Key": {"Type": "String", "Default": "AKIA" + "IOSFODNN7ABCDEFG"}})
    findings = secrets.review(doc, template_file="t.yaml")
    assert "parameter_default_secret" in _rules(findings)


def test_parameter_default_high_entropy_secret_name_is_flagged() -> None:
    doc = _doc({}, parameters={"DBPassword": {"Type": "String", "Default": "A7f9K2mQ8xLpZ3"}})
    findings = secrets.review(doc, template_file="t.yaml")
    assert "parameter_default_secret" in _rules(findings)


def test_parameter_default_placeholder_is_not_flagged() -> None:
    doc = _doc({}, parameters={"DBPassword": {"Type": "String", "Default": "changeme"}})
    findings = secrets.review(doc, template_file="t.yaml")
    assert "parameter_default_secret" not in _rules(findings)


def test_parameter_without_default_is_safe() -> None:
    doc = _doc({}, parameters={"DBPassword": {"Type": "String", "NoEcho": True}})
    assert secrets.review(doc, template_file="t.yaml") == []


# ---------------------------------------------------------------------------
# Finding contract: always redacted, always Confirmed, always valid
# ---------------------------------------------------------------------------


def test_findings_never_contain_the_secret_value() -> None:
    """The whole point: a secret finding must not echo the secret."""
    doc = _doc({
        "Fn": {"Type": "AWS::Lambda::Function", "Properties": {
            "Environment": {"Variables": {"API_KEY": "sk-supersecret1234567890"}}}},
    })
    findings = secrets.review(doc, template_file="t.yaml")
    assert findings
    for f in findings:
        assert f.Confidence == CONFIRMED
        assert f.Source == ["Secret Review"]
        for e in f.Evidence:
            assert e.Excerpt == REDACTED_EXCERPT
            assert "supersecret" not in (e.Excerpt or "")
        assert "supersecret" not in f.Finding
        validate(dataclasses.replace(f, ID=1))


def test_empty_template_is_safe() -> None:
    assert secrets.review(_doc({}), template_file="t.yaml") == []


def test_review_is_deterministic() -> None:
    doc = _doc({
        "Fn": {"Type": "AWS::Lambda::Function", "Properties": {
            "Environment": {"Variables": {"TOKEN": "A7f9K2mQ8xLpZ3"}}}},
    })
    first = [f.Finding for f in secrets.review(doc, template_file="t.yaml")]
    second = [f.Finding for f in secrets.review(doc, template_file="t.yaml")]
    assert first == second


# ---------------------------------------------------------------------------
# Source wrapper
# ---------------------------------------------------------------------------


def test_run_and_normalize_returns_a_secret_source_result(tmp_path) -> None:
    template = tmp_path / "t.yaml"
    template.write_text(
        "Resources:\n"
        "  Fn:\n"
        "    Type: AWS::Lambda::Function\n"
        "    Properties:\n"
        "      Environment:\n"
        "        Variables:\n"
        "          API_KEY: sk-supersecret1234567890\n",
        encoding="utf-8",
    )
    result = secrets.run_and_normalize(str(template), workspace_root=tmp_path)
    assert result.source == "Secret Review"
    assert result.errors == []
    assert "lambda_env_plaintext_secret" in _rules(result.findings)
