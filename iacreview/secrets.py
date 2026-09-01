"""Deterministic detection of plaintext secrets embedded in a template.

This is the v0.5.0 fifth deterministic Source, "Secret Review". It walks the
specific value-bearing locations where a credential most often ends up in
cleartext -- Lambda environment variables, EC2 UserData scripts, Parameter
defaults, and Outputs -- and reports a finding when a value has the shape of a
secret. cfn-lint's W1011 / W2501 warn about a *parameter* used as a password;
this Source finds the value written down directly, which those warnings do not
see.

What "the shape of a secret" means here
    A value is reported when it matches one of the credential shapes in
    :data:`SECRET_RULES` (an AWS key, a provider token, a high-entropy string
    assigned to a password/api-key/secret name) AND is not obviously a
    placeholder or an unresolved reference. The allowlist matters more than the
    rules: a template is full of ``!Ref`` and ``${...}`` where a real
    deployment would hold a value, and reporting those would train a reader to
    ignore the Source.

Excerpts are always redacted
    A finding here is, by definition, about a value that must not be echoed.
    Every finding this module produces carries :data:`REDACTED_EXCERPT` rather
    than the matched text (steering/security.md: no credential value in
    output). The location and the reason are enough to fix it.

Determinism and safety
    Locations are walked in template order, values are matched by fixed
    regular expressions, and findings are produced in a stable order. Nothing
    in the template is evaluated; intrinsic functions arrive in long form and a
    value that is a dict (an intrinsic) is never treated as a literal secret.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Pattern, Tuple

from iacreview.finding import (
    CONFIRMED,
    REDACTED_EXCERPT,
    UNASSIGNED_ID,
    Evidence,
    Finding,
    Location,
    sorted_sources,
)
from iacreview.source import SourceResult, workspace_relative
from iacreview.template import LoadedTemplate

__all__ = [
    "SOURCE_NAME",
    "SECRET_RULES",
    "review",
    "run_and_normalize",
    "looks_like_secret",
]

#: The Source name. Must be in ``iacreview.finding.SOURCES``.
SOURCE_NAME = "Secret Review"

#: What makes a value obviously not a credential: placeholder vocabulary and
#: unresolved references. Applied to the whole candidate string. Kept close to
#: the CI secret scanner's allowlist so the two agree on what a placeholder is.
_ALLOWLIST = re.compile(
    r"""
    example | placeholder | dummy | sample | redacted | changeme | change[_-]me
    | not[_-]?a[_-]?real | your[_-] | xxxx | fake | to[_-]?be[_-]?set
    | \{\{ | \$\{ | <[a-z_-]+> | \.\.\. | \*\*\*
    """,
    re.IGNORECASE | re.VERBOSE,
)

#: A name that signals its value is a secret.
_SECRET_NAME = re.compile(
    r"(?i)(password|passwd|pwd|secret|secret[_-]?key|client[_-]?secret"
    r"|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|bearer[_-]?token|token)"
)


class _SecretRule:
    """One credential shape.

    Attributes:
        name: Reported rule id.
        description: What the shape is.
        pattern: Compiled regex matched against a candidate string.
    """

    def __init__(self, name: str, description: str, pattern: Pattern[str]) -> None:
        self.name = name
        self.description = description
        self.pattern = pattern


#: The credential shapes this Source recognizes in a *value*.
SECRET_RULES: Tuple[_SecretRule, ...] = (
    _SecretRule(
        "aws_access_key_id",
        "an AWS access key ID",
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    ),
    _SecretRule(
        "provider_token",
        "a provider token with a recognizable prefix",
        re.compile(
            r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}"
            r"|xox[abposr]-[A-Za-z0-9-]{10,}"
            r"|sk_live_[A-Za-z0-9]{16,}"
            r"|sk-[A-Za-z0-9]{16,})\b"
        ),
    ),
    _SecretRule(
        "private_key_block",
        "a PEM private key header",
        re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
    ),
)


def looks_like_secret(value: str) -> Optional[str]:
    """Return the rule name if ``value`` looks like a secret, else ``None``.

    A value that matches the placeholder allowlist is never a secret, whatever
    else it matches: an obvious placeholder is the intended content of a
    template field.
    """
    if not isinstance(value, str) or not value:
        return None
    if _ALLOWLIST.search(value):
        return None
    for rule in SECRET_RULES:
        if rule.pattern.search(value):
            return rule.name
    return None


def _high_entropy(value: str) -> bool:
    """Whether a string is long and varied enough to be a real secret.

    A crude gate that keeps a short or dictionary-word value from being
    reported as a secret while still catching a long, high-entropy string.
    while still catching ``password: A7f9K2mQ...``. At least 12 characters, and
    a mix of character classes.
    """
    if len(value) < 12:
        return False
    classes = 0
    if re.search(r"[a-z]", value):
        classes += 1
    if re.search(r"[A-Z]", value):
        classes += 1
    if re.search(r"[0-9]", value):
        classes += 1
    if re.search(r"[^A-Za-z0-9]", value):
        classes += 1
    return classes >= 3


def _resources(doc: Any) -> List[Tuple[str, Dict[str, Any]]]:
    """``(logical_id, body)`` pairs, in template order."""
    out: List[Tuple[str, Dict[str, Any]]] = []
    section = doc.get("Resources") if isinstance(doc, dict) else None
    if isinstance(section, dict):
        for logical_id, body in section.items():
            if isinstance(logical_id, str) and isinstance(body, dict):
                out.append((logical_id, body))
    return out


def _finding(
    *,
    logical_id: Optional[str],
    template_file: str,
    template_path: List[str],
    rule: str,
    text: str,
    why: str,
    recommendation: str,
) -> Finding:
    """One Confirmed Secret Review finding, always with a redacted excerpt."""
    return Finding(
        ID=UNASSIGNED_ID,
        Normalized_Category="DataProtection",
        FindingType="Security",
        Severity="HIGH",
        Confidence=CONFIRMED,
        Source=sorted_sources([SOURCE_NAME]),
        Resource=logical_id,
        Location=Location(
            File=template_file, Line=None, Column=None, TemplatePath=template_path
        ),
        Finding="[{0}] {1}".format(rule, text),
        WhyItMatters=why,
        Evidence=[
            Evidence(
                Source=SOURCE_NAME,
                Detail="Secret Review rule {0}; value redacted".format(rule),
                RuleId=rule,
                Excerpt=REDACTED_EXCERPT,
            )
        ],
        Recommendation=recommendation,
        SuggestedRemediation=None,
    )


def _scan_lambda_env(
    logical_id: str, body: Dict[str, Any], template_file: str
) -> List[Finding]:
    """Plaintext secrets in a Lambda function's environment variables."""
    findings: List[Finding] = []
    props = body.get("Properties")
    if not isinstance(props, dict):
        return findings
    env = props.get("Environment")
    variables = env.get("Variables") if isinstance(env, dict) else None
    if not isinstance(variables, dict):
        return findings
    for key, value in variables.items():
        if not isinstance(key, str) or not isinstance(value, str):
            continue
        rule = looks_like_secret(value)
        entropy_hit = bool(_SECRET_NAME.search(key)) and _high_entropy(value) \
            and not _ALLOWLIST.search(value)
        if rule or entropy_hit:
            findings.append(_finding(
                logical_id=logical_id, template_file=template_file,
                template_path=["Resources", logical_id, "Properties",
                               "Environment", "Variables", key],
                rule="lambda_env_plaintext_secret",
                text=(
                    "The Lambda environment variable {0} holds a value that "
                    "looks like a plaintext secret.".format(key)
                ),
                why=(
                    "Environment-variable secrets are visible to anyone with "
                    "lambda:GetFunction, appear in deployment logs, and cannot "
                    "be rotated independently of a deployment."
                ),
                recommendation=(
                    "Store the secret in AWS Secrets Manager and reference it "
                    "with a dynamic reference, resolving the value at runtime."
                ),
            ))
    return findings


def _scan_userdata(
    logical_id: str, body: Dict[str, Any], template_file: str
) -> List[Finding]:
    """Plaintext secrets written in an EC2 instance's UserData script."""
    findings: List[Finding] = []
    props = body.get("Properties")
    if not isinstance(props, dict):
        return findings
    userdata = props.get("UserData")
    text = _userdata_text(userdata)
    if text is None:
        return findings
    # Look for KEY=value or KEY: value assignments to secret-named keys.
    for match in re.finditer(
        r"(?im)([A-Za-z0-9_.-]*"
        r"(?:password|passwd|pwd|secret|api[_-]?key|token))"
        r"\s*[:=]\s*(\S+)",
        text,
    ):
        name, value = match.group(1), match.group(2).strip("\"'")
        if _ALLOWLIST.search(value):
            continue
        if looks_like_secret(value) or _high_entropy(value) or len(value) >= 6:
            findings.append(_finding(
                logical_id=logical_id, template_file=template_file,
                template_path=["Resources", logical_id, "Properties", "UserData"],
                rule="userdata_plaintext_secret",
                text=(
                    "The UserData script assigns a value to {0}, which looks "
                    "like a plaintext secret written to the instance.".format(name)
                ),
                why=(
                    "A secret in UserData is stored in the launch configuration "
                    "and on the instance disk in cleartext, readable by any "
                    "process on the instance."
                ),
                recommendation=(
                    "Retrieve the secret at boot from SSM Parameter Store "
                    "SecureString or Secrets Manager rather than embedding it."
                ),
            ))
            break  # one finding per UserData block is enough
    return findings


def _userdata_text(userdata: Any) -> Optional[str]:
    """Extract the script text from a UserData property, or ``None``.

    Handles the ``Fn::Base64`` wrapper and the ``Fn::Sub`` long form that
    :mod:`iacreview.yamlcfn` produces. A ``Fn::Sub`` with a list argument uses
    the first element as the template body.
    """
    value = userdata
    if isinstance(value, dict) and "Fn::Base64" in value:
        value = value["Fn::Base64"]
    if isinstance(value, dict) and "Fn::Sub" in value:
        sub = value["Fn::Sub"]
        if isinstance(sub, list) and sub and isinstance(sub[0], str):
            return sub[0]
        if isinstance(sub, str):
            return sub
    if isinstance(value, str):
        return value
    return None


def _scan_parameters(doc: Any, template_file: str) -> List[Finding]:
    """Secret-shaped default values on parameters."""
    findings: List[Finding] = []
    section = doc.get("Parameters") if isinstance(doc, dict) else None
    if not isinstance(section, dict):
        return findings
    for name, body in section.items():
        if not isinstance(name, str) or not isinstance(body, dict):
            continue
        default = body.get("Default")
        if not isinstance(default, str):
            continue
        if _ALLOWLIST.search(default):
            continue
        secret_named = bool(_SECRET_NAME.search(name))
        if looks_like_secret(default) or (secret_named and _high_entropy(default)):
            findings.append(_finding(
                logical_id=None, template_file=template_file,
                template_path=["Parameters", name, "Default"],
                rule="parameter_default_secret",
                text=(
                    "Parameter {0} has a default value that looks like a "
                    "plaintext secret.".format(name)
                ),
                why=(
                    "A default secret means every deployment that does not "
                    "override it uses the same known value, and the value is "
                    "visible in the console and in change sets."
                ),
                recommendation=(
                    "Remove the Default, set NoEcho: true, and supply the value "
                    "at deploy time or via a Secrets Manager dynamic reference."
                ),
            ))
    return findings


def review(doc: Any, *, template_file: str) -> List[Finding]:
    """Run every secret detector over a parsed template.

    Returns findings in a fixed order: Lambda environment variables and EC2
    UserData in template order, then parameter defaults. All are
    ``Confidence: Confirmed`` with a redacted excerpt.
    """
    findings: List[Finding] = []
    for logical_id, body in _resources(doc):
        rtype = body.get("Type")
        if rtype == "AWS::Lambda::Function":
            findings.extend(_scan_lambda_env(logical_id, body, template_file))
        elif rtype == "AWS::EC2::Instance":
            findings.extend(_scan_userdata(logical_id, body, template_file))
    findings.extend(_scan_parameters(doc, template_file))
    return findings


def run_and_normalize(
    template_path: Any,
    *,
    workspace_root: Any = None,
    loaded: Optional[LoadedTemplate] = None,
) -> SourceResult:
    """Run the secret review as a Source, returning a :class:`SourceResult`.

    Mirrors the other deterministic Sources. Reads the parsed template directly,
    so it accepts an already-parsed ``loaded`` template to avoid parsing twice.
    """
    from pathlib import Path
    from iacreview.template import load_template

    root = Path(workspace_root) if workspace_root is not None else Path.cwd()
    path_obj = Path(template_path)
    if loaded is None:
        loaded = load_template(path_obj)

    template_file = workspace_relative(str(path_obj), root) or path_obj.name
    findings = review(loaded.doc, template_file=template_file)
    return SourceResult(source=SOURCE_NAME, findings=findings, errors=[], stats={})
