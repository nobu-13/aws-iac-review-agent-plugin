"""Convert a Review_Report into SARIF 2.1.0.

This is the v0.7.0 interoperability bridge. SARIF (Static Analysis Results
Interchange Format) is the format GitHub's code-scanning tab, and most CI
result viewers, consume. Emitting it lets a review run surface in the same place
as every other static-analysis tool, without a consumer learning this plugin's
own Finding schema.

Scope
    This module is a pure, deterministic transform: Review_Report in, SARIF
    document out. It runs no review, reads no file, and makes no network call.
    The same report always produces the same SARIF, byte for byte, so a diff of
    two runs is a diff of the findings and nothing else.

The mapping, briefly
    - Each distinct ``Evidence[].RuleId`` (falling back to the Source name)
      becomes one entry in ``tool.driver.rules``, so a consumer can group and
      filter by rule.
    - Each Finding becomes one ``result``, its ``ruleId`` the finding's rule,
      its ``level`` derived from Severity and FindingType, its ``message`` the
      Finding text, and its ``locations`` the template file plus the logical-ID
      breadcrumb in ``TemplatePath``.
    - The plugin's Confidence and Normalized_Category, which have no native
      SARIF field, travel in each result's ``properties`` bag so nothing is
      lost.

What SARIF cannot represent, and how it is preserved
    SARIF has no notion of a merged finding from several sources. A Finding
    merged from cfn-lint and cfn-guard keeps both in its ``Source`` list; the
    result records the joined list in ``properties.sources`` and picks the
    first for ``ruleId`` attribution. Nothing is dropped.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

__all__ = [
    "SARIF_VERSION",
    "SARIF_SCHEMA_URI",
    "TOOL_NAME",
    "to_sarif",
    "level_for",
]

#: The SARIF version this module emits.
SARIF_VERSION = "2.1.0"

#: The published schema URI for SARIF 2.1.0. A consumer validates against this.
SARIF_SCHEMA_URI = (
    "https://json.schemastore.org/sarif-2.1.0.json"
)

#: The tool name recorded in ``tool.driver.name``.
TOOL_NAME = "aws-iac-review-agent-plugin"

#: SARIF's three result levels. A review Finding maps to one of these; SARIF has
#: no CRITICAL, so CRITICAL and HIGH both become ``error`` and are told apart by
#: ``properties.severity`` and by the numeric ``security-severity`` rank below.
_LEVEL_ERROR = "error"
_LEVEL_WARNING = "warning"
_LEVEL_NOTE = "note"

#: GitHub reads ``security-severity`` (a 0-10 string) to bucket a finding into
#: critical/high/medium/low in the security tab. Mapped from the plugin's
#: Severity so a Security finding lands in the expected bucket.
_SECURITY_SEVERITY: Dict[str, str] = {
    "CRITICAL": "9.5",
    "HIGH": "8.0",
    "MEDIUM": "5.5",
    "LOW": "3.0",
    "INFO": "1.0",
}


def level_for(severity: str, finding_type: str) -> str:
    """The SARIF level for one Finding.

    CRITICAL and HIGH are ``error``; MEDIUM is ``warning``; LOW and INFO are
    ``note``. FindingType does not change the level -- SARIF's level is about
    how loudly to surface a result, and the plugin's Severity already encodes
    that -- but it is accepted so a future policy can use it without a signature
    change.
    """
    if severity in ("CRITICAL", "HIGH"):
        return _LEVEL_ERROR
    if severity == "MEDIUM":
        return _LEVEL_WARNING
    return _LEVEL_NOTE


def _rule_id(finding: Dict[str, Any]) -> str:
    """The rule id a Finding is attributed to.

    The first ``Evidence[].RuleId`` that is set, else the first Source name, so
    every result has a stable, groupable id even for an Agent finding that
    carries no rule.
    """
    for evidence in finding.get("Evidence", []):
        if isinstance(evidence, dict):
            rule = evidence.get("RuleId")
            if isinstance(rule, str) and rule:
                return rule
    sources = finding.get("Source") or []
    if sources:
        return str(sources[0])
    return "unknown"


def _short_description(finding: Dict[str, Any]) -> str:
    """A one-line rule description: the Finding text without its ``[rule]`` prefix."""
    text = finding.get("Finding", "")
    if text.startswith("[") and "]" in text:
        return text[text.index("]") + 1 :].strip()
    return text


def _region_free_location(finding: Dict[str, Any]) -> Dict[str, Any]:
    """The SARIF location for a Finding.

    ``Location.File`` is the artifact URI. Line and column are omitted when the
    plugin did not resolve them (the deterministic Sources work on the parsed
    document and carry ``null`` there); a consumer still gets file-level
    attribution. The logical-ID breadcrumb from ``TemplatePath`` goes in the
    location's ``logicalLocations`` so a reader can find the resource.
    """
    location = finding.get("Location", {})
    file_uri = location.get("File") if isinstance(location, dict) else None
    physical: Dict[str, Any] = {
        "artifactLocation": {"uri": file_uri or "unknown"},
    }
    line = location.get("Line") if isinstance(location, dict) else None
    if isinstance(line, int) and line > 0:
        region: Dict[str, Any] = {"startLine": line}
        column = location.get("Column")
        if isinstance(column, int) and column > 0:
            region["startColumn"] = column
        physical["region"] = region

    result_location: Dict[str, Any] = {"physicalLocation": physical}

    template_path = location.get("TemplatePath") if isinstance(location, dict) else None
    if isinstance(template_path, list) and template_path:
        result_location["logicalLocations"] = [
            {
                "name": str(finding.get("Resource") or template_path[0]),
                "fullyQualifiedName": "/".join(str(p) for p in template_path),
                "kind": "resource",
            }
        ]
    return result_location


def _collect_rules(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """One ``tool.driver.rules`` entry per distinct rule id, in first-seen order."""
    rules: List[Dict[str, Any]] = []
    seen = set()
    for finding in findings:
        rule_id = _rule_id(finding)
        if rule_id in seen:
            continue
        seen.add(rule_id)
        rules.append({
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": _short_description(finding)},
            "properties": {
                "category": finding.get("Normalized_Category", "Other"),
                "findingType": finding.get("FindingType", ""),
            },
        })
    return rules


def _result(finding: Dict[str, Any]) -> Dict[str, Any]:
    """One SARIF ``result`` for one Finding."""
    severity = finding.get("Severity", "INFO")
    finding_type = finding.get("FindingType", "")
    rule_id = _rule_id(finding)
    return {
        "ruleId": rule_id,
        "level": level_for(severity, finding_type),
        "message": {"text": finding.get("Finding", "")},
        "locations": [_region_free_location(finding)],
        "properties": {
            "security-severity": _SECURITY_SEVERITY.get(severity, "1.0"),
            "severity": severity,
            "findingType": finding_type,
            "confidence": finding.get("Confidence", ""),
            "category": finding.get("Normalized_Category", "Other"),
            "sources": list(finding.get("Source") or []),
        },
    }


def to_sarif(report: Dict[str, Any], *, tool_version: Optional[str] = None) -> Dict[str, Any]:
    """Convert a Review_Report to a SARIF 2.1.0 document.

    Args:
        report: A Review_Report, as produced by ``iac-review`` or any Skill.
            Only ``findings`` is required; a report missing it yields a run with
            no results rather than an error.
        tool_version: The plugin version to record in ``tool.driver.version``.
            Read from the caller rather than imported so this module stays a
            pure transform with no dependency on the package's ``__version__``.

    Returns:
        A JSON-serializable SARIF document. Deterministic for the same report.
    """
    findings = report.get("findings")
    findings = findings if isinstance(findings, list) else []

    driver: Dict[str, Any] = {
        "name": TOOL_NAME,
        "informationUri": "https://github.com/nobu-13/aws-iac-review-agent-plugin",
        "rules": _collect_rules(findings),
    }
    if tool_version:
        driver["version"] = tool_version

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {"driver": driver},
                "results": [_result(finding) for finding in findings],
            }
        ],
    }
