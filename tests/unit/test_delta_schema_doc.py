"""``docs/delta-schema.md`` agrees with the Delta_Tool constants (v1.1 Task 10).

Requirement 9 AC6 / AC10: every closed set is a module constant and this test
fails when the document and the constants disagree. The document is English
and ASCII, and states what the results do not mean (R4.1, R6.12, R6.15, R7.8,
R12.6).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Tuple

import pytest

from iacreview import deltareport, deltaschema

DOC = Path(__file__).resolve().parents[2] / "docs" / "delta-schema.md"
_MARKER = re.compile(r"^<!-- closed-set: ([A-Z_]+) -->$")
_ITEM = re.compile(r"^- `([^`]+)`: (.+)$")

#: Constant name -> the values it documents, in order.
DOCUMENTED: Dict[str, Tuple[object, ...]] = {
    "IDENTIFIER_MODES": deltaschema.IDENTIFIER_MODES,
    "SIDES": deltaschema.SIDES,
    "FAILURE_INPUTS": deltaschema.FAILURE_INPUTS,
    "DELTA_CLASSIFICATIONS": deltaschema.DELTA_CLASSIFICATIONS,
    "ENTRY_OBSERVATIONS": deltaschema.ENTRY_OBSERVATIONS,
    "ANALYSIS_STATES": deltaschema.ANALYSIS_STATES,
    "OBSERVATIONS": deltaschema.OBSERVATIONS,
    "STRUCTURAL_COMPLETENESS": deltaschema.STRUCTURAL_COMPLETENESS,
    "CLASSIFICATION_COMPLETENESS": deltaschema.CLASSIFICATION_COMPLETENESS,
    "CHANGE_KINDS": deltaschema.CHANGE_KINDS,
    "CHANGE_QUALIFIERS": deltaschema.CHANGE_QUALIFIERS,
    "SEMANTIC_LIMITATIONS": deltaschema.SEMANTIC_LIMITATIONS,
    "CHANGE_HINTS": deltaschema.CHANGE_HINTS,
    "UNCOMPARED_REASONS": deltaschema.UNCOMPARED_REASONS,
    "AMBIGUOUS_REASONS": deltaschema.AMBIGUOUS_REASONS,
    "UNCONFIRMED_REASONS": deltaschema.UNCONFIRMED_REASONS,
    "UNVERIFIED_ASSUMPTIONS": deltaschema.UNVERIFIED_ASSUMPTIONS,
    "INPUT_DECLARATION_STATUSES": deltaschema.INPUT_DECLARATION_STATUSES,
    "TEMPLATE_REPORT_CORRESPONDENCE": deltaschema.TEMPLATE_REPORT_CORRESPONDENCE,
    "REPORT_INTEGRITY_CHECKS": deltaschema.REPORT_INTEGRITY_CHECKS,
    "MATCH_STAGES": tuple(str(stage) for stage in deltaschema.MATCH_STAGES),
    "FAILURE_CODES": deltaschema.FAILURE_CODES,
    "ENVELOPE_KEYS": deltareport.ENVELOPE_KEYS,
    "SIDE_INPUT_KEYS": deltareport.SIDE_INPUT_KEYS,
    "TEMPLATE_INPUT_KEYS": deltareport.TEMPLATE_INPUT_KEYS,
    "REPORT_INPUT_KEYS": deltareport.REPORT_INPUT_KEYS,
    "SEMANTIC_DIFF_KEYS": deltareport.SEMANTIC_DIFF_KEYS,
    "CHANGE_ENTRY_KEYS": deltareport.CHANGE_ENTRY_KEYS,
    "UNCOMPARED_PATH_KEYS": deltareport.UNCOMPARED_PATH_KEYS,
    "FINDING_DELTA_KEYS": deltareport.FINDING_DELTA_KEYS,
    "DELTA_ENTRY_KEYS": deltareport.DELTA_ENTRY_KEYS,
    "PROJECTION_KEYS": deltareport.PROJECTION_KEYS,
    "EVIDENCE_KEYS": deltareport.EVIDENCE_KEYS,
    "EVIDENCE_DELTA_KEYS": deltareport.EVIDENCE_DELTA_KEYS,
    "FAILURE_KEYS": deltareport.FAILURE_KEYS,
    "SUMMARY_KEYS": deltareport.SUMMARY_KEYS,
    "SUMMARY_SEMANTIC_DIFF_KEYS": deltareport.SUMMARY_SEMANTIC_DIFF_KEYS,
    "SUMMARY_FINDING_DELTA_KEYS": deltareport.SUMMARY_FINDING_DELTA_KEYS,
    "TOP_LEVEL_SECTIONS": deltareport.TOP_LEVEL_SECTIONS,
    "RESOURCE_PLAIN_KEYS": deltareport.RESOURCE_PLAIN_KEYS,
    "PARAMETER_ATTRIBUTES": deltareport.PARAMETER_ATTRIBUTES,
    "OUTPUT_ATTRIBUTES": deltareport.OUTPUT_ATTRIBUTES,
    "RULE_ATTRIBUTES": deltareport.RULE_ATTRIBUTES,
    "INTRINSIC_NAMES": deltareport.INTRINSIC_NAMES,
    "PLAIN_TOOL_NAMES": deltareport.PLAIN_TOOL_NAMES,
    "FORBIDDEN_KEYS": deltareport.FORBIDDEN_KEYS,
}


def _text() -> str:
    return DOC.read_text(encoding="utf-8")


def _sets() -> Dict[str, List[Tuple[str, str]]]:
    """Every ``closed-set`` list of the document: name -> [(value, text)]."""
    found: Dict[str, List[Tuple[str, str]]] = {}
    current = None
    for line in _text().splitlines():
        marker = _MARKER.match(line)
        if marker is not None:
            assert marker.group(1) not in found, "documented twice: " + marker.group(1)
            current = marker.group(1)
            found[current] = []
            continue
        if current is None:
            continue
        item = _ITEM.match(line)
        if item is not None:
            found[current].append((item.group(1), item.group(2)))
        elif line.strip() == "" and not found[current]:
            continue
        else:
            current = None
    return found


def test_document_exists_and_is_ascii_english() -> None:
    text = _text()
    assert text.startswith("# Delta_Report Schema")
    offenders = [n for n, line in enumerate(text.splitlines(), 1) if not line.isascii()]
    assert offenders == []
    assert sum(1 for line in text.splitlines() if line.startswith("# ")) == 1


def test_every_documented_set_is_known() -> None:
    assert set(_sets()) == set(DOCUMENTED)


@pytest.mark.parametrize("name", sorted(DOCUMENTED))
def test_closed_set_matches_constant(name: str) -> None:
    items = _sets()[name]
    assert tuple(value for value, _ in items) == DOCUMENTED[name]
    assert all(text.strip() for _, text in items)


def test_every_closed_set_constant_of_deltaschema_is_documented() -> None:
    for name in dir(deltaschema):
        value = getattr(deltaschema, name)
        if name.isupper() and isinstance(value, tuple) and name != "DECLARATION_CODES":
            assert name in DOCUMENTED, name
    # The declaration Codes are the Unverified_Assumption set.
    assert deltaschema.DECLARATION_CODES == deltaschema.UNVERIFIED_ASSUMPTIONS


def test_failure_code_table_matches() -> None:
    for code, text in _sets()["FAILURE_CODES"]:
        error_class, exit_code = deltaschema.FAILURE_CODE_TABLE[code]
        assert text == "`{0}`, exit {1}.".format(error_class, exit_code)


def test_limits_table_matches() -> None:
    text = _text()
    for name in deltaschema.LIMIT_FAILURE_CODES:
        value = getattr(deltaschema, name)
        row = next(line for line in text.splitlines() if line.startswith("| `{0}` |".format(name)))
        assert str(value) in row.replace(",", ""), name
        assert "`{0}`".format(deltaschema.LIMIT_FAILURE_CODES[name]) in row


def test_fixed_values_and_patterns_are_documented() -> None:
    text = _text()
    assert "`{0}`".format(deltaschema.DELTA_SCHEMA_VERSION) in text
    assert "`{0}`".format(deltaschema.SCOPE) in text
    assert "`{0}`".format(deltaschema.REPORT_AUTHENTICITY) in text
    assert "`{0}`".format(deltareport.AWS_RESOURCE_TYPE_PATTERN.pattern) in text
    assert "`{0}`".format(deltareport.CFN_LINT_RULE_ID_PATTERN.pattern) in text
    assert "`{0}000001`".format(deltareport.TOKEN_PREFIX) in text
    assert "`{0}`".format(deltareport.CUSTOM_RESOURCE_PREFIX) in text


@pytest.mark.parametrize(
    "statement",
    [
        # R4.1: complete does not imply equivalence after deployment.
        "including `complete` with `no_changes_observed`, implies equivalence after\ndeployment",
        # R6.12: Unchanged is a match, not a shared root cause.
        "It does not\nmean that they share a root cause.",
        # R6.15: mis-pairing risk of Evidence differences.
        "their Evidence\ndifference then compares the Evidence of two different problems",
        "An Evidence\ndifference is an observed difference: it is not classified",
        # R7.8: what Resolved means.
        "`Resolved` means: the matching procedure found no corresponding Head Finding,",
        # R12.6: anonymization limits.
        "A Token is stable only within one Delta_Report.",
        "Equal Tokens reveal equal identifiers.",
        "The Report digest lets anyone holding the same file confirm",
        # R16.5: not stable interfaces.
        "stderr messages and help text are not stable interfaces.",
    ],
)
def test_required_statements(statement: str) -> None:
    assert statement in _text()


def test_known_limitations_section() -> None:
    text = _text()
    assert "## Known limitations" in text
    section = text.split("## Known limitations", 1)[1]
    for phrase in ("stages 1 and 2 only", "not verified", "5 MiB", "Markdown output"):
        assert phrase in section
