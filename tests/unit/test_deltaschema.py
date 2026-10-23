"""Unit tests for :mod:`iacreview.deltaschema` (v1.1 Task 1).

The constants are checked against values written out here from the v1.1
Requirements and Design (closed sets, Design 10-5 failure table, the limits
approved at Gate M0), not against the module itself, so a change to a constant
has to be made in two places on purpose.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Dict, Tuple

import pytest

from iacreview import deltaschema, errors, exitcodes, template

MODULE_PATH = Path(deltaschema.__file__)

CLOSED_SETS: Dict[str, Tuple[object, ...]] = {
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
    "DECLARATION_CODES": deltaschema.DECLARATION_CODES,
    "UNVERIFIED_ASSUMPTIONS": deltaschema.UNVERIFIED_ASSUMPTIONS,
    "INPUT_DECLARATION_STATUSES": deltaschema.INPUT_DECLARATION_STATUSES,
    "TEMPLATE_REPORT_CORRESPONDENCE": deltaschema.TEMPLATE_REPORT_CORRESPONDENCE,
    "REPORT_INTEGRITY_CHECKS": deltaschema.REPORT_INTEGRITY_CHECKS,
    "MATCH_STAGES": deltaschema.MATCH_STAGES,
    "FAILURE_CODES": deltaschema.FAILURE_CODES,
}

#: Expected contents, transcribed from requirements.md / design.md.
EXPECTED_SETS: Dict[str, Tuple[object, ...]] = {
    "IDENTIFIER_MODES": ("anonymized", "plain"),
    "SIDES": ("base", "head"),
    "FAILURE_INPUTS": ("template", "report", "output"),
    "DELTA_CLASSIFICATIONS": ("New", "Resolved", "Unchanged", "Unconfirmed", "Ambiguous"),
    "ENTRY_OBSERVATIONS": ("matched", "head_only", "base_only", "unmatched"),
    "ANALYSIS_STATES": ("analyzed", "unanalyzable"),
    "OBSERVATIONS": ("changes_observed", "no_changes_observed"),
    "STRUCTURAL_COMPLETENESS": ("complete", "partial"),
    "CLASSIFICATION_COMPLETENESS": ("complete", "partial"),
    "CHANGE_KINDS": ("added", "removed", "modified"),
    "CHANGE_QUALIFIERS": (
        "expression_unevaluated",
        "conditional",
        "dynamic_reference_unresolved",
        "external_value",
        "pre_transform",
    ),
    "SEMANTIC_LIMITATIONS": (
        "transform_not_expanded",
        "indirect_effects_not_evaluated",
        "dynamic_reference_unresolved",
        "nested_stack_not_compared",
    ),
    "CHANGE_HINTS": ("possible_logical_id_rename",),
    "UNCOMPARED_REASONS": ("duplicate_key", "non_string_key", "yaml_timestamp"),
    "AMBIGUOUS_REASONS": (
        "identity_undetermined",
        "duplicate_fingerprint",
        "source_not_comparable",
        "tool_version_mismatch",
        "template_not_reviewed",
        "non_deterministic_source",
        "possible_logical_id_rename",
        "report_integrity_failed",
        "template_report_mismatch",
    ),
    "UNCONFIRMED_REASONS": ("input_declaration_absent",),
    "DECLARATION_CODES": (
        "reports_unmodified",
        "same_plugin_version",
        "same_rule_set",
        "same_tool_configuration",
        "same_agent_findings_input",
        "reports_match_templates",
    ),
    "UNVERIFIED_ASSUMPTIONS": (
        "reports_unmodified",
        "same_plugin_version",
        "same_rule_set",
        "same_tool_configuration",
        "same_agent_findings_input",
        "reports_match_templates",
    ),
    "INPUT_DECLARATION_STATUSES": ("declared_not_verified",),
    "TEMPLATE_REPORT_CORRESPONDENCE": (
        "inconsistent",
        "unknown",
        "consistent_by_name_only",
        "not_applicable",
    ),
    "REPORT_INTEGRITY_CHECKS": ("rebuild_mismatch", "dedup_invariant_violated"),
    "MATCH_STAGES": (1, 2),
}

#: Design 10-5, transcribed.
EXPECTED_FAILURE_TABLE: Dict[str, Tuple[str, int]] = {
    "invalid_arguments": ("invalid_arguments", 2),
    "input_not_found": ("input_not_found", 3),
    "path_violation": ("path_violation", 7),
    "template_too_large": ("input_too_large", 3),
    "report_too_large": ("input_too_large", 3),
    "report_finding_limit_exceeded": ("input_too_large", 3),
    "template_node_limit_exceeded": ("input_too_large", 3),
    "template_depth_limit_exceeded": ("input_too_large", 3),
    "change_entry_limit_exceeded": ("input_too_large", 3),
    "output_size_limit_exceeded": ("input_too_large", 3),
    "template_parse_failure": ("parse_failure", 4),
    "template_encoding_failure": ("parse_failure", 4),
    "template_alias_cycle": ("parse_failure", 4),
    "template_not_reviewable": ("no_reviewable_template", 8),
    "report_parse_failure": ("schema_violation", 4),
    "report_duplicate_json_key": ("schema_violation", 4),
    "report_schema_violation": ("schema_violation", 4),
    "parser_divergence": ("unexpected", 1),
    "unexpected": ("unexpected", 1),
}

#: Limits approved at H1 (Requirements D-H16, Design 12-1, Tasks 3-1).
H1_LIMITS: Dict[str, int] = {
    "MAX_TEMPLATE_BYTES": 5 * 1024 * 1024,
    "MAX_REPORT_BYTES": 5 * 1024 * 1024,
    "MAX_REPORT_FINDINGS": 10000,
    "MAX_TEMPLATE_DEPTH": 64,
    "MAX_TEMPLATE_NODES": 3000000,
    "MAX_CHANGE_ENTRIES": 200000,
    "MAX_OUTPUT_BYTES": 128 * 1024 * 1024,
}

H1_LIMIT_CODES: Dict[str, str] = {
    "MAX_TEMPLATE_BYTES": "template_too_large",
    "MAX_REPORT_BYTES": "report_too_large",
    "MAX_REPORT_FINDINGS": "report_finding_limit_exceeded",
    "MAX_TEMPLATE_DEPTH": "template_depth_limit_exceeded",
    "MAX_TEMPLATE_NODES": "template_node_limit_exceeded",
    "MAX_CHANGE_ENTRIES": "change_entry_limit_exceeded",
    "MAX_OUTPUT_BYTES": "output_size_limit_exceeded",
}


def test_schema_version_starts_at_one_zero_zero() -> None:
    assert deltaschema.DELTA_SCHEMA_VERSION == "1.0.0"


def test_fixed_values() -> None:
    assert deltaschema.SCOPE == "declared_template"
    assert deltaschema.REPORT_AUTHENTICITY == "unverified"


@pytest.mark.parametrize("name", sorted(CLOSED_SETS))
def test_closed_sets_are_tuples_without_duplicates(name: str) -> None:
    values = CLOSED_SETS[name]
    assert isinstance(values, tuple)
    assert len(values) == len(set(values)), name
    assert values, name


@pytest.mark.parametrize("name", sorted(EXPECTED_SETS))
def test_closed_sets_match_the_specification(name: str) -> None:
    assert CLOSED_SETS[name] == EXPECTED_SETS[name]


def test_every_closed_set_is_exported() -> None:
    for name in CLOSED_SETS:
        assert name in deltaschema.__all__


def test_correspondence_has_no_verified_value() -> None:
    assert "verified" not in deltaschema.TEMPLATE_REPORT_CORRESPONDENCE


def test_no_closed_set_value_asserts_quality() -> None:
    """Requirement 7 AC7: nothing claims improvement, fixing or passing."""
    forbidden = ("improved", "fixed", "passed", "safe")
    for name, values in CLOSED_SETS.items():
        for value in values:
            if isinstance(value, str):
                for word in forbidden:
                    assert word not in value.lower(), (name, value)


def test_unchanged_is_only_a_classification() -> None:
    """Requirement 5 AC8: ``unchanged`` is not a comparison-level status."""
    comparison_level = (
        deltaschema.ANALYSIS_STATES
        + deltaschema.OBSERVATIONS
        + deltaschema.STRUCTURAL_COMPLETENESS
        + deltaschema.CLASSIFICATION_COMPLETENESS
    )
    assert "unchanged" not in {value.lower() for value in comparison_level}
    assert "Unchanged" in deltaschema.DELTA_CLASSIFICATIONS


def test_failure_table_matches_design() -> None:
    assert dict(deltaschema.FAILURE_CODE_TABLE) == EXPECTED_FAILURE_TABLE


def test_every_failure_code_is_in_the_table_and_back() -> None:
    assert set(deltaschema.FAILURE_CODES) == set(deltaschema.FAILURE_CODE_TABLE)
    assert len(deltaschema.FAILURE_CODES) == len(deltaschema.FAILURE_CODE_TABLE)


def test_failure_error_classes_are_existing_error_classes() -> None:
    for code, (error_class, _) in deltaschema.FAILURE_CODE_TABLE.items():
        assert error_class in errors.ERROR_CLASSES, code


def test_failure_exit_codes_are_existing_exit_codes() -> None:
    allowed = set(exitcodes.EXIT_CODES.values())
    assert allowed == set(range(0, 9))
    for code, (_, exit_code) in deltaschema.FAILURE_CODE_TABLE.items():
        assert exit_code in allowed, code
        assert exit_code != exitcodes.OK, code


def test_failure_exit_code_is_the_one_v1_uses_for_the_error_class() -> None:
    """Requirement 10 AC2: map onto the existing exception classes' exit codes."""
    by_class: Dict[str, set] = {}
    for cls in errors.ERROR_CLASS_HIERARCHY:
        by_class.setdefault(cls.error_class, set()).add(cls.exit_code)
    for code, (error_class, exit_code) in deltaschema.FAILURE_CODE_TABLE.items():
        assert by_class[error_class] == {exit_code}, code


def test_failure_codes_do_not_reuse_error_class_names_ambiguously() -> None:
    """A Code equal to an error class names that same class."""
    for code, (error_class, _) in deltaschema.FAILURE_CODE_TABLE.items():
        if code in errors.ERROR_CLASSES:
            assert code == error_class


@pytest.mark.parametrize("name", sorted(H1_LIMITS))
def test_limits_are_the_h1_approved_values(name: str) -> None:
    assert getattr(deltaschema, name) == H1_LIMITS[name]
    assert type(getattr(deltaschema, name)) is int


def test_limit_failure_codes() -> None:
    assert dict(deltaschema.LIMIT_FAILURE_CODES) == H1_LIMIT_CODES
    for code in deltaschema.LIMIT_FAILURE_CODES.values():
        assert deltaschema.FAILURE_CODE_TABLE[code] == ("input_too_large", 3)


def test_byte_limits_agree_with_the_reused_v1_reader() -> None:
    """Both byte limits are the value the v1.0 reader enforces (Design 1-4)."""
    assert deltaschema.MAX_TEMPLATE_BYTES == template.MAX_TEMPLATE_BYTES
    assert deltaschema.MAX_REPORT_BYTES == template.MAX_TEMPLATE_BYTES


def test_tables_are_read_only() -> None:
    with pytest.raises(TypeError):
        deltaschema.FAILURE_CODE_TABLE["x"] = ("unexpected", 1)  # type: ignore[index]
    with pytest.raises(TypeError):
        deltaschema.LIMIT_FAILURE_CODES["x"] = "unexpected"  # type: ignore[index]


def _module_tree() -> ast.Module:
    return ast.parse(MODULE_PATH.read_text(encoding="utf-8"))


def test_module_holds_constants_only() -> None:
    """Task 1: no function, class, or statement with behaviour."""
    for node in _module_tree().body:
        assert not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        assert isinstance(
            node, (ast.Expr, ast.Import, ast.ImportFrom, ast.Assign, ast.AnnAssign)
        ), type(node).__name__


def test_module_imports_only_the_standard_library() -> None:
    imported = set()
    for node in ast.walk(_module_tree()):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert imported <= {"__future__", "types", "typing"}


def test_module_text_constraints() -> None:
    """Tasks 0-2 rule 5: strings the existing tests forbid under ``iacreview/``."""
    text = MODULE_PATH.read_text(encoding="utf-8")
    assert "hypothesis" not in text
    assert ".kiro" not in text
