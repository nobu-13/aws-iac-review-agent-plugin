"""Constants of the v1.1 Delta_Tool: closed sets, failure codes, limits, version.

This module is the single definition of every value the Delta_Tool modules
(``deltaio``, ``semdiff``, ``reportcheck``, ``delta``, ``deltareport``,
``deltacli``) share. It holds data only -- no function, no I/O -- and imports
nothing outside the standard library, so every other Delta module can depend on
it without creating an import cycle.

Closed sets are ordered tuples
    Each closed set is a ``Tuple[str, ...]`` whose order is the documented
    order. A tuple, rather than a ``frozenset``, lets the schema document and
    the summary counts list the values in one fixed order, and lets a test
    compare the documentation with the constants element by element
    (Requirement 9 AC6).

Failure codes name the reason, error classes stay the v1.0 set
    A failure Code (for example ``template_node_limit_exceeded``) tells a
    consumer exactly which check failed. It maps onto one ``error_class`` of the
    existing StructuredError (``iacreview.errors.ERROR_CLASSES``) and one exit
    code of ``iacreview.exitcodes.EXIT_CODES``; v1.1 adds no error class and no
    exit code (Requirement 10 AC1, AC2).

Limits are the values approved at Gate M0 (H1)
    Exceeding any limit is a failure with its own Code, never a partial or
    successful result. Time and memory budgets are evaluation targets measured
    outside the tool and are deliberately not defined here: the tool enforces
    the limits below and nothing else.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Mapping, Tuple

__all__ = [
    "DELTA_SCHEMA_VERSION",
    "SCOPE",
    "IDENTIFIER_MODES",
    "SIDES",
    "FAILURE_INPUTS",
    "DELTA_CLASSIFICATIONS",
    "ENTRY_OBSERVATIONS",
    "ANALYSIS_STATES",
    "OBSERVATIONS",
    "STRUCTURAL_COMPLETENESS",
    "CLASSIFICATION_COMPLETENESS",
    "CHANGE_KINDS",
    "CHANGE_QUALIFIERS",
    "SEMANTIC_LIMITATIONS",
    "CHANGE_HINTS",
    "UNCOMPARED_REASONS",
    "AMBIGUOUS_REASONS",
    "UNCONFIRMED_REASONS",
    "DECLARATION_CODES",
    "UNVERIFIED_ASSUMPTIONS",
    "INPUT_DECLARATION_STATUSES",
    "REPORT_AUTHENTICITY",
    "TEMPLATE_REPORT_CORRESPONDENCE",
    "REPORT_INTEGRITY_CHECKS",
    "MATCH_STAGES",
    "FAILURE_CODES",
    "FAILURE_CODE_TABLE",
    "MAX_TEMPLATE_BYTES",
    "MAX_REPORT_BYTES",
    "MAX_REPORT_FINDINGS",
    "MAX_TEMPLATE_DEPTH",
    "MAX_TEMPLATE_NODES",
    "MAX_CHANGE_ENTRIES",
    "MAX_OUTPUT_BYTES",
    "LIMIT_FAILURE_CODES",
]

# ---------------------------------------------------------------------------
# Version and fixed values
# ---------------------------------------------------------------------------

#: Version of the Delta_Report schema, independent of the Review_Report
#: ``schema_version`` (Requirement 9 AC2). Additive changes only within MAJOR 1.
DELTA_SCHEMA_VERSION = "1.0.0"

#: The fixed comparison scope: only the declared Template is compared, and no
#: result implies equivalence after deployment (Requirement 4 AC1).
SCOPE = "declared_template"

#: ``identifier_mode`` values. ``anonymized`` is the default; ``plain`` records
#: that identifiers were printed in plain form on request (Requirement 12 AC7).
IDENTIFIER_MODES: Tuple[str, ...] = ("anonymized", "plain")

#: The two sides of a comparison, in the order failures are reported.
SIDES: Tuple[str, ...] = ("base", "head")

#: Which input a failure belongs to (``failure.input``).
FAILURE_INPUTS: Tuple[str, ...] = ("template", "report", "output")

# ---------------------------------------------------------------------------
# Closed sets of the state model (Requirement 5, Requirement 9 AC6)
# ---------------------------------------------------------------------------

#: Delta_Classification of one Delta_Entry.
DELTA_CLASSIFICATIONS: Tuple[str, ...] = (
    "New",
    "Resolved",
    "Unchanged",
    "Unconfirmed",
    "Ambiguous",
)

#: Entry_Observation of one Delta_Entry.
ENTRY_OBSERVATIONS: Tuple[str, ...] = ("matched", "head_only", "base_only", "unmatched")

#: ``analysis_state`` of a comparison.
ANALYSIS_STATES: Tuple[str, ...] = ("analyzed", "unanalyzable")

#: ``observation`` of a comparison (``null`` only when ``unanalyzable``).
OBSERVATIONS: Tuple[str, ...] = ("changes_observed", "no_changes_observed")

#: ``structural_completeness`` of the Semantic Diff.
STRUCTURAL_COMPLETENESS: Tuple[str, ...] = ("complete", "partial")

#: ``classification_completeness`` of the Finding Delta.
CLASSIFICATION_COMPLETENESS: Tuple[str, ...] = ("complete", "partial")

#: Change kind of a Change_Entry.
CHANGE_KINDS: Tuple[str, ...] = ("added", "removed", "modified")

#: Change_Qualifier codes (Requirement 4 AC2-AC7).
CHANGE_QUALIFIERS: Tuple[str, ...] = (
    "expression_unevaluated",
    "conditional",
    "dynamic_reference_unresolved",
    "external_value",
    "pre_transform",
)

#: Semantic_Limitation codes (Requirement 4 AC8).
SEMANTIC_LIMITATIONS: Tuple[str, ...] = (
    "transform_not_expanded",
    "indirect_effects_not_evaluated",
    "dynamic_reference_unresolved",
    "nested_stack_not_compared",
)

#: Hints attached to a Change_Entry (Requirement 4 AC13).
CHANGE_HINTS: Tuple[str, ...] = ("possible_logical_id_rename",)

#: Reasons a path is listed in ``uncompared_paths`` (Design 2-4, 4-1).
UNCOMPARED_REASONS: Tuple[str, ...] = ("duplicate_key", "non_string_key", "yaml_timestamp")

#: Reasons for ``Ambiguous`` (Requirement 6 AC7, Requirement 7 AC2, Design 7-1).
AMBIGUOUS_REASONS: Tuple[str, ...] = (
    "identity_undetermined",
    "duplicate_fingerprint",
    "source_not_comparable",
    "tool_version_mismatch",
    "template_not_reviewed",
    "non_deterministic_source",
    "possible_logical_id_rename",
    "report_integrity_failed",
    "template_report_mismatch",
)

#: Reasons for ``Unconfirmed`` (Requirement 7 AC3).
UNCONFIRMED_REASONS: Tuple[str, ...] = ("input_declaration_absent",)

#: Unverified_Assumption codes, always listed in full (Requirement 8 AC3).
UNVERIFIED_ASSUMPTIONS: Tuple[str, ...] = (
    "reports_unmodified",
    "same_plugin_version",
    "same_rule_set",
    "same_tool_configuration",
    "same_agent_findings_input",
    "reports_match_templates",
)

#: Input_Declaration codes accepted on the command line, one per declaration
#: (Requirement 8 AC4). The same set as :data:`UNVERIFIED_ASSUMPTIONS`: a
#: declaration names an assumption the tool cannot check.
DECLARATION_CODES: Tuple[str, ...] = UNVERIFIED_ASSUMPTIONS

#: Status recorded for every declared code (Requirement 8 AC5).
INPUT_DECLARATION_STATUSES: Tuple[str, ...] = ("declared_not_verified",)

#: The fixed ``report_authenticity`` value (Requirement 8 AC2).
REPORT_AUTHENTICITY = "unverified"

#: ``template_report_correspondence`` values. ``verified`` does not exist
#: (Requirement 8 AC6).
TEMPLATE_REPORT_CORRESPONDENCE: Tuple[str, ...] = (
    "inconsistent",
    "unknown",
    "consistent_by_name_only",
    "not_applicable",
)

#: Names of the internal-consistency checks of a Review_Report (Design 9-2).
REPORT_INTEGRITY_CHECKS: Tuple[str, ...] = ("rebuild_mismatch", "dedup_invariant_violated")

#: ``match_stage`` of a matched Delta_Entry (Requirement 6 AC15).
MATCH_STAGES: Tuple[int, ...] = (1, 2)

# ---------------------------------------------------------------------------
# Failure codes (Design 10-5)
# ---------------------------------------------------------------------------

#: Every failure Code, grouped by ``error_class`` in the order of Design 10-5.
FAILURE_CODES: Tuple[str, ...] = (
    "invalid_arguments",
    "input_not_found",
    "path_violation",
    "template_too_large",
    "report_too_large",
    "report_finding_limit_exceeded",
    "template_node_limit_exceeded",
    "template_depth_limit_exceeded",
    "change_entry_limit_exceeded",
    "output_size_limit_exceeded",
    "template_parse_failure",
    "template_encoding_failure",
    "template_alias_cycle",
    "template_not_reviewable",
    "report_parse_failure",
    "report_duplicate_json_key",
    "report_schema_violation",
    "parser_divergence",
    "unexpected",
)

#: Failure Code -> ``(error_class, exit code)``. The error class is a member of
#: the v1.0 ``ERROR_CLASSES`` and the exit code is the one the v1.0 exception
#: class for that error class uses. Read-only.
FAILURE_CODE_TABLE: Mapping[str, Tuple[str, int]] = MappingProxyType(
    {
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
)

# ---------------------------------------------------------------------------
# Limits approved at Gate M0 (H1, Design 12-1)
# ---------------------------------------------------------------------------

#: Largest Template file read, in bytes. Inherited from the v1.0 reader, which
#: enforces it before parsing.
MAX_TEMPLATE_BYTES = 5 * 1024 * 1024

#: Largest Review_Report file read, in bytes. Fixed by reusing the v1.0 reader,
#: which enforces the same value before parsing.
MAX_REPORT_BYTES = 5 * 1024 * 1024

#: Largest ``findings[]`` count of one Review_Report, checked before matching.
MAX_REPORT_FINDINGS = 10000

#: Deepest Template accepted, counted as a tree with the root at depth 1.
MAX_TEMPLATE_DEPTH = 64

#: Largest logical node count of a Template: the size of the tree obtained by
#: expanding every alias share, counted without expanding it.
MAX_TEMPLATE_NODES = 3000000

#: Largest number of Change_Entries of one Semantic Diff.
MAX_CHANGE_ENTRIES = 200000

#: Largest serialized Delta_Report, in bytes.
MAX_OUTPUT_BYTES = 128 * 1024 * 1024

#: Limit constant name -> failure Code reported when that limit is exceeded.
LIMIT_FAILURE_CODES: Mapping[str, str] = MappingProxyType(
    {
        "MAX_TEMPLATE_BYTES": "template_too_large",
        "MAX_REPORT_BYTES": "report_too_large",
        "MAX_REPORT_FINDINGS": "report_finding_limit_exceeded",
        "MAX_TEMPLATE_DEPTH": "template_depth_limit_exceeded",
        "MAX_TEMPLATE_NODES": "template_node_limit_exceeded",
        "MAX_CHANGE_ENTRIES": "change_entry_limit_exceeded",
        "MAX_OUTPUT_BYTES": "output_size_limit_exceeded",
    }
)
