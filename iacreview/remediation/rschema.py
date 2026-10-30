"""Closed vocabularies, limits and exit codes of the remediation verifier.

Everything a report may contain that is not a digest, a count or a trusted
identifier comes from a table in this module, so the report schema can be
checked against one place.
"""

from __future__ import annotations

from typing import Dict, FrozenSet, Tuple

CONTRACT_SCHEMA_VERSION = "0.1.0"
REPORT_SCHEMA_VERSION = "0.1.0"
REPORT_KIND = "remediation_verification"

VERIFIED = "VERIFIED"
BLOCKED = "BLOCKED"
UNVERIFIED = "UNVERIFIED"
ERROR = "ERROR"

#: Representative-value order: the first that occurs wins.
DECISION_PRIORITY: Tuple[str, ...] = (ERROR, BLOCKED, UNVERIFIED, VERIFIED)

#: Exit codes of ``verify``. Separate from ``iacreview.exitcodes`` (unchanged).
DECISION_EXIT_CODES: Dict[str, int] = {VERIFIED: 0, BLOCKED: 20, UNVERIFIED: 21, ERROR: 22}

TASK_OUTCOMES: Tuple[str, ...] = ("resolved", "already_satisfied", "not_resolved", "not_evaluated")
EXECUTION_MODES: Tuple[str, ...] = ("local_preview", "trusted_ci")
ENFORCEMENT_STATUSES: Tuple[str, ...] = ("not_verified",)
CONTRACT_SOURCES: Tuple[str, ...] = ("git_revision", "draft_file")
OPERATIONS: Tuple[str, ...] = ("add", "replace", "remove")

#: Check states. Only PASS counts towards VERIFIED; FAIL is a definite failure.
CHECK_PASS = "PASS"
CHECK_FAIL = "FAIL"
CHECK_STATES: Tuple[str, ...] = (
    CHECK_PASS,
    CHECK_FAIL,
    "NOT_RUN",
    "NOT_PASSED",
    "TOOL_UNAVAILABLE",
    "VERSION_MISMATCH",
    "TIMEOUT",
    "FAILED",
    "OUTPUT_INVALID",
    "OUTPUT_TOO_LARGE",
)

#: Diagnostic code -> (decision it forces, plain description for the Summary).
CODES: Dict[str, Tuple[str, str]] = {
    # ERROR: the evaluation itself is invalid.
    "invalid_arguments": (ERROR, "the command line is invalid"),
    "contract_invalid": (ERROR, "the contract does not follow the contract schema"),
    "contract_not_found": (ERROR, "the contract path does not exist in the trusted revision"),
    "profile_unknown": (ERROR, "the contract names a profile this validator does not ship"),
    "revision_not_found": (ERROR, "a revision could not be resolved to a commit"),
    "repository_unreadable": (ERROR, "the repository could not be read with git"),
    "internal_error": (ERROR, "the validator failed internally"),
    # BLOCKED: a known boundary violation or a definite failure.
    "file_added_outside_scope": (BLOCKED, "a file outside the contract target was added"),
    "file_removed_outside_scope": (BLOCKED, "a file outside the contract target was removed"),
    "file_modified_outside_scope": (BLOCKED, "a file outside the contract target was modified"),
    "file_mode_changed": (BLOCKED, "a file mode (executable bit, symlink, submodule) changed"),
    "target_template_removed": (BLOCKED, "the target Template no longer exists in Head"),
    "target_not_regular_file": (BLOCKED, "the target Template is not a regular file"),
    "template_change_outside_scope": (BLOCKED, "a Template path outside the allowed edits changed"),
    "resource_added": (BLOCKED, "a Resource was added"),
    "resource_removed": (BLOCKED, "a Resource was removed (a rename is a removal plus an addition)"),
    "resource_type_changed": (BLOCKED, "a Resource Type changed"),
    "parent_replaced": (BLOCKED, "a parent of an allowed property was replaced as a whole"),
    "operation_not_allowed": (BLOCKED, "an allowed property was changed with an operation the contract does not allow"),
    "outcome_not_achieved": (BLOCKED, "a required outcome is not met in Head"),
    "invariant_violated": (BLOCKED, "an invariant that held in Base fails in Head"),
    "check_failed": (BLOCKED, "a required check failed on Head"),
    # UNVERIFIED: evidence is missing, stale, unapproved or incomplete.
    "contract_not_approved": (UNVERIFIED, "the contract was not read from a trusted revision"),
    "config_not_ancestor_of_base": (UNVERIFIED, "the trusted config revision is not an ancestor of Base"),
    "base_not_ancestor_of_head": (UNVERIFIED, "Base is not an ancestor of Head (Base moved or Head is unrelated)"),
    "snapshot_changed": (UNVERIFIED, "the working tree changed during verification"),
    "comparison_incomplete": (UNVERIFIED, "part of the Template could not be compared (duplicate key, non-string key, timestamp)"),
    "template_not_comparable": (UNVERIFIED, "a Template could not be parsed within the structure limits"),
    "unsupported_construct": (UNVERIFIED, "the change needs evaluation Phase 1 does not perform (Transform, nested stack, condition, dynamic reference)"),
    "tool_unavailable": (UNVERIFIED, "a required tool is not installed"),
    "tool_version_mismatch": (UNVERIFIED, "a required tool is not the pinned version"),
    "tool_timeout": (UNVERIFIED, "a required tool exceeded its timeout"),
    "tool_failed": (UNVERIFIED, "a required tool failed or crashed"),
    "tool_output_invalid": (UNVERIFIED, "a required tool wrote output that is not its documented format"),
    "tool_output_too_large": (UNVERIFIED, "a required tool exceeded the output limit"),
    "check_not_passed": (UNVERIFIED, "a required rule was skipped, not applicable or not evaluated"),
    "invariant_failed_on_base": (UNVERIFIED, "an invariant already fails in Base; no regression can be ruled out"),
    "target_resource_missing": (UNVERIFIED, "the contract's Resource does not exist in Base with the profile's Type"),
    "outcome_not_evaluated": (UNVERIFIED, "a required outcome could not be evaluated on Base or Head"),
}

#: What to do next, per representative decision and leading code.
NEXT_ACTIONS: Dict[str, str] = {
    VERIFIED: "human_review",
    BLOCKED: "revise_candidate",
    UNVERIFIED: "supply_missing_evidence",
    ERROR: "fix_invocation_or_contract",
}

NEXT_ACTION_TEXT: Dict[str, str] = {
    "human_review": "Review the change yourself. VERIFIED is not an approval to merge or deploy.",
    "revise_candidate": "Revise the candidate so it stays inside the contract and meets the outcomes, then verify again.",
    "supply_missing_evidence": "Provide what is missing (approved contract, tool, fresh revisions), then verify again. Nothing was accepted.",
    "fix_invocation_or_contract": "Fix the command line or the contract. No verification took place.",
}

#: Facts Phase 1 never establishes; listed in every report.
NOT_VERIFIED: Tuple[str, ...] = (
    "runtime_behavior",
    "effective_iam_permissions",
    "resource_replacement",
    "deployment",
    "merge_enforcement",
)

#: Resource-level keys that are a closed vocabulary and may be displayed.
DISPLAYABLE_KEYS: FrozenSet[str] = frozenset(
    (
        "Type",
        "Properties",
        "DependsOn",
        "Condition",
        "DeletionPolicy",
        "UpdateReplacePolicy",
        "UpdatePolicy",
        "CreationPolicy",
        "Metadata",
    )
)

#: Top-level sections that may be displayed.
DISPLAYABLE_SECTIONS: FrozenSet[str] = frozenset(
    (
        "AWSTemplateFormatVersion",
        "Description",
        "Metadata",
        "Parameters",
        "Rules",
        "Mappings",
        "Conditions",
        "Transform",
        "Resources",
        "Outputs",
    )
)

# Limits (Design 4, 6). Not raised silently; a change needs a profile review.
CHECK_TIMEOUT_S = 60
CHECK_MAX_OUTPUT_BYTES = 8 * 1024 * 1024
GIT_TIMEOUT_S = 60
GIT_MAX_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_TREE_ENTRIES = 200_000
MAX_CONTRACT_BYTES = 64 * 1024
MAX_REPORT_BYTES = 4 * 1024 * 1024
MAX_WORKTREE_FILE_BYTES = 64 * 1024 * 1024
