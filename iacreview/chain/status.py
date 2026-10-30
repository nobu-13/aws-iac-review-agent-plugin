"""Chain vocabulary: links, statuses, reason codes, the composition rule and the reserved exit codes.

Source: ``docs/v2/phase2/m2/wp0/m2-schemas.md`` rev1 §3 (Chain Result) and §4 (reason codes).

A link's status is derived from its reason codes, never set by hand: each code has one status in
:data:`REASONS`, and a link is the worst of its codes (``BROKEN > INCOMPLETE > NOT_PROVEN``), or LINKED
when it has none. The chain status is then derived from the six link statuses by :func:`compose`. The
codes stay in the result next to both statuses, so a BROKEN chain still shows its NOT_PROVEN reasons.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, Mapping, Optional, Tuple

LINKED, BROKEN, INCOMPLETE, NOT_PROVEN, NOT_PRESENT = "LINKED", "BROKEN", "INCOMPLETE", "NOT_PROVEN", "NOT_PRESENT"
COMPLETE = "COMPLETE"

LINKS: Tuple[str, ...] = ("subject", "contract", "review", "verification", "gate", "github")
OPTIONAL_LINKS: Tuple[str, ...] = ("review", "github")
LINK_STATUSES: Tuple[str, ...] = (LINKED, BROKEN, INCOMPLETE, NOT_PROVEN, NOT_PRESENT)
CHAIN_STATUSES: Tuple[str, ...] = (BROKEN, INCOMPLETE, NOT_PROVEN, COMPLETE)
_RANK: Dict[str, int] = {BROKEN: 3, INCOMPLETE: 2, NOT_PROVEN: 1}

#: What a chain never claims, whatever its status (m2-schemas.md §3).
NOT_CLAIMED: Tuple[str, ...] = (
    "approval_counted_by_rules",
    "approver_permission",
    "capture_authenticity",
    "human_identity",
    "issuer_pinning",
    "merge_enforcement",
    "runtime_behavior",
)

#: Reserved exit codes (D-2). No CLI uses them in WP1; ``exit_code_for`` is the library mapping.
EXIT_CODES: Mapping[str, int] = {COMPLETE: 0, NOT_PROVEN: 31, INCOMPLETE: 32, BROKEN: 33}
EXIT_INPUT_INVALID = 34


@dataclass(frozen=True)
class Reason:
    """One reason code: the links that may report it, the status it forces, what it means, what stays unproven."""

    links: Tuple[str, ...]
    status: str
    cause: str
    unproven: str


def _r(links: Tuple[str, ...], status: str, cause: str, unproven: str) -> Reason:
    return Reason(links, status, cause, unproven)


_M = ("manifest",)

#: Every reason code (m2-schemas.md rev1 §4, plus the two WP1 additions marked below).
REASONS: Mapping[str, Reason] = {
    # Manifest itself (no link is evaluated)
    "manifest_invalid": _r(_M, BROKEN, "the manifest violates the schema", "every link"),
    "locator_outside_root": _r(_M, BROKEN, "a locator leaves the chain root (.., absolute path, link)", "every link"),
    "manifest_unreadable": _r(_M, INCOMPLETE, "the manifest cannot be read, is too large or is not UTF-8 JSON", "every link"),
    # subject
    "base_not_ancestor_of_head": _r(("subject",), BROKEN, "the head commit does not descend from the base commit", "the candidate change"),
    "subject_mismatch": _r(("subject",), BROKEN, "the verification report names other base / head commits", "that the report is about this subject"),
    "revision_not_found": _r(("subject", "contract"), INCOMPLETE, "a named commit is not in the repository", "the subject or contract revision"),
    # contract
    "config_not_ancestor_of_base": _r(("contract",), BROKEN, "the contract's config commit is not an ancestor of the base", "that the contract was approved before the base"),
    "contract_digest_mismatch": _r(("contract",), BROKEN, "the contract blob at the config commit has another SHA-256", "the approved contract's content"),
    "contract_mismatch_with_report": _r(("contract",), BROKEN, "the verification report names another contract source, path or digest", "that the report used this contract"),
    "contract_blob_missing": _r(("contract",), INCOMPLETE, "the config commit holds no regular file at the contract path", "the approved contract's content"),
    # review
    "review_digest_mismatch": _r(("review",), BROKEN, "the review report file has another SHA-256 than the manifest", "the review report's content"),
    "finding_missing": _r(("review",), BROKEN, "no finding, or several, with the referenced ID", "the referenced finding"),
    "finding_digest_mismatch": _r(("review",), BROKEN, "the referenced finding's canonical SHA-256 differs", "the referenced finding's content"),
    "identity_key_mismatch": _r(("review",), BROKEN, "the finding's Identity_Key digest differs", "the referenced finding's identity"),
    "review_artifact_missing": _r(("review",), INCOMPLETE, "the review report file is absent", "the review"),
    "review_report_has_errors": _r(("review",), INCOMPLETE, "the review report has errors[] entries (part of the review did not run)", "that the review covered what it was asked to"),
    "review_tool_unavailable": _r(("review",), INCOMPLETE, "the review report lists no tool, or a tool that was not available", "that the review's tools ran"),
    "review_report_invalid": _r(("review",), INCOMPLETE, "the review report is not a consistent Review_Report 1.0.0", "the review"),
    # verification
    "verification_digest_mismatch": _r(("verification",), BROKEN, "the verification report file has another SHA-256 than the manifest", "the verification report's content"),
    "payload_digest_mismatch": _r(("verification",), BROKEN, "the payload differs from the manifest's digest or from the recomputation", "the verification result"),
    "metadata_digest_mismatch": _r(("verification",), BROKEN, "metadata.payload_sha256 does not match the payload", "the verification report's integrity"),
    "report_subject_mismatch": _r(("verification",), BROKEN, "the report's base / head differ from the manifest", "that the report is about this subject"),
    "verification_artifact_missing": _r(("verification",), INCOMPLETE, "the verification report file is absent", "the verification"),
    "report_invalid": _r(("verification",), INCOMPLETE, "the verification report is not a valid Remediation_Verification_Report", "the verification"),
    "recompute_unavailable": _r(("verification",), NOT_PROVEN, "the verification could not be recomputed (tool missing, other version, failure)", "that the report's result is reproducible here"),
    # gate (GV-1..GV-4 are WP2)
    "gate_record_missing": _r(("gate",), INCOMPLETE, "the manifest names no gate record", "every Human Gate fact"),
    "gate_evaluation_not_implemented": _r(("gate",), NOT_PROVEN, "WP1 addition: gate records are not evaluated before WP2", "every Human Gate fact"),
    # github
    "store_manifest_mismatch": _r(("github",), BROKEN, "the store revision's MANIFEST differs from the manifest, or the evidence is in another revision", "that the evidence is the referenced capture"),
    "repository_mismatch": _r(("github",), BROKEN, "the evidence names another repository than repository_id", "that the evidence is about this repository"),
    "integrity_not_pass": _r(("github",), INCOMPLETE, "the M1 integrity validator does not pass the named evidence", "the evidence's integrity"),
    "evidence_id_missing": _r(("github",), INCOMPLETE, "the store, the revision or a named evidence id is absent", "the named evidence"),
    "capture_incomplete": _r(("github",), INCOMPLETE, "a named capture is incomplete (pagination, limits, errors)", "the captured answers"),
    # any link
    "link_check_error": _r(LINKS, INCOMPLETE, "WP1 addition: the link check stopped on an unexpected error", "that link"),
}


#: Diagnostic codes (WP1 final audit, N-5). They describe the environment and never change a link or chain
#: status; the validator writes them to the result's metadata, outside the deterministic payload.
DIAGNOSTICS: Mapping[str, str] = {
    "validator_identity_matches": "the report's validator identity equals the recomputation's (not an authentication)",
    "validator_identity_differs": "the report names another plugin revision, source digest or Python version than the recomputation",
    "validator_identity_not_compared": "no recomputation ran, so the identities were not compared",
}


def reason(code: str) -> Optional[Reason]:
    """The catalog entry of ``code``, or ``None`` when the code is unknown."""
    return REASONS.get(code)


def link_status(codes: Iterable[str]) -> str:
    """The status a link's codes force. An unknown code counts as INCOMPLETE (fail closed)."""
    worst = 0
    for code in codes:
        entry = REASONS.get(code)
        worst = max(worst, _RANK[entry.status] if entry is not None and entry.status in _RANK else _RANK[INCOMPLETE])
    return next((s for s, r in _RANK.items() if r == worst), LINKED) if worst else LINKED


def compose(statuses: Mapping[str, str]) -> str:
    """Chain status from the link statuses (m2-schemas.md §3).

    BROKEN > INCOMPLETE > NOT_PROVEN > COMPLETE. COMPLETE only when all six links are LINKED. A missing
    link, NOT_PRESENT and any value outside :data:`LINK_STATUSES` count as INCOMPLETE.
    """
    worst = 0
    for link in LINKS:
        value = statuses.get(link)
        if value == LINKED:
            continue
        if value in (BROKEN, NOT_PROVEN):
            worst = max(worst, _RANK[value])
        else:  # INCOMPLETE, NOT_PRESENT, missing, unknown
            worst = max(worst, _RANK[INCOMPLETE])
    if set(statuses) - set(LINKS):
        worst = max(worst, _RANK[INCOMPLETE])
    return next((s for s, r in _RANK.items() if r == worst), COMPLETE) if worst else COMPLETE


def exit_code_for(chain_status: str, input_invalid: bool = False) -> int:
    """The reserved exit code of a chain status (34 for an unusable input). Unknown statuses map to INCOMPLETE."""
    if input_invalid:
        return EXIT_INPUT_INVALID
    return EXIT_CODES.get(chain_status, EXIT_CODES[INCOMPLETE])
