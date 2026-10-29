"""Catalog of evaluator rule ids (Phase 2 M1 WP1).

Source: ``docs/v2/phase2/m1/wp0/acceptance-alignment-audit.md`` §2 (criterion
to function table) and ``m1-architecture-proposal.md`` §3-5. Purpose: give
every rule id an Acceptance Definition may name a single, closed entry with its
implementation status, so that a Definition can never point at a rule that does
not exist and a planned rule can never be mistaken for an implemented one.

Status: WP1 implemented no rule. WP2 implemented ``s7.evidence.raw_api_data_stored``
(criterion S7-01, :mod:`iacreview.evidence.rule_s7_evidence`). WP3 implements
``phase2.artifact.whole_tree_matches_source`` (P2-AI-01) and
``phase2.artifact.published_matches_source`` (P2-AI-02,
:mod:`iacreview.evidence.artifact`). WP4 implements the 20 rules planned for WP4
(:mod:`iacreview.evidence.rules_s7`). WP5 implements ``s7.open_questions.recorded``
(criterion S7-19, :mod:`iacreview.evidence.open_questions`); no rule is ``PLANNED`` now. ``wp`` is the planned WP for a
planned rule and the implementing WP for an implemented one.

A rule becomes ``IMPLEMENTED`` only together with a callable in
:data:`IMPLEMENTATIONS`, and the registry validator requires its rule tests to be
``IMPLEMENTED`` too (and a planned rule's rule tests to be planned). An
implemented rule is code that exists; it is not a result. A rule shows a PASS
only by being run on evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, FrozenSet, Mapping

from iacreview.evidence import artifact, open_questions, rule_s7_evidence, rules_s7

#: Closed set of rule implementation states.
RULE_STATUSES: FrozenSet[str] = frozenset({"PLANNED", "IMPLEMENTED"})

#: The statuses a rule can produce. A Definition's expected_result must name exactly the outcomes its rule can
#: reach (registry check, Pre-Commit Remediation C-2); tests/unit/test_evidence_rule_outcomes.py checks each
#: declaration against the rule's code.
ALL_OUTCOMES: FrozenSet[str] = frozenset({"PASS", "FAILED", "NOT_PROVEN"})
LIMIT_OUTCOMES: FrozenSet[str] = frozenset({"NOT_PROVEN"})
OPEN_QUESTION_OUTCOMES: FrozenSet[str] = frozenset({"PASS", "NOT_PROVEN"})

#: Work packages a planned rule may be assigned to.
PLANNED_WPS: FrozenSet[str] = frozenset({"WP2", "WP3", "WP4", "WP5"})


@dataclass(frozen=True)
class RuleSpec:
    """One evaluator rule: what it decides, and whether it exists yet."""

    rule_id: str
    status: str
    planned_wp: str
    summary: str
    outcomes: FrozenSet[str] = ALL_OUTCOMES


def _planned(rule_id: str, wp: str, summary: str, outcomes: FrozenSet[str] = ALL_OUTCOMES) -> RuleSpec:
    return RuleSpec(rule_id=rule_id, status="PLANNED", planned_wp=wp, summary=summary, outcomes=outcomes)


def _implemented(rule_id: str, wp: str, summary: str, outcomes: FrozenSet[str] = ALL_OUTCOMES) -> RuleSpec:
    return RuleSpec(rule_id=rule_id, status="IMPLEMENTED", planned_wp=wp, summary=summary, outcomes=outcomes)


_SPECS = (
    # Evidence recording and composition
    _implemented("s7.evidence.raw_api_data_stored", "WP2", "raw GitHub API responses are stored, not only extracted fields"),
    _implemented("s7.compose.all_parts", "WP4", "scenario PASS only if every part PASS; any FAILED part makes it FAILED"),
    _implemented("s7.limits.recorded_not_proven", "WP4", "G8, AC28, admin bypass and same_app_with_key are NOT_PROVEN with a reason",
                 LIMIT_OUTCOMES),
    _implemented("s7.open_questions.recorded", "WP5", "the open questions of the plan are reported as not verified until observed",
                 OPEN_QUESTION_OUTCOMES),
    # Gate provenance
    _implemented("s7.gate.base_gate_provenance", "WP4", "the run is the base gate (event, path, head, base, pins, contract, token)"),
    _implemented("s7.gate.verify_step_as_expected", "WP4", "the verify step decided as the scenario expects"),
    # App check provenance
    _implemented("s7.app_check.exactly_one_app_check", "WP4", "exactly one App check of the required name on the head"),
    _implemented("s7.app_check.external_id_names_gate_run", "WP4", "external_id <run>.<attempt>:<digest> names the gate run"),
    _implemented("s7.app_check.report_digest_matches", "WP4", "the downloaded report's recomputed digest equals the external_id digest"),
    _implemented("s7.app_check.conclusion_as_expected", "WP4", "the App check conclusion is the expected one"),
    # Required check / isRequired
    _implemented("s7.required.impostor_not_required", "WP4", "every same-named non-App check run or status has isRequired = false"),
    _implemented("s7.required.app_check_required", "WP4", "the App's check has isRequired = true"),
    _implemented("s7.required.same_name_other_source", "WP4", "G3/G3S/G6: the impostor exists with isRequired = false and the App check is the required one"),
    _implemented("s7.required.impostor_required_fails_scenario", "WP4", "an impostor with isRequired = true makes the scenario FAILED"),
    _implemented("s6.expected.impostor_not_required", "WP4", "the pre-fixed scenario table expects the same-named impostor to be not required"),
    # Merge blocking
    _implemented("s7.required.merge_state_as_expected", "WP4", "GitHub's merge state is the expected one"),
    _implemented("s7.merge.spoof_scenario_blocked", "WP4", "G3/G3S/G6: the merge state is BLOCKED"),
    # Issuer pinning (axis added in Phase 1 rev2, not in section 7)
    _implemented("phase2.issuer_pinning.independent_proof", "WP4",
             "a same-named non-App context is shown not to satisfy the rule on a head where the App check alone does not explain the merge state"),
    # G11 environment boundary
    _implemented("s7.steal.no_step_executed", "WP4", "every steal.yml run concluded and no job executed any step"),
    _implemented("s7.steal.app_checks_name_gate_runs", "WP4", "every App check on the head names a gate run"),
    _implemented("s7.steal.environment_refuses_both_events", "WP4", "the environment refuses pull_request and push (no step, no token, no foreign App check)"),
    _implemented("s7.limit.same_app_with_key", "WP4", "a same-App success by a key holder stays a limit, never a pass", LIMIT_OUTCOMES),
    # Artifact integrity (added in Phase 2; section 7 had no such criterion)
    _implemented("phase2.artifact.whole_tree_matches_source", "WP3", "the pushed commit's whole tree equals the approved source byte for byte"),
    _implemented("phase2.artifact.published_matches_source", "WP3", "the content published on GitHub equals the approved source (git blob id)"),
)

#: Every known rule id. Read-only view; the registry validator checks against it.
RULE_CATALOG: Mapping[str, RuleSpec] = {spec.rule_id: spec for spec in _SPECS}

#: Callables of IMPLEMENTED rules, by rule id.
IMPLEMENTATIONS: Dict[str, Callable[..., object]] = {
    rule_s7_evidence.RULE_ID: rule_s7_evidence.raw_api_data_stored,
    artifact.RULE_WHOLE_TREE: artifact.whole_tree_matches_source,
    artifact.RULE_PUBLISHED: artifact.published_matches_source,
    rules_s7.COMPOSE_RULE: rules_s7.compose,
    open_questions.RULE_ID: open_questions.open_questions_recorded,
    **dict(rules_s7.RULES),
}


def catalog_problems() -> list:
    """Internal consistency of the catalog itself; empty means consistent."""
    problems = []
    if len(RULE_CATALOG) != len(_SPECS):
        problems.append("duplicate rule id in the catalog")
    for spec in _SPECS:
        if spec.status not in RULE_STATUSES:
            problems.append("{0}: unknown status {1!r}".format(spec.rule_id, spec.status))
        if spec.planned_wp not in PLANNED_WPS:
            problems.append("{0}: rule without a WP".format(spec.rule_id))
        if not spec.outcomes or not spec.outcomes <= ALL_OUTCOMES or "NOT_PROVEN" not in spec.outcomes:
            problems.append("{0}: outcomes must be a subset of PASS / FAILED / NOT_PROVEN that includes NOT_PROVEN".format(spec.rule_id))
        if (spec.status == "IMPLEMENTED") != (spec.rule_id in IMPLEMENTATIONS):
            problems.append("{0}: status {1} does not match the implementations".format(spec.rule_id, spec.status))
    for rule_id in IMPLEMENTATIONS:
        if rule_id not in RULE_CATALOG:
            problems.append("{0}: implementation without a catalog entry".format(rule_id))
    return problems
