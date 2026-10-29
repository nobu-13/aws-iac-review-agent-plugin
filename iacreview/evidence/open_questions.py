"""S7-19: the open questions of the plan, recorded with their state (Phase 2 M1 WP5-1).

Source: ``docs/v2/phase1/app-demo-plan.md`` §7, last clause (S7-19 in ``definitions/phase1-app-demo-s7.v1.json``):

    Not verified until the run: whether ``isRequired`` honours the expected source; whether ``POST /rulesets``
    accepts ``integration_id`` directly; whether ``user/installations`` reports the permissions as planned;
    whether step outputs of a failed step reach the publisher (if not, BLOCKED runs still publish failure).

Purpose: report each of the four questions as *not verified* until evidence answers it, and never as answered
because the rule or the question exists. The state of a question is derived from the per-scenario criterion
results of the same evaluation and from the facts; it is never read from a registry, a claim or a Phase 1
classification.

States (closed set, one per question):

``NOT_RUN``                no evidence of the observation the question needs
``RUN_UNSETTLED``          the observation exists, but GitHub's answer in it is not settled (e.g. ``isRequired`` null,
                           a gate run that has not completed)
``EVIDENCE_INSUFFICIENT``  evidence exists, but not the evidence that answers the question
``LIMIT_DECLARED``         declared as a limit by the caller (the evaluator declares none: a limit needs an approved
                           Definition change)
``EVIDENCE_SATISFIED``     the evidence answers the question; ``answer`` records which way

The criterion is PASS only if every question is ``EVIDENCE_SATISFIED``; otherwise it is NOT_PROVEN with the ids
of the questions that are not. The clause names no violation, so this rule never returns FAILED (an answer
that is unwelcome, such as "``isRequired`` does not honour the expected source", is a settled answer here and a
FAILED in S7-08 / S7-15, which judge it).

Interpretations (recorded in ``docs/v2/phase2/m1/wp5/wp5-acceptance-report.md`` for Human review):

* Q1 is settled by one counterexample (an impostor with ``isRequired = true``, or an App check with
  ``isRequired = false``) or by all three spoof scenarios showing the impostor present and not required and the
  App check required.
* Q2 needs the answer of the create call itself. The read-only collector captures no write call, so a ruleset
  read back with the App's ``integration_id`` is ``EVIDENCE_INSUFFICIENT``, not an answer.
* Q3 needs ``GET /user/installations``, which needs a GitHub App user access token (plan §3); no evidence role
  carries it, so it stays ``NOT_RUN``.
* Q4 is settled when a scenario whose verify step is expected to fail shows the decision published (S7-03b), the
  App check naming the run (S7-05), the published digest equal to the report's (S7-06) and the expected
  conclusion (S7-07). A digest that differs is not read as "the outputs did not reach the publisher".
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from iacreview.evidence import rules_s7

RULE_ID = "s7.open_questions.recorded"
CRITERION_ID = "S7-19"

NOT_RUN, RUN_UNSETTLED, INSUFFICIENT, LIMIT, SATISFIED = (
    "NOT_RUN", "RUN_UNSETTLED", "EVIDENCE_INSUFFICIENT", "LIMIT_DECLARED", "EVIDENCE_SATISFIED")
STATES = (NOT_RUN, RUN_UNSETTLED, INSUFFICIENT, LIMIT, SATISFIED)

#: The four questions, as quoted from the S7-19 criterion text (whitespace-normalized).
QUESTIONS: Tuple[Tuple[str, str], ...] = (
    ("Q1", "whether `isRequired` honours the expected source"),
    ("Q2", "whether `POST /rulesets` accepts `integration_id` directly"),
    ("Q3", "whether `user/installations` reports the permissions as planned"),
    ("Q4", "whether step outputs of a failed step reach the publisher"),
)

#: Scenarios whose verify step is expected to fail (§6), used by Q4.
FAILURE_SCENARIOS = tuple(sorted(s for s, (concl, _) in rules_s7.SCENARIO_EXPECTATIONS.items() if concl == "failure"))

Results = Sequence[Mapping[str, Any]]


def _criteria(results: Results) -> Dict[Tuple[str, str], Tuple[str, str]]:
    return {(r["scenario"], c["criterion_id"]): (c["status"], c["reason_code"]) for r in results for c in r.get("criteria") or []}


def _basis(by: Mapping[Tuple[str, str], Tuple[str, str]], scenario: str, crits: Sequence[str]) -> List[Dict[str, Any]]:
    return [{"scenario": scenario, "criterion_id": c, "status": by[(scenario, c)][0], "reason_code": by[(scenario, c)][1]}
            for c in crits if (scenario, c) in by]


def _combine(per: Sequence[str]) -> str:
    """Per-scenario observations (not_run / unsettled / insufficient) to one state when nothing settled the question."""
    if not per or all(p == "not_run" for p in per):
        return NOT_RUN
    if "unsettled" in per:
        return RUN_UNSETTLED
    return INSUFFICIENT


def _q1(by: Mapping[Tuple[str, str], Tuple[str, str]]) -> Tuple[str, Optional[str], str, List[Dict[str, Any]]]:
    per: List[str] = []
    honours: List[str] = []
    counter: List[str] = []
    basis: List[Dict[str, Any]] = []
    for s in rules_s7.SPOOF_SCENARIOS:
        if (s, "S7-08") not in by or (s, "S7-09") not in by:
            per.append("not_run")
            continue
        basis += _basis(by, s, ("S7-08", "S7-09"))
        (st8, r8), (st9, r9) = by[(s, "S7-08")], by[(s, "S7-09")]
        if st8 == "FAILED" or st9 == "FAILED":
            counter.append(s)
        elif st8 == "PASS" and r8 == "impostors_not_required" and st9 == "PASS":
            honours.append(s)
        elif r8 == "rollup_or_check_source_missing" and r9 == "rollup_or_check_source_missing":
            per.append("not_run")
        elif r8 in ("impostor_is_required_missing",) or r9 in ("app_is_required_missing",):
            per.append("unsettled")
        else:
            per.append("insufficient")
    if counter:
        return SATISFIED, "does_not_honour", "counterexample_observed", basis
    if len(honours) == len(rules_s7.SPOOF_SCENARIOS):
        return SATISFIED, "honours", "all_spoof_scenarios_settled", basis
    # Some spoof scenarios settled as "honours" but not all: a partial observation, never NOT_RUN.
    state = _combine(per + ["insufficient"] * len(honours))
    return state, None, {NOT_RUN: "spoof_observation_missing", RUN_UNSETTLED: "is_required_unsettled",
                         INSUFFICIENT: "spoof_evidence_insufficient"}[state], basis


def _pin_observed(rules_main: Any, app_id: Any) -> bool:
    for rule in rules_main if isinstance(rules_main, list) else []:
        if not isinstance(rule, dict) or rule.get("type") != "required_status_checks":
            continue
        for c in ((rule.get("parameters") or {}).get("required_status_checks") or []):
            if isinstance(c, dict) and c.get("context") == rules_s7.CHECK_NAME and c.get("integration_id") == app_id and app_id is not None:
                return True
    return False


def _q2(facts_by_scenario: Mapping[str, Mapping[str, Any]]) -> Tuple[str, Optional[str], str, List[Dict[str, Any]]]:
    seen = [(s, f) for s, f in sorted(facts_by_scenario.items()) if f.get("rules_main") is not None]
    if not seen:
        return NOT_RUN, None, "ruleset_not_observed", []
    pinned = sorted(s for s, f in seen if _pin_observed(f.get("rules_main"), f.get("app_id")))
    basis = [{"scenario": s, "criterion_id": None, "status": "OBSERVED", "reason_code": "rules_main_pinned" if s in pinned else "rules_main_read"}
             for s, _ in seen]
    return INSUFFICIENT, None, "pin_observed_create_call_not_captured" if pinned else "create_call_not_captured", basis


def _q3() -> Tuple[str, Optional[str], str, List[Dict[str, Any]]]:
    return NOT_RUN, None, "user_installations_not_captured", []


def _q4(by: Mapping[Tuple[str, str], Tuple[str, str]]) -> Tuple[str, Optional[str], str, List[Dict[str, Any]]]:
    crits = ("S7-03b", "S7-05", "S7-06", "S7-07")
    per: List[str] = []
    basis: List[Dict[str, Any]] = []
    reached: List[str] = []
    for s in FAILURE_SCENARIOS:
        if not all((s, c) in by for c in crits):
            continue
        b = _basis(by, s, crits)
        basis += b
        if all(x["status"] == "PASS" for x in b):
            reached.append(s)
        elif by[(s, "S7-03b")][1] == "gate_runs_missing":
            per.append("not_run")
        elif by[(s, "S7-03b")][1] == "no_completed_gate_run_on_head":
            per.append("unsettled")
        else:
            per.append("insufficient")
    if reached:
        return SATISFIED, "outputs_reach_publisher", "failed_step_report_published", basis
    state = _combine(per)
    return state, None, {NOT_RUN: "failed_gate_run_not_observed", RUN_UNSETTLED: "gate_run_not_completed",
                         INSUFFICIENT: "published_report_not_shown"}[state], basis


def open_questions_recorded(results: Results, facts_by_scenario: Mapping[str, Mapping[str, Any]],
                            declared_limits: Optional[Mapping[str, str]] = None) -> Dict[str, Any]:
    """S7-19 over one evaluation: per-question state and the criterion status (PASS / NOT_PROVEN, never FAILED)."""
    by = _criteria(results)
    derived = {"Q1": _q1(by), "Q2": _q2(facts_by_scenario), "Q3": _q3(), "Q4": _q4(by)}
    limits = dict(declared_limits or {})
    questions: List[Dict[str, Any]] = []
    for qid, clause in QUESTIONS:
        state, answer, reason, basis = derived[qid]
        if qid in limits and state != SATISFIED:
            state, answer, reason = LIMIT, None, "limit_declared:" + str(limits[qid])
        questions.append({"question_id": qid, "clause": clause, "state": state, "answer": answer, "reason_code": reason,
                          "basis": sorted(basis, key=lambda x: (x["scenario"], str(x["criterion_id"])))})
    open_ids = [str(q["question_id"]) for q in questions if q["state"] != SATISFIED]
    status, reason = ("PASS", "all_open_questions_settled") if not open_ids else ("NOT_PROVEN", "open_questions_unsettled:" + ",".join(open_ids))
    return {"criterion_id": CRITERION_ID, "rule_id": RULE_ID, "status": status, "reason_code": reason, "questions": questions}


def not_implemented() -> Dict[str, Any]:
    """The record when the catalog does not mark the rule IMPLEMENTED: NOT_PROVEN, no question answered."""
    return {"criterion_id": CRITERION_ID, "rule_id": RULE_ID, "status": "NOT_PROVEN", "reason_code": "rule_not_implemented",
            "questions": []}
