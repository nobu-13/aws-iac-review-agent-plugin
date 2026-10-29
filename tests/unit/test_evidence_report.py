"""S7-19 open questions and the Final Report (Phase 2 M1 WP5-1, WP5-4).

Scenario results come from synthetic GitHub answers (``evidence_synth.py``) judged by the same evaluator code as
the native replay. Every question starts as not verified; a question becomes EVIDENCE_SATISFIED only when the
evidence of the same evaluation answers it, never because the rule or the question is registered.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Mapping, Tuple

import pytest

import evidence_synth as syn
from iacreview.evidence import canonical, evaluator, final_report, open_questions, replay, rules

ROOT = Path(__file__).resolve().parents[2]


def judged(*specs: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Dict[str, Mapping[str, Any]]]:
    definition, _ = replay.load_definition()
    results, facts_by = [], {}
    for spec in specs:
        f = syn.direct_facts(spec)
        facts_by[spec["gid"]] = f
        results.append(evaluator.evaluate_scenario(spec["gid"], f, definition, {}))
    return results, facts_by


def states(record: Dict[str, Any]) -> Dict[str, str]:
    return {q["question_id"]: q["state"] for q in record["questions"]}


def spoof(**over: Any) -> List[Dict[str, Any]]:
    return [syn.scenario_spec(g, **over) for g in ("G3", "G3S", "G6")]


def test_s7_open_questions_recorded() -> None:
    """Rule behaviour of S7-19: every question has one of the five states; the criterion is never PASS while a
    question is open, and never FAILED (the clause names no violation)."""
    # Nothing observed: every question NOT_RUN, criterion NOT_PROVEN.
    rec = open_questions.open_questions_recorded([], {})
    assert states(rec) == {"Q1": "NOT_RUN", "Q2": "NOT_RUN", "Q3": "NOT_RUN", "Q4": "NOT_RUN"}
    assert rec["status"] == "NOT_PROVEN" and rec["reason_code"] == "open_questions_unsettled:Q1,Q2,Q3,Q4"

    # The full synthetic set: Q1 settled ("honours"), Q4 settled, Q2 / Q3 not answerable by read-only evidence.
    rec = open_questions.open_questions_recorded(*judged(syn.scenario_spec("G2"), *spoof()))
    assert states(rec) == {"Q1": "EVIDENCE_SATISFIED", "Q2": "EVIDENCE_INSUFFICIENT", "Q3": "NOT_RUN", "Q4": "EVIDENCE_SATISFIED"}
    by = {q["question_id"]: q for q in rec["questions"]}
    assert by["Q1"]["answer"] == "honours" and by["Q4"]["answer"] == "outputs_reach_publisher"
    assert by["Q2"]["reason_code"] == "pin_observed_create_call_not_captured" and by["Q3"]["reason_code"] == "user_installations_not_captured"
    assert rec["status"] == "NOT_PROVEN" and rec["reason_code"] == "open_questions_unsettled:Q2,Q3"

    # One counterexample settles Q1 the other way (an unwelcome answer is still an answer here).
    rec = open_questions.open_questions_recorded(*judged(syn.scenario_spec("G3", impostor_required=True)))
    assert {q["question_id"]: (q["state"], q["answer"]) for q in rec["questions"]}["Q1"] == ("EVIDENCE_SATISFIED", "does_not_honour")

    # GitHub's answer not settled in the observation: RUN_UNSETTLED.
    rec = open_questions.open_questions_recorded(*judged(*spoof(impostor_required=None)))
    assert states(rec)["Q1"] == "RUN_UNSETTLED"

    # Two of three spoof scenarios settled, one without evidence: EVIDENCE_INSUFFICIENT, not "honours".
    specs = spoof()
    specs[2] = syn.scenario_spec("G6", omit=("rollup",))
    rec = open_questions.open_questions_recorded(*judged(*specs))
    assert states(rec)["Q1"] == "EVIDENCE_INSUFFICIENT"

    # Q4 without the report artifact: the published digest cannot be compared, so not settled.
    rec = open_questions.open_questions_recorded(*judged(syn.scenario_spec("G2", omit=("report_artifact",))))
    assert states(rec)["Q4"] == "EVIDENCE_INSUFFICIENT"
    rec = open_questions.open_questions_recorded(*judged(syn.scenario_spec("G2", omit=("gate_run",))))
    assert states(rec)["Q4"] == "NOT_RUN"

    # A declared limit is LIMIT_DECLARED, and the criterion is still not PASS.
    rec = open_questions.open_questions_recorded(*judged(syn.scenario_spec("G2"), *spoof()), declared_limits={"Q3": "needs_user_token"})
    assert states(rec)["Q3"] == "LIMIT_DECLARED" and rec["status"] == "NOT_PROVEN"
    assert all(q["state"] in open_questions.STATES for q in rec["questions"])
    # PASS (every question EVIDENCE_SATISFIED) is not reachable with today's evidence roles (Q2, Q3); the
    # combination itself is tested in test_s7_19_pass_needs_every_question_satisfied.


def test_s7_19_pass_needs_every_question_satisfied(monkeypatch: pytest.MonkeyPatch) -> None:
    sat = (open_questions.SATISFIED, "yes", "stub", [])
    for q in ("_q1", "_q2", "_q4"):
        monkeypatch.setattr(open_questions, q, lambda *a, **k: sat)
    monkeypatch.setattr(open_questions, "_q3", lambda: sat)
    rec = open_questions.open_questions_recorded([], {})
    assert rec["status"] == "PASS" and rec["reason_code"] == "all_open_questions_settled"
    monkeypatch.setattr(open_questions, "_q3", lambda: (open_questions.NOT_RUN, None, "x", []))
    assert open_questions.open_questions_recorded([], {})["status"] == "NOT_PROVEN"


def test_s7_19_never_returns_failed_even_for_a_failed_scenario() -> None:
    rec = open_questions.open_questions_recorded(*judged(syn.scenario_spec("G3", impostor_required=True), syn.scenario_spec("G2", app_required=False)))
    assert rec["status"] != "FAILED"


def test_the_questions_are_quoted_from_the_s7_19_text() -> None:
    definition, _ = replay.load_definition()
    text = next(c["criterion_text"] for ac in definition["acceptance_criteria"] for c in ac["criteria"] if c["criterion_id"] == "S7-19")
    flat = re.sub(r"\s+", " ", text)
    assert [q for q, _ in open_questions.QUESTIONS] == ["Q1", "Q2", "Q3", "Q4"]
    for _, clause in open_questions.QUESTIONS:
        assert flat.count(clause) == 1, clause
    assert flat.startswith("Not verified until the run:")


def test_registration_alone_is_not_an_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    """The record is NOT_PROVEN rule_not_implemented when the catalog does not mark the rule implemented, and the
    implemented rule still answers nothing without evidence."""
    spec = rules.RULE_CATALOG[open_questions.RULE_ID]
    fake = dict(rules.RULE_CATALOG)
    fake[spec.rule_id] = rules.RuleSpec(spec.rule_id, "PLANNED", "WP5", spec.summary)
    monkeypatch.setattr(rules, "RULE_CATALOG", fake)
    rec = evaluator._open_questions([], {})
    assert rec == open_questions.not_implemented() and rec["status"] == "NOT_PROVEN"
    monkeypatch.undo()
    assert evaluator._open_questions([], {})["status"] == "NOT_PROVEN"


# ---------------------------------------------------------------------------
# Final Report
# ---------------------------------------------------------------------------


def _result(tmp_path: Path) -> bytes:
    b = syn.Builder(tmp_path)
    for gid in ("G1", "G2"):
        b.add_scenario(syn.scenario_spec(gid))
    b.add_scenario(syn.scenario_spec("G3", impostor_required=True))
    return replay.replay(b.seal())


def test_the_final_report_copies_the_result_and_claims_no_authenticity(tmp_path: Path) -> None:
    data = _result(tmp_path)
    rep = final_report.build(data)
    assert rep["result_sha256"] == __import__("hashlib").sha256(data).hexdigest()
    assert rep["assurance"]["capture_authenticity"] == "NOT_PROVEN" and rep["assurance"]["independent_reproduction"] == "NOT_PROVEN"
    assert rep["assurance"]["rules_implemented"] == "PASS" and rep["assurance"]["evidence_kind"] == "NATIVE_RAW"
    by = {s["scenario"]: s for s in rep["scenarios"]}
    assert by["G3"]["s7_result"] == "FAILED" and {c["criterion_id"] for c in by["G3"]["not_pass"]} >= {"S7-08", "S7-15"}
    assert rep["counts"]["s7_result"] == {"PASS": 2, "FAILED": 1, "NOT_PROVEN": 0}
    assert rep["open_questions"]["status"] == "NOT_PROVEN"
    out = final_report.report_bytes(data)
    assert out == final_report.report_bytes(data) and canonical.dumps(json.loads(out)) == out


def test_the_final_report_refuses_a_non_canonical_or_foreign_input(tmp_path: Path) -> None:
    data = _result(tmp_path)
    doc = json.loads(data)
    with pytest.raises(final_report.ReportInputError, match="canonical"):
        final_report.build(json.dumps(doc, indent=1).encode())
    other = copy.deepcopy(doc)
    other["result_format"] = "something/1"
    with pytest.raises(final_report.ReportInputError, match="format"):
        final_report.build(canonical.dumps(other))
    with pytest.raises(final_report.ReportInputError):
        final_report.build(b"\xff")


def test_the_final_report_cli(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    path = tmp_path / "result.json"
    path.write_bytes(_result(tmp_path))
    assert final_report.main([str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["report_format"] == final_report.REPORT_FORMAT
    (tmp_path / "bad.json").write_bytes(b"{}")
    assert final_report.main([str(tmp_path / "bad.json")]) == 2


# ---------------------------------------------------------------------------
# S7-19 interpretations I-1 ... I-6 and the four paths without an assertion (Pre-Commit Remediation C-2)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("specs", [
    [],
    [("G3", {"impostor_required": True})],
    [("G3", {"app_required": False}), ("G3S", {}), ("G6", {})],
    [("G2", {"verify": "success"})],
    [("G2", {"report_tamper": True})],
    [("G2", {"run_on_head": False})],
])
def test_s7_19_i1_never_failed(specs: List[Tuple[str, Dict[str, Any]]]) -> None:
    """I-1: §7 names no violation for S7-19; failed scenarios elsewhere never make S7-19 FAILED."""
    rec = open_questions.open_questions_recorded(*judged(*[syn.scenario_spec(g, **o) for g, o in specs]))
    assert rec["status"] in ("PASS", "NOT_PROVEN")


def test_s7_19_i2_q1_counterexample_from_an_app_check_not_required() -> None:
    """I-2 (path 1 of 4): an App check with isRequired = false on a spoof scenario settles Q1 as does_not_honour."""
    results, facts_by = judged(syn.scenario_spec("G3", app_required=False))
    by = {c["criterion_id"]: c for c in results[0]["criteria"]}
    assert by["S7-08"]["status"] == "PASS" and by["S7-09"]["status"] == "FAILED"
    q = {x["question_id"]: x for x in open_questions.open_questions_recorded(results, facts_by)["questions"]}["Q1"]
    assert (q["state"], q["answer"], q["reason_code"]) == ("EVIDENCE_SATISFIED", "does_not_honour", "counterexample_observed")


def test_s7_19_i2_q1_all_three_spoof_scenarios_settle_honours() -> None:
    q = {x["question_id"]: x for x in open_questions.open_questions_recorded(*judged(*spoof()))["questions"]}["Q1"]
    assert (q["state"], q["answer"]) == ("EVIDENCE_SATISFIED", "honours")
    q = {x["question_id"]: x for x in open_questions.open_questions_recorded(*judged(*spoof()[:2]))["questions"]}["Q1"]
    assert (q["state"], q["answer"]) == ("EVIDENCE_INSUFFICIENT", None)  # two of three is not "honours"


def test_s7_19_i3_q2_a_ruleset_without_the_pin() -> None:
    """I-3 (path 2 of 4): a ruleset read back without the App pin is EVIDENCE_INSUFFICIENT create_call_not_captured."""
    results, facts_by = judged(syn.scenario_spec("G2"))
    facts_by = {k: dict(v, rules_main=[{"type": "pull_request", "parameters": {}}]) for k, v in facts_by.items()}
    q = {x["question_id"]: x for x in open_questions.open_questions_recorded(results, facts_by)["questions"]}["Q2"]
    assert (q["state"], q["reason_code"]) == ("EVIDENCE_INSUFFICIENT", "create_call_not_captured")
    assert q["basis"] == [{"scenario": "G2", "criterion_id": None, "status": "OBSERVED", "reason_code": "rules_main_read"}]


def test_s7_19_i3_q2_no_ruleset_observed() -> None:
    """I-3 (path 3 of 4): no ruleset evidence at all is NOT_RUN ruleset_not_observed."""
    results, facts_by = judged(syn.scenario_spec("G2", omit=("rules_main",)))
    q = {x["question_id"]: x for x in open_questions.open_questions_recorded(results, facts_by)["questions"]}["Q2"]
    assert (q["state"], q["reason_code"]) == ("NOT_RUN", "ruleset_not_observed")


def test_s7_19_i3_q2_a_pinned_ruleset_is_still_not_an_answer() -> None:
    q = {x["question_id"]: x for x in open_questions.open_questions_recorded(*judged(syn.scenario_spec("G2")))["questions"]}["Q2"]
    assert (q["state"], q["answer"], q["reason_code"]) == ("EVIDENCE_INSUFFICIENT", None, "pin_observed_create_call_not_captured")


def test_s7_19_i4_q3_is_never_answered() -> None:
    for specs in ([], [syn.scenario_spec("G2")], spoof()):
        q = {x["question_id"]: x for x in open_questions.open_questions_recorded(*judged(*specs))["questions"]}["Q3"]
        assert (q["state"], q["answer"], q["reason_code"]) == ("NOT_RUN", None, "user_installations_not_captured")


def test_s7_19_i5_q4_reached_needs_all_four_criteria() -> None:
    q = {x["question_id"]: x for x in open_questions.open_questions_recorded(*judged(syn.scenario_spec("G2")))["questions"]}["Q4"]
    assert (q["state"], q["answer"]) == ("EVIDENCE_SATISFIED", "outputs_reach_publisher")
    assert {b["criterion_id"] for b in q["basis"]} == {"S7-03b", "S7-05", "S7-06", "S7-07"}
    q = {x["question_id"]: x for x in open_questions.open_questions_recorded(*judged(syn.scenario_spec("G2", report_tamper=True)))["questions"]}["Q4"]
    assert q["state"] == "EVIDENCE_INSUFFICIENT" and q["answer"] is None  # a differing digest is not read as "did not reach"
    q = {x["question_id"]: x for x in open_questions.open_questions_recorded(*judged(syn.scenario_spec("G1")))["questions"]}["Q4"]
    assert q["state"] == "NOT_RUN"  # G1 is expected to pass: no failed step to observe


def test_s7_19_i5_q4_gate_run_not_completed_on_the_head() -> None:
    """I-5 (path 4 of 4): a gate run not completed on the head is RUN_UNSETTLED gate_run_not_completed."""
    results, facts_by = judged(syn.scenario_spec("G2", run_on_head=False))
    assert {c["criterion_id"]: c["reason_code"] for c in results[0]["criteria"]}["S7-03b"] == "no_completed_gate_run_on_head"
    q = {x["question_id"]: x for x in open_questions.open_questions_recorded(results, facts_by)["questions"]}["Q4"]
    assert (q["state"], q["reason_code"]) == ("RUN_UNSETTLED", "gate_run_not_completed")


def test_s7_19_i6_limits_only_when_declared() -> None:
    plain = open_questions.open_questions_recorded(*judged(syn.scenario_spec("G2")))
    assert all(q["state"] != "LIMIT_DECLARED" for q in plain["questions"])
    assert evaluator._open_questions(*judged(syn.scenario_spec("G2"))) == plain  # the evaluator declares none
    declared = open_questions.open_questions_recorded(*judged(syn.scenario_spec("G2")), declared_limits={"Q1": "x", "Q4": "y"})
    states_ = {q["question_id"]: q["state"] for q in declared["questions"]}
    assert states_["Q1"] == "LIMIT_DECLARED" and states_["Q4"] == "EVIDENCE_SATISFIED"  # a satisfied answer is not overridden


# ---------------------------------------------------------------------------
# S7-01 in the Final Report (Pre-Commit Remediation, S7-01)
# ---------------------------------------------------------------------------


def test_the_final_report_carries_s7_01_per_scenario(tmp_path: Path) -> None:
    rep = final_report.build(_result(tmp_path))
    er = rep["evidence_recording"]
    assert er["criterion_id"] == "S7-01" and er["status"] == "PASS" and er["counts"] == {"PASS": 3, "FAILED": 0, "NOT_PROVEN": 0}
    assert [r["reason_code"] for r in er["scenarios"]] == ["raw_api_bytes_stored_and_verified"] * 3


def test_s7_01_without_the_required_evidence_is_not_proven(tmp_path: Path) -> None:
    b = syn.Builder(tmp_path)
    b.add_scenario(syn.scenario_spec("G2", omit=("rollup",)))
    rep = final_report.build(replay.replay(b.seal()))
    assert rep["evidence_recording"]["status"] == "NOT_PROVEN"
    assert rep["evidence_recording"]["scenarios"] == [{"scenario": "G2", "status": "NOT_PROVEN", "reason_code": "required_role_missing:rollup"}]


def test_an_empty_s7_01_set_is_never_pass() -> None:
    assert final_report._compose_s7_01([]) == "NOT_PROVEN"
    assert final_report._compose_s7_01([{"status": "PASS"}, {"status": "NOT_PROVEN"}]) == "NOT_PROVEN"
    assert final_report._compose_s7_01([{"status": "PASS"}, {"status": "FAILED"}]) == "FAILED"


def test_s7_01_without_a_store_is_not_proven_and_does_not_change_the_s7_result() -> None:
    definition, _ = replay.load_definition()
    r = evaluator.evaluate_scenario("G2", syn.direct_facts(syn.scenario_spec("G2")), definition, {})
    c = next(c for c in r["criteria"] if c["criterion_id"] == "S7-01")
    assert (c["status"], c["reason_code"]) == ("NOT_PROVEN", "store_evidence_not_supplied")
    assert r["axes"]["evidence_recording"] == "NOT_PROVEN" and r["s7_result"] == "PASS"  # S7-01 is not one of the four parts
