"""§6-§7 evaluator rules: one rule-behaviour test per rule id named by the Definition (Phase 2 M1 WP4-2, WP4-3).

Facts come from synthetic GitHub answers (``evidence_synth.py``) parsed by the same parser the native
replay uses. Each test shows PASS, FAILED and NOT_PROVEN where the rule can produce them, and that missing
evidence is NOT_PROVEN, never PASS.
"""

from __future__ import annotations

import copy
from typing import Any, Dict

import pytest

import evidence_synth as syn
from iacreview.evidence import evaluator, rules, rules_s7

RULE_IDS = sorted(rules_s7.RULES) + [rules_s7.COMPOSE_RULE]


def facts(gid: str, **over: Any) -> Dict[str, Any]:
    return syn.direct_facts(syn.scenario_spec(gid, **over))


def st(rule: str, f: Dict[str, Any], gid: str) -> str:
    return rules_s7.RULES[rule](f, gid).status


def without(f: Dict[str, Any], *keys: str) -> Dict[str, Any]:
    g = copy.deepcopy(f)
    for k in keys:
        g[k] = None
    return g


def test_every_wp4_rule_is_implemented_with_a_callable() -> None:
    for rule in RULE_IDS:
        assert rules.RULE_CATALOG[rule].status == "IMPLEMENTED" and rules.RULE_CATALOG[rule].planned_wp == "WP4", rule
        assert rule in rules.IMPLEMENTATIONS
    assert rules.RULE_CATALOG["s7.open_questions.recorded"].status == "IMPLEMENTED"  # WP5-1; PLANNED in WP4


# ---------------------------------------------------------------------------
# Required check / isRequired
# ---------------------------------------------------------------------------


def test_s7_required_impostor_not_required() -> None:
    r = "s7.required.impostor_not_required"
    assert st(r, facts("G3"), "G3") == "PASS"
    assert st(r, facts("G3", impostor_required=True), "G3") == "FAILED"
    assert st(r, facts("G3S", impostor_required=True), "G3S") == "FAILED"
    assert st(r, facts("G2"), "G2") == "PASS"  # no impostor on the head
    assert st(r, facts("G3", impostor_required=None), "G3") == "NOT_PROVEN"
    assert st(r, without(facts("G3"), "contexts"), "G3") == "NOT_PROVEN"
    assert st(r, without(facts("G3"), "rest_checks"), "G3") == "NOT_PROVEN"  # check source needed to tell the App apart


def test_s7_required_app_check_required() -> None:
    r = "s7.required.app_check_required"
    assert st(r, facts("G2"), "G2") == "PASS"
    assert st(r, facts("G2", app_required=False), "G2") == "FAILED"
    assert st(r, facts("G2", app_required=None), "G2") == "NOT_PROVEN"
    assert st(r, facts("G2", app_check_present=False), "G2") == "NOT_PROVEN"
    assert st(r, without(facts("G2"), "contexts"), "G2") == "NOT_PROVEN"


def test_s7_required_same_name_other_source() -> None:
    r = "s7.required.same_name_other_source"
    assert st(r, facts("G6"), "G6") == "PASS"
    assert st(r, facts("G6", impostor_required=True), "G6") == "FAILED"
    assert st(r, facts("G6", app_required=False), "G6") == "FAILED"
    assert st(r, facts("G6", impostor=None), "G6") == "NOT_PROVEN"
    assert st(r, without(facts("G6"), "contexts"), "G6") == "NOT_PROVEN"


def test_s7_required_impostor_required_fails_scenario() -> None:
    r = "s7.required.impostor_required_fails_scenario"
    assert st(r, facts("G3S"), "G3S") == "PASS"
    assert st(r, facts("G3S", impostor_required=True), "G3S") == "FAILED"
    assert st(r, facts("G3S", impostor=None), "G3S") == "NOT_PROVEN"
    assert st(r, without(facts("G3S"), "rest_checks"), "G3S") == "NOT_PROVEN"


def test_s6_expected_impostor_not_required() -> None:
    r = "s6.expected.impostor_not_required"
    for gid in ("G3", "G3S", "G6"):
        assert st(r, facts(gid), gid) == "PASS"
        assert st(r, facts(gid, impostor_required=True), gid) == "FAILED"
    assert st(r, facts("G3", impostor=("check_run", "skipped")), "G3") == "NOT_PROVEN"  # not the impostor §6 names
    assert st(r, facts("G2"), "G2") == "NOT_PROVEN"


def test_an_impostor_required_fails_the_required_part_even_when_merge_is_blocked() -> None:
    """The Phase 1 divergence (WP0 §3-1): BLOCKED by the App failure never offsets an impostor's isRequired = true."""
    f = facts("G3", impostor_required=True)
    result = evaluator.evaluate_scenario("G3", f, _definition())
    assert result["axes"]["merge_blocking"] == "PASS" and result["axes"]["required_check"] == "FAILED"
    assert result["parts"]["required"] == "FAILED" and result["s7_result"] == "FAILED"


# ---------------------------------------------------------------------------
# Merge blocking
# ---------------------------------------------------------------------------


def test_s7_required_merge_state_as_expected() -> None:
    r = "s7.required.merge_state_as_expected"
    assert st(r, facts("G2"), "G2") == "PASS"
    assert st(r, facts("G2", merge_state="CLEAN"), "G2") == "FAILED"
    assert st(r, facts("G2", merge_state="UNKNOWN"), "G2") == "NOT_PROVEN"
    assert st(r, facts("G1"), "G1") == "PASS" and st(r, facts("G1", merge_state="BLOCKED"), "G1") == "FAILED"
    assert st(r, facts("G0"), "G0") == "PASS"
    g9 = facts("G9")
    assert st(r, g9, "G9") == "NOT_PROVEN"  # the W0 view is missing
    g9["mergeable_before_ruleset"] = "MERGEABLE"
    assert st(r, g9, "G9") == "PASS"
    assert st(r, without(facts("G2"), "merge_state"), "G2") == "NOT_PROVEN"


def test_s7_merge_spoof_scenario_blocked() -> None:
    r = "s7.merge.spoof_scenario_blocked"
    assert st(r, facts("G3"), "G3") == "PASS"
    assert st(r, facts("G3", merge_state="CLEAN"), "G3") == "FAILED"
    assert st(r, without(facts("G3"), "merge_state"), "G3") == "NOT_PROVEN"


# ---------------------------------------------------------------------------
# Issuer pinning
# ---------------------------------------------------------------------------


def test_phase2_issuer_pinning_independent_proof() -> None:
    r = "phase2.issuer_pinning.independent_proof"
    assert st(r, facts("G3"), "G3") == "NOT_PROVEN"  # App failure explains BLOCKED (Phase 1 situation)
    assert rules_s7.issuer_pinning_independent(facts("G3"), "G3").reason_code == "app_failure_explains_block"
    absent = facts("G3", app_check_present=False)
    assert st(r, absent, "G3") == "PASS"  # only the impostor, still BLOCKED
    assert st(r, facts("G3", app_check_present=False, merge_state="CLEAN"), "G3") == "FAILED"
    assert st(r, without(absent, "rules_main"), "G3") == "NOT_PROVEN"
    assert st(r, facts("G2"), "G2") == "NOT_PROVEN"  # no passing impostor


# ---------------------------------------------------------------------------
# Gate provenance
# ---------------------------------------------------------------------------


def test_s7_gate_base_gate_provenance() -> None:
    r = "s7.gate.base_gate_provenance"
    assert st(r, facts("G2"), "G2") == "PASS"
    for over in ({"event": "pull_request"}, {"path": ".github/workflows/spoof.yml"}, {"permissions": ("Contents: write",)},
                 {"relaxed": True}):
        assert st(r, facts("G2", **over), "G2") == "FAILED", over
    assert st(r, facts("G2", run_on_head=False), "G2") == "NOT_PROVEN"  # no gate run on the head
    f = facts("G2")
    f["gate_runs"][0]["log"]["token_permissions"] = None  # a missing fact is never defaulted (WP0 HA-5)
    assert st(r, f, "G2") == "NOT_PROVEN"
    assert st(r, without(facts("G2"), "gate_runs"), "G2") == "NOT_PROVEN"


def test_s7_gate_verify_step_as_expected() -> None:
    r = "s7.gate.verify_step_as_expected"
    assert st(r, facts("G2"), "G2") == "PASS" and st(r, facts("G1"), "G1") == "PASS"
    assert st(r, facts("G2", verify="success"), "G2") == "FAILED"
    f = facts("G2")
    f["gate_runs"][0]["publish_job"] = "failure"
    assert st(r, f, "G2") == "FAILED"
    assert st(r, without(facts("G2"), "gate_runs"), "G2") == "NOT_PROVEN"


# ---------------------------------------------------------------------------
# App check provenance
# ---------------------------------------------------------------------------


def test_s7_app_check_exactly_one_app_check() -> None:
    r = "s7.app_check.exactly_one_app_check"
    assert st(r, facts("G2"), "G2") == "PASS"
    two = facts("G2")
    two["rest_checks"].append(dict(two["rest_checks"][0], check_run_id=1))
    assert st(r, two, "G2") == "FAILED"
    assert st(r, facts("G2", app_check_present=False), "G2") == "NOT_PROVEN"
    assert st(r, without(facts("G2"), "rest_checks"), "G2") == "NOT_PROVEN"


def test_s7_app_check_external_id_names_gate_run() -> None:
    r = "s7.app_check.external_id_names_gate_run"
    assert st(r, facts("G2"), "G2") == "PASS"
    assert st(r, facts("G2", external_id_run=123), "G2") == "FAILED"
    f = facts("G2")
    f["rest_checks"][0]["external_id"] = "not-an-id"
    assert st(r, f, "G2") == "FAILED"
    assert st(r, without(facts("G2"), "gate_runs"), "G2") == "NOT_PROVEN"


def test_s7_app_check_report_digest_matches() -> None:
    r = "s7.app_check.report_digest_matches"
    assert st(r, facts("G2"), "G2") == "PASS"
    assert st(r, facts("G2", report_tamper=True), "G2") == "FAILED"
    assert st(r, facts("G2", omit=("report_artifact",)), "G2") == "NOT_PROVEN"


def test_s7_app_check_conclusion_as_expected() -> None:
    r = "s7.app_check.conclusion_as_expected"
    assert st(r, facts("G2"), "G2") == "PASS"
    assert st(r, facts("G2", app_conclusion="success"), "G2") == "FAILED"
    assert st(r, facts("G1", app_conclusion="failure"), "G1") == "FAILED"
    assert st(r, without(facts("G2"), "rest_checks"), "G2") == "NOT_PROVEN"


# ---------------------------------------------------------------------------
# G11 environment boundary
# ---------------------------------------------------------------------------


def test_s7_steal_no_step_executed() -> None:
    r = "s7.steal.no_step_executed"
    assert st(r, facts("G11"), "G11") == "PASS"
    assert st(r, facts("G11", steal_step=True), "G11") == "FAILED"
    assert st(r, facts("G11", steal=False), "G11") == "NOT_PROVEN"


def test_s7_steal_app_checks_name_gate_runs() -> None:
    r = "s7.steal.app_checks_name_gate_runs"
    assert st(r, facts("G11"), "G11") == "PASS"
    assert st(r, facts("G11", external_id_run=4242), "G11") == "FAILED"  # an App check naming a non-gate run
    assert st(r, without(facts("G11"), "gate_runs"), "G11") == "NOT_PROVEN"


def test_s7_steal_environment_refuses_both_events() -> None:
    r = "s7.steal.environment_refuses_both_events"
    assert st(r, facts("G11"), "G11") == "PASS"
    assert st(r, facts("G11", steal_step=True), "G11") == "FAILED"
    f = facts("G11")
    f["steal_runs"] = [x for x in f["steal_runs"] if x["event"] == "pull_request"]
    assert st(r, f, "G11") == "NOT_PROVEN"
    g = facts("G11")
    g["steal_runs"][0]["environment_denied"] = None
    assert st(r, g, "G11") == "NOT_PROVEN"


def test_s7_limit_same_app_with_key() -> None:
    assert st("s7.limit.same_app_with_key", facts("G11"), "G11") == "NOT_PROVEN"


def test_s7_limits_recorded_not_proven() -> None:
    for subject in ("G8", "AC28", "admin_bypass", "same_app_with_key"):
        assert rules_s7.limits_recorded({}, subject).status == "NOT_PROVEN"


# ---------------------------------------------------------------------------
# Composition
# ---------------------------------------------------------------------------


def test_s7_compose_all_parts() -> None:
    assert rules_s7.compose(["PASS", "PASS"]) == "PASS"
    assert rules_s7.compose(["PASS", "NOT_PROVEN"]) == "NOT_PROVEN"
    assert rules_s7.compose(["NOT_PROVEN", "FAILED", "PASS"]) == "FAILED"
    assert rules_s7.compose([]) == "NOT_PROVEN"
    ok = evaluator.evaluate_scenario("G2", facts("G2"), _definition())
    assert ok["s7_result"] == "PASS" and set(ok["parts"]) == {"gate", "app_check", "required"}
    missing = evaluator.evaluate_scenario("G2", without(facts("G2"), "gate_runs"), _definition())
    assert missing["s7_result"] == "NOT_PROVEN"


@pytest.mark.parametrize("gid", ["G0", "G1", "G2", "G3", "G3S", "G4", "G5", "G6", "G10", "G11"])
def test_every_scenario_passes_when_observed_as_section_6_expects(gid: str) -> None:
    result = evaluator.evaluate_scenario(gid, facts(gid), _definition())
    assert result["s7_result"] == "PASS", [c for c in result["criteria"] if c["status"] != "PASS"]


def test_the_section_6_expectations_are_the_plan_table() -> None:
    """SCENARIO_EXPECTATIONS and SPOOF_IMPOSTOR are read against the §6 table of the committed plan."""
    from pathlib import Path

    text = (Path(__file__).resolve().parents[2] / "docs" / "v2" / "phase1" / "app-demo-plan.md").read_text(encoding="utf-8")
    rows = {cells[1]: cells for cells in ([c.strip() for c in line.split("|")] for line in text.splitlines()
                                          if line.startswith("| G")) if len(cells) > 6}
    for gid, (app, merge) in rules_s7.SCENARIO_EXPECTATIONS.items():
        assert rows[gid][4].startswith(app), gid
        assert {"mergeable": "mergeable", "clean": "CLEAN", "blocked": "BLOCKED", "mergeable_then_blocked": "MERGEABLE in W0, BLOCKED after"}[merge] == rows[gid][5], gid
    for gid in rules_s7.SPOOF_IMPOSTOR:
        assert "not required" in rows[gid][6]


def _definition() -> Dict[str, Any]:
    from iacreview.evidence import replay

    return replay.load_definition()[0]
