"""Phase 1 section 7 Definition: fidelity to the committed criterion and locked Phase 1 results (WP1-3).

Source: docs/v2/phase1/app-demo-plan.md §6-§7 (committed in 24b7a6e, unchanged
through 4bd6e01), Phase 1 final acceptance rev2 §3-1 and rev3 AC27 (quoted in
the Definition; not read here). These tests show that the Definition quotes the
criterion exactly and completely and keeps the Phase 1 results. They do not
show that any evaluator rule behaves as defined: the rule_behaviour tests named
by the Definition do that (all implemented since WP5).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

from iacreview.evidence import registry, rules

ROOT = Path(__file__).resolve().parents[2]
DEFINITION = ROOT / "iacreview" / "evidence" / "definitions" / "phase1-app-demo-s7.v1.json"
SPOOF = ("G3", "G3S", "G6")


@pytest.fixture(scope="module")
def doc() -> Dict[str, Any]:
    return registry.load_definition(DEFINITION, ROOT)


def criteria(d: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [c for ac in d["acceptance_criteria"] for c in ac["criteria"]]


def test_every_historical_clause_occurs_once_in_the_worktree_section(doc: Dict[str, Any]) -> None:
    """The working-tree file is byte-identical to a verified commit, and section 7 is fully quoted."""
    sections, problems = registry.worktree_sections(doc, ROOT)
    assert problems == []
    assert set(sections) == {"app-demo-plan-s7", "app-demo-plan-s6"}
    assert registry.clause_problems(doc, sections) == []


def test_every_historical_clause_occurs_once_at_every_verified_commit(doc: Dict[str, Any]) -> None:
    """Against git history: recorded blob ids, the section, and every quote at each verified commit."""
    problems, unavailable = registry.git_source_problems(doc, ROOT)
    assert problems == []
    commits = {c for s in doc["historical_sources"] for c in s["verified_commits"]}
    if unavailable and set(unavailable) == commits:
        pytest.skip("NOT VERIFIED: the verified commits are not in this (shallow) clone; the worktree test still ran")
    assert unavailable == [], "some verified commits are missing locally: {0}".format(unavailable)


def test_g3_g3s_g6_historical_classification_is_locked(doc: Dict[str, Any]) -> None:
    locked = {(e["subject"], e["axis"]): e["status"] for e in doc["phase1_locked_classifications"]}
    for g in SPOOF:
        assert locked[(g, "required_check")] == "FAILED"
        assert locked[(g, "merge_blocking")] == "PASS"
        assert locked[(g, "issuer_pinning_independent_proof")] == "NOT_PROVEN"
    by_axis: Dict[str, Dict[str, set]] = {}
    for ac in doc["acceptance_criteria"]:
        for c in ac["criteria"]:
            for h in c["historical_classification"]:
                if h["subject"] in SPOOF:
                    by_axis.setdefault(ac["axis"], {}).setdefault(h["subject"], set()).add(h["status"])
    assert by_axis["required_check"] == {g: {"FAILED"} for g in SPOOF}
    assert by_axis["merge_blocking"] == {g: {"PASS"} for g in SPOOF}
    assert by_axis["issuer_pinning_independent_proof"] == {g: {"NOT_PROVEN"} for g in SPOOF}
    assert by_axis["scenario_composition"] == {g: {"FAILED"} for g in SPOOF}
    assert doc["phase1_final_results"]["scenarios"]["G3"] == "FAILED"


def test_phase2_added_criteria_cite_no_phase1_commit(doc: Dict[str, Any]) -> None:
    sources = {s["source_id"]: s for s in doc["historical_sources"]}
    added = [c for c in criteria(doc) if c["origin"] == "phase2_added"]
    assert {c["criterion_id"] for c in added} == {"P2-IP-01", "P2-AI-01", "P2-AI-02"}
    for c in added:
        src = sources[c["source_id"]]
        assert src["kind"] == "phase2_document" and src["commit"] is None and src["verified_commits"] == []


def test_the_seven_required_axes_are_held_separately(doc: Dict[str, Any]) -> None:
    axes = [ac["axis"] for ac in doc["acceptance_criteria"]]
    for axis in ("gate_provenance", "app_check_provenance", "required_check", "merge_blocking",
                 "issuer_pinning_independent_proof", "g11_environment_boundary", "artifact_integrity"):
        assert axes.count(axis) == 1, axis


def test_phase1_final_results_are_quoted_unchanged(doc: Dict[str, Any]) -> None:
    final = doc["phase1_final_results"]
    assert final["scenario_counts"] == {"PASS": 8, "FAILED": 3, "PARTIAL": 1, "NOT_PROVEN": 3}
    assert final["ac_rev3_counts"] == {"PASS": 40, "PARTIAL": 4, "FAILED": 1, "NOT_PROVEN": 3}
    assert {k: final["scenarios"][k] for k in ("G11", "G11b", "G12")} == {"G11": "NOT_PROVEN", "G11b": "PASS", "G12": "PARTIAL"}


def test_the_definition_is_marked_as_written_in_phase2_with_an_unknown_helper_version(doc: Dict[str, Any]) -> None:
    origin = doc["machine_readable_origin"]
    assert origin["committed_in_phase1"] is False and origin["created_by_work_package"] == "WP1"
    assert doc["historical_evaluator"]["version_at_evidence_time"] == "UNKNOWN"
    assert doc["historical_evaluator"]["public"] is False


def test_every_s7_clause_maps_to_one_catalog_rule_and_a_rule_test_matching_its_status(doc: Dict[str, Any]) -> None:
    """M1-02: the correspondence is complete. Every rule is implemented with an implemented rule test (WP5 state;
    in WP4, S7-19's rule and rule test were PLANNED)."""
    ids = [c["criterion_id"] for c in criteria(doc)]
    for n in ("01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "12", "13", "15", "16", "17", "18", "19"):
        assert "S7-" + n in ids
    assert {"S7-03b", "S7-14a", "S7-14b", "S6-G3", "S6-G3S", "S6-G6"} <= set(ids)
    used = {c["evaluator_rule_id"] for c in criteria(doc)}
    assert used == set(rules.RULE_CATALOG)
    for c in criteria(doc):
        behaviour = [t for t in c["tests"] if t["kind"] == "rule_behaviour"]
        spec = rules.RULE_CATALOG[c["evaluator_rule_id"]]
        assert spec.status == "IMPLEMENTED" and [t["status"] for t in behaviour] == ["IMPLEMENTED"], c["criterion_id"]


def test_the_known_helper_divergences_are_recorded(doc: Dict[str, Any]) -> None:
    alignment = {c["criterion_id"]: c["historical_implementation"]["alignment"] for c in criteria(doc)}
    assert alignment["S7-08"] == alignment["S7-09"] == alignment["S7-15"] == "NOT_IMPLEMENTED"
    assert alignment["S7-01"] == alignment["S7-02"] == alignment["S7-14a"] == "DIVERGENT"
    assert alignment["S7-03"] == alignment["S7-10"] == "PARTIAL_DEFAULTS"


def test_the_definition_file_is_canonical_utf8_json() -> None:
    data = DEFINITION.read_bytes()
    assert data == (json.dumps(json.loads(data), indent=2, ensure_ascii=False) + "\n").encode("utf-8")
