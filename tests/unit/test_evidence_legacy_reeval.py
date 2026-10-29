"""Legacy Derived Re-evaluation (Phase 2 M1 WP4-5, M1-12).

Synthetic tests run everywhere. Tests on the real Phase 1 files run only where the private ``.agents/``
sources exist (a clean checkout skips them: NOT VERIFIED there) and only read them.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any, Dict

import pytest

import evidence_synth as syn
from iacreview.evidence import canonical, evaluator, legacy, legacy_reeval, replay

ROOT = Path(__file__).resolve().parents[2]
HAVE_PHASE1 = (ROOT / legacy_reeval.TARGETS[0][1]).is_file()
# WP5 output, regenerated from the final source (Pre-Commit Remediation). The WP4 result file was moved out of the
# public tree: its evaluator source and Definition hashes no longer match, so it cannot be reproduced.
RESULTS = ROOT / "docs" / "v2" / "phase2" / "m1" / "wp5" / "legacy-reevaluation-results.json"


def helper_row(gid: str, **over: Any) -> Dict[str, Any]:
    """A Phase 1 helper app-evidence row (same shape as E18) built from synthetic facts."""
    f = syn.direct_facts(syn.scenario_spec(gid, **over))
    run = f["gate_runs"][0]
    log = run["log"]
    return {"pr": 5, "head_sha": f["head_sha"], "base_sha": f["base_sha"],
            "required_view": {"merge_state": f["merge_state"], "mergeable": f["mergeable"],
                              "contexts": [{"kind": c["kind"], "name": c["name"], "check_run_id": c["check_run_id"], "app_id": c["graphql_app_id"],
                                            "state": c["state"], "is_required": c["is_required"]} for c in f["contexts"]]},
            "checks_by_head": {f["head_sha"]: f["rest_checks"]},
            "gate_runs": [{"run_id": run["run_id"], "run_attempt": run["run_attempt"], "event": run["event"], "workflow_path": run["workflow_path"],
                           "run_head_sha": run["run_head_sha"], "status": run["status"], "verify_step": run["verify_step"],
                           "failed_steps": run["failed_steps"], "publish_job": run["publish_job"],
                           "log_has_validator_pin": log["validator_pinned"], "log_validator_checked_out": log["validator_checked_out"],
                           "log_gate_scripts_pinned": log["gate_scripts_pinned"], "log_subject_is_base": log["subject_is_base"],
                           "log_head_env_is_pr_head": log["head_env_is_pr_head"], "log_has_trusted_contract": log["trusted_contract"],
                           "log_has_relaxed_contract": log["relaxed_contract"], "token_permissions": log["token_permissions"]}],
            "other_runs": []}


def write_legacy(tmp_path: Path, rows: Dict[str, Any]) -> Path:
    doc = {"app_id": syn.APP_ID, "scenarios": rows, "effective_rules_main": [], "classification": {"G3": {"status": "PROVEN"}}}
    path = tmp_path / "app-evidence.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def run_synthetic(tmp_path: Path, rows: Dict[str, Any], lmap: Dict[str, Any]) -> Dict[str, Any]:
    write_legacy(tmp_path, rows)
    definition, dsha = replay.load_definition()
    return evaluator.legacy_reevaluation(tmp_path, "app-evidence.json", "SYN", lmap, definition, dsha)


def scen(result: Dict[str, Any], gid: str) -> Dict[str, Any]:
    return next(s for s in result["scenarios"] if s["scenario"] == gid)


def test_legacy_rows_are_judged_by_the_same_rules(tmp_path: Path) -> None:
    rows = {"G3": helper_row("G3", impostor_required=True), "G2": helper_row("G2")}
    out = run_synthetic(tmp_path, rows, legacy.load_map())
    assert out["mode"] == "LEGACY_DERIVED_REEVALUATION" and out["capture_integrity"]["status"] == "NOT_PROVEN"
    assert scen(out, "G3")["s7_result"] == "FAILED" and scen(out, "G3")["axes"]["merge_blocking"] == "PASS"
    assert scen(out, "G2")["s7_result"] == "NOT_PROVEN"  # no report artifact supplied: S7-06 cannot be shown
    # S7-01 is NOT_PROVEN raw_unavailable for every legacy row (Pre-Commit Remediation; the helper kept no raw response).
    assert {c["reason_code"] for c in scen(out, "G2")["criteria"] if c["status"] != "PASS"} == {"report_artifact_missing", "raw_unavailable"}
    assert all(s["s7_result"] == "NOT_PROVEN" for s in out["scenarios"] if s["scenario"] not in rows)


def test_the_historical_classification_is_never_the_evaluator_result(tmp_path: Path) -> None:
    """The map says G3 FAILED; data where the impostor is not required gives a required axis PASS, and the
    difference is reported beside the result, not hidden."""
    lmap = legacy.load_map()
    out = run_synthetic(tmp_path, {"G3": helper_row("G3", impostor_required=False)}, lmap)
    assert scen(out, "G3")["axes"]["required_check"] == "PASS"
    attached = evaluator.attach_historical_reference(out, lmap)
    cmp = next(c for c in attached["historical_classification_reference"]["comparisons"] if c["scenario"] == "G3")
    assert cmp["historical_phase1_result"] == "FAILED" and cmp["differs"] is True
    assert attached["historical_classification_reference"]["used_by_rules"] is False
    assert "historical_classification_reference" not in out  # attaching makes a copy; the evaluation itself carries none


def test_a_legacy_file_that_differs_from_the_map_is_refused(tmp_path: Path) -> None:
    lmap = copy.deepcopy(legacy.load_map())
    lmap["entries"].append({"legacy_evidence_id": "SYN", "source_files": [{"path": "app-evidence.json", "current_sha256": "0" * 64}]})
    with pytest.raises(evaluator.LegacyDrift, match="differs from the Legacy Evidence Map"):
        run_synthetic(tmp_path, {"G2": helper_row("G2")}, lmap)


def test_a_missing_legacy_file_is_refused(tmp_path: Path) -> None:
    definition, dsha = replay.load_definition()
    with pytest.raises(evaluator.LegacyDrift, match="missing"):
        evaluator.legacy_reevaluation(tmp_path, "absent.json", "SYN", legacy.load_map(), definition, dsha)


def test_the_legacy_result_is_canonical(tmp_path: Path) -> None:
    out = run_synthetic(tmp_path, {"G3": helper_row("G3")}, legacy.load_map())
    data = canonical.dumps(out)
    assert data == canonical.dumps(json.loads(data)) and str(tmp_path) not in data.decode("ascii")


@pytest.mark.skipif(not HAVE_PHASE1, reason="NOT VERIFIED: the private Phase 1 sources are not in this checkout")
def test_the_committed_results_are_reproduced_byte_for_byte() -> None:
    assert canonical.dumps(legacy_reeval.run(ROOT)) == RESULTS.read_bytes()


def test_the_results_report_keeps_phase1_and_reports_differences() -> None:
    doc = json.loads(RESULTS.read_text(encoding="utf-8"))
    assert "Phase 1 results are unchanged" in doc["statement"]
    e18 = next(r for r in doc["results"] if r["legacy_evidence_id"] == "E18")
    by = {s["scenario"]: s for s in e18["scenarios"]}
    for gid in ("G3", "G3S", "G6"):
        assert by[gid]["s7_result"] == "FAILED" and by[gid]["axes"]["required_check"] == "FAILED"
        assert by[gid]["axes"]["merge_blocking"] == "PASS" and by[gid]["axes"]["issuer_pinning_independent_proof"] == "NOT_PROVEN"
    assert by["G11"]["s7_result"] == "PASS" and by["G11"]["phase2_result"] == "NOT_PROVEN"
    cmp = {c["scenario"]: c for c in e18["historical_classification_reference"]["comparisons"]}
    assert cmp["G11"]["differs"] is True and cmp["G11"]["differs_phase2"] is False
    assert [g for g, c in cmp.items() if c["differs"]] == ["G11"]
    assert all(r["capture_integrity"]["status"] == "NOT_PROVEN" for r in doc["results"])
    # WP5-1: S7-19 is judged and stays NOT_PROVEN (Q2 / Q3 not answerable from the helper's evidence).
    assert all(r["not_implemented_rules"] == [] and r["open_questions"]["status"] == "NOT_PROVEN" for r in doc["results"])
    assert "nobu" + "-13" not in RESULTS.read_text(encoding="utf-8")


@pytest.mark.skipif(not HAVE_PHASE1, reason="NOT VERIFIED: the private Phase 1 sources are not in this checkout")
def test_the_phase1_sources_are_unchanged_by_the_reevaluation() -> None:
    before = legacy.current_state(legacy.load_map(), ROOT)
    legacy_reeval.run(ROOT)
    after = legacy.current_state(legacy.load_map(), ROOT)
    assert before == after and after["changed"] == [] and after["missing"] == []
    assert hashlib.sha256(RESULTS.read_bytes()).hexdigest()
