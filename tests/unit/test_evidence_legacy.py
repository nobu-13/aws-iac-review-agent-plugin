"""Legacy Evidence Map: read-only traceability of the Phase 1 evidence (Phase 2 M1 WP3-2, M1-10).

The map file is public; the Phase 1 sources it names are under the private,
ignored ``.agents/`` and are absent from a clean checkout. Tests that compare
current hashes therefore run only where the sources exist and otherwise report
the sources as missing (never as present).
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Dict

import pytest

from iacreview.evidence import legacy

ROOT = Path(__file__).resolve().parents[2]
HAVE_PHASE1 = (ROOT / ".agents" / "tasks" / "phase1" / "final-acceptance").is_dir()


@pytest.fixture()
def doc() -> Dict[str, Any]:
    return json.loads(legacy.MAP_PATH.read_text(encoding="utf-8"))


def entry(d: Dict[str, Any], eid: str) -> Dict[str, Any]:
    return next(e for e in d["entries"] if e["legacy_evidence_id"] == eid)


def subject(d: Dict[str, Any], name: str) -> Dict[str, Any]:
    return next(s for s in d["subjects"] if s["subject"] == name)


def test_the_shipped_map_is_valid_and_covers_every_required_id(doc: Dict[str, Any]) -> None:
    assert legacy.map_problems(doc) == []
    ids = {e["legacy_evidence_id"] for e in doc["entries"]}
    assert legacy.REQUIRED_IDS <= ids
    assert {"E{0:02d}".format(i) for i in range(1, 41) if i != 23} <= ids and {"H01", "H02", "H03"} <= ids
    assert any(i.startswith("P1-REV2-") for i in ids) and any(i.startswith("P1-REV3-") for i in ids)


def test_the_map_is_not_a_reevaluation_and_the_helper_revision_is_unknown(doc: Dict[str, Any]) -> None:
    assert doc["is_reevaluation"] is False and doc["historical_helper_revision"] == "UNKNOWN"
    assert "not a re-evaluation" in doc["statement"] and "new observation" in doc["statement"]


def test_no_phase1_entry_claims_a_raw_api_body_or_completeness(doc: Dict[str, Any]) -> None:
    assert {e["raw_api_response"] for e in doc["entries"]} <= {"RAW_UNAVAILABLE", "RAW_FIELD_ONLY", "NOT_APPLICABLE"}
    assert entry(doc, "E18")["raw_api_response"] == "RAW_UNAVAILABLE"
    assert {e["completeness"] for e in doc["entries"]} <= {"INCOMPLETE", "SOURCE_MISSING", "NOT_CAPTURED"}
    for h in ("H01", "H02", "H03"):
        assert entry(doc, h)["source_files"] == [] and entry(doc, h)["completeness"] == "NOT_CAPTURED"


def test_entries_without_a_recorded_hash_are_historical_integrity_not_proven(doc: Dict[str, Any]) -> None:
    for e in doc["entries"]:
        if e["historical_hash"]["kind"] == "none":
            assert e["historical_hash"]["status"] == "HISTORICAL_INTEGRITY_NOT_PROVEN"
            assert "HISTORICAL_INTEGRITY_NOT_PROVEN" in e["traceability_limitations"]
    assert entry(doc, "E18")["historical_hash"]["status"] == "HISTORICAL_INTEGRITY_NOT_PROVEN"


def test_phase1_subject_results_are_kept(doc: Dict[str, Any]) -> None:
    for g in ("G3", "G3S", "G6"):
        s = subject(doc, g)
        assert s["phase1_result"] == "FAILED"
        assert s["axes"] == {"required_check": "FAILED", "merge_blocking": "PASS", "issuer_pinning_independent_proof": "NOT_PROVEN"}
    assert subject(doc, "G11")["phase1_result"] == "NOT_PROVEN" and subject(doc, "G11b")["phase1_result"] == "PASS"
    assert subject(doc, "G12")["phase1_result"] == "PARTIAL" and subject(doc, "AC27")["phase1_result"] == "FAILED"


@pytest.mark.parametrize("name,field,value", [
    ("G3", "phase1_result", "PARTIAL"), ("G3S", "phase1_result", "NOT_PROVEN"), ("G6", "phase1_result", "PASS"),
    ("G11", "phase1_result", "PASS"), ("G11b", "phase1_result", "NOT_PROVEN"), ("G12", "phase1_result", "PASS"), ("AC27", "phase1_result", "PASS"),
])
def test_altering_a_phase1_classification_is_refused(doc: Dict[str, Any], name: str, field: str, value: str) -> None:
    subject(doc, name)[field] = value
    assert any(name in p for p in legacy.map_problems(doc))


@pytest.mark.parametrize("axis,value", [("required_check", "PARTIAL"), ("merge_blocking", "FAILED"), ("issuer_pinning_independent_proof", "PASS")])
def test_altering_a_g3_axis_is_refused(doc: Dict[str, Any], axis: str, value: str) -> None:
    subject(doc, "G3")["axes"][axis] = value
    assert any("axis {0}".format(axis) in p for p in legacy.map_problems(doc))


@pytest.mark.parametrize("mutate,needle", [
    (lambda d: d.update(is_reevaluation=True), "is_reevaluation"),
    (lambda d: d.update(historical_helper_revision="493177b4"), "UNKNOWN"),
    (lambda d: entry(d, "E18").update(raw_api_response="RAW_AVAILABLE"), "raw_api_response"),
    (lambda d: entry(d, "E18").update(raw_api_response="NOT_APPLICABLE"), "RAW_UNAVAILABLE"),
    (lambda d: entry(d, "E18").update(completeness="COMPLETE"), "completeness"),
    (lambda d: entry(d, "E18")["historical_hash"].update(status="HISTORICAL_HASH_MATCHES"), "HISTORICAL_INTEGRITY_NOT_PROVEN"),
    (lambda d: entry(d, "E18")["traceability_limitations"].remove("RAW_UNAVAILABLE"), "limitation RAW_UNAVAILABLE"),
    (lambda d: entry(d, "E38")["traceability_limitations"].remove("HELPER_REVISION_UNKNOWN"), "HELPER_REVISION_UNKNOWN"),
    (lambda d: d["entries"].remove(entry(d, "E37")), "required id E37"),
    (lambda d: d["entries"].append(copy.deepcopy(entry(d, "E01"))), "duplicate id E01"),
    (lambda d: entry(d, "H02").update(source_files=[{"path": "x", "present": True, "current_sha256": "a" * 64, "size": 1}]), "human report"),
    (lambda d: subject(d, "G11")["evidence_ids"].append("E99"), "unknown evidence id E99"),
])
def test_an_altered_map_is_refused(doc: Dict[str, Any], mutate: Any, needle: str) -> None:
    mutate(doc)
    problems = legacy.map_problems(doc)
    assert any(needle in p for p in problems), problems


def test_a_source_file_recorded_as_missing_must_say_so(doc: Dict[str, Any]) -> None:
    f = entry(doc, "E01")["source_files"][0]
    f.update(present=False, current_sha256=None, size=None)
    assert any("SOURCE_MISSING" in p for p in legacy.map_problems(doc))
    entry(doc, "E01")["completeness"] = "SOURCE_MISSING"
    entry(doc, "E01")["traceability_limitations"].append("SOURCE_FILE_MISSING")
    assert legacy.map_problems(doc) == []


def test_missing_legacy_evidence_is_reported_missing_never_present(doc: Dict[str, Any], tmp_path: Path) -> None:
    """Against an empty tree every source is SOURCE_MISSING, and gap traceability is not a PASS."""
    state = legacy.current_state(doc, tmp_path)
    assert state["all_match"] is False and set(state["missing"]) == {e["legacy_evidence_id"] for e in doc["entries"] if e["source_files"]}
    summary = legacy.traceability_summary(doc, state)
    assert summary["gap_traceability"] == "NOT_PROVEN" and summary["historical_raw_reachability"] == "NOT_PROVEN"


def test_a_changed_legacy_file_is_detected(doc: Dict[str, Any], tmp_path: Path) -> None:
    e = entry(doc, "E25")
    target = tmp_path / e["source_files"][0]["path"]
    target.parent.mkdir(parents=True)
    target.write_bytes(b"not the original\n")
    state = legacy.current_state(doc, tmp_path)
    assert "E25" in state["changed"]
    assert legacy.traceability_summary(doc, state)["gap_traceability"] == "FAILED"


def test_a_symlinked_legacy_file_is_not_followed(doc: Dict[str, Any], tmp_path: Path) -> None:
    e = entry(doc, "E25")
    target = tmp_path / e["source_files"][0]["path"]
    target.parent.mkdir(parents=True)
    real = tmp_path / "elsewhere.md"
    real.write_bytes(b"x")
    target.symlink_to(real)
    assert "E25" in legacy.current_state(doc, tmp_path)["missing"]


@pytest.mark.skipif(not HAVE_PHASE1, reason="NOT VERIFIED: the private Phase 1 sources are not in this checkout")
def test_every_phase1_source_is_unchanged_since_the_map_was_made(doc: Dict[str, Any]) -> None:
    state = legacy.current_state(doc, ROOT)
    assert state["missing"] == [] and state["changed"] == [] and state["all_match"]
    summary = legacy.traceability_summary(doc, state)
    assert summary["gap_traceability"] == "PASS" and summary["historical_raw_reachability"] == "NOT_PROVEN"
    assert "E18" in summary["raw_unavailable_ids"] and sorted(summary["raw_field_only_ids"]) == ["GE-RAW-PROBE", "GE-RAW-STEAL"]


def test_the_map_names_no_account_or_absolute_path() -> None:
    text = legacy.MAP_PATH.read_text(encoding="utf-8")
    assert "/Users/" not in text and "\\\\" not in text
    owner = "nobu" + "-13"
    assert owner not in text
