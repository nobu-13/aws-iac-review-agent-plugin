"""End-to-end replay integration on synthetic raw evidence (Phase 2 M1 WP5-4).

Path under test:

    Capture (collector, fake transport) → Security Gate (secretgate, inside the collector)
    → Immutable Store → Integrity Validator → Verified Snapshot → Evaluator → Offline Replay → Final Report

Every answer is synthetic (``evidence_synth.py``); nothing reaches GitHub. These tests show the path for synthetic
raw only. They do not show that real GitHub answers would be judged the same way (NOT_PROVEN, not captured).
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest

import evidence_synth as syn
from iacreview.evidence import collector, evaluator, final_report, replay, rules, snapshot, store

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = b"name: probe\non: [pull_request]\npermissions: {}\n"


def build(tmp_path: Path) -> Dict[str, Any]:
    b = syn.Builder(tmp_path)
    for gid in ("G0", "G1", "G2", "G3S", "G6"):
        b.add_scenario(syn.scenario_spec(gid))
    b.add_scenario(syn.scenario_spec("G3", impostor_required=True))
    g11 = syn.scenario_spec("G11")
    b.add_scenario(g11, b.add_artifact(g11["head"], {".github/workflows/probe.yml": WORKFLOW}, {".github/workflows/probe.yml": WORKFLOW}))
    return b.seal()


@pytest.fixture()
def pipeline(tmp_path: Path) -> Tuple[Dict[str, Any], bytes]:
    spec = build(tmp_path)
    return spec, replay.replay(spec)


def scen(result: Dict[str, Any], gid: str) -> Dict[str, Any]:
    return next(s for s in result["scenarios"] if s["scenario"] == gid)


def _bound_raw(spec: Dict[str, Any], gid: str, role: str) -> Path:
    eid = next(b for b in spec["bundles"] if b["scenario"] == gid)["roles"][role][0]
    st = store.EvidenceStore(Path(spec["store_root"]), Path(spec["containment_base"]))
    rev, _ = st.verify().find(eid)  # type: ignore[misc]
    return st.root / rev.revision_id / (eid + ".raw")


def _writable(path: Path) -> None:
    os.chmod(str(path.parent), 0o700)
    os.chmod(str(path), 0o600)


def _env(pythonpath: Path) -> Dict[str, str]:
    return dict(os.environ, PYTHONHASHSEED="random", PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(pythonpath))


# ---------------------------------------------------------------------------
# The whole path, and its reproducibility
# ---------------------------------------------------------------------------


def test_the_whole_path_from_capture_to_final_report(pipeline: Tuple[Dict[str, Any], bytes]) -> None:
    spec, data = pipeline
    result = json.loads(data)
    assert result["mode"] == "NATIVE_RAW_REPLAY" and result["not_implemented_rules"] == []
    assert all(v["overall_status"] == "PASS" for v in result["validation"].values())  # integrity validator
    assert scen(result, "G3")["s7_result"] == "FAILED" and scen(result, "G3")["axes"]["merge_blocking"] == "PASS"
    assert scen(result, "G11")["phase2_result"] == "PASS"
    assert result["open_questions"]["status"] == "NOT_PROVEN"
    # S7-01 (raw API data stored and verified) is judged for every scenario from the same store.
    assert {s["scenario"]: next(c["status"] for c in s["criteria"] if c["criterion_id"] == "S7-01") for s in result["scenarios"]} == \
        {g: "PASS" for g in ("G0", "G1", "G2", "G3", "G3S", "G6", "G11")}
    rep = final_report.build(data)
    assert rep["evidence_recording"]["status"] == "PASS"
    assert rep["result_sha256"] == hashlib.sha256(data).hexdigest() and rep["snapshot_sha256"] == result["snapshot_sha256"]
    assert rep["assurance"]["capture_authenticity"] == "NOT_PROVEN"


def test_the_same_input_gives_identical_result_and_report_bytes(pipeline: Tuple[Dict[str, Any], bytes]) -> None:
    spec, data = pipeline
    again = replay.verify(spec, data)
    assert again == data and final_report.report_bytes(again) == final_report.report_bytes(data)


def test_a_separate_process_reproduces_the_result_and_the_report(pipeline: Tuple[Dict[str, Any], bytes], tmp_path: Path) -> None:
    spec, data = pipeline
    (tmp_path / "spec.json").write_text(json.dumps(spec), encoding="utf-8")
    (tmp_path / "expected.json").write_bytes(data)
    done = subprocess.run([sys.executable, "-m", "iacreview.evidence.replay", "spec.json", "--expect", "expected.json"],
                          cwd=str(tmp_path), env=_env(ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    assert done.returncode == 0, done.stderr.decode()
    assert done.stdout == data
    rep = subprocess.run([sys.executable, "-m", "iacreview.evidence.final_report", "expected.json"], cwd=str(tmp_path), env=_env(ROOT),
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    assert rep.returncode == 0 and rep.stdout == final_report.report_bytes(data)


def test_the_replay_and_the_report_complete_without_network(pipeline: Tuple[Dict[str, Any], bytes],
                                                            monkeypatch: pytest.MonkeyPatch) -> None:
    spec, data = pipeline

    def refuse(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("network access")

    for name in ("socket", "create_connection", "getaddrinfo"):
        monkeypatch.setattr(socket, name, refuse)
    assert replay.verify(spec, data) == data
    assert final_report.report_bytes(data)


# ---------------------------------------------------------------------------
# Refusals
# ---------------------------------------------------------------------------


def test_a_raw_hash_mismatch_before_the_replay_is_refused(pipeline: Tuple[Dict[str, Any], bytes]) -> None:
    spec, data = pipeline
    path = _bound_raw(spec, "G3", "rollup")
    _writable(path)
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(replay.ReplayMismatch) as err:
        replay.verify(spec, data)
    assert err.value.code == "SNAPSHOT_CHANGED"
    out = json.loads(replay.replay(spec))
    assert scen(out, "G3")["s7_result"] != "PASS" and out["validation"]["G3-api"]["overall_status"] == "FAILED"


def test_a_raw_hash_mismatch_after_the_snapshot_is_refused(pipeline: Tuple[Dict[str, Any], bytes]) -> None:
    spec, _ = pipeline
    definition, dsha = replay.load_definition()
    st = store.EvidenceStore(Path(spec["store_root"]), Path(spec["containment_base"]))
    snap = snapshot.take(st, {k: (v["evidence_ids"], syn.requirement(v)) for k, v in spec["groups"].items()}, definition, dsha,
                         evaluator.EVALUATOR_VERSION)
    path = _bound_raw(spec, "G2", "check_runs")
    _writable(path)
    path.write_bytes(b"{}")
    with pytest.raises(snapshot.SnapshotDrift):
        evaluator.native_replay(snap, spec["bundles"], definition, dsha)


def test_a_source_change_is_refused(pipeline: Tuple[Dict[str, Any], bytes], tmp_path: Path) -> None:
    """A copy of the package whose rule module differs by one comment line: the result made with the original
    source is not reproduced (SOURCE_CHANGED, exit 4)."""
    spec, data = pipeline
    copy_root = tmp_path / "src-copy"
    shutil.copytree(str(ROOT / "iacreview"), str(copy_root / "iacreview"), ignore=shutil.ignore_patterns("__pycache__"))
    target = copy_root / "iacreview/evidence/rules_s7.py"
    target.write_text(target.read_text(encoding="utf-8") + "# changed\n", encoding="utf-8")
    (tmp_path / "spec.json").write_text(json.dumps(spec), encoding="utf-8")
    (tmp_path / "expected.json").write_bytes(data)
    env = _env(copy_root)
    env.pop("COV_CORE_SOURCE", None)  # the copy is not the measured source: keep pytest-cov out of this subprocess
    done = subprocess.run([sys.executable, "-m", "iacreview.evidence.replay", "spec.json", "--expect", "expected.json"],
                          cwd=str(tmp_path), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    assert done.returncode == 4 and b"SOURCE_CHANGED" in done.stderr and done.stdout == b""


def test_a_definition_change_is_refused(pipeline: Tuple[Dict[str, Any], bytes], tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    spec, data = pipeline
    doc = json.loads(replay.DEFINITION_PATH.read_text(encoding="utf-8"))
    doc["title"] = doc["title"] + " (edited)"
    edited = tmp_path / replay.DEFINITION_PATH.name
    edited.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    monkeypatch.setattr(replay, "DEFINITION_PATH", edited)
    with pytest.raises(replay.ReplayMismatch) as err:
        replay.verify(spec, data)
    assert err.value.code == "DEFINITION_CHANGED"
    # The evaluator itself refuses a Definition whose hash differs from the one the snapshot was taken for.
    definition, dsha = replay.load_definition()
    st = store.EvidenceStore(Path(spec["store_root"]), Path(spec["containment_base"]))
    snap = snapshot.take(st, {k: (v["evidence_ids"], syn.requirement(v)) for k, v in spec["groups"].items()}, definition, dsha,
                         evaluator.EVALUATOR_VERSION)
    with pytest.raises(ValueError, match="definition changed"):
        evaluator.native_replay(snap, spec["bundles"], definition, "0" * 64)


def test_missing_evidence_is_refused_and_never_pass(pipeline: Tuple[Dict[str, Any], bytes]) -> None:
    spec, data = pipeline
    path = _bound_raw(spec, "G1", "rollup")
    _writable(path)
    path.unlink()
    with pytest.raises(replay.ReplayMismatch) as err:
        replay.verify(spec, data)
    assert err.value.code == "SNAPSHOT_CHANGED"
    out = json.loads(replay.replay(spec))
    assert out["validation"]["G1-api"]["overall_status"] == "FAILED"
    g1 = scen(out, "G1")
    assert g1["s7_result"] == "NOT_PROVEN" and all(c["status"] != "PASS" for c in g1["criteria"] if c["criterion_id"] in ("S7-08", "S7-09", "S7-10"))


def test_an_incomplete_revision_is_refused(pipeline: Tuple[Dict[str, Any], bytes]) -> None:
    spec, data = pipeline
    st = store.EvidenceStore(Path(spec["store_root"]), Path(spec["containment_base"]))
    w = st.begin_revision("interrupted")
    ev, refusal = collector.non_api_evidence("LOCAL", "cap-int-0001-l", "cap-int-0001", "interrupted write", b"x", syn.T0, syn.REPO, None)
    assert refusal is None and ev is not None
    w.add(ev)  # never sealed
    assert not st.verify().valid
    with pytest.raises(replay.ReplayMismatch) as err:
        replay.verify(spec, data)
    assert err.value.code == "SNAPSHOT_CHANGED"
    out = json.loads(replay.replay(spec))
    assert out["evidence"] == [] and all(s["s7_result"] != "PASS" for s in out["scenarios"])
    assert {next(c["reason_code"] for c in s["criteria"] if c["criterion_id"] == "S7-01") for s in out["scenarios"]} == {"evidence_not_bound"}
    assert final_report.build(replay.replay(spec))["evidence_recording"]["status"] == "NOT_PROVEN"
    assert all(v["overall_status"] != "PASS" for v in out["validation"].values())


def test_an_unimplemented_rule_never_passes(pipeline: Tuple[Dict[str, Any], bytes], monkeypatch: pytest.MonkeyPatch) -> None:
    spec, _ = pipeline
    rid = "s7.required.app_check_required"
    spec_ = rules.RULE_CATALOG[rid]
    fake = dict(rules.RULE_CATALOG)
    fake[rid] = rules.RuleSpec(rid, "PLANNED", "WP5", spec_.summary)
    monkeypatch.setattr(rules, "RULE_CATALOG", fake)
    # The registry refuses a Definition that still names an implemented rule test for a planned rule ...
    with pytest.raises(Exception, match="is PLANNED but a rule_behaviour test is IMPLEMENTED"):
        replay.load_definition()
    # ... so the Definition is made consistent (its rule test planned too) before the evaluation.
    definition = json.loads(replay.DEFINITION_PATH.read_text(encoding="utf-8"))
    for ac in definition["acceptance_criteria"]:
        for c in ac["criteria"]:
            for t in c["tests"]:
                if c["evaluator_rule_id"] == rid and t["kind"] == "rule_behaviour":
                    t.update(status="PLANNED", planned_wp="WP5")
    monkeypatch.setattr(replay, "load_definition", lambda: (definition, "d" * 64))
    data = replay.replay(spec)
    out = json.loads(data)
    assert out["not_implemented_rules"] == [rid]
    for s in out["scenarios"]:
        c = next(c for c in s["criteria"] if c["criterion_id"] == "S7-09") if s["scenario"] != "G0" else None
        if c is not None:
            assert (c["status"], c["reason_code"]) == ("NOT_PROVEN", "rule_not_implemented")
            assert s["s7_result"] != "PASS"
    assert final_report.build(data)["assurance"]["rules_implemented"] == "NOT_PROVEN"


def test_a_secret_in_a_capture_never_reaches_the_store(tmp_path: Path) -> None:
    """Security Gate stage: a page with a token-shaped value is refused by the collector and is not stored."""
    token = "gh" + "p_" + "Z9" * 18
    queue: List[collector.HttpResponse] = [collector.HttpResponse(200, {"Content-Type": "application/json"},
                                                                  json.dumps({"check_runs": [], "note": token}).encode())]
    cap = collector.Collector(lambda r: queue.pop(0), syn.REPO, now=lambda: syn.T0, id_factory=lambda: "cap-sec-0001").capture(
        "GET", "/repos/{0}/commits/{1}/check-runs?per_page=100".format(syn.REPO, "a" * 40), subject_commit_sha="a" * 40)
    assert cap.refusals and not cap.evidence and not cap.complete
    st = store.EvidenceStore(tmp_path / "evidence-store", tmp_path)
    assert not (tmp_path / "evidence-store").exists() or st.verify().revisions == []
    assert token not in repr(cap)
