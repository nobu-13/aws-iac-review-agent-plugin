"""Snapshot binding, Deterministic Offline Replay and canonical output (Phase 2 M1 WP4-1, WP4-4, M1-05).

Every store is built under tmp_path from synthetic answers. M1-05 is shown here for synthetic raw only;
an end-to-end replay of real GitHub evidence is NOT_PROVEN (not captured).
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict

import pytest

import evidence_synth as syn
from iacreview.evidence import canonical, evaluator, replay, snapshot, store
from iacreview.evidence.store import MANIFEST

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = b"name: probe\non: [pull_request]\npermissions: {}\n"


def build(tmp_path: Path, **g3: Any) -> Dict[str, Any]:
    b = syn.Builder(tmp_path)
    for gid in ("G0", "G1", "G2", "G3S", "G6"):
        b.add_scenario(syn.scenario_spec(gid))
    b.add_scenario(syn.scenario_spec("G3", **dict({"impostor_required": True}, **g3)))
    g11 = syn.scenario_spec("G11")
    extra = b.add_artifact(g11["head"], {".github/workflows/probe.yml": WORKFLOW}, {".github/workflows/probe.yml": WORKFLOW})
    b.add_scenario(g11, extra)
    return b.seal()


def take(spec: Dict[str, Any]) -> snapshot.Snapshot:
    definition, dsha = replay.load_definition()
    st = store.EvidenceStore(Path(spec["store_root"]), Path(spec["containment_base"]))
    groups = {k: (v["evidence_ids"], syn.requirement(v)) for k, v in spec["groups"].items()}
    return snapshot.take(st, groups, definition, dsha, evaluator.EVALUATOR_VERSION)


def scen(result: Dict[str, Any], gid: str) -> Dict[str, Any]:
    return next(s for s in result["scenarios"] if s["scenario"] == gid)


def test_native_replay_judges_the_synthetic_scenarios(tmp_path: Path) -> None:
    out = json.loads(replay.replay(build(tmp_path)))
    assert out["mode"] == "NATIVE_RAW_REPLAY" and out["capture_integrity"]["authenticity"] == "NOT_PROVEN"
    for gid in ("G0", "G1", "G2", "G3S", "G6"):
        assert scen(out, gid)["s7_result"] == "PASS", gid
    g3 = scen(out, "G3")
    assert g3["s7_result"] == "FAILED" and g3["axes"]["required_check"] == "FAILED" and g3["axes"]["merge_blocking"] == "PASS"
    assert g3["axes"]["issuer_pinning_independent_proof"] == "NOT_PROVEN"
    g11 = scen(out, "G11")
    assert g11["axes"]["artifact_integrity"] == "PASS" and g11["s7_result"] == "PASS"
    assert out["not_implemented_rules"] == []  # WP5-1; ["s7.open_questions.recorded"] in WP4
    assert out["open_questions"]["status"] == "NOT_PROVEN" and out["open_questions"]["criterion_id"] == "S7-19"
    assert all(v["overall_status"] == "PASS" for v in out["validation"].values())
    assert {b["evidence_id"] for b in out["evidence"]} >= set(g3["evidence_ids"])


def test_the_published_artifact_drift_is_failed(tmp_path: Path) -> None:
    b = syn.Builder(tmp_path)
    g11 = syn.scenario_spec("G11")
    extra = b.add_artifact(g11["head"], {".github/workflows/probe.yml": WORKFLOW}, {".github/workflows/probe.yml": WORKFLOW + b"# drift\n"})
    b.add_scenario(g11, extra)
    out = json.loads(replay.replay(b.seal()))
    crit = {c["criterion_id"]: c for c in scen(out, "G11")["criteria"]}
    assert crit["P2-AI-02"]["status"] == "FAILED" and scen(out, "G11")["phase2_result"] == "FAILED"


def test_two_runs_give_identical_bytes(tmp_path: Path) -> None:
    spec = build(tmp_path)
    a, b = replay.replay(spec), replay.replay(spec)
    assert a == b and hashlib.sha256(a).hexdigest() == hashlib.sha256(b).hexdigest()


def test_a_separate_process_with_a_random_hash_seed_gives_the_same_hash(tmp_path: Path) -> None:
    spec = build(tmp_path)
    here = hashlib.sha256(replay.replay(spec)).hexdigest()
    path = tmp_path / "spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    env = dict(os.environ, PYTHONHASHSEED="random", PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(ROOT))
    for _ in range(2):
        done = subprocess.run([sys.executable, "-m", "iacreview.evidence.replay", str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              cwd=str(tmp_path), env=env, check=False)
        assert done.returncode == 0, done.stderr.decode()
        assert hashlib.sha256(done.stdout).hexdigest() == here


def test_the_canonical_result_carries_no_time_path_or_host_information(tmp_path: Path) -> None:
    spec = build(tmp_path)
    data = replay.replay(spec)
    text = data.decode("ascii")
    assert data.endswith(b"\n") and text.count("\n") == 1 and data == canonical.dumps(json.loads(data))
    assert str(tmp_path) not in text and "2026-10-29" not in text and "evaluated_at" not in text
    assert canonical.problems(json.loads(data)) == []


@pytest.mark.parametrize("obj,needle", [({"evaluated_at": 1}, "run-time key"), ({"x": 1.5}, "floats"), ({"x": "/tmp/a"}, "host path"),
                                        ({"x": "C:\\a"}, "host path"), ({"x": float("nan")}, "floats"), ({"x": object()}, "unsupported")])
def test_the_canonical_serializer_refuses_what_the_specification_forbids(obj: Any, needle: str) -> None:
    with pytest.raises(canonical.CanonicalError, match=needle):
        canonical.dumps(obj)


def test_canonical_bytes_are_ascii_sorted_and_compact() -> None:
    assert canonical.dumps({"b": [2, 1], "a": "\u00e9", "c": None, "d": True}) == b'{"a":"\\u00e9","b":[2,1],"c":null,"d":true}\n'


def test_replay_never_opens_a_network_socket(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    spec = build(tmp_path)

    def refuse(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("network access during replay")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    assert replay.replay(spec)


# ---------------------------------------------------------------------------
# Binding: nothing changes after the snapshot, nothing unbound is read
# ---------------------------------------------------------------------------


def _ids(spec: Dict[str, Any], gid: str, role: str) -> str:
    return next(b for b in spec["bundles"] if b["scenario"] == gid)["roles"][role][0]


def _file(snap: snapshot.Snapshot, eid: str, name: str) -> Path:
    return snap.store.root / snap.bindings[eid].revision_id / name


def test_raw_changed_after_the_snapshot_refuses_the_evaluation(tmp_path: Path) -> None:
    spec = build(tmp_path)
    snap = take(spec)
    eid = _ids(spec, "G3", "rollup")
    path = _file(snap, eid, eid + ".raw")
    path.write_bytes(path.read_bytes().replace(b'"isRequired": true', b'"isRequired": false'))
    with pytest.raises(snapshot.SnapshotDrift, match="raw content changed"):
        evaluator.native_replay(snap, spec["bundles"], replay.load_definition()[0])


def test_a_manifest_changed_after_the_snapshot_refuses_the_evaluation(tmp_path: Path) -> None:
    spec = build(tmp_path)
    snap = take(spec)
    eid = _ids(spec, "G3", "rollup")
    path = _file(snap, eid, MANIFEST)
    m = json.loads(path.read_text())
    m["reason"] = "edited after the snapshot"
    path.write_bytes(store.manifest_bytes(m))
    with pytest.raises(snapshot.SnapshotDrift, match="manifest"):
        snap.read(eid)


def test_an_envelope_changed_after_the_snapshot_refuses_the_evaluation(tmp_path: Path) -> None:
    spec = build(tmp_path)
    snap = take(spec)
    eid = _ids(spec, "G2", "check_runs")
    path = _file(snap, eid, eid + ".envelope.json")
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(snapshot.SnapshotDrift, match="envelope"):
        snap.read(eid)


def test_a_bound_id_cannot_be_repointed_to_another_store(tmp_path: Path) -> None:
    """Same evidence ids, different (unvalidated) bytes in another store: the bound hashes refuse them."""
    spec_a = build(tmp_path / "a")
    snap = take(spec_a)
    other = build(tmp_path / "b", impostor_required=False)
    snap.store = store.EvidenceStore(Path(other["store_root"]), Path(other["containment_base"]))
    with pytest.raises(snapshot.SnapshotDrift):
        evaluator.native_replay(snap, spec_a["bundles"], replay.load_definition()[0])


def test_an_unbound_evidence_id_is_never_read(tmp_path: Path) -> None:
    """Revision binding: evidence that is in the store but not bound (its group did not validate) is not used."""
    spec = build(tmp_path)
    spec["groups"] = {k: v for k, v in spec["groups"].items() if k != "G2-api"}
    snap = take(spec)
    eid = _ids(spec, "G2", "rollup")
    assert snap.store.verify().find(eid) is not None and not snap.is_bound(eid)
    with pytest.raises(snapshot.SnapshotDrift, match="not bound"):
        snap.read(eid)
    out = evaluator.native_replay(snap, spec["bundles"], replay.load_definition()[0])
    g2 = scen(out, "G2")
    assert g2["s7_result"] == "NOT_PROVEN" and eid in g2["unbound_evidence_ids"]


def test_a_group_that_fails_validation_is_not_bound(tmp_path: Path) -> None:
    b = syn.Builder(tmp_path)
    b.add_scenario(syn.scenario_spec("G2"))
    spec = b.seal()
    spec["groups"]["G2-api"]["evidence_ids"].append("absent-0001")
    snap = take(spec)
    assert snap.validation["G2-api"]["overall_status"] == "NOT_PROVEN"
    out = evaluator.native_replay(snap, spec["bundles"], replay.load_definition()[0])
    assert scen(out, "G2")["s7_result"] == "NOT_PROVEN"


def test_a_snapshot_for_another_definition_or_evaluator_is_refused(tmp_path: Path) -> None:
    spec = build(tmp_path)
    snap = take(spec)
    definition = replay.load_definition()[0]
    snap.evaluator_version = "iacreview.evidence.evaluator/0"
    with pytest.raises(ValueError, match="evaluator version"):
        evaluator.native_replay(snap, spec["bundles"], definition)
    snap.evaluator_version = evaluator.EVALUATOR_VERSION
    snap.definition_version = 99
    with pytest.raises(ValueError, match="another definition"):
        evaluator.native_replay(snap, spec["bundles"], definition)


def test_an_unknown_role_or_scenario_is_refused(tmp_path: Path) -> None:
    spec = build(tmp_path)
    spec["bundles"][0]["roles"]["anything"] = []
    with pytest.raises(ValueError, match="unknown role"):
        replay.replay(spec)


def test_the_replay_cli_reports_drift_with_exit_3(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    spec = build(tmp_path)
    path = tmp_path / "spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    real = snapshot.take

    def take_then_tamper(*a: Any, **k: Any) -> snapshot.Snapshot:
        snap = real(*a, **k)
        eid = _ids(spec, "G3", "rollup")
        p = _file(snap, eid, eid + ".raw")
        p.write_bytes(p.read_bytes() + b" ")
        return snap

    monkeypatch.setattr(snapshot, "take", take_then_tamper)
    assert replay.main([str(path)]) == 3
    assert replay.main([str(tmp_path / "missing.json")]) == 2
