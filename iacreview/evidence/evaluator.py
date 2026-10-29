"""Versioned Deterministic Evaluator for the Phase 1 §7 Definition (Phase 2 M1 WP4-2, WP4-4, WP4-5).

Source: ``definitions/phase1-app-demo-s7.v1.json`` (criteria, rule ids), :mod:`iacreview.evidence.rules_s7`,
:mod:`iacreview.evidence.facts`, :mod:`iacreview.evidence.snapshot`. Purpose: produce, from fixed inputs, one
canonical result (``canonical.dumps``) per evaluation, in one of two modes:

``NATIVE_RAW_REPLAY``
    input: a :class:`~iacreview.evidence.snapshot.Snapshot` (integrity-validated, hash-bound evidence) and
    scenario bundles naming evidence ids per role. Only bound bytes are read; any change after the snapshot
    refuses the evaluation (SnapshotDrift propagates).

``LEGACY_DERIVED_REEVALUATION``
    input: a Phase 1 helper ``app-evidence`` file (E18 and siblings), the W0 views (E09) and the report
    artifacts (E17), each bound by its current SHA-256. The same rules run on the helper's transcribed facts.
    The result is a new artifact; it never replaces a Phase 1 result. Completeness and authenticity of what
    the helper captured stay NOT_PROVEN (``capture_integrity``).

``HISTORICAL_CLASSIFICATION_REFERENCE``
    the Phase 1 results quoted from the Legacy Evidence Map, attached to a legacy result *after* evaluation
    for comparison only (:func:`attach_historical_reference`). The rules never see them.

Each criterion is evaluated only by a rule whose catalog status is IMPLEMENTED; any other criterion is
NOT_PROVEN with ``rule_not_implemented``. The canonical result carries no time, no host path and no OS
information; run metadata is returned separately.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from iacreview.evidence import artifact, canonical, facts as facts_mod, open_questions, rule_s7_evidence, rules, rules_s7
from iacreview.evidence.snapshot import Snapshot

EVALUATOR_VERSION = "iacreview.evidence.evaluator/1"
RESULT_FORMAT = "iacreview.evidence.evaluation/1"
NATIVE, LEGACY, HISTORICAL = "NATIVE_RAW_REPLAY", "LEGACY_DERIVED_REEVALUATION", "HISTORICAL_CLASSIFICATION_REFERENCE"
_SOURCES = ("evaluator.py", "rules_s7.py", "open_questions.py", "rule_s7_evidence.py", "facts.py", "canonical.py", "snapshot.py",
            "artifact.py")

#: §7 parts and the criteria that make them (S7-02 composes these).
PARTS: Mapping[str, Tuple[str, ...]] = {
    "gate": ("S7-03", "S7-03b"),
    "app_check": ("S7-04", "S7-05", "S7-06", "S7-07"),
    "required": ("S7-08", "S7-09", "S7-10", "S7-14a", "S7-14b", "S7-15", "S6-G3", "S6-G3S", "S6-G6"),
    "steal": ("S7-12", "S7-13", "S7-16"),
}
#: Reporting axes (WP1 Definition axes).
AXES: Mapping[str, Tuple[str, ...]] = {
    "gate_provenance": ("S7-03", "S7-03b"), "app_check_provenance": ("S7-04", "S7-05", "S7-06", "S7-07"),
    "required_check": ("S7-08", "S7-09", "S7-14a", "S7-15", "S6-G3", "S6-G3S", "S6-G6"), "merge_blocking": ("S7-10", "S7-14b"),
    "issuer_pinning_independent_proof": ("P2-IP-01",), "g11_environment_boundary": ("S7-12", "S7-13", "S7-16", "S7-17"),
    "artifact_integrity": ("P2-AI-01", "P2-AI-02"), "evidence_recording": ("S7-01",),
}
#: S7-01 (Pre-Commit Remediation): the raw API data of the four parts must be in the verified store. The roles that
#: carry the evidence types the Definition names for S7-01 (GraphQL rollup, REST check runs, Actions run).
S7_01_ROLES = ("rollup", "check_runs", "gate_run")
PROTECTED = ("G1", "G2", "G3", "G3S", "G4", "G5", "G6", "G9", "G10", "G11")
SCENARIOS = ("G0",) + PROTECTED
NOT_RUN = ("G7",)
LIMIT_SUBJECTS = ("G8", "AC28", "admin_bypass", "same_app_with_key")


def applicable(scenario: str) -> List[str]:
    """Criteria evaluated for ``scenario`` (fixed by §6-§7)."""
    if scenario == "G0":
        return ["S7-01", "S7-03", "S7-03b", "S7-04", "S7-05", "S7-06", "S7-07", "S7-10"]
    out = ["S7-01"] + list(PARTS["gate"] + PARTS["app_check"]) + ["S7-08", "S7-09", "S7-10"]
    if scenario in rules_s7.SPOOF_SCENARIOS:
        out += ["S7-14a", "S7-14b", "S7-15", "S6-" + scenario, "P2-IP-01"]
    if scenario == "G11":
        out += ["S7-12", "S7-13", "S7-16", "S7-17", "P2-AI-01", "P2-AI-02"]
    return out


def _definition_rules(definition: Mapping[str, Any]) -> Dict[str, str]:
    return {c["criterion_id"]: c["evaluator_rule_id"] for ac in definition["acceptance_criteria"] for c in ac["criteria"]}


def evaluator_source_sha256() -> str:
    here = Path(__file__).resolve().parent
    h = hashlib.sha256()
    for name in _SOURCES:
        h.update(name.encode("ascii") + b"\0" + (here / name).read_bytes() + b"\0")
    return h.hexdigest()


ArtifactJudge = Callable[[str], Dict[str, Tuple[str, str]]]


def _judge(criterion: str, rule_id: str, facts: Mapping[str, Any], scenario: str,
           artifact_results: Mapping[str, Tuple[str, str]]) -> Tuple[str, str]:
    spec = rules.RULE_CATALOG.get(rule_id)
    if spec is None or spec.status != "IMPLEMENTED":
        return "NOT_PROVEN", "rule_not_implemented"
    if rule_id in (artifact.RULE_WHOLE_TREE, artifact.RULE_PUBLISHED):
        return artifact_results.get(criterion, ("NOT_PROVEN", "artifact_evidence_not_supplied"))
    if rule_id == rule_s7_evidence.RULE_ID:
        return artifact_results.get(criterion, ("NOT_PROVEN", "store_evidence_not_supplied"))
    fn = rules_s7.RULES.get(rule_id)
    if fn is None:
        return "NOT_PROVEN", "rule_not_implemented"
    out = fn(facts, scenario)
    return out.status, out.reason_code


def evaluate_scenario(scenario: str, facts: Mapping[str, Any], definition: Mapping[str, Any],
                      artifact_results: Optional[Mapping[str, Tuple[str, str]]] = None) -> Dict[str, Any]:
    by_criterion = _definition_rules(definition)
    results = []
    for cid in applicable(scenario):
        status, reason = _judge(cid, by_criterion[cid], facts, scenario, artifact_results or {})
        results.append({"criterion_id": cid, "rule_id": by_criterion[cid], "status": status, "reason_code": reason})
    status_of = {r["criterion_id"]: r["status"] for r in results}
    parts = {name: rules_s7.compose([status_of[c] for c in crits if c in status_of]) for name, crits in PARTS.items()
             if any(c in status_of for c in crits)}
    axes = {name: rules_s7.compose([status_of[c] for c in crits if c in status_of]) for name, crits in AXES.items()
            if any(c in status_of for c in crits)}
    s7 = rules_s7.compose(list(parts.values()))  # S7-02
    phase2 = rules_s7.compose([s7] + [axes[a] for a in ("issuer_pinning_independent_proof", "artifact_integrity") if a in axes])
    return {"scenario": scenario, "criteria": sorted(results, key=lambda r: r["criterion_id"]), "parts": parts, "axes": axes,
            "s7_result": s7, "s7_compose_rule": rules_s7.COMPOSE_RULE, "phase2_result": phase2}


def _limits(definition: Mapping[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for subject in LIMIT_SUBJECTS:
        o = rules_s7.limits_recorded({}, subject)
        out.append({"subject": subject, "criterion_id": "S7-18", "rule_id": "s7.limits.recorded_not_proven", "status": o.status,
                    "reason_code": o.reason_code})
    out += [{"subject": s, "criterion_id": None, "rule_id": None, "status": "NOT_PROVEN", "reason_code": "scenario_not_run"} for s in NOT_RUN]
    return out


def _open_questions(scenarios: Sequence[Mapping[str, Any]], facts_by_scenario: Mapping[str, Mapping[str, Any]]) -> Dict[str, Any]:
    """S7-19, judged once per evaluation from the scenario results and facts (WP5-1). NOT_PROVEN while the
    catalog does not mark the rule IMPLEMENTED."""
    spec = rules.RULE_CATALOG.get(open_questions.RULE_ID)
    if spec is None or spec.status != "IMPLEMENTED":
        return open_questions.not_implemented()
    return open_questions.open_questions_recorded(scenarios, facts_by_scenario)


def _not_implemented(definition: Mapping[str, Any]) -> List[str]:
    return sorted({c["evaluator_rule_id"] for ac in definition["acceptance_criteria"] for c in ac["criteria"]
                   if rules.RULE_CATALOG[c["evaluator_rule_id"]].status != "IMPLEMENTED"})


def _header(mode: str, definition: Mapping[str, Any], definition_sha256: str) -> Dict[str, Any]:
    return {"result_format": RESULT_FORMAT, "mode": mode,
            "definition": {"definition_id": definition["definition_id"], "definition_version": definition["definition_version"],
                           "definition_sha256": definition_sha256},
            "evaluator": {"version": EVALUATOR_VERSION, "source_sha256": evaluator_source_sha256()},
            "not_implemented_rules": _not_implemented(definition)}


# ---------------------------------------------------------------------------
# Native raw replay
# ---------------------------------------------------------------------------


def _native_artifact(bundle: Mapping[str, Any], snap: Snapshot) -> Dict[str, Tuple[str, str]]:
    roles = bundle.get("roles") or {}
    rec_ids, pub_ids = list(roles.get("artifact_record") or []), list(roles.get("published_contents") or [])
    out: Dict[str, Tuple[str, str]] = {}
    if len(rec_ids) != 1 or not snap.is_bound(rec_ids[0]):
        return out
    rec_env, rec_raw = snap.read(rec_ids[0])
    comparison = artifact.comparison_from_record(rec_raw) if rec_raw is not None else None
    if comparison is None or rec_env.get("source_type") != "LOCAL" or rec_env.get("subject_commit_sha") != comparison.commit:
        out["P2-AI-01"] = ("NOT_PROVEN", "artifact_record_unusable")
        return out
    r1 = artifact.whole_tree_matches_source(comparison)
    out["P2-AI-01"] = (r1.status, r1.reason_code)
    if len(pub_ids) == 1 and snap.is_bound(pub_ids[0]):
        pub_env, pub_raw = snap.read(pub_ids[0])
        approved = dict(comparison.file_sha256) if comparison.status == "MATCH" else {}
        r2 = artifact.judge_contents(pub_env, pub_raw, comparison, approved, (pub_ids[0],))
        out["P2-AI-02"] = (r2.status, r2.reason_code)
    return out


def _native_s7_01(bundle: Mapping[str, Any], snap: Snapshot, report: Any) -> Tuple[str, str]:
    """S7-01 for one bundle: every evidence of the required roles is bound and the WP2 rule finds it stored."""
    roles = bundle.get("roles") or {}
    missing = [r for r in S7_01_ROLES if not roles.get(r)]
    if missing:
        return "NOT_PROVEN", "required_role_missing:" + missing[0]
    ids = sorted({i for r in S7_01_ROLES for i in roles[r]})
    if not all(snap.is_bound(i) for i in ids):
        return "NOT_PROVEN", "evidence_not_bound"
    r = rule_s7_evidence.raw_api_data_stored(report, ids)
    return r.status, r.reason_code


def _bundle_ids(bundle: Mapping[str, Any]) -> List[str]:
    return sorted({i for ids in (bundle.get("roles") or {}).values() for i in ids})


def bundle_problems(bundle: Mapping[str, Any]) -> List[str]:
    problems = []
    if bundle.get("scenario") not in SCENARIOS:
        problems.append("unknown scenario {0!r}".format(bundle.get("scenario")))
    for role in (bundle.get("roles") or {}):
        if not (facts_mod.ROLE.match(role) or role in ("artifact_record", "published_contents")):
            problems.append("unknown role {0!r}".format(role))
    return problems


def native_replay(snap: Snapshot, bundles: Sequence[Mapping[str, Any]], definition: Mapping[str, Any],
                  definition_sha256: Optional[str] = None) -> Dict[str, Any]:
    """Evaluate every bundle from bound bytes only. Raises SnapshotDrift if the store changed after the snapshot, and
    ValueError if the Definition (id, version or, when given, SHA-256) differs from the one the snapshot was taken for."""
    for b in bundles:
        p = bundle_problems(b)
        if p:
            raise ValueError("; ".join(p))
    if (definition["definition_id"], definition["definition_version"]) != (snap.definition_id, snap.definition_version):
        raise ValueError("the snapshot was taken for another definition")
    if definition_sha256 is not None and definition_sha256 != snap.definition_sha256:
        raise ValueError("the definition changed after the snapshot")
    if snap.evaluator_version != EVALUATOR_VERSION:
        raise ValueError("the snapshot was taken for another evaluator version")
    scenarios = []
    facts_by: Dict[str, Mapping[str, Any]] = {}
    store_report = snap.store.verify()
    for b in sorted(bundles, key=lambda x: x["scenario"]):
        f, used = facts_mod.native_facts(b, snap.read, snap.is_bound)
        facts_by[b["scenario"]] = f
        art = _native_artifact(b, snap) if b["scenario"] == "G11" else {}
        art["S7-01"] = _native_s7_01(b, snap, store_report)
        r = evaluate_scenario(b["scenario"], f, definition, art)
        r["evidence_ids"] = sorted(set(used) | ({i for k in ("artifact_record", "published_contents")
                                                  for i in (b.get("roles") or {}).get(k, []) if snap.is_bound(i)}))
        r["unbound_evidence_ids"] = sorted(i for i in _bundle_ids(b) if not snap.is_bound(i))
        scenarios.append(r)
    result = _header(NATIVE, definition, snap.definition_sha256)
    result.update(snapshot_sha256=snap.digest, evidence=snap.binding_table(), scenarios=scenarios, limits=_limits(definition),
                  open_questions=_open_questions(scenarios, facts_by),
                  capture_integrity={"status": "PASS_FOR_BOUND_EVIDENCE", "authenticity": "NOT_PROVEN"},
                  validation={k: v for k, v in sorted(snap.validation.items())})
    return result


# ---------------------------------------------------------------------------
# Legacy derived re-evaluation
# ---------------------------------------------------------------------------


def _sha256_file(path: Path) -> Optional[str]:
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return None
    try:
        h = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            h.update(chunk)
        return h.hexdigest()
    finally:
        os.close(fd)


def _read_bound(path: Path, sha: str) -> bytes:
    data = path.read_bytes() if not path.is_symlink() else b""
    if hashlib.sha256(data).hexdigest() != sha:
        raise LegacyDrift("{0} changed after it was bound".format(path.name))
    return data


class LegacyDrift(Exception):
    """A legacy file differs from the hash it was bound to; the re-evaluation is refused."""


def legacy_reevaluation(repo_root: Path, evidence_rel: str, legacy_id: str, legacy_map: Mapping[str, Any],
                        definition: Mapping[str, Any], definition_sha256: str, w0_rel: Optional[str] = None,
                        artifacts_dir_rel: Optional[str] = None) -> Dict[str, Any]:
    """Re-evaluate one helper ``app-evidence`` file. Every file read is bound to its SHA-256 from the Legacy Map
    (when the map knows it) or to the hash taken at the start; a change during the run refuses the evaluation."""
    entries = {f["path"]: (e["legacy_evidence_id"], f["current_sha256"]) for e in legacy_map["entries"] for f in e["source_files"]}
    bound: List[Dict[str, Any]] = []

    def bind(rel: str) -> Tuple[Path, str]:
        path = repo_root / rel
        got = _sha256_file(path)
        if got is None:
            raise LegacyDrift("{0} is missing".format(rel.rsplit("/", 1)[-1]))
        known = entries.get(rel)
        if known is not None and known[1] != got:
            raise LegacyDrift("{0} differs from the Legacy Evidence Map".format(rel.rsplit("/", 1)[-1]))
        bound.append({"legacy_evidence_id": known[0] if known else None, "file": rel.rsplit("/", 1)[-1], "sha256": got})
        return path, got

    p, sha = bind(evidence_rel)
    doc = json.loads(_read_bound(p, sha).decode("utf-8"))
    w0 = None
    if w0_rel:
        wp, wsha = bind(w0_rel)
        w0 = json.loads(_read_bound(wp, wsha).decode("utf-8"))

    def digest_of(run_id: int) -> Optional[str]:
        if not artifacts_dir_rel:
            return "MISSING"
        rel = "{0}/{1}/remediation-report.json".format(artifacts_dir_rel, run_id)
        if _sha256_file(repo_root / rel) is None:
            return "MISSING"
        ap, asha = bind(rel)
        return facts_mod.report_payload_digest(_read_bound(ap, asha))

    app_id = int(doc["app_id"])
    rows = doc.get("scenarios") or {}
    scenarios = []
    facts_by: Dict[str, Mapping[str, Any]] = {}
    for scenario in SCENARIOS:
        f = facts_mod.legacy_facts(scenario, rows.get(scenario) or {}, app_id, doc.get("effective_rules_main"), w0, digest_of)
        facts_by[scenario] = f
        # S7-01: the helper kept transcribed fields, not the raw API responses (Legacy Map: RAW_UNAVAILABLE).
        scenarios.append(evaluate_scenario(scenario, f, definition, {"S7-01": ("NOT_PROVEN", "raw_unavailable")}))
    result = _header(LEGACY, definition, definition_sha256)
    result.update(legacy_evidence_id=legacy_id, evidence=sorted(bound, key=lambda b: (str(b["legacy_evidence_id"]), b["file"])),
                  scenarios=scenarios, limits=_limits(definition), open_questions=_open_questions(scenarios, facts_by),
                  capture_integrity={"status": "NOT_PROVEN", "raw_api_response": "RAW_UNAVAILABLE",
                                     "reason": "helper-transcribed fields; the GitHub responses of the time were not kept"})
    return result


def attach_historical_reference(result: Dict[str, Any], legacy_map: Mapping[str, Any]) -> Dict[str, Any]:
    """A copy of a legacy result with the Phase 1 results quoted beside it, and per-scenario differences.
    Applied after evaluation; the rules never read these values."""
    ref = {s["subject"]: s["phase1_result"] for s in legacy_map["subjects"]}
    out = json.loads(json.dumps(result))
    diffs = []
    for s in out["scenarios"]:
        historical = ref.get(s["scenario"])
        if historical is not None:
            diffs.append({"scenario": s["scenario"], "historical_phase1_result": historical, "reevaluated_s7_result": s["s7_result"],
                          "reevaluated_phase2_result": s["phase2_result"], "differs": historical != s["s7_result"],
                          "differs_phase2": historical != s["phase2_result"]})
    out["historical_classification_reference"] = {"mode": HISTORICAL, "source": "legacy map subjects (quoted from rev2 / rev3)",
                                                  "used_by_rules": False, "comparisons": sorted(diffs, key=lambda d: d["scenario"])}
    return out


def canonical_bytes(result: Mapping[str, Any]) -> bytes:
    return canonical.dumps(result)
