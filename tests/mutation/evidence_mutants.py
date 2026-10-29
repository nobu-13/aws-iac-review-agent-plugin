"""Mutation harness for the evidence foundation (Phase 2 M1 WP4-6, WP5-5, M1-03). Not a test module.

    python3 tests/mutation/evidence_mutants.py [--json OUT]

For each mutant: copy the plugin's ``iacreview/``, the evidence tests and the files they read into a fresh
temporary directory, apply the mutant's text edits to the *copy* (the work tree is never changed), run the
mutant's kill tests there with pytest, and record whether they failed (killed). A baseline run of every
kill test on the unmutated copy must pass first; otherwise the harness reports an error, not a kill.

Each edit must match its source text exactly once, so a mutant can never silently apply to nothing.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[2]
EV = "iacreview/evidence/"
U = "tests/unit/"


@dataclass(frozen=True)
class Mutant:
    mutant_id: str
    condition: str
    edits: Tuple[Tuple[str, str, str], ...]  # (file, exact old text, new text)
    kill_tests: Tuple[str, ...]
    expected_failure: str


MUTANTS: Tuple[Mutant, ...] = (
    Mutant("MU-01", "an impostor with isRequired = true is PASS for S7-08",
           ((EV + "rules_s7.py",
             '    _, impostors, unknown = split\n    if any(c.get("is_required") is True for c in impostors):\n        return FAILED("impostor_is_required")\n    if unknown:\n        return MISSING("context_origin_unknown")\n    if any(c.get("is_required") is None for c in impostors):\n        return MISSING("impostor_is_required_missing")\n    return PASS("impostors_not_required"',
             '    _, impostors, unknown = split\n    if any(c.get("is_required") is True for c in impostors):\n        return PASS("impostor_is_required")\n    if unknown:\n        return MISSING("context_origin_unknown")\n    if any(c.get("is_required") is None for c in impostors):\n        return MISSING("impostor_is_required_missing")\n    return PASS("impostors_not_required"'),),
           (U + "test_evidence_evaluator_s7.py::test_s7_required_impostor_not_required",),
           "G3 with impostor isRequired = true must be FAILED; the mutant gives PASS"),
    Mutant("MU-02", "the App check's isRequired is ignored (S7-09)",
           ((EV + "rules_s7.py", '    if value is False:\n        return FAILED("app_check_not_required")', '    if False:\n        return FAILED("app_check_not_required")'),),
           (U + "test_evidence_evaluator_s7.py::test_s7_required_app_check_required",),
           "app_required=False must be FAILED"),
    Mutant("MU-03", "Merge Blocking by an App failure counts as an issuer-pinning PASS",
           ((EV + "rules_s7.py", '    if "failure" in app_states:\n        return MISSING("app_failure_explains_block")',
             '    if "failure" in app_states and facts.get("merge_state") == "BLOCKED":\n        return PASS("blocked")'),),
           (U + "test_evidence_evaluator_s7.py::test_phase2_issuer_pinning_independent_proof",),
           "G3 with an App failure must stay NOT_PROVEN for P2-IP-01"),
    Mutant("MU-04", "missing evidence is PASS",
           ((EV + "rules_s7.py", 'def MISSING(reason: str) -> Outcome:\n    return Outcome("NOT_PROVEN", reason)',
             'def MISSING(reason: str) -> Outcome:\n    return Outcome("PASS", reason)'),),
           (U + "test_evidence_evaluator_s7.py::test_s7_required_app_check_required", U + "test_evidence_evaluator_s7.py::test_s7_compose_all_parts"),
           "absent App check / missing gate runs must be NOT_PROVEN"),
    Mutant("MU-05", "the Source App id comparison is disabled (every check run is the App's)",
           ((EV + "rules_s7.py", '            r["origin"] = "app" if rest_app == app_id else "other_app"', '            r["origin"] = "app"'),),
           (U + "test_evidence_evaluator_s7.py::test_s7_required_impostor_not_required",),
           "the GitHub Actions impostor must not be taken for the App"),
    Mutant("MU-06", "the Head SHA comparison of the gate run is disabled",
           ((EV + "rules_s7.py", '    chosen = [r for r in runs if r.get("run_head_sha") == head and r.get("status") == "completed"]',
             '    chosen = [r for r in runs if r.get("status") == "completed"]'),
            (EV + "rules_s7.py", '"run_head_sha": None if run.get("run_head_sha") is None or head is None else run["run_head_sha"] == head,',
             '"run_head_sha": True,')),
           (U + "test_evidence_evaluator_s7.py::test_s7_gate_base_gate_provenance",),
           "a gate run on another head must not be the base gate (NOT_PROVEN)"),
    Mutant("MU-07", "the gate workflow provenance (event, path) is disabled",
           ((EV + "rules_s7.py", '"event": None if run.get("event") is None else run.get("event") == "pull_request_target",', '"event": True,'),
            (EV + "rules_s7.py", '"workflow_path": None if run.get("workflow_path") is None else str(run["workflow_path"]).startswith(GATE_PATH),',
             '"workflow_path": True,')),
           (U + "test_evidence_evaluator_s7.py::test_s7_gate_base_gate_provenance",),
           "a pull_request event or another workflow path must be FAILED"),
    Mutant("MU-08", "the manifest hash binding is not checked",
           ((EV + "snapshot.py", "            if manifest is None or env.sha256_hex(manifest) != b.manifest_sha256:", "            if False:"),),
           (U + "test_evidence_replay.py::test_a_manifest_changed_after_the_snapshot_refuses_the_evaluation",),
           "a manifest edited after the snapshot must refuse the read"),
    Mutant("MU-09", "the raw content hash binding is not checked",
           ((EV + "snapshot.py", "                if raw is None or env.sha256_hex(raw) != b.raw_sha256:", "                if False:"),),
           (U + "test_evidence_replay.py::test_raw_changed_after_the_snapshot_refuses_the_evaluation",),
           "a raw file edited after the snapshot must refuse the evaluation"),
    Mutant("MU-10", "the snapshot / revision binding is disabled (unbound ids are read from the store)",
           ((EV + "snapshot.py", "        return evidence_id in self.bindings", "        return True"),
            (EV + "snapshot.py",
             '        b = self.bindings.get(evidence_id)\n        if b is None:\n            raise SnapshotDrift("evidence {0} is not bound in this snapshot".format(evidence_id))',
             '        b = self.bindings.get(evidence_id)\n        if b is None:\n            rev, e = self.store.verify().find(evidence_id)  # type: ignore[misc]\n'
             '            entry = next(x for x in rev.manifest["entries"] if x["evidence_id"] == evidence_id)\n'
             '            b = Binding(evidence_id, rev.revision_id, e["raw_content_sha256"], entry["envelope_sha256"], str(rev.manifest_sha256),'
             ' e["subject_commit_sha"], e["source_type"])')),
           (U + "test_evidence_replay.py::test_an_unbound_evidence_id_is_never_read",),
           "evidence whose group did not validate must not be read"),
    Mutant("MU-11", "the evaluation result carries the run time",
           ((EV + "evaluator.py", "    result.update(snapshot_sha256=snap.digest,",
             "    import datetime as _dt\n    result['replay_clock'] = _dt.datetime.now(_dt.timezone.utc).strftime('%H%M%S%f')\n"
             "    result.update(snapshot_sha256=snap.digest,"),),
           (U + "test_evidence_replay.py::test_two_runs_give_identical_bytes",),
           "two runs must give identical bytes"),
    Mutant("MU-12", "the Legacy historical classification is used as the evaluator result",
           ((EV + "evaluator.py", '        scenarios.append(evaluate_scenario(scenario, f, definition, {"S7-01": ("NOT_PROVEN", "raw_unavailable")}))',
             '        _r = evaluate_scenario(scenario, f, definition, {"S7-01": ("NOT_PROVEN", "raw_unavailable")})\n'
             "        _h = {s['subject']: s['phase1_result'] for s in legacy_map['subjects']}\n"
             "        _r['s7_result'] = _h.get(scenario, _r['s7_result'])\n"
             "        scenarios.append(_r)"),),
           (U + "test_evidence_legacy_reeval.py::test_the_historical_classification_is_never_the_evaluator_result",),
           "the re-evaluation must show its own result and report the difference"),
    # --- WP5-5: fail-closed conditions of the collector, the secret gate, the integrity validator, the replay
    # comparison and the rule catalog. Detection rates below are for this mutant set only.
    Mutant("MU-13", "secret detection disabled (a matched rule is not reported)",
           ((EV + "secretgate.py", "    if findings:\n        return ScanResult(DETECTED", "    if False:\n        return ScanResult(DETECTED"),),
           (U + "test_evidence_secretgate.py::test_each_canary_shape_is_detected_and_never_echoed",
            U + "test_evidence_pipeline.py::test_a_secret_in_a_capture_never_reaches_the_store"),
           "a token-shaped value must be DETECTED and the page refused"),
    Mutant("MU-14", "the collector's security gate is bypassed (no page is scanned before it is kept)",
           ((EV + "collector.py", 'refusal = _gate(record, page["raw"], self.max_page_bytes)', "refusal = None"),),
           (U + "test_evidence_collector.py::test_a_secret_in_a_page_is_refused_and_the_capture_is_incomplete",
            U + "test_evidence_pipeline.py::test_a_secret_in_a_capture_never_reaches_the_store"),
           "a page with a secret must be refused, not kept"),
    Mutant("MU-15", "an unfinished pagination is recorded as complete",
           ((EV + "collector.py", 'pagination_complete = not last["has_next"] and not capture_errors and not any(p["errors"] for p in pages)',
             "pagination_complete = True"),),
           (U + "test_evidence_collector.py::test_an_unfinished_pagination_is_never_complete",),
           "pages of a capture stopped at the page limit must not claim pagination_complete / COMPLETE"),
    Mutant("MU-16", "a raw content change is not detected (store manifest check and envelope check both disabled)",
           ((EV + "store.py", 'if env.sha256_hex(raw) != entry["raw_sha256"] or len(raw) != entry["raw_length"]:', "if False:"),
            (EV + "envelope.py", '            if sha256_hex(raw) != sha:\n                problems.append("raw content sha256 differs',
             '            if False:\n                problems.append("raw content sha256 differs')),
           (U + "test_evidence_integrity.py::test_one_raw_byte_changed_fails_v1",
            U + "test_evidence_pipeline.py::test_a_raw_hash_mismatch_before_the_replay_is_refused"),
           "a changed raw byte must fail V1 and make the replay refuse"),
    Mutant("MU-17", "a broken revision chain is not detected (previous manifest hash not compared)",
           ((EV + "store.py", 'if previous.manifest_sha256 is None or m["previous_manifest_sha256"] != previous.manifest_sha256:', "if False:"),),
           (U + "test_evidence_integrity.py::test_a_broken_chain_fails_v3",),
           "a rewritten earlier manifest must fail V3 previous_manifest_sha256_mismatch"),
    Mutant("MU-18", "snapshot drift of an envelope is ignored",
           ((EV + "snapshot.py", "if env_bytes is None or env.sha256_hex(env_bytes) != b.envelope_sha256:", "if env_bytes is None:"),),
           (U + "test_evidence_replay.py::test_an_envelope_changed_after_the_snapshot_refuses_the_evaluation",),
           "an envelope changed after the snapshot must refuse the evaluation"),
    Mutant("MU-19", "the replay comparison ignores a changed snapshot",
           ((EV + "replay.py", '    if json.loads(out.decode("ascii")).get("snapshot_sha256") != exp.get("snapshot_sha256"):\n        raise ReplayMismatch("SNAPSHOT_CHANGED")',
             '    if False:\n        raise ReplayMismatch("SNAPSHOT_CHANGED")'),),
           (U + "test_evidence_pipeline.py::test_an_incomplete_revision_is_refused",
            U + "test_evidence_pipeline.py::test_missing_evidence_is_refused_and_never_pass"),
           "an incomplete revision or missing evidence must be refused as SNAPSHOT_CHANGED"),
    Mutant("MU-20", "an unimplemented rule is judged PASS",
           ((EV + "evaluator.py", '    if spec is None or spec.status != "IMPLEMENTED":\n        return "NOT_PROVEN", "rule_not_implemented"',
             '    if spec is None or spec.status != "IMPLEMENTED":\n        return "PASS", "rule_not_implemented"'),),
           (U + "test_evidence_pipeline.py::test_an_unimplemented_rule_never_passes",),
           "a criterion whose rule is not implemented must be NOT_PROVEN rule_not_implemented"),
    Mutant("MU-21", "S7-19: a question with no evidence is recorded as answered",
           ((EV + "open_questions.py", '    return NOT_RUN, None, "user_installations_not_captured", []',
             '    return SATISFIED, "yes", "user_installations_not_captured", []'),),
           (U + "test_evidence_report.py::test_s7_open_questions_recorded",),
           "Q3 (no evidence role) must stay NOT_RUN and S7-19 NOT_PROVEN"),
    Mutant("MU-22", "S7-19: the catalog status is not consulted (a registered rule answers by itself)",
           ((EV + "evaluator.py", '    if spec is None or spec.status != "IMPLEMENTED":\n        return open_questions.not_implemented()\n',
             ''),),
           (U + "test_evidence_report.py::test_registration_alone_is_not_an_answer",),
           "with the rule not IMPLEMENTED the record must be rule_not_implemented"),
    # --- WP5-5: the WP0 fixed mutants (m1-acceptance-test-matrix.md, "削除は不可") that MU-01..12 did not carry.
    Mutant("MU-23", "WP0 MU-04: composition prefers NOT_PROVEN over FAILED (S7-02)",
           ((EV + "rules_s7.py", '    if "FAILED" in statuses:\n        return "FAILED"\n    if statuses and all(',
             '    if "NOT_PROVEN" in statuses:\n        return "NOT_PROVEN"\n    if "FAILED" in statuses:\n        return "FAILED"\n    if statuses and all('),),
           (U + "test_evidence_evaluator_s7.py::test_s7_compose_all_parts",),
           "a FAILED part must make the scenario FAILED even when another part is NOT_PROVEN"),
    Mutant("MU-24", "WP0 MU-11: composition returns PARTIAL for a mixed scenario",
           ((EV + "rules_s7.py", '        return "PASS"\n    return "NOT_PROVEN"\n\n\nRULES:', '        return "PASS"\n    return "PARTIAL" if "PASS" in statuses else "NOT_PROVEN"\n\n\nRULES:'),),
           (U + "test_evidence_evaluator_s7.py::test_s7_compose_all_parts",),
           "PASS + NOT_PROVEN must compose to NOT_PROVEN; PARTIAL is not a §7 result"),
    Mutant("MU-25", "WP0 MU-12: two same-named App checks on the head are PASS (S7-04)",
           ((EV + "rules_s7.py", '    if len(on_head) == 1:\n        return PASS("one_app_check")', '    if len(on_head) >= 1:\n        return PASS("one_app_check")'),),
           (U + "test_evidence_evaluator_s7.py::test_s7_app_check_exactly_one_app_check",),
           "two App checks on the head must be FAILED several_app_checks"),
    Mutant("MU-26", "WP0 MU-10: HUMAN provenance satisfies an API requirement (V7)",
           ((EV + "integrity.py", '    wrong = sorted(eid for eid, e in located.items() if e["source_type"] != req.source_type)',
             '    wrong = []  # type: ignore[var-annotated]'),),
           (U + "test_evidence_integrity.py::test_the_wrong_provenance_is_not_proven_v7",),
           "HUMAN evidence must be NOT_PROVEN source_type_not_api for an API requirement"),
    Mutant("MU-27", "WP0 MU-02: an impostor with isRequired = true makes S7-15 NOT_PROVEN instead of FAILED",
           ((EV + "rules_s7.py", '    """S7-15: if GitHub reports isRequired = true for an impostor, the scenario is FAILED."""\n    split = _split(facts)\n'
             '    if split is None:\n        return MISSING("rollup_or_check_source_missing")\n    _, impostors, unknown = split\n'
             '    if any(c.get("is_required") is True for c in impostors):\n        return FAILED("impostor_is_required")',
             '    """S7-15: if GitHub reports isRequired = true for an impostor, the scenario is FAILED."""\n    split = _split(facts)\n'
             '    if split is None:\n        return MISSING("rollup_or_check_source_missing")\n    _, impostors, unknown = split\n'
             '    if any(c.get("is_required") is True for c in impostors):\n        return MISSING("impostor_is_required")'),),
           (U + "test_evidence_evaluator_s7.py::test_s7_required_impostor_required_fails_scenario",),
           "S7-15 must be FAILED for an impostor with isRequired = true"),
    Mutant("MU-28", "WP0 MU-05: a missing gate fact is defaulted to true (token_permissions, log facts such as validator_checked_out)",
           ((EV + "rules_s7.py", "        return v if isinstance(v, bool) else None", "        return v if isinstance(v, bool) else True"),
            (EV + "rules_s7.py", '"token_permissions": None if not isinstance(perms, list) else perms == TOKEN_PERMISSIONS,',
             '"token_permissions": True if not isinstance(perms, list) else perms == TOKEN_PERMISSIONS,')),
           (U + "test_evidence_evaluator_s7.py::test_s7_gate_base_gate_provenance",),
           "a gate run whose token permissions were not observed must be NOT_PROVEN"),
    Mutant("MU-29", "WP0 MU-06: effective rules not read (None) do not stop the issuer-pinning proof",
           ((EV + "rules_s7.py", '    if facts.get("rules_main") is None:\n        return MISSING("effective_rules_missing")\n', ""),),
           (U + "test_evidence_evaluator_s7.py::test_phase2_issuer_pinning_independent_proof",),
           "P2-IP-01 without the effective rules must be NOT_PROVEN"),
    # --- Pre-Commit Remediation: Definition / rule outcome agreement and S7-01 in the Final Report.
    Mutant("MU-30", "the registry does not compare expected_result with the rule's reachable outcomes",
           ((EV + "registry.py", "    problems += _check_reachable_outcomes(doc)\n", ""),),
           (U + "test_evidence_rule_outcomes.py::test_an_intentional_mismatch_is_refused",),
           "violated = FAILED for S7-19 (unreachable) must be refused"),
    Mutant("MU-31", "an empty S7-01 set is PASS in the Final Report",
           ((EV + "final_report.py", '    return "PASS" if statuses and all(x == "PASS" for x in statuses) else "NOT_PROVEN"',
             '    return "PASS" if all(x == "PASS" for x in statuses) else "NOT_PROVEN"'),),
           (U + "test_evidence_report.py::test_an_empty_s7_01_set_is_never_pass",),
           "S7-01 evaluated for no scenario must be NOT_PROVEN"),
    Mutant("MU-32", "S7-01 uses evidence that is not bound in the snapshot",
           ((EV + "evaluator.py", "    if not all(snap.is_bound(i) for i in ids):", "    if False:"),),
           (U + "test_evidence_pipeline.py::test_an_incomplete_revision_is_refused",),
           "evidence of a revision that did not validate must make S7-01 NOT_PROVEN evidence_not_bound"),
)

COPY = ("iacreview", "tests/unit", "tests/conftest.py", "tests/fixtures/evidence_raw", "docs/v2/phase1/app-demo-plan.md",
        "pyproject.toml", ".github/scripts/scan_secrets.py")


def _copy_tree(dest: Path) -> None:
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache", ".mypy_cache")
    for rel in COPY:
        src, dst = ROOT / rel, dest / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            shutil.copytree(str(src), str(dst), ignore=ignore)
        else:
            shutil.copyfile(str(src), str(dst))
    results = ROOT / "docs/v2/phase2/m1/wp5/legacy-reevaluation-results.json"
    if results.is_file():
        (dest / "docs/v2/phase2/m1/wp5").mkdir(parents=True, exist_ok=True)
        shutil.copyfile(str(results), str(dest / "docs/v2/phase2/m1/wp5/legacy-reevaluation-results.json"))


def edit_problems(m: Mutant, root: Path = ROOT) -> List[str]:
    out = []
    for f, old, _ in m.edits:
        n = (root / f).read_text(encoding="utf-8").count(old)
        if n != 1:
            out.append("{0}: edit in {1} matches {2} times".format(m.mutant_id, f, n))
    return out


def _apply(m: Mutant, root: Path) -> None:
    for f, old, new in m.edits:
        p = root / f
        text = p.read_text(encoding="utf-8")
        assert text.count(old) == 1, (m.mutant_id, f)
        p.write_text(text.replace(old, new, 1), encoding="utf-8")


def _pytest(root: Path, tests: Sequence[str]) -> Tuple[int, str, str]:
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(root))
    env.pop("COV_CORE_SOURCE", None)
    done = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", "-p", "no:warnings", "--no-header",
                           "-o", "addopts=", *tests], cwd=str(root), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    lines = done.stdout.decode("utf-8", "replace").strip().splitlines()
    first_e = next((ln.strip() for ln in lines if ln.startswith("E ")), "")
    return done.returncode, (lines[-1] if lines else ""), first_e[:200]


def run(mutants: Sequence[Mutant] = MUTANTS) -> Dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="evidence-mutants-") as tmp:
        base = Path(tmp) / "baseline"
        _copy_tree(base)
        all_tests = sorted({t for m in mutants for t in m.kill_tests})
        code, summary, _ = _pytest(base, all_tests)
        rows = []
        for m in mutants:
            work = Path(tmp) / m.mutant_id
            _copy_tree(work)
            problems = edit_problems(m, work)
            if problems:
                rows.append({"mutant_id": m.mutant_id, "condition": m.condition, "kill_tests": list(m.kill_tests),
                             "expected_failure": m.expected_failure, "exit_code": None, "result": "; ".join(problems), "failure": "",
                             "killed": False})
                continue
            _apply(m, work)
            rc, tail, first_e = _pytest(work, m.kill_tests)
            # Killed only by a failing assertion (exit 1 with an AssertionError line), not by an import or syntax error.
            killed = rc == 1 and ("assert" in first_e.lower() or "SnapshotDrift" in first_e or "DID NOT RAISE" in first_e)
            rows.append({"mutant_id": m.mutant_id, "condition": m.condition, "kill_tests": list(m.kill_tests),
                         "expected_failure": m.expected_failure, "exit_code": rc, "result": tail, "failure": first_e, "killed": killed})
            shutil.rmtree(str(work))
    return {"baseline": {"exit_code": code, "result": summary, "tests": all_tests}, "mutants": rows,
            "killed": sum(1 for r in rows if r["killed"]), "total": len(rows)}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", default=None)
    args = parser.parse_args(argv)
    result = run()
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.json:
        Path(args.json).write_text(text, encoding="utf-8")
    sys.stdout.write(text)
    ok = result["baseline"]["exit_code"] == 0 and result["killed"] == result["total"]
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
