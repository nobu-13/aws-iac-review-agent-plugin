"""Mutation harness for the Remediation Evidence Chain, WP1 (Phase 2 M2, MU2-01..MU2-20). Not a test module.

    python3 tests/mutation/chain_mutants.py [--json OUT]

Same method as ``tests/mutation/evidence_mutants.py`` (M1): for each mutant, copy the plugin files the
kill tests need into a fresh temporary directory, apply the mutant's text edits to the *copy* (the work
tree is never changed), run the mutant's kill tests there and record whether they failed (killed). A
baseline run of every kill test on the unmutated copy must pass first. Each edit must match its source
exactly once. Source of the mutant list: docs/v2/phase2/m2/wp0/m2-acceptance-test-matrix.md §13.
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
C = "iacreview/chain/"
U = "tests/unit/"
M = U + "test_chain_manifest.py::"
L = U + "test_chain_links.py::"
S = U + "test_chain_status.py::"
R = U + "test_chain_replay.py::"


@dataclass(frozen=True)
class Mutant:
    mutant_id: str
    condition: str
    edits: Tuple[Tuple[str, str, str], ...]  # (file, exact old text, new text)
    kill_tests: Tuple[str, ...]
    expected_failure: str


MUTANTS: Tuple[Mutant, ...] = (
    Mutant("MU2-01", "the manifest's unknown-key check is removed",
           ((C + "manifest.py", "    if not isinstance(value, dict) or set(value) != set(keys):",
             "    if not isinstance(value, dict) or not set(keys) <= set(value):"),),
           (M + "test_tc_01_03_schema_violations_are_manifest_invalid",),
           "an unknown key at any level must be manifest_invalid"),
    Mutant("MU2-02", "the locator containment check is removed",
           ((C + "manifest.py", '    return all(seg not in (".", "..") and _SEGMENT.match(seg) is not None for seg in value.split("/"))',
             "    return True"),),
           (M + "test_tc_01_05_unsafe_locator_text_is_outside_the_root",),
           "a locator with .., an absolute path or a backslash must be locator_outside_root"),
    Mutant("MU2-03", "canonicalization keeps the input key order",
           ((C + "manifest.py", "    return hashlib.sha256(remediation_report.canonical(value)).hexdigest()",
             '    return hashlib.sha256(json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")).hexdigest()'),),
           (M + "test_tc_01_02_key_order_and_whitespace_do_not_change_the_digest",),
           "a reordered manifest must have the same digest"),
    Mutant("MU2-04", "the base -> head ancestry check is inverted",
           ((C + "links.py", "        if not gitsnap.is_ancestor(ctx.repo, base, head):", "        if gitsnap.is_ancestor(ctx.repo, base, head):"),),
           (L + "test_tc_02_01_a_correct_chain_links_subject_and_contract",
            L + "test_tc_02_02_a_head_that_does_not_descend_from_the_base_is_broken"),
           "a correct chain must link and a reversed subject must be BROKEN"),
    Mutant("MU2-05", "the contract is read from the head instead of the config commit",
           ((C + "links.py", "        entry = gitsnap.commit_snapshot(ctx.repo, config).entries.get(path)",
             '        entry = gitsnap.commit_snapshot(ctx.repo, ctx.doc["subject"]["head_commit"]).entries.get(path)'),),
           (L + "test_tc_02_08_a_contract_only_in_the_head_is_never_read",),
           "a contract present only in the head must be contract_blob_missing"),
    Mutant("MU2-06", "the contract is not compared with the verification report",
           ((C + "links.py", "    if ctx.report is not None:\n        trust = ctx.report", "    if False:\n        trust = ctx.report"),),
           (L + "test_tc_02_07_a_report_naming_another_contract_digest_is_broken",),
           "a report naming another contract digest must be contract_mismatch_with_report"),
    Mutant("MU2-07", "the verification is not recomputed (the report is trusted)",
           ((C + "links.py", "    again, unavailable = recompute(ctx)", '    again, unavailable = ctx.report["payload"], None'),),
           (L + "test_tc_03_04_a_forged_decision_with_consistent_digests_is_broken",),
           "a forged VERIFIED with consistent digests must be payload_digest_mismatch"),
    Mutant("MU2-08", "a VERIFIED decision links the verification by itself",
           ((C + "links.py", '    res.observed["execution_mode"] = payload["execution_mode"]\n',
             '    res.observed["execution_mode"] = payload["execution_mode"]\n    if payload["decision"] == "VERIFIED":\n        return res\n'),),
           (L + "test_tc_03_04_a_forged_decision_with_consistent_digests_is_broken",),
           "the decision must never raise the link status"),
    Mutant("MU2-09", "a recomputation without its tools is LINKED",
           ((C + "links.py", '    if again is None:\n        res.add("recompute_unavailable")\n        return res',
             "    if again is None:\n        return res"),),
           (L + "test_tc_03_08_a_missing_tool_makes_the_recomputation_unavailable",),
           "a missing cfn-guard must be recompute_unavailable (NOT_PROVEN)"),
    Mutant("MU2-10", "the review's errors[] is not checked",
           ((C + "links.py", "    if checked.errors:\n", "    if False:\n"),),
           (L + "test_tc_04_02_errors_next_to_the_referenced_finding_are_incomplete",),
           "a review with errors[] must be review_report_has_errors"),
    Mutant("MU2-11", "review completeness is decided by the summary's pass flag",
           ((C + "links.py", "    for code in review_evidence_complete(checked):",
             '    for code in ([] if obj["summary"].get("passed_all' + '_checks") is False else review_evidence_complete(checked)):'),),
           (L + "test_tc_04_02_errors_next_to_the_referenced_finding_are_incomplete", L + "test_tc_04_08_the_chain_never_reads_the_pass_flag"),
           "the pass flag must never be read"),
    Mutant("MU2-12", "the finding digest is not compared",
           ((C + "links.py", '        if mf.canonical_sha256(raw) != ref_f["finding_sha256"]:', "        if False:"),),
           (L + "test_tc_04_05_a_changed_finding_is_broken",),
           "a changed finding must be finding_digest_mismatch"),
    Mutant("MU2-13", "the M1 integrity result is ignored",
           ((C + "links.py", '    if result["overall_status"] != "PASS":', "    if False:"),),
           (L + "test_tc_05_02_a_changed_raw_byte_fails_the_m1_integrity",),
           "a changed raw byte must be integrity_not_pass"),
    Mutant("MU2-14", "the repository of the evidence is not compared",
           ((C + "links.py", '            if not isinstance(repo, str) or repository_id(repo) != ctx.doc["repository_id"]:', "            if False:"),),
           (L + "test_tc_05_05_evidence_of_another_repository_is_broken",),
           "evidence of another repository must be repository_mismatch"),
    Mutant("MU2-15", "INCOMPLETE and NOT_PROVEN swap priority",
           ((C + "status.py", "_RANK: Dict[str, int] = {BROKEN: 3, INCOMPLETE: 2, NOT_PROVEN: 1}",
             "_RANK: Dict[str, int] = {BROKEN: 3, INCOMPLETE: 1, NOT_PROVEN: 2}"),),
           (S + "test_tc_06_01_every_combination_of_link_statuses_composes_by_the_rule",),
           "INCOMPLETE must outrank NOT_PROVEN"),
    Mutant("MU2-16", "NOT_PRESENT counts as LINKED",
           ((C + "status.py", "        if value == LINKED:\n            continue", "        if value in (LINKED, NOT_PRESENT):\n            continue"),),
           (S + "test_tc_06_01_every_combination_of_link_statuses_composes_by_the_rule",),
           "a link that is not present must keep the chain from COMPLETE"),
    Mutant("MU2-17", "an error inside a link check passes silently",
           ((C + "validator.py", '        res = lk.LinkResult(link)\n        res.add("link_check_error")\n        return res',
             "        return lk.LinkResult(link)"),),
           (S + "test_tc_06_04_an_error_inside_a_link_check_is_never_a_pass",),
           "an exception must be link_check_error (INCOMPLETE)"),
    Mutant("MU2-18", "a VERIFIED decision hides an incomplete review in the chain status",
           ((C + "validator.py", '    statuses = {r["link"]: r["status"] for r in links}\n',
             '    statuses = {r["link"]: r["status"] for r in links}\n'
             '    if any(r.observed.get("decision") == "VERIFIED" for r in results):\n        statuses["review"] = st.LINKED\n'),),
           (S + "test_tc_06_05_a_review_with_errors_keeps_the_chain_from_complete",),
           "an incomplete review must keep the chain INCOMPLETE whatever the decision"),
    Mutant("MU2-19", "the payload carries the run time",
           ((C + "validator.py", '        "chain_status": chain,\n', '        "chain_status": chain,\n        "generated_at": repr(time.time()),\n'),),
           (R + "test_tc_07_01_four_runs_agree_and_keep_the_link_order",),
           "four runs must give the same payload digest"),
    Mutant("MU2-20", "the link order is not fixed",
           ((C + "validator.py", "    return [out[name] for name in st.LINKS]", "    return sorted(out.values(), key=lambda r: r.status)"),),
           (R + "test_tc_07_01_four_runs_agree_and_keep_the_link_order",),
           "the links must be in the fixed order"),
)

COPY = ("iacreview", "skills", "rules", "tests/unit", "tests/conftest.py", "tests/remediation_bench", "tests/fixtures/chain_replay",
        "tests/fixtures/evidence_replay", "benchmark/remediation", "plugin.json", "pyproject.toml", ".github/scripts/evidence_ci_check.py")


def _copy_tree(dest: Path) -> None:
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache", ".mypy_cache")
    for rel in COPY:
        src, dst = ROOT / rel, dest / rel
        if not src.exists():
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            shutil.copytree(str(src), str(dst), ignore=ignore, symlinks=True)
        else:
            shutil.copyfile(str(src), str(dst))


def edit_problems(m: Mutant, root: Path = ROOT) -> List[str]:
    out = []
    for f, old, _ in m.edits:
        n = (root / f).read_text(encoding="utf-8").count(old)
        if n != 1:
            out.append("{0}: {1} matches {2} times in {3}".format(m.mutant_id, old[:50], n, f))
    return out


def _apply(m: Mutant, root: Path) -> None:
    for f, old, new in m.edits:
        path = root / f
        text = path.read_text(encoding="utf-8")
        assert text.count(old) == 1, (m.mutant_id, f)
        path.write_text(text.replace(old, new), encoding="utf-8")


def _pytest(root: Path, tests: Sequence[str]) -> Tuple[int, str, str]:
    # As the M1 harness: the copy is first on the path, and the parent's coverage run does not measure the copy.
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(root))
    env.pop("COV_CORE_SOURCE", None)
    out = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-x", *tests], cwd=str(root), env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1800, check=False)
    return out.returncode, out.stdout.decode("utf-8", "replace")[-4000:], out.stderr.decode("utf-8", "replace")[-2000:]


def run(mutants: Sequence[Mutant] = MUTANTS) -> Dict[str, object]:
    tests = sorted({t for m in mutants for t in m.kill_tests})
    with tempfile.TemporaryDirectory(prefix="chain-mutants-") as tmp:
        base = Path(tmp) / "baseline"
        _copy_tree(base)
        code, out, err = _pytest(base, tests)
        result: Dict[str, object] = {"baseline": {"exit_code": code, "tests": len(tests)}, "mutants": []}
        if code != 0:
            result["baseline"]["output"] = out + err  # type: ignore[index]
            result.update(total=len(mutants), killed=0)
            return result
        records = []
        for m in mutants:
            work = Path(tmp) / m.mutant_id
            _copy_tree(work)
            _apply(m, work)
            mcode, mout, _ = _pytest(work, m.kill_tests)
            # Killed only by a failing test (exit 1), not by a crash or a collection error.
            records.append({"mutant_id": m.mutant_id, "condition": m.condition, "exit_code": mcode, "killed": mcode == 1,
                            "expected_failure": m.expected_failure})
            shutil.rmtree(str(work), ignore_errors=True)
        result["mutants"] = records
        result.update(total=len(records), killed=sum(1 for r in records if r["killed"]))
        return result


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Phase 2 M2 WP1 chain mutation harness")
    parser.add_argument("--json", help="write the result as JSON to this new file")
    args = parser.parse_args(argv)
    problems = [p for m in MUTANTS for p in edit_problems(m)]
    if problems:
        print("\n".join(problems))
        return 2
    result = run()
    text = json.dumps(result, indent=2, sort_keys=True)
    if args.json:
        with open(args.json, "x", encoding="utf-8") as handle:
            handle.write(text + "\n")
    print("baseline exit {0}; killed {1} / {2}".format(result["baseline"]["exit_code"], result["killed"], result["total"]))  # type: ignore[index]
    return 0 if result["baseline"]["exit_code"] == 0 and result["killed"] == result["total"] else 1  # type: ignore[index]


if __name__ == "__main__":
    sys.exit(main())
