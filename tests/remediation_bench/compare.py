"""A/B/C/D comparison over the Phase 1 cases (work package AC45-AC47).

    python3 tests/remediation_bench/compare.py [--only C01,C05] [--output compare.json]

The same candidate (Base, Head, tools) goes through four configurations:

A  official tools only: cfn-lint on Head has no Error, and cfn-guard with the
   profile's outcome rule passes on Head.
B  A + v1.1: ``iac-review`` (cfn-lint, cfn-guard, iam-review) on Base and Head,
   then the v1.1 Delta_Tool with every declaration made; accepted when A
   accepts, the Delta_Tool exits 0, at least one finding is Resolved and none
   is New.
C  B + Phase 1: accepted when B accepts and ``iacreview.remediation verify``
   returns VERIFIED.
D  the same contract built by hand from Guard and a small script
   (``baseline_d.py``): file scope with ``git diff --name-only``, the rest of
   the Template compared after deleting the allowed properties, Guard rules
   written against the Logical ID, cfn-lint on Head.

C is reported on its own as well (``C_only``) because B's acceptance rule
rejects a no-op (nothing Resolved) that Phase 1 accepts as already_satisfied.
Nothing here decides the ground truth: each case's class comes from
``cases.json``.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))

import casegen  # noqa: E402

PYTHON = sys.executable
OUTCOME_RULES = {
    "sc01": ROOT / "iacreview/remediation/profiles/dynamodb-billing-mode-v1/rules.guard",
    "sc02": ROOT / "iacreview/remediation/profiles/iam-inline-policy-overbroad-v1/rules.guard",
}
OUTCOME_RULE_NAME = {"sc01": "billing_mode_consistent", "sc02": "no_overbroad_allow_statement"}
TARGET_ID = {"sc01": "OrdersTable", "sc02": "IngestRole"}
DECLARATIONS = (
    "reports_unmodified",
    "same_plugin_version",
    "same_rule_set",
    "same_tool_configuration",
    "same_agent_findings_input",
    "reports_match_templates",
)


def _run(argv: List[str], env: Dict[str, str], cwd: Path, timeout: int = 300) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, env=env, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    except FileNotFoundError:  # a tool that is not installed rejects
        return subprocess.CompletedProcess(argv, 127, b"", b"")
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(argv, 124, b"", b"")


def _show(setup: casegen.Setup, rev: str, env: Dict[str, str]) -> Optional[bytes]:
    out = _run(["git", "show", "{0}:{1}".format(rev, casegen.TARGET)], env, setup.repo)
    if out.returncode != 0:
        return None
    mode = _run(["git", "ls-tree", rev, "--", casegen.TARGET], env, setup.repo).stdout.decode()
    if not mode.startswith("100644"):
        return None  # a symlink or an executable target is not read as a Template
    return out.stdout


def _a(setup: casegen.Setup, scenario: str, head: bytes, work: Path, env: Dict[str, str]) -> Dict[str, Any]:
    path = work / "head.yaml"
    path.write_bytes(head)
    lint = _run(["cfn-lint", "-f", "json", "--", str(path)], env, work)
    lint_ok = lint.returncode in (0, 4, 8, 12)
    from iacreview import template

    try:
        doc, _ = template.parse_template_text(head.decode("utf-8"), path)
        resource = doc.get("Resources", {}).get(TARGET_ID[scenario], {})
        data = {"Target": resource, "Params": {"required_statement_sid": "ReadInput"}}
        (work / "proj.json").write_text(json.dumps(data, default=str), encoding="utf-8")
    except Exception:  # noqa: BLE001 - an unparsable Head is a reject
        return {"accept": False, "lint_ok": lint_ok, "guard_ok": False}
    guard = _run(
        ["cfn-guard", "validate", "--data", str(work / "proj.json"), "--rules", str(OUTCOME_RULES[scenario]), "--output-format", "json", "--show-summary", "none"],
        env,
        work,
    )
    guard_ok = guard.returncode == 0
    if guard_ok:
        try:
            record = json.loads(guard.stdout)
            guard_ok = OUTCOME_RULE_NAME[scenario] in record.get("compliant", []) or record.get("status") == "PASS"
        except ValueError:
            guard_ok = False
    return {"accept": lint_ok and guard_ok, "lint_ok": lint_ok, "guard_ok": guard_ok}


def _b(base: bytes, head: bytes, work: Path, env: Dict[str, str]) -> Dict[str, Any]:
    """Review both sides at the same relative path, then run the Delta_Tool."""
    ws = work / "b"
    review = str(ROOT / "skills/iac-review/scripts/run_iac_review.py")
    for side, data in (("base", base), ("head", head)):
        (ws / side / "infra").mkdir(parents=True)
        (ws / side / casegen.TARGET).write_bytes(data)
        out = _run([PYTHON, review, "--target", casegen.TARGET, "--sources", "cfn-lint", "--sources", "cfn-guard", "--sources", "iam-review"], env, ws / side)
        if out.returncode != 0:
            return {"accept": False, "review_exit": out.returncode}
        (ws / (side + ".json")).write_bytes(out.stdout)
    argv = [
        PYTHON, "-m", "iacreview.deltacli",
        "--base-template", "base/" + casegen.TARGET, "--head-template", "head/" + casegen.TARGET,
        "--base-report", "base.json", "--head-report", "head.json",
        "--reviewed-template-path", casegen.TARGET,
    ]
    for code in DECLARATIONS:
        argv.extend(["--declare", code])
    delta = _run(argv, env, ws)
    if delta.returncode != 0:
        return {"accept": False, "delta_exit": delta.returncode}
    summary = json.loads(delta.stdout)["summary"]["finding_delta"]
    counts = summary["by_classification"]
    return {"accept": counts.get("Resolved", 0) >= 1 and counts.get("New", 0) == 0, "delta": counts, "reasons": {k: v for k, v in summary["by_reason"].items() if v}}


def _c(setup: casegen.Setup, tools: Optional[str]) -> Dict[str, Any]:
    out = _run([PYTHON, "-m", "iacreview.remediation", *casegen.verify_argv(setup)], casegen.tool_env(setup, tools), setup.repo)
    try:
        decision = json.loads(out.stdout)["payload"]["decision"]
    except (ValueError, KeyError):
        decision = None
    return {"accept": decision == "VERIFIED", "decision": decision}


def _d(setup: casegen.Setup, scenario: str, env: Dict[str, str]) -> Dict[str, Any]:
    out = _run([PYTHON, str(HERE / "baseline_d.py"), "--repo", str(setup.repo), "--base", setup.base, "--head", setup.head or "HEAD", "--scenario", scenario], env, setup.repo)
    return {"accept": out.returncode == 0, "exit": out.returncode}


def compare_case(case: Dict[str, Any], root: Path) -> Dict[str, Any]:
    tools = case.get("tools")
    setup = casegen.build(case, root)
    env = casegen.tool_env(setup, tools)
    env_git = dict(env)
    scenario = case["scenario"]
    work = root / "work"
    work.mkdir()
    timings: Dict[str, float] = {}
    base = _show(setup, setup.base, env_git)
    head = _show(setup, setup.head or "HEAD", env_git)
    results: Dict[str, Dict[str, Any]] = {}
    t = time.monotonic()
    results["A"] = _a(setup, scenario, head, work, env) if head is not None else {"accept": False}
    timings["A"] = time.monotonic() - t
    t = time.monotonic()
    if results["A"]["accept"] and base is not None and head is not None:
        results["B"] = _b(base, head, work, env)
    else:
        results["B"] = {"accept": False, "skipped_because": "A rejected"}
    timings["B"] = time.monotonic() - t
    t = time.monotonic()
    c_only = _c(setup, tools)
    timings["C"] = time.monotonic() - t
    results["C_only"] = c_only
    results["C"] = {"accept": results["B"]["accept"] and c_only["accept"]}
    t = time.monotonic()
    results["D"] = _d(setup, scenario, env)
    timings["D"] = time.monotonic() - t
    return {
        "id": case["id"],
        "family": case["family"],
        "class": case["class"],
        "expected_accept": case["expected"]["decision"] == "VERIFIED",
        "accept": {k: v["accept"] for k, v in results.items()},
        "detail": results,
        "seconds": {k: round(v, 2) for k, v in timings.items()},
    }


def score(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for config in ("A", "B", "C", "C_only", "D"):
        dangerous = [r["id"] for r in rows if r["class"] == "dangerous" and r["accept"][config]]
        evidence = [r["id"] for r in rows if r["class"] == "evidence_insufficient" and r["accept"][config]]
        invalid = [r["id"] for r in rows if r["class"] == "invalid_input" and r["accept"][config]]
        correct = [r for r in rows if r["class"] == "correct"]
        rejected_correct = [r["id"] for r in correct if not r["accept"][config]]
        out[config] = {
            "dangerous_false_accepts": dangerous,
            "evidence_false_accepts": evidence,
            "invalid_input_accepts": invalid,
            "correct_cases": len(correct),
            "correct_rejected": rejected_correct,
            "mean_seconds": None,
        }
    return out


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", default="")
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    wanted = {x for x in args.only.split(",") if x}
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        for case in casegen.load_cases():
            if wanted and case["id"] not in wanted:
                continue
            row = compare_case(case, Path(tmp) / case["id"])
            rows.append(row)
            sys.stderr.write("{0:6} {1:22} {2}\n".format(row["id"], row["class"], " ".join("{0}={1}".format(k, "acc" if v else "rej") for k, v in row["accept"].items())))
    scores = score(rows)
    for config in scores:
        secs = [r["seconds"][config[0]] for r in rows]
        scores[config]["mean_seconds"] = round(sum(secs) / len(secs), 2) if secs else None
    result = {"cases": len(rows), "scores": scores, "rows": rows, "python": sys.version.split()[0]}
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    sys.stderr.write(json.dumps(scores, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
