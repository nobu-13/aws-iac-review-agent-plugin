"""A/B/C/D comparison over the Phase 1 cases (work package AC45-AC47).

    python3 tests/remediation_bench/compare.py [--only C01,C05] [--output compare.json]

Every configuration gets the same candidate: the same git repository (Base,
Head, trusted config revision), the same PATH with the same tools (real or the
case's fake ones), the same profile Guard rules where it uses rules, and the
same expected values (``benchmark/remediation/cases.json``, fixed before the
verifier). For each configuration two things are recorded separately:

* ``tool_results``: what the tools reported (exit codes, rule states, Delta
  classification counts, verifier decision), with no judgement;
* ``accept``: the runner's acceptance rule applied to those results.

Configurations (work package AC45):

A   official tools: cfn-lint on Head and cfn-guard with the profile outcome
    rule on the Head projection. Accept: no cfn-lint Error and the rule PASS.
B   A + v1.1: ``iac-review`` on Base and Head, then the Delta_Tool. The v1.1
    Delta is not a gate (docs/delta-schema.md); the acceptance rule used here
    (A, at least one Resolved, no New) is the runner's model of how a user
    might read it, recorded as such.
C   B + Phase 1, as AC45 defines it: A's and B's results are produced and kept
    as reference; acceptance is decided by Phase 1 alone (``verify`` returns
    VERIFIED). Delta Resolved or Delta exit 0 never counts towards acceptance.
C&B the stricter rule reported in the first evaluation (B accepts AND Phase 1
    VERIFIED). Kept to show why that number differed from C.
D0  simple hand-built equivalent (``baseline_d0.py``, hard-coded scope,
    hand-written rules, no evidence handling).
D1  hand-built equivalent of the same contract and evidence conditions
    (``baseline_d1.py``): reads the same contract from the same trusted
    revision and uses the same profile rules and tools, no line limit.
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
CONFIGS = ("A", "B", "C", "C&B", "D0", "D1")


def _run(argv: List[str], env: Dict[str, str], cwd: Path, timeout: int = 300) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, env=env, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    except FileNotFoundError:  # a tool that is not installed
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


def _tools_a(scenario: str, head: Optional[bytes], work: Path, env: Dict[str, str]) -> Dict[str, Any]:
    """Run the official tools on Head. Results only; no acceptance here."""
    if head is None:
        return {"head_template": "absent_or_not_regular"}
    path = work / "head.yaml"
    path.write_bytes(head)
    lint = _run(["cfn-lint", "-f", "json", "--", str(path)], env, work)
    result: Dict[str, Any] = {"cfn_lint_exit": lint.returncode}
    try:
        result["cfn_lint_errors"] = sum(1 for r in json.loads(lint.stdout) if r.get("Level") == "Error")
    except (ValueError, TypeError, AttributeError):
        result["cfn_lint_errors"] = None
    from iacreview import template

    try:
        doc, _ = template.parse_template_text(head.decode("utf-8"), path)
        resource = doc.get("Resources", {}).get(TARGET_ID[scenario], {})
        data = {"Target": resource, "Params": {"required_statement_sid": "ReadInput"}}
        (work / "proj.json").write_text(json.dumps(data, default=str), encoding="utf-8")
    except Exception:  # noqa: BLE001 - recorded as a result
        result["guard_rule"] = "head_not_parsed"
        return result
    guard = _run(
        ["cfn-guard", "validate", "--data", str(work / "proj.json"), "--rules", str(OUTCOME_RULES[scenario]), "--output-format", "json", "--show-summary", "none"],
        env,
        work,
    )
    result["cfn_guard_exit"] = guard.returncode
    try:
        record = json.loads(guard.stdout)
        name = OUTCOME_RULE_NAME[scenario]
        result["guard_rule"] = "PASS" if name in record.get("compliant", []) else "FAIL" if any(
            e.get("Rule", {}).get("name") == name for e in record.get("not_compliant", [])
        ) else "SKIP"
    except (ValueError, TypeError, AttributeError):
        result["guard_rule"] = "unparsed"
    return result


def _accept_a(t: Dict[str, Any]) -> bool:
    return t.get("cfn_lint_exit") in (0, 4, 8, 12) and t.get("cfn_lint_errors") == 0 and t.get("guard_rule") == "PASS"


def _tools_b(base: Optional[bytes], head: Optional[bytes], work: Path, env: Dict[str, str]) -> Dict[str, Any]:
    """v1.1: review both sides at the same relative path, then the Delta_Tool."""
    if base is None or head is None:
        return {"delta": "not_run_template_missing"}
    ws = work / "b"
    review = str(ROOT / "skills/iac-review/scripts/run_iac_review.py")
    result: Dict[str, Any] = {}
    for side, data in (("base", base), ("head", head)):
        (ws / side / "infra").mkdir(parents=True)
        (ws / side / casegen.TARGET).write_bytes(data)
        out = _run([PYTHON, review, "--target", casegen.TARGET, "--sources", "cfn-lint", "--sources", "cfn-guard", "--sources", "iam-review"], env, ws / side)
        result["review_exit_" + side] = out.returncode
        if out.returncode != 0:
            return result
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
    result["delta_exit"] = delta.returncode
    if delta.returncode == 0:
        summary = json.loads(delta.stdout)["summary"]["finding_delta"]
        result["delta_classification"] = summary["by_classification"]
    return result


def _accept_b(a_ok: bool, t: Dict[str, Any]) -> bool:
    counts = t.get("delta_classification") or {}
    return a_ok and t.get("delta_exit") == 0 and counts.get("Resolved", 0) >= 1 and counts.get("New", 0) == 0


def _phase1(setup: casegen.Setup, tools: Optional[str]) -> Dict[str, Any]:
    out = _run([PYTHON, "-m", "iacreview.remediation", *casegen.verify_argv(setup)], casegen.tool_env(setup, tools), setup.repo)
    try:
        payload = json.loads(out.stdout)["payload"]
        return {"exit": out.returncode, "decision": payload["decision"], "task_outcome": payload["task_outcome"]}
    except (ValueError, KeyError):
        return {"exit": out.returncode, "decision": None}


def _d0(setup: casegen.Setup, scenario: str, env: Dict[str, str]) -> Dict[str, Any]:
    out = _run([PYTHON, str(HERE / "baseline_d0.py"), "--repo", str(setup.repo), "--base", setup.base, "--head", setup.head or "HEAD", "--scenario", scenario], env, setup.repo)
    return {"exit": out.returncode}


def _d1(setup: casegen.Setup, env: Dict[str, str]) -> Dict[str, Any]:
    if setup.contract_file is not None:
        return {"exit": 21, "note": "no trusted revision given (draft file); D1 refuses like Phase 1"}
    argv = [PYTHON, str(HERE / "baseline_d1.py"), "--repo", str(setup.repo), "--base", setup.base, "--head", setup.head or "HEAD",
            "--config-rev", setup.config_rev or "", "--contract", setup.contract_path or ""]
    return {"exit": _run(argv, env, setup.repo).returncode}


def compare_case(case: Dict[str, Any], root: Path) -> Dict[str, Any]:
    tools = case.get("tools")
    setup = casegen.build(case, root)
    env = casegen.tool_env(setup, tools)
    scenario = case["scenario"]
    work = root / "work"
    work.mkdir()
    seconds: Dict[str, float] = {}
    base = _show(setup, setup.base, env)
    head = _show(setup, setup.head or "HEAD", env)

    t0 = time.monotonic()
    tools_a = _tools_a(scenario, head, work, env)
    seconds["A"] = time.monotonic() - t0
    t0 = time.monotonic()
    tools_b = _tools_b(base, head, work, env)  # always run: C keeps it as reference
    seconds["B_extra"] = time.monotonic() - t0
    t0 = time.monotonic()
    phase1 = _phase1(setup, tools)
    seconds["Phase1"] = time.monotonic() - t0
    t0 = time.monotonic()
    d0 = _d0(setup, scenario, env)
    seconds["D0"] = time.monotonic() - t0
    t0 = time.monotonic()
    d1 = _d1(setup, env)
    seconds["D1"] = time.monotonic() - t0

    a_ok = _accept_a(tools_a)
    b_ok = _accept_b(a_ok, tools_b)
    p1_ok = phase1.get("decision") == "VERIFIED"
    accept = {"A": a_ok, "B": b_ok, "C": p1_ok, "C&B": b_ok and p1_ok, "D0": d0["exit"] == 0, "D1": d1["exit"] == 0}
    return {
        "id": case["id"],
        "family": case["family"],
        "class": case["class"],
        "expected_decision": case["expected"]["decision"],
        "expected_accept": case["expected"]["decision"] == "VERIFIED",
        "tool_results": {"A": tools_a, "B": tools_b, "Phase1": phase1, "D0": d0, "D1": d1},
        "accept": accept,
        "seconds": {k: round(v, 2) for k, v in seconds.items()},
    }


def score(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for config in CONFIGS:
        out[config] = {
            "dangerous_false_accepts": [r["id"] for r in rows if r["class"] == "dangerous" and r["accept"][config]],
            "evidence_false_accepts": [r["id"] for r in rows if r["class"] == "evidence_insufficient" and r["accept"][config]],
            "invalid_input_accepts": [r["id"] for r in rows if r["class"] == "invalid_input" and r["accept"][config]],
            "correct_cases": sum(r["class"] == "correct" for r in rows),
            "correct_rejected": [r["id"] for r in rows if r["class"] == "correct" and not r["accept"][config]],
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
    result = {"cases": len(rows), "scores": score(rows), "rows": rows, "python": sys.version.split()[0]}
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    for config, s in result["scores"].items():
        sys.stderr.write("{0:4} dangerous={1} evidence={2} invalid={3} correct_rejected={4}\n".format(
            config, len(s["dangerous_false_accepts"]), len(s["evidence_false_accepts"]), len(s["invalid_input_accepts"]), len(s["correct_rejected"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
