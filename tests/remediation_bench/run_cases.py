"""Run the Phase 1 cases through the verifier CLI and compare with ``cases.json``.

    python3 tests/remediation_bench/run_cases.py [--only C01,C05] [--output results.json]

Each case is built in a fresh temporary directory, the CLI runs as a
subprocess with a PATH holding only git and the case's tools, and the result is
compared with the expected values written before the implementation. Exit 0
when every case matches, 1 otherwise. Raw verifier output is not printed.
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
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1]))

import casegen  # noqa: E402

PYTHON = sys.executable


def _cli(setup: casegen.Setup, argv: List[str], tools: Optional[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [PYTHON, "-m", "iacreview.remediation", *argv],
        env=casegen.tool_env(setup, tools),
        cwd=str(setup.repo),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=600,
        check=False,
    )


def _explain_stale(setup: casegen.Setup, report: Dict[str, Any], tools: Optional[str], **revs: str) -> int:
    path = setup.repo.parent / "old-report.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    argv = ["explain", str(path), "--check-binding", "--repo", str(setup.repo)]
    for key in ("base", "head", "config_rev"):
        argv.extend(["--" + key.replace("_", "-"), revs[key]])
    argv.extend(["--contract", setup.contract_path or ""])
    return _cli(setup, argv, tools).returncode


def evaluate(case: Dict[str, Any], root: Path) -> Dict[str, Any]:
    tools = case.get("tools")
    setup = casegen.build(case, root)
    expected = case["expected"]
    checks: Dict[str, bool] = {}
    started = time.monotonic()
    old_report = None
    if expected.get("old_evidence") == "stale":
        extra = setup.extra
        old_setup = casegen.Setup(
            setup.case_id,
            setup.repo,
            str(extra.get("old_base", setup.base)),
            str(extra["old_head"]),
            str(extra.get("old_config", setup.config_rev)),
            setup.contract_path,
            bin_dir=setup.bin_dir,
        )
        old = _cli(old_setup, casegen.verify_argv(old_setup), tools)
        old_report = json.loads(old.stdout.decode("utf-8"))
        checks["old_report_was_verified"] = old.returncode == 0 and old_report["payload"]["decision"] == "VERIFIED"
    proc = _cli(setup, casegen.verify_argv(setup), tools)
    elapsed = time.monotonic() - started
    try:
        report = json.loads(proc.stdout.decode("utf-8"))
        payload = report["payload"]
    except (ValueError, KeyError):
        report, payload = None, None
    again = _cli(setup, casegen.verify_argv(setup), tools)
    try:
        checks["payload_deterministic"] = (
            json.loads(again.stdout.decode("utf-8"))["metadata"]["payload_sha256"]
            == json.loads(proc.stdout.decode("utf-8"))["metadata"]["payload_sha256"]
        )
    except (ValueError, KeyError):
        checks["payload_deterministic"] = False
    actual: Dict[str, Any] = {"exit_code": proc.returncode}
    if payload is not None:
        actual.update(
            decision=payload["decision"],
            task_outcome=payload["task_outcome"],
            codes=sorted({e["code"] for e in payload["violations"] + payload["diagnostics"]}),
        )
        checks["decision"] = payload["decision"] == expected["decision"]
        if expected.get("task_outcome") is not None:
            checks["task_outcome"] = payload["task_outcome"] == expected["task_outcome"]
        checks["codes"] = set(expected["codes"]) <= set(actual["codes"])
        checks["no_verified_when_codes_expected"] = not (expected["codes"] and payload["decision"] == "VERIFIED")
    else:
        checks["report_parsed"] = False
    checks["exit_code"] = proc.returncode == expected["exit_code"]
    checks["no_traceback"] = b"Traceback" not in proc.stderr
    if expected.get("markers") == "absent":
        wt = _cli(setup, casegen.verify_argv(setup, worktree=True), tools)
        checks["worktree_preview_ran"] = wt.returncode in (0, 20, 21)
        checks["markers_absent"] = setup.marker is not None and not setup.marker.exists()
    if expected.get("canary") == "absent":
        summary = _cli(setup, casegen.verify_argv(setup) + ["--summary"], tools)
        blob = proc.stdout + proc.stderr + summary.stdout + summary.stderr
        for needle in (casegen.CANARY, casegen.CANARY_ID, "zqxCANARY7f3c9a", casegen.BIDI):
            checks["canary_absent:" + needle.encode("unicode_escape").decode("ascii")] = (
                needle.encode("utf-8") not in blob and needle.encode("unicode_escape") not in blob
                and json.dumps(needle).strip('"').encode("ascii") not in blob
            )
    if expected.get("contract_from") == "trusted_config" and payload is not None:
        import hashlib

        trusted = hashlib.sha256(casegen.contract_text(case["scenario"]).encode("utf-8")).hexdigest()
        checks["contract_from_trusted_config"] = payload["trust"]["contract_sha256"] == trusted
    if expected.get("validator_from") == "installed" and payload is not None:
        from iacreview.remediation import report as report_mod

        checks["validator_from_installed"] = payload["validator"]["source_sha256"] == report_mod.validator_identity()["source_sha256"]
    if old_report is not None:
        revs = {"base": setup.base, "head": setup.head or "", "config_rev": setup.config_rev or ""}
        checks["old_evidence_stale"] = _explain_stale(setup, old_report, tools, **revs) == 21
    status = "PASS" if all(checks.values()) else "FAIL"
    return {
        "id": case["id"],
        "family": case["family"],
        "class": case["class"],
        "expected": expected,
        "actual": actual,
        "checks": checks,
        "status": status,
        "seconds": round(elapsed, 2),
        "report_payload_sha256": report["metadata"]["payload_sha256"] if report else None,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", default="")
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    wanted = {x for x in args.only.split(",") if x}
    results = []
    with tempfile.TemporaryDirectory() as tmp:
        for case in casegen.load_cases():
            if wanted and case["id"] not in wanted:
                continue
            result = evaluate(case, Path(tmp) / case["id"])
            results.append(result)
            failed = [k for k, v in result["checks"].items() if not v]
            sys.stderr.write("{0:6} {1} {2}\n".format(result["id"], result["status"], ",".join(failed)))
    summary = {
        "cases": len(results),
        "passed": sum(r["status"] == "PASS" for r in results),
        "families": len({r["family"] for r in results}),
        "results": results,
    }
    text = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    sys.stderr.write("{0}/{1} cases matched the ground truth\n".format(summary["passed"], summary["cases"]))
    return 0 if summary["passed"] == summary["cases"] else 1


if __name__ == "__main__":
    sys.exit(main())
