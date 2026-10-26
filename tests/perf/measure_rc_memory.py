"""RC Blocker P0 memory harness for the v1.1 Delta_Tool (A-1b / H-M1-2).

Usage (from the plugin root)::

    PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 tests/perf/measure_rc_memory.py \
        --work "$TMPDIR/v11-rc/mem/work" --out "$TMPDIR/v11-rc/mem/after.jsonl" \
        --runs 3 --scales 10,25,50,100

Two input shapes, at a percentage of the M1 case (``gen_inputs.py``):

* ``list``: ``deep_list_change_pair(200000 * scale, 57)``, every element changed
  (200,000 Change_Entries of path length 61 at 100%).
* ``dup``: ``deep_duplicate_key_pair(285000 * scale, 57)`` compared with itself
  (285,000 uncompared paths at 100%).

For each shape and scale, in ascending scale order:

* ``stages``: one child process runs the CLI pipeline stage by stage under
  ``tracemalloc`` (``reset_peak`` before each stage): ``read`` (both sides),
  ``diff``, ``lower_bound`` (when the product has it), ``render_collect``,
  ``render_tokens``, ``render_final``, ``serialize`` (bounded when the product
  has it, else ``report.dump`` and the size check), ``minimal`` (over the
  limit). Stages the product does not have are recorded as skipped, so the
  same script measures before and after a change.
* ``cli``: ``--runs`` runs of ``python3 -m iacreview.deltacli``: exit code,
  wall time, child max RSS (``os.wait4``), stdout bytes and SHA-256.

Safety rules (macOS does not enforce ``RLIMIT_AS``, so it is not used):

1. Before each scale the available memory is ``vm_stat`` free + inactive +
   speculative pages, and ``cap = min(--max-cap-mib, 0.5 * available)``.
2. The peak RSS of the next scale is extrapolated linearly from the largest
   max RSS measured so far for that shape (or from ``--prior-mib`` at 100%
   before the first measurement). A scale whose extrapolation exceeds ``cap``
   is not run and is recorded ``SKIPPED (unsafe)``.
3. Every child runs a watchdog thread that reads its own peak RSS every
   0.05 s and exits with code 99 once it exceeds ``cap``; the run is recorded
   ``ABORTED (rss > cap)`` and no larger scale of that shape is run. (``ps``
   is not available to the harness in the sandbox.)
4. Children run one at a time; nothing else heavy should run alongside.

``--src`` selects the product tree on ``PYTHONPATH`` (default: this plugin),
for a before / after comparison against a copy outside the repository.
Generated inputs go under ``--work`` and results to ``--out``, both outside
the repository. Not collected by pytest. Results are diagnostics for a Human
decision, never a pass / fail gate (Requirement 14 AC10).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import threading
import time
import tracemalloc
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

PLUGIN_ROOT = Path(__file__).resolve().parents[2]
PERF_DIR = Path(__file__).resolve().parent
MIB = 1024 * 1024
LEVELS = 57
FULL_SIZE = {"list": 200_000, "dup": 285_000}
#: M1 CLI max RSS at 100% (docs/v2/v1.1-m1-evidence.md 3-4), the default prior.
M1_RSS_MIB = {"list": 2316.6, "dup": 2941.4}
WATCHDOG_EXIT = 99
WATCHDOG_SECONDS = 0.05
CHILD_WALL_SECONDS = 1200


# ---------------------------------------------------------------------------
# memory guard
# ---------------------------------------------------------------------------


def available_mib() -> float:
    """``vm_stat`` free + inactive + speculative pages, in MiB."""
    text = subprocess.run(["vm_stat"], capture_output=True, text=True, check=True).stdout
    page = int(text.split("page size of", 1)[1].split()[0])
    counts: Dict[str, int] = {}
    for line in text.splitlines()[1:]:
        name, _, value = line.partition(":")
        value = value.strip().rstrip(".")
        if value.isdigit():
            counts[name.strip()] = int(value)
    pages = counts.get("Pages free", 0) + counts.get("Pages inactive", 0) + counts.get("Pages speculative", 0)
    return pages * page / MIB


def _max_rss_mib() -> float:
    import resource

    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return rss / (MIB if sys.platform == "darwin" else 1024)


def _start_watchdog(cap_mib: float) -> None:
    def watch() -> None:
        while True:
            if _max_rss_mib() > cap_mib:
                os.write(2, "measure_rc_memory: ABORTED (rss > cap {0:.0f} MiB)\n".format(cap_mib).encode())
                os._exit(WATCHDOG_EXIT)
            time.sleep(WATCHDOG_SECONDS)

    threading.Thread(target=watch, daemon=True).start()


# ---------------------------------------------------------------------------
# inputs
# ---------------------------------------------------------------------------


def _count(shape: str, scale: float) -> int:
    return max(1, round(FULL_SIZE[shape] * scale / 100.0))


def write_inputs(ws: Path, shape: str, count: int) -> List[str]:
    """Write the inputs of ``shape`` into ``ws``; return the CLI arguments."""
    sys.path.insert(0, str(PERF_DIR))
    import gen_inputs

    if ws.exists():
        shutil.rmtree(ws)
    ws.mkdir(parents=True)
    files: Dict[str, str] = {}
    if shape == "list":
        files["base.json"], files["head.json"] = gen_inputs.deep_list_change_pair(count, LEVELS)
        argv = ["--base-template", "base.json", "--head-template", "head.json"]
    else:
        files["base.json"] = gen_inputs.deep_duplicate_key_pair(count, LEVELS)
        argv = ["--base-template", "base.json", "--head-template", "base.json"]
    for name, text in files.items():
        with (ws / name).open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
    return argv


# ---------------------------------------------------------------------------
# children
# ---------------------------------------------------------------------------


class _Stages:
    def __init__(self) -> None:
        self.rows: Dict[str, Dict[str, Any]] = {}

    def run(self, name: str, fn: Callable[[], Any]) -> Any:
        tracemalloc.reset_peak()
        start = time.perf_counter()
        result = fn()
        elapsed = time.perf_counter() - start
        current, peak = tracemalloc.get_traced_memory()
        self.rows[name] = {"s": round(elapsed, 3), "peak_traced_mib": round(peak / MIB, 1),
                           "current_after_mib": round(current / MIB, 1)}
        return result

    def skip(self, name: str, why: str) -> None:
        self.rows[name] = {"skipped": why}


def _stage_child(ws: Path, argv: Sequence[str], cap_mib: float) -> Dict[str, Any]:
    """The pipeline of ``deltacli`` for a Template_Pair, stage by stage."""
    _start_watchdog(cap_mib)
    from iacreview import categories, deltaio, deltareport, deltaschema, semdiff
    from iacreview.deltaio import Failure
    from iacreview.deltareport import DeltaRequest, FailureRecord, TemplateInput

    os.chdir(ws)
    root = ws.resolve()
    stages = _Stages()
    tracemalloc.start()
    names = (argv[1], argv[3])
    parsed = [stages.run("read_" + side, lambda n=name, s=side: deltaio.read_template(n, root, s))
              for side, name in zip(("base", "head"), names)]
    assert not any(isinstance(p, Failure) for p in parsed), parsed
    result = stages.run("diff", lambda: semdiff.diff(parsed[0], parsed[1]))
    assert not isinstance(result, Failure), result
    request = DeltaRequest(templates=(TemplateInput(names[0], parsed[0]), TemplateInput(names[1], parsed[1])),
                           reports=None, semantic_diff=result, finding_delta=None)
    failures = deltareport._ordered_failures(request.failures)
    limit = deltaschema.MAX_OUTPUT_BYTES
    over = False
    text: Optional[str] = None
    if hasattr(deltareport, "_output_lower_bound"):
        bound = stages.run("lower_bound", lambda: deltareport._output_lower_bound(request, failures))
        stages.rows["lower_bound"]["bytes"] = bound
        over = bound > limit
    else:
        stages.skip("lower_bound", "not in this product version")
    if over:
        for name in ("render_collect", "render_tokens", "render_final", "serialize"):
            stages.skip(name, "lower bound over the limit")
    else:
        category_map = categories.load_map()
        collector = deltareport._Names(False, None)
        stages.run("render_collect", lambda: deltareport._Renderer(request, collector, "anonymized", category_map)
                   .render(failures, False))
        table = stages.run("render_tokens", lambda: deltareport.build_token_table(collector.collected))
        final = deltareport._Names(False, table)
        built = stages.run("render_final", lambda: deltareport._Renderer(request, final, "anonymized", category_map)
                           .render(failures, False))
        del collector
        if hasattr(deltareport, "_serialize"):
            text = stages.run("serialize", lambda: deltareport._serialize(built, limit))
            over = text is None
        else:
            full = stages.run("serialize", lambda: deltareport.dump(built))
            stages.rows["serialize"]["chars"] = len(full)
            over = stages.run("limit_check", lambda: deltareport._over_limit(full))
            text = None if over else full
            del full
        del built, table, final
    if over:
        records = failures + (FailureRecord(Failure("output_size_limit_exceeded", None, "output")),)
        text = stages.run("minimal", lambda: deltareport.dump(
            deltareport._render(request, "anonymized", records, output_failed=True)))
    else:
        stages.skip("minimal", "within the limit")
    _, overall = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert text is not None
    data = text.encode("utf-8")
    return {"stages": stages.rows, "over_limit": over, "pipeline_stdout_bytes": len(data),
            "pipeline_sha256": hashlib.sha256(data).hexdigest(), "max_rss_mib": round(_max_rss_mib(), 1),
            "change_entries": len(result.changes), "uncompared_paths": len(result.uncompared_paths)}


def _guarded_cli(argv: Sequence[str], cap_mib: float) -> None:
    """``python3 -m iacreview.deltacli`` with the watchdog of safety rule 3."""
    import runpy

    _start_watchdog(cap_mib)
    sys.argv = ["deltacli"] + list(argv)
    runpy.run_module("iacreview.deltacli", run_name="__main__", alter_sys=True)


# ---------------------------------------------------------------------------
# parent
# ---------------------------------------------------------------------------


def _child_env(src: Path) -> Dict[str, str]:
    return dict(os.environ, PYTHONPATH=str(src), PYTHONDONTWRITEBYTECODE="1")


def _run_child(command: List[str], ws: Path, src: Path, stdout: Any) -> Tuple[int, float, float, str]:
    """(exit code, wall seconds, max RSS MiB, stderr) of one child."""
    err_path = ws / "child.stderr"
    with err_path.open("wb") as err:
        start = time.perf_counter()
        proc = subprocess.Popen(command, cwd=str(ws), env=_child_env(src), stdin=subprocess.DEVNULL,
                                stdout=stdout, stderr=err)
        deadline = start + CHILD_WALL_SECONDS
        while True:
            pid, status, usage = os.wait4(proc.pid, os.WNOHANG)
            if pid:
                break
            if time.perf_counter() > deadline:
                proc.kill()
                pid, status, usage = os.wait4(proc.pid, 0)
                break
            time.sleep(0.05)
        wall = time.perf_counter() - start
    code = os.waitstatus_to_exitcode(status)
    proc.returncode = code  # reaped by os.wait4 above
    rss = usage.ru_maxrss / (MIB if sys.platform == "darwin" else 1024)
    return code, wall, rss, err_path.read_text(encoding="utf-8", errors="replace")


def _cli_runs(ws: Path, argv: List[str], src: Path, runs: int, cap: float) -> Dict[str, Any]:
    out_path = ws / "cli.out"
    rows: List[Dict[str, Any]] = []
    for _ in range(runs):
        with out_path.open("wb") as out:
            command = [sys.executable, str(Path(__file__).resolve()), "--guarded-cli", "--cap-mib", str(cap), "--"]
            code, wall, rss, err = _run_child(command + argv, ws, src, out)
        data = out_path.read_bytes()
        rows.append({"exit": code, "wall_s": round(wall, 3), "max_rss_mib": round(rss, 1),
                     "stdout_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                     "stderr": err.splitlines()[:3]})
        if code == WATCHDOG_EXIT:
            break
    walls = [r["wall_s"] for r in rows]
    return {"runs": rows, "exit_codes": sorted({r["exit"] for r in rows}),
            "distinct_sha256": len({r["sha256"] for r in rows}), "sha256": rows[0]["sha256"],
            "stdout_bytes": rows[0]["stdout_bytes"], "wall_median_s": round(statistics.median(walls), 3),
            "wall_max_s": max(walls), "max_rss_mib": max(r["max_rss_mib"] for r in rows),
            "aborted": any(r["exit"] == WATCHDOG_EXIT for r in rows)}


def _outside_repository(parser: argparse.ArgumentParser, path: Path, option: str) -> Path:
    resolved = path.resolve()
    if resolved == PLUGIN_ROOT or PLUGIN_ROOT in resolved.parents:
        parser.error("{0} must be outside the repository".format(option))
    return resolved


def _measure(args: argparse.Namespace, work: Path, src: Path, out: Any) -> None:
    out.write(json.dumps({"exp": "environment", "python": sys.version.split()[0], "platform": platform.platform(),
                          "machine": platform.machine(), "src": str(src), "runs": args.runs,
                          "max_cap_mib": args.max_cap_mib}) + "\n")
    for shape in args.shapes:
        seen: List[Tuple[float, float]] = []  # (scale, max RSS MiB)
        stop = False
        for scale in args.scales:
            available = available_mib()
            cap = min(args.max_cap_mib, 0.5 * available)
            if seen:
                ref_scale, ref_rss = max(seen, key=lambda item: item[1])
                predicted = ref_rss * scale / ref_scale
            else:
                predicted = args.prior_mib.get(shape, M1_RSS_MIB[shape]) * scale / 100.0
            row: Dict[str, Any] = {"exp": "scale", "shape": shape, "scale_pct": scale, "count": _count(shape, scale),
                                   "available_mib": round(available, 1), "cap_mib": round(cap, 1),
                                   "extrapolated_peak_mib": round(predicted, 1)}
            if stop:
                row["status"] = "SKIPPED (a smaller scale was aborted)"
            elif predicted > cap:
                row["status"] = "SKIPPED (unsafe: extrapolated {0:.0f} MiB > cap {1:.0f} MiB)".format(predicted, cap)
            else:
                ws = work / "{0}_{1}".format(shape, scale)
                argv = write_inputs(ws, shape, row["count"])
                row["input_bytes"] = sorted({p.stat().st_size for p in ws.glob("*.json")})
                if not args.cli_only:
                    command = [sys.executable, str(Path(__file__).resolve()), "--stage-child", "--cap-mib", str(cap),
                               "--work", str(ws), "--"]
                    with (ws / "stage.out").open("wb") as stage_out:
                        code, wall, rss, err = _run_child(command + argv, ws, src, stage_out)
                    row["stage_child"] = {"exit": code, "wall_s": round(wall, 3), "max_rss_mib": round(rss, 1),
                                          "stderr_tail": err[-600:]}
                    if code == 0:
                        row["stage_child"].update(json.loads((ws / "stage.out").read_text(encoding="utf-8")))
                    seen.append((scale, rss))
                    if code == WATCHDOG_EXIT:
                        row["status"] = "ABORTED (rss > cap)"
                        stop = True
                if not stop:
                    row["cli"] = _cli_runs(ws, argv, src, args.runs, cap)
                    seen.append((scale, row["cli"]["max_rss_mib"]))
                    if row["cli"]["aborted"]:
                        row["status"] = "ABORTED (rss > cap)"
                        stop = True
                    else:
                        row["status"] = "MEASURED"
                        if "stage_child" in row and "pipeline_sha256" in row["stage_child"]:
                            row["pipeline_matches_cli"] = row["stage_child"]["pipeline_sha256"] == row["cli"]["sha256"]
                shutil.rmtree(ws, ignore_errors=True)
            out.write(json.dumps(row, sort_keys=True) + "\n")
            out.flush()
            print(json.dumps({k: row.get(k) for k in ("shape", "scale_pct", "status", "cap_mib",
                                                      "extrapolated_peak_mib")}), flush=True)


def _scales(text: str) -> List[float]:
    values = sorted(float(part) for part in text.split(",") if part)
    if not values or any(v <= 0 or v > 100 for v in values):
        raise argparse.ArgumentTypeError("scales are percentages in (0, 100]")
    return values


def _priors(text: str) -> Dict[str, float]:
    result: Dict[str, float] = {}
    for part in text.split(","):
        if part:
            shape, _, value = part.partition("=")
            if shape not in FULL_SIZE:
                raise argparse.ArgumentTypeError("unknown shape " + shape)
            result[shape] = float(value)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--work", help="directory for generated inputs (outside the repository)")
    parser.add_argument("--out", help="JSON lines file (outside the repository)")
    parser.add_argument("--src", default=str(PLUGIN_ROOT), help="product tree put on PYTHONPATH")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--scales", type=_scales, default=_scales("10,25,50,100"))
    parser.add_argument("--shapes", type=lambda t: t.split(","), default=["list", "dup"])
    parser.add_argument("--max-cap-mib", type=float, default=3072.0)
    parser.add_argument("--prior-mib", type=_priors, default={}, help="shape=MiB at 100%%, e.g. list=2316.6")
    parser.add_argument("--cli-only", action="store_true")
    parser.add_argument("--cap-mib", type=float, help=argparse.SUPPRESS)
    parser.add_argument("--stage-child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--guarded-cli", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("rest", nargs=argparse.REMAINDER, help=argparse.SUPPRESS)
    args = parser.parse_args()
    rest = args.rest[1:] if args.rest[:1] == ["--"] else args.rest
    if args.guarded_cli:
        _guarded_cli(rest, args.cap_mib)
        return 0
    if args.stage_child:
        print(json.dumps(_stage_child(Path(args.work), rest, args.cap_mib), sort_keys=True))
        return 0
    if args.work is None or args.out is None:
        parser.error("--work and --out are required")
    if args.runs < 1 or any(shape not in FULL_SIZE for shape in args.shapes):
        parser.error("--runs must be positive and --shapes a subset of list,dup")
    work = _outside_repository(parser, Path(args.work), "--work")
    out_path = _outside_repository(parser, Path(args.out), "--out")
    src = Path(args.src).resolve()
    if src != PLUGIN_ROOT:
        _outside_repository(parser, src, "--src")
    work.mkdir(parents=True, exist_ok=True)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("a", encoding="utf-8") as out:
        _measure(args, work, src, out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
