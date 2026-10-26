"""Gate M1 measurement harness for the v1.1 Delta_Tool (tasks.md Task 16).

Usage (from the plugin root)::

    PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 tests/perf/measure_m1.py \
        --work "$TMPDIR/v11-m1/work" --out "$TMPDIR/v11-m1/m1.jsonl"

The implementation is measured with the M0 generator (``gen_inputs.py``,
seed fixed) and the inputs of Task 0.4, plus the ``MAX_CHANGE_ENTRIES``
boundary and the largest output a pair of in-limit inputs can produce.

Every experiment runs in its own child process with ``RLIMIT_CPU`` and a wall
timeout. For each case it records:

* ``phases``: the CLI pipeline split into phases (read, parse, structure /
  check, diff / match, render passes, serialization, size check, write), each
  timed with ``time.perf_counter`` over ``--runs`` runs (median and max). The
  pipeline calls the same functions as ``iacreview.deltacli`` in the same order;
  the SHA-256 of its text is compared with the CLI's stdout.
* ``memory``: one separate run under ``tracemalloc`` with the peak of each
  phase (``tracemalloc.reset_peak`` before the phase) and the overall peak.
* ``cli``: ``python3 -m iacreview.deltacli`` as a subprocess, ``--runs`` runs:
  exit code, stdout bytes against ``MAX_OUTPUT_BYTES``, the number of distinct
  stdout digests (1 means the runs were byte-identical), wall time and the
  child's maximum RSS.

Generated inputs are written under ``--work`` (outside the repository) and
removed after each case. Results are JSON lines in ``--out`` (outside the
repository). Not collected by pytest (the file name does not start with
``test_``). Results are diagnostics for a Human decision, never a pass / fail
gate (Requirement 14 AC10).
"""

from __future__ import annotations

import argparse
import cProfile
import hashlib
import io
import json
import os
import platform
import pstats
import resource
import shutil
import statistics
import subprocess
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

PLUGIN_ROOT = Path(__file__).resolve().parents[2]
PERF_DIR = Path(__file__).resolve().parent
MIB = 1024 * 1024
#: Same target size as M0 (``measure_m0.NEAR_LIMIT``).
NEAR_LIMIT = int(5 * MIB * 0.97)
CHILD_CPU_SECONDS = 1800
CHILD_WALL_SECONDS = 2400
REPORT_DECLARATIONS = (
    "reports_unmodified",
    "same_plugin_version",
    "same_rule_set",
    "same_tool_configuration",
    "same_agent_findings_input",
)

#: Set by ``--cli-only``: measure the CLI subprocess only, not the phases.
CLI_ONLY = False

#: Phases inside the approved budget scope (design.md 12-1-1).
TEMPLATE_BUDGET_PHASES = ("read", "parse", "structure", "diff")
REPORT_BUDGET_PHASES = ("read", "parse", "check", "match")


# ---------------------------------------------------------------------------
# environment
# ---------------------------------------------------------------------------


def _cpu_model() -> Optional[str]:
    if sys.platform == "darwin":
        try:
            return subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True,
                                  text=True, timeout=10, check=False).stdout.strip() or None
        except OSError:
            return None
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        return None
    return None


def _env(runs: int) -> Dict[str, Any]:
    import yaml

    return {
        "exp": "environment",
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "executable": sys.executable,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu_model": _cpu_model(),
        "cpu_count": os.cpu_count(),
        "pyyaml": yaml.__version__,
        "pyyaml_libyaml": hasattr(yaml, "CSafeLoader"),
        "runs": runs,
    }


# ---------------------------------------------------------------------------
# timing helpers
# ---------------------------------------------------------------------------


def _stats(samples: Sequence[float]) -> Dict[str, Any]:
    return {"median_s": round(statistics.median(samples), 4), "max_s": round(max(samples), 4),
            "min_s": round(min(samples), 4), "n": len(samples)}


class _Clock:
    """Accumulates the time of named phases within one run."""

    def __init__(self, traced: bool = False) -> None:
        self.times: Dict[str, float] = {}
        self.peaks: Dict[str, float] = {}
        self._traced = traced

    def run(self, name: str, fn: Callable[[], Any]) -> Any:
        if self._traced:
            tracemalloc.reset_peak()
        start = time.perf_counter()
        result = fn()
        self.times[name] = self.times.get(name, 0.0) + time.perf_counter() - start
        if self._traced:
            _, peak = tracemalloc.get_traced_memory()
            self.peaks[name] = max(self.peaks.get(name, 0.0), peak / MIB)
        return result


def _phase_summary(runs: List[Dict[str, float]], budget: Sequence[str]) -> Dict[str, Any]:
    names = list(runs[0])
    phases = {name: _stats([r[name] for r in runs]) for name in names}
    budget_scope = _stats([sum(r[n] for n in budget if n in r) for r in runs])
    total = _stats([sum(r.values()) for r in runs])
    return {"phases": phases, "budget_scope": budget_scope, "pipeline_total": total}


def _memory_summary(clock: _Clock, budget: Sequence[str]) -> Dict[str, Any]:
    return {
        "phase_peak_traced_mib": {k: round(v, 1) for k, v in clock.peaks.items()},
        "budget_scope_peak_traced_mib": round(max(clock.peaks[n] for n in budget if n in clock.peaks), 1),
        "pipeline_peak_traced_mib": round(max(clock.peaks.values()), 1),
    }


# ---------------------------------------------------------------------------
# the pipeline, phase by phase (mirrors iacreview.deltacli)
# ---------------------------------------------------------------------------


def _render_phases(clock: _Clock, request: Any, out_path: Path) -> Tuple[str, Dict[str, Any]]:
    from iacreview import categories, deltareport

    failures = deltareport._ordered_failures(request.failures)
    category_map = clock.run("render_setup", categories.load_map)
    collector = deltareport._Names(False, None)
    clock.run("render_collect", lambda: deltareport._Renderer(request, collector, "anonymized", category_map)
              .render(failures, False))
    table = clock.run("render_tokens", lambda: deltareport.build_token_table(collector.collected))
    names = deltareport._Names(False, table)
    built = clock.run("render_final", lambda: deltareport._Renderer(request, names, "anonymized", category_map)
                      .render(failures, False))
    text = clock.run("serialize", lambda: deltareport.dump(built))
    over = clock.run("limit_check", lambda: deltareport._over_limit(text))
    if over:
        raise AssertionError("the measured case is over MAX_OUTPUT_BYTES; measure it through the CLI only")

    def write() -> None:
        with out_path.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)

    clock.run("write", write)
    return text, built


def _template_pipeline(clock: _Clock, ws: Path, names: Tuple[str, str], out_path: Path) -> Tuple[str, Dict[str, Any]]:
    from iacreview import deltaio, pathguard, semdiff, template
    from iacreview.deltaio import Failure, ParsedTemplate
    from iacreview.deltareport import DeltaRequest, TemplateInput

    root = ws.resolve()
    inputs: List[Any] = []
    for side, arg in zip(("base", "head"), names):
        path = clock.run("read", lambda: pathguard.resolve_within(arg, root))
        text = clock.run("read", lambda: template._read_text(path))
        doc = clock.run("parse", lambda: deltaio.parse_document(text, path, side))
        assert not isinstance(doc, Failure), doc
        assert clock.run("structure", lambda: template.is_reviewable(doc.doc))
        shape = clock.run("structure", lambda: deltaio.check_structure(doc.doc, side))
        assert not isinstance(shape, Failure), shape
        parsed = ParsedTemplate(doc=doc.doc, fmt=doc.fmt, marked=doc.marked,
                                duplicate_sections=doc.duplicate_sections, shape=shape)
        inputs.append(TemplateInput(path.relative_to(root).as_posix(), parsed))
    result = clock.run("diff", lambda: semdiff.diff(inputs[0].parsed, inputs[1].parsed))
    assert not isinstance(result, Failure), result
    request = DeltaRequest(templates=(inputs[0], inputs[1]), reports=None, semantic_diff=result, finding_delta=None)
    return _render_phases(clock, request, out_path)


def _report_pipeline(clock: _Clock, ws: Path, names: Tuple[str, str], out_path: Path) -> Tuple[str, Dict[str, Any]]:
    from iacreview import delta, deltaio, pathguard, reportcheck, template
    from iacreview.deltaio import Failure
    from iacreview.deltareport import DeltaRequest, ReportInput
    from iacreview.reportcheck import CheckedReport

    root = ws.resolve()
    inputs: List[Any] = []
    for side, arg in zip(("base", "head"), names):
        path = clock.run("read", lambda: pathguard.resolve_within(arg, root))
        raw = clock.run("read", lambda: template._read_bytes_toctou_safe(path))
        loaded = clock.run("parse", lambda: deltaio.parse_report_bytes(raw, side))
        assert not isinstance(loaded, Failure), loaded
        checked = clock.run("check", lambda: reportcheck.check_report(loaded.obj, side))
        assert isinstance(checked, CheckedReport), checked
        inputs.append(ReportInput(path.relative_to(root).as_posix(), loaded.sha256, checked))
    guard = clock.run("guard_rules", deltaio.load_guard_rule_names)

    def match() -> Any:
        corr = reportcheck.correspondence(None, None, inputs[0].checked, inputs[1].checked, None)
        return delta.match_and_classify(inputs[0].checked, inputs[1].checked,
                                        declarations=frozenset(REPORT_DECLARATIONS), correspondence=corr)

    result = clock.run("match", match)
    request = DeltaRequest(templates=None, reports=(inputs[0], inputs[1]), semantic_diff=None,
                           finding_delta=result, declarations=frozenset(REPORT_DECLARATIONS),
                           guard_rule_names=guard)
    return _render_phases(clock, request, out_path)


def _list_bytes(built: Dict[str, Any], section: str, key: str) -> Tuple[int, int]:
    """(entries, bytes the entries add to the serialized Delta_Report)."""
    from iacreview import deltareport

    part = built.get(section)
    if not part or not part.get(key):
        return 0, 0
    full = len(deltareport.dump(built).encode("utf-8"))
    items = part[key]
    part[key] = []
    try:
        empty = len(deltareport.dump(built).encode("utf-8"))
    finally:
        part[key] = items
    return len(items), full - empty


# ---------------------------------------------------------------------------
# CLI subprocess
# ---------------------------------------------------------------------------


def _cli(ws: Path, argv: Sequence[str], runs: int, out_path: Path) -> Dict[str, Any]:
    from iacreview import deltaschema

    # The inherited environment is kept: HOME locates a user-site PyYAML. The
    # Delta_Tool reads no environment variable that changes its output.
    env = dict(os.environ, PYTHONPATH=str(PLUGIN_ROOT), PYTHONDONTWRITEBYTECODE="1")
    samples: List[float] = []
    digests: List[str] = []
    exits: List[int] = []
    rss: List[int] = []
    size = 0
    err_path = out_path.with_suffix(".stderr")
    for _ in range(runs):
        with out_path.open("wb") as out, err_path.open("wb") as err:
            start = time.perf_counter()
            proc = subprocess.Popen([sys.executable, "-m", "iacreview.deltacli", *argv], cwd=str(ws), env=env,
                                    stdin=subprocess.DEVNULL, stdout=out, stderr=err)
            _, status, usage = os.wait4(proc.pid, 0)
            samples.append(time.perf_counter() - start)
            proc.returncode = os.waitstatus_to_exitcode(status)
        exits.append(proc.returncode)
        rss.append(usage.ru_maxrss)
        data = out_path.read_bytes()
        size = len(data)
        digests.append(hashlib.sha256(data).hexdigest())
    stderr_text = err_path.read_text(encoding="utf-8", errors="replace")
    summary: Optional[Dict[str, Any]] = None
    if size:
        built = json.loads(out_path.read_text(encoding="utf-8"))
        summary = {
            "errors": [e["message"] for e in built.get("errors", [])],
            "semantic_diff_changes": (built["summary"]["semantic_diff"]["changes"]),
            "finding_delta_entries": (built["summary"]["finding_delta"]["entries"]),
        }
    return {
        "exit_codes": sorted(set(exits)),
        "wall": _stats(samples),
        "stdout_bytes": size,
        "max_output_bytes": deltaschema.MAX_OUTPUT_BYTES,
        "fraction_of_output_limit": round(size / deltaschema.MAX_OUTPUT_BYTES, 4),
        "distinct_stdout_sha256": len(set(digests)),
        "stdout_sha256": digests[0] if digests else None,
        "child_maxrss_mib": round(max(rss) / (MIB if sys.platform == "darwin" else 1024), 1),
        "stderr_lines": stderr_text.splitlines()[:5],
        "summary": summary,
    }


# ---------------------------------------------------------------------------
# cases
# ---------------------------------------------------------------------------


def _write_case(work: Path, case: str, files: Dict[str, str]) -> Path:
    ws = work / case
    if ws.exists():
        shutil.rmtree(ws)
    ws.mkdir(parents=True)
    for name, text in files.items():
        with (ws / name).open("w", encoding="utf-8", newline="\n") as handle:  # Path.write_text has no newline= on 3.9
            handle.write(text)
    return ws


def _measure_case(work: Path, case: str, kind: str, files: Dict[str, str], runs: int, keep: bool,
                  phases: bool = True, cli_runs: Optional[int] = None) -> Dict[str, Any]:
    ws = _write_case(work, case, files)
    names = (next(n for n in files if n.startswith("base")), next(n for n in files if n.startswith("head")))
    sizes = {name: len(text.encode("utf-8")) for name, text in files.items()}
    row: Dict[str, Any] = {"exp": "case", "case": case, "kind": kind, "input_bytes": sizes}
    out_path = work / (case + ".out")
    phases = phases and not CLI_ONLY
    row["cli_only"] = CLI_ONLY
    try:
        if phases:
            pipeline = _template_pipeline if kind == "template" else _report_pipeline
            budget = TEMPLATE_BUDGET_PHASES if kind == "template" else REPORT_BUDGET_PHASES
            run_times: List[Dict[str, float]] = []
            text = ""
            built: Dict[str, Any] = {}
            for _ in range(runs):
                clock = _Clock()
                text, built = pipeline(clock, ws, names, out_path)
                run_times.append(clock.times)
            row.update(_phase_summary(run_times, budget))
            row["pipeline_output_bytes"] = len(text.encode("utf-8"))
            row["pipeline_sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
            if kind == "template":
                row["change_entries"], row["change_entry_bytes"] = _list_bytes(built, "semantic_diff", "changes")
            else:
                row["delta_entries"], row["delta_entry_bytes"] = _list_bytes(built, "finding_delta", "entries")
            del text, built
            tracemalloc.start()
            try:
                clock = _Clock(traced=True)
                pipeline(clock, ws, names, out_path)
            finally:
                tracemalloc.stop()
            row["memory"] = _memory_summary(clock, budget)
        if kind == "template":
            argv = ["--base-template", names[0], "--head-template", names[1]]
        else:
            argv = ["--base-report", names[0], "--head-report", names[1]]
            for code in REPORT_DECLARATIONS:
                argv += ["--declare", code]
        row["cli"] = _cli(ws, argv, cli_runs if cli_runs is not None else runs, out_path)
        if phases:
            row["pipeline_matches_cli"] = row["pipeline_sha256"] == row["cli"]["stdout_sha256"]
    finally:
        if not keep:
            shutil.rmtree(ws, ignore_errors=True)
            for suffix in (".out", ".stderr"):
                (work / (case + suffix)).unlink(missing_ok=True)
    return row


def exp_template(work: Path, runs: int, keep: bool, fmt: str) -> List[Dict[str, Any]]:
    import gen_inputs

    rows = []
    for mode in gen_inputs.CHANGE_MODES:
        base, head, resources = gen_inputs.template_pair(NEAR_LIMIT, fmt, mode)
        row = _measure_case(work, "template_{0}_{1}".format(fmt, mode), "template",
                            {"base." + fmt: base, "head." + fmt: head}, runs, keep)
        row.update({"fmt": fmt, "mode": mode, "resources": resources})
        rows.append(row)
    return rows


def exp_template_json(work: Path, runs: int, keep: bool) -> List[Dict[str, Any]]:
    return exp_template(work, runs, keep, "json")


def exp_template_yaml(work: Path, runs: int, keep: bool) -> List[Dict[str, Any]]:
    return exp_template(work, runs, keep, "yaml")


def exp_report(work: Path, runs: int, keep: bool) -> List[Dict[str, Any]]:
    import gen_inputs
    from iacreview import report

    rows = []
    for mode in ("same", "all_new", "null_groups"):
        base, head = gen_inputs.report_pair(4000, 3, mode)
        row = _measure_case(work, "report_{0}".format(mode), "report",
                            {"base.json": report.dump(base), "head.json": report.dump(head)}, runs, keep)
        row.update({"mode": mode, "findings": 4000, "evidence_per_finding": 3})
        rows.append(row)
    return rows


def exp_boundary(work: Path, runs: int, keep: bool) -> List[Dict[str, Any]]:
    """MAX_CHANGE_ENTRIES exactly and + 1, through the whole CLI."""
    import gen_inputs
    from iacreview import deltaschema

    limit = deltaschema.MAX_CHANGE_ENTRIES
    rows = []
    for fmt, entries, phases, cli_runs in (("json", limit, True, runs), ("json", limit + 1, False, 1),
                                           ("yaml", limit, True, runs)):
        base, head, resources = gen_inputs.change_entry_pair(entries, fmt)
        row = _measure_case(work, "boundary_{0}_{1}".format(fmt, entries), "template",
                            {"base." + fmt: base, "head." + fmt: head}, runs, keep, phases=phases, cli_runs=cli_runs)
        row.update({"fmt": fmt, "requested_change_entries": entries, "resources": resources})
        rows.append(row)
    return rows


def _largest_disjoint_reports(evidence: int) -> Tuple[int, Dict[str, Any], Dict[str, Any]]:
    import gen_inputs
    from iacreview import report

    findings = 7000
    while True:
        base, head = gen_inputs.report_pair_disjoint(findings, evidence)
        if max(len(report.dump(base).encode("utf-8")), len(report.dump(head).encode("utf-8"))) <= 5 * MIB:
            return findings, base, head
        findings -= 50


def exp_worst_output(work: Path, runs: int, keep: bool) -> List[Dict[str, Any]]:
    """The largest Delta_Report in-limit inputs give: 200,000 Change_Entries and
    the most one-sided Delta_Entries two 5 MiB Reports can hold."""
    import gen_inputs
    from iacreview import deltaschema, report

    findings, base_r, head_r = _largest_disjoint_reports(1)
    rows = []
    # Report side alone (Delta_Entry bytes, M1-4)
    row = _measure_case(work, "report_disjoint_max", "report",
                        {"base.json": report.dump(base_r), "head.json": report.dump(head_r)}, runs, keep)
    row.update({"findings_each_side": findings, "evidence_per_finding": 1})
    rows.append(row)
    # Both pairs together through the CLI: output bytes against the limit
    base_t, head_t, _ = gen_inputs.change_entry_pair(deltaschema.MAX_CHANGE_ENTRIES, "json")
    files = {"base.json": base_t, "head.json": head_t,
             "rbase.json": report.dump(base_r), "rhead.json": report.dump(head_r)}
    ws = _write_case(work, "combined_worst", files)
    out_path = work / "combined_worst.out"
    try:
        argv = ["--base-template", "base.json", "--head-template", "head.json",
                "--base-report", "rbase.json", "--head-report", "rhead.json"]
        cli = _cli(ws, argv, 1, out_path)
        old_cwd = os.getcwd()
        os.chdir(ws)
        try:
            from iacreview import deltacli

            tracemalloc.start()
            try:
                with (work / "combined_worst.traced").open("w", encoding="utf-8") as sink:
                    exit_code = deltacli.main(argv, stdout=sink, stderr=io.StringIO())
                _, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
        finally:
            os.chdir(old_cwd)
        rows.append({"exp": "case", "case": "combined_worst", "kind": "combined",
                     "input_bytes": {k: len(v.encode("utf-8")) for k, v in files.items()},
                     "findings_each_side": findings, "cli": cli,
                     "in_process_cli_exit": exit_code, "in_process_cli_peak_traced_mib": round(peak / MIB, 1)})
    finally:
        if not keep:
            shutil.rmtree(ws, ignore_errors=True)
            for suffix in (".out", ".stderr", ".traced"):
                (work / ("combined_worst" + suffix)).unlink(missing_ok=True)
    return rows


def _top(profile: cProfile.Profile, limit: int) -> List[Dict[str, Any]]:
    stats = pstats.Stats(profile)
    rows = []
    for (filename, line, func), (cc, nc, tt, ct, _callers) in stats.stats.items():  # type: ignore[attr-defined]
        rows.append({"function": "{0}:{1}:{2}".format(Path(filename).name, line, func),
                     "ncalls": nc, "tottime_s": round(tt, 4), "cumtime_s": round(ct, 4)})
    rows.sort(key=lambda r: r["tottime_s"], reverse=True)
    return rows[:limit]


def exp_profile(work: Path, runs: int, keep: bool) -> List[Dict[str, Any]]:
    """Where the JSON all-leaf pair spends its time (M1-2)."""
    import gen_inputs
    from iacreview import report, semdiff

    base, head, _ = gen_inputs.template_pair(NEAR_LIMIT, "json", "all_leaves")
    ws = _write_case(work, "profile", {"base.json": base, "head.json": head})
    out_path = work / "profile.out"
    rows: List[Dict[str, Any]] = []
    try:
        clock = _Clock()
        _, built = _template_pipeline(clock, ws, ("base.json", "head.json"), out_path)
        # semdiff internals, timed separately
        from iacreview import deltaio

        parsed = []
        for side, name in (("base", "base.json"), ("head", "head.json")):
            text = (ws / name).read_text(encoding="utf-8")
            parsed.append(deltaio.parse_template(text, ws / name, side))
        differ_samples, limitation_samples, total_samples = [], [], []
        for _ in range(runs):
            start = time.perf_counter()
            semdiff._Differ(parsed[0], parsed[1]).run()
            differ_samples.append(time.perf_counter() - start)
            start = time.perf_counter()
            semdiff._scan_limitations(parsed[0].doc)
            semdiff._scan_limitations(parsed[1].doc)
            limitation_samples.append(time.perf_counter() - start)
            start = time.perf_counter()
            semdiff.diff(parsed[0], parsed[1])
            total_samples.append(time.perf_counter() - start)
        rows.append({"exp": "semdiff_internals", "differ_run": _stats(differ_samples),
                     "scan_limitations_both": _stats(limitation_samples), "diff_total": _stats(total_samples)})
        # serializer: report.dump (indent=2, pure-Python encoder) against the C encoder (no indent)
        dump_samples, compact_samples = [], []
        for _ in range(runs):
            start = time.perf_counter()
            report.dump(built)
            dump_samples.append(time.perf_counter() - start)
            start = time.perf_counter()
            json.dumps(built, sort_keys=True, ensure_ascii=False)
            compact_samples.append(time.perf_counter() - start)
        rows.append({"exp": "serializer", "report_dump_indent2": _stats(dump_samples),
                     "json_dumps_no_indent_c_encoder": _stats(compact_samples),
                     "note": "the no-indent bytes differ from report.dump; diagnostic only"})
        for name, fn in (("semdiff.diff", lambda: semdiff.diff(parsed[0], parsed[1])),
                         ("render_and_serialize", lambda: _template_pipeline(_Clock(), ws, ("base.json", "head.json"), out_path))):
            profile = cProfile.Profile()
            profile.enable()
            fn()
            profile.disable()
            rows.append({"exp": "profile", "target": name, "top_tottime": _top(profile, 25)})
    finally:
        if not keep:
            shutil.rmtree(ws, ignore_errors=True)
            out_path.unlink(missing_ok=True)
    return rows


EXPERIMENTS: Dict[str, Callable[[Path, int, bool], List[Dict[str, Any]]]] = {
    "template_json": exp_template_json,
    "report": exp_report,
    "boundary": exp_boundary,
    "worst_output": exp_worst_output,
    "profile": exp_profile,
    "template_yaml": exp_template_yaml,
}


def _child(name: str, work: Path, runs: int, keep: bool) -> None:
    resource.setrlimit(resource.RLIMIT_CPU, (CHILD_CPU_SECONDS, CHILD_CPU_SECONDS))
    sys.path.insert(0, str(PLUGIN_ROOT))
    sys.path.insert(0, str(PERF_DIR))
    work.mkdir(parents=True, exist_ok=True)
    for row in EXPERIMENTS[name](work, runs, keep):
        print(json.dumps(row, sort_keys=True, default=str), flush=True)
    usage = resource.getrusage(resource.RUSAGE_SELF)
    print(json.dumps({"exp": name, "child_cpu_s": round(usage.ru_utime + usage.ru_stime, 2)}), flush=True)


def _outside_repository(parser: argparse.ArgumentParser, path: Path, option: str) -> Path:
    resolved = path.resolve()
    if resolved == PLUGIN_ROOT or PLUGIN_ROOT in resolved.parents:
        parser.error("{0} must be outside the repository".format(option))
    return resolved


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--work", required=True, help="directory for generated inputs (outside the repository)")
    parser.add_argument("--out", required=True, help="JSON lines file (outside the repository)")
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--only", choices=sorted(EXPERIMENTS), action="append")
    parser.add_argument("--keep", action="store_true", help="keep generated inputs")
    parser.add_argument("--cli-only", action="store_true", help="measure the CLI subprocess only")
    parser.add_argument("--child", choices=sorted(EXPERIMENTS))
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be positive")
    work = _outside_repository(parser, Path(args.work), "--work")
    out = _outside_repository(parser, Path(args.out), "--out")
    if args.child:
        global CLI_ONLY
        CLI_ONLY = args.cli_only
        _child(args.child, work, args.runs, args.keep)
        return 0
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(_env(args.runs)) + "\n")
        for name in args.only or list(EXPERIMENTS):
            start = time.perf_counter()
            command = [sys.executable, __file__, "--child", name, "--work", str(work), "--out", str(out),
                       "--runs", str(args.runs)] + (["--keep"] if args.keep else []) + (
                           ["--cli-only"] if args.cli_only else [])
            try:
                proc = subprocess.run(command, capture_output=True, text=True, timeout=CHILD_WALL_SECONDS)
                handle.write(proc.stdout)
                status: Dict[str, Any] = {"exp": name, "child_exit": proc.returncode, "stderr_tail": proc.stderr[-2000:]}
            except subprocess.TimeoutExpired:
                status = {"exp": name, "child_exit": "timeout", "timeout_s": CHILD_WALL_SECONDS}
            status["wall_s"] = round(time.perf_counter() - start, 1)
            handle.write(json.dumps(status) + "\n")
            handle.flush()
            print(json.dumps(status), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
