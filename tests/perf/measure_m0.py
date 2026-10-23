"""Gate M0 measurement harness for the v1.1 Delta_Tool (tasks.md Task 0.4).

Usage (from the plugin root)::

    PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 tests/perf/measure_m0.py \
        --prototype "$TMPDIR/<prototype dir>" --out "$TMPDIR/<dir>/m0.jsonl"

Each experiment runs in its own child process with ``RLIMIT_CPU`` and a wall
timeout. Results are written as JSON lines to ``--out``, which must be outside
the repository. The comparison steps are provided by a throwaway prototype
module (``proto_delta.py``) that lives outside the repository (Requirement 14
AC12); this harness only drives and times it, together with the existing
v1.0 parser.

Not collected by pytest (the file name does not start with ``test_``). Results
are diagnostics for a Human decision, never a pass / fail gate (Requirement 14
AC10).
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import resource
import statistics
import subprocess
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Any, Callable, Dict, List

PLUGIN_ROOT = Path(__file__).resolve().parents[2]
MIB = 1024 * 1024
#: Largest size the existing reader accepts is 5 MiB; generated inputs aim just below it.
NEAR_LIMIT = int(5 * MIB * 0.97)
CANDIDATE_NODES = 3_000_000
CANDIDATE_DEPTH = 64
CHILD_CPU_SECONDS = 900
CHILD_WALL_SECONDS = 1200
CHILD_ADDRESS_SPACE = 6 * 1024 * MIB


def _env() -> Dict[str, Any]:
    import yaml

    return {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_count": os.cpu_count(),
        "pyyaml": yaml.__version__,
        "pyyaml_libyaml": hasattr(yaml, "CSafeLoader"),
    }


def _timed(fn: Callable[[], Any], runs: int) -> Dict[str, Any]:
    samples: List[float] = []
    result: Any = None
    for _ in range(runs):
        start = time.perf_counter()
        result = fn()
        samples.append(time.perf_counter() - start)
    return {"runs": runs, "median_s": round(statistics.median(samples), 4), "max_s": round(max(samples), 4),
            "min_s": round(min(samples), 4), "result": result}


def _peak(fn: Callable[[], Any]) -> Dict[str, Any]:
    tracemalloc.start()
    start = time.perf_counter()
    try:
        fn()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return {"peak_traced_mib": round(peak / MIB, 1), "wall_with_tracemalloc_s": round(time.perf_counter() - start, 3)}


# ---------------------------------------------------------------------------
# experiments (run inside the child)
# ---------------------------------------------------------------------------


def exp_parse_scale(proto: Any) -> List[Dict[str, Any]]:
    import gen_inputs
    from iacreview import template

    rows = []
    for fmt in ("json", "yaml"):
        for target in (MIB // 2, MIB, 2 * MIB, NEAR_LIMIT):
            base, _, resources = gen_inputs.template_pair(target, fmt, "none")
            size = len(base.encode("utf-8"))
            existing = _timed(lambda: template.parse_template_text(base, Path("t." + fmt))[0] is not None, 5)
            row: Dict[str, Any] = {"exp": "parse_scale", "fmt": fmt, "bytes": size, "resources": resources,
                                   "existing_parse": existing}
            if fmt == "yaml":
                single = _timed(lambda: proto.single_pass_yaml(base)[0] is not None, 5)
                row["single_pass_marking"] = single
                row["overhead_ratio_median"] = round(single["median_s"] / existing["median_s"], 3)
                doc_a = template.parse_template_text(base, Path("t.yaml"))[0]
                doc_b = proto.single_pass_yaml(base)[0]
                row["single_pass_doc_equal"] = doc_a == doc_b
            if target in (MIB, NEAR_LIMIT):
                row["existing_parse_memory"] = _peak(lambda: template.parse_template_text(base, Path("t." + fmt)))
                if fmt == "yaml":
                    row["single_pass_memory"] = _peak(lambda: proto.single_pass_yaml(base))
            rows.append(row)
    return rows


def exp_pair_memory(proto: Any) -> List[Dict[str, Any]]:
    import gen_inputs
    from iacreview import template

    rows = []
    for fmt in ("json", "yaml"):
        base, head, _ = gen_inputs.template_pair(NEAR_LIMIT, fmt, "one_percent")

        def both() -> None:
            a = template.parse_template_text(base, Path("b." + fmt))[0]
            b = template.parse_template_text(head, Path("h." + fmt))[0]
            proto.check_structure(a, CANDIDATE_NODES, CANDIDATE_DEPTH)
            proto.check_structure(b, CANDIDATE_NODES, CANDIDATE_DEPTH)
            proto.diff(a, b, 10 ** 7)

        rows.append({"exp": "pair_memory", "fmt": fmt, "bytes_each": len(base.encode("utf-8")), **_peak(both)})
    return rows


def exp_structure(proto: Any) -> List[Dict[str, Any]]:
    import gen_inputs
    from iacreview import template

    rows = []
    base, _, _ = gen_inputs.template_pair(NEAR_LIMIT, "yaml", "none")
    doc = template.parse_template_text(base, Path("t.yaml"))[0]
    timed = _timed(lambda: proto.check_structure(doc, CANDIDATE_NODES, CANDIDATE_DEPTH), 5)
    rows.append({"exp": "structure_normal_5mib_yaml", **timed,
                 "memory": _peak(lambda: proto.check_structure(doc, CANDIDATE_NODES, CANDIDATE_DEPTH))})
    rows.append({"exp": "structure_early_stop", "cap": 1000,
                 **_timed(lambda: proto.check_structure(doc, 1000, CANDIDATE_DEPTH), 5)})
    for levels in (6, 7, 8):
        obj, logical = gen_inputs.shared_fanout_object(levels, 10)
        rows.append({"exp": "structure_fanout_object", "levels": levels, "logical_nodes_closed_form": logical,
                     "at_candidate_cap": _timed(lambda: proto.check_structure(obj, CANDIDATE_NODES, CANDIDATE_DEPTH), 5),
                     "cap_equal_logical": proto.check_structure(obj, logical, CANDIDATE_DEPTH)[0],
                     "cap_logical_minus_1": proto.check_structure(obj, logical - 1, CANDIDATE_DEPTH)[0]})
    bomb = (PLUGIN_ROOT / "tests" / "fixtures" / "invalid" / "billion_laughs.yaml").read_text(encoding="utf-8")
    bomb_doc = template.parse_template_text(bomb, Path("b.yaml"))[0]
    rows.append({"exp": "structure_billion_laughs", **_timed(lambda: proto.check_structure(bomb_doc, CANDIDATE_NODES, CANDIDATE_DEPTH), 5),
                 "exact": proto.check_structure(bomb_doc, 10 ** 12, 10 ** 6)})
    for kind in ("list", "mapping", "resource"):
        cdoc = template.parse_template_text(gen_inputs.cycle_yaml(kind), Path("c.yaml"))[0]
        rows.append({"exp": "structure_cycle", "kind": kind, **_timed(lambda: proto.check_structure(cdoc, CANDIDATE_NODES, CANDIDATE_DEPTH), 5)})
    for depth in (CANDIDATE_DEPTH, CANDIDATE_DEPTH + 1):
        ddoc = gen_inputs.nested_list_document(depth)
        rows.append({"exp": "structure_depth", "depth": depth, "status": proto.check_structure(ddoc, CANDIDATE_NODES, CANDIDATE_DEPTH)})
    return rows


def exp_diff_scale(proto: Any) -> List[Dict[str, Any]]:
    import gen_inputs
    from iacreview import template

    rows = []
    for fmt in ("json", "yaml"):
        for mode in ("none", "one_percent", "all_leaves"):
            base, head, resources = gen_inputs.template_pair(NEAR_LIMIT, fmt, mode)
            a = template.parse_template_text(base, Path("b." + fmt))[0]
            b = template.parse_template_text(head, Path("h." + fmt))[0]
            timed = _timed(lambda: len(proto.diff(a, b, 10 ** 7)), 5)
            changes = proto.diff(a, b, 10 ** 7)
            entry_bytes = proto.entry_json_bytes(changes) if changes else 0
            rows.append({"exp": "diff_scale", "fmt": fmt, "mode": mode, "resources": resources,
                         "changes": len(changes), **{k: v for k, v in timed.items() if k != "result"},
                         "entries_json_bytes": entry_bytes,
                         "bytes_per_entry": round(entry_bytes / len(changes), 1) if changes else None})
    # Shared (alias) subtree compared path by path. Only inputs whose logical size
    # is at or below the candidate cap are walked; the size is known in closed
    # form and confirmed with the DAG check before any tree walk.
    for levels in (5, 6):
        text, refs, logical = gen_inputs.alias_fanout_yaml(levels, 10)
        if logical > CANDIDATE_NODES:
            raise AssertionError("refusing to walk a tree above the candidate cap")
        a = template.parse_template_text(text, Path("f.yaml"))[0]
        b = template.parse_template_text(text, Path("f.yaml"))[0]
        assert proto.check_structure(a, CANDIDATE_NODES, CANDIDATE_DEPTH)[0] == "ok"
        rows.append({"exp": "diff_shared_tree_below_cap", "alias_references": refs, "logical_nodes": logical,
                     **{k: v for k, v in _timed(lambda: len(proto.diff(a, b, 10 ** 7)), 5).items() if k != "result"}})
    return rows


def exp_report_scale(proto: Any) -> List[Dict[str, Any]]:
    import gen_inputs
    from iacreview import report
    from iacreview.finding import from_dict

    rows = []
    for findings in (1000, 4000, 10000):
        for evidence in (1, 3):
            base, head = gen_inputs.report_pair(findings, evidence, "same")
            text = report.dump(head)
            size = len(text.encode("utf-8"))

            def load() -> int:
                obj = json.loads(text)
                return len([from_dict(d) for d in obj["findings"]])

            def rebuild() -> bool:
                obj = json.loads(text)
                meta = report.ReportMeta(files=obj["target"]["files"], sources_enabled=obj["sources_enabled"], tools=[],
                                         cdk_detected=obj["target"]["cdk"]["detected"],
                                         synthesized_templates=obj["target"]["cdk"]["synthesized_templates"],
                                         cdk_synthesis=obj["target"]["cdk"]["synthesis"])
                rebuilt = report.build_report([from_dict(d) for d in obj["findings"]], [], meta)
                return report.dump(rebuilt) == text

            rows.append({"exp": "report_scale", "findings": findings, "evidence_per_finding": evidence, "bytes": size,
                         "fits_5mib": size <= 5 * MIB,
                         "load_validate": {k: v for k, v in _timed(load, 5).items() if k != "result"},
                         "rebuild_compare": _timed(rebuild, 5),
                         "load_memory": _peak(load)})
    for mode in ("same", "all_new", "null_groups"):
        base, head = gen_inputs.report_pair(10000, 1, mode)
        rows.append({"exp": "match_10000", "mode": mode,
                     **_timed(lambda: proto.match(base["findings"], head["findings"]), 5)})
    return rows


def exp_alias_construct(proto: Any) -> List[Dict[str, Any]]:
    import gen_inputs
    from iacreview import template, yamlcfn
    from iacreview.errors import TemplateParseError

    rows = []
    for refs in (1000, yamlcfn.MAX_ALIAS_EXPANSIONS, yamlcfn.MAX_ALIAS_EXPANSIONS + 1):
        text = gen_inputs.alias_reference_heavy_yaml(refs)

        def parse() -> str:
            try:
                template.parse_template_text(text, Path("a.yaml"))
                return "parsed"
            except TemplateParseError:
                return "parse_failure"

        rows.append({"exp": "alias_reference_heavy", "references": refs, "bytes": len(text.encode("utf-8")), **_timed(parse, 5)})
    return rows


EXPERIMENTS: Dict[str, Callable[[Any], List[Dict[str, Any]]]] = {
    "parse_scale": exp_parse_scale,
    "pair_memory": exp_pair_memory,
    "structure": exp_structure,
    "diff_scale": exp_diff_scale,
    "report_scale": exp_report_scale,
    "alias_construct": exp_alias_construct,
}


def _child(name: str, prototype: str) -> None:
    resource.setrlimit(resource.RLIMIT_CPU, (CHILD_CPU_SECONDS, CHILD_CPU_SECONDS))
    applied_as = True
    try:
        resource.setrlimit(resource.RLIMIT_AS, (CHILD_ADDRESS_SPACE, CHILD_ADDRESS_SPACE))
    except (ValueError, OSError):
        applied_as = False
    sys.path.insert(0, str(PLUGIN_ROOT))
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    sys.path.insert(0, prototype)
    import proto_delta  # noqa: E402  (outside the repository)

    for row in EXPERIMENTS[name](proto_delta):
        row["rlimit_as_applied"] = applied_as
        print(json.dumps(row, sort_keys=True, default=str), flush=True)
    usage = resource.getrusage(resource.RUSAGE_SELF)
    print(json.dumps({"exp": name, "child_maxrss_bytes_macos_or_kib_linux": usage.ru_maxrss,
                      "child_cpu_s": round(usage.ru_utime + usage.ru_stime, 2)}), flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--prototype", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--only", choices=sorted(EXPERIMENTS), action="append")
    parser.add_argument("--child", choices=sorted(EXPERIMENTS))
    args = parser.parse_args()
    if args.child:
        _child(args.child, args.prototype)
        return 0
    out = Path(args.out).resolve()
    if PLUGIN_ROOT in out.parents:
        parser.error("--out must be outside the repository")
    with out.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"exp": "environment", **_env()}) + "\n")
        for name in args.only or list(EXPERIMENTS):
            start = time.perf_counter()
            try:
                proc = subprocess.run([sys.executable, __file__, "--child", name, "--prototype", args.prototype, "--out", str(out)],
                                      capture_output=True, text=True, timeout=CHILD_WALL_SECONDS)
                handle.write(proc.stdout)
                status = {"exp": name, "child_exit": proc.returncode, "stderr_tail": proc.stderr[-1500:]}
            except subprocess.TimeoutExpired:
                status = {"exp": name, "child_exit": "timeout", "timeout_s": CHILD_WALL_SECONDS}
            status["wall_s"] = round(time.perf_counter() - start, 1)
            handle.write(json.dumps(status) + "\n")
            handle.flush()
            print(json.dumps(status), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
