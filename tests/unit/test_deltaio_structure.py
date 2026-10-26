"""Unit tests for :func:`iacreview.deltaio.check_structure` (v1.1 Task 4, Design 2-5).

The structure check walks a parsed document as a graph: each container is
expanded once, and the tree's logical node count and depth are memoised sums
that saturate at the limit + 1. These tests pin the cycle detection, the limits
at and one above their value (set small with ``monkeypatch``), the order in
which failures are reported, the early stop on the visited-container count,
that DAG sharing is not taken for a cycle, and that no recursion is used.

Safety: no test builds a large tree. The alias fan-out fixture is checked with
the shipped limits and, once, in a child process with a CPU limit.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

import pytest

from iacreview import deltaio, deltaschema
from iacreview.deltaio import Failure, ParsedTemplate, Shape

REPO_ROOT = Path(__file__).resolve().parents[2]
DELTA_TEMPLATES = REPO_ROOT / "tests" / "fixtures" / "delta" / "templates"
ALIAS_BOMB = REPO_ROOT / "tests" / "fixtures" / "invalid" / "billion_laughs.yaml"
PATH = Path("structure.yaml")


def _parse(text: str, side: str = "head") -> Any:
    return deltaio.parse_template(text, PATH, side)


def _limits(monkeypatch: pytest.MonkeyPatch, nodes: int, depth: int) -> None:
    monkeypatch.setattr(deltaschema, "MAX_TEMPLATE_NODES", nodes)
    monkeypatch.setattr(deltaschema, "MAX_TEMPLATE_DEPTH", depth)


def _expected(name: str) -> Dict[str, Any]:
    return json.loads((DELTA_TEMPLATES / name / "expected.json").read_text(encoding="utf-8"))


def _side_text(name: str, side: str) -> str:
    inputs = _expected(name)["inputs"]
    if side == "head" and "head_ref" in inputs:
        return (REPO_ROOT / inputs["head_ref"]).read_text(encoding="utf-8")
    return (DELTA_TEMPLATES / name / inputs[side]).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# cycles
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["cycle_list", "cycle_mapping", "cycle_inside_resource"])
def test_alias_cycles_are_template_alias_cycle(name: str) -> None:
    """R2.12: three kinds of reference cycle, from the Task 2 fixtures."""
    expected = _expected(name)["expected"]["failure"]
    base = _parse(_side_text(name, "base"), "base")
    assert isinstance(base, ParsedTemplate)
    head = _parse(_side_text(name, "head"))
    assert isinstance(head, Failure)
    assert (head.side, head.input, head.code) == (expected["side"], expected["input"], expected["code"])
    assert head.code == "template_alias_cycle"
    assert head.error_class == "parse_failure" and head.exit_code == 4


@pytest.mark.parametrize("name", ["cycle_inside_short_tag", "alias_forward_reference"])
def test_short_tag_cycle_and_forward_reference_are_parse_failures(name: str) -> None:
    head = _parse(_side_text(name, "head"))
    assert isinstance(head, Failure) and head.code == "template_parse_failure"


def test_cycle_built_in_python_is_detected() -> None:
    loop: List[Any] = []
    loop.append({"x": loop})
    result = deltaio.check_structure({"Resources": {"R": loop}})
    assert isinstance(result, Failure) and result.code == "template_alias_cycle"


def test_self_containing_root() -> None:
    root: Dict[str, Any] = {}
    root["Resources"] = root
    result = deltaio.check_structure(root, "base")
    assert isinstance(result, Failure) and result.code == "template_alias_cycle" and result.side == "base"


def test_dag_sharing_is_not_a_cycle() -> None:
    """A diamond: one object reached through two parents, counted twice."""
    shared = [1, 2]
    doc = {"Resources": {"A": {"x": shared}, "B": {"y": shared}}}
    result = deltaio.check_structure(doc)
    assert result == Shape(nodes=1 + 1 + 2 * (1 + 3), depth=5, containers=5)


def test_the_same_child_twice_in_one_parent_is_not_a_cycle() -> None:
    shared = {"k": 1}
    assert deltaio.check_structure([shared, shared]) == Shape(nodes=5, depth=3, containers=2)


# ---------------------------------------------------------------------------
# !!pairs / !!omap: lists of (key, value) tuples (regression, phase 1 review P1-1)
# ---------------------------------------------------------------------------

_PAIRS_CYCLE = "Resources:\n  R:\n    Type: AWS::S3::Bucket\n    Properties:\n      P: &p {tag} [ {{k: *p}} ]\n"


@pytest.mark.parametrize("tag", ["!!pairs", "!!omap"])
def test_cycle_through_pairs_or_omap_is_template_alias_cycle(tag: str) -> None:
    """R2.12: the alias sits in a tuple built by the tag; it must not be a leaf."""
    result = _parse(_PAIRS_CYCLE.format(tag=tag))
    assert isinstance(result, Failure) and result.code == "template_alias_cycle"


def test_cycle_through_a_tuple_built_in_python_is_detected() -> None:
    loop: List[Any] = []
    loop.append(("k", loop))
    result = deltaio.check_structure({"Resources": {"R": loop}})
    assert isinstance(result, Failure) and result.code == "template_alias_cycle"


def test_pairs_are_counted_as_containers() -> None:
    """Each tuple is a container whose two elements are children.

    a0 = 1 list + 2 x (tuple + key + scalar) = 7; a1 = 1 + 2 x (1 + 1 + 7) = 19;
    root = 1 + 7 + 19 = 27. Depth: root, a1, tuple, a0, tuple, scalar = 6.
    Containers: root, 2 lists, 4 tuples = 7.
    """
    text = "a0: &a0 !!pairs [{k: x}, {k: y}]\na1: !!pairs [{k: *a0}, {k: *a0}]\n"
    parsed = deltaio.parse_document(text, PATH, "head")
    assert not isinstance(parsed, Failure)
    assert deltaio.check_structure(parsed.doc) == Shape(nodes=27, depth=6, containers=7)


def _pairs_bomb(levels: int, width: int) -> str:
    """A billion-laughs variant whose aliases sit inside ``!!pairs`` tuples."""
    lines = ["Resources:", "  R:", "    Type: AWS::S3::Bucket", "    Properties:"]
    leaf = ", ".join("{{k{0}: x}}".format(i) for i in range(width))
    lines.append("      a0: &a0 !!pairs [{0}]".format(leaf))
    for level in range(1, levels):
        items = ", ".join("{{k{0}: *a{1}}}".format(i, level - 1) for i in range(width))
        lines.append("      a{0}: &a{0} !!pairs [{1}]".format(level, items))
    return "\n".join(lines) + "\n"


def test_pairs_fan_out_is_refused_with_the_shipped_limits() -> None:
    """10 levels x 10: about 3.3 x 10 ** 10 logical nodes from 110 real containers."""
    assert deltaschema.MAX_TEMPLATE_NODES == 3000000
    start = time.perf_counter()
    result = _parse(_pairs_bomb(levels=10, width=10))
    elapsed = time.perf_counter() - start
    assert isinstance(result, Failure) and result.code == "template_node_limit_exceeded"
    assert elapsed < 1.0


def test_pairs_fan_out_is_counted_without_expanding(monkeypatch: pytest.MonkeyPatch) -> None:
    """Level sizes: s0 = 1 + w x 3, s(n) = 1 + w x (2 + s(n-1)); w = 10 gives
    s(n) = (10 ** (n + 2) - 1) / 3 - 2. Properties holds a0..a9 (values only)."""
    _limits(monkeypatch, 10 ** 12, 64)
    sizes = [(10 ** (n + 2) - 1) // 3 - 2 for n in range(10)]
    properties = 1 + sum(sizes)
    resource = 1 + 1 + properties  # R, Type scalar, Properties
    root = 1 + 1 + resource  # root, Resources
    result = _parse(_pairs_bomb(levels=10, width=10))
    assert isinstance(result, ParsedTemplate)
    # Depth: root, Resources, R, Properties, then list + tuple per level, then the scalar.
    assert result.shape == Shape(nodes=root, depth=4 + 2 * 10 + 1, containers=4 + 10 * 11)


# ---------------------------------------------------------------------------
# fan-out without expansion
# ---------------------------------------------------------------------------


def test_alias_bomb_is_refused_with_the_shipped_limits() -> None:
    assert deltaschema.MAX_TEMPLATE_NODES == 3000000
    start = time.perf_counter()
    result = _parse(ALIAS_BOMB.read_text(encoding="utf-8"))
    elapsed = time.perf_counter() - start
    assert isinstance(result, Failure) and result.code == "template_node_limit_exceeded"
    assert result.error_class == "input_too_large" and result.exit_code == 3
    assert elapsed < 1.0


def test_alias_bomb_is_counted_exactly_without_expanding(monkeypatch: pytest.MonkeyPatch) -> None:
    """Design F-14: 1,234,567,901 logical nodes, depth 12, 11 real containers."""
    _limits(monkeypatch, 10 ** 10, 64)
    shape = _expected("billion_laughs_reference")["expected"]["shapes"]["head"]
    result = _parse(ALIAS_BOMB.read_text(encoding="utf-8"))
    assert isinstance(result, ParsedTemplate)
    assert result.shape == Shape(nodes=shape["nodes"], depth=shape["depth"], containers=shape["containers"])
    # Visited containers never exceed the containers that exist.
    assert result.shape.containers == 11


def test_alias_bomb_in_a_child_process_with_a_cpu_limit() -> None:
    code = (
        "import resource, sys\n"
        "resource.setrlimit(resource.RLIMIT_CPU, (20, 20))\n"
        "from pathlib import Path\n"
        "from iacreview import deltaio\n"
        "p = Path(sys.argv[1])\n"
        "r = deltaio.parse_template(p.read_text(encoding='utf-8'), p, 'head')\n"
        "print(r.code)\n"
    )
    completed = subprocess.run(
        [sys.executable, "-c", code, str(ALIAS_BOMB)],
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
        env=dict(os.environ, PYTHONPATH=str(REPO_ROOT)),
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    assert completed.stdout.decode("utf-8").strip() == "template_node_limit_exceeded"


# ---------------------------------------------------------------------------
# limits: exactly at and one above
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["node_limit_boundary", "depth_limit_boundary"])
def test_boundary_fixtures(name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    doc = _expected(name)
    for constant, value in doc["limits"].items():
        monkeypatch.setattr(deltaschema, constant, value)
    shapes = doc["expected"]["shapes"]
    base = _parse(_side_text(name, "base"), "base")
    assert isinstance(base, ParsedTemplate)
    assert base.shape == Shape(**shapes["base"])
    head = _parse(_side_text(name, "head"))
    assert isinstance(head, Failure)
    assert head.code == doc["expected"]["failure"]["code"] and head.side == "head"


def test_boundary_fixtures_pass_with_the_shipped_limits() -> None:
    for name in ("node_limit_boundary", "depth_limit_boundary"):
        shapes = _expected(name)["expected"]["shapes"]
        head = _parse(_side_text(name, "head"))
        assert isinstance(head, ParsedTemplate)
        assert head.shape == Shape(**shapes["head"])


def _chain(depth: int) -> Any:
    """A list nested so the document is ``depth`` deep (root = 1, leaf scalar counted)."""
    value: Any = 1
    for _ in range(depth - 1):
        value = [value]
    return value


@pytest.mark.parametrize("depth", [5, 6])
def test_depth_at_and_over_the_limit(depth: int, monkeypatch: pytest.MonkeyPatch) -> None:
    _limits(monkeypatch, 1000, 5)
    result = deltaio.check_structure(_chain(depth))
    if depth == 5:
        assert result == Shape(nodes=5, depth=5, containers=4)
    else:
        assert isinstance(result, Failure) and result.code == "template_depth_limit_exceeded"
        assert result.error_class == "input_too_large" and result.exit_code == 3


@pytest.mark.parametrize("extra,ok", [(0, True), (1, False)])
def test_logical_nodes_at_and_over_the_limit(extra: int, ok: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    shared = [1, 2, 3]  # 4 logical nodes, shared three times
    doc: Dict[str, Any] = {"a": shared, "b": shared, "c": shared}
    for i in range(extra):
        doc["x{0}".format(i)] = 0
    _limits(monkeypatch, 13, 64)  # 1 + 3 * 4 = 13
    result = deltaio.check_structure(doc)
    if ok:
        assert result == Shape(nodes=13, depth=3, containers=2)
    else:
        assert isinstance(result, Failure) and result.code == "template_node_limit_exceeded"


def test_sizes_saturate_instead_of_growing(monkeypatch: pytest.MonkeyPatch) -> None:
    # 30 real containers, about 10 ** 30 logical nodes.
    _limits(monkeypatch, 40, 64)
    code, visited, nodes, depth = deltaio._walk_structure(
        _shared_tower(levels=30, width=10)
    )
    assert code == "template_node_limit_exceeded"
    assert nodes == 41  # saturated at limit + 1
    assert visited == 30
    assert depth == 31


def _shared_tower(levels: int, width: int) -> Any:
    level: Any = ["leaf"] * width
    for _ in range(levels - 1):
        level = [level] * width
    return level


# ---------------------------------------------------------------------------
# order of the checks and the early stop
# ---------------------------------------------------------------------------


def test_cycle_is_reported_before_the_node_count(monkeypatch: pytest.MonkeyPatch) -> None:
    shared = [1, 1, 1]
    loop: List[Any] = []
    loop.append(loop)
    doc = {"Resources": {"A": [shared, shared, shared], "C": loop}}
    _limits(monkeypatch, 5, 64)  # logical nodes far above 5, containers = 5
    result = deltaio.check_structure(doc)
    assert isinstance(result, Failure) and result.code == "template_alias_cycle"


def test_early_stop_wins_over_an_unvisited_cycle(monkeypatch: pytest.MonkeyPatch) -> None:
    loop: List[Any] = []
    loop.append(loop)
    doc = {"Resources": {"A": {"B": {}}, "C": loop}}
    _limits(monkeypatch, 2, 64)
    result = deltaio.check_structure(doc)
    assert isinstance(result, Failure) and result.code == "template_node_limit_exceeded"


def test_early_stop_happens_at_limit_plus_one(monkeypatch: pytest.MonkeyPatch) -> None:
    doc = {"Resources": {"R{0}".format(i): {} for i in range(50)}}
    _limits(monkeypatch, 4, 64)
    code, visited, _, _ = deltaio._walk_structure(doc)
    assert code == "template_node_limit_exceeded"
    assert visited == 5


def test_depth_is_reported_before_the_node_count(monkeypatch: pytest.MonkeyPatch) -> None:
    doc = {"a": [[1, 1, 1, 1]]}  # 3 containers, 7 logical nodes, depth 4
    _limits(monkeypatch, 5, 3)
    result = deltaio.check_structure(doc)
    assert isinstance(result, Failure) and result.code == "template_depth_limit_exceeded"


def test_scalar_and_empty_roots() -> None:
    assert deltaio.check_structure("x") == Shape(nodes=1, depth=1, containers=0)
    assert deltaio.check_structure({}) == Shape(nodes=1, depth=1, containers=1)


def test_limits_are_read_at_call_time(monkeypatch: pytest.MonkeyPatch) -> None:
    doc = {"a": [1]}
    assert isinstance(deltaio.check_structure(doc), Shape)
    _limits(monkeypatch, 2, 64)
    assert isinstance(deltaio.check_structure(doc), Failure)


# ---------------------------------------------------------------------------
# no recursion
# ---------------------------------------------------------------------------


def _frame_depth() -> int:
    depth = 0
    frame = sys._getframe()
    while frame is not None:
        depth += 1
        frame = frame.f_back  # type: ignore[assignment]
    return depth


def test_no_python_recursion(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 3,000-deep document is walked with a recursion limit barely above the
    current stack, which any recursive walk would exceed."""
    _limits(monkeypatch, 10 ** 6, 10 ** 6)
    doc = {"Resources": {"R": _chain(3000)}}
    old = sys.getrecursionlimit()
    sys.setrecursionlimit(_frame_depth() + 40)
    try:
        result = deltaio.check_structure(doc)
    finally:
        sys.setrecursionlimit(old)
    assert result == Shape(nodes=3002, depth=3002, containers=3001)


def test_deep_document_fails_on_depth_not_recursion() -> None:
    doc = {"Resources": {"R": _chain(3000)}}
    old = sys.getrecursionlimit()
    sys.setrecursionlimit(_frame_depth() + 40)
    try:
        result = deltaio.check_structure(doc)
    finally:
        sys.setrecursionlimit(old)
    assert isinstance(result, Failure) and result.code == "template_depth_limit_exceeded"


def test_parse_template_returns_only_checked_documents(monkeypatch: pytest.MonkeyPatch) -> None:
    text = "Resources:\n  R:\n    Type: AWS::S3::Bucket\n    Properties: {A: [1, [2, [3]]]}\n"
    assert isinstance(_parse(text), ParsedTemplate)
    _limits(monkeypatch, 3000000, 5)
    result = _parse(text)
    assert isinstance(result, Failure) and result.code == "template_depth_limit_exceeded"
