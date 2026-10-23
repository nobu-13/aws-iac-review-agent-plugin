"""Unit tests for the Template side of :mod:`iacreview.deltaio` (v1.1 Task 3).

Covers the single-pass parse (Design 2-2 method B) for JSON and YAML, the
duplicate-key marking (Design 2-2-1, 2-3) against the Task 2 fixtures, the
five ``construct_object`` cases of Design F-17, ``id()`` reuse, delegation of
failures to the v1.0 parser, ``parser_divergence``, the path and read checks of
:func:`deltaio.read_template`, and that no exception text reaches a Failure.
"""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest

from iacreview import deltaio, deltaschema, template, yamlcfn
from iacreview.errors import ToolUnavailableError
from iacreview.deltaio import Failure, ParsedDocument, ParsedTemplate

REPO_ROOT = Path(__file__).resolve().parents[2]
DELTA_TEMPLATES = REPO_ROOT / "tests" / "fixtures" / "delta" / "templates"
PATH = Path("fixture.yaml")


def _doc(text: str) -> ParsedDocument:
    parsed = deltaio.parse_document(text, PATH, "head")
    assert isinstance(parsed, ParsedDocument), parsed
    return parsed


def _at(doc: Any, path: List[Any]) -> Any:
    value = doc
    for segment in path:
        value = value[segment]
    return value


def _containers(root: Any) -> List[Any]:
    """Distinct containers of an acyclic document, each once."""
    out: List[Any] = []
    seen = set()
    stack = [root]
    while stack:
        value = stack.pop()
        if not isinstance(value, (dict, list)) or id(value) in seen:
            continue
        seen.add(id(value))
        out.append(value)
        stack.extend(value.values() if isinstance(value, dict) else value)
    return out


# ---------------------------------------------------------------------------
# method B: JSON and YAML
# ---------------------------------------------------------------------------


def test_json_document_equals_the_v1_parse() -> None:
    text = '{"Resources": {"B": {"Type": "AWS::S3::Bucket", "Properties": {"N": 1.5, "F": false}}}}'
    parsed = _doc(text)
    assert parsed.fmt == "json"
    assert parsed.doc == template.parse_template_text(text, PATH)[0]
    assert len(parsed.marked) == 0
    assert parsed.duplicate_sections == ()


def test_yaml_document_equals_the_v1_parse() -> None:
    text = "Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties:\n      N: !Ref X\n      G: !GetAtt A.Arn\n"
    parsed = _doc(text)
    assert parsed.fmt == "yaml"
    assert parsed.doc == template.parse_template_text(text, PATH)[0]
    assert len(parsed.marked) == 0


def test_json_duplicate_is_last_wins_and_marked() -> None:
    parsed = _doc('{"Resources": {"B": {"Type": "A", "Type": "B"}}}')
    inner = parsed.doc["Resources"]["B"]
    assert inner == {"Type": "B"}
    assert parsed.marked.contains(inner)
    assert not parsed.marked.contains(parsed.doc["Resources"])


def test_json_duplicate_top_level_key_is_recorded_by_name() -> None:
    parsed = _doc('{"Description": "a", "Resources": {"B": {}}, "Description": "b", "Resources": {"C": {}}}')
    assert parsed.duplicate_sections == ("Description", "Resources")
    assert not parsed.marked.contains(parsed.doc)
    assert len(parsed.marked) == 0


def test_yaml_duplicate_top_level_key_is_recorded_by_name() -> None:
    parsed = _doc("Resources: {A: 1}\nOutputs: {}\nResources: {B: 2}\n")
    assert parsed.duplicate_sections == ("Resources",)
    assert parsed.doc == {"Resources": {"B": 2}, "Outputs": {}}
    assert len(parsed.marked) == 0


# ---------------------------------------------------------------------------
# duplicate keys against the Task 2 fixtures
# ---------------------------------------------------------------------------


def _duplicate_cases() -> List[Tuple[str, str, Dict[str, Any]]]:
    cases = []
    for directory in sorted(DELTA_TEMPLATES.iterdir()):
        expected = json.loads((directory / "expected.json").read_text(encoding="utf-8"))
        paths = [u for u in expected["expected"]["uncompared_paths"] if u["reason"] == "duplicate_key"]
        if paths:
            for side in ("base", "head"):
                cases.append((directory.name, side, expected))
    return cases


@pytest.mark.parametrize(
    "name,side,expected", _duplicate_cases(), ids=lambda v: v if isinstance(v, str) else ""
)
def test_duplicate_fixtures_mark_exactly_the_expected_paths(
    name: str, side: str, expected: Dict[str, Any]
) -> None:
    """R2.5: the marked objects and sections are those the fixture lists (head side)."""
    directory = DELTA_TEMPLATES / name
    text = (directory / expected["inputs"][side]).read_text(encoding="utf-8")
    parsed = _doc(text)
    paths = [u["path"] for u in expected["expected"]["uncompared_paths"] if u["reason"] == "duplicate_key"]
    if side == "base":
        # Every duplicate in these fixtures is on the Head side.
        assert len(parsed.marked) == 0 and parsed.duplicate_sections == ()
        return
    sections = sorted(p[0] for p in paths if len(p) == 1)
    assert list(parsed.duplicate_sections) == sections
    targets = [_at(parsed.doc, p) for p in paths if len(p) > 1]
    for target in targets:
        assert parsed.marked.contains(target)
    assert len(parsed.marked) == len({id(t) for t in targets})
    assert parsed.doc == template.parse_template_text(text, PATH)[0]


def test_duplicate_deep_inside_a_list() -> None:
    parsed = _doc("Resources:\n  R:\n    Properties:\n      L:\n        - {A: 1}\n        - {A: 1, A: 2}\n")
    items = parsed.doc["Resources"]["R"]["Properties"]["L"]
    assert not parsed.marked.contains(items[0])
    assert parsed.marked.contains(items[1])


def test_quoted_and_plain_spellings_of_one_key_are_duplicates() -> None:
    parsed = _doc('Resources:\n  R: {Type: a, "Type": b}\n')
    assert parsed.marked.contains(parsed.doc["Resources"]["R"])


def test_merge_key_is_not_a_duplicate() -> None:
    parsed = _doc("Resources:\n  base: &b {K: 1}\n  R: {<<: *b, K: 2, Type: AWS::S3::Bucket}\n")
    assert len(parsed.marked) == 0
    assert parsed.doc["Resources"]["R"]["K"] == 2


def test_merge_from_a_duplicate_mapping_is_marked_too() -> None:
    """A merged value inherits the last-wins ambiguity of its source."""
    parsed = _doc("Resources:\n  base: &b {K: 1, K: 3}\n  R: {<<: *b, Type: AWS::S3::Bucket}\n")
    resources = parsed.doc["Resources"]
    assert parsed.marked.contains(resources["base"])
    assert parsed.marked.contains(resources["R"])


def test_transitive_merge_into_the_root_records_the_section() -> None:
    """R2.5 (phase 1 review P1-3): the root merges b, b merges the duplicate
    mapping a; the inherited ``Resources`` must be left uncompared."""
    text = (
        "Metadata: &a\n"
        "  Resources: {X: {Type: A}}\n"
        "  Resources: {X: {Type: B}}\n"
        "Outputs: &b\n"
        "  <<: *a\n"
        "<<: *b\n"
    )
    parsed = _doc(text)
    assert parsed.duplicate_sections == ("Resources",)
    assert parsed.marked.contains(parsed.doc["Metadata"])
    assert parsed.marked.contains(parsed.doc["Outputs"])
    assert not parsed.marked.contains(parsed.doc)
    assert parsed.doc == template.parse_template_text(text, PATH)[0]


def test_direct_merge_into_the_root_records_the_section() -> None:
    text = "Metadata: &a\n  Resources: {X: 1}\n  Resources: {X: 2}\n<<: *a\n"
    assert _doc(text).duplicate_sections == ("Resources",)


def test_mapping_that_merges_a_duplicate_root_is_marked() -> None:
    """Marks flow through the root to the mappings that merge from it."""
    parsed = _doc("--- &r\nResources: {A: 1}\nResources: {B: 2}\nX: {<<: *r}\n")
    assert parsed.duplicate_sections == ("Resources",)
    assert parsed.marked.contains(parsed.doc["X"])
    assert not parsed.marked.contains(parsed.doc)


def _merge_chain(length: int, padding: int) -> str:
    """a0 repeats a key; a(n) merges a(n-1). The scan meets the chain from its
    far end, the order a fixed-point loop needs one pass per link for. Unrelated
    inline merges are added so that a scan over all merges per pass would grow."""
    lines = ["Resources:", "  a0: &a0 {k: 1, k: 2}"]
    for n in range(1, length + 1):
        lines.append("  a{0}: &a{0} {{<<: *a{1}}}".format(n, n - 1))
    for n in range(padding):
        lines.append("  p{0}: {{<<: {{k: 1}}}}".format(n))
    return "\n".join(lines) + "\n"


def test_merge_chain_propagation_examines_each_edge_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """Phase 1 review P1-2: propagation is linear in the merge edges reached."""
    length, padding = 2000, 500
    examined: List[int] = []
    original = deltaio._propagate_merge_marks

    def counting(*args: Any) -> Any:
        newly, edges = original(*args)
        examined.append(edges)
        return newly, edges

    monkeypatch.setattr(deltaio, "_propagate_merge_marks", counting)
    parsed = _doc(_merge_chain(length, padding))
    assert examined == [length]
    resources = parsed.doc["Resources"]
    for n in range(length + 1):
        assert parsed.marked.contains(resources["a{0}".format(n)])
    for n in range(padding):
        assert not parsed.marked.contains(resources["p{0}".format(n)])
    assert len(parsed.marked) == length + 1


def test_propagation_visits_each_node_once_in_the_worst_order() -> None:
    nodes = [object() for _ in range(5000)]
    root = object()
    # nodes[i + 1] merges nodes[i]; given as a mapping from source to dependents.
    dependents = {id(nodes[i]): [nodes[i + 1]] for i in range(len(nodes) - 1)}
    newly, edges = deltaio._propagate_merge_marks([nodes[0]], dependents, root)
    assert edges == len(nodes) - 1
    assert [id(n) for n in newly] == [id(n) for n in nodes[1:]]


def test_propagation_does_not_mark_the_root_but_passes_through_it() -> None:
    source, root, after = object(), object(), object()
    dependents = {id(source): [root], id(root): [after]}
    newly, edges = deltaio._propagate_merge_marks([source], dependents, root)
    assert newly == [after] and edges == 2


def test_non_string_keys_are_not_judged_duplicates() -> None:
    """Design 2-3: int / bool / null keys are left to the N-5 rule."""
    parsed = _doc("Resources:\n  R:\n    Metadata: {1: a, 1: b, true: c, true: d, ~: e, ~: f}\n")
    assert len(parsed.marked) == 0


# ---------------------------------------------------------------------------
# Design F-17: construct_object marks the final object
# ---------------------------------------------------------------------------

F17 = {
    "plain": ("Resources:\n  R:\n    Type: AWS::S3::Bucket\n    Properties: {A: 1, A: 2}\n", ["Resources", "R", "Properties"]),
    "tagged": ("Resources:\n  R:\n    Type: AWS::S3::Bucket\n    Properties: {N: !Sub {x: 1, x: 2}}\n", ["Resources", "R", "Properties", "N"]),
    "aliased": ("Resources:\n  base: &b {K: 1, K: 2}\n  R:\n    Type: AWS::S3::Bucket\n    Properties: {U: *b, V: *b}\n", ["Resources", "R", "Properties", "U"]),
    "merge_is_not_a_duplicate": ("Resources:\n  base: &b {K: 1}\n  R: {<<: *b, K: 2, Type: AWS::S3::Bucket}\n", None),
    "no_duplicate": ("Resources:\n  R: {Type: AWS::S3::Bucket, Properties: {A: 1, B: 2}}\n", None),
}


@pytest.mark.parametrize("name", sorted(F17))
def test_construct_object_cases(name: str) -> None:
    text, path = F17[name]
    parsed = _doc(text)
    assert parsed.doc == yamlcfn.load_yaml(text)
    if path is None:
        assert len(parsed.marked) == 0
        return
    target = _at(parsed.doc, path)
    assert parsed.marked.contains(target)
    if name == "aliased":
        properties = parsed.doc["Resources"]["R"]["Properties"]
        assert properties["U"] is properties["V"] is parsed.doc["Resources"]["base"]
        assert len(parsed.marked) == 1
    if name == "tagged":
        assert target == {"Fn::Sub": {"x": 2}}
        assert not parsed.marked.contains(target["Fn::Sub"])


def test_loader_subclass_leaves_the_base_registry_unchanged() -> None:
    base = yamlcfn.cfn_safe_loader()
    before = dict(base.yaml_constructors)
    _doc("Resources: {R: !Sub {a: 1, a: 2}}\n")
    assert dict(base.yaml_constructors) == before
    assert not hasattr(base, "watch")


# ---------------------------------------------------------------------------
# id() reuse
# ---------------------------------------------------------------------------


def test_only_held_objects_are_reported_as_marked() -> None:
    """Many temporary dicts are built and dropped while parsing; none of their
    ids may be mistaken for a marked object, before or after the parse."""
    items = "\n".join("      - !Sub {{k{0}: v, j: !Sub {{x: y}}}}".format(i) for i in range(500))
    text = "Resources:\n  R:\n    Properties:\n      D: {A: 1, A: 2}\n      L:\n" + items + "\n"
    parsed = _doc(text)
    marked = [obj for obj in _containers(parsed.doc) if parsed.marked.contains(obj)]
    assert marked == [parsed.doc["Resources"]["R"]["Properties"]["D"]]
    churn = [{"x": i} for i in range(20000)] + [[i] for i in range(20000)]
    assert not any(parsed.marked.contains(obj) for obj in churn)


def test_marked_objects_keep_and_discard() -> None:
    marks = deltaio.MarkedObjects()
    a, b = {"a": 1}, {"a": 1}
    marks.keep(a)
    marks.keep(a)
    assert len(marks) == 1 and marks.contains(a) and not marks.contains(b)
    marks.discard(b)
    assert marks.contains(a)
    marks.discard(a)
    assert len(marks) == 0 and not marks.contains(a)


# ---------------------------------------------------------------------------
# failures are delegated to the v1.0 parser
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "Resources:\n  R: {A: 1\n",
        '{"Resources": {"R": }',
        "Resources:\n  R: !Bogus x\n",
        "Resources:\n  R: !!python/object/apply:os.system [echo]\n",
        "---\nResources: {}\n---\nResources: {}\n",
        "",
        "   \n\ufeff",
        "\ufeff{\"Resources\": {\"R\": {}}}",
    ],
    ids=["yaml_syntax", "json_syntax", "unknown_tag", "python_tag", "two_documents", "empty", "blank", "json_bom"],
)
def test_failures_are_the_canonical_parse_failure(text: str) -> None:
    result = deltaio.parse_document(text, PATH, "base")
    assert isinstance(result, Failure)
    assert result.code == "template_parse_failure"
    assert result.error_class == "parse_failure" and result.exit_code == 4
    assert result.side == "base" and result.input == "template"
    with pytest.raises(Exception) as caught:
        template.parse_template_text(text, PATH)
    assert (result.line, result.column) == (caught.value.line, caught.value.column)  # type: ignore[attr-defined]


def test_alias_budget_is_inherited(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(yamlcfn, "MAX_ALIAS_EXPANSIONS", 3)
    monkeypatch.setattr(yamlcfn, "_LOADER", None)
    result = deltaio.parse_document("Resources:\n  a: &a [1]\n  b: [*a, *a, *a, *a]\n", PATH, "head")
    assert isinstance(result, Failure) and result.code == "template_parse_failure"
    assert isinstance(deltaio.parse_document("Resources:\n  a: &a [1]\n  b: [*a, *a, *a]\n", PATH, "head"), ParsedDocument)


def test_parser_divergence(monkeypatch: pytest.MonkeyPatch) -> None:
    """Method B fails but the v1.0 parser succeeds: reported, exit 1."""
    monkeypatch.setattr(template, "parse_template_text", lambda text, path: ({"Resources": {"R": {}}}, "yaml"))
    result = deltaio.parse_document("Resources:\n  R: {A: 1\n", PATH, "head")
    assert isinstance(result, Failure)
    assert result.code == "parser_divergence"
    assert result.error_class == "unexpected" and result.exit_code == 1


def test_missing_pyyaml_is_unexpected(monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable() -> Any:
        raise ToolUnavailableError("PyYAML is required")

    monkeypatch.setattr(yamlcfn, "import_yaml", unavailable)
    monkeypatch.setattr(template, "_parse_yaml", lambda text, path: unavailable())
    result = deltaio.parse_document("Resources: {R: {}}\n", PATH, "head")
    assert isinstance(result, Failure) and result.code == "unexpected"


CANARY = "QzCanaryParseLine7731"


@pytest.mark.parametrize(
    "text",
    [
        "Resources:\n  R: {A: " + CANARY + "\n",
        '{"Resources": {"' + CANARY + '": }',
        "Resources:\n  R: !" + CANARY + " x\n",
    ],
)
def test_no_exception_text_is_kept(text: str) -> None:
    """Requirement 12 AC10 / Design 10-4: a Failure holds integers and codes only."""
    with pytest.raises(Exception) as caught:
        template.parse_template_text(text, PATH)
    if not text.startswith("{"):
        # Requirements C-1: a YAML parse message quotes the input; JSON does not.
        assert CANARY in str(caught.value)
    result = deltaio.parse_document(text, PATH, "head")
    assert isinstance(result, Failure)
    assert CANARY not in repr(result)
    for value in vars(result).values():
        assert value is None or isinstance(value, int) or value in (
            deltaschema.FAILURE_CODES + deltaschema.SIDES + deltaschema.FAILURE_INPUTS
        )


# ---------------------------------------------------------------------------
# parse_template and read_template
# ---------------------------------------------------------------------------


def test_parse_template_rejects_a_non_reviewable_document() -> None:
    for text in ("Description: x\n", "Resources: {}\n", "[1, 2]\n", "# only a comment\n"):
        result = deltaio.parse_template(text, PATH, "base")
        assert isinstance(result, Failure), text
        assert result.code == "template_not_reviewable" and result.exit_code == 8


def test_parse_template_returns_a_checked_template() -> None:
    result = deltaio.parse_template("Resources:\n  R:\n    Type: AWS::S3::Bucket\n", PATH, "base")
    assert isinstance(result, ParsedTemplate)
    assert result.shape == deltaio.Shape(nodes=4, depth=4, containers=3)
    assert result.fmt == "yaml"


def _write(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def test_read_template_success(tmp_path: Path) -> None:
    _write(tmp_path / "t" / "a.json", b'{"Resources": {"R": {"Type": "AWS::S3::Bucket"}}}')
    result = deltaio.read_template("t/a.json", tmp_path, "head")
    assert isinstance(result, ParsedTemplate) and result.fmt == "json"


@pytest.mark.parametrize(
    "arg,code",
    [
        ("../outside.yaml", "path_violation"),
        ("/etc/hosts", "path_violation"),
        ("missing.yaml", "input_not_found"),
        ("a;b.yaml", "invalid_arguments"),
        ("", "invalid_arguments"),
    ],
)
def test_read_template_path_failures(tmp_path: Path, arg: str, code: str) -> None:
    result = deltaio.read_template(arg, tmp_path, "base")
    assert isinstance(result, Failure) and result.code == code
    assert result.exit_code == deltaschema.FAILURE_CODE_TABLE[code][1]


def test_read_template_refuses_an_outward_symlink(tmp_path: Path) -> None:
    root = tmp_path / "ws"
    root.mkdir()
    outside = _write(tmp_path / "secret.yaml", b"Resources: {R: {}}\n")
    (root / "link.yaml").symlink_to(outside)
    result = deltaio.read_template("link.yaml", root, "base")
    assert isinstance(result, Failure) and result.code == "path_violation"


def test_read_template_refuses_a_directory(tmp_path: Path) -> None:
    (tmp_path / "d.yaml").mkdir()
    result = deltaio.read_template("d.yaml", tmp_path, "base")
    assert isinstance(result, Failure) and result.code == "path_violation"


def test_read_template_refuses_a_fifo(tmp_path: Path) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("os.mkfifo is not available on this platform")
    os.mkfifo(tmp_path / "p.yaml")
    result = deltaio.read_template("p.yaml", tmp_path, "base")
    assert isinstance(result, Failure) and result.code == "path_violation"


def test_read_template_size_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    body = b'{"Resources": {"R": {}}}'
    _write(tmp_path / "a.json", body)
    monkeypatch.setattr(template, "MAX_TEMPLATE_BYTES", len(body))
    assert isinstance(deltaio.read_template("a.json", tmp_path, "base"), ParsedTemplate)
    monkeypatch.setattr(template, "MAX_TEMPLATE_BYTES", len(body) - 1)
    result = deltaio.read_template("a.json", tmp_path, "base")
    assert isinstance(result, Failure) and result.code == "template_too_large"
    assert result.error_class == "input_too_large" and result.exit_code == 3


def test_read_template_invalid_utf8(tmp_path: Path) -> None:
    _write(tmp_path / "b.yaml", b"Resources:\n  R: \xff\xfe\n")
    result = deltaio.read_template("b.yaml", tmp_path, "head")
    assert isinstance(result, Failure) and result.code == "template_encoding_failure"
    assert result.error_class == "parse_failure" and result.line == 2


def test_read_template_not_reviewable(tmp_path: Path) -> None:
    _write(tmp_path / "n.yaml", b"Description: x\n")
    result = deltaio.read_template("n.yaml", tmp_path, "head")
    assert isinstance(result, Failure) and result.code == "template_not_reviewable"


# ---------------------------------------------------------------------------
# Failure and module constraints
# ---------------------------------------------------------------------------


def test_failure_rejects_values_outside_the_closed_sets() -> None:
    with pytest.raises(ValueError):
        Failure("no_such_code", "base", "template")
    with pytest.raises(ValueError):
        Failure("unexpected", "left", "template")
    with pytest.raises(ValueError):
        Failure("unexpected", None, "stdin")
    with pytest.raises(ValueError):
        Failure("unexpected", None, "template", line=0)
    with pytest.raises(ValueError):
        Failure("unexpected", None, "template", column=True)


def test_module_text_and_imports() -> None:
    path = Path(deltaio.__file__)
    text = path.read_text(encoding="utf-8")
    assert "hypothesis" not in text and ".kiro" not in text
    forbidden = {"subprocess", "socket", "urllib", "http", "ssl", "ftplib", "smtplib", "asyncio"}
    allowed_roots = {"__future__", "hashlib", "json", "math", "dataclasses", "pathlib", "typing", "iacreview", "yaml"}
    for node in ast.walk(ast.parse(text)):
        names: List[str] = []
        if isinstance(node, ast.Import):
            names = [alias.name.split(".")[0] for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [(node.module or "").split(".")[0]]
        for name in names:
            assert name not in forbidden
            assert name in allowed_roots, name
