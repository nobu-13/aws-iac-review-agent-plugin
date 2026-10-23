"""Contract tests for the v1.0 behaviour that the v1.1 Delta_Tool design relies on.

The v1.1 design (``.kiro/specs/aws-iac-bounded-remediation-v1.1/design.md``
sections 1-4, 2-2 and 2-5) reuses existing code without changing it:

* two private readers in :mod:`iacreview.template`, for the TOCTOU-safe,
  size-bounded read of a Template and of a Review_Report;
* the internal steps of PyYAML's ``yaml.load`` (``get_single_node`` then
  ``construct_document``), so that duplicate keys can be found on the node
  graph inside a single parse;
* a subclass of the existing CloudFormation loader that overrides
  ``construct_object``.

Nothing in this file exercises v1.1 code, which does not exist yet. These tests
pin the v1.0 and PyYAML behaviour the design was measured against, so that a
change to it is caught here before it silently invalidates the design.

Safety: no test expands an alias fan-out into a tree or compares a cyclic or
heavily shared document with ``==``. Shared structure is inspected through a
memoized walk that visits each container once.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest

from iacreview import template, yamlcfn
from iacreview.errors import (
    InputNotFoundError,
    InputTooLargeError,
    PathContainmentError,
    TemplateParseError,
)

yaml = yamlcfn.import_yaml()

REPO_ROOT: Path = Path(__file__).resolve().parents[2]

#: Directories whose YAML / JSON files are used as real-world parser inputs.
PARSER_CORPUS_DIRS: Tuple[str, ...] = ("benchmark/cases", "examples", "tests/fixtures")

#: The alias fan-out fixture. Parsed, but never compared with ``==``.
ALIAS_BOMB = REPO_ROOT / "tests" / "fixtures" / "invalid" / "billion_laughs.yaml"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _write(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


def _corpus_files(suffixes: Tuple[str, ...]) -> List[Path]:
    found: List[Path] = []
    for relative in PARSER_CORPUS_DIRS:
        for directory, _, names in os.walk(REPO_ROOT / relative):
            for name in sorted(names):
                if name.endswith(suffixes):
                    found.append(Path(directory) / name)
    return sorted(found)


def _uses_alias(text: str) -> bool:
    """True when ``text`` may contain a YAML alias. Conservative on purpose."""
    return "*" in text and "&" in text


def _shape(root: Any, cap: int = 10 ** 12) -> Tuple[int, int, bool]:
    """Logical tree size, distinct container count, and whether a cycle exists.

    Iterative post-order with three colours; each container is expanded once,
    so a fan-out is counted without being walked. The size saturates at ``cap``.
    """
    white, grey, black = 0, 1, 2
    colour: Dict[int, int] = {}
    size: Dict[int, int] = {}

    def children(value: Any) -> List[Any]:
        if isinstance(value, dict):
            return list(value.values())
        if isinstance(value, list):
            return list(value)
        return []

    if not isinstance(root, (dict, list)):
        return 1, 0, False
    stack: List[Tuple[Any, bool]] = [(root, False)]
    while stack:
        node, leaving = stack.pop()
        key = id(node)
        if leaving:
            total = 1
            for child in children(node):
                total += size[id(child)] if isinstance(child, (dict, list)) else 1
                total = min(total, cap + 1)
            size[key] = total
            colour[key] = black
            continue
        state = colour.get(key, white)
        if state == black:
            continue
        if state == grey:
            return 0, len(colour), True
        colour[key] = grey
        stack.append((node, True))
        for child in children(node):
            if isinstance(child, (dict, list)):
                child_state = colour.get(id(child), white)
                if child_state == grey:
                    return 0, len(colour), True
                if child_state == white:
                    stack.append((child, False))
    return size[id(root)], len(colour), False


def _load_by_steps(text: str, loader_class: Any) -> Any:
    """``yaml.load`` decomposed into the steps the v1.1 design uses."""
    loader = loader_class(text)
    try:
        node = loader.get_single_node()
        return loader.construct_document(node) if node is not None else None
    finally:
        loader.dispose()


# ---------------------------------------------------------------------------
# (1) template._read_text / template._read_bytes_toctou_safe
# ---------------------------------------------------------------------------


def test_read_bytes_returns_the_file_content(tmp_path: Path) -> None:
    payload = b'{"Resources": {"B": {"Type": "AWS::S3::Bucket"}}}\n'
    path = _write(tmp_path / "report.json", payload)
    assert template._read_bytes_toctou_safe(path) == payload


def test_read_text_returns_decoded_text(tmp_path: Path) -> None:
    path = _write(tmp_path / "t.yaml", "Resources:\n  B: {Type: AWS::S3::Bucket}\n".encode("utf-8"))
    assert template._read_text(path) == "Resources:\n  B: {Type: AWS::S3::Bucket}\n"


@pytest.mark.parametrize("reader", ["_read_text", "_read_bytes_toctou_safe"])
def test_readers_refuse_a_file_over_the_limit_before_reading(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reader: str
) -> None:
    path = _write(tmp_path / "big.json", b"x" * 64)
    monkeypatch.setattr(template, "MAX_TEMPLATE_BYTES", 63)
    with pytest.raises(InputTooLargeError):
        getattr(template, reader)(path)


@pytest.mark.parametrize("reader", ["_read_text", "_read_bytes_toctou_safe"])
def test_readers_accept_a_file_at_the_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reader: str
) -> None:
    path = _write(tmp_path / "edge.json", b"{}" + b" " * 62)
    monkeypatch.setattr(template, "MAX_TEMPLATE_BYTES", 64)
    assert len(getattr(template, reader)(path)) == 64


def test_the_shipped_limit_is_five_mebibytes() -> None:
    """The Report limit of the v1.1 design is this value, inherited unchanged."""
    assert template.MAX_TEMPLATE_BYTES == 5 * 1024 * 1024


@pytest.mark.parametrize("reader", ["_read_text", "_read_bytes_toctou_safe"])
def test_readers_refuse_a_directory(tmp_path: Path, reader: str) -> None:
    target = tmp_path / "dir.json"
    target.mkdir()
    with pytest.raises(PathContainmentError) as caught:
        getattr(template, reader)(target)
    assert caught.value.error_class == "path_violation"


@pytest.mark.parametrize("reader", ["_read_text", "_read_bytes_toctou_safe"])
def test_readers_refuse_a_fifo(tmp_path: Path, reader: str) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("os.mkfifo is not available on this platform")
    fifo = tmp_path / "pipe.json"
    os.mkfifo(fifo)
    with pytest.raises(PathContainmentError) as caught:
        getattr(template, reader)(fifo)
    assert caught.value.error_class == "path_violation"


@pytest.mark.parametrize("reader", ["_read_text", "_read_bytes_toctou_safe"])
def test_readers_refuse_a_final_symlink(tmp_path: Path, reader: str) -> None:
    """``O_NOFOLLOW`` refuses a final-component symlink at open time.

    Observed in M0: the refusal surfaces as ``input_not_found`` (the ``ELOOP``
    from ``os.open``), not as ``path_violation``. In the v1.1 flow a symlink is
    normally resolved and containment-checked by ``pathguard.resolve_within``
    before the reader runs; this pins what the reader itself does if one
    reaches it.
    """
    real = _write(tmp_path / "real.json", b"{}")
    link = tmp_path / "link.json"
    link.symlink_to(real)
    with pytest.raises(InputNotFoundError) as caught:
        getattr(template, reader)(link)
    assert caught.value.error_class == "input_not_found"


def test_read_text_reports_invalid_utf8_with_a_position(tmp_path: Path) -> None:
    path = _write(tmp_path / "bad.yaml", b"Resources:\n  B: \xff\xfe\n")
    with pytest.raises(TemplateParseError) as caught:
        template._read_text(path)
    error = caught.value
    assert error.error_class == "parse_failure"
    assert isinstance(error.line, int) and error.line >= 1
    assert isinstance(error.column, int) and error.column >= 1


def test_read_bytes_does_not_decode(tmp_path: Path) -> None:
    """The Report reader decodes on its own; the byte reader must not reject bytes."""
    payload = b"\xff\xfe not utf-8"
    path = _write(tmp_path / "r.json", payload)
    assert template._read_bytes_toctou_safe(path) == payload


# ---------------------------------------------------------------------------
# (2) PyYAML internal steps used by the single-pass design
# ---------------------------------------------------------------------------


def _yaml_corpus() -> List[Path]:
    return [p for p in _corpus_files((".yaml", ".yml")) if p != ALIAS_BOMB]


@pytest.mark.parametrize("path", _yaml_corpus(), ids=lambda p: str(p.relative_to(REPO_ROOT)))
def test_load_by_steps_matches_load_yaml(path: Path) -> None:
    """``get_single_node`` + ``construct_document`` equals ``yamlcfn.load_yaml``.

    Both must succeed with equal documents, or both must fail. Documents that
    may use aliases are compared by shape only, never with ``==``.
    """
    text = path.read_text(encoding="utf-8", errors="strict") if _decodes(path) else None
    if text is None:
        pytest.skip("not UTF-8; covered by the reader tests")
    loader_class = yamlcfn.cfn_safe_loader()
    try:
        expected: Optional[Any] = yamlcfn.load_yaml(text)
        expected_error: Optional[type] = None
    except Exception as exc:  # noqa: BLE001 - mirrors the parser's broad failure path
        expected, expected_error = None, type(exc)
    try:
        actual: Optional[Any] = _load_by_steps(text, loader_class)
        actual_error: Optional[type] = None
    except Exception as exc:  # noqa: BLE001
        actual, actual_error = None, type(exc)
    assert actual_error == expected_error
    if expected_error is not None:
        return
    if _uses_alias(text):
        assert _shape(actual) == _shape(expected)
    else:
        assert actual == expected


def _decodes(path: Path) -> bool:
    try:
        path.read_text(encoding="utf-8", errors="strict")
    except (UnicodeDecodeError, OSError):
        return False
    return True


def test_load_by_steps_on_the_alias_bomb_matches_by_shape() -> None:
    """The fan-out fixture parses under the shipped alias budget (Design F-14)."""
    text = ALIAS_BOMB.read_text(encoding="utf-8")
    by_steps = _load_by_steps(text, yamlcfn.cfn_safe_loader())
    by_load = yamlcfn.load_yaml(text)
    assert _shape(by_steps) == _shape(by_load) == (1234567901, 11, False)


def test_alias_bomb_is_built_as_shared_objects() -> None:
    doc, _ = template.parse_template_text(ALIAS_BOMB.read_text(encoding="utf-8"), ALIAS_BOMB)
    resources = doc["Resources"]
    assert resources["l1"][0] is resources["l0"]
    assert resources["l8"][0] is resources["l7"]


def test_shipped_alias_budget_counts_references_not_expansion() -> None:
    """The fixture has 80 alias references, far under the 10,000 budget."""
    text = ALIAS_BOMB.read_text(encoding="utf-8")
    assert yamlcfn.MAX_ALIAS_EXPANSIONS == 10000
    assert sum(1 for token in text.replace(",", " ").replace("[", " ").replace("]", " ").split() if token.startswith("*")) == 80


# ---------------------------------------------------------------------------
# (3) subclassing the existing loader
# ---------------------------------------------------------------------------


def _marking_subclass(base: Any) -> Any:
    class Marking(base):  # type: ignore[misc, valid-type]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self.watch: set = set()
            self.kept: List[Any] = []

        def construct_object(self, node: Any, deep: bool = False) -> Any:
            obj = super().construct_object(node, deep=deep)
            if node in self.watch:
                self.kept.append(obj)
            return obj

    return Marking


def _duplicate_mapping_nodes(root: Any) -> set:
    found: set = set()
    seen: set = set()
    stack = [root]
    while stack:
        node = stack.pop()
        if node is None or id(node) in seen:
            continue
        seen.add(id(node))
        if isinstance(node, yaml.MappingNode):
            keys: set = set()
            for key_node, value_node in node.value:
                if isinstance(key_node, yaml.ScalarNode) and key_node.tag == "tag:yaml.org,2002:str":
                    if key_node.value in keys:
                        found.add(node)
                    keys.add(key_node.value)
                stack.extend((key_node, value_node))
        elif isinstance(node, yaml.SequenceNode):
            stack.extend(node.value)
    return found


def test_subclass_leaves_the_base_constructor_registry_unchanged() -> None:
    base = yamlcfn.cfn_safe_loader()
    before = dict(base.yaml_constructors)
    _marking_subclass(base)
    assert dict(base.yaml_constructors) == before


def test_subclass_inherits_the_alias_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(yamlcfn, "MAX_ALIAS_EXPANSIONS", 3)
    monkeypatch.setattr(yamlcfn, "_LOADER", None)
    marking = _marking_subclass(yamlcfn.cfn_safe_loader())
    loader = marking("a: &a [1]\nb: [*a, *a, *a, *a]\n")
    try:
        with pytest.raises(yaml.YAMLError):
            loader.get_single_node()
    finally:
        loader.dispose()


MARKING_CASES: Dict[str, str] = {
    "plain": "Resources:\n  R:\n    Type: AWS::S3::Bucket\n    Properties: {A: 1, A: 2}\n",
    "tagged": "Resources:\n  R:\n    Type: AWS::S3::Bucket\n    Properties: {N: !Sub {x: 1, x: 2}}\n",
    "aliased": "Resources:\n  base: &b {K: 1, K: 2}\n  R:\n    Type: AWS::S3::Bucket\n    Properties: {U: *b, V: *b}\n",
    "merge_is_not_a_duplicate": "Resources:\n  base: &b {K: 1}\n  R: {<<: *b, K: 2, Type: AWS::S3::Bucket}\n",
    "no_duplicate": "Resources:\n  R: {Type: AWS::S3::Bucket, Properties: {A: 1, B: 2}}\n",
}


def _marked_target(name: str, doc: Any) -> Optional[Any]:
    resource = doc["Resources"]["R"]
    return {
        "plain": lambda: resource["Properties"],
        "tagged": lambda: resource["Properties"]["N"],
        "aliased": lambda: resource["Properties"]["U"],
    }.get(name, lambda: None)()


@pytest.mark.parametrize("name", sorted(MARKING_CASES))
def test_construct_object_marks_the_final_object(name: str) -> None:
    """Design F-17: ``construct_object`` returns the object that ends up in the doc."""
    text = MARKING_CASES[name]
    marking = _marking_subclass(yamlcfn.cfn_safe_loader())
    loader = marking(text)
    try:
        node = loader.get_single_node()
        loader.watch = _duplicate_mapping_nodes(node)
        doc = loader.construct_document(node)
    finally:
        loader.dispose()
    assert doc == yamlcfn.load_yaml(text)
    kept_ids = {id(obj) for obj in loader.kept}
    target = _marked_target(name, doc)
    if target is None:
        assert loader.watch == set() and kept_ids == set()
    else:
        assert id(target) in kept_ids


def test_construct_mapping_override_misses_plain_mappings() -> None:
    """Design F-17: the rejected approach. Pinned so the design reason stays true."""
    base = yamlcfn.cfn_safe_loader()
    recorded: List[int] = []

    class ByMapping(base):  # type: ignore[misc, valid-type]
        def construct_mapping(self, node: Any, deep: bool = False) -> Any:
            mapping = super().construct_mapping(node, deep=deep)
            recorded.append(id(mapping))
            return mapping

    text = "Resources:\n  R:\n    Type: AWS::S3::Bucket\n    Properties: {A: 1, B: !Sub {x: 1}}\n"
    doc = _load_by_steps(text, ByMapping)
    properties = doc["Resources"]["R"]["Properties"]
    assert id(properties) not in recorded
    assert id(properties["B"]["Fn::Sub"]) in recorded


# ---------------------------------------------------------------------------
# (4) cycles and nesting depth in the existing parse path
# ---------------------------------------------------------------------------


CYCLES: Dict[str, str] = {
    "list_self": "Resources:\n  R: &a [*a]\n",
    "mapping_self": "Resources: &r\n  R: *r\n",
    "inside_resource": "Resources:\n  R: &a\n    Type: AWS::S3::Bucket\n    Properties: {Loop: *a}\n",
}


@pytest.mark.parametrize("name", sorted(CYCLES))
def test_alias_cycles_pass_the_existing_parse(name: str) -> None:
    """Design F-15: a reference cycle is parsed, not rejected, by v1.0."""
    doc, fmt = template.parse_template_text(CYCLES[name], Path("cycle.yaml"))
    assert fmt == "yaml"
    assert template.is_reviewable(doc)
    assert _shape(doc)[2] is True


@pytest.mark.parametrize(
    "text",
    [
        "Resources:\n  R: &a !Ref [*a]\n",
        "Resources:\n  R: [*a]\n  S: &a [1]\n",
    ],
    ids=["cycle_inside_short_tag", "forward_reference"],
)
def test_some_alias_misuse_is_a_parse_failure(text: str) -> None:
    with pytest.raises(TemplateParseError):
        template.parse_template_text(text, Path("bad.yaml"))


def test_merge_key_self_reference_leaves_no_cycle() -> None:
    doc, _ = template.parse_template_text("Resources:\n  R: &a {<<: *a, x: 1}\n", Path("m.yaml"))
    assert _shape(doc)[2] is False


@pytest.mark.parametrize("fmt,depth,parses", [("yaml", 60, True), ("yaml", 500, False), ("json", 500, True), ("json", 2000, False)])
def test_parser_depth_limits(fmt: str, depth: int, parses: bool) -> None:
    """Design F-16: the existing parsers bound nesting through RecursionError."""
    if fmt == "yaml":
        text = "Resources:\n  R: " + "[" * depth + "]" * depth + "\n"
    else:
        text = '{"Resources": {"R": ' + "[" * depth + "]" * depth + "}}"
    if parses:
        doc, _ = template.parse_template_text(text, Path("deep." + fmt))
        assert template.is_reviewable(doc)
    else:
        with pytest.raises(TemplateParseError):
            template.parse_template_text(text, Path("deep." + fmt))


def test_duplicate_keys_are_last_wins_in_both_parsers() -> None:
    """Requirements C-2: the reason the design detects duplicates itself."""
    yaml_doc, _ = template.parse_template_text(
        "Resources:\n  B: {Type: AWS::S3::Bucket}\n  B: {Type: AWS::SQS::Queue}\n", Path("d.yaml")
    )
    json_doc, _ = template.parse_template_text(
        '{"Resources": {"B": {"Type": "AWS::S3::Bucket"}, "B": {"Type": "AWS::SQS::Queue"}}}', Path("d.json")
    )
    assert yaml_doc == json_doc == {"Resources": {"B": {"Type": "AWS::SQS::Queue"}}}
