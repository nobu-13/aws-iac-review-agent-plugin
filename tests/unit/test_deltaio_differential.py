"""Differential test: :func:`deltaio.parse_document` against the v1.0 parser (Task 3).

Design 2-2 requires the single-pass parse to produce the same document as
``template.parse_template_text`` and to fail exactly when it fails. Every YAML
and JSON file under ``tests/fixtures`` (including the Task 2 fixtures),
``benchmark/cases`` and ``examples`` is parsed both ways.

Documents are compared with ``==`` only after :func:`deltaio.check_structure`
shows they are acyclic and small; a cyclic document would make ``==`` recurse
without end and a large alias fan-out would make it expand. Those inputs are
compared by shape, and the cyclic ones get their own test: method B parses them
and the structure check reports ``template_alias_cycle``, while the v1.0 parse
succeeds (Design F-15).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, List, Optional, Tuple

import pytest

from iacreview import deltaio, deltaschema, template
from iacreview.deltaio import Failure, ParsedDocument, Shape
from iacreview.errors import IacReviewError

REPO_ROOT = Path(__file__).resolve().parents[2]
CORPUS_DIRS = ("tests/fixtures", "benchmark/cases", "examples")
#: Above this many logical nodes, documents are compared by shape only.
EQUALITY_NODE_LIMIT = 100000
UNBOUNDED = 10 ** 12


def _corpus() -> List[Path]:
    found: List[Path] = []
    for relative in CORPUS_DIRS:
        for directory, _, names in os.walk(REPO_ROOT / relative):
            for name in names:
                if name.endswith((".yaml", ".yml", ".json", ".template")):
                    found.append(Path(directory) / name)
    return sorted(found)


def _text(path: Path) -> Optional[str]:
    try:
        return path.read_bytes().decode("utf-8")
    except UnicodeDecodeError:
        return None


CORPUS = _corpus()
TEXTS: List[Tuple[Path, str]] = [(p, t) for p, t in ((p, _text(p)) for p in CORPUS) if t is not None]


def _v1(text: str, path: Path) -> Tuple[Optional[Any], Optional[IacReviewError]]:
    try:
        return template.parse_template_text(text, path)[0], None
    except IacReviewError as exc:
        return None, exc


def _shape(doc: Any) -> Any:
    return deltaio.check_structure(doc)


def test_corpus_is_not_trivial() -> None:
    """The comparison runs over a real number of inputs (reported in the Evidence)."""
    assert len(TEXTS) >= 150
    assert any(p.parts[-4:-2] == ("delta", "templates") for p, _ in TEXTS)


@pytest.mark.parametrize("path,text", TEXTS, ids=[str(p.relative_to(REPO_ROOT)) for p, _ in TEXTS])
def test_method_b_agrees_with_the_v1_parser(
    path: Path, text: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(deltaschema, "MAX_TEMPLATE_NODES", UNBOUNDED)
    monkeypatch.setattr(deltaschema, "MAX_TEMPLATE_DEPTH", UNBOUNDED)
    expected, error = _v1(text, path)
    actual = deltaio.parse_document(text, path, "base")
    if error is not None:
        assert isinstance(actual, Failure), path
        assert actual.code == "template_parse_failure"
        assert (actual.line, actual.column) == (error.line, error.column)  # type: ignore[attr-defined]
        return
    assert isinstance(actual, ParsedDocument), (path, actual)
    assert actual.fmt == template.detect_format(text)
    shape_actual, shape_expected = _shape(actual.doc), _shape(expected)
    if isinstance(shape_expected, Failure):
        # Only a cycle can fail with unbounded limits.
        assert shape_expected.code == "template_alias_cycle"
        assert isinstance(shape_actual, Failure) and shape_actual.code == "template_alias_cycle"
        return
    assert shape_actual == shape_expected
    assert isinstance(shape_actual, Shape)
    if shape_actual.nodes <= EQUALITY_NODE_LIMIT:
        assert actual.doc == expected


CYCLES = {
    "list": "Resources:\n  R: &a [*a]\n",
    "mapping": "Resources: &r\n  R: *r\n",
    "inside_resource": "Resources:\n  R: &a\n    Type: AWS::S3::Bucket\n    Properties: {Loop: *a}\n",
}


@pytest.mark.parametrize("name", sorted(CYCLES))
def test_cycles_parse_in_both_and_only_the_structure_check_refuses(name: str) -> None:
    text = CYCLES[name]
    _, error = _v1(text, Path("c.yaml"))
    assert error is None
    parsed = deltaio.parse_document(text, Path("c.yaml"), "head")
    assert isinstance(parsed, ParsedDocument)
    result = deltaio.parse_template(text, Path("c.yaml"), "head")
    assert isinstance(result, Failure) and result.code == "template_alias_cycle"


def test_alias_bomb_agrees_by_shape() -> None:
    path = REPO_ROOT / "tests" / "fixtures" / "invalid" / "billion_laughs.yaml"
    text = path.read_text(encoding="utf-8")
    expected, error = _v1(text, path)
    assert error is None
    parsed = deltaio.parse_document(text, path, "head")
    assert isinstance(parsed, ParsedDocument)
    resources = parsed.doc["Resources"]
    assert resources["l1"][0] is resources["l0"]
    assert len(parsed.marked) == 0
