"""Property test: the single-pass parse agrees with the v1.0 parser (v1.1 Task 3).

Generated YAML (flow style, with anchors, aliases, CloudFormation short tags,
and repeated keys) and generated JSON (with repeated keys) are parsed by
:func:`iacreview.deltaio.parse_document` and by
``iacreview.template.parse_template_text``. The two must succeed or fail
together and, on success, return equal documents (Design 2-2). Independently of
the parser, the generator records whether it wrote a repeated string key; the
parse must report a duplicate exactly when it did (Requirement 2 AC5).

Aliases only refer to anchors whose node is already complete, so generated
documents are acyclic and small, and ``==`` is safe on them.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from hypothesis import given, settings
from hypothesis import strategies as st

from iacreview import deltaio, template
from iacreview.deltaio import Failure, ParsedDocument
from iacreview.errors import IacReviewError

MAX_EXAMPLES = 100
PATH = Path("generated.yaml")

KEYS = ("A", "B", "Type", "Name", "k1")
YAML_SCALARS = ("x", "'quoted'", '"double"', "true", "null", "1.5", "7", "-3", "2012-10-17", "''")
TAGS = ("Ref", "Sub", "GetAtt", "If", "Join", "Base64")


@st.composite
def _yaml_value(draw: Any, depth: int, state: Dict[str, Any]) -> str:
    kinds = ["scalar"]
    if depth > 0:
        kinds += ["mapping", "list", "tagged"]
    if state["anchors"]:
        kinds.append("alias")
    kind = draw(st.sampled_from(kinds))
    if kind == "scalar":
        return draw(st.sampled_from(YAML_SCALARS))
    if kind == "alias":
        return "*" + draw(st.sampled_from(state["anchors"]))
    if kind == "tagged":
        tag = draw(st.sampled_from(TAGS))
        inner = draw(_yaml_value(depth - 1, state))
        return "!{0} {1}".format(tag, inner)
    anchor = draw(st.booleans())
    if kind == "mapping":
        keys = draw(st.lists(st.sampled_from(KEYS), min_size=0, max_size=4))
        if len(keys) != len(set(keys)):
            state["duplicate"] = True
        parts = ["{0}: {1}".format(k, draw(_yaml_value(depth - 1, state))) for k in keys]
        body = "{" + ", ".join(parts) + "}"
    else:
        items = draw(st.lists(_yaml_value(depth - 1, state), min_size=0, max_size=4))
        body = "[" + ", ".join(items) + "]"
    if anchor:
        name = "a{0}".format(len(state["anchors"]))
        # The anchor becomes usable only after its node is complete.
        state["anchors"].append(name)
        return "&{0} {1}".format(name, body)
    return body


@st.composite
def yaml_documents(draw: Any) -> Dict[str, Any]:
    state: Dict[str, Any] = {"anchors": [], "duplicate": False}
    keys = draw(st.lists(st.sampled_from(("Resources", "Outputs", "Resources", "Parameters")), min_size=1, max_size=3))
    if len(keys) != len(set(keys)):
        state["duplicate"] = True
    lines = ["{0}: {1}".format(k, draw(_yaml_value(3, state))) for k in keys]
    return {"text": "\n".join(lines) + "\n", "duplicate": state["duplicate"]}


@st.composite
def _json_value(draw: Any, depth: int, state: Dict[str, Any]) -> str:
    kinds = ["scalar"] + (["object", "array"] if depth > 0 else [])
    kind = draw(st.sampled_from(kinds))
    if kind == "scalar":
        return draw(st.sampled_from(('"x"', "1", "-2.5", "true", "false", "null", '"\\u00e9"', "1e3")))
    if kind == "object":
        keys = draw(st.lists(st.sampled_from(KEYS), min_size=0, max_size=4))
        if len(keys) != len(set(keys)):
            state["duplicate"] = True
        return "{" + ", ".join("{0}: {1}".format(json.dumps(k), draw(_json_value(depth - 1, state))) for k in keys) + "}"
    items = draw(st.lists(_json_value(depth - 1, state), min_size=0, max_size=4))
    return "[" + ", ".join(items) + "]"


@st.composite
def json_documents(draw: Any) -> Dict[str, Any]:
    state: Dict[str, Any] = {"duplicate": False}
    return {"text": draw(_json_value(4, state)), "duplicate": state["duplicate"]}


def _check(text: str, wrote_duplicate: bool) -> None:
    try:
        expected: Any = template.parse_template_text(text, PATH)[0]
        error: Any = None
    except IacReviewError as exc:
        expected, error = None, exc
    actual = deltaio.parse_document(text, PATH, "head")
    if error is not None:
        assert isinstance(actual, Failure)
        assert actual.code == "template_parse_failure"
        assert (actual.line, actual.column) == (error.line, error.column)
        return
    assert isinstance(actual, ParsedDocument)
    assert actual.doc == expected
    found = len(actual.marked) > 0 or bool(actual.duplicate_sections)
    assert found == wrote_duplicate


@settings(max_examples=MAX_EXAMPLES, deadline=None)
@given(yaml_documents())
def test_yaml_single_pass_matches_v1_parse(case: Dict[str, Any]) -> None:
    _check(case["text"], case["duplicate"])


@settings(max_examples=MAX_EXAMPLES, deadline=None)
@given(json_documents())
def test_json_single_pass_matches_v1_parse(case: Dict[str, Any]) -> None:
    _check(case["text"], case["duplicate"])


def test_generators_reach_both_branches() -> None:
    """The properties are not vacuous: duplicates, aliases and tags all occur."""
    samples: List[Dict[str, Any]] = []

    @settings(max_examples=200, deadline=None)
    @given(yaml_documents())
    def collect(case: Dict[str, Any]) -> None:
        samples.append(case)

    collect()
    assert any(s["duplicate"] for s in samples)
    assert any(not s["duplicate"] for s in samples)
    assert any("*a" in s["text"] for s in samples)
    assert any("!" in s["text"] for s in samples)
