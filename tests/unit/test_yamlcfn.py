"""Tests for the CloudFormation-aware YAML loader.

Three groups, matching tasks.md 5.1:

1. All 18 shorthand tags convert to their long form, including the ``!GetAtt``
   dotted-scalar split and nesting of one tag inside another.
2. ``!!python/object`` and ``!!python/object/apply`` are rejected
   (Requirement 9 AC7).
3. A tag outside the allowlist (``!Bogus``) is rejected, and the allowlist does
   not leak onto ``yaml.SafeLoader``.

A fourth group covers the lazy import: a missing or too-old PyYAML must surface
as a structured error, because that is what keeps JSON-only reviews working in
an environment without PyYAML.
"""

from __future__ import annotations

import sys
from typing import Any, Dict, List, Tuple

import pytest

from iacreview import yamlcfn
from iacreview.errors import ToolUnavailableError, ToolVersionError

yaml = pytest.importorskip("yaml", reason="PyYAML is required for these tests")


def _load_value(expression: str) -> Any:
    """Parse a one-key document and return the value under ``Value``.

    Wrapping the expression in a mapping is what a real Template does; parsing a
    bare tag at document root exercises a different PyYAML code path than the
    plugin ever sees.
    """
    return yamlcfn.load_yaml("Value: {0}\n".format(expression))["Value"]


# --- (1) shorthand tag conversion -------------------------------------------

#: ``(tag name, YAML expression, expected long form)`` for every allowlisted tag.
TAG_CASES: Tuple[Tuple[str, str, Dict[str, Any]], ...] = (
    ("Ref", "!Ref MyBucket", {"Ref": "MyBucket"}),
    ("GetAtt", "!GetAtt MyBucket.Arn", {"Fn::GetAtt": ["MyBucket", "Arn"]}),
    (
        "Sub",
        '!Sub "arn:${AWS::Partition}:s3:::${Bucket}"',
        {"Fn::Sub": "arn:${AWS::Partition}:s3:::${Bucket}"},
    ),
    ("If", "!If [IsProd, RETAIN, DELETE]", {"Fn::If": ["IsProd", "RETAIN", "DELETE"]}),
    ("Not", "!Not [IsProd]", {"Fn::Not": ["IsProd"]}),
    (
        "Equals",
        "!Equals [!Ref Env, prod]",
        {"Fn::Equals": [{"Ref": "Env"}, "prod"]},
    ),
    ("And", "!And [IsProd, IsEast]", {"Fn::And": ["IsProd", "IsEast"]}),
    ("Or", "!Or [IsProd, IsStaging]", {"Fn::Or": ["IsProd", "IsStaging"]}),
    ("Join", '!Join ["-", [app, prod]]', {"Fn::Join": ["-", ["app", "prod"]]}),
    ("Select", "!Select [0, [a, b]]", {"Fn::Select": [0, ["a", "b"]]}),
    ("Split", '!Split [",", "a,b"]', {"Fn::Split": [",", "a,b"]}),
    (
        "FindInMap",
        "!FindInMap [RegionMap, us-east-1, ami]",
        {"Fn::FindInMap": ["RegionMap", "us-east-1", "ami"]},
    ),
    ("Base64", "!Base64 hello", {"Fn::Base64": "hello"}),
    (
        "Cidr",
        '!Cidr ["10.0.0.0/16", 6, 5]',
        {"Fn::Cidr": ["10.0.0.0/16", 6, 5]},
    ),
    ("ImportValue", "!ImportValue SharedVpcId", {"Fn::ImportValue": "SharedVpcId"}),
    ("GetAZs", '!GetAZs ""', {"Fn::GetAZs": ""}),
    (
        "Transform",
        "!Transform {Name: MyMacro, Parameters: {Key: Value}}",
        {"Fn::Transform": {"Name": "MyMacro", "Parameters": {"Key": "Value"}}},
    ),
    ("Condition", "!Condition IsProd", {"Condition": "IsProd"}),
)


@pytest.mark.parametrize(
    "expression,expected",
    [(expression, expected) for _, expression, expected in TAG_CASES],
    ids=[name for name, _, _ in TAG_CASES],
)
def test_shorthand_tag_converts_to_long_form(
    expression: str, expected: Dict[str, Any]
) -> None:
    assert _load_value(expression) == expected


def test_every_allowlisted_tag_has_a_case() -> None:
    """Guard against a tag being added to the allowlist but left untested."""
    assert {name for name, _, _ in TAG_CASES} == set(yamlcfn.SHORT_TAGS)
    assert len(yamlcfn.SHORT_TAGS) == 18


@pytest.mark.parametrize(
    "expression,expected",
    [
        # Already-long list form is preserved as written.
        ("!GetAtt [MyBucket, Arn]", ["MyBucket", "Arn"]),
        # Nested stack output: only the first separator splits.
        ("!GetAtt Stack.Outputs.BucketName", ["Stack", "Outputs.BucketName"]),
        # Invalid CloudFormation, but a parse-time judgement is not ours to
        # make; the list shape stays consistent.
        ("!GetAtt MyBucket", ["MyBucket"]),
    ],
    ids=["list-form", "nested-stack-output", "no-separator"],
)
def test_getatt_value_shapes(expression: str, expected: List[str]) -> None:
    assert _load_value(expression) == {"Fn::GetAtt": expected}


def test_long_form_keys_distinguish_bare_tags_from_functions() -> None:
    assert yamlcfn.long_form_key("Ref") == "Ref"
    assert yamlcfn.long_form_key("Condition") == "Condition"
    assert yamlcfn.long_form_key("Sub") == "Fn::Sub"


def test_tags_nest_inside_a_resource_document() -> None:
    template = (
        "Resources:\n"
        "  Policy:\n"
        "    Properties:\n"
        "      Value: !Sub\n"
        "        - '${Arn}/*'\n"
        "        - Arn: !GetAtt Bucket.Arn\n"
    )

    doc = yamlcfn.load_yaml(template)

    assert doc["Resources"]["Policy"]["Properties"]["Value"] == {
        "Fn::Sub": ["${Arn}/*", {"Arn": {"Fn::GetAtt": ["Bucket", "Arn"]}}]
    }


# --- (2) arbitrary Python object construction is rejected -------------------


@pytest.mark.parametrize(
    "expression",
    [
        "!!python/object:os.system",
        "!!python/object/apply:os.system ['touch /tmp/pwned']",
        "!!python/name:os.system",
    ],
    ids=["object", "object-apply", "name"],
)
def test_python_object_tags_are_rejected(expression: str) -> None:
    with pytest.raises(yaml.YAMLError):
        _load_value(expression)


def test_rejected_python_tag_does_not_execute_the_callable(tmp_path) -> None:
    """The tag is refused during construction, so nothing runs."""
    marker = tmp_path / "pwned"

    with pytest.raises(yaml.YAMLError):
        yamlcfn.load_yaml(
            "Value: !!python/object/apply:os.system ['touch {0}']\n".format(marker)
        )

    assert not marker.exists()


# --- (3) unknown tags and registry isolation --------------------------------


@pytest.mark.parametrize(
    "expression",
    ["!Bogus value", "!FnRef value", "!ref lowercase"],
    ids=["unknown", "near-miss", "wrong-case"],
)
def test_tags_outside_the_allowlist_are_rejected(expression: str) -> None:
    with pytest.raises(yaml.YAMLError):
        _load_value(expression)


def test_allowlist_is_not_registered_on_the_shared_safeloader() -> None:
    yamlcfn.cfn_safe_loader()

    assert "!Ref" not in yaml.SafeLoader.yaml_constructors
    with pytest.raises(yaml.YAMLError):
        yaml.safe_load("Value: !Ref MyBucket\n")


def test_no_multi_constructor_is_registered() -> None:
    """A prefix multi-constructor would accept tags outside the allowlist."""
    loader = yamlcfn.cfn_safe_loader()

    assert loader.yaml_multi_constructors == yaml.SafeLoader.yaml_multi_constructors


def test_loader_class_is_cached_and_safeloader_derived() -> None:
    loader = yamlcfn.cfn_safe_loader()

    assert loader is yamlcfn.cfn_safe_loader()
    assert issubclass(loader, yaml.SafeLoader)


def test_malformed_yaml_raises_a_yaml_error_with_a_position() -> None:
    """The caller needs ``problem_mark`` to fill in line and column."""
    with pytest.raises(yaml.YAMLError) as exc_info:
        yamlcfn.load_yaml("Resources:\n  - [unclosed\n")

    assert getattr(exc_info.value, "problem_mark", None) is not None


# --- (4) lazy PyYAML import -------------------------------------------------


def test_missing_pyyaml_raises_tool_unavailable(monkeypatch) -> None:
    # A ``None`` entry in sys.modules makes ``import yaml`` raise ImportError,
    # which is what an environment without PyYAML looks like from inside the
    # function.
    monkeypatch.setitem(sys.modules, "yaml", None)
    monkeypatch.setattr(yamlcfn, "_LOADER", None)

    with pytest.raises(ToolUnavailableError) as exc_info:
        yamlcfn.load_yaml("Resources: {}\n")

    error = exc_info.value
    assert error.tool == "PyYAML"
    assert error.required_min_version == "6.0"
    assert "pip install 'PyYAML>=6.0'" in (error.remediation or "")


def test_outdated_pyyaml_raises_tool_version_error(monkeypatch) -> None:
    monkeypatch.setattr(yaml, "__version__", "5.4.1")

    with pytest.raises(ToolVersionError) as exc_info:
        yamlcfn.load_yaml("Resources: {}\n")

    error = exc_info.value
    assert error.detected_version == "5.4.1"
    assert error.required_min_version == "6.0"
    assert "PyYAML" in (error.remediation or "")


def test_unparseable_pyyaml_version_does_not_block_parsing(monkeypatch) -> None:
    """An unexpected version string is not a reason to refuse to run."""
    monkeypatch.setattr(yaml, "__version__", "unknown")

    assert yamlcfn.load_yaml("Value: !Ref X\n") == {"Value": {"Ref": "X"}}


# --- (5) alias-expansion budget ---------------------------------------------


def _nested_alias_document(levels: int, fan_out: int) -> str:
    """Build a billion-laughs style document without materializing it.

    Each level is a sequence of ``fan_out`` references to the level below, so
    the number of *alias references* the composer must resolve grows quickly
    while the source text stays a few dozen lines. The document is never
    expanded here -- it is only text -- so this consumes no memory itself; the
    point is that the loader refuses it before *it* would.
    """
    lines = ['l0: &l0 ["x", "x"]']
    for level in range(1, levels + 1):
        refs = ", ".join(["*l{0}".format(level - 1)] * fan_out)
        lines.append("l{0}: &l{0} [{1}]".format(level, refs))
    return "\n".join(lines) + "\n"


def test_a_nested_alias_document_trips_a_small_budget(monkeypatch) -> None:
    """With a small budget, a fan-out document fails as a YAML error.

    The budget is monkeypatched low so the failure is reached in the first few
    levels, without a real billion-laughs payload. The raised error is a
    ``yaml.YAMLError`` (so :mod:`iacreview.template` turns it into a positioned
    ``TemplateParseError``) and carries a ``problem_mark`` for that position.
    """
    monkeypatch.setattr(yamlcfn, "MAX_ALIAS_EXPANSIONS", 5)
    monkeypatch.setattr(yamlcfn, "_LOADER", None)

    document = _nested_alias_document(levels=5, fan_out=4)

    with pytest.raises(yaml.constructor.ConstructorError) as exc_info:
        yamlcfn.load_yaml(document)

    error = exc_info.value
    assert isinstance(error, yaml.YAMLError)
    assert getattr(error, "problem_mark", None) is not None
    assert str(yamlcfn.MAX_ALIAS_EXPANSIONS) in str(error)


def test_the_budget_is_not_charged_until_it_is_exceeded(monkeypatch) -> None:
    """A document with exactly the budgeted number of aliases still parses.

    The check is ``> MAX_ALIAS_EXPANSIONS``, so the boundary value is allowed;
    this pins that anchors and aliases are legal YAML and are not banned outright
    (the budget only refuses documents that go *past* it).
    """
    monkeypatch.setattr(yamlcfn, "MAX_ALIAS_EXPANSIONS", 3)
    monkeypatch.setattr(yamlcfn, "_LOADER", None)

    document = "base: &b value\n" "uses: [*b, *b, *b]\n"  # exactly 3 aliases

    assert yamlcfn.load_yaml(document) == {"base": "value", "uses": ["value"] * 3}


def test_a_normal_template_reusing_aliases_is_unaffected() -> None:
    """A realistic reuse of anchors stays far below the default budget.

    Anchors and aliases are ordinary YAML; a template that factors a common
    block out and references it a handful of times must parse normally with the
    shipped :data:`MAX_ALIAS_EXPANSIONS`.
    """
    template = (
        "Mappings:\n"
        "  Common: &tags\n"
        "    Team: platform\n"
        "    Env: prod\n"
        "Resources:\n"
        "  A:\n"
        "    Properties:\n"
        "      Tags: *tags\n"
        "  B:\n"
        "    Properties:\n"
        "      Tags: *tags\n"
    )

    doc = yamlcfn.load_yaml(template)

    assert doc["Resources"]["A"]["Properties"]["Tags"] == {
        "Team": "platform",
        "Env": "prod",
    }
    assert doc["Resources"]["B"]["Properties"]["Tags"] == {
        "Team": "platform",
        "Env": "prod",
    }


def test_the_alias_counter_is_per_document(monkeypatch) -> None:
    """Each parse starts from zero; one document's aliases do not carry over.

    The counter lives on the loader instance, and a new instance is created per
    parse. Two sequential parses that each stay under the budget must both
    succeed even though their combined alias count exceeds it.
    """
    monkeypatch.setattr(yamlcfn, "MAX_ALIAS_EXPANSIONS", 3)
    monkeypatch.setattr(yamlcfn, "_LOADER", None)

    document = "base: &b value\nuses: [*b, *b]\n"  # 2 aliases, under budget

    assert yamlcfn.load_yaml(document)["uses"] == ["value", "value"]
    # A second parse would exceed the budget only if the counter were shared.
    assert yamlcfn.load_yaml(document)["uses"] == ["value", "value"]
