"""Template loader tests.

The centre of this module is :data:`CASES`: the eight inputs tasks.md 5.2
enumerates as the completion condition (valid YAML, valid JSON, malformed YAML,
malformed JSON, binary, truncated, no ``Resources``, empty ``Resources``) plus
the empty file, each backed by a fixture under ``tests/fixtures/``. Every one of
them must end in a defined result or an ``IacReviewError`` -- never an unhandled
exception (Requirement 12 AC8).

The parse-failure cases additionally assert that ``error_type``, ``line``, and
``column`` are all filled in, which is Requirement 3 AC6. Exact line numbers are
asserted only where the fixture pins them unambiguously; elsewhere the assertion
is that a usable position exists, because the precise mark PyYAML chooses is a
detail of its scanner rather than something this plugin defines.

Remaining groups cover format detection by content rather than by extension
(Requirement 3 AC4), the reviewability predicate as a total function
(Requirement 3 AC1), and the boundary with neighbouring modules: an unreadable
path is an ``input_not_found``, and a missing PyYAML stays a ``tool_unavailable``
instead of being relabelled a parse failure.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Optional, Tuple, Type

import pytest

from iacreview import template
from iacreview.errors import (
    IacReviewError,
    InputNotFoundError,
    NotReviewableError,
    TemplateParseError,
    ToolUnavailableError,
)
from iacreview.source import display_path

FIXTURES: Path = Path(__file__).resolve().parents[1] / "fixtures"


class _Case:
    """One input file and the outcome :func:`load_template` must produce.

    ``expected`` is either ``None`` for a successful load or the exception class
    the load must raise. Written as a small class rather than a tuple so the
    parametrize table below stays readable.
    """

    def __init__(
        self,
        name: str,
        relative: str,
        expected: Optional[Type[IacReviewError]],
        fmt: Optional[str] = None,
    ) -> None:
        self.name = name
        self.path = FIXTURES / relative
        self.expected = expected
        self.fmt = fmt


#: The eight required inputs, plus the empty file the implementation notes call
#: out separately.
CASES: Tuple[_Case, ...] = (
    _Case(
        "valid-yaml",
        "valid/minimal_compliant_template.yaml",
        expected=None,
        fmt="yaml",
    ),
    _Case("valid-json", "valid/minimal_template.json", expected=None, fmt="json"),
    _Case("malformed-yaml", "invalid/malformed_syntax.yaml", TemplateParseError),
    _Case("malformed-json", "invalid/malformed_syntax.json", TemplateParseError),
    _Case("binary", "invalid/binary_content.yaml", TemplateParseError),
    _Case("truncated", "invalid/truncated.yaml", TemplateParseError),
    _Case("empty-file", "invalid/empty_file.yaml", TemplateParseError),
    _Case("no-resources", "invalid/no_resources.yaml", NotReviewableError),
    _Case("empty-resources", "invalid/empty_resources.json", NotReviewableError),
)

PARSE_FAILURE_CASES: Tuple[_Case, ...] = tuple(
    case for case in CASES if case.expected is TemplateParseError
)

SUCCESS_CASES: Tuple[_Case, ...] = tuple(case for case in CASES if case.expected is None)


def _ids(cases: Tuple[_Case, ...]) -> list:
    return [case.name for case in cases]


# --- (1) every enumerated input reaches a defined outcome -------------------


def test_all_nine_fixture_files_exist() -> None:
    """A missing fixture would silently turn a case into an unrelated error."""
    missing = [case.name for case in CASES if not case.path.is_file()]

    assert missing == []


@pytest.mark.parametrize("case", CASES, ids=_ids(CASES))
def test_input_produces_a_defined_result_or_an_iacreview_error(case: _Case) -> None:
    if case.expected is None:
        loaded = template.load_template(case.path)
        assert isinstance(loaded, template.LoadedTemplate)
        return

    with pytest.raises(case.expected):
        template.load_template(case.path)


@pytest.mark.parametrize("case", SUCCESS_CASES, ids=_ids(SUCCESS_CASES))
def test_successful_load_reports_path_document_and_format(case: _Case) -> None:
    loaded = template.load_template(case.path)

    assert loaded.path == case.path
    assert loaded.fmt == case.fmt
    assert loaded.fmt in template.TEMPLATE_FORMATS
    assert template.is_reviewable(loaded.doc)
    assert "DataBucket" in loaded.doc["Resources"]


# --- (2) parse failures carry error type, line, and column (Req 3 AC6) ------


@pytest.mark.parametrize("case", PARSE_FAILURE_CASES, ids=_ids(PARSE_FAILURE_CASES))
def test_parse_failure_reports_error_type_line_and_column(case: _Case) -> None:
    with pytest.raises(TemplateParseError) as exc_info:
        template.load_template(case.path)

    error = exc_info.value
    assert error.error_type is not None
    assert error.error_type != ""
    assert error.line is not None
    assert error.column is not None
    assert isinstance(error.line, int) and error.line >= 1
    assert isinstance(error.column, int) and error.column >= 1


@pytest.mark.parametrize("case", PARSE_FAILURE_CASES, ids=_ids(PARSE_FAILURE_CASES))
def test_parse_failure_is_a_parse_failure_structured_error(case: _Case) -> None:
    """The position lives on the instance; the dict shape stays unchanged."""
    with pytest.raises(TemplateParseError) as exc_info:
        template.load_template(case.path)

    structured = exc_info.value.to_structured_error(source="template")

    assert structured["error_class"] == "parse_failure"
    # The file is named, and named the way a report names it: workspace-relative,
    # never the absolute path the caller passed in (Requirement 16 AC11). These
    # messages reach ``errors[]`` on stdout for the standalone Skills.
    message = str(structured["message"])
    assert case.path.name in message
    assert str(case.path) not in message


def test_malformed_json_position_comes_from_the_decoder() -> None:
    """The trailing comma sits on line 5 of the fixture."""
    with pytest.raises(TemplateParseError) as exc_info:
        template.load_template(FIXTURES / "invalid/malformed_syntax.json")

    error = exc_info.value
    assert error.error_type == "json.decoder.JSONDecodeError"
    assert error.line == 6
    assert error.column >= 1


def test_binary_input_reports_a_decode_failure_not_a_syntax_error() -> None:
    with pytest.raises(TemplateParseError) as exc_info:
        template.load_template(FIXTURES / "invalid/binary_content.yaml")

    error = exc_info.value
    assert error.error_type == "UnicodeDecodeError"
    # The first invalid byte is the leading 0x89, i.e. line 1 column 1.
    assert (error.line, error.column) == (1, 1)


def test_empty_file_reports_an_empty_document() -> None:
    with pytest.raises(TemplateParseError) as exc_info:
        template.load_template(FIXTURES / "invalid/empty_file.yaml")

    error = exc_info.value
    assert error.error_type == template.EMPTY_DOCUMENT_ERROR_TYPE
    assert (error.line, error.column) == (
        template.DEFAULT_LINE,
        template.DEFAULT_COLUMN,
    )


def test_malformed_yaml_error_type_names_the_pyyaml_class() -> None:
    with pytest.raises(TemplateParseError) as exc_info:
        template.load_template(FIXTURES / "invalid/malformed_syntax.yaml")

    assert (exc_info.value.error_type or "").startswith("yaml.")


def test_disallowed_yaml_tag_becomes_a_parse_failure(tmp_path: Path) -> None:
    """``yamlcfn`` raises a YAMLError for a non-allowlisted tag; we convert it."""
    path = tmp_path / "template.yaml"
    path.write_text(
        "Resources:\n"
        "  Bucket:\n"
        "    Type: !!python/object/apply:os.system ['echo pwned']\n",
        encoding="utf-8",
    )

    with pytest.raises(TemplateParseError) as exc_info:
        template.load_template(path)

    error = exc_info.value
    assert error.error_type is not None
    assert error.line is not None and error.column is not None


def test_whitespace_only_file_is_an_empty_document(tmp_path: Path) -> None:
    path = tmp_path / "template.yaml"
    path.write_text("\n\n   \n", encoding="utf-8")

    with pytest.raises(TemplateParseError) as exc_info:
        template.load_template(path)

    assert exc_info.value.error_type == template.EMPTY_DOCUMENT_ERROR_TYPE


# --- (3) format detection is content-based, not extension-based -------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ('{"Resources": {}}', "json"),
        ("  \n  {\"Resources\": {}}", "json"),
        ("\ufeff{\"Resources\": {}}", "json"),
        ("[1, 2]", "json"),
        ("Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n", "yaml"),
        ("---\nResources: {}\n", "yaml"),
        ("# comment\nResources: {}\n", "yaml"),
        ("", "yaml"),
    ],
    ids=[
        "json-object",
        "json-leading-whitespace",
        "json-with-bom",
        "json-array",
        "yaml-block",
        "yaml-document-start",
        "yaml-comment",
        "empty-defaults-to-yaml",
    ],
)
def test_detect_format_uses_the_first_content_character(
    text: str, expected: str
) -> None:
    assert template.detect_format(text) == expected


def test_json_content_in_a_yaml_named_file_is_parsed_as_json(tmp_path: Path) -> None:
    path = tmp_path / "template.yaml"
    path.write_text(
        json.dumps({"Resources": {"Bucket": {"Type": "AWS::S3::Bucket"}}}),
        encoding="utf-8",
    )

    loaded = template.load_template(path)

    assert loaded.fmt == "json"


def test_yaml_content_in_a_json_named_file_is_parsed_as_yaml(tmp_path: Path) -> None:
    path = tmp_path / "template.json"
    path.write_text(
        "Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n", encoding="utf-8"
    )

    loaded = template.load_template(path)

    assert loaded.fmt == "yaml"


def test_shorthand_tags_survive_loading_in_long_form(tmp_path: Path) -> None:
    path = tmp_path / "template.yaml"
    path.write_text(
        "Resources:\n"
        "  Bucket:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Properties:\n"
        "      BucketName: !Ref NameParam\n",
        encoding="utf-8",
    )

    loaded = template.load_template(path)

    assert loaded.doc["Resources"]["Bucket"]["Properties"]["BucketName"] == {
        "Ref": "NameParam"
    }


def test_yaml_and_json_of_the_same_template_load_to_the_same_document(
    tmp_path: Path,
) -> None:
    document = {"Resources": {"Bucket": {"Type": "AWS::S3::Bucket"}}}
    json_path = tmp_path / "a.json"
    yaml_path = tmp_path / "b.yaml"
    json_path.write_text(json.dumps(document), encoding="utf-8")
    yaml_path.write_text(
        "Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n", encoding="utf-8"
    )

    assert template.load_template(json_path).doc == template.load_template(yaml_path).doc


# --- (4) the reviewability predicate (Requirement 3 AC1) --------------------


@pytest.mark.parametrize(
    ("doc", "expected"),
    [
        ({"Resources": {"Bucket": {"Type": "AWS::S3::Bucket"}}}, True),
        ({"Resources": {"A": 1, "B": 2}}, True),
        ({"Resources": {}}, False),
        ({"Resources": None}, False),
        ({"Resources": []}, False),
        ({"Resources": "Bucket"}, False),
        ({"resources": {"Bucket": {}}}, False),
        ({}, False),
        (None, False),
        ("Resources", False),
        (42, False),
        ([{"Resources": {"Bucket": {}}}], False),
    ],
    ids=[
        "one-resource",
        "two-resources",
        "empty-mapping",
        "null",
        "list",
        "string",
        "wrong-case-key",
        "empty-document",
        "none",
        "scalar-string",
        "scalar-int",
        "list-document",
    ],
)
def test_is_reviewable_only_accepts_a_non_empty_resources_mapping(
    doc: Any, expected: bool
) -> None:
    assert template.is_reviewable(doc) is expected


@pytest.mark.parametrize(
    "relative",
    ["invalid/no_resources.yaml", "invalid/empty_resources.json"],
    ids=["no-resources", "empty-resources"],
)
def test_not_reviewable_error_names_the_path(relative: str) -> None:
    path = FIXTURES / relative

    with pytest.raises(NotReviewableError) as exc_info:
        template.load_template(path)

    error = exc_info.value
    # Requirement 3 AC5 asks for the file path in the report; Requirement 16 AC11
    # forbids an absolute one there. The workspace-relative form satisfies both.
    assert display_path(path) in error.message
    assert str(path) not in error.message
    assert error.to_structured_error()["error_class"] == "no_reviewable_template"


# --- (5) boundaries with neighbouring modules -------------------------------


def test_missing_file_is_reported_as_input_not_found(tmp_path: Path) -> None:
    with pytest.raises(InputNotFoundError):
        template.load_template(tmp_path / "does_not_exist.yaml")


def test_directory_input_is_reported_as_input_not_found(tmp_path: Path) -> None:
    with pytest.raises(InputNotFoundError):
        template.load_template(tmp_path)


def test_missing_pyyaml_stays_a_tool_unavailable_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PyYAML's absence must not be relabelled as a parse failure."""
    from iacreview import yamlcfn

    path = tmp_path / "template.yaml"
    path.write_text("Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n", encoding="utf-8")
    monkeypatch.setitem(sys.modules, "yaml", None)
    monkeypatch.setattr(yamlcfn, "_LOADER", None)

    with pytest.raises(ToolUnavailableError):
        template.load_template(path)


def test_json_input_does_not_need_pyyaml(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from iacreview import yamlcfn

    path = tmp_path / "template.json"
    path.write_text(
        json.dumps({"Resources": {"Bucket": {"Type": "AWS::S3::Bucket"}}}),
        encoding="utf-8",
    )
    monkeypatch.setitem(sys.modules, "yaml", None)
    monkeypatch.setattr(yamlcfn, "_LOADER", None)

    assert template.load_template(path).fmt == "json"


def test_loaded_template_is_frozen() -> None:
    loaded = template.load_template(FIXTURES / "valid/minimal_template.json")

    with pytest.raises(Exception):
        loaded.fmt = "yaml"  # type: ignore[misc]


def test_public_api_is_exported() -> None:
    for name in ("LoadedTemplate", "load_template", "is_reviewable", "detect_format"):
        assert name in template.__all__
        assert hasattr(template, name)
