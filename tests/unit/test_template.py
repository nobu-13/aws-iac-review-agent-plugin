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
import os
import sys
from pathlib import Path
from typing import Any, Optional, Tuple, Type

import pytest

from iacreview import template
from iacreview.errors import (
    IacReviewError,
    InputNotFoundError,
    InputTooLargeError,
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


def test_directory_input_is_reported_as_a_non_regular_file(tmp_path: Path) -> None:
    """A directory opens but is not a regular file, so it is a path violation.

    Requirement 17 AC6 asks for a directory (like a FIFO or a device) to be
    refused because it is not a regular file. The fd-based read confirms
    ``stat.S_ISREG`` on the opened descriptor and reports the refusal as
    ``path_violation`` rather than ``input_not_found``: the path exists and can
    be opened, it simply does not name a Template file.
    """
    from iacreview.errors import PathContainmentError

    with pytest.raises(PathContainmentError) as exc_info:
        template.load_template(tmp_path)

    assert exc_info.value.error_class == "path_violation"
    assert str(tmp_path) not in exc_info.value.message


# ---------------------------------------------------------------------------
# Single-file size limit (Requirement 17 AC1). The limit is a named constant
# and is monkeypatched to a small value rather than writing a multi-megabyte
# file, so the test is portable and does not depend on a platform resource
# limit facility (Requirement 17 AC4).
# ---------------------------------------------------------------------------


def _write_template(path: Path, padding: int = 0) -> Path:
    """Write a minimal reviewable Template, optionally padded with a comment."""
    body = "Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n"
    if padding:
        body += "# " + "x" * padding + "\n"
    path.write_text(body, encoding="utf-8")
    return path


def test_file_over_the_limit_is_refused_as_input_too_large(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_template(tmp_path / "template.yaml", padding=200)
    size = path.stat().st_size
    monkeypatch.setattr(template, "MAX_TEMPLATE_BYTES", size - 1)

    with pytest.raises(InputTooLargeError):
        template.load_template(path)


def test_over_the_limit_file_is_not_read_into_memory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC1: an oversized file must be refused *without* loading it. Any call to
    ``read_bytes`` here would fail the test."""
    path = _write_template(tmp_path / "template.yaml", padding=200)
    size = path.stat().st_size
    monkeypatch.setattr(template, "MAX_TEMPLATE_BYTES", size - 1)

    def _forbidden_read(self: Path) -> bytes:  # pragma: no cover - must not run
        raise AssertionError("read_bytes was called for an oversized file")

    monkeypatch.setattr(Path, "read_bytes", _forbidden_read)

    with pytest.raises(InputTooLargeError):
        template.load_template(path)


def test_file_at_the_limit_is_still_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The comparison is strict ``>``; a file exactly at the limit loads."""
    path = _write_template(tmp_path / "template.yaml")
    size = path.stat().st_size
    monkeypatch.setattr(template, "MAX_TEMPLATE_BYTES", size)

    assert template.load_template(path).fmt == "yaml"


def test_input_too_large_message_carries_no_absolute_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Requirement 16 AC11: the reported message names no absolute host path."""
    path = _write_template(tmp_path / "template.yaml", padding=200)
    monkeypatch.setattr(template, "MAX_TEMPLATE_BYTES", 1)

    with pytest.raises(InputTooLargeError) as exc_info:
        template.load_template(path)

    assert str(tmp_path) not in exc_info.value.message
    assert exc_info.value.message.count("/") == 0 or display_path(path) in exc_info.value.message


def test_max_template_bytes_is_exported() -> None:
    assert "MAX_TEMPLATE_BYTES" in template.__all__
    assert template.MAX_TEMPLATE_BYTES == 5 * 1024 * 1024


# ---------------------------------------------------------------------------
# TOCTOU-safe, fd-based reading (Requirement 17 AC5, AC6).
#
# The read now opens the path once with ``O_NOFOLLOW`` and verifies, on that one
# descriptor, that the file is regular and that its inode still matches the
# resolved path. The regression suite pins the security-relevant refusals; the
# tests here confirm the ordinary path still works and that the fd-based size
# check preserves the Task 30 behaviour.
# ---------------------------------------------------------------------------


def test_normal_regular_file_still_loads_through_the_fd_path(tmp_path: Path) -> None:
    """The common case is unchanged: a regular file reads and parses as before."""
    path = _write_template(tmp_path / "template.yaml")

    loaded = template.load_template(path)

    assert loaded.fmt == "yaml"
    assert "Bucket" in loaded.doc["Resources"]


def test_size_check_uses_the_fstat_of_the_opened_descriptor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC1 preserved on the fd path: the limit is checked against fstat st_size.

    ``os.read`` is forbidden here to prove the refusal happens before any byte is
    read, mirroring the Task 30 guarantee now that the read goes through a
    descriptor instead of ``Path.read_bytes``.
    """
    path = _write_template(tmp_path / "template.yaml", padding=200)
    size = path.stat().st_size
    monkeypatch.setattr(template, "MAX_TEMPLATE_BYTES", size - 1)

    real_read = template.os.read

    def _forbidden_read(fd: int, n: int) -> bytes:  # pragma: no cover - must not run
        raise AssertionError("os.read was called for an oversized file")

    monkeypatch.setattr(template.os, "read", _forbidden_read)
    try:
        with pytest.raises(InputTooLargeError):
            template.load_template(path)
    finally:
        monkeypatch.setattr(template.os, "read", real_read)


def test_a_fifo_passed_as_the_template_is_refused(tmp_path: Path) -> None:
    """AC6: a FIFO is not a regular file and must be refused as path_violation."""
    from iacreview.errors import PathContainmentError

    fifo = tmp_path / "pipe.yaml"
    if not hasattr(os, "mkfifo"):
        pytest.skip("os.mkfifo is not available on this platform")
    os.mkfifo(fifo)

    with pytest.raises(PathContainmentError) as exc_info:
        template.load_template(fifo)

    assert exc_info.value.error_class == "path_violation"
    assert str(tmp_path) not in exc_info.value.message


def test_inode_mismatch_between_check_and_read_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC5: if the resolved-path stat differs from the fstat, the read is refused.

    A fully deterministic swap between check and read is hard to force in a test,
    so the identity comparison is exercised directly: ``os.stat`` (the
    resolved-path lookup) is patched to report a different inode than the
    ``os.fstat`` of the opened descriptor. This proves the comparison rejects a
    mismatch, which is the check that closes the TOCTOU window.
    """
    from iacreview.errors import PathContainmentError

    path = _write_template(tmp_path / "template.yaml")
    real_stat = os.stat

    class _Fake:
        def __init__(self, base: os.stat_result) -> None:
            self.st_dev = base.st_dev
            self.st_ino = base.st_ino + 1
            self.st_size = base.st_size
            self.st_mode = base.st_mode

    def _fake_stat(target: object, *args: object, **kwargs: object) -> object:
        result = real_stat(target, *args, **kwargs)
        if os.fspath(target) == str(path):
            return _Fake(result)
        return result

    monkeypatch.setattr(template.os, "stat", _fake_stat)

    with pytest.raises(PathContainmentError) as exc_info:
        template.load_template(path)

    assert exc_info.value.error_class == "path_violation"
    assert "changed between" in exc_info.value.message


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
