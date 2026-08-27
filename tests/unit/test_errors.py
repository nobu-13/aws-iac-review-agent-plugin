"""Exception hierarchy and StructuredError shape checks.

Locks three things that later modules depend on:

* the ``error_class`` / ``exit_code`` pair of every exception class
  (design.md, Error Handling / 構造化エラーの一貫性),
* the StructuredError key set, identical for every class regardless of which
  optional detail fields were supplied (Requirement 12 AC7, AC8),
* the 5-line ``stderr_head`` cap (Requirement 15 AC7).
"""

from __future__ import annotations

from typing import Optional, Tuple, Type

import pytest

from iacreview import errors, exitcodes

# (class, error_class, exit_code) written out literally rather than read from
# the module, so a change to either attribute fails here.
EXPECTED: Tuple[Tuple[Type[errors.IacReviewError], str, int], ...] = (
    (errors.IacReviewError, "unexpected", 1),
    (errors.InvalidArgumentsError, "invalid_arguments", 2),
    (errors.InputNotFoundError, "input_not_found", 3),
    (errors.TemplateParseError, "parse_failure", 4),
    (errors.ToolUnavailableError, "tool_unavailable", 5),
    (errors.ToolVersionError, "tool_version", 5),
    (errors.ToolExecutionError, "tool_execution", 6),
    (errors.ToolTimeoutError, "tool_timeout", 6),
    (errors.PathContainmentError, "path_violation", 7),
    (errors.UnsafeArgumentError, "invalid_arguments", 2),
    (errors.NotReviewableError, "no_reviewable_template", 8),
    (errors.SchemaViolationError, "schema_violation", 4),
    (errors.MappingFileError, "unexpected", 1),
)


def _ids() -> list:
    return [cls.__name__ for cls, _, _ in EXPECTED]


@pytest.mark.parametrize(("cls", "error_class", "exit_code"), EXPECTED, ids=_ids())
def test_class_declares_documented_error_class_and_exit_code(
    cls: Type[errors.IacReviewError], error_class: str, exit_code: int
) -> None:
    assert cls.error_class == error_class
    assert cls.exit_code == exit_code


@pytest.mark.parametrize(("cls", "error_class", "exit_code"), EXPECTED, ids=_ids())
def test_every_class_derives_from_the_base(
    cls: Type[errors.IacReviewError], error_class: str, exit_code: int
) -> None:
    assert issubclass(cls, errors.IacReviewError)
    assert issubclass(cls, Exception)


@pytest.mark.parametrize(("cls", "error_class", "exit_code"), EXPECTED, ids=_ids())
def test_error_class_is_within_the_permitted_set(
    cls: Type[errors.IacReviewError], error_class: str, exit_code: int
) -> None:
    assert cls.error_class in errors.ERROR_CLASSES


@pytest.mark.parametrize(("cls", "error_class", "exit_code"), EXPECTED, ids=_ids())
def test_exit_code_comes_from_the_exit_code_table(
    cls: Type[errors.IacReviewError], error_class: str, exit_code: int
) -> None:
    assert cls.exit_code in set(exitcodes.EXIT_CODES.values())


@pytest.mark.parametrize(("cls", "error_class", "exit_code"), EXPECTED, ids=_ids())
def test_structured_error_key_set_is_identical_for_every_class(
    cls: Type[errors.IacReviewError], error_class: str, exit_code: int
) -> None:
    minimal = cls("something failed").to_structured_error()
    detailed = cls(
        "something failed",
        tool="cfn-lint",
        tool_exit_code=1,
        required_min_version="1.0.0",
        detected_version="0.9.0",
        remediation="pip install --upgrade cfn-lint",
        stderr="boom\n",
    ).to_structured_error(source="cfn-lint")

    assert set(minimal) == set(errors.STRUCTURED_ERROR_KEYS)
    assert set(detailed) == set(errors.STRUCTURED_ERROR_KEYS)
    assert minimal["error_class"] == error_class
    assert minimal["error_class"] in errors.ERROR_CLASSES


def test_permitted_error_class_set_has_eleven_values() -> None:
    assert len(errors.ERROR_CLASSES) == 11


def test_every_permitted_error_class_is_used_by_some_class() -> None:
    used = {cls.error_class for cls, _, _ in EXPECTED}
    assert used == set(errors.ERROR_CLASSES)


def test_unset_optional_fields_are_none_not_missing() -> None:
    structured = errors.InvalidArgumentsError("--target is required").to_structured_error()

    assert structured == {
        "error_class": "invalid_arguments",
        "source": None,
        "tool": None,
        "exit_code": None,
        "message": "--target is required",
        "required_min_version": None,
        "detected_version": None,
        "remediation": None,
        "stderr_head": [],
    }


def test_structured_error_matches_the_design_example() -> None:
    """The tool_unavailable example from design.md, field for field."""
    error = errors.ToolUnavailableError(
        "cfn-guard was not found on the system PATH.",
        tool="cfn-guard",
        required_min_version="3.0.0",
        remediation=(
            "Install cfn-guard: see "
            "https://github.com/aws-cloudformation/cloudformation-guard#installation"
        ),
    )

    assert error.to_structured_error(source="cfn-guard") == {
        "error_class": "tool_unavailable",
        "source": "cfn-guard",
        "tool": "cfn-guard",
        "exit_code": None,
        "message": "cfn-guard was not found on the system PATH.",
        "required_min_version": "3.0.0",
        "detected_version": None,
        "remediation": (
            "Install cfn-guard: see "
            "https://github.com/aws-cloudformation/cloudformation-guard#installation"
        ),
        "stderr_head": [],
    }


def test_stderr_head_keeps_only_the_first_five_of_six_lines() -> None:
    stderr = "\n".join("line{0}".format(n) for n in range(1, 7))

    structured = errors.ToolExecutionError("cfn-lint crashed", stderr=stderr).to_structured_error()

    assert structured["stderr_head"] == ["line1", "line2", "line3", "line4", "line5"]
    assert len(structured["stderr_head"]) == errors.STDERR_HEAD_MAX_LINES


@pytest.mark.parametrize(
    ("stderr", "expected"),
    [
        (None, []),
        ("", []),
        ("only one line", ["only one line"]),
        ("a\nb\n", ["a", "b"]),
        ("a\r\nb\r\n", ["a", "b"]),
        ("a\n\nb", ["a", "", "b"]),
    ],
    ids=["none", "empty", "single", "trailing-newline", "crlf", "blank-line-kept"],
)
def test_stderr_head_normalizes_short_input(stderr: Optional[str], expected: list) -> None:
    structured = errors.ToolTimeoutError("timed out", stderr=stderr).to_structured_error()

    assert structured["stderr_head"] == expected


def test_stderr_head_list_is_not_shared_with_the_exception() -> None:
    error = errors.ToolExecutionError("cfn-guard failed", stderr="line1\nline2")
    structured = error.to_structured_error()

    structured["stderr_head"].append("injected")  # type: ignore[union-attr]

    assert error.stderr_head == ["line1", "line2"]


def test_message_is_also_the_exception_str() -> None:
    error = errors.TemplateParseError("mapping values are not allowed here (line 3, column 5)")

    assert str(error) == error.message
    assert error.to_structured_error()["message"] == error.message


def test_unknown_error_class_is_rejected() -> None:
    class BogusError(errors.IacReviewError):
        error_class = "not_a_permitted_value"
        exit_code = exitcodes.UNEXPECTED

    with pytest.raises(ValueError, match="not a permitted value"):
        BogusError("boom").to_structured_error()


def test_hierarchy_constant_lists_every_tested_class() -> None:
    assert tuple(errors.ERROR_CLASS_HIERARCHY) == tuple(cls for cls, _, _ in EXPECTED)


def test_public_api_exports_every_exception_class() -> None:
    exported = set(errors.__all__)

    for cls, _, _ in EXPECTED:
        assert cls.__name__ in exported
    assert {"ERROR_CLASSES", "STRUCTURED_ERROR_KEYS", "STDERR_HEAD_MAX_LINES"} <= exported
