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
    (errors.InputTooLargeError, "input_too_large", 3),
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


def test_permitted_error_class_set_has_twelve_values() -> None:
    assert len(errors.ERROR_CLASSES) == 12


def test_every_permitted_error_class_is_used_by_some_class() -> None:
    used = {cls.error_class for cls, _, _ in EXPECTED}
    assert used == set(errors.ERROR_CLASSES)


def test_input_too_large_is_a_permitted_error_class_with_a_mapping() -> None:
    """v0.8.0 (Requirement 17 AC1/AC2/AC9): ``input_too_large`` is in the closed
    set and its exception maps to a documented exit code."""
    assert "input_too_large" in errors.ERROR_CLASSES
    assert errors.InputTooLargeError.error_class == "input_too_large"
    assert errors.InputTooLargeError.exit_code in set(exitcodes.EXIT_CODES.values())
    structured = errors.InputTooLargeError("too big").to_structured_error()
    assert structured["error_class"] == "input_too_large"
    assert set(structured) == set(errors.STRUCTURED_ERROR_KEYS)


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


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        (
            "open('/Users/alice/workspace/tpl.yaml') failed",
            "open('<path> failed",
        ),
        (
            'File "/opt/tool/cfnlint/runner.py", line 42',
            'File "<path> line 42',
        ),
        (
            "cfn-lint: could not read /etc/passwd",
            "cfn-lint: could not read <path>",
        ),
        ("RuntimeError: fake cfn-lint always crashes", "RuntimeError: fake cfn-lint always crashes"),
        (
            "copied /var/tmp/a to /var/tmp/b",
            "copied <path> to <path>",
        ),
        ("prefer read/write access and/or none", "prefer read/write access and/or none"),
        ("computed a / b as a ratio", "computed a / b as a ratio"),
        ("/absolute/leading/path only", "<path> only"),
    ],
    ids=[
        "absolute-path-redacted",
        "quoted-path-redacted",
        "trailing-path-redacted",
        "no-path-unchanged",
        "multiple-paths-all-redacted",
        "relative-fragments-unchanged",
        "bare-slash-unchanged",
        "leading-path-redacted",
    ],
)
def test_redact_host_paths_replaces_only_absolute_path_tokens(line: str, expected: str) -> None:
    """Requirement 18 AC2: absolute host paths collapse to a fixed placeholder;
    normal words and relative fragments are left intact."""
    assert errors.redact_host_paths(line) == expected


def test_redact_host_paths_leaves_the_bare_word_unmangled() -> None:
    """A word that merely contains ``or`` next to a slash is not a path."""
    assert errors.redact_host_paths("read and/or write") == "read and/or write"


def test_redact_host_paths_is_deterministic_and_idempotent() -> None:
    """Requirement 18 AC3: the placeholder is fixed, so redaction is stable and
    reapplying it changes nothing."""
    once = errors.redact_host_paths("failed on /home/ci/build/tpl.json now")
    assert once == "failed on <path> now"
    assert errors.redact_host_paths(once) == once


def test_stderr_head_redacts_absolute_paths_after_the_five_line_cap() -> None:
    """Redaction runs on the retained lines, satisfying both the 5-line cap
    (Requirement 15 AC7) and the no-host-path rule (Requirement 18 AC2)."""
    stderr = "\n".join(
        [
            "cfn-lint failed while reading /Users/ci/repo/tpl.yaml",
            "Traceback (most recent call last):",
            "  File \"/opt/tool/cfnlint/runner.py\", line 42",
            "RuntimeError: boom",
            "context: /var/log/tool.log",
            "/should/not/appear/line6",
        ]
    )

    structured = errors.ToolExecutionError("cfn-lint crashed", stderr=stderr).to_structured_error()
    head = structured["stderr_head"]

    assert len(head) == errors.STDERR_HEAD_MAX_LINES  # type: ignore[arg-type]
    joined = "\n".join(head)  # type: ignore[arg-type]
    assert "/Users/ci/repo/tpl.yaml" not in joined
    assert "/opt/tool/cfnlint/runner.py" not in joined
    assert "/var/log/tool.log" not in joined
    assert "/should/not/appear/line6" not in joined  # dropped by the cap
    assert errors.HOST_PATH_PLACEHOLDER in joined


# ---------------------------------------------------------------------------
# redact_stderr_line: host paths + labeled PIDs + timestamps (Requirement 20)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "line,expected",
    [
        # Labeled PIDs: the label is kept, the value collapses (AC1).
        ("child pid 4242 exited", "child pid <pid> exited"),
        ("killed pid=1001", "killed pid=<pid>"),
        ("PID: 77 timed out", "PID: <pid> timed out"),
        # Recognized timestamps: the compound date-time collapses (AC2).
        ("2026-09-01T21:25:14Z failed", "<timestamp> failed"),
        ("started 2026-09-01 21:25:14.123 now", "started <timestamp> now"),
        ("at 2026-09-01T21:25:14+09:00 done", "at <timestamp> done"),
        # A host path is still redacted through the same function.
        ("could not read /etc/passwd", "could not read <path>"),
        # All three at once.
        (
            "pid 42 read /etc/hosts at 2026-01-02T03:04:05Z",
            "pid <pid> read <path> at <timestamp>",
        ),
        # Non-targets preserved (AC3): rule ID, line number, byte count, version,
        # a bare integer, and a date-only or version-like number.
        ("rule E3012 on line 7 (128 bytes)", "rule E3012 on line 7 (128 bytes)"),
        ("cfn-lint 1.46.0 ready", "cfn-lint 1.46.0 ready"),
        ("exit code 42", "exit code 42"),
        ("released on 2026-09-01", "released on 2026-09-01"),
    ],
    ids=[
        "pid-space",
        "pid-equals",
        "pid-colon-uppercase",
        "timestamp-iso-z",
        "timestamp-space-fraction",
        "timestamp-offset",
        "host-path-still-redacted",
        "all-three-at-once",
        "rule-id-line-bytes-preserved",
        "version-preserved",
        "bare-integer-preserved",
        "date-only-preserved",
    ],
)
def test_redact_stderr_line_redacts_only_recognized_env_dependent_values(
    line: str, expected: str
) -> None:
    """Requirement 20 AC1-AC3: host paths, labeled PIDs and recognized timestamps
    collapse to fixed placeholders; a bare number, a rule ID, a line number, a
    byte count, a version, and a date-only fragment are preserved."""
    assert errors.redact_stderr_line(line) == expected


def test_redact_stderr_line_is_deterministic_and_idempotent() -> None:
    """Requirement 20 AC4: fixed placeholders, so reapplying changes nothing."""
    once = errors.redact_stderr_line("pid 9 at 2026-09-01T00:00:00Z read /tmp/x")
    assert once == "pid <pid> at <timestamp> read <path>"
    assert errors.redact_stderr_line(once) == once


def test_redact_host_paths_still_leaves_pids_and_timestamps_untouched() -> None:
    """The host-path primitive keeps its narrow contract: only paths, so the
    v0.9.0 extension lives in redact_stderr_line rather than widening it."""
    line = "pid 4242 at 2026-09-01T00:00:00Z"
    assert errors.redact_host_paths(line) == line


def test_stderr_head_redacts_pids_and_timestamps_after_the_cap() -> None:
    """Requirement 20 AC4: the retained stderr lines carry no labeled PID and no
    recognized timestamp."""
    stderr = "\n".join(
        [
            "worker pid 3131 crashed",
            "at 2026-09-01T21:25:14Z during parse",
            "rule E3012 fired on line 9",
        ]
    )
    structured = errors.ToolExecutionError("tool crashed", stderr=stderr).to_structured_error()
    joined = "\n".join(structured["stderr_head"])  # type: ignore[arg-type]

    assert "3131" not in joined
    assert "2026-09-01T21:25:14Z" not in joined
    assert errors.PID_PLACEHOLDER in joined
    assert errors.TIMESTAMP_PLACEHOLDER in joined
    # AC3: a rule ID and a line number a tool prints survive.
    assert "E3012" in joined
    assert "line 9" in joined


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
