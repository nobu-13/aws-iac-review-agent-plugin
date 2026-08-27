"""Unit tests for the shared Source result shape.

:class:`~iacreview.source.SourceResult` is the value cfn-lint, cfn-guard and IAM
Review all return, so the two behaviours checked here are the ones every Source
depends on: a result may report failure while still being a well-formed result
(Requirement 4 AC12, Requirement 5 AC6), and the exit code a standalone Skill
derives from it follows design.md's failure matrix rather than the exception
class's own ``exit_code``.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Optional

import pytest

from iacreview import exitcodes
from iacreview.errors import (
    SchemaViolationError,
    TemplateParseError,
    ToolExecutionError,
    ToolTimeoutError,
    ToolUnavailableError,
    ToolVersionError,
)
from iacreview.source import SourceResult, workspace_relative


def test_a_clean_result_defaults_to_empty_containers() -> None:
    result = SourceResult(source="cfn-lint")
    assert result.findings == []
    assert result.errors == []
    assert result.stats == {}
    assert result.exit_status() == exitcodes.OK


def test_an_unknown_source_name_is_rejected() -> None:
    """A misspelled Source is otherwise invisible until the report validates."""
    with pytest.raises(SchemaViolationError):
        SourceResult(source="cfnlint")


@pytest.mark.parametrize("source", ["cfn-lint", "cfn-guard", "IAM Review", "Agent Review"])
def test_every_schema_source_is_accepted(source: str) -> None:
    assert SourceResult(source=source).source == source


def test_the_result_container_is_immutable() -> None:
    """A consumer cannot re-attribute a result it received."""
    result = SourceResult(source="cfn-lint")
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.source = "cfn-guard"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (ToolUnavailableError("absent"), exitcodes.TOOL_UNAVAILABLE),
        (ToolVersionError("too old"), exitcodes.TOOL_UNAVAILABLE),
        (ToolExecutionError("crashed"), exitcodes.TOOL_EXECUTION_FAILURE),
        (ToolTimeoutError("hung"), exitcodes.TOOL_EXECUTION_FAILURE),
        # parse_failure inside a Source is a tool that did not produce usable
        # output, which the failure matrix puts at 6 -- not the 4 the exception
        # class carries for a template that would not parse.
        (TemplateParseError("bad output"), exitcodes.TOOL_EXECUTION_FAILURE),
    ],
)
def test_exit_status_follows_the_failure_matrix(
    error: Exception, expected: int
) -> None:
    result = SourceResult(
        source="cfn-lint",
        errors=[error.to_structured_error(source="cfn-lint")],  # type: ignore[attr-defined]
    )
    assert result.exit_status() == expected


def test_a_tool_output_mismatch_does_not_use_the_exception_exit_code() -> None:
    """The one place the exception hierarchy and the failure matrix disagree.

    ``TemplateParseError`` exists for a template that would not parse, and exits
    4. When a *Source* reports it, the payload that would not parse was an
    external tool's output, which the matrix classifies as a tool execution
    failure at 6.
    """
    error = TemplateParseError("cfn-lint JSON output at <stdout>: truncated")
    result = SourceResult(
        source="cfn-lint", errors=[error.to_structured_error(source="cfn-lint")]
    )
    assert error.exit_code == exitcodes.PARSE_FAILURE
    assert result.errors[0]["error_class"] == "parse_failure"
    assert result.exit_status() == exitcodes.TOOL_EXECUTION_FAILURE


def test_exit_status_of_an_unlisted_error_class_is_unexpected() -> None:
    """An error class the table does not know must not look like a success."""
    result = SourceResult(source="cfn-lint", errors=[{"error_class": "invented"}])
    assert result.exit_status() == exitcodes.UNEXPECTED


def test_findings_and_errors_are_independent() -> None:
    """Reporting a failure does not prevent returning what was salvaged."""
    result = SourceResult(
        source="cfn-lint",
        errors=[ToolExecutionError("unknown status").to_structured_error("cfn-lint")],
        stats={"exit_code": 3},
    )
    assert result.errors and result.findings == []
    assert result.stats["exit_code"] == 3


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("templates/app.yaml", "templates/app.yaml"),
        ("./templates/app.yaml", "templates/app.yaml"),
        ("app.yaml", "app.yaml"),
        ("../outside.yaml", None),
        ("templates/../../outside.yaml", None),
        ("", None),
        ("   ", None),
        (None, None),
    ],
)
def test_workspace_relative_accepts_only_contained_relative_paths(
    text: Optional[str], expected: Optional[str]
) -> None:
    assert workspace_relative(text) == expected


def test_workspace_relative_needs_a_root_for_an_absolute_path(tmp_path: Path) -> None:
    inside = str(tmp_path / "templates" / "app.yaml")
    assert workspace_relative(inside) is None
    assert workspace_relative(inside, tmp_path) == "templates/app.yaml"


def test_workspace_relative_rejects_an_absolute_path_outside_the_root(
    tmp_path: Path,
) -> None:
    """An out-of-workspace path must not be displayed in a report."""
    assert workspace_relative("/elsewhere/app.yaml", tmp_path) is None
