"""Unit tests for cfn-lint exit code decoding and result extraction.

Three contracts are checked here, all reachable without cfn-lint installed:

1. Every exit code from 0 to 16 decodes to the outcome design.md's table
   states, so "findings were reported" is never mistaken for "the tool failed"
   (Requirement 4 AC11, AC12).
2. ``resource_from_path`` maps the five ``Location.Path`` shapes in design.md's
   table onto a logical ID or ``None``.
3. ``parse_output`` accepts the cfn-lint result structure and discards the whole
   payload, as a ``parse_failure``, on any structural mismatch.

The exhaustive 0-16 sweep is the interesting part of (1): the codes that trip up
a magnitude-based reading are 4, 6, 8, 10, 12 and 14, which are all successful
runs, and 3, which is not despite sitting between two of them.
"""

from __future__ import annotations

from typing import List, Optional

import pytest

from iacreview.cfnlint import (
    CFNLINT_FINDING_BITS,
    PARSE_ERROR_TYPE,
    CfnLintExitDecision,
    RawResult,
    decode_cfnlint_exit,
    parse_output,
    resource_from_path,
)
from iacreview.errors import InvalidArgumentsError, TemplateParseError

#: Exit codes 0-16 with the decoding design.md's table prescribes, as
#: ``(code, ok, has_findings)``.
EXIT_CODE_TABLE = [
    (0, True, False),  # no findings
    (1, False, False),  # crash / usage error
    (2, True, True),  # E
    (3, False, False),  # bit 0 is outside {2,4,8}
    (4, True, True),  # W
    (5, False, False),  # 4 | 1
    (6, True, True),  # E + W
    (7, False, False),  # 6 | 1
    (8, True, True),  # I
    (9, False, False),  # 8 | 1
    (10, True, True),  # E + I
    (11, False, False),  # 10 | 1
    (12, True, True),  # W + I
    (13, False, False),  # 12 | 1
    (14, True, True),  # E + W + I
    (15, False, False),  # 14 | 1
    (16, False, False),  # bit 4 is outside {2,4,8}
]

#: The codes the task's completion condition names explicitly.
SUCCESS_CODES = [0, 2, 4, 6, 8, 10, 12, 14]
FAILURE_CODES = [1, 3, 16]


def test_finding_bit_mask_is_fourteen() -> None:
    """The mask is the union of the Error, Warning and Informational bits."""
    assert CFNLINT_FINDING_BITS == 14


@pytest.mark.parametrize(("code", "ok", "has_findings"), EXIT_CODE_TABLE)
def test_decode_exit_code_matches_design_table(
    code: int, ok: bool, has_findings: bool
) -> None:
    assert decode_cfnlint_exit(code) == CfnLintExitDecision(
        ok=ok, has_findings=has_findings
    )


@pytest.mark.parametrize("code", SUCCESS_CODES)
def test_findings_bit_combinations_are_successful(code: int) -> None:
    """0 and every subset of {2,4,8} is a successful run (Requirement 4 AC11)."""
    assert decode_cfnlint_exit(code).ok is True


@pytest.mark.parametrize("code", FAILURE_CODES)
def test_codes_outside_the_mask_are_failures(code: int) -> None:
    """Exit 1 and any code with a foreign bit is an execution error (AC12)."""
    decision = decode_cfnlint_exit(code)
    assert decision.ok is False
    assert decision.has_findings is False


def test_only_zero_decodes_to_no_findings() -> None:
    """A successful run reports findings unless the code is exactly 0."""
    assert decode_cfnlint_exit(0).has_findings is False
    for code in SUCCESS_CODES[1:]:
        assert decode_cfnlint_exit(code).has_findings is True


@pytest.mark.parametrize("code", [-9, -1, 255, 1024])
def test_signals_and_large_codes_are_failures(code: int) -> None:
    """Negative statuses (killed by signal) and large ones are not successes."""
    assert decode_cfnlint_exit(code).ok is False


def test_non_integer_exit_code_is_a_programming_error() -> None:
    with pytest.raises(InvalidArgumentsError):
        decode_cfnlint_exit("2")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# resource_from_path: the five cases in design.md's table
# ---------------------------------------------------------------------------

RESOURCE_PATH_CASES = [
    (["Resources", "MyBucket", "Properties", "BucketName"], "MyBucket"),
    (["Resources", "MyBucket"], "MyBucket"),
    (["Parameters", "DbPassword"], None),
    (["Outputs", "BucketArn"], None),
    ([], None),
]


@pytest.mark.parametrize(("path", "expected"), RESOURCE_PATH_CASES)
def test_resource_from_path_matches_design_table(
    path: List[object], expected: Optional[str]
) -> None:
    assert resource_from_path(path) == expected


def test_resource_from_path_accepts_a_missing_path() -> None:
    """A template-level finding may carry no path at all."""
    assert resource_from_path(None) is None


def test_resource_from_path_ignores_a_bare_resources_key() -> None:
    """``["Resources"]`` names the section, not a resource."""
    assert resource_from_path(["Resources"]) is None


def test_resource_from_path_ignores_a_non_string_logical_id() -> None:
    """A sequence index cannot be a logical ID."""
    assert resource_from_path(["Resources", 0, "Properties"]) is None


def test_resource_from_path_accepts_a_tuple() -> None:
    """``RawResult.template_path`` is a tuple, and feeds straight in."""
    assert resource_from_path(("Resources", "MyQueue")) == "MyQueue"


# ---------------------------------------------------------------------------
# parse_output structural contract
# ---------------------------------------------------------------------------


def _result_json() -> str:
    """One complete cfn-lint result object, as a JSON array."""
    return """
    [
      {
        "Filename": "examples/template.yaml",
        "Level": "Warning",
        "Location": {
          "Start": {"LineNumber": 12, "ColumnNumber": 7},
          "End": {"LineNumber": 12, "ColumnNumber": 30},
          "Path": ["Resources", "MyBucket", "Properties", "BucketName"]
        },
        "Message": "Bucket name is hardcoded",
        "Rule": {
          "Id": "W3011",
          "ShortDescription": "Hardcoded name",
          "Description": "Use a generated name instead",
          "Source": "https://example.invalid/W3011"
        }
      }
    ]
    """


def test_parse_output_extracts_every_consumed_field() -> None:
    (result,) = parse_output(_result_json())
    assert result == RawResult(
        rule_id="W3011",
        rule_short_description="Hardcoded name",
        rule_description="Use a generated name instead",
        rule_source="https://example.invalid/W3011",
        level="Warning",
        message="Bucket name is hardcoded",
        line=12,
        column=7,
        template_path=("Resources", "MyBucket", "Properties", "BucketName"),
        filename="examples/template.yaml",
    )


def test_parse_output_drops_the_end_position() -> None:
    """``Location.End`` is not part of the captured structure."""
    assert not hasattr(parse_output(_result_json())[0], "end_line")


@pytest.mark.parametrize("raw", ["[]", "", "   \n"])
def test_parse_output_reads_no_results_as_an_empty_list(raw: str) -> None:
    """A clean template is zero results, not a failure."""
    assert parse_output(raw) == []


def test_parse_output_preserves_tool_order() -> None:
    raw = """
    [
      {"Level": "Error", "Message": "second", "Rule": {"Id": "E0002"}},
      {"Level": "Error", "Message": "first", "Rule": {"Id": "E0001"}}
    ]
    """
    assert [r.rule_id for r in parse_output(raw)] == ["E0002", "E0001"]


def test_parse_output_treats_a_zero_line_number_as_no_position() -> None:
    """cfn-lint reports line 0 for an unplaceable finding; the schema wants None."""
    raw = """
    [
      {
        "Level": "Error",
        "Message": "Template format error",
        "Location": {"Start": {"LineNumber": 0, "ColumnNumber": 0}, "Path": []},
        "Rule": {"Id": "E0000"}
      }
    ]
    """
    (result,) = parse_output(raw)
    assert result.line is None
    assert result.column is None
    assert result.template_path == ()
    assert resource_from_path(result.template_path) is None


def test_parse_output_accepts_a_result_without_optional_fields() -> None:
    raw = '[{"Level": "Informational", "Rule": {"Id": "I3013"}}]'
    (result,) = parse_output(raw)
    assert result.rule_id == "I3013"
    assert result.level == "Informational"
    assert result.message == ""
    assert result.rule_short_description is None
    assert result.rule_description is None
    assert result.rule_source is None
    assert result.line is None
    assert result.column is None
    assert result.template_path is None
    assert result.filename is None


def test_parse_output_ignores_unknown_fields() -> None:
    """A newer cfn-lint adding a field must not break the Source."""
    raw = """
    [
      {
        "Level": "Error",
        "Message": "boom",
        "Rule": {"Id": "E1001", "Something": "new"},
        "Unknown": {"nested": true}
      }
    ]
    """
    assert parse_output(raw)[0].rule_id == "E1001"


@pytest.mark.parametrize(
    ("raw", "field"),
    [
        ('{"Level": "Error"}', "<stdout>"),  # object, not array
        ("[[]]", "[0]"),  # element is not an object
        ('[{"Level": "Error"}]', "[0].Rule"),  # no Rule
        ('[{"Level": "Error", "Rule": {}}]', "[0].Rule.Id"),  # no Rule.Id
        ('[{"Level": "Error", "Rule": {"Id": ""}}]', "[0].Rule.Id"),  # empty Id
        ('[{"Rule": {"Id": "E1"}}]', "[0].Level"),  # no Level
        ('[{"Level": 2, "Rule": {"Id": "E1"}}]', "[0].Level"),  # Level not text
        (
            '[{"Level": "Error", "Rule": {"Id": "E1"}, '
            '"Location": {"Start": {"LineNumber": "12"}}}]',
            "[0].Location.Start.LineNumber",
        ),
        (
            '[{"Level": "Error", "Rule": {"Id": "E1"}, '
            '"Location": {"Path": "Resources"}}]',
            "[0].Location.Path",
        ),
        (
            '[{"Level": "Error", "Rule": {"Id": "E1"}, '
            '"Location": {"Path": [{"a": 1}]}}]',
            "[0].Location.Path[0]",
        ),
    ],
)
def test_parse_output_rejects_a_structural_mismatch(raw: str, field: str) -> None:
    """Any deviation discards the payload and reports a ``parse_failure``."""
    with pytest.raises(TemplateParseError) as caught:
        parse_output(raw)
    error = caught.value
    assert error.error_class == "parse_failure"
    assert error.error_type == PARSE_ERROR_TYPE
    assert error.tool == "cfn-lint"
    assert error.field == field


def test_parse_output_reports_the_position_of_a_json_syntax_error() -> None:
    with pytest.raises(TemplateParseError) as caught:
        parse_output('[{"Level": "Error",}]')
    error = caught.value
    assert error.error_class == "parse_failure"
    assert error.error_type == "JSONDecodeError"
    assert error.line == 1
    assert error.column is not None


def test_parse_output_discards_valid_results_alongside_a_bad_one() -> None:
    """No partial list: one unusable object invalidates the whole payload."""
    raw = """
    [
      {"Level": "Error", "Message": "ok", "Rule": {"Id": "E0001"}},
      {"Level": "Error", "Message": "bad", "Rule": {}}
    ]
    """
    with pytest.raises(TemplateParseError):
        parse_output(raw)


def test_parse_failure_renders_as_a_structured_error() -> None:
    with pytest.raises(TemplateParseError) as caught:
        parse_output("not json")
    structured = caught.value.to_structured_error(source="cfn-lint")
    assert structured["error_class"] == "parse_failure"
    assert structured["source"] == "cfn-lint"
    assert structured["tool"] == "cfn-lint"
