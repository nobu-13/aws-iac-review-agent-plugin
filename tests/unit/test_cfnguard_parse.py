"""Unit tests for cfn-guard result interpretation and output parsing.

Three contracts are checked, all reachable with cfn-guard absent:

1. :func:`~iacreview.cfnguard.interpret_guard_result` classifies a run by
   whether stdout parses as the expected structure, never by the exit code value
   (Requirement 5 AC7). The load-bearing case is the pair of tests that feed the
   *same* stdout with exit 5 and exit 19 and assert the same classification: 5
   and 19 are both real cfn-guard 3.2.1 codes, 19 for violations and 5 for a
   rule file that fails to parse, and a numeric reading would have to disagree
   about at least one of them.
2. :func:`~iacreview.cfnguard.parse_output` extracts the rule name, logical
   resource name, property path, provided / expected value and custom message
   from every clause shape cfn-guard emits, and discards the whole payload on
   any structural mismatch (Requirement 5 AC4, AC6).
3. :func:`~iacreview.cfnguard.load_rule_metadata` degrades a category whose
   ``_meta.json`` is missing or broken to the hardcoded fallback, records a
   ``parse_failure``, and keeps every other category intact.

The three ``tests/fixtures/tool_output/cfnguard_*`` files are verbatim cfn-guard
3.2.1 stdout, captured as documented in each file, with the absolute path of the
capture machine replaced by a repository-relative one.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

from iacreview import cfnguard
from iacreview.cfnguard import (
    FALLBACK_FINDING_TYPE,
    FALLBACK_SEVERITY,
    KIND_ALL_PASSED,
    KIND_TIMEOUT,
    KIND_TOOL_ERROR,
    KIND_VIOLATIONS,
    GuardInterpretation,
    RawResult,
    interpret_guard_result,
    load_rule_metadata,
    parse_output,
    parse_records,
    resource_from_path,
    try_parse_guard_json,
)
from iacreview.errors import InvalidArgumentsError, TemplateParseError
from iacreview.iam.locate import PolicyKind, PolicySite
from iacreview.proc import ProcResult

TOOL_OUTPUT = Path(__file__).resolve().parents[1] / "fixtures" / "tool_output"

#: Exit codes measured against cfn-guard 3.2.1 and recorded in
#: ``docs/architecture.md`` (Task 11.3): 0 all pass, 19 rule violations, 5 a rule
#: file that fails to parse, 255 a missing rules directory or an unparsable
#: template. Every non-zero one is fed through the same classification below,
#: which is the point.
OBSERVED_NONZERO_CODES = [5, 19, 255]

#: The five measured cases from ``docs/architecture.md``, as
#: ``(case, exit code, stdout is the expected structure, classification)``.
#: Cases c, d and e all produced empty stdout, which is why they classify alike
#: despite 255 and 5 being different codes, and why 19 sitting between them
#: cannot be separated out by any comparison against a threshold.
OBSERVED_CASES = [
    ("a all rules pass", 0, True, KIND_ALL_PASSED),
    ("b rule violations", 19, True, KIND_VIOLATIONS),
    ("c unparsable template", 255, False, KIND_TOOL_ERROR),
    ("d missing rules directory", 255, False, KIND_TOOL_ERROR),
    ("e unparsable rule file", 5, False, KIND_TOOL_ERROR),
]


@pytest.fixture(scope="module")
def violations_stdout() -> str:
    """Real stdout from a run with nine violated rules."""
    return (TOOL_OUTPUT / "cfnguard_violations.json").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def pass_stdout() -> str:
    """Real stdout from a run where every applicable rule passed."""
    return (TOOL_OUTPUT / "cfnguard_pass.json").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def malformed_stdout() -> str:
    """Real stdout that is not the expected JSON structure."""
    return (TOOL_OUTPUT / "cfnguard_malformed.txt").read_text(encoding="utf-8")


def _proc(
    exit_code: int, stdout: str = "", stderr: str = "", timed_out: bool = False
) -> ProcResult:
    return ProcResult(
        exit_code=exit_code, stdout=stdout, stderr=stderr, timed_out=timed_out
    )


# ---------------------------------------------------------------------------
# (a) - (e) interpret_guard_result
# ---------------------------------------------------------------------------


def test_exit_zero_is_all_passed(pass_stdout: str) -> None:
    """(a) Exit 0 is the one status cfn-guard documents: every rule passed."""
    interpretation = interpret_guard_result(_proc(0, stdout=pass_stdout))
    assert interpretation == GuardInterpretation(kind=KIND_ALL_PASSED)


def test_exit_zero_does_not_consult_stdout(malformed_stdout: str) -> None:
    """Exit 0 needs no parse, so unreadable stdout cannot demote it."""
    assert interpret_guard_result(_proc(0, stdout=malformed_stdout)).kind == (
        KIND_ALL_PASSED
    )


def test_exit_five_with_valid_json_is_violations(violations_stdout: str) -> None:
    """(b) A parsable payload means rule violations whatever the code was."""
    interpretation = interpret_guard_result(_proc(5, stdout=violations_stdout))
    assert interpretation.kind == KIND_VIOLATIONS
    assert interpretation.exit_code == 5
    assert interpretation.payload is not None
    assert len(interpretation.payload) == 9


def test_exit_five_with_non_json_is_tool_error(malformed_stdout: str) -> None:
    """(c) Unparsable stdout means the tool failed (Requirement 5 AC6)."""
    interpretation = interpret_guard_result(
        _proc(5, stdout=malformed_stdout, stderr="line1\nline2\n")
    )
    assert interpretation.kind == KIND_TOOL_ERROR
    assert interpretation.exit_code == 5
    assert interpretation.payload is None
    assert interpretation.stderr_head == ("line1", "line2")


def test_exit_nineteen_with_valid_json_is_violations(violations_stdout: str) -> None:
    """(d) Exit 19 and exit 5 differ only in what gets recorded, not in kind."""
    interpretation = interpret_guard_result(_proc(19, stdout=violations_stdout))
    assert interpretation.kind == KIND_VIOLATIONS
    assert interpretation.exit_code == 19


@pytest.mark.parametrize("code", OBSERVED_NONZERO_CODES)
def test_classification_is_independent_of_the_exit_code_value(
    code: int, violations_stdout: str, malformed_stdout: str
) -> None:
    """(d) The same stdout classifies the same way under every observed code.

    This is Requirement 5 AC7 stated as a test: only stdout decides, and the
    code is carried into the result untouched so it still reaches
    ``StructuredError.exit_code``.
    """
    parsable = interpret_guard_result(_proc(code, stdout=violations_stdout))
    unparsable = interpret_guard_result(_proc(code, stdout=malformed_stdout))
    assert parsable.kind == KIND_VIOLATIONS
    assert unparsable.kind == KIND_TOOL_ERROR
    assert parsable.exit_code == code
    assert unparsable.exit_code == code


def test_the_payload_is_identical_across_exit_codes(violations_stdout: str) -> None:
    """Nothing about the parsed result depends on the status that carried it."""
    payloads = [
        interpret_guard_result(_proc(code, stdout=violations_stdout)).payload
        for code in OBSERVED_NONZERO_CODES
    ]
    assert payloads[0] is not None
    assert all(payload == payloads[0] for payload in payloads)


@pytest.mark.parametrize(
    "case,code,structured,expected", OBSERVED_CASES, ids=[c[0] for c in OBSERVED_CASES]
)
def test_the_measured_cases_classify_as_documented(
    case: str,
    code: int,
    structured: bool,
    expected: str,
    violations_stdout: str,
) -> None:
    """Each case in ``docs/architecture.md`` reaches the classification recorded.

    A regression anchor for the documented table, not a dependency on it: the
    codes are inputs here, never inspected. Its value is that if a future
    cfn-guard changes what any of these five cases produces, the failure names
    the case, and the fix is to re-measure and update both the table and this
    list rather than to add a branch on a code value.
    """
    stdout = violations_stdout if structured else ""
    assert interpret_guard_result(_proc(code, stdout=stdout)).kind == expected


def test_no_documented_code_is_separable_by_magnitude() -> None:
    """19 (violations) sits between 5 and 255 (both failures).

    So no threshold on the code distinguishes a violation from a failure, which
    is the concrete reason the cfn-lint style of decoding a status numerically
    has no analogue for cfn-guard.
    """
    violation_code = 19
    failure_codes = [code for _, code, structured, _ in OBSERVED_CASES if not structured]
    assert min(failure_codes) < violation_code < max(failure_codes)


def test_timeout_is_decided_before_anything_else(violations_stdout: str) -> None:
    """(e) A killed process's status and partial stdout describe the kill."""
    interpretation = interpret_guard_result(
        _proc(19, stdout=violations_stdout, stderr="partial", timed_out=True)
    )
    assert interpretation == GuardInterpretation(kind=KIND_TIMEOUT)


def test_empty_stdout_on_a_non_zero_exit_is_a_tool_error() -> None:
    """The signature of a rule file that failed to parse: exit 5, silent stdout.

    Reading silence as "no violations" would report that failure as a clean
    review, which is the outcome Requirement 5 AC6 exists to prevent.
    """
    interpretation = interpret_guard_result(
        _proc(5, stdout="", stderr="Parsing error handling rule file = broken.guard")
    )
    assert interpretation.kind == KIND_TOOL_ERROR


def test_stderr_head_is_capped_at_five_lines() -> None:
    """The cap bounds how much untrusted tool output reaches the report."""
    stderr = "\n".join("line{0}".format(n) for n in range(1, 12))
    interpretation = interpret_guard_result(_proc(255, stdout="nope", stderr=stderr))
    assert interpretation.stderr_head == (
        "line1",
        "line2",
        "line3",
        "line4",
        "line5",
    )


def test_a_non_integer_exit_code_is_a_programming_error() -> None:
    with pytest.raises(InvalidArgumentsError):
        interpret_guard_result(_proc("19"))  # type: ignore[arg-type]


def test_readable_output_with_no_failed_check_is_violations(pass_stdout: str) -> None:
    """A non-zero status over an all-pass payload stays on the readable path."""
    interpretation = interpret_guard_result(_proc(19, stdout=pass_stdout))
    assert interpretation.kind == KIND_VIOLATIONS
    assert interpretation.payload == ()


def test_try_parse_distinguishes_empty_from_unreadable(
    pass_stdout: str, malformed_stdout: str
) -> None:
    """``()`` means readable with nothing failed; ``None`` means unreadable."""
    assert try_parse_guard_json(pass_stdout) == ()
    assert try_parse_guard_json(malformed_stdout) is None


# ---------------------------------------------------------------------------
# parse_records / parse_output against real output
# ---------------------------------------------------------------------------


def test_the_output_is_a_stream_of_one_record_per_rule_file(
    violations_stdout: str,
) -> None:
    """cfn-guard concatenates objects rather than emitting an array.

    ``json.loads`` rejects the fixture outright, which is the reason
    :func:`parse_records` decodes incrementally.
    """
    with pytest.raises(ValueError):
        json.loads(violations_stdout)
    assert len(parse_records(violations_stdout)) == 11


def test_a_single_json_array_is_read_as_the_same_records(
    violations_stdout: str,
) -> None:
    """A version that wraps the stream in ``[...]`` needs no separate handling."""
    records = parse_records(violations_stdout)
    values = [
        value for value in cfnguard._iter_json_values(violations_stdout)
    ]
    assert parse_records(json.dumps(values)) == records


def test_parse_output_names_every_violated_rule(violations_stdout: str) -> None:
    """Nine of the eleven bundled rules fire on the captured input."""
    assert sorted(result.rule_name for result in parse_output(violations_stdout)) == [
        "rds_backup_retention",
        "rds_deletion_protection",
        "rds_publicly_accessible",
        "rds_storage_encrypted",
        "required_tags",
        "s3_access_logging",
        "s3_bucket_encryption",
        "s3_public_access_block",
        "security_group_open_ingress",
    ]


def _by_rule(raw: str, rule_name: str) -> RawResult:
    matches = [r for r in parse_output(raw) if r.rule_name == rule_name]
    assert len(matches) == 1, "expected exactly one {0} result".format(rule_name)
    return matches[0]


def test_a_resolved_check_carries_the_provided_and_expected_values(
    violations_stdout: str,
) -> None:
    """A property that exists and compared unfavourably: both values are known."""
    result = _by_rule(violations_stdout, "rds_storage_encrypted")
    assert result.resource == "PublicDb"
    assert result.template_path == (
        "Resources",
        "PublicDb",
        "Properties",
        "StorageEncrypted",
    )
    assert result.provided_value == "false"
    assert result.expected_value == "true"
    assert result.custom_message is not None
    assert result.custom_message.startswith("Storage encryption is not enabled")


def test_a_resolved_check_keeps_sequence_indices_in_the_path(
    violations_stdout: str,
) -> None:
    """The path reaches the specific ingress entry, not just the property.

    cfn-guard writes the index as the string ``"0"`` because its path is one
    ``/``-separated string. It is canonicalized to ``int`` at this Source
    boundary so every Source spells one position identically; see
    :func:`iacreview.finding.canonical_template_path`.
    """
    result = _by_rule(violations_stdout, "security_group_open_ingress")
    assert result.resource == "OpenSg"
    assert result.template_path == (
        "Resources",
        "OpenSg",
        "Properties",
        "SecurityGroupIngress",
        0,
        "CidrIp",
    )
    assert result.provided_value == "0.0.0.0/0"


def test_a_numeric_logical_id_stays_a_mapping_key() -> None:
    """Index 1 is a section member name, so a digit-only one is not an index."""
    raw = json.dumps(
        _record(
            _violation(
                "rds_storage_encrypted",
                _clause(
                    "Binary",
                    {
                        "Resolved": {
                            "from": {
                                "path": "/Resources/123/Properties/StorageEncrypted",
                                "value": False,
                            },
                            "to": {"path": "", "value": True},
                            "comparison": ["Eq", False],
                        }
                    },
                ),
            )
        )
    )
    (result,) = parse_output(raw)
    assert result.template_path[:2] == ("Resources", "123")
    assert result.resource == "123"


def test_cfn_guard_and_iam_review_agree_on_one_statement_position() -> None:
    """The same statement, addressed by two Sources, is one ``TemplatePath``.

    cfn-guard reconstructs the path from a ``/``-separated string and IAM Review
    from a ``.``-separated one. Deduplication merges their Findings and picks one
    ``Location`` for the result, so a disagreement over ``0`` versus ``"0"``
    would make one position look like two in the report.
    """
    statement_path = "Resources.AppExecutionRole.Properties.Policies.0.PolicyDocument.Statement.0.Action"
    raw = json.dumps(
        _record(
            _violation(
                "iam_policy_no_star_star",
                _clause(
                    "Binary",
                    {
                        "Resolved": {
                            "from": {
                                "path": "/" + statement_path.replace(".", "/"),
                                "value": ["*"],
                            },
                            "to": {"path": "", "value": "*"},
                            "comparison": ["Eq", True],
                        }
                    },
                ),
            )
        )
    )
    (guard_result,) = parse_output(raw)
    site = PolicySite(
        logical_id="AppExecutionRole",
        kind=PolicyKind.INLINE_ROLE_POLICY,
        json_path=statement_path,
        document={},
    )

    assert list(guard_result.template_path) == site.template_path


def test_an_unresolved_check_reports_the_property_that_is_missing(
    violations_stdout: str,
) -> None:
    """The path is traversal + remaining query, not the struct traversal stopped at.

    Without reassembling the two, every missing-property violation on one
    resource would report the same path, and a report could not say which
    property was absent.
    """
    result = _by_rule(violations_stdout, "s3_bucket_encryption")
    assert result.resource == "PlainBucket"
    assert result.template_path == (
        "Resources",
        "PlainBucket",
        "Properties",
        "BucketEncryption",
    )
    assert result.provided_value is None
    assert result.expected_value is None
    assert result.error_message is not None
    assert "BucketEncryption" in result.error_message


def test_a_dotted_remaining_query_becomes_separate_path_segments() -> None:
    """cfn-guard writes ``VersioningConfiguration.Status`` as one fragment."""
    raw = json.dumps(
        _record(
            _violation(
                "versioning_enabled",
                _clause(
                    "Binary",
                    {
                        "UnResolved": {
                            "value": {
                                "traversed_to": {
                                    "path": "/Resources/PlainBucket/Properties",
                                    "value": {"BucketName": "plain-bucket"},
                                },
                                "remaining_query": "VersioningConfiguration.Status",
                                "reason": "Could not find key",
                            },
                            "comparison": ["Eq", False],
                        }
                    },
                ),
            )
        )
    )
    (result,) = parse_output(raw)
    assert result.template_path == (
        "Resources",
        "PlainBucket",
        "Properties",
        "VersioningConfiguration",
        "Status",
    )


def test_an_index_inside_a_remaining_query_is_canonicalized() -> None:
    """Canonicalization sees the assembled path, not the two fragments.

    The remaining query's own second segment is ``0``. Canonicalizing each
    fragment separately would exempt it as a logical-ID position and leave the
    string ``"0"`` in the middle of the path.
    """
    raw = json.dumps(
        _record(
            _violation(
                "bucket_tags_present",
                _clause(
                    "Binary",
                    {
                        "UnResolved": {
                            "value": {
                                "traversed_to": {
                                    "path": "/Resources/PlainBucket/Properties",
                                    "value": {"BucketName": "plain-bucket"},
                                },
                                "remaining_query": "Tags.0.Key",
                                "reason": "Could not find key",
                            },
                            "comparison": ["Eq", False],
                        }
                    },
                ),
            )
        )
    )
    (result,) = parse_output(raw)
    assert result.template_path == (
        "Resources",
        "PlainBucket",
        "Properties",
        "Tags",
        0,
        "Key",
    )


def test_a_custom_message_is_stripped_of_the_padding_guard_adds(
    violations_stdout: str,
) -> None:
    """cfn-guard pads a ``<<...>>`` message with a space on each side."""
    for result in parse_output(violations_stdout):
        assert result.custom_message is not None
        assert result.custom_message == result.custom_message.strip()


def test_the_clause_context_records_what_was_checked(
    violations_stdout: str,
) -> None:
    """The clause text is Evidence the rule name only implies."""
    result = _by_rule(violations_stdout, "s3_public_access_block")
    assert result.context == (
        "%s3_buckets[*].Properties.PublicAccessBlockConfiguration EXISTS"
    )


def test_a_pass_run_reports_no_violations_and_the_rule_counts(
    pass_stdout: str,
) -> None:
    """``compliant`` / ``not_applicable`` are what make Requirement 5 AC4 countable."""
    records = parse_records(pass_stdout)
    assert parse_output(pass_stdout) == []
    assert sum(len(record.compliant) for record in records) == 4
    assert sum(len(record.not_applicable) for record in records) == 7
    assert {record.status for record in records} == {"PASS", "SKIP"}


def test_record_order_follows_the_tool(violations_stdout: str) -> None:
    """Ordering the report is Requirement 7 AC15's job, not this Source's."""
    names = [
        record.violations[0].rule_name
        for record in parse_records(violations_stdout)
        if record.violations
    ]
    assert names != sorted(names)


# ---------------------------------------------------------------------------
# Clause shapes not present in the captured fixture
# ---------------------------------------------------------------------------


def _clause(arity: str, check: Dict[str, Any], context: str = " ctx ") -> Dict[str, Any]:
    return {
        "Clause": {
            arity: {
                "context": context,
                "messages": {"custom_message": " msg ", "error_message": " err "},
                "check": check,
            }
        }
    }


def _violation(rule_name: str, *checks: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "Rule": {
            "name": rule_name,
            "metadata": {},
            "messages": {"custom_message": None, "error_message": None},
            "checks": list(checks),
        }
    }


def _record(*violations: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": "template.yaml",
        "metadata": {},
        "status": "FAIL" if violations else "PASS",
        "not_compliant": list(violations),
        "not_applicable": [],
        "compliant": [],
    }


def test_a_dependent_rule_failure_has_no_template_location() -> None:
    """``UnResolvedContext`` names a rule, not a property (observed shape)."""
    raw = json.dumps(
        _record(
            _violation(
                "outer",
                _clause(
                    "Unary",
                    {"UnResolvedContext": "inner"},
                    context="Rule(inner@Location[file:outer.guard, line:9, column:3])",
                ),
            )
        )
    )
    (result,) = parse_output(raw)
    assert result.rule_name == "outer"
    assert result.resource is None
    assert result.template_path == ()
    assert result.provided_value is None


def test_a_unary_resolved_check_carries_a_value_and_no_comparison_target() -> None:
    """A ``Unary`` ``Resolved`` check has ``value``, not ``from`` and ``to``.

    Regression test. ``_parse_resolved`` originally required the ``Binary`` shape
    for every ``Resolved`` check, so a ``Unary`` operator over a query that *did*
    resolve made the whole payload unparsable -- and because an unparsable
    payload is discarded in full (Requirement 5 AC6), every Guard finding for
    that template was lost and the Source degraded to a ``tool_error``.

    The bundled rule that reaches this shape is
    ``rules/iam/iam_policy_no_star_star.guard``, whose body asks whether a
    filtered ``Statement`` list is ``empty``: when a statement matches the
    filter, the query resolves to that statement and cfn-guard reports the
    statement itself as the value. The bundled ``exists`` rules never exposed the
    bug because an absent property resolves to ``UnResolved`` instead.

    The payload below is the shape cfn-guard 3.2.1 emitted for
    ``benchmark/cases/case-001-iam-wildcard``, which is the case that measures
    it.
    """
    raw = json.dumps(
        _record(
            _violation(
                "iam_policy_no_star_star",
                _clause(
                    "Unary",
                    {
                        "Resolved": {
                            "value": {
                                "path": (
                                    "/Resources/AdministratorManagedPolicy"
                                    "/Properties/PolicyDocument/Statement/0"
                                ),
                                "value": {
                                    "Sid": "AllowEverything",
                                    "Effect": "Allow",
                                    "Action": "*",
                                    "Resource": "*",
                                },
                            },
                            "comparison": ["Empty", False],
                        }
                    },
                ),
            )
        )
    )

    (result,) = parse_output(raw)

    assert result.rule_name == "iam_policy_no_star_star"
    assert result.resource == "AdministratorManagedPolicy"
    assert result.template_path == (
        "Resources",
        "AdministratorManagedPolicy",
        "Properties",
        "PolicyDocument",
        "Statement",
        0,
    )
    # The matched statement, rendered as stable JSON: the evidence a reader needs
    # to see why the rule fired.
    assert result.provided_value is not None
    assert '"Action":"*"' in result.provided_value
    # No expected value exists. A unary operator compares against nothing, and
    # ``error_message`` already spells the operator out.
    assert result.expected_value is None


def test_a_unary_resolved_check_without_a_value_is_a_structural_mismatch() -> None:
    """The ``Unary`` branch is not a licence to accept anything.

    ``value`` has to be an object carrying a ``path``; a payload that is neither
    the ``Binary`` shape nor a usable ``Unary`` one is discarded like any other
    unrecognized structure rather than yielding a Finding with no location.
    """
    raw = json.dumps(
        _record(
            _violation(
                "iam_policy_no_star_star",
                _clause("Unary", {"Resolved": {"comparison": ["Empty", False]}}),
            )
        )
    )

    with pytest.raises(TemplateParseError):
        parse_records(raw)


def test_a_nested_rule_is_attributed_to_the_outer_rule() -> None:
    """The outer rule is what the policy set names and what ``_meta.json`` describes."""
    inner = _violation(
        "inner",
        _clause(
            "Binary",
            {
                "Resolved": {
                    "from": {"path": "/Resources/Db/Properties/Encrypted", "value": False},
                    "to": {"path": "", "value": True},
                    "comparison": ["Eq", False],
                }
            },
        ),
    )
    raw = json.dumps(_record(_violation("outer", inner)))
    (result,) = parse_output(raw)
    assert result.rule_name == "outer"
    assert result.resource == "Db"


def test_a_non_string_value_is_rendered_as_stable_json() -> None:
    """Key order cannot vary between runs (Requirement 16 AC11)."""
    raw = json.dumps(
        _record(
            _violation(
                "struct_rule",
                _clause(
                    "Binary",
                    {
                        "Resolved": {
                            "from": {
                                "path": "/Resources/B/Properties/Cfg",
                                "value": {"b": 2, "a": 1},
                            },
                            "to": {"path": "", "value": [1, 2]},
                            "comparison": ["Eq", False],
                        }
                    },
                ),
            )
        )
    )
    (result,) = parse_output(raw)
    assert result.provided_value == '{"a":1,"b":2}'
    assert result.expected_value == "[1,2]"


def test_unknown_record_fields_are_ignored() -> None:
    """A newer cfn-guard adding a field must not break the Source."""
    record = _record()
    record["future_field"] = {"nested": True}
    assert parse_records(json.dumps(record))[0].violations == ()


def test_a_clause_without_messages_yields_none() -> None:
    """A rule that declares no ``<<...>>`` message has no remediation of its own.

    The caller falls back to the sidecar's ``recommendation``, which is why
    ``None`` and ``""`` are not distinguished here.
    """
    clause = _clause("Unary", {"UnResolvedContext": "inner"})
    clause["Clause"]["Unary"]["messages"] = {
        "custom_message": None,
        "error_message": "",
    }
    (result,) = parse_output(json.dumps(_record(_violation("r", clause))))
    assert result.custom_message is None
    assert result.error_message is None


def test_records_separated_by_whitespace_are_read_as_a_stream() -> None:
    """cfn-guard 3.2.1 concatenates with no separator; newlines are tolerated."""
    raw = "\n".join([json.dumps(_record()), json.dumps(_record())]) + "\n"
    assert len(parse_records(raw)) == 2


def test_nesting_beyond_the_depth_limit_is_rejected() -> None:
    """A bound on recursion, so a hostile payload cannot exhaust the stack."""
    innermost = _violation(
        "leaf", _clause("Unary", {"UnResolvedContext": "inner"})
    )
    nested = innermost
    for _ in range(cfnguard.MAX_CHECK_DEPTH + 2):
        nested = _violation("wrapper", nested)
    with pytest.raises(TemplateParseError) as caught:
        parse_output(json.dumps(_record(nested)))
    assert "maximum depth" in caught.value.reason


# ---------------------------------------------------------------------------
# resource_from_path
# ---------------------------------------------------------------------------

RESOURCE_PATH_CASES = [
    (("Resources", "MyBucket", "Properties", "BucketName"), "MyBucket"),
    (("Resources", "MyBucket"), "MyBucket"),
    (("Resources",), None),
    (("Parameters", "DbPassword"), None),
    (("Outputs", "BucketArn"), None),
    ((), None),
]


@pytest.mark.parametrize(("path", "expected"), RESOURCE_PATH_CASES)
def test_resource_from_path(path: tuple, expected: object) -> None:
    assert resource_from_path(path) == expected


def test_resource_from_path_accepts_a_missing_path() -> None:
    assert resource_from_path(None) is None


# ---------------------------------------------------------------------------
# Structural mismatch: the whole payload is discarded
# ---------------------------------------------------------------------------

MISMATCH_CASES = [
    ("", "<stdout>"),  # silent stdout is a rule parse failure, not a clean run
    ("   \n\t ", "<stdout>"),
    ("Evaluating data template.yaml against rules x.guard", "<stdout>"),
    ("{}", "[0].not_compliant"),  # no not_compliant
    ('{"not_compliant": {}}', "[0].not_compliant"),  # not a list
    ('{"not_compliant": [[]]}', "[0].not_compliant[0]"),  # element not an object
    ('{"not_compliant": [{}]}', "[0].not_compliant[0].Rule"),  # no Rule
    (
        '{"not_compliant": [{"Rule": {"checks": []}}]}',
        "[0].not_compliant[0].Rule.name",
    ),
    (
        '{"not_compliant": [{"Rule": {"name": "", "checks": []}}]}',
        "[0].not_compliant[0].Rule.name",
    ),
    (
        '{"not_compliant": [{"Rule": {"name": "r", "checks": {}}}]}',
        "[0].not_compliant[0].Rule.checks",
    ),
    (
        '{"not_compliant": [{"Rule": {"name": "r", "checks": [{"Nope": {}}]}}]}',
        "[0].not_compliant[0].Rule.checks[0]",
    ),
    (
        '{"not_compliant": [{"Rule": {"name": "r", '
        '"checks": [{"Clause": {"Ternary": {}}}]}}]}',
        "[0].not_compliant[0].Rule.checks[0].Clause",
    ),
    (
        '{"not_compliant": [{"Rule": {"name": "r", '
        '"checks": [{"Clause": {"Unary": {"check": {"Whatever": 1}}}}]}}]}',
        "[0].not_compliant[0].Rule.checks[0].Clause.Unary.check",
    ),
    (
        '{"not_compliant": [], "compliant": [1]}',
        "[0].compliant[0]",
    ),
    (
        '{"not_compliant": [], "not_applicable": "all"}',
        "[0].not_applicable",
    ),
    ('{"not_compliant": [], "status": 5}', "[0].status"),
    ('{"not_compliant": [], "name": []}', "[0].name"),
]


@pytest.mark.parametrize(("raw", "field"), MISMATCH_CASES)
def test_a_structural_mismatch_discards_the_payload(raw: str, field: str) -> None:
    with pytest.raises(TemplateParseError) as caught:
        parse_output(raw)
    error = caught.value
    assert error.error_class == "parse_failure"
    assert error.tool == "cfn-guard"
    assert error.field == field


def test_a_resolved_check_without_a_path_is_a_mismatch() -> None:
    """``from.path`` is the only route to the logical resource name."""
    raw = json.dumps(
        _record(
            _violation(
                "r",
                _clause(
                    "Binary",
                    {"Resolved": {"from": {"value": 1}, "to": {"value": 2}}},
                ),
            )
        )
    )
    with pytest.raises(TemplateParseError) as caught:
        parse_output(raw)
    assert caught.value.field.endswith("Resolved.from.path")


def test_a_json_syntax_error_reports_its_position() -> None:
    with pytest.raises(TemplateParseError) as caught:
        parse_output('{"not_compliant": [},}')
    error = caught.value
    assert error.error_class == "parse_failure"
    assert error.error_type == "JSONDecodeError"
    assert error.line == 1
    assert error.column is not None


def test_valid_records_are_discarded_alongside_a_bad_one() -> None:
    """No partial list: one unusable record invalidates the whole stream."""
    raw = json.dumps(_record()) + json.dumps({"status": "FAIL"})
    with pytest.raises(TemplateParseError):
        parse_output(raw)


def test_non_text_stdout_is_a_mismatch() -> None:
    with pytest.raises(TemplateParseError):
        parse_output(None)  # type: ignore[arg-type]


def test_a_parse_failure_renders_as_a_structured_error() -> None:
    with pytest.raises(TemplateParseError) as caught:
        parse_output("not json at all")
    structured = caught.value.to_structured_error(source="cfn-guard")
    assert structured["error_class"] == "parse_failure"
    assert structured["source"] == "cfn-guard"
    assert structured["tool"] == "cfn-guard"


# ---------------------------------------------------------------------------
# (f) _meta.json loading
# ---------------------------------------------------------------------------


def test_the_bundled_sidecars_resolve_every_bundled_rule() -> None:
    """Eleven rules across six categories, with no fallback and no error."""
    metadata = load_rule_metadata()
    assert metadata.errors == ()
    assert metadata.rule_count == 17
    assert len(metadata.category_names()) == 6
    for rule_name in metadata.rule_names():
        meta = metadata.for_rule(rule_name)
        assert meta.from_sidecar is True
        assert meta.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        assert meta.why_it_matters
        assert meta.recommendation


def test_a_rule_level_normalized_category_overrides_its_directory() -> None:
    """The exception design.md names: public-access -> NetworkSecurity."""
    metadata = load_rule_metadata()
    assert metadata.for_rule("security_group_open_ingress").normalized_category == (
        "NetworkSecurity"
    )
    assert metadata.for_rule("s3_public_access_block").normalized_category == (
        "PublicAccess"
    )


def test_a_rule_falls_back_to_its_category_default() -> None:
    """``default`` covers a rule the sidecar's ``rules`` object omits."""
    metadata = load_rule_metadata()
    assert metadata.for_rule("s3_bucket_encryption").finding_type == "Security"


def test_a_rule_no_directory_declares_resolves_conservatively() -> None:
    """cfn-guard naming an unknown rule is not a reason to fail the review."""
    meta = load_rule_metadata().for_rule("some_rule_from_a_users_own_directory")
    assert meta.category is None
    assert meta.finding_type == FALLBACK_FINDING_TYPE
    assert meta.severity == FALLBACK_SEVERITY
    assert meta.normalized_category == "Other"
    assert meta.from_sidecar is False


def _rule_tree(root: Path, category: str, rule_names: List[str]) -> Path:
    directory = root / category
    directory.mkdir(parents=True, exist_ok=True)
    for rule_name in rule_names:
        (directory / "{0}.guard".format(rule_name)).write_text(
            "rule {0} {{\n  Resources exists\n}}\n".format(rule_name),
            encoding="utf-8",
        )
    return directory


def _valid_meta(category: str, normalized: str, severity: str) -> str:
    return json.dumps(
        {
            "schema_version": "1.0.0",
            "category": category,
            "normalized_category": normalized,
            "default": {"finding_type": "Security", "severity": severity},
            "rules": {},
        }
    )


MALFORMED_META = [
    pytest.param("", id="empty file"),
    pytest.param("{ not json", id="invalid json"),
    pytest.param("[]", id="not an object"),
    pytest.param('{"default": {"finding_type": "Security", "severity": "HIGH"}}', id="no schema_version"),
    pytest.param('{"schema_version": "2.0.0", "default": {"finding_type": "Security", "severity": "HIGH"}}', id="unsupported major"),
    pytest.param('{"schema_version": "1.0.0"}', id="no default"),
    pytest.param('{"schema_version": "1.0.0", "default": {"severity": "HIGH"}}', id="no default.finding_type"),
    pytest.param('{"schema_version": "1.0.0", "default": {"finding_type": "Security", "severity": "SEVERE"}}', id="unknown severity"),
    pytest.param('{"schema_version": "1.0.0", "default": {"finding_type": "Vulnerability", "severity": "HIGH"}}', id="unknown finding_type"),
    pytest.param('{"schema_version": "1.0.0", "normalized_category": "Networking", "default": {"finding_type": "Security", "severity": "HIGH"}}', id="unknown normalized_category"),
    pytest.param('{"schema_version": "1.0.0", "default": {"finding_type": "Security", "severity": "HIGH"}, "rules": {"r": {"normalised_category": "IAM"}}}', id="misspelled rule field"),
    pytest.param('{"schema_version": "1.0.0", "default": {"finding_type": "Security", "severity": "HIGH"}, "rules": {"r": {"severity": "SEVERE"}}}', id="unknown rule severity"),
    pytest.param('{"schema_version": "1.0.0", "defaults": {"finding_type": "Security", "severity": "HIGH"}}', id="misspelled top-level field"),
    pytest.param('{"schema_version": "x.0.0", "default": {"finding_type": "Security", "severity": "HIGH"}}', id="non-numeric major"),
    pytest.param('{"schema_version": 1, "default": {"finding_type": "Security", "severity": "HIGH"}}', id="schema_version not a string"),
    pytest.param('{"schema_version": "1.0.0", "normalized_category": 7, "default": {"finding_type": "Security", "severity": "HIGH"}}', id="normalized_category not a string"),
    pytest.param('{"schema_version": "1.0.0", "default": {"finding_type": "Security", "severity": "HIGH"}, "rules": {"": {}}}', id="empty rule name key"),
    pytest.param('{"schema_version": "1.0.0", "default": {"finding_type": "Security", "severity": "HIGH"}, "rules": {"r": {"finding_type": "Vulnerability"}}}', id="unknown rule finding_type"),
    pytest.param('{"schema_version": "1.0.0", "default": {"finding_type": "Security", "severity": "HIGH"}, "rules": {"r": {"normalized_category": "Networking"}}}', id="unknown rule normalized_category"),
    pytest.param('{"schema_version": "1.0.0", "default": {"finding_type": "Security", "severity": "HIGH"}, "rules": {"r": {"why_it_matters": ""}}}', id="empty rule why_it_matters"),
    pytest.param('{"schema_version": "1.0.0", "default": {"finding_type": "Security", "severity": "HIGH"}, "rules": "none"}', id="rules not an object"),
]


@pytest.mark.parametrize("content", MALFORMED_META)
def test_a_broken_sidecar_falls_back_and_records_a_parse_failure(
    content: str, tmp_path: Path
) -> None:
    """(f) The category degrades, an error is recorded, the rule still resolves."""
    directory = _rule_tree(tmp_path, "encryption", ["r"])
    (directory / "_meta.json").write_text(content, encoding="utf-8")

    metadata = load_rule_metadata([tmp_path])

    assert metadata.rule_names() == ("r",)
    meta = metadata.for_rule("r")
    assert meta.category == "encryption"
    assert meta.finding_type == FALLBACK_FINDING_TYPE
    assert meta.severity == FALLBACK_SEVERITY
    assert meta.why_it_matters == ""
    assert meta.recommendation == ""
    assert meta.from_sidecar is False

    (error,) = metadata.errors
    assert error["error_class"] == "parse_failure"
    assert error["source"] == "cfn-guard"
    assert error["tool"] == "cfn-guard"
    assert "_meta.json" in str(error["message"])
    assert "_meta.json" in str(error["remediation"])


def test_a_missing_sidecar_falls_back_and_records_a_parse_failure(
    tmp_path: Path,
) -> None:
    """(f) An absent ``_meta.json`` is handled exactly as a broken one."""
    _rule_tree(tmp_path, "logging", ["r"])
    metadata = load_rule_metadata([tmp_path])

    assert metadata.for_rule("r").severity == FALLBACK_SEVERITY
    (error,) = metadata.errors
    assert error["error_class"] == "parse_failure"


def test_a_sidecar_that_is_not_utf8_falls_back(tmp_path: Path) -> None:
    """Untrusted bytes must fail safely, not raise out of the loader."""
    directory = _rule_tree(tmp_path, "backup", ["r"])
    (directory / "_meta.json").write_bytes(b'{"category": "\xff\xfe"}')

    metadata = load_rule_metadata([tmp_path])

    assert metadata.for_rule("r").severity == FALLBACK_SEVERITY
    (error,) = metadata.errors
    assert error["error_class"] == "parse_failure"


def test_the_fallback_category_meta_is_reported_as_a_fallback(
    tmp_path: Path,
) -> None:
    """A report can tell a degraded category from one that chose these values."""
    _rule_tree(tmp_path, "tagging", ["r"])
    metadata = load_rule_metadata([tmp_path])

    meta = metadata.category_meta("tagging")
    assert meta is not None
    assert meta.is_fallback is True
    assert meta.default_severity == FALLBACK_SEVERITY
    assert metadata.category_meta("absent-category") is None


def test_a_single_guard_file_is_accepted_as_a_rules_path(tmp_path: Path) -> None:
    """``cfn-guard --rules`` takes a file or a directory, and so does the loader."""
    directory = _rule_tree(tmp_path, "encryption", ["only_rule", "other_rule"])
    (directory / "_meta.json").write_text(
        _valid_meta("encryption", "Encryption", "HIGH"), encoding="utf-8"
    )

    metadata = load_rule_metadata([directory / "only_rule.guard"])

    assert metadata.rule_names() == ("only_rule",)
    assert metadata.for_rule("only_rule").severity == "HIGH"


def test_a_non_guard_file_is_not_read_as_a_rule(tmp_path: Path) -> None:
    """``_meta.json`` sits beside the rules and must never count as one."""
    directory = _rule_tree(tmp_path, "encryption", ["r"])
    (directory / "_meta.json").write_text(
        _valid_meta("encryption", "Encryption", "HIGH"), encoding="utf-8"
    )
    (directory / "notes.md").write_text("not a rule", encoding="utf-8")

    assert load_rule_metadata([tmp_path]).rule_names() == ("r",)
    assert load_rule_metadata([directory / "_meta.json"]).rule_names() == ()


def test_a_duplicate_rule_name_resolves_the_same_way_either_order(
    tmp_path: Path,
) -> None:
    """Two directories declaring one rule name must not depend on argument order."""
    first = tmp_path / "first"
    second = tmp_path / "second"
    encryption = _rule_tree(first, "encryption", ["shared"])
    (encryption / "_meta.json").write_text(
        _valid_meta("encryption", "Encryption", "HIGH"), encoding="utf-8"
    )
    logging_dir = _rule_tree(second, "logging", ["shared"])
    (logging_dir / "_meta.json").write_text(
        _valid_meta("logging", "Logging", "LOW"), encoding="utf-8"
    )

    forward = load_rule_metadata([first, second])
    reverse = load_rule_metadata([second, first])

    assert forward.rule_count == reverse.rule_count == 1
    assert forward.for_rule("shared") == reverse.for_rule("shared")


def test_same_named_directories_keep_their_own_sidecars(tmp_path: Path) -> None:
    """A sidecar governs its own directory, never a namesake under another root.

    Two roots may each ship an ``encryption/`` directory. Keying metadata on the
    directory name would let one sidecar decide the Severity of rules it never
    described.
    """
    bundled = _rule_tree(tmp_path / "bundled", "encryption", ["bundled_rule"])
    (bundled / "_meta.json").write_text(
        _valid_meta("encryption", "Encryption", "HIGH"), encoding="utf-8"
    )
    extra = _rule_tree(tmp_path / "extra", "encryption", ["extra_rule"])
    (extra / "_meta.json").write_text(
        _valid_meta("encryption", "DataProtection", "LOW"), encoding="utf-8"
    )

    metadata = load_rule_metadata([tmp_path / "bundled", tmp_path / "extra"])

    assert metadata.errors == ()
    assert metadata.category_names() == ("encryption",)
    assert metadata.for_rule("bundled_rule").severity == "HIGH"
    assert metadata.for_rule("bundled_rule").normalized_category == "Encryption"
    assert metadata.for_rule("extra_rule").severity == "LOW"
    assert metadata.for_rule("extra_rule").normalized_category == "DataProtection"


def test_a_broken_sidecar_does_not_degrade_another_category(tmp_path: Path) -> None:
    """Rule execution continues, and only the broken category loses its values."""
    broken = _rule_tree(tmp_path, "encryption", ["broken_rule"])
    (broken / "_meta.json").write_text("{ not json", encoding="utf-8")
    intact = _rule_tree(tmp_path, "iam", ["intact_rule"])
    (intact / "_meta.json").write_text(
        _valid_meta("iam", "IAM", "CRITICAL"), encoding="utf-8"
    )

    metadata = load_rule_metadata([tmp_path])

    assert metadata.rule_names() == ("broken_rule", "intact_rule")
    assert len(metadata.errors) == 1
    assert metadata.for_rule("broken_rule").severity == FALLBACK_SEVERITY
    assert metadata.for_rule("intact_rule").severity == "CRITICAL"
    assert metadata.for_rule("intact_rule").normalized_category == "IAM"


def test_the_result_does_not_depend_on_the_order_of_rules_dirs(
    tmp_path: Path,
) -> None:
    """Requirement 16 AC11: identical input, identical output, any order."""
    first = tmp_path / "first"
    second = tmp_path / "second"
    encryption = _rule_tree(first, "encryption", ["a_rule"])
    (encryption / "_meta.json").write_text(
        _valid_meta("encryption", "Encryption", "HIGH"), encoding="utf-8"
    )
    logging_dir = _rule_tree(second, "logging", ["b_rule"])
    (logging_dir / "_meta.json").write_text(
        _valid_meta("logging", "Logging", "MEDIUM"), encoding="utf-8"
    )

    forward = load_rule_metadata([first, second])
    reverse = load_rule_metadata([second, first])

    assert forward.rule_names() == reverse.rule_names() == ("a_rule", "b_rule")
    for rule_name in forward.rule_names():
        assert forward.for_rule(rule_name) == reverse.for_rule(rule_name)
    assert forward.errors == reverse.errors


def test_a_flat_rules_directory_uses_its_own_name_as_the_category(
    tmp_path: Path,
) -> None:
    """A sidecar governs the rules beside it, whatever the layout."""
    flat = tmp_path / "my-rules"
    flat.mkdir()
    (flat / "custom.guard").write_text("rule custom {\n  Resources exists\n}\n")
    (flat / "_meta.json").write_text(
        _valid_meta("my-rules", "Availability", "LOW"), encoding="utf-8"
    )

    metadata = load_rule_metadata([flat])
    meta = metadata.for_rule("custom")
    assert metadata.errors == ()
    assert meta.category == "my-rules"
    assert meta.normalized_category == "Availability"
    assert meta.severity == "LOW"


def test_a_nonexistent_rules_dir_yields_no_rules(tmp_path: Path) -> None:
    """Reporting a missing directory is cfn-guard's job; this loader stays quiet."""
    metadata = load_rule_metadata([tmp_path / "absent"])
    assert metadata.rule_names() == ()
    assert metadata.rule_count == 0
    assert metadata.errors == ()


def test_rule_count_is_the_rules_evaluated_fallback() -> None:
    """The count Requirement 5 AC4 needs when the tool's output omits it."""
    metadata = load_rule_metadata()
    assert metadata.rule_count == len(metadata.rule_names())
