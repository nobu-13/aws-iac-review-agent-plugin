"""Tests for :mod:`iacreview.iam.intrinsics` (Task 13.2; Requirement 6 AC7, AC8).

Four groups, matching the module's two obligations and the completion condition.

1. :data:`PRINCIPAL_CASES` -- one case per branch of design.md's
   ``classify_principal`` pseudocode, covering all five
   :class:`~iacreview.iam.intrinsics.PrincipalClass` values.
   :func:`test_every_principal_class_is_covered` fails if a class has no case,
   so the parametrization cannot quietly stop being exhaustive.
2. :data:`TABLE_CASES` -- the seven rows of design.md's *解決不能な intrinsic
   function の扱い* table, each case tagged with its row.
   :func:`test_every_table_row_is_covered` asserts all seven rows appear, which
   is Task 13.2's completion condition expressed as a test.
3. Unresolvable is never silent: the located records, their Finding text, and
   the deduplication that keeps one gap from being reported fifteen times.
4. Untrusted input: wrong types and hostile nesting must produce a reason, not
   an exception.

Predicates in these tests are the two shapes real detectors use -- "is exactly
``*``" and "contains ``*``" -- because the module's contract is about how a
predicate reaches the value, not about what the predicate asks.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Callable, List, Tuple

import pytest

# tests/unit/test_iam_intrinsics.py -> tests/unit -> tests -> plugin root
PLUGIN_ROOT: Path = Path(__file__).resolve().parents[2]
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

from iacreview.iam import intrinsics
from iacreview.iam.intrinsics import (
    PrincipalClass,
    ResolutionContext,
    UnresolvedValue,
    ValueKind,
    Verdict,
)

Predicate = Callable[[str], bool]


def is_star(text: str) -> bool:
    """A Resource or Action that is exactly ``"*"``."""
    return text == "*"


def has_wildcard(text: str) -> bool:
    """A Resource or Action containing a wildcard anywhere."""
    return "*" in text


# ---------------------------------------------------------------------------
# 1. classify_principal: the five classes
# ---------------------------------------------------------------------------

#: (value, expected class, case id). One case per pseudocode branch, written
#: from design.md rather than from the implementation.
PRINCIPAL_CASES: List[Tuple[Any, PrincipalClass, str]] = [
    # STAR (AC9): both spellings the requirement names.
    ("*", PrincipalClass.STAR, "literal_star"),
    ({"AWS": "*"}, PrincipalClass.STAR, "aws_star_mapping"),
    # SAME_ACCOUNT (AC8): every spelling of the pseudo parameter.
    ({"Ref": "AWS::AccountId"}, PrincipalClass.SAME_ACCOUNT, "ref_account_id"),
    (
        {"Fn::Sub": "arn:aws:iam::${AWS::AccountId}:root"},
        PrincipalClass.SAME_ACCOUNT,
        "sub_account_id_only",
    ),
    (
        "arn:aws:iam::${AWS::AccountId}:root",
        PrincipalClass.SAME_ACCOUNT,
        "string_account_id_substitution",
    ),
    # CROSS_ACCOUNT (AC7): a bare literal ID and one embedded in an ARN.
    ("123456789012", PrincipalClass.CROSS_ACCOUNT, "literal_account_id"),
    (
        "arn:aws:iam::123456789012:role/Peer",
        PrincipalClass.CROSS_ACCOUNT,
        "arn_with_account_id",
    ),
    (
        "arn:aws-cn:iam::123456789012:root",
        PrincipalClass.CROSS_ACCOUNT,
        "arn_non_default_partition",
    ),
    # SERVICE.
    ("lambda.amazonaws.com", PrincipalClass.SERVICE, "service_principal"),
    # UNRESOLVABLE: one case per way the value can fail to be determined.
    (
        {"Fn::Sub": "arn:aws:iam::${TrustedAccount}:root"},
        PrincipalClass.UNRESOLVABLE,
        "sub_other_variable",
    ),
    (
        {"Fn::Sub": "arn:aws:iam::${AWS::AccountId}:role/${RoleName}"},
        PrincipalClass.UNRESOLVABLE,
        "sub_account_id_plus_other_variable",
    ),
    (
        {"Fn::Sub": ["arn:aws:iam::${Peer}:root", {"Peer": {"Ref": "PeerAccount"}}]},
        PrincipalClass.UNRESOLVABLE,
        "sub_list_form_with_variable_map",
    ),
    (
        {"Fn::GetAtt": ["PeerRole", "Arn"]},
        PrincipalClass.UNRESOLVABLE,
        "get_att",
    ),
    (
        {"Fn::ImportValue": "shared-peer-account"},
        PrincipalClass.UNRESOLVABLE,
        "import_value",
    ),
    ({"Ref": "PeerAccount"}, PrincipalClass.UNRESOLVABLE, "ref_parameter"),
    ("12345", PrincipalClass.UNRESOLVABLE, "too_few_digits"),
    (123456789012, PrincipalClass.UNRESOLVABLE, "non_string_scalar"),
    (None, PrincipalClass.UNRESOLVABLE, "empty_value"),
]


@pytest.mark.parametrize(
    "value,expected",
    [(value, expected) for value, expected, _ in PRINCIPAL_CASES],
    ids=[case_id for _, _, case_id in PRINCIPAL_CASES],
)
def test_classify_principal(value: Any, expected: PrincipalClass) -> None:
    assert intrinsics.classify_principal(value) is expected


def test_every_principal_class_is_covered() -> None:
    """All five classes must have a case, or the parametrization is incomplete."""
    covered = {expected for _, expected, _ in PRINCIPAL_CASES}
    assert covered == set(PrincipalClass)
    assert len(PrincipalClass) == 5


def test_account_id_pseudo_parameter_is_never_cross_account() -> None:
    """Requirement 6 AC8 stated directly: no spelling of it is cross-account."""
    spellings: Tuple[Any, ...] = (
        {"Ref": "AWS::AccountId"},
        {"Fn::Sub": "arn:aws:iam::${AWS::AccountId}:root"},
        {"Fn::Sub": "${AWS::AccountId}"},
        "arn:aws:sts::${AWS::AccountId}:assumed-role/App",
    )
    for value in spellings:
        assert (
            intrinsics.classify_principal(value) is PrincipalClass.SAME_ACCOUNT
        ), value


def test_literal_account_id_is_same_account_when_declared_as_own() -> None:
    """``template_account_refs`` marks IDs the caller knows to be its own."""
    own = frozenset({"123456789012"})

    assert (
        intrinsics.classify_principal("123456789012", own)
        is PrincipalClass.SAME_ACCOUNT
    )
    assert (
        intrinsics.classify_principal("arn:aws:iam::123456789012:root", own)
        is PrincipalClass.SAME_ACCOUNT
    )
    # A different account is still cross-account, and the default set is empty,
    # which is the design.md behaviour.
    assert (
        intrinsics.classify_principal("210987654321", own)
        is PrincipalClass.CROSS_ACCOUNT
    )
    assert (
        intrinsics.classify_principal("123456789012")
        is PrincipalClass.CROSS_ACCOUNT
    )


# ---------------------------------------------------------------------------
# 2. The seven rows of the intrinsic resolution table
# ---------------------------------------------------------------------------

ROW_LITERAL = "literal"
ROW_ACCOUNT_ID = "account_id"
ROW_REF_DEFAULT = "ref_default_only"
ROW_REF_ALLOWED_VALUES = "ref_allowed_values"
ROW_FN_SUB = "fn_sub"
ROW_OPAQUE = "get_att_or_import_value"
ROW_FN_IF = "fn_if"

#: The table's rows, in design.md's order.
TABLE_ROWS: Tuple[str, ...] = (
    ROW_LITERAL,
    ROW_ACCOUNT_ID,
    ROW_REF_DEFAULT,
    ROW_REF_ALLOWED_VALUES,
    ROW_FN_SUB,
    ROW_OPAQUE,
    ROW_FN_IF,
)

#: Parameters the table's ``Ref`` rows need. ``Stage`` has a Default and no
#: AllowedValues; ``AnyBucket`` allows only wildcards; ``MixedBucket`` allows
#: one wildcard and one exact ARN; ``NamedBucket`` allows neither.
PARAMETERS = {
    "Stage": {"Type": "String", "Default": "prod"},
    "Unset": {"Type": "String"},
    "AnyBucket": {"Type": "String", "AllowedValues": ["*", "arn:aws:s3:::*"]},
    "MixedBucket": {
        "Type": "String",
        "AllowedValues": ["arn:aws:s3:::*", "arn:aws:s3:::reports"],
    },
    "NamedBucket": {
        "Type": "String",
        "AllowedValues": ["arn:aws:s3:::reports", "arn:aws:s3:::audit"],
    },
}

CONTEXT = ResolutionContext.from_template({"Parameters": PARAMETERS})

#: (row, value, predicate, expected verdict, case id).
TABLE_CASES: List[Tuple[str, Any, Predicate, Verdict, str]] = [
    # Row 1: a literal is evaluated as written, in both directions.
    (ROW_LITERAL, "*", is_star, Verdict.MATCH, "literal_star_matches"),
    (
        ROW_LITERAL,
        "arn:aws:s3:::reports/*",
        is_star,
        Verdict.NO_MATCH,
        "literal_arn_does_not_match",
    ),
    (
        ROW_LITERAL,
        ["arn:aws:s3:::reports", "*"],
        is_star,
        Verdict.MATCH,
        "literal_list_any_element_matches",
    ),
    # Row 2: the pseudo parameter is determined, so a non-match is final.
    (
        ROW_ACCOUNT_ID,
        {"Ref": "AWS::AccountId"},
        has_wildcard,
        Verdict.NO_MATCH,
        "ref_account_id_is_resolved",
    ),
    (
        ROW_ACCOUNT_ID,
        {"Fn::Sub": "arn:aws:iam::${AWS::AccountId}:role/App"},
        has_wildcard,
        Verdict.NO_MATCH,
        "sub_account_id_is_resolved",
    ),
    # Row 3: a Default is not resolved, so the location is unresolvable.
    (
        ROW_REF_DEFAULT,
        {"Ref": "Stage"},
        has_wildcard,
        Verdict.UNRESOLVABLE,
        "ref_with_default_only",
    ),
    (
        ROW_REF_DEFAULT,
        {"Ref": "Unset"},
        has_wildcard,
        Verdict.UNRESOLVABLE,
        "ref_without_default",
    ),
    (
        ROW_REF_DEFAULT,
        {"Ref": "UndeclaredResource"},
        has_wildcard,
        Verdict.UNRESOLVABLE,
        "ref_to_resource",
    ),
    # Row 4: every AllowedValue is evaluated. All dangerous is certain, some is
    # a deploy-time choice, none is clean.
    (
        ROW_REF_ALLOWED_VALUES,
        {"Ref": "AnyBucket"},
        has_wildcard,
        Verdict.MATCH,
        "allowed_values_all_match",
    ),
    (
        ROW_REF_ALLOWED_VALUES,
        {"Ref": "MixedBucket"},
        has_wildcard,
        Verdict.UNRESOLVABLE,
        "allowed_values_some_match",
    ),
    (
        ROW_REF_ALLOWED_VALUES,
        {"Ref": "NamedBucket"},
        has_wildcard,
        Verdict.NO_MATCH,
        "allowed_values_none_match",
    ),
    # Row 5: Fn::Sub is judged on its fixed parts. design.md's own example.
    (
        ROW_FN_SUB,
        {"Fn::Sub": "arn:aws:iam::${AWS::AccountId}:role/*"},
        has_wildcard,
        Verdict.MATCH,
        "sub_fixed_part_matches",
    ),
    (
        ROW_FN_SUB,
        {"Fn::Sub": "arn:aws:s3:::${BucketName}/reports"},
        has_wildcard,
        Verdict.UNRESOLVABLE,
        "sub_variable_leaves_gap",
    ),
    (
        ROW_FN_SUB,
        {"Fn::Sub": "arn:aws:s3:::${!BucketName}"},
        has_wildcard,
        Verdict.NO_MATCH,
        "sub_escape_is_not_a_substitution",
    ),
    # Row 6: nothing to evaluate at all.
    (
        ROW_OPAQUE,
        {"Fn::GetAtt": ["ReportsBucket", "Arn"]},
        has_wildcard,
        Verdict.UNRESOLVABLE,
        "get_att",
    ),
    (
        ROW_OPAQUE,
        {"Fn::ImportValue": "shared-bucket-arn"},
        has_wildcard,
        Verdict.UNRESOLVABLE,
        "import_value",
    ),
    (
        ROW_OPAQUE,
        {"Fn::Join": ["", ["arn:aws:s3:::", {"Ref": "Stage"}]]},
        has_wildcard,
        Verdict.UNRESOLVABLE,
        "unhandled_function_is_not_ignored",
    ),
    # Row 7: both branches are evaluated independently.
    (
        ROW_FN_IF,
        {"Fn::If": ["IsProd", "arn:aws:s3:::reports", "*"]},
        is_star,
        Verdict.MATCH,
        "fn_if_false_branch_matches",
    ),
    (
        ROW_FN_IF,
        {"Fn::If": ["IsProd", "*", "arn:aws:s3:::reports"]},
        is_star,
        Verdict.MATCH,
        "fn_if_true_branch_matches",
    ),
    (
        ROW_FN_IF,
        {"Fn::If": ["IsProd", "arn:aws:s3:::reports", "arn:aws:s3:::audit"]},
        is_star,
        Verdict.NO_MATCH,
        "fn_if_neither_branch_matches",
    ),
    (
        ROW_FN_IF,
        {
            "Fn::If": [
                "IsProd",
                "arn:aws:s3:::reports",
                {"Fn::ImportValue": "shared-bucket-arn"},
            ]
        },
        is_star,
        Verdict.UNRESOLVABLE,
        "fn_if_one_branch_unresolvable",
    ),
]


@pytest.mark.parametrize(
    "value,predicate,expected",
    [(value, predicate, expected) for _, value, predicate, expected, _ in TABLE_CASES],
    ids=[case_id for _, _, _, _, case_id in TABLE_CASES],
)
def test_intrinsic_resolution_table(
    value: Any, predicate: Predicate, expected: Verdict
) -> None:
    assert intrinsics.evaluate(value, predicate, CONTEXT).verdict is expected


def test_every_table_row_is_covered() -> None:
    """Task 13.2 completion condition: all seven rows have a branch and a case."""
    covered = {row for row, _, _, _, _ in TABLE_CASES}
    assert covered == set(TABLE_ROWS)
    assert len(TABLE_ROWS) == 7


def test_ref_with_default_reports_the_default_was_not_used() -> None:
    """Row 3's reason must say why, or the reader will assume it was resolved."""
    evaluation = intrinsics.evaluate({"Ref": "Stage"}, has_wildcard, CONTEXT)

    assert evaluation.verdict is Verdict.UNRESOLVABLE
    assert len(evaluation.blockers) == 1
    detail = evaluation.blockers[0].detail
    assert "Stage" in detail
    assert "Default" in detail


def test_allowed_values_are_all_evaluated() -> None:
    """Row 4: the whole set is examined, not just the first entry."""
    resolution = intrinsics.resolve({"Ref": "MixedBucket"}, CONTEXT)

    assert [candidate.text for candidate in resolution.candidates] == [
        "arn:aws:s3:::*",
        "arn:aws:s3:::reports",
    ]
    assert resolution.groups[0].all_required is True


def test_fn_if_records_which_branch_matched() -> None:
    """Row 7 requires the branch in Evidence, not just the fact of a match."""
    evaluation = intrinsics.evaluate(
        {"Fn::If": ["IsProd", "arn:aws:s3:::reports", "*"]}, is_star, CONTEXT
    )

    assert evaluation.verdict is Verdict.MATCH
    assert [candidate.branch for candidate in evaluation.matched] == [
        "Fn::If[IsProd] false branch"
    ]


def test_nested_fn_if_labels_every_branch_taken() -> None:
    value = {
        "Fn::If": [
            "IsProd",
            {"Fn::If": ["HasAudit", "*", "arn:aws:s3:::reports"]},
            "arn:aws:s3:::audit",
        ]
    }

    evaluation = intrinsics.evaluate(value, is_star, CONTEXT)

    assert evaluation.verdict is Verdict.MATCH
    assert [candidate.branch for candidate in evaluation.matched] == [
        "Fn::If[IsProd] true branch / Fn::If[HasAudit] true branch"
    ]


def test_resolved_values_are_marked_fully_resolved() -> None:
    """A literal and a pseudo parameter leave nothing unexamined."""
    assert intrinsics.resolve("*").is_fully_resolved is True
    assert intrinsics.resolve({"Ref": "AWS::AccountId"}).is_fully_resolved is True
    assert (
        intrinsics.resolve({"Fn::Sub": "arn:aws:iam::${AWS::AccountId}:role/App"})
        .is_fully_resolved
        is True
    )
    assert (
        intrinsics.resolve({"Fn::Sub": "arn:aws:s3:::${BucketName}"}).is_fully_resolved
        is False
    )


def test_ref_no_value_contributes_nothing() -> None:
    """``AWS::NoValue`` removes the value, so it is neither a match nor a gap."""
    evaluation = intrinsics.evaluate({"Ref": "AWS::NoValue"}, has_wildcard, CONTEXT)

    assert evaluation.verdict is Verdict.NO_MATCH
    assert evaluation.resolution.candidates == ()
    assert evaluation.blockers == ()


def test_no_context_makes_parameter_refs_unresolvable() -> None:
    """Without a Parameters section the conservative answer is unresolvable."""
    evaluation = intrinsics.evaluate({"Ref": "AnyBucket"}, has_wildcard)

    assert evaluation.verdict is Verdict.UNRESOLVABLE


# ---------------------------------------------------------------------------
# 3. Unresolvable is never silent
# ---------------------------------------------------------------------------

TEMPLATE_PATH: Tuple[Any, ...] = (
    "Resources",
    "AppExecutionRole",
    "Properties",
    "Policies",
    0,
    "PolicyDocument",
    "Statement",
    1,
    "Resource",
)


def _records(value: Any, predicate: Predicate = has_wildcard) -> List[UnresolvedValue]:
    evaluation = intrinsics.evaluate(value, predicate, CONTEXT)
    return intrinsics.unresolved_values(
        evaluation, "AppExecutionRole", TEMPLATE_PATH, ValueKind.RESOURCE
    )


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(value, id=case_id)
        for _, value, _, expected, case_id in TABLE_CASES
        if expected is Verdict.UNRESOLVABLE
    ],
)
def test_every_unresolvable_case_is_recorded(value: Any) -> None:
    """No unresolvable verdict may pass without a located record."""
    records = _records(value)

    assert records, "an unresolvable value produced no record"
    for record in records:
        assert record.logical_id == "AppExecutionRole"
        assert record.template_path == TEMPLATE_PATH
        assert record.value_kind == ValueKind.RESOURCE.value
        assert record.intrinsic
        assert record.detail


def test_record_carries_the_finding_text_design_prescribes() -> None:
    record = _records({"Fn::ImportValue": "shared-bucket-arn"})[0]

    assert record.rule_id == "unresolvable_value"
    assert record.finding_text == (
        "[unresolvable_value] The Resource value at this location is produced "
        "by Fn::ImportValue and cannot be evaluated statically, so IAM checks "
        "were not applied to it."
    )
    assert record.json_path == (
        "Resources.AppExecutionRole.Properties.Policies.0.PolicyDocument."
        "Statement.1.Resource"
    )
    assert "skipped by the deterministic IAM checks" in record.why_it_matters
    assert "cross-stack import" in record.recommendation


def test_record_names_the_branch_when_the_gap_is_inside_fn_if() -> None:
    record = _records(
        {
            "Fn::If": [
                "IsProd",
                "arn:aws:s3:::reports",
                {"Fn::ImportValue": "shared-bucket-arn"},
            ]
        }
    )[0]

    assert record.branch == "Fn::If[IsProd] false branch"
    assert "Fn::If[IsProd] false branch" in record.finding_text


@pytest.mark.parametrize(
    "value,predicate",
    [
        pytest.param("*", is_star, id="match"),
        pytest.param("arn:aws:s3:::reports", is_star, id="no_match"),
    ],
)
def test_decided_values_produce_no_record(value: Any, predicate: Predicate) -> None:
    """A location that was checked is not a coverage gap, either way."""
    assert _records(value, predicate) == []


def test_repeated_reports_of_one_gap_collapse() -> None:
    """Fifteen detectors examining one statement disclose it once."""
    records = _records({"Fn::ImportValue": "shared-bucket-arn"}) * 15

    assert len(intrinsics.dedupe_unresolved(records)) == 1


def test_distinct_gaps_are_kept_apart() -> None:
    same_path = _records({"Fn::GetAtt": ["ReportsBucket", "Arn"]})
    other_kind = [
        UnresolvedValue(
            logical_id=record.logical_id,
            template_path=record.template_path,
            value_kind=ValueKind.ACTION.value,
            intrinsic=record.intrinsic,
            detail=record.detail,
        )
        for record in same_path
    ]

    assert len(intrinsics.dedupe_unresolved(same_path + other_kind)) == 2


# ---------------------------------------------------------------------------
# 4. Untrusted input
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(None, id="none"),
        pytest.param(7, id="int"),
        pytest.param(True, id="bool"),
        pytest.param({}, id="empty_mapping"),
        pytest.param([], id="empty_list"),
        pytest.param({"Ref": {"Fn::GetAtt": ["A", "B"]}}, id="ref_to_mapping"),
        pytest.param({"Fn::Sub": {"unexpected": "shape"}}, id="sub_mapping"),
        pytest.param({"Fn::Sub": []}, id="sub_empty_list"),
        pytest.param({"Fn::If": ["OnlyOneArgument"]}, id="malformed_fn_if"),
        pytest.param({"Fn::If": "not-a-list"}, id="fn_if_not_a_list"),
        pytest.param({"Fn::If": [{"Ref": "C"}, "a", "b"]}, id="fn_if_unnamed_condition"),
        pytest.param({"Effect": "Allow"}, id="mapping_that_is_not_intrinsic"),
        pytest.param({"Ref": "AnyBucket", "Fn::Sub": "*"}, id="two_intrinsic_keys"),
    ],
)
def test_hostile_shapes_resolve_without_raising(value: Any) -> None:
    evaluation = intrinsics.evaluate(value, has_wildcard, CONTEXT)

    assert evaluation.verdict in set(Verdict)
    # Whatever the shape, either the value was decided or a reason exists.
    assert evaluation.verdict is not Verdict.UNRESOLVABLE or evaluation.blockers


def test_malformed_fn_if_is_reported_not_guessed() -> None:
    """An Fn::If that cannot be split is a gap, not a branch chosen at random."""
    evaluation = intrinsics.evaluate(
        {"Fn::If": ["IsProd", "*"]}, is_star, CONTEXT
    )

    assert evaluation.verdict is Verdict.UNRESOLVABLE
    assert [blocker.intrinsic for blocker in evaluation.blockers] == ["Fn::If"]


def test_deep_nesting_fails_safely() -> None:
    """Nesting built to exhaust the stack becomes a reason, not a crash."""
    value: Any = "*"
    for _ in range(intrinsics.MAX_NESTING_DEPTH * 4):
        value = [value]

    evaluation = intrinsics.evaluate(value, is_star, CONTEXT)

    assert evaluation.verdict is Verdict.UNRESOLVABLE
    assert evaluation.blockers


def test_deeply_nested_conditionals_fail_safely() -> None:
    value: Any = "*"
    for index in range(intrinsics.MAX_NESTING_DEPTH * 4):
        value = {"Fn::If": ["C{0}".format(index), value, "arn:aws:s3:::reports"]}

    evaluation = intrinsics.evaluate(value, is_star, CONTEXT)

    assert evaluation.verdict in (Verdict.MATCH, Verdict.UNRESOLVABLE)


def test_allowed_values_with_a_non_string_entry_is_disclosed() -> None:
    context = ResolutionContext.from_template(
        {"Parameters": {"Odd": {"AllowedValues": ["arn:aws:s3:::reports", 7]}}}
    )

    evaluation = intrinsics.evaluate({"Ref": "Odd"}, has_wildcard, context)

    assert evaluation.verdict is Verdict.UNRESOLVABLE
    assert evaluation.blockers


def test_resolution_context_accepts_any_template_shape() -> None:
    for doc in (None, [], "template", {}, {"Parameters": "nope"}, {"Parameters": {7: 8}}):
        assert ResolutionContext.from_template(doc).parameters == {}


def test_expand_conditionals_returns_one_branch_for_a_plain_value() -> None:
    branches = intrinsics.expand_conditionals("arn:aws:s3:::reports")

    assert len(branches) == 1
    assert branches[0].value == "arn:aws:s3:::reports"
    assert branches[0].label is None


def test_expand_conditionals_returns_true_branch_first() -> None:
    branches = intrinsics.expand_conditionals({"Fn::If": ["IsProd", "yes", "no"]})

    assert [branch.value for branch in branches] == ["yes", "no"]
    assert [branch.label for branch in branches] == [
        "Fn::If[IsProd] true branch",
        "Fn::If[IsProd] false branch",
    ]
