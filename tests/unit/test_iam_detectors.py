"""Tests for :mod:`iacreview.iam.detectors` (Task 13.3; Requirement 6 AC1-AC13).

Six groups, in the order the module's contract matters.

1. :data:`DESIGN_TABLE` -- design.md's *Layer 1: 決定論的検出器* table,
   transcribed by hand. :func:`test_spec_matches_design_table` compares the
   module's own table against it, so a detector whose Severity drifts from the
   design fails here rather than in a benchmark much later.
2. :data:`CASES` -- Task 13.3's completion condition: at least one positive and
   one negative case per detector.
   :func:`test_every_detector_has_a_positive_and_a_negative_case` fails if a
   detector loses either, so the parametrization cannot quietly stop being
   exhaustive.
3. The ExternalId reduction (Requirement 6 AC10): ``HIGH -> MEDIUM``, the
   ``INFO`` floor, and its non-application to ``principal_star``.
4. The ``no_iam_resources`` empty path (Requirement 6 AC12).
5. :func:`iacreview.iam.detectors.scan` over a whole Template, which is where
   detector order, Finding schema conformance and the reduction meet.
6. Untrusted structure: a statement, Condition or Action of the wrong type must
   yield fewer Findings, never an exception.

Documents are written inline rather than loaded from files, because a case is
only readable when the policy and the expectation sit next to each other. The
one fixture used is ``tests/fixtures/security/iam_dangerous_policies.yaml``,
whose defects are listed in the file itself so the expectation is written from
the Template rather than read back from the review output.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest

# tests/unit/test_iam_detectors.py -> tests/unit -> tests -> plugin root
PLUGIN_ROOT: Path = Path(__file__).resolve().parents[2]
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

from iacreview import finding as finding_module
from iacreview import template
from iacreview.errors import SchemaViolationError
from iacreview.finding import CONFIRMED, Evidence, Finding, Location
from iacreview.iam import detectors, locate
from iacreview.iam.detectors import (
    Detector,
    PolicyTarget,
    apply_external_id_mitigation,
    lower_one_level,
)
from iacreview.iam.intrinsics import ResolutionContext
from iacreview.iam.locate import PolicyKind, PolicySite

DANGEROUS_FIXTURE: Path = (
    PLUGIN_ROOT / "tests" / "fixtures" / "security" / "iam_dangerous_policies.yaml"
)
NO_IAM_FIXTURE: Path = (
    PLUGIN_ROOT / "tests" / "fixtures" / "valid" / "minimal_template.json"
)

TEMPLATE_FILE = "tests/fixtures/security/iam_dangerous_policies.yaml"
LOGICAL_ID = "AppResource"

#: Path of the inline-policy site the case documents are mounted at. Chosen so
#: the asserted ``TemplatePath`` exercises the list-index segment as well.
INLINE_JSON_PATH = "Resources.{0}.Properties.Policies.0.PolicyDocument".format(LOGICAL_ID)


# ---------------------------------------------------------------------------
# Document builders
# ---------------------------------------------------------------------------


def statement(**fields: Any) -> Dict[str, Any]:
    """One policy statement, defaulting to ``Effect: Allow``."""
    body: Dict[str, Any] = {"Effect": "Allow"}
    body.update(fields)
    return body


def policy(*statements: Any) -> Dict[str, Any]:
    """A policy document around ``statements``."""
    return {"Version": "2012-10-17", "Statement": list(statements)}


def make_target(
    document: Any,
    *,
    kind: PolicyKind = PolicyKind.INLINE_ROLE_POLICY,
    json_path: str = INLINE_JSON_PATH,
    parameters: Optional[Dict[str, Any]] = None,
) -> PolicyTarget:
    """Build the target a detector is called with."""
    site = PolicySite(
        logical_id=LOGICAL_ID, kind=kind, json_path=json_path, document=document
    )
    context = ResolutionContext(parameters=dict(parameters or {}))
    return PolicyTarget.from_site(
        site, template_file=TEMPLATE_FILE, context=context
    )


# ---------------------------------------------------------------------------
# 1. The design table
# ---------------------------------------------------------------------------

#: Detector name -> (FindingType, Severity, Normalized_Category), transcribed
#: from design.md's *Layer 1: 決定論的検出器* table. ``privesc_broad_trust``
#: carries two Severities in the design; the table records its lower one and
#: :data:`CASES` asserts the CRITICAL variant separately.
DESIGN_TABLE: Dict[str, Tuple[str, str, str]] = {
    "star_action_star_resource": ("Security", "CRITICAL", "IAM"),
    "wildcard_action": ("Security", "HIGH", "IAM"),
    "wildcard_resource": ("Security", "HIGH", "IAM"),
    "sensitive_prefix_without_condition": ("Security", "HIGH", "IAM"),
    "passrole_unrestricted": ("Security", "CRITICAL", "IAM"),
    "assumerole_unrestricted": ("Security", "HIGH", "IAM"),
    "privesc_policy_mutation": ("Security", "CRITICAL", "IAM"),
    "privesc_lambda_passrole": ("Security", "CRITICAL", "IAM"),
    "privesc_broad_trust": ("Security", "HIGH", "IAM"),
    "cross_service_missing_condition": ("Security", "HIGH", "IAM"),
    "cross_account_principal": ("Security", "HIGH", "IAM"),
    "principal_star": ("Security", "CRITICAL", "IAM"),
    "dangerous_s3_combo": ("Security", "HIGH", "IAM"),
    "dangerous_ec2_passrole": ("Security", "HIGH", "IAM"),
    "dangerous_lambda_combo": ("Security", "HIGH", "IAM"),
}


def test_fifteen_detectors_in_design_table_order() -> None:
    """The registry is the design table: same names, same order, no extras."""
    assert len(detectors.DETECTORS) == 15
    assert detectors.DETECTOR_NAMES == tuple(DESIGN_TABLE)
    assert tuple(d.__name__ for d in detectors.DETECTORS) == tuple(DESIGN_TABLE)


@pytest.mark.parametrize("name", list(DESIGN_TABLE), ids=list(DESIGN_TABLE))
def test_spec_matches_design_table(name: str) -> None:
    """FindingType / Severity / Category are the table's values, fixed."""
    finding_type, severity, category = DESIGN_TABLE[name]
    spec = detectors.SPECS[name]

    assert (spec.finding_type, spec.severity, spec.category) == (
        finding_type,
        severity,
        category,
    )
    assert spec.why_it_matters
    assert spec.recommendation


# ---------------------------------------------------------------------------
# 2. Per-detector positive and negative cases
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Case:
    """One detector applied to one document, with the expected outcome.

    Attributes:
        detector: The function under test.
        document: The policy document (or ``AWS::Lambda::Permission``
            properties) mounted at the site.
        positive: Whether the detector must report at least one Finding.
        case_id: pytest id, prefixed with the detector name.
        kind: Site kind, which matters to the detectors scoped to one.
        severity: Expected Severity when it differs from the spec's -- only
            ``privesc_broad_trust``'s CRITICAL variant.
        json_path: Site path, so the Lambda Permission cases sit at
            ``Properties``.
        parameters: Template ``Parameters`` the document Refs.
    """

    detector: Detector
    document: Any
    positive: bool
    case_id: str
    kind: PolicyKind = PolicyKind.INLINE_ROLE_POLICY
    severity: Optional[str] = None
    json_path: str = INLINE_JSON_PATH
    parameters: Dict[str, Any] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.detector.__name__

    @property
    def expected_severity(self) -> str:
        return self.severity or detectors.SPECS[self.name].severity


TRUST_PATH = "Resources.{0}.Properties.AssumeRolePolicyDocument".format(LOGICAL_ID)
RESOURCE_POLICY_PATH = "Resources.{0}.Properties.PolicyDocument".format(LOGICAL_ID)
LAMBDA_PERMISSION_PATH = "Resources.{0}.Properties".format(LOGICAL_ID)

APP_BUCKET_ARN = "arn:aws:s3:::app-bucket/report.csv"
APP_ROLE_ARN = "arn:aws:iam::123456789012:role/AppRole"
APP_QUEUE_ARN = "arn:aws:sqs:us-east-1:123456789012:app-queue"
SOURCE_ACCOUNT_CONDITION = {"StringEquals": {"aws:SourceAccount": "123456789012"}}


def trust_case(detector: Detector, document: Any, positive: bool, case_id: str) -> Case:
    return Case(
        detector=detector,
        document=document,
        positive=positive,
        case_id=case_id,
        kind=PolicyKind.TRUST_POLICY,
        json_path=TRUST_PATH,
    )


def resource_policy_case(
    detector: Detector, document: Any, positive: bool, case_id: str
) -> Case:
    return Case(
        detector=detector,
        document=document,
        positive=positive,
        case_id=case_id,
        kind=PolicyKind.RESOURCE_POLICY,
        json_path=RESOURCE_POLICY_PATH,
    )


def lambda_permission_case(
    detector: Detector, properties: Any, positive: bool, case_id: str
) -> Case:
    return Case(
        detector=detector,
        document=properties,
        positive=positive,
        case_id=case_id,
        kind=PolicyKind.LAMBDA_PERMISSION,
        json_path=LAMBDA_PERMISSION_PATH,
    )


#: At least one positive and one negative case per detector (Task 13.3).
CASES: List[Case] = [
    # --- star_action_star_resource (AC1) -----------------------------------
    Case(
        detectors.star_action_star_resource,
        policy(statement(Action="*", Resource="*")),
        True,
        "allow_star_on_star",
    ),
    Case(
        detectors.star_action_star_resource,
        policy(statement(Action="*", Resource=APP_BUCKET_ARN)),
        False,
        "star_action_but_named_resource",
    ),
    Case(
        # Effect: Deny removes access; reporting it as a permission would be a
        # false positive, and every detector is gated on Allow for that reason.
        detectors.star_action_star_resource,
        policy({"Effect": "Deny", "Action": "*", "Resource": "*"}),
        False,
        "deny_star_on_star",
    ),
    # --- wildcard_action (AC4) ---------------------------------------------
    Case(
        detectors.wildcard_action,
        policy(statement(Action="s3:*", Resource=APP_BUCKET_ARN)),
        True,
        "service_wide_wildcard",
    ),
    Case(
        detectors.wildcard_action,
        policy(statement(Action=["s3:GetObject", "s3:PutObject"], Resource=APP_BUCKET_ARN)),
        False,
        "named_actions_only",
    ),
    # --- wildcard_resource (AC4) -------------------------------------------
    Case(
        detectors.wildcard_resource,
        policy(statement(Action="s3:GetObject", Resource="arn:aws:s3:::app-bucket/*")),
        True,
        "wildcard_object_arn",
    ),
    Case(
        detectors.wildcard_resource,
        policy(statement(Action="s3:GetObject", Resource=APP_BUCKET_ARN)),
        False,
        "literal_object_arn",
    ),
    # --- sensitive_prefix_without_condition (AC2) --------------------------
    Case(
        detectors.sensitive_prefix_without_condition,
        policy(statement(Action="iam:ListRoles", Resource=APP_ROLE_ARN)),
        True,
        "iam_action_unconditioned",
    ),
    Case(
        detectors.sensitive_prefix_without_condition,
        policy(
            statement(
                Action="iam:ListRoles",
                Resource=APP_ROLE_ARN,
                Condition=SOURCE_ACCOUNT_CONDITION,
            )
        ),
        False,
        "iam_action_conditioned",
    ),
    Case(
        detectors.sensitive_prefix_without_condition,
        policy(statement(Action="sqs:SendMessage", Resource=APP_QUEUE_ARN)),
        False,
        "non_sensitive_prefix",
    ),
    # --- passrole_unrestricted (AC3) ---------------------------------------
    Case(
        detectors.passrole_unrestricted,
        policy(statement(Action="iam:PassRole", Resource="*")),
        True,
        "passrole_on_star",
    ),
    Case(
        detectors.passrole_unrestricted,
        policy(statement(Action="iam:PassRole", Resource="arn:aws:iam::*:role/*")),
        True,
        "passrole_on_wildcard_role_arn",
    ),
    Case(
        detectors.passrole_unrestricted,
        policy(statement(Action="iam:PassRole", Resource=APP_ROLE_ARN)),
        False,
        "passrole_on_named_role",
    ),
    # --- assumerole_unrestricted (AC3) -------------------------------------
    Case(
        detectors.assumerole_unrestricted,
        policy(statement(Action="sts:AssumeRole", Resource="*")),
        True,
        "assumerole_on_star",
    ),
    Case(
        detectors.assumerole_unrestricted,
        policy(statement(Action="sts:AssumeRole", Resource=APP_ROLE_ARN)),
        False,
        "assumerole_on_named_role",
    ),
    # --- privesc_policy_mutation (AC5) -------------------------------------
    Case(
        detectors.privesc_policy_mutation,
        policy(statement(Action="iam:PutRolePolicy", Resource=APP_ROLE_ARN)),
        True,
        "put_role_policy",
    ),
    Case(
        # IAM wildcard semantics: iam:* grants iam:AttachRolePolicy, so a policy
        # cannot escape the detector by writing a pattern instead of a name.
        detectors.privesc_policy_mutation,
        policy(statement(Action="iam:*", Resource=APP_ROLE_ARN)),
        True,
        "iam_wildcard_covers_mutation",
    ),
    Case(
        detectors.privesc_policy_mutation,
        policy(statement(Action=["iam:GetRole", "iam:ListRoles"], Resource=APP_ROLE_ARN)),
        False,
        "read_only_iam_actions",
    ),
    # --- privesc_lambda_passrole (AC5) -------------------------------------
    Case(
        detectors.privesc_lambda_passrole,
        policy(
            statement(Action="lambda:CreateFunction", Resource="*"),
            statement(Action="iam:PassRole", Resource=APP_ROLE_ARN),
        ),
        True,
        "create_function_and_passrole_split",
    ),
    Case(
        detectors.privesc_lambda_passrole,
        policy(statement(Action="lambda:CreateFunction", Resource="*")),
        False,
        "create_function_without_passrole",
    ),
    # --- privesc_broad_trust (AC5) -----------------------------------------
    Case(
        detectors.privesc_broad_trust,
        policy(statement(Principal="*", Action="sts:AssumeRole")),
        True,
        "trust_any_principal",
        kind=PolicyKind.TRUST_POLICY,
        severity="CRITICAL",
        json_path=TRUST_PATH,
    ),
    trust_case(
        detectors.privesc_broad_trust,
        policy(
            statement(
                Principal={"Service": "lambda.amazonaws.com"}, Action="sts:AssumeRole"
            )
        ),
        True,
        "trust_service_unconditioned",
    ),
    trust_case(
        detectors.privesc_broad_trust,
        policy(
            statement(
                Principal={"Service": "lambda.amazonaws.com"},
                Action="sts:AssumeRole",
                Condition=SOURCE_ACCOUNT_CONDITION,
            )
        ),
        False,
        "trust_service_conditioned",
    ),
    Case(
        # Scoped to trust policies: the same statement in an inline policy is a
        # different thing and is covered by the Principal detectors instead.
        detectors.privesc_broad_trust,
        policy(statement(Principal="*", Action="sts:AssumeRole")),
        False,
        "not_a_trust_policy",
    ),
    # --- cross_service_missing_condition (AC6) -----------------------------
    resource_policy_case(
        detectors.cross_service_missing_condition,
        policy(
            statement(
                Principal={"Service": "cloudtrail.amazonaws.com"},
                Action="s3:PutObject",
                Resource=APP_BUCKET_ARN,
            )
        ),
        True,
        "service_principal_unscoped",
    ),
    resource_policy_case(
        detectors.cross_service_missing_condition,
        policy(
            statement(
                Principal={"Service": "cloudtrail.amazonaws.com"},
                Action="s3:PutObject",
                Resource=APP_BUCKET_ARN,
                Condition=SOURCE_ACCOUNT_CONDITION,
            )
        ),
        False,
        "service_principal_scoped_by_source_account",
    ),
    lambda_permission_case(
        detectors.cross_service_missing_condition,
        {
            "FunctionName": "app-function",
            "Action": "lambda:InvokeFunction",
            "Principal": "events.amazonaws.com",
        },
        True,
        "lambda_permission_without_source_account",
    ),
    lambda_permission_case(
        detectors.cross_service_missing_condition,
        {
            "FunctionName": "app-function",
            "Action": "lambda:InvokeFunction",
            "Principal": "events.amazonaws.com",
            "SourceAccount": "123456789012",
        },
        False,
        "lambda_permission_with_source_account",
    ),
    # --- cross_account_principal (AC7, AC8) --------------------------------
    resource_policy_case(
        detectors.cross_account_principal,
        policy(
            statement(
                Principal={"AWS": "210987654321"},
                Action="s3:GetObject",
                Resource=APP_BUCKET_ARN,
            )
        ),
        True,
        "literal_account_id",
    ),
    resource_policy_case(
        detectors.cross_account_principal,
        policy(
            statement(
                Principal={"AWS": "arn:aws:iam::210987654321:role/Partner"},
                Action="s3:GetObject",
                Resource=APP_BUCKET_ARN,
            )
        ),
        True,
        "account_id_inside_arn",
    ),
    resource_policy_case(
        # Requirement 6 AC8: the pseudo parameter is same-account, never cross.
        detectors.cross_account_principal,
        policy(
            statement(
                Principal={"AWS": {"Ref": "AWS::AccountId"}},
                Action="s3:GetObject",
                Resource=APP_BUCKET_ARN,
            )
        ),
        False,
        "account_id_pseudo_parameter",
    ),
    # --- principal_star (AC9) ----------------------------------------------
    resource_policy_case(
        detectors.principal_star,
        policy(statement(Principal="*", Action="s3:GetObject", Resource=APP_BUCKET_ARN)),
        True,
        "literal_star_principal",
    ),
    resource_policy_case(
        detectors.principal_star,
        policy(
            statement(
                Principal={"AWS": "*"}, Action="s3:GetObject", Resource=APP_BUCKET_ARN
            )
        ),
        True,
        "aws_star_principal",
    ),
    resource_policy_case(
        # The standard "deny unencrypted transport" bucket policy. Flagging it
        # CRITICAL would punish the correct pattern.
        detectors.principal_star,
        policy(
            {
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": APP_BUCKET_ARN,
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            }
        ),
        False,
        "deny_star_principal",
    ),
    # --- dangerous_s3_combo (AC11) -----------------------------------------
    Case(
        detectors.dangerous_s3_combo,
        policy(
            statement(
                Action=["s3:GetObject", "s3:PutObject", "s3:DeleteObject"], Resource="*"
            )
        ),
        True,
        "read_write_delete_on_star",
    ),
    Case(
        detectors.dangerous_s3_combo,
        policy(statement(Action=["s3:GetObject", "s3:PutObject"], Resource="*")),
        False,
        "read_write_without_delete",
    ),
    Case(
        detectors.dangerous_s3_combo,
        policy(
            statement(
                Action=["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                Resource=APP_BUCKET_ARN,
            )
        ),
        False,
        "read_write_delete_on_named_object",
    ),
    # --- dangerous_ec2_passrole (AC11) -------------------------------------
    Case(
        detectors.dangerous_ec2_passrole,
        policy(
            statement(Action="ec2:RunInstances", Resource="*"),
            statement(Action="iam:PassRole", Resource=APP_ROLE_ARN),
        ),
        True,
        "run_instances_and_passrole",
    ),
    Case(
        detectors.dangerous_ec2_passrole,
        policy(statement(Action="ec2:RunInstances", Resource="*")),
        False,
        "run_instances_without_passrole",
    ),
    # --- dangerous_lambda_combo (AC11) -------------------------------------
    Case(
        detectors.dangerous_lambda_combo,
        policy(
            statement(
                Action=["lambda:UpdateFunctionCode", "lambda:InvokeFunction"],
                Resource="arn:aws:lambda:us-east-1:123456789012:function:app",
            )
        ),
        True,
        "update_code_and_invoke",
    ),
    Case(
        detectors.dangerous_lambda_combo,
        policy(
            statement(
                Action="lambda:InvokeFunction",
                Resource="arn:aws:lambda:us-east-1:123456789012:function:app",
            )
        ),
        False,
        "invoke_without_update_code",
    ),
]

POSITIVE_CASES = [case for case in CASES if case.positive]
NEGATIVE_CASES = [case for case in CASES if not case.positive]


def _case_id(case: Case) -> str:
    return "{0}-{1}-{2}".format(
        case.name, "positive" if case.positive else "negative", case.case_id
    )


def test_every_detector_has_a_positive_and_a_negative_case() -> None:
    """Task 13.3's completion condition, expressed as a test of the cases."""
    positives = {case.name for case in POSITIVE_CASES}
    negatives = {case.name for case in NEGATIVE_CASES}

    assert positives == set(DESIGN_TABLE), "detectors without a positive case"
    assert negatives == set(DESIGN_TABLE), "detectors without a negative case"
    assert len(CASES) >= 30


@pytest.mark.parametrize("case", CASES, ids=[_case_id(case) for case in CASES])
def test_detector_case(case: Case) -> None:
    """Each detector fires on its positive case and stays silent otherwise."""
    target = make_target(
        case.document,
        kind=case.kind,
        json_path=case.json_path,
        parameters=case.parameters,
    )

    findings = case.detector(target).findings

    if not case.positive:
        assert findings == (), "expected no Finding, got {0}".format(
            [f.Finding for f in findings]
        )
        return
    assert findings, "expected at least one Finding"


@pytest.mark.parametrize(
    "case", POSITIVE_CASES, ids=[_case_id(case) for case in POSITIVE_CASES]
)
def test_positive_finding_carries_the_fixed_fields(case: Case) -> None:
    """Requirement 6 AC13 plus the fields design.md fixes for every Layer 1 row."""
    target = make_target(
        case.document,
        kind=case.kind,
        json_path=case.json_path,
        parameters=case.parameters,
    )
    spec = detectors.SPECS[case.name]

    for produced in case.detector(target).findings:
        assert produced.FindingType == spec.finding_type
        assert produced.Severity == case.expected_severity
        assert produced.Normalized_Category == spec.category
        assert produced.Confidence == CONFIRMED
        assert produced.Source == ["IAM Review"]
        assert produced.Resource == LOGICAL_ID
        assert produced.Finding.startswith("[{0}] ".format(case.name))
        assert produced.Location.File == TEMPLATE_FILE
        assert produced.Location.TemplatePath is not None
        # The statement position, not the document position: a Finding has to
        # point at the statement that carries the risk.
        assert produced.Location.TemplatePath[:2] == ["Resources", LOGICAL_ID]
        assert [entry.RuleId for entry in produced.Evidence] == [case.name]
        assert produced.Evidence[0].Source == "IAM Review"
        assert produced.Evidence[0].Detail
        # Confidence is Confirmed, so the RuleId is the evidence and no Excerpt
        # of Template content is quoted (Requirement 7 AC11).
        assert produced.Evidence[0].Excerpt is None
        assert produced.WhyItMatters == spec.why_it_matters
        assert produced.Recommendation == spec.recommendation
        assert produced.SuggestedRemediation is None
        assert produced.ID == finding_module.UNASSIGNED_ID


@pytest.mark.parametrize(
    "case", POSITIVE_CASES, ids=[_case_id(case) for case in POSITIVE_CASES]
)
def test_positive_finding_satisfies_the_report_schema(case: Case) -> None:
    """Every Finding validates once the report has assigned its ID."""
    target = make_target(
        case.document,
        kind=case.kind,
        json_path=case.json_path,
        parameters=case.parameters,
    )

    for produced in case.detector(target).findings:
        finding_module.validate(replace(produced, ID=1))


def test_statement_template_path_addresses_the_statement() -> None:
    """The reported path is the statement's own, index included."""
    target = make_target(
        policy(
            statement(Action="s3:GetObject", Resource=APP_BUCKET_ARN),
            statement(Action="*", Resource="*"),
        )
    )

    findings = detectors.star_action_star_resource(target).findings

    assert len(findings) == 1
    assert findings[0].Location.TemplatePath == [
        "Resources",
        LOGICAL_ID,
        "Properties",
        "Policies",
        0,
        "PolicyDocument",
        "Statement",
        1,
    ]


def test_detectors_are_independent_of_each_other() -> None:
    """One statement matching several rows yields one Finding per row.

    design.md's intended behaviour: the reasons are kept and merged later by
    dedup, rather than one detector suppressing another.
    """
    target = make_target(policy(statement(Action="*", Resource="*")))

    fired = {
        detector.__name__
        for detector in detectors.DETECTORS
        if detector(target).findings
    }

    assert {
        "star_action_star_resource",
        "wildcard_action",
        "wildcard_resource",
        "passrole_unrestricted",
        "assumerole_unrestricted",
        "privesc_policy_mutation",
        "privesc_lambda_passrole",
        "dangerous_s3_combo",
        "dangerous_ec2_passrole",
        "dangerous_lambda_combo",
    } <= fired


def test_unresolvable_value_is_recorded_not_ignored() -> None:
    """A value no detector could read is returned as a coverage gap."""
    target = make_target(
        policy(statement(Action="s3:GetObject", Resource={"Fn::ImportValue": "SharedArn"}))
    )

    result = detectors.wildcard_resource(target)

    assert result.findings == ()
    assert [record.intrinsic for record in result.unresolved] == ["Fn::ImportValue"]
    assert result.unresolved[0].value_kind == "Resource"
    assert result.unresolved[0].json_path.endswith("Statement.0.Resource")


def test_both_branches_of_a_conditional_statement_are_examined() -> None:
    """``Fn::If`` is reported from either branch (design.md, intrinsic table)."""
    target = make_target(
        policy({"Fn::If": ["IsProd", statement(Action="*", Resource="*"), {"Ref": "AWS::NoValue"}]})
    )

    findings = detectors.star_action_star_resource(target).findings

    assert len(findings) == 1
    assert "true branch" in findings[0].Evidence[0].Detail


# ---------------------------------------------------------------------------
# 3. The ExternalId reduction (Requirement 6 AC10)
# ---------------------------------------------------------------------------

EXTERNAL_ID_STATEMENT: Dict[str, Any] = statement(
    Principal={"AWS": "210987654321"},
    Action="s3:GetObject",
    Resource=APP_BUCKET_ARN,
    Condition={"StringEquals": {"sts:ExternalId": "partner-secret-reference"}},
)


def cross_account_finding(severity: str = "HIGH") -> Finding:
    """A ``cross_account_principal`` Finding at ``severity``."""
    return Finding(
        ID=finding_module.UNASSIGNED_ID,
        Normalized_Category="IAM",
        FindingType="Security",
        Severity=severity,
        Confidence=CONFIRMED,
        Source=["IAM Review"],
        Resource=LOGICAL_ID,
        Location=Location(File=TEMPLATE_FILE, TemplatePath=["Resources", LOGICAL_ID]),
        Finding="[cross_account_principal] Grants access to another account.",
        WhyItMatters="Access extends beyond this account.",
        Evidence=[
            Evidence(
                Source="IAM Review",
                Detail="Principal contains a literal 12-digit account ID.",
                RuleId="cross_account_principal",
                Excerpt=None,
            )
        ],
        Recommendation="Confirm the external account is intended.",
        SuggestedRemediation=None,
    )


def test_external_id_reduces_high_to_medium() -> None:
    """Requirement 6 AC10: exactly one level down, with Evidence recorded."""
    original = cross_account_finding("HIGH")

    reduced = apply_external_id_mitigation(original, EXTERNAL_ID_STATEMENT)

    assert reduced.Severity == "MEDIUM"
    assert original.Severity == "HIGH", "the input Finding must not be mutated"
    assert len(reduced.Evidence) == len(original.Evidence) + 1
    assert "sts:ExternalId" in reduced.Evidence[-1].Detail
    assert reduced.Evidence[-1].RuleId == "cross_account_principal"


def test_external_id_does_not_go_below_info() -> None:
    """``INFO`` is the floor, so the reduction cannot fall off the scale."""
    reduced = apply_external_id_mitigation(
        cross_account_finding("INFO"), EXTERNAL_ID_STATEMENT
    )

    assert reduced.Severity == "INFO"
    assert lower_one_level("INFO") == "INFO"


def test_external_id_does_not_apply_to_principal_star() -> None:
    """An ExternalId on ``Principal: "*"`` keeps CRITICAL (design.md).

    Anyone who learns the ExternalId is admitted, so the grant is not narrowed
    to a party the account owner chose.
    """
    star_statement = statement(
        Principal="*",
        Action="s3:GetObject",
        Resource=APP_BUCKET_ARN,
        Condition={"StringEquals": {"sts:ExternalId": "shared-secret-reference"}},
    )
    target = make_target(
        policy(star_statement),
        kind=PolicyKind.RESOURCE_POLICY,
        json_path=RESOURCE_POLICY_PATH,
    )

    detected = detectors.principal_star(target).findings[0]
    unchanged = apply_external_id_mitigation(detected, star_statement)

    assert detected.Severity == "CRITICAL"
    assert unchanged is detected


def test_external_id_only_counts_in_the_same_statement() -> None:
    """AC10 says "in the same statement"; another statement's condition is not it."""
    other_statement = statement(
        Principal={"AWS": "210987654321"}, Action="s3:GetObject", Resource=APP_BUCKET_ARN
    )

    unchanged = apply_external_id_mitigation(cross_account_finding(), other_statement)

    assert unchanged.Severity == "HIGH"
    assert len(unchanged.Evidence) == 1


@pytest.mark.parametrize(
    "condition",
    [
        {"StringEquals": {"sts:externalid": "lowercase-key"}},
        {"StringLike": {"STS:EXTERNALID": "uppercase-key"}},
        {"ArnEquals": {"sts:ExternalId": "any-operator"}},
    ],
    ids=["lowercase", "uppercase", "other_operator"],
)
def test_external_id_matches_any_operator_case_insensitively(
    condition: Dict[str, Any]
) -> None:
    """The key is compared case-insensitively under any Condition operator."""
    reduced = apply_external_id_mitigation(
        cross_account_finding(), statement(Condition=condition)
    )

    assert reduced.Severity == "MEDIUM"


def test_external_id_is_applied_by_scan_before_dedup() -> None:
    """``scan`` returns the reduced Severity, so the merge stage sees it."""
    site = PolicySite(
        logical_id=LOGICAL_ID,
        kind=PolicyKind.RESOURCE_POLICY,
        json_path=RESOURCE_POLICY_PATH,
        document=policy(EXTERNAL_ID_STATEMENT),
    )

    findings = detectors.scan([site], template_file=TEMPLATE_FILE)
    cross_account = [
        produced
        for produced in findings
        if produced.Evidence[0].RuleId == "cross_account_principal"
    ]

    assert len(cross_account) == 1
    assert cross_account[0].Severity == "MEDIUM"
    assert any("Mitigating condition" in e.Detail for e in cross_account[0].Evidence)


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        ("CRITICAL", "HIGH"),
        ("HIGH", "MEDIUM"),
        ("MEDIUM", "LOW"),
        ("LOW", "INFO"),
        ("INFO", "INFO"),
    ],
)
def test_lower_one_level(severity: str, expected: str) -> None:
    assert lower_one_level(severity) == expected


def test_lower_one_level_rejects_an_unknown_severity() -> None:
    """Guessing would produce a Finding the report schema rejects."""
    with pytest.raises(SchemaViolationError):
        lower_one_level("SEVERE")


# ---------------------------------------------------------------------------
# 4. The empty path (Requirement 6 AC12)
# ---------------------------------------------------------------------------


def test_no_iam_resources_returns_no_findings() -> None:
    """A Template with nothing IAM-related yields zero findings."""
    loaded = template.load_template(NO_IAM_FIXTURE)
    sites = locate.find_policy_documents(loaded.doc)

    result = detectors.scan_sites(
        sites,
        template_file="tests/fixtures/valid/minimal_template.json",
        context=ResolutionContext.from_template(loaded.doc),
    )

    assert sites == []
    assert detectors.no_iam_resources(sites) is True
    assert result.findings == []
    assert result.unresolved == []
    assert detectors.NO_IAM_RESOURCES_MESSAGE


def test_no_iam_resources_is_false_when_a_site_exists() -> None:
    site = PolicySite(
        logical_id=LOGICAL_ID,
        kind=PolicyKind.INLINE_ROLE_POLICY,
        json_path=INLINE_JSON_PATH,
        document=policy(statement(Action="s3:GetObject", Resource=APP_BUCKET_ARN)),
    )

    assert detectors.no_iam_resources([site]) is False


def test_scan_of_no_sites_is_empty() -> None:
    assert detectors.scan([], template_file=TEMPLATE_FILE) == []


@pytest.mark.parametrize(
    ("kind", "document"),
    [
        (PolicyKind.PERMISSIONS_BOUNDARY, "arn:aws:iam::123456789012:policy/Boundary"),
        (PolicyKind.INLINE_ROLE_POLICY, "not a policy document"),
        (PolicyKind.INLINE_ROLE_POLICY, [statement(Action="*", Resource="*")]),
        (PolicyKind.INLINE_ROLE_POLICY, None),
    ],
    ids=["permissions_boundary_arn", "document_is_a_string", "document_is_a_list", "document_is_empty"],
)
def test_site_with_nothing_to_analyse_yields_no_findings(
    kind: PolicyKind, document: Any
) -> None:
    """A site holding no analysable document is skipped, not guessed at.

    Malformed documents are disclosed by the IAM Source through
    ``locate.malformed_document_sites``, so silence here is not silence in the
    report.
    """
    site = PolicySite(
        logical_id=LOGICAL_ID, kind=kind, json_path=INLINE_JSON_PATH, document=document
    )

    result = detectors.scan_sites([site], template_file=TEMPLATE_FILE)

    assert result.findings == []


# ---------------------------------------------------------------------------
# 5. scan over a whole Template
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def dangerous_scan() -> detectors.ScanResult:
    loaded = template.load_template(DANGEROUS_FIXTURE)
    return detectors.scan_sites(
        locate.find_policy_documents(loaded.doc),
        template_file=TEMPLATE_FILE,
        context=ResolutionContext.from_template(loaded.doc),
    )


@pytest.mark.parametrize("name", list(DESIGN_TABLE), ids=list(DESIGN_TABLE))
def test_every_detector_fires_on_the_dangerous_fixture(
    name: str, dangerous_scan: detectors.ScanResult
) -> None:
    """The fixture's documented defects reach the scan output, one rule each."""
    fired = {
        entry.RuleId
        for produced in dangerous_scan.findings
        for entry in produced.Evidence
    }

    assert name in fired


def test_scan_leaves_the_scoped_resource_alone(
    dangerous_scan: detectors.ScanResult,
) -> None:
    """``ScopedRole`` is written to be clean, so no Finding may name it."""
    assert [
        produced.Finding
        for produced in dangerous_scan.findings
        if produced.Resource == "ScopedRole"
    ] == []


def test_scan_reduces_the_partner_policy_to_medium(
    dangerous_scan: detectors.ScanResult,
) -> None:
    """The fixture's cross-account grant carries an ExternalId (AC10)."""
    partner = [
        produced
        for produced in dangerous_scan.findings
        if produced.Resource == "PartnerBucketPolicy"
        and produced.Evidence[0].RuleId == "cross_account_principal"
    ]

    assert [produced.Severity for produced in partner] == ["MEDIUM"]


def test_scan_reports_a_public_lambda_permission(
    dangerous_scan: detectors.ScanResult,
) -> None:
    """An ``AWS::Lambda::Permission`` with ``Principal: "*"`` is AC9's case."""
    public = [
        produced
        for produced in dangerous_scan.findings
        if produced.Resource == "PublicInvokePermission"
    ]

    assert [produced.Evidence[0].RuleId for produced in public] == ["principal_star"]
    assert public[0].Severity == "CRITICAL"
    assert public[0].Location.TemplatePath == [
        "Resources",
        "PublicInvokePermission",
        "Properties",
    ]


def test_scan_is_deterministic(dangerous_scan: detectors.ScanResult) -> None:
    """Same input, same output -- Requirement 16 AC11 in the small."""
    loaded = template.load_template(DANGEROUS_FIXTURE)
    again = detectors.scan_sites(
        locate.find_policy_documents(loaded.doc),
        template_file=TEMPLATE_FILE,
        context=ResolutionContext.from_template(loaded.doc),
    )

    assert [finding_module.to_dict(f) for f in again.findings] == [
        finding_module.to_dict(f) for f in dangerous_scan.findings
    ]


def test_scan_findings_validate(dangerous_scan: detectors.ScanResult) -> None:
    for index, produced in enumerate(dangerous_scan.findings, start=1):
        finding_module.validate(replace(produced, ID=index))


# ---------------------------------------------------------------------------
# 6. Untrusted structure
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "document",
    [
        {"Version": "2012-10-17"},
        {"Version": "2012-10-17", "Statement": "Allow everything"},
        {"Version": "2012-10-17", "Statement": ["a string", 7, None]},
        {"Version": "2012-10-17", "Statement": {"Effect": "Allow", "Action": 7}},
        {"Version": "2012-10-17", "Statement": [statement(Action="*", Resource="*", Condition=[])]},
        {"Version": "2012-10-17", "Statement": [{"Effect": {"Ref": "Mode"}, "Action": "*", "Resource": "*"}]},
    ],
    ids=[
        "no_statement_key",
        "statement_is_a_string",
        "statement_entries_are_not_mappings",
        "action_is_a_number",
        "condition_is_a_list",
        "effect_is_a_deploy_time_value",
    ],
)
def test_untrusted_document_shapes_never_raise(document: Any) -> None:
    """Every detector tolerates a shape IAM would reject."""
    target = make_target(document)

    for detector in detectors.DETECTORS:
        detector(target)


def test_single_statement_mapping_is_examined() -> None:
    """IAM accepts one statement without a list, and so does the scan."""
    target = make_target(
        {"Version": "2012-10-17", "Statement": statement(Action="*", Resource="*")}
    )

    findings = detectors.star_action_star_resource(target).findings

    assert len(findings) == 1
    assert findings[0].Location.TemplatePath[-1] == "Statement"


def test_effect_that_cannot_be_resolved_is_not_read_as_a_grant() -> None:
    """A deploy-time ``Effect`` is disclosed, not asserted to be an Allow."""
    target = make_target(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": {"Ref": "Mode"}, "Action": "*", "Resource": "*"}],
        },
        parameters={"Mode": {"Type": "String"}},
    )

    result = detectors.star_action_star_resource(target)

    assert result.findings == ()
    assert [record.value_kind for record in result.unresolved] == ["Effect"]
