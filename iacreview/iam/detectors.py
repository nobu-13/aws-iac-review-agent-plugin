"""Layer 1 of the IAM review: the fifteen deterministic detectors.

Requirement 6 enumerates its dangerous patterns by name -- exact action names,
exact Principal values, exact structures -- so matching them is structural
comparison rather than judgement. design.md therefore splits Requirement 6 into
two layers, and this module is Layer 1: every Finding it produces carries
``Confidence: "Confirmed"`` because a rule either matched the Template or it did
not. Layer 2 (the ``iam-review`` Skill's guidance to the host Agent) handles the
questions that need reasoning, and never claims ``Confirmed``.

The detectors are the fifteen rows of design.md's *Layer 1: 決定論的検出器*
table, in that order, plus :func:`no_iam_resources` for the empty case
(Requirement 6 AC12, which produces no Finding at all). Each is an independent
pure function over one :class:`PolicyTarget`, so one detector cannot influence
another and the result never depends on the order they run in. A statement
matching several detectors yields several Findings, all with
``Normalized_Category: "IAM"``, which ``dedup`` later merges on the owning
resource -- keeping every reason a resource was flagged rather than collapsing
them into one.

Four decisions worth knowing before reading or extending the module:

every detector reports grants, never restrictions
    All fifteen require ``Effect: Allow``. design.md spells that condition out
    on only some rows, but applying it everywhere is not a weakening: a ``Deny``
    statement removes access, so reporting one as a permission would be a false
    positive, and Requirement 6's own wording is about permissions
    ("wildcard permissions", "cross-account access"). The clearest case is
    ``Effect: Deny`` with ``Principal: "*"``, which is the standard shape of a
    bucket policy denying unencrypted transport; flagging it CRITICAL would
    punish the correct pattern. An ``Effect`` that cannot be resolved is not
    read as a grant either -- it is disclosed as an unresolvable value instead,
    so the statement is not silently dropped.

no detector interprets an intrinsic function itself
    Every value question goes through :func:`iacreview.iam.intrinsics.evaluate`,
    which applies design.md's resolution policy once for all fifteen. A detector
    only supplies a predicate over plain strings. Where a value could not be
    decided, the location is collected as an
    :class:`~iacreview.iam.intrinsics.UnresolvedValue` and returned alongside
    the Findings, so Task 13.4 can disclose the coverage gap as an
    ``Informational`` Finding instead of letting it pass as clean.

action matching follows IAM wildcard semantics
    ``iam:*`` grants ``iam:PutRolePolicy``, and ``"*"`` grants everything. A
    detector looking for a named action therefore matches any pattern that
    *covers* it (:func:`grants`), not just the literal spelling. Without this a
    policy could escape every named-action detector by writing ``iam:P*``.

the ExternalId reduction happens after detection, not inside it
    :func:`apply_external_id_mitigation` is applied by :func:`scan` once the
    Findings exist and before deduplication (Requirement 6 AC10). Keeping it out
    of ``cross_account_principal`` is what makes the reduction testable on its
    own and keeps the detector's Severity fixed at the table's value.

Nothing here reads a file, runs a process, or mutates its input. Every value
comes from an already-parsed Template and is treated as untrusted: a statement
that is a string, an ``Action`` that is a number, a ``Condition`` that is a list
all produce fewer Findings rather than an exception.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from functools import lru_cache
from typing import (
    Any,
    Callable,
    Dict,
    FrozenSet,
    List,
    Optional,
    Sequence,
    Tuple,
    Union,
)

from iacreview.finding import (
    CONFIRMED,
    SEVERITIES,
    SEVERITY_ORDER,
    UNASSIGNED_ID,
    Evidence,
    Finding,
    Location,
    schema_violation,
    sorted_sources,
)
from iacreview.iam.intrinsics import (
    Candidate,
    PrincipalClass,
    ResolutionContext,
    UnresolvedValue,
    ValueKind,
    Verdict,
    classify_principal,
    dedupe_unresolved,
    evaluate,
    expand_conditionals,
    unresolved_values,
)
from iacreview.iam.locate import PathSegment, PolicyKind, PolicySite

__all__ = [
    "SOURCE_NAME",
    "CATEGORY",
    "FINDING_TYPE",
    "SEVERITY_FLOOR",
    "EFFECT_KEY",
    "ACTION_KEY",
    "RESOURCE_KEY",
    "PRINCIPAL_KEY",
    "CONDITION_KEY",
    "STATEMENT_KEY",
    "ALLOW_EFFECT",
    "SENSITIVE_ACTION_PREFIXES",
    "POLICY_MUTATION_ACTIONS",
    "PASS_ROLE_ACTION",
    "ASSUME_ROLE_ACTION",
    "LAMBDA_CREATE_FUNCTION_ACTION",
    "LAMBDA_UPDATE_CODE_ACTION",
    "LAMBDA_INVOKE_ACTION",
    "EC2_RUN_INSTANCES_ACTION",
    "S3_COMBO_ACTIONS",
    "CONFUSED_DEPUTY_CONDITION_KEYS",
    "EXTERNAL_ID_CONDITION_KEY",
    "LAMBDA_PERMISSION_CONDITION_PROPERTIES",
    "NO_IAM_RESOURCES_MESSAGE",
    "DetectorSpec",
    "SPECS",
    "DETECTORS",
    "DETECTOR_NAMES",
    "StatementView",
    "PolicyTarget",
    "PrincipalValue",
    "Detection",
    "DetectorResult",
    "ScanResult",
    "grants",
    "lower_one_level",
    "star_action_star_resource",
    "wildcard_action",
    "wildcard_resource",
    "sensitive_prefix_without_condition",
    "passrole_unrestricted",
    "assumerole_unrestricted",
    "privesc_policy_mutation",
    "privesc_lambda_passrole",
    "privesc_broad_trust",
    "cross_service_missing_condition",
    "cross_account_principal",
    "principal_star",
    "dangerous_s3_combo",
    "dangerous_ec2_passrole",
    "dangerous_lambda_combo",
    "no_iam_resources",
    "apply_external_id_mitigation",
    "scan",
    "scan_sites",
    "scan_target",
]


# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------

#: ``Source`` and ``Evidence[].Source`` of every Finding this module builds.
SOURCE_NAME = "IAM Review"

#: ``Normalized_Category`` fixed by design.md's table for all fifteen rows.
CATEGORY = "IAM"

#: ``FindingType`` fixed by design.md's table for all fifteen rows.
FINDING_TYPE = "Security"

#: Lowest Severity :func:`lower_one_level` will return (Requirement 6 AC10).
SEVERITY_FLOOR = "INFO"

EFFECT_KEY = "Effect"
ACTION_KEY = "Action"
RESOURCE_KEY = "Resource"
PRINCIPAL_KEY = "Principal"
CONDITION_KEY = "Condition"
STATEMENT_KEY = "Statement"

#: The only ``Effect`` that grants access. Compared case-insensitively.
ALLOW_EFFECT = "Allow"

#: Action prefixes Requirement 6 AC2 calls sensitive. Compared case-insensitively
#: against the start of an action string, so ``iam:*`` and ``iam:PassRole`` both
#: qualify. A bare ``"*"`` deliberately does not: it has no service prefix, and
#: ``star_action_star_resource`` / ``wildcard_action`` already report it.
SENSITIVE_ACTION_PREFIXES: Tuple[str, ...] = ("iam:", "sts:", "lambda:", "s3:")

#: The eight policy-mutating actions Requirement 6 AC5 enumerates. Each grants
#: the holder a way to attach or rewrite a policy, and therefore a way to grant
#: itself anything.
POLICY_MUTATION_ACTIONS: Tuple[str, ...] = (
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:AttachUserPolicy",
    "iam:AttachGroupPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutGroupPolicy",
    "iam:PutRolePolicy",
)

PASS_ROLE_ACTION = "iam:PassRole"
ASSUME_ROLE_ACTION = "sts:AssumeRole"
LAMBDA_CREATE_FUNCTION_ACTION = "lambda:CreateFunction"
LAMBDA_UPDATE_CODE_ACTION = "lambda:UpdateFunctionCode"
LAMBDA_INVOKE_ACTION = "lambda:InvokeFunction"
EC2_RUN_INSTANCES_ACTION = "ec2:RunInstances"

#: The three-action combination Requirement 6 AC11 names for S3: full read,
#: write and delete over an unrestricted Resource.
S3_COMBO_ACTIONS: Tuple[str, ...] = (
    "s3:GetObject",
    "s3:PutObject",
    "s3:DeleteObject",
)

#: Condition keys that scope a cross-service or cross-account grant to a caller
#: the account owner controls (Requirement 6 AC6). Lower-cased, because IAM
#: condition keys are matched case-insensitively.
CONFUSED_DEPUTY_CONDITION_KEYS: FrozenSet[str] = frozenset(
    {"aws:sourceaccount", "aws:sourcearn", "aws:principalorgid"}
)

#: The mitigating condition key of Requirement 6 AC10, lower-cased.
EXTERNAL_ID_CONDITION_KEY = "sts:externalid"

#: ``AWS::Lambda::Permission`` property -> the IAM condition key it is equivalent
#: to. The resource has no policy document, but these three properties are
#: exactly the confused-deputy conditions AWS applies on the caller's behalf, so
#: treating them as conditions lets ``cross_service_missing_condition`` ask one
#: question of both shapes (design.md, Policy document の所在).
LAMBDA_PERMISSION_CONDITION_PROPERTIES: Dict[str, str] = {
    "SourceAccount": "aws:SourceAccount",
    "SourceArn": "aws:SourceArn",
    "PrincipalOrgID": "aws:PrincipalOrgID",
}

#: Operator the synthesized ``AWS::Lambda::Permission`` conditions are recorded
#: under. Only the condition *keys* are ever read, so the operator is a label.
_SYNTHETIC_CONDITION_OPERATOR = "StringEquals"

#: ``Evidence[].Detail`` note naming the synthesized origin of that statement.
_LAMBDA_PERMISSION_ORIGIN = "AWS::Lambda::Permission properties"

#: ``stats.informational_message`` for a Template with nothing IAM-related
#: (Requirement 6 AC12). The message lives here, next to the detectors, so the
#: IAM Source in Task 13.4 reports the absence in the same words the detectors
#: define it by.
NO_IAM_RESOURCES_MESSAGE = (
    "No IAM-related resources or policies were found in this Template, so the "
    "deterministic IAM checks reported no findings."
)

#: ``Evidence[].Detail`` of the ExternalId reduction, verbatim from design.md.
EXTERNAL_ID_MITIGATION_DETAIL = (
    "Mitigating condition present: sts:ExternalId is required in this "
    "statement, which prevents the confused-deputy pattern. Severity was "
    "reduced by one level."
)

#: How many matched values a Finding quotes before it says "and others". Bounded
#: so that a policy with a hundred wildcard resources still produces a readable
#: sentence and a bounded report.
_QUOTED_VALUE_LIMIT = 3

#: Recognises an IAM role ARN, used to tell ``arn:aws:iam::*:role/*`` from an
#: unrelated ARN that merely contains a wildcard.
_ROLE_ARN = re.compile(r"^arn:[^:]*:iam:[^:]*:[^:]*:role/", re.IGNORECASE)

#: Severity rank -> name, derived from :data:`iacreview.finding.SEVERITY_ORDER`
#: so the two cannot disagree.
_SEVERITY_BY_RANK: Dict[int, str] = {
    rank: name for name, rank in SEVERITY_ORDER.items()
}


# ---------------------------------------------------------------------------
# Severity arithmetic
# ---------------------------------------------------------------------------


def lower_one_level(severity: str) -> str:
    """Return the Severity one step below ``severity``.

    One step on the ordering ``CRITICAL > HIGH > MEDIUM > LOW > INFO``, with
    :data:`SEVERITY_FLOOR` as the floor: lowering ``INFO`` returns ``INFO``
    rather than falling off the scale (Requirement 6 AC10, Property 27).

    Args:
        severity: A value from :data:`iacreview.finding.SEVERITIES`.

    Raises:
        SchemaViolationError: ``severity`` is not a known Severity. Guessing
            would silently produce a Finding the report schema rejects.
    """
    rank = SEVERITY_ORDER.get(severity)
    if rank is None:
        raise schema_violation(
            "Severity", "{0!r} is not one of {1}".format(severity, list(SEVERITIES))
        )
    return _SEVERITY_BY_RANK[max(rank - 1, SEVERITY_ORDER[SEVERITY_FLOOR])]


# ---------------------------------------------------------------------------
# Detector specifications
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DetectorSpec:
    """The fixed part of one detector's Finding.

    design.md's table assigns ``FindingType``, ``Severity`` and
    ``Normalized_Category`` per detector, and Requirement 6 AC13 requires each
    Finding to explain the risk. Holding all of that in one table means a
    detector's function body contains only its matching logic, and a test can
    compare the table against design.md directly.

    Attributes:
        name: The detector's name, used as the ``[name]`` prefix of the Finding
            text and as ``Evidence[].RuleId``. Equal to the function's name.
        severity: The table's Severity. ``privesc_broad_trust`` is the one
            detector whose Severity depends on what it found; it passes an
            explicit override and this value is its lower case.
        why_it_matters: ``WhyItMatters`` -- the consequence, not the rule.
        recommendation: ``Recommendation`` -- what to change.
        finding_type: Always :data:`FINDING_TYPE` for the fifteen Layer 1 rows.
        category: Always :data:`CATEGORY`.
    """

    name: str
    severity: str
    why_it_matters: str
    recommendation: str
    finding_type: str = FINDING_TYPE
    category: str = CATEGORY


_STAR_ACTION_STAR_RESOURCE = DetectorSpec(
    name="star_action_star_resource",
    severity="CRITICAL",
    why_it_matters=(
        "A statement allowing every action on every resource grants full "
        "administrative control of the account. Anything that obtains this "
        "identity obtains the account, and no later restriction elsewhere in "
        "the Template narrows it."
    ),
    recommendation=(
        "Replace the wildcards with the specific actions and the specific "
        "resource ARNs this identity needs, and add the remaining permissions "
        "only when a failure shows they are required."
    ),
)

_WILDCARD_ACTION = DetectorSpec(
    name="wildcard_action",
    severity="HIGH",
    why_it_matters=(
        "A wildcard action grants every current and future API call matching "
        "the pattern, including calls added by AWS after this Template was "
        "written. The effective permission set therefore grows without any "
        "change to the Template."
    ),
    recommendation=(
        "List the individual actions this identity calls instead of a wildcard "
        "pattern."
    ),
)

_WILDCARD_RESOURCE = DetectorSpec(
    name="wildcard_resource",
    severity="HIGH",
    why_it_matters=(
        "A wildcard resource applies the allowed actions to every resource the "
        "pattern covers, including resources created later. Access is then no "
        "longer bounded by what this workload owns."
    ),
    recommendation=(
        "Scope Resource to the ARNs of the resources this identity uses, using "
        "Ref or Fn::Sub against the resources declared in this Template."
    ),
)

_SENSITIVE_PREFIX_WITHOUT_CONDITION = DetectorSpec(
    name="sensitive_prefix_without_condition",
    severity="HIGH",
    why_it_matters=(
        "Actions under iam:, sts:, lambda: and s3: can change who holds which "
        "permissions, or reach data directly. Without a Condition, the grant "
        "applies in every context: any caller, any source, any time."
    ),
    recommendation=(
        "Add a Condition that bounds the grant -- for example "
        "aws:SourceAccount, aws:SourceArn, aws:PrincipalOrgID, or a resource "
        "tag condition -- or narrow the actions so the sensitive ones are not "
        "included."
    ),
)

_PASSROLE_UNRESTRICTED = DetectorSpec(
    name="passrole_unrestricted",
    severity="CRITICAL",
    why_it_matters=(
        "iam:PassRole on an unrestricted Resource lets the holder hand any role "
        "in the account to a service it can start. Combined with any "
        "service-creating permission, that is a direct path to the most "
        "privileged role that exists."
    ),
    recommendation=(
        "Restrict Resource to the exact role ARNs that may be passed, and add "
        "an iam:PassedToService condition naming the service allowed to "
        "receive them."
    ),
)

_ASSUMEROLE_UNRESTRICTED = DetectorSpec(
    name="assumerole_unrestricted",
    severity="HIGH",
    why_it_matters=(
        "sts:AssumeRole on Resource \"*\" lets the holder assume every role "
        "whose trust policy admits it, so its effective permissions are the "
        "union of those roles rather than what this policy lists."
    ),
    recommendation=(
        "Restrict Resource to the specific role ARNs this identity needs to "
        "assume."
    ),
)

_PRIVESC_POLICY_MUTATION = DetectorSpec(
    name="privesc_policy_mutation",
    severity="CRITICAL",
    why_it_matters=(
        "An identity that can attach or rewrite policies can grant itself any "
        "permission. Every other restriction in this Template is then advisory "
        "rather than enforced."
    ),
    recommendation=(
        "Remove the policy-mutating actions, or confine them to a dedicated "
        "administrative identity and bound them with a permissions boundary."
    ),
)

_PRIVESC_LAMBDA_PASSROLE = DetectorSpec(
    name="privesc_lambda_passrole",
    severity="CRITICAL",
    why_it_matters=(
        "lambda:CreateFunction together with iam:PassRole lets the holder "
        "create a function running as a more privileged role and execute code "
        "as that role. The two permissions are individually ordinary and "
        "jointly a full privilege escalation."
    ),
    recommendation=(
        "Remove one of the two actions, or restrict iam:PassRole to role ARNs "
        "that are no more privileged than this identity."
    ),
)

_PRIVESC_BROAD_TRUST = DetectorSpec(
    name="privesc_broad_trust",
    severity="HIGH",
    why_it_matters=(
        "A trust policy decides who may become this role. When it admits every "
        "principal, or admits a service without bounding which of that "
        "service's resources may call, the role's permissions are reachable by "
        "callers the account owner never enumerated."
    ),
    recommendation=(
        "Name the specific principals allowed to assume the role, and for a "
        "service principal add aws:SourceAccount and aws:SourceArn conditions "
        "identifying the resource that may assume it."
    ),
)

_CROSS_SERVICE_MISSING_CONDITION = DetectorSpec(
    name="cross_service_missing_condition",
    severity="HIGH",
    why_it_matters=(
        "A grant to an AWS service or to another account with no "
        "aws:SourceAccount, aws:SourceArn or aws:PrincipalOrgID condition is "
        "open to the confused-deputy pattern: a third party can ask the same "
        "service to act on this resource on their behalf."
    ),
    recommendation=(
        "Add aws:SourceAccount or aws:SourceArn naming the account and "
        "resource allowed to invoke this grant, or aws:PrincipalOrgID to "
        "confine it to your organization."
    ),
)

_CROSS_ACCOUNT_PRINCIPAL = DetectorSpec(
    name="cross_account_principal",
    severity="HIGH",
    why_it_matters=(
        "This grant is to a principal in another AWS account, so access "
        "extends beyond the security boundary this stack is deployed into and "
        "is governed by controls the account owner does not administer."
    ),
    recommendation=(
        "Confirm that the external account is intended, restrict the grant to "
        "the specific role or user ARN rather than the account root, and "
        "require an sts:ExternalId condition so the third party cannot be used "
        "as a confused deputy."
    ),
)

_PRINCIPAL_STAR = DetectorSpec(
    name="principal_star",
    severity="CRITICAL",
    why_it_matters=(
        "A Principal of \"*\" grants the allowed actions to every AWS principal "
        "and, on a resource policy, to anonymous callers. Nothing outside this "
        "statement's own Condition block limits who is admitted."
    ),
    recommendation=(
        "Replace \"*\" with the specific accounts, roles or service principals "
        "that need access. If public access is genuinely required, state that "
        "intent explicitly and bound it with a Condition."
    ),
)

_DANGEROUS_S3_COMBO = DetectorSpec(
    name="dangerous_s3_combo",
    severity="HIGH",
    why_it_matters=(
        "Read, write and delete on an unrestricted Resource allows every "
        "object in every bucket the identity can see to be exfiltrated, "
        "replaced, or destroyed -- including backups stored in the same "
        "account."
    ),
    recommendation=(
        "Scope Resource to the specific bucket and prefix ARNs, and split read "
        "and delete permissions between separate identities where the workload "
        "allows it."
    ),
)

_DANGEROUS_EC2_PASSROLE = DetectorSpec(
    name="dangerous_ec2_passrole",
    severity="HIGH",
    why_it_matters=(
        "ec2:RunInstances together with iam:PassRole lets the holder launch an "
        "instance carrying another role's credentials and read those "
        "credentials from instance metadata, acquiring that role's permissions."
    ),
    recommendation=(
        "Restrict iam:PassRole to the instance profile roles this workload "
        "launches, with an iam:PassedToService condition of ec2.amazonaws.com."
    ),
)

_DANGEROUS_LAMBDA_COMBO = DetectorSpec(
    name="dangerous_lambda_combo",
    severity="HIGH",
    why_it_matters=(
        "lambda:UpdateFunctionCode together with lambda:InvokeFunction lets the "
        "holder replace a function's code and run it, executing arbitrary code "
        "with that function's execution role."
    ),
    recommendation=(
        "Separate deployment permissions from invocation permissions, and "
        "restrict Resource to the specific function ARNs each identity needs."
    ),
)

#: Every spec, in design.md's table order. :data:`SPECS` and
#: :data:`DETECTOR_NAMES` are derived from it, so the order is stated once.
_ALL_SPECS: Tuple[DetectorSpec, ...] = (
    _STAR_ACTION_STAR_RESOURCE,
    _WILDCARD_ACTION,
    _WILDCARD_RESOURCE,
    _SENSITIVE_PREFIX_WITHOUT_CONDITION,
    _PASSROLE_UNRESTRICTED,
    _ASSUMEROLE_UNRESTRICTED,
    _PRIVESC_POLICY_MUTATION,
    _PRIVESC_LAMBDA_PASSROLE,
    _PRIVESC_BROAD_TRUST,
    _CROSS_SERVICE_MISSING_CONDITION,
    _CROSS_ACCOUNT_PRINCIPAL,
    _PRINCIPAL_STAR,
    _DANGEROUS_S3_COMBO,
    _DANGEROUS_EC2_PASSROLE,
    _DANGEROUS_LAMBDA_COMBO,
)

#: Detector name -> its specification.
SPECS: Dict[str, DetectorSpec] = {spec.name: spec for spec in _ALL_SPECS}

#: Detector names in design.md's table order.
DETECTOR_NAMES: Tuple[str, ...] = tuple(spec.name for spec in _ALL_SPECS)


# ---------------------------------------------------------------------------
# What a detector looks at
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StatementView:
    """One policy statement, with the address a Finding reports it at.

    Attributes:
        statement: The statement mapping. For
            :attr:`~iacreview.iam.locate.PolicyKind.LAMBDA_PERMISSION` this is
            synthesized from the resource's properties; see
            :attr:`origin`.
        template_path: Path to the statement, extending
            :attr:`iacreview.iam.locate.PolicySite.template_path` with
            ``Statement`` and the statement index. This is the Finding's
            ``Location.TemplatePath`` (Requirement 6 AC13).
        branch: The ``Fn::If`` alternative this statement came from, or ``None``.
            Both alternatives of a conditional statement are examined
            independently, so a grant that exists in only one deploy-time
            branch is still reported; the label says which.
        origin: What the statement was synthesized from, or ``None`` when it was
            written as a statement in the Template. Non-``None`` marks a view
            that is not a real policy statement, which is why
            :attr:`PolicyTarget.policy_statements` excludes it.
    """

    statement: Dict[str, Any]
    template_path: Tuple[PathSegment, ...]
    branch: Optional[str] = None
    origin: Optional[str] = None

    @property
    def is_policy_statement(self) -> bool:
        """Whether the Template wrote this as a policy statement."""
        return self.origin is None

    @property
    def json_path(self) -> str:
        """Dotted path, spelled as ``PolicySite.json_path`` is."""
        return ".".join(str(segment) for segment in self.template_path)


@dataclass(frozen=True)
class PolicyTarget:
    """One :class:`~iacreview.iam.locate.PolicySite` prepared for detection.

    Built once per site by :meth:`from_site` and handed unchanged to all fifteen
    detectors, so the statement list is walked once however many detectors ask
    about it, and no detector can see a site another detector modified.

    Attributes:
        site: The located site.
        statements: Every statement to examine, including the synthesized
            ``AWS::Lambda::Permission`` view. In Template order.
        context: Template-level facts for intrinsic resolution.
        template_file: Workspace-relative path of the reviewed Template, used as
            ``Location.File``.
    """

    site: PolicySite
    statements: Tuple[StatementView, ...]
    context: ResolutionContext
    template_file: str

    @property
    def logical_id(self) -> str:
        """Logical ID of the owning resource; the Finding's ``Resource``."""
        return self.site.logical_id

    @property
    def kind(self) -> PolicyKind:
        """Which of the nine site kinds this is."""
        return self.site.kind

    @property
    def policy_statements(self) -> Tuple[StatementView, ...]:
        """Statements the Template wrote as policy statements.

        What the twelve action- and resource-based detectors iterate. It
        excludes the synthesized ``AWS::Lambda::Permission`` view, because that
        resource's ``Action`` is a single fixed API call granted to a caller
        rather than a permission set being designed -- asking
        ``sensitive_prefix_without_condition`` about it would flag every Lambda
        Permission ever written. design.md scopes that resource to the Principal
        detectors, which read it through :attr:`statements`.
        """
        return tuple(view for view in self.statements if view.is_policy_statement)

    @classmethod
    def from_site(
        cls,
        site: PolicySite,
        *,
        template_file: str,
        context: Optional[ResolutionContext] = None,
    ) -> "PolicyTarget":
        """Prepare ``site`` for detection.

        Args:
            site: A site from
                :func:`iacreview.iam.locate.find_policy_documents`.
            template_file: Workspace-relative path of the reviewed Template.
            context: Template-level facts; omitting it resolves literals and
                pseudo parameters only, which is conservative rather than wrong.

        Returns:
            The target. A site with nothing to examine -- a permissions
            boundary, or a malformed policy document -- yields an empty
            :attr:`statements`, and every detector then returns no Findings.
            Malformed documents are disclosed by the IAM Source through
            :func:`iacreview.iam.locate.malformed_document_sites`, not here.
        """
        return cls(
            site=site,
            statements=tuple(_statement_views(site)),
            context=context if context is not None else ResolutionContext(),
            template_file=template_file,
        )


@dataclass(frozen=True)
class PrincipalValue:
    """One Principal a statement admits, already classified.

    Attributes:
        value: The value as the Template wrote it.
        label: The Principal type key it sat under (``"AWS"``, ``"Service"``,
            ``"Federated"``), or ``"Principal"`` when the value was written
            directly.
        classification: What :func:`iacreview.iam.intrinsics.classify_principal`
            made of it.
    """

    value: Any
    label: str
    classification: PrincipalClass


@dataclass(frozen=True)
class Detection:
    """One Finding together with the statement it was raised on.

    The statement travels with the Finding because
    :func:`apply_external_id_mitigation` needs *that* statement's Condition
    block and no other (Requirement 6 AC10 says "in the same statement"). Doing
    it this way rather than looking the statement up again from the Finding's
    path keeps the association exact where two ``Fn::If`` alternatives share one
    path.
    """

    finding: Finding
    statement: Dict[str, Any]


@dataclass(frozen=True)
class DetectorResult:
    """What one detector found on one target.

    Attributes:
        detections: The Findings, each with its statement. Empty when the
            detector's pattern did not match.
        unresolved: Locations this detector could not evaluate, deduplicated.
            Returned rather than discarded so that Task 13.4 can disclose them:
            a value skipped by a deterministic check is a gap in coverage, not a
            clean result.
    """

    detections: Tuple[Detection, ...] = ()
    unresolved: Tuple[UnresolvedValue, ...] = ()

    @property
    def findings(self) -> Tuple[Finding, ...]:
        """The Findings alone, in detection order."""
        return tuple(detection.finding for detection in self.detections)


#: A detector: one target in, its Findings and coverage gaps out.
Detector = Callable[[PolicyTarget], DetectorResult]

#: A predicate over one resolved value string.
Predicate = Callable[[str], bool]

#: Which statement element a value came from, as :func:`_match` accepts it.
Element = Union[ValueKind, str]


# ---------------------------------------------------------------------------
# Statement extraction
# ---------------------------------------------------------------------------


def _statement_views(site: PolicySite) -> List[StatementView]:
    """Enumerate the statements of one site, with their paths.

    Both ``Statement`` forms IAM accepts are handled -- a list of statements and
    a single statement mapping -- and an ``Fn::If`` at either level is expanded
    into its alternatives, because the condition is decided at deploy time and
    reporting only one branch would hide a real grant.
    """
    if site.kind is PolicyKind.LAMBDA_PERMISSION:
        return _lambda_permission_views(site)
    if not site.has_policy_document:
        return []
    base: Tuple[PathSegment, ...] = tuple(site.template_path) + (STATEMENT_KEY,)
    views: List[StatementView] = []
    for branch in expand_conditionals(site.document.get(STATEMENT_KEY)):
        _collect_statement_views(branch.value, branch.label, base, views)
    return views


def _collect_statement_views(
    value: Any,
    branch: Optional[str],
    path: Tuple[PathSegment, ...],
    out: List[StatementView],
) -> None:
    if isinstance(value, list):
        for index, entry in enumerate(value):
            for inner in expand_conditionals(entry):
                _append_statement_view(
                    inner.value, _merge_branches(branch, inner.label), path + (index,), out
                )
        return
    _append_statement_view(value, branch, path, out)


def _append_statement_view(
    value: Any,
    branch: Optional[str],
    path: Tuple[PathSegment, ...],
    out: List[StatementView],
) -> None:
    """Add a statement view, or nothing when there is no statement here.

    A non-mapping statement -- a string, ``None`` from an empty YAML value, an
    ``Fn::If`` too malformed for :func:`expand_conditionals` to read -- is
    skipped. Reporting on a shape IAM itself rejects would state a permission
    that cannot exist; cfn-lint is what reports the malformed statement.
    """
    if isinstance(value, dict):
        out.append(StatementView(statement=value, template_path=path, branch=branch))


def _merge_branches(outer: Optional[str], inner: Optional[str]) -> Optional[str]:
    if outer is None:
        return inner
    if inner is None:
        return outer
    return "{0} / {1}".format(outer, inner)


def _lambda_permission_views(site: PolicySite) -> List[StatementView]:
    """Present an ``AWS::Lambda::Permission`` as a single statement.

    The resource has no policy document, but it is a grant: ``Principal`` says
    who, ``Action`` says what, and ``SourceAccount`` / ``SourceArn`` /
    ``PrincipalOrgID`` are the confused-deputy conditions AWS applies for the
    caller. Rendering those as ``Effect`` / ``Action`` / ``Principal`` /
    ``Condition`` lets the Principal detectors ask one question of both shapes
    instead of carrying a second code path.

    ``Effect`` is ``Allow`` because a Lambda Permission only ever grants; it has
    no deny form. Only properties the Template actually set are represented, so
    nothing is invented. The view's ``template_path`` is the resource's
    ``Properties``, which is where each of these values really lives, so a
    Finding still points at a real location.
    """
    properties = site.document
    if not isinstance(properties, dict):
        return []

    statement: Dict[str, Any] = {EFFECT_KEY: ALLOW_EFFECT}
    for key in (ACTION_KEY, PRINCIPAL_KEY):
        if key in properties:
            statement[key] = properties[key]

    conditions = {
        condition_key: properties[property_name]
        for property_name, condition_key in LAMBDA_PERMISSION_CONDITION_PROPERTIES.items()
        if property_name in properties
    }
    if conditions:
        statement[CONDITION_KEY] = {_SYNTHETIC_CONDITION_OPERATOR: conditions}

    return [
        StatementView(
            statement=statement,
            template_path=tuple(site.template_path),
            origin=_LAMBDA_PERMISSION_ORIGIN,
        )
    ]


# ---------------------------------------------------------------------------
# Value predicates
# ---------------------------------------------------------------------------


def _is_star(text: str) -> bool:
    """Whether a value is exactly ``"*"``."""
    return text == "*"


def _has_wildcard(text: str) -> bool:
    """Whether a value contains a wildcard anywhere, as ``s3:*`` does."""
    return "*" in text


def _is_allow(text: str) -> bool:
    """Whether an ``Effect`` grants. IAM compares ``Effect`` case-insensitively."""
    return text.strip().lower() == ALLOW_EFFECT.lower()


def grants(pattern: str, action: str) -> bool:
    """Whether the action pattern ``pattern`` covers the API call ``action``.

    IAM action patterns admit ``*`` (any run of characters) and ``?`` (one
    character) and are matched case-insensitively, so ``iam:*``, ``iam:P*`` and
    ``*`` all grant ``iam:PassRole``. Detectors looking for a named action use
    this rather than string equality: without it, a policy would escape every
    named-action detector by writing a wildcard that happens to cover the same
    call.

    Args:
        pattern: An ``Action`` value from the Template.
        action: The API call to test for, for example :data:`PASS_ROLE_ACTION`.
    """
    return _action_regex(pattern).match(action) is not None


@lru_cache(maxsize=512)
def _action_regex(pattern: str) -> "re.Pattern[str]":
    """Compile one action pattern. Bounded cache: patterns are untrusted input."""
    parts = []
    for character in pattern:
        if character == "*":
            parts.append(".*")
        elif character == "?":
            parts.append(".")
        else:
            parts.append(re.escape(character))
    return re.compile("".join(parts) + r"\Z", re.IGNORECASE)


def _grants_any(actions: Sequence[str]) -> Predicate:
    """Predicate: does this ``Action`` value grant any of ``actions``."""

    def predicate(text: str) -> bool:
        return any(grants(text, action) for action in actions)

    return predicate


def _is_sensitive_prefix(text: str) -> bool:
    """Whether an action names one of Requirement 6 AC2's sensitive services."""
    lowered = text.lower()
    return any(lowered.startswith(prefix) for prefix in SENSITIVE_ACTION_PREFIXES)


def _is_unrestricted_role_resource(text: str) -> bool:
    """Whether a ``Resource`` leaves ``iam:PassRole`` effectively unbounded.

    design.md names two shapes: ``"*"``, and a wildcarded role ARN such as
    ``arn:aws:iam::*:role/*``. An unrelated ARN containing a wildcard is not one
    of them, which is why the ARN itself is recognised rather than only the
    wildcard.
    """
    if _is_star(text):
        return True
    return _has_wildcard(text) and _ROLE_ARN.match(text) is not None


_GRANTS_PASS_ROLE = _grants_any((PASS_ROLE_ACTION,))
_GRANTS_ASSUME_ROLE = _grants_any((ASSUME_ROLE_ACTION,))
_GRANTS_POLICY_MUTATION = _grants_any(POLICY_MUTATION_ACTIONS)


# ---------------------------------------------------------------------------
# Asking questions about a statement
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Match:
    """The outcome of applying one predicate to one statement element."""

    matched: bool
    candidates: Tuple[Candidate, ...]


class _Probe:
    """Answers a detector's questions and remembers what it could not answer.

    Every question routes through :func:`iacreview.iam.intrinsics.evaluate`, so
    a detector never inspects an intrinsic function itself. Where a value could
    not be decided, the location is accumulated here and returned by
    :meth:`records`, which is how ``UNRESOLVABLE`` reaches the report instead of
    being dropped.

    The accumulator is local to one detector call, so a detector using a probe
    is still a pure function of its target.
    """

    def __init__(self, target: PolicyTarget) -> None:
        self._target = target
        self._unresolved: List[UnresolvedValue] = []

    def records(self) -> Tuple[UnresolvedValue, ...]:
        """The coverage gaps seen so far, deduplicated."""
        return tuple(dedupe_unresolved(self._unresolved))

    def allows(self, view: StatementView) -> bool:
        """Whether this statement grants access.

        ``True`` only for a definite ``Allow``. A statement whose ``Effect`` is
        a deploy-time value is not read as a grant -- a ``Confirmed`` Finding
        cannot rest on a guess -- and the location is recorded instead, so the
        statement is disclosed rather than silently skipped. An ``Fn::If``
        choosing between ``Allow`` and ``Deny`` counts as allowing, because one
        of its alternatives does.
        """
        return self.match(view, EFFECT_KEY, _is_allow).matched

    def match(self, view: StatementView, element: Element, predicate: Predicate) -> _Match:
        """Apply ``predicate`` to one element of this statement."""
        key = element.value if isinstance(element, ValueKind) else element
        evaluation = evaluate(view.statement.get(key), predicate, self._target.context)
        self._unresolved.extend(
            unresolved_values(
                evaluation,
                self._target.logical_id,
                view.template_path + (key,),
                element,
            )
        )
        return _Match(
            matched=evaluation.verdict is Verdict.MATCH, candidates=evaluation.matched
        )

    def principals(self, view: StatementView) -> Tuple[PrincipalValue, ...]:
        """Classify every Principal this statement admits.

        A Principal that cannot be classified is recorded as a coverage gap and
        left out of the result: a value that *might* name another account is not
        evidence that it does (Requirement 6 AC7 asks for a literal ID).
        """
        raw = view.statement.get(PRINCIPAL_KEY)
        if raw is None:
            return ()

        collected: List[Tuple[Any, str]] = []
        for branch in expand_conditionals(raw):
            _collect_principals(branch.value, PRINCIPAL_KEY, collected)

        resolved: List[PrincipalValue] = []
        for value, label in collected:
            classification = classify_principal(value)
            if classification is PrincipalClass.UNRESOLVABLE:
                self._unresolved.append(
                    _unresolvable_principal(self._target, view, value, label)
                )
                continue
            resolved.append(
                PrincipalValue(value=value, label=label, classification=classification)
            )
        return tuple(resolved)


def _collect_principals(value: Any, label: str, out: List[Tuple[Any, str]]) -> None:
    """Split a ``Principal`` value into the individual principals it names.

    ``classify_principal`` takes one principal at a time, and only the exact
    mapping ``{"AWS": "*"}`` whole (Requirement 6 AC9 names it). Everything else
    is unwrapped from its Principal type key here, which is the part that knows
    it is looking at ``Principal``.
    """
    if value == "*" or value == {"AWS": "*"}:
        out.append((value, label))
        return
    if isinstance(value, list):
        for element in value:
            _collect_principals(element, label, out)
        return
    if isinstance(value, dict):
        if _is_intrinsic(value):
            # An intrinsic standing in for the whole Principal: classify it as
            # written, rather than treating its function name as a type key.
            out.append((value, label))
            return
        for key, sub_value in value.items():
            key_label = key if isinstance(key, str) else label
            _collect_principals(sub_value, key_label, out)
        return
    out.append((value, label))


def _is_intrinsic(value: Dict[Any, Any]) -> bool:
    return any(
        isinstance(key, str) and (key == "Ref" or key.startswith("Fn::")) for key in value
    )


def _unresolvable_principal(
    target: PolicyTarget, view: StatementView, value: Any, label: str
) -> UnresolvedValue:
    """Record a Principal the classifier could not decide.

    Named as precisely as the value allows: an intrinsic function by its own
    name, anything else as a value the classifier does not recognise. Both read
    as the subject of "is produced by ..." in the disclosure Finding's text.
    """
    if isinstance(value, dict):
        intrinsic = next(
            (
                key
                for key in value
                if isinstance(key, str) and (key == "Ref" or key.startswith("Fn::"))
            ),
            "a mapping that is not a supported intrinsic function",
        )
        detail = (
            "Unresolved Principal under {0}: {1} does not resolve to a literal "
            "account ID, ARN or service name, so the cross-account checks were "
            "not applied.".format(label, intrinsic)
        )
    else:
        intrinsic = "a Principal value this review does not recognise"
        detail = (
            "Unresolved Principal under {0}: the value is neither a literal "
            "account ID, an ARN embedding one, nor a service principal, so the "
            "cross-account checks were not applied.".format(label)
        )
    return UnresolvedValue(
        logical_id=target.logical_id,
        template_path=view.template_path + (PRINCIPAL_KEY,),
        value_kind=ValueKind.PRINCIPAL.value,
        intrinsic=intrinsic,
        detail=detail,
        branch=view.branch,
    )


def _condition_keys(statement: Dict[str, Any]) -> FrozenSet[str]:
    """Every condition key in a statement, lower-cased.

    IAM nests them as ``Condition -> operator -> key -> value``, and matches the
    key case-insensitively, so the operator is irrelevant to the questions asked
    here: "is there an ``sts:ExternalId``", "is there any of the three
    confused-deputy keys". An ``Fn::If`` around the whole block is expanded, and
    any shape that is not the documented nesting contributes no key rather than
    an exception.
    """
    keys = set()
    for branch in expand_conditionals(statement.get(CONDITION_KEY)):
        block = branch.value
        if not isinstance(block, dict):
            continue
        for entries in block.values():
            if not isinstance(entries, dict):
                continue
            for key in entries:
                if isinstance(key, str):
                    keys.add(key.lower())
    return frozenset(keys)


def _has_condition(statement: Dict[str, Any]) -> bool:
    """Whether a statement is bounded by at least one condition key.

    An empty or unreadable ``Condition`` counts as absent: it constrains
    nothing, so treating it as a bound would hide the grant design.md's
    "``Condition`` が無い" rows are about.
    """
    return bool(_condition_keys(statement))


def _has_external_id_condition(statement: Any) -> bool:
    """Whether this statement requires an ``sts:ExternalId`` (Requirement 6 AC10)."""
    if not isinstance(statement, dict):
        return False
    return EXTERNAL_ID_CONDITION_KEY in _condition_keys(statement)


# ---------------------------------------------------------------------------
# Finding construction
# ---------------------------------------------------------------------------


def _quote(candidates: Sequence[Candidate]) -> str:
    """Render matched values for a Finding sentence, bounded in length."""
    texts: List[str] = []
    for candidate in candidates:
        if candidate.text not in texts:
            texts.append(candidate.text)
    shown = ", ".join('"{0}"'.format(text) for text in texts[:_QUOTED_VALUE_LIMIT])
    if len(texts) > _QUOTED_VALUE_LIMIT:
        return "{0} and {1} more".format(shown, len(texts) - _QUOTED_VALUE_LIMIT)
    return shown


def _detail(target: PolicyTarget, view: StatementView, detail: str) -> str:
    """Append the location and provenance every Evidence entry should carry."""
    parts = [detail, "Detected in the {0} at {1}.".format(target.kind.value, view.json_path)]
    if view.branch is not None:
        parts.append("This statement is the {0}.".format(view.branch))
    if view.origin is not None:
        parts.append("The statement was derived from {0}.".format(view.origin))
    return " ".join(parts)


def _detect(
    target: PolicyTarget,
    view: StatementView,
    spec: DetectorSpec,
    *,
    finding: str,
    detail: str,
    severity: Optional[str] = None,
) -> Detection:
    """Build one Detection with every field design.md fixes for Layer 1.

    ``Confidence`` is ``Confirmed`` because the rule matched the Template as
    written. ``Line`` and ``Column`` are ``None``: this Source works on the
    parsed document, and ``TemplatePath`` is the precise address (Requirement 6
    AC13). ``ID`` is :data:`~iacreview.finding.UNASSIGNED_ID`, assigned when the
    report is sorted. ``Excerpt`` is ``None``, which the schema permits only
    because ``Confidence`` is ``Confirmed``; the ``RuleId`` is the evidence.
    """
    return Detection(
        finding=Finding(
            ID=UNASSIGNED_ID,
            Normalized_Category=spec.category,
            FindingType=spec.finding_type,
            Severity=spec.severity if severity is None else severity,
            Confidence=CONFIRMED,
            Source=sorted_sources([SOURCE_NAME]),
            Resource=target.logical_id,
            Location=Location(
                File=target.template_file,
                Line=None,
                Column=None,
                TemplatePath=list(view.template_path),
            ),
            Finding="[{0}] {1}".format(spec.name, finding),
            WhyItMatters=spec.why_it_matters,
            Evidence=[
                Evidence(
                    Source=SOURCE_NAME,
                    Detail=_detail(target, view, detail),
                    RuleId=spec.name,
                    Excerpt=None,
                )
            ],
            Recommendation=spec.recommendation,
            SuggestedRemediation=None,
        ),
        statement=view.statement,
    )


# ---------------------------------------------------------------------------
# Detectors: wildcards (Requirement 6 AC1, AC4)
# ---------------------------------------------------------------------------


def star_action_star_resource(target: PolicyTarget) -> DetectorResult:
    """``Effect: Allow`` with ``Action`` ``"*"`` and ``Resource`` ``"*"``.

    Requirement 6 AC1. Both must be the bare ``"*"``: a narrower wildcard such
    as ``s3:*`` is :func:`wildcard_action`'s HIGH, not this CRITICAL.
    """
    probe = _Probe(target)
    detections: List[Detection] = []
    for view in target.policy_statements:
        if not probe.allows(view):
            continue
        action = probe.match(view, ValueKind.ACTION, _is_star)
        resource = probe.match(view, ValueKind.RESOURCE, _is_star)
        if not (action.matched and resource.matched):
            continue
        detections.append(
            _detect(
                target,
                view,
                _STAR_ACTION_STAR_RESOURCE,
                finding=(
                    "This statement allows every action on every resource: "
                    "Action includes \"*\" and Resource includes \"*\"."
                ),
                detail=(
                    "Effect is Allow, Action includes \"*\" and Resource "
                    "includes \"*\" in the same statement."
                ),
            )
        )
    return DetectorResult(tuple(detections), probe.records())


def wildcard_action(target: PolicyTarget) -> DetectorResult:
    """An allowed ``Action`` containing ``"*"``, ``s3:*`` included.

    Requirement 6 AC4.
    """
    probe = _Probe(target)
    detections: List[Detection] = []
    for view in target.policy_statements:
        if not probe.allows(view):
            continue
        action = probe.match(view, ValueKind.ACTION, _has_wildcard)
        if not action.matched:
            continue
        quoted = _quote(action.candidates)
        detections.append(
            _detect(
                target,
                view,
                _WILDCARD_ACTION,
                finding=(
                    "This statement allows the wildcard action {0}, which "
                    "covers more API calls than it names.".format(quoted)
                ),
                detail="Action contains the wildcard value {0}.".format(quoted),
            )
        )
    return DetectorResult(tuple(detections), probe.records())


def wildcard_resource(target: PolicyTarget) -> DetectorResult:
    """An allowed ``Resource`` containing ``"*"``.

    Requirement 6 AC4.
    """
    probe = _Probe(target)
    detections: List[Detection] = []
    for view in target.policy_statements:
        if not probe.allows(view):
            continue
        resource = probe.match(view, ValueKind.RESOURCE, _has_wildcard)
        if not resource.matched:
            continue
        quoted = _quote(resource.candidates)
        detections.append(
            _detect(
                target,
                view,
                _WILDCARD_RESOURCE,
                finding=(
                    "This statement allows its actions on the wildcard "
                    "resource {0}.".format(quoted)
                ),
                detail="Resource contains the wildcard value {0}.".format(quoted),
            )
        )
    return DetectorResult(tuple(detections), probe.records())


def sensitive_prefix_without_condition(target: PolicyTarget) -> DetectorResult:
    """An allowed ``iam:`` / ``sts:`` / ``lambda:`` / ``s3:`` action, no Condition.

    Requirement 6 AC2.
    """
    probe = _Probe(target)
    detections: List[Detection] = []
    for view in target.policy_statements:
        if not probe.allows(view):
            continue
        if _has_condition(view.statement):
            continue
        action = probe.match(view, ValueKind.ACTION, _is_sensitive_prefix)
        if not action.matched:
            continue
        quoted = _quote(action.candidates)
        detections.append(
            _detect(
                target,
                view,
                _SENSITIVE_PREFIX_WITHOUT_CONDITION,
                finding=(
                    "This statement allows {0} with no Condition block, so the "
                    "grant applies in every context.".format(quoted)
                ),
                detail=(
                    "Effect is Allow on the sensitive action {0} and the "
                    "statement carries no Condition key.".format(quoted)
                ),
            )
        )
    return DetectorResult(tuple(detections), probe.records())


# ---------------------------------------------------------------------------
# Detectors: PassRole and AssumeRole (Requirement 6 AC3)
# ---------------------------------------------------------------------------


def passrole_unrestricted(target: PolicyTarget) -> DetectorResult:
    """``iam:PassRole`` allowed on ``"*"`` or a wildcarded role ARN.

    Requirement 6 AC3.
    """
    probe = _Probe(target)
    detections: List[Detection] = []
    for view in target.policy_statements:
        if not probe.allows(view):
            continue
        action = probe.match(view, ValueKind.ACTION, _GRANTS_PASS_ROLE)
        if not action.matched:
            continue
        resource = probe.match(view, ValueKind.RESOURCE, _is_unrestricted_role_resource)
        if not resource.matched:
            continue
        detections.append(
            _detect(
                target,
                view,
                _PASSROLE_UNRESTRICTED,
                finding=(
                    "This statement allows iam:PassRole on the unrestricted "
                    "Resource {0}, so any role in the account can be "
                    "passed.".format(_quote(resource.candidates))
                ),
                detail=(
                    "Action {0} grants iam:PassRole and Resource {1} does not "
                    "restrict which role may be passed.".format(
                        _quote(action.candidates), _quote(resource.candidates)
                    )
                ),
            )
        )
    return DetectorResult(tuple(detections), probe.records())


def assumerole_unrestricted(target: PolicyTarget) -> DetectorResult:
    """``sts:AssumeRole`` allowed on ``Resource: "*"``.

    Requirement 6 AC3.
    """
    probe = _Probe(target)
    detections: List[Detection] = []
    for view in target.policy_statements:
        if not probe.allows(view):
            continue
        action = probe.match(view, ValueKind.ACTION, _GRANTS_ASSUME_ROLE)
        if not action.matched:
            continue
        resource = probe.match(view, ValueKind.RESOURCE, _is_star)
        if not resource.matched:
            continue
        detections.append(
            _detect(
                target,
                view,
                _ASSUMEROLE_UNRESTRICTED,
                finding=(
                    "This statement allows sts:AssumeRole on Resource \"*\", so "
                    "every role that trusts this identity can be assumed."
                ),
                detail=(
                    "Action {0} grants sts:AssumeRole and Resource is "
                    "\"*\".".format(_quote(action.candidates))
                ),
            )
        )
    return DetectorResult(tuple(detections), probe.records())


# ---------------------------------------------------------------------------
# Detectors: privilege escalation (Requirement 6 AC5)
# ---------------------------------------------------------------------------


def privesc_policy_mutation(target: PolicyTarget) -> DetectorResult:
    """Any of the eight policy-mutating IAM actions, allowed.

    Requirement 6 AC5. Matched through :func:`grants`, so ``iam:*`` and ``"*"``
    are reported too: they grant these calls just as an explicit list does.
    """
    probe = _Probe(target)
    detections: List[Detection] = []
    for view in target.policy_statements:
        if not probe.allows(view):
            continue
        action = probe.match(view, ValueKind.ACTION, _GRANTS_POLICY_MUTATION)
        if not action.matched:
            continue
        quoted = _quote(action.candidates)
        detections.append(
            _detect(
                target,
                view,
                _PRIVESC_POLICY_MUTATION,
                finding=(
                    "This statement allows {0}, which grants the ability to "
                    "attach or rewrite IAM policies and therefore to escalate "
                    "privileges.".format(quoted)
                ),
                detail=(
                    "Action {0} grants at least one of the policy-mutating "
                    "actions {1}.".format(quoted, list(POLICY_MUTATION_ACTIONS))
                ),
            )
        )
    return DetectorResult(tuple(detections), probe.records())


def privesc_lambda_passrole(target: PolicyTarget) -> DetectorResult:
    """``lambda:CreateFunction`` and ``iam:PassRole`` in one policy document.

    Requirement 6 AC5. Document-scoped, because the pair is dangerous however it
    is split across statements: the holder ends up with both permissions either
    way. Reported at the statement granting ``lambda:CreateFunction``, with the
    location of the ``iam:PassRole`` grant in Evidence.
    """
    probe = _Probe(target)
    create = _first_granting(probe, target, LAMBDA_CREATE_FUNCTION_ACTION)
    pass_role = _first_granting(probe, target, PASS_ROLE_ACTION)
    if create is None or pass_role is None:
        return DetectorResult((), probe.records())
    return DetectorResult(
        (
            _detect(
                target,
                create,
                _PRIVESC_LAMBDA_PASSROLE,
                finding=(
                    "This policy document allows both lambda:CreateFunction "
                    "and iam:PassRole, which together let the holder run code "
                    "as another role."
                ),
                detail=(
                    "lambda:CreateFunction is allowed at {0} and iam:PassRole "
                    "is allowed at {1}.".format(create.json_path, pass_role.json_path)
                ),
            ),
        ),
        probe.records(),
    )


def privesc_broad_trust(target: PolicyTarget) -> DetectorResult:
    """A trust policy admitting ``"*"``, or a service principal with no Condition.

    Requirement 6 AC5. Two Severities, as design.md's table specifies:
    ``Principal: "*"`` is CRITICAL because any AWS principal can assume the
    role, while an unconditioned service principal is HIGH -- the service is
    named, but nothing says which of its resources may act.
    """
    if target.kind is not PolicyKind.TRUST_POLICY:
        return DetectorResult()

    probe = _Probe(target)
    detections: List[Detection] = []
    for view in target.policy_statements:
        if not probe.allows(view):
            continue
        if not probe.match(view, ValueKind.ACTION, _GRANTS_ASSUME_ROLE).matched:
            continue
        conditioned = _has_condition(view.statement)
        for principal in probe.principals(view):
            if principal.classification is PrincipalClass.STAR:
                detections.append(
                    _detect(
                        target,
                        view,
                        _PRIVESC_BROAD_TRUST,
                        severity="CRITICAL",
                        finding=(
                            "This trust policy allows sts:AssumeRole from "
                            "Principal \"*\", so any AWS principal can assume "
                            "this role."
                        ),
                        detail=(
                            "The trust policy allows sts:AssumeRole and its "
                            "Principal is \"*\"."
                        ),
                    )
                )
            elif principal.classification is PrincipalClass.SERVICE and not conditioned:
                detections.append(
                    _detect(
                        target,
                        view,
                        _PRIVESC_BROAD_TRUST,
                        finding=(
                            "This trust policy allows sts:AssumeRole from the "
                            "service principal \"{0}\" with no Condition "
                            "bounding which of that service's resources may "
                            "assume it.".format(principal.value)
                        ),
                        detail=(
                            "The trust policy allows sts:AssumeRole for the "
                            "service principal \"{0}\" under {1} and carries "
                            "no Condition key.".format(principal.value, principal.label)
                        ),
                    )
                )
    return DetectorResult(tuple(detections), probe.records())


# ---------------------------------------------------------------------------
# Detectors: principals (Requirement 6 AC6, AC7, AC9)
# ---------------------------------------------------------------------------


def cross_service_missing_condition(target: PolicyTarget) -> DetectorResult:
    """A cross-service or cross-account grant with no scoping condition.

    Requirement 6 AC6: none of ``aws:SourceAccount``, ``aws:SourceArn`` or
    ``aws:PrincipalOrgID`` present. Reads
    :attr:`PolicyTarget.statements`, so an ``AWS::Lambda::Permission`` is
    covered through its ``SourceAccount`` / ``SourceArn`` / ``PrincipalOrgID``
    properties.
    """
    probe = _Probe(target)
    detections: List[Detection] = []
    for view in target.statements:
        if not probe.allows(view):
            continue
        if _condition_keys(view.statement) & CONFUSED_DEPUTY_CONDITION_KEYS:
            continue
        for principal in probe.principals(view):
            if principal.classification not in (
                PrincipalClass.SERVICE,
                PrincipalClass.CROSS_ACCOUNT,
            ):
                continue
            detections.append(
                _detect(
                    target,
                    view,
                    _CROSS_SERVICE_MISSING_CONDITION,
                    finding=(
                        "This statement grants access to the {0} principal "
                        "\"{1}\" without an aws:SourceAccount, aws:SourceArn "
                        "or aws:PrincipalOrgID condition.".format(
                            principal.classification.value.replace("_", "-"),
                            principal.value,
                        )
                    ),
                    detail=(
                        "Principal \"{0}\" under {1} is {2} and none of {3} is "
                        "present in this statement.".format(
                            principal.value,
                            principal.label,
                            principal.classification.value,
                            sorted(CONFUSED_DEPUTY_CONDITION_KEYS),
                        )
                    ),
                )
            )
    return DetectorResult(tuple(detections), probe.records())


def cross_account_principal(target: PolicyTarget) -> DetectorResult:
    """A Principal naming a literal 12-digit account, alone or inside an ARN.

    Requirement 6 AC7. The ``AWS::AccountId`` pseudo parameter is same-account
    in every spelling and never reaches here (Requirement 6 AC8), and a Principal
    that cannot be resolved is disclosed rather than reported as cross-account.

    This detector's Findings are the only ones
    :func:`apply_external_id_mitigation` acts on (Requirement 6 AC10).
    """
    probe = _Probe(target)
    detections: List[Detection] = []
    for view in target.statements:
        if not probe.allows(view):
            continue
        for principal in probe.principals(view):
            if principal.classification is not PrincipalClass.CROSS_ACCOUNT:
                continue
            detections.append(
                _detect(
                    target,
                    view,
                    _CROSS_ACCOUNT_PRINCIPAL,
                    finding=(
                        "This statement grants access to \"{0}\", which names "
                        "an AWS account other than the one this stack is "
                        "deployed into.".format(principal.value)
                    ),
                    detail=(
                        "Principal \"{0}\" under {1} contains a literal 12-digit "
                        "AWS account ID.".format(principal.value, principal.label)
                    ),
                )
            )
    return DetectorResult(tuple(detections), probe.records())


def principal_star(target: PolicyTarget) -> DetectorResult:
    """A Principal of ``"*"`` or ``{"AWS": "*"}``.

    Requirement 6 AC9. ``Effect: Allow`` only, which matters more here than
    anywhere else: ``Effect: Deny`` with ``Principal: "*"`` is the standard
    shape of a bucket policy denying unencrypted transport, and reporting that
    as a CRITICAL grant would flag the correct pattern.
    """
    probe = _Probe(target)
    detections: List[Detection] = []
    for view in target.statements:
        if not probe.allows(view):
            continue
        for principal in probe.principals(view):
            if principal.classification is not PrincipalClass.STAR:
                continue
            detections.append(
                _detect(
                    target,
                    view,
                    _PRINCIPAL_STAR,
                    finding=(
                        "Principal is \"*\", so this statement grants its "
                        "actions to every AWS principal."
                    ),
                    detail=(
                        "Principal under {0} is the wildcard value, which "
                        "admits every principal.".format(principal.label)
                    ),
                )
            )
    return DetectorResult(tuple(detections), probe.records())


# ---------------------------------------------------------------------------
# Detectors: dangerous combinations (Requirement 6 AC11)
# ---------------------------------------------------------------------------


def dangerous_s3_combo(target: PolicyTarget) -> DetectorResult:
    """``s3:GetObject`` + ``s3:PutObject`` + ``s3:DeleteObject`` on ``"*"``.

    Requirement 6 AC11. Each action is looked for among the allowed statements
    whose ``Resource`` includes ``"*"``, so the combination is found whether it
    is written in one statement or spread across three.
    """
    probe = _Probe(target)
    unrestricted = [
        view
        for view in target.policy_statements
        if probe.allows(view) and probe.match(view, ValueKind.RESOURCE, _is_star).matched
    ]
    located = [
        _first_granting(probe, target, action, views=unrestricted)
        for action in S3_COMBO_ACTIONS
    ]
    if any(view is None for view in located):
        return DetectorResult((), probe.records())

    views = [view for view in located if view is not None]
    return DetectorResult(
        (
            _detect(
                target,
                views[0],
                _DANGEROUS_S3_COMBO,
                finding=(
                    "This policy document allows s3:GetObject, s3:PutObject "
                    "and s3:DeleteObject on Resource \"*\", so every reachable "
                    "object can be read, replaced or deleted."
                ),
                detail=(
                    "The three actions {0} are all allowed on Resource \"*\", "
                    "at {1}.".format(
                        list(S3_COMBO_ACTIONS),
                        sorted({view.json_path for view in views}),
                    )
                ),
            ),
        ),
        probe.records(),
    )


def dangerous_ec2_passrole(target: PolicyTarget) -> DetectorResult:
    """``ec2:RunInstances`` and ``iam:PassRole`` in one policy document.

    Requirement 6 AC11.
    """
    probe = _Probe(target)
    run_instances = _first_granting(probe, target, EC2_RUN_INSTANCES_ACTION)
    pass_role = _first_granting(probe, target, PASS_ROLE_ACTION)
    if run_instances is None or pass_role is None:
        return DetectorResult((), probe.records())
    return DetectorResult(
        (
            _detect(
                target,
                run_instances,
                _DANGEROUS_EC2_PASSROLE,
                finding=(
                    "This policy document allows both ec2:RunInstances and "
                    "iam:PassRole, which together let the holder obtain "
                    "another role's credentials from instance metadata."
                ),
                detail=(
                    "ec2:RunInstances is allowed at {0} and iam:PassRole is "
                    "allowed at {1}.".format(
                        run_instances.json_path, pass_role.json_path
                    )
                ),
            ),
        ),
        probe.records(),
    )


def dangerous_lambda_combo(target: PolicyTarget) -> DetectorResult:
    """``lambda:UpdateFunctionCode`` and ``lambda:InvokeFunction`` together.

    Requirement 6 AC11.
    """
    probe = _Probe(target)
    update = _first_granting(probe, target, LAMBDA_UPDATE_CODE_ACTION)
    invoke = _first_granting(probe, target, LAMBDA_INVOKE_ACTION)
    if update is None or invoke is None:
        return DetectorResult((), probe.records())
    return DetectorResult(
        (
            _detect(
                target,
                update,
                _DANGEROUS_LAMBDA_COMBO,
                finding=(
                    "This policy document allows both "
                    "lambda:UpdateFunctionCode and lambda:InvokeFunction, "
                    "which together let the holder execute arbitrary code as "
                    "the function's execution role."
                ),
                detail=(
                    "lambda:UpdateFunctionCode is allowed at {0} and "
                    "lambda:InvokeFunction is allowed at {1}.".format(
                        update.json_path, invoke.json_path
                    )
                ),
            ),
        ),
        probe.records(),
    )


def _first_granting(
    probe: _Probe,
    target: PolicyTarget,
    action: str,
    views: Optional[Sequence[StatementView]] = None,
) -> Optional[StatementView]:
    """First allowed statement granting ``action``, or ``None``.

    Shared by the four document-scoped detectors. ``views`` defaults to every
    policy statement of the target; the S3 combination passes a list already
    narrowed to the statements whose Resource is ``"*"``.
    """
    predicate = _grants_any((action,))
    for view in target.policy_statements if views is None else views:
        if not probe.allows(view):
            continue
        if probe.match(view, ValueKind.ACTION, predicate).matched:
            return view
    return None


# ---------------------------------------------------------------------------
# The empty case (Requirement 6 AC12)
# ---------------------------------------------------------------------------


def no_iam_resources(sites: Sequence[PolicySite]) -> bool:
    """Whether a Template offered nothing IAM-related to examine.

    The sixteenth row of design.md's table, and the only one that produces no
    Finding: a Finding requires a resource, and there is none to name. The IAM
    Source reports :data:`NO_IAM_RESOURCES_MESSAGE` instead, so a Template with
    no IAM at all is distinguishable from one that was reviewed and found clean.

    ``True`` also when the Template declares IAM resources whose properties hold
    no policy to look at, which is the same situation from a reviewer's point of
    view: nothing was checked, and saying so is the honest report.
    """
    return not sites


# ---------------------------------------------------------------------------
# Severity reduction (Requirement 6 AC10)
# ---------------------------------------------------------------------------


def apply_external_id_mitigation(finding: Finding, statement: Any) -> Finding:
    """Lower a cross-account Finding one level when ``sts:ExternalId`` is required.

    Requirement 6 AC10 and Property 27. A third party that must present a secret
    ``ExternalId`` cannot be used as a confused deputy by someone who does not
    know it, so the grant is genuinely narrower than a bare cross-account trust
    -- but it is still cross-account, which is why the Severity moves one step
    rather than disappearing.

    Args:
        finding: A Finding to reconsider. Returned unchanged unless it came from
            :func:`cross_account_principal`.
        statement: The statement the Finding was raised on. Only this
            statement's ``Condition`` block counts: AC10 says "in the same
            statement", and a condition on a different statement does not
            constrain this grant. Any shape is accepted.

    Returns:
        A new Finding one Severity level lower, with an Evidence entry recording
        the mitigating condition, or ``finding`` itself when nothing applies.
        Never mutates the input.

    The restriction to ``cross_account_principal`` is enforced here rather than
    only at the call site. :func:`principal_star` is deliberately excluded: an
    ``ExternalId`` on ``Principal: "*"`` still admits anyone who learns the
    ExternalId, so the grant is not narrowed to a party the account owner chose,
    and its CRITICAL stands. design.md assigns this judgement a home in
    ``docs/security-model.md``, which a later task writes.
    """
    if not _is_cross_account_finding(finding):
        return finding
    if not _has_external_id_condition(statement):
        return finding
    return replace(
        finding,
        Severity=lower_one_level(finding.Severity),
        Evidence=list(finding.Evidence)
        + [
            Evidence(
                Source=SOURCE_NAME,
                Detail=EXTERNAL_ID_MITIGATION_DETAIL,
                RuleId=_CROSS_ACCOUNT_PRINCIPAL.name,
                Excerpt=None,
            )
        ],
    )


def _is_cross_account_finding(finding: Finding) -> bool:
    """Whether ``finding`` came from :func:`cross_account_principal`.

    Read from ``Evidence[].RuleId``, which is where each detector records its
    identity, so the check does not depend on the Finding's wording.
    """
    if not isinstance(finding, Finding):
        return False
    return any(
        entry.RuleId == _CROSS_ACCOUNT_PRINCIPAL.name
        for entry in finding.Evidence
        if isinstance(entry, Evidence)
    )


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

#: The fifteen detectors, in design.md's table order. The order fixes the order
#: Findings appear in within one site, which keeps output byte-stable
#: (Requirement 16 AC11); it has no effect on *which* Findings appear, because
#: the detectors are independent.
DETECTORS: Tuple[Detector, ...] = (
    star_action_star_resource,
    wildcard_action,
    wildcard_resource,
    sensitive_prefix_without_condition,
    passrole_unrestricted,
    assumerole_unrestricted,
    privesc_policy_mutation,
    privesc_lambda_passrole,
    privesc_broad_trust,
    cross_service_missing_condition,
    cross_account_principal,
    principal_star,
    dangerous_s3_combo,
    dangerous_ec2_passrole,
    dangerous_lambda_combo,
)


@dataclass(frozen=True)
class ScanResult:
    """Everything a deterministic IAM scan produced.

    Attributes:
        findings: ``Confirmed`` Security Findings, with the ExternalId reduction
            already applied. In site order, and within a site in
            :data:`DETECTORS` order. Carry
            :data:`~iacreview.finding.UNASSIGNED_ID`, like every Source's
            output.
        unresolved: Deduplicated locations no detector could evaluate. The IAM
            Source turns each into the ``Informational`` / ``INFO`` /
            ``Confirmed`` disclosure design.md specifies, so a gap in coverage
            appears in the report rather than reading as clean.
    """

    findings: List[Finding]
    unresolved: List[UnresolvedValue]


def scan_target(target: PolicyTarget) -> ScanResult:
    """Run all fifteen detectors over one prepared target.

    The ExternalId reduction is applied here, as each Finding is collected: that
    is the normalizer stage, before deduplication merges Findings and their
    Severities, so a reduced Severity is what the merge sees.
    """
    findings: List[Finding] = []
    unresolved: List[UnresolvedValue] = []
    for detector in DETECTORS:
        result = detector(target)
        for detection in result.detections:
            findings.append(
                apply_external_id_mitigation(detection.finding, detection.statement)
            )
        unresolved.extend(result.unresolved)
    return ScanResult(findings=findings, unresolved=dedupe_unresolved(unresolved))


def scan_sites(
    sites: Sequence[PolicySite],
    *,
    template_file: str,
    context: Optional[ResolutionContext] = None,
) -> ScanResult:
    """Run the deterministic IAM scan over every located site.

    Args:
        sites: Output of :func:`iacreview.iam.locate.find_policy_documents`.
        template_file: Workspace-relative path of the reviewed Template, used as
            ``Location.File``. Never an absolute host path: the report has to be
            byte-identical across machines (Requirement 16 AC11).
        context: Template-level facts from
            :meth:`iacreview.iam.intrinsics.ResolutionContext.from_template`.
            Omitting it resolves literals and pseudo parameters only, which
            yields more unresolvable disclosures and never a wrong Finding.

    Returns:
        A :class:`ScanResult`. An empty ``sites`` yields empty lists -- the
        ``no_iam_resources`` path of Requirement 6 AC12, where the IAM Source
        reports :data:`NO_IAM_RESOURCES_MESSAGE` instead of a Finding.

    Never raises on Template content: every value is treated as untrusted, and a
    shape no detector can read contributes fewer Findings or an unresolvable
    record.
    """
    resolution = context if context is not None else ResolutionContext()
    findings: List[Finding] = []
    unresolved: List[UnresolvedValue] = []
    for site in sites:
        result = scan_target(
            PolicyTarget.from_site(
                site, template_file=template_file, context=resolution
            )
        )
        findings.extend(result.findings)
        unresolved.extend(result.unresolved)
    return ScanResult(findings=findings, unresolved=dedupe_unresolved(unresolved))


def scan(
    sites: Sequence[PolicySite],
    *,
    template_file: str,
    context: Optional[ResolutionContext] = None,
) -> List[Finding]:
    """The Findings of a deterministic IAM scan (design.md's ``detectors.scan``).

    A thin view over :func:`scan_sites` for callers that do not need the
    unresolvable locations. The IAM Source uses :func:`scan_sites`, because
    disclosing those locations is part of its contract.
    """
    return scan_sites(sites, template_file=template_file, context=context).findings
