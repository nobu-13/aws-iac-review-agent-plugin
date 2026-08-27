"""What a Template value says -- and an honest answer when that cannot be known.

An IAM detector wants to ask simple questions: is this ``Resource`` a ``"*"``,
does this ``Principal`` name another account. A CloudFormation Template does not
always contain the answer. ``Ref``, ``Fn::Sub``, ``Fn::GetAtt``, ``Fn::If`` and
``Fn::ImportValue`` all stand in for values that only exist once the stack is
deployed, and **static analysis cannot resolve them in principle**. This module
is where that gap is handled, once, so that
:mod:`iacreview.iam.detectors` contains pattern matching and nothing else.

Two public entry points, matching the two things design.md specifies.

:func:`classify_principal`
    The Principal classifier of design.md's *Cross-account 判定ロジック*, with
    the five outcomes of :class:`PrincipalClass` (Requirement 6 AC7-AC9).

:func:`evaluate`
    A detector's string predicate applied to a value through the resolution
    policy of design.md's *解決不能な intrinsic function の扱い* table, returning
    one of the three :class:`Verdict` values. Its seven rows map onto code as:

    ======================================  =========================================
    Situation                               Where it is implemented
    ======================================  =========================================
    literal value                           :func:`_resolve_scalar`, exact candidate
    ``AWS::AccountId``                      :func:`classify_principal`, and
                                            :data:`PSEUDO_PARAMETERS` in
                                            :func:`_resolve_ref` /
                                            :func:`_resolve_sub`
    ``Ref`` to a parameter, ``Default``     :func:`_resolve_ref` -> ``unresolved``
    only, no ``AllowedValues``              (the Default is deliberately not used)
    ``Ref`` to a parameter with             :func:`_resolve_ref` -> a group with
    ``AllowedValues``                       ``all_required=True``
    ``Fn::Sub``                             :func:`_resolve_sub`, fixed parts as a
                                            candidate plus a blocker
    ``Fn::GetAtt`` / ``Fn::ImportValue``    :func:`_resolve_mapping` -> ``unresolved``
    ``Fn::If``                              :func:`expand_conditionals`, both
                                            branches evaluated independently
    ======================================  =========================================

The design decisions those rows encode, and why they are not negotiable:

a ``Default`` is not an answer
    ``{"Ref": "BucketName"}`` where ``BucketName`` has ``Default: my-bucket``
    looks resolvable and is not: every deploy may override it. Judging the
    Default would produce findings about a value that never exists in the
    account being reviewed, so the location is reported as unresolvable instead.
    ``AllowedValues`` *is* an answer, because the deployer cannot leave the set:
    when every allowed value is dangerous the finding is certain, and when only
    some are, the outcome depends on a deploy-time choice and is unresolvable.

``Fn::If`` is not a choice this module makes
    Both branches are evaluated independently and a match in either one counts,
    with :attr:`Candidate.branch` recording which. The condition is decided at
    deploy time; reporting only one branch would hide a real grant.

unresolvable is a result, never a silence
    Every path that cannot decide produces an :class:`Unresolved` reason, which
    :func:`unresolved_values` turns into a located record carrying the exact
    ``Informational`` / ``INFO`` / ``Confirmed`` Finding text design.md
    prescribes. A location skipped by the deterministic checks is disclosed as a
    coverage gap rather than counted as clean. That Finding is factual -- "this
    could not be evaluated" is itself deterministic -- so it asserts no
    vulnerability, which is what steering/security.md requires.

Nothing here evaluates a Template value in any executable sense: substitution
variables are left standing as ``${Name}`` text, no string is interpolated, no
Default is substituted, and every input is treated as untrusted. A value of the
wrong type, a malformed intrinsic, or nesting past :data:`MAX_NESTING_DEPTH`
yields an :class:`Unresolved` reason rather than an exception.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import (
    AbstractSet,
    Any,
    Callable,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Optional,
    Sequence,
    Tuple,
    Union,
)

from iacreview.iam.locate import PathSegment

__all__ = [
    "PrincipalClass",
    "Verdict",
    "ValueKind",
    "Branch",
    "Candidate",
    "CandidateGroup",
    "Unresolved",
    "Resolution",
    "Evaluation",
    "ResolutionContext",
    "UnresolvedValue",
    "REF",
    "FN_SUB",
    "FN_GETATT",
    "FN_IMPORT_VALUE",
    "FN_IF",
    "PARAMETERS_KEY",
    "ALLOWED_VALUES_KEY",
    "DEFAULT_KEY",
    "PSEUDO_PARAMETERS",
    "ACCOUNT_ID_PSEUDO_PARAMETER",
    "ACCOUNT_ID_SUBSTITUTION",
    "NO_VALUE_PSEUDO_PARAMETER",
    "SERVICE_PRINCIPAL_SUFFIX",
    "MAX_NESTING_DEPTH",
    "UNRESOLVABLE_RULE_ID",
    "UNRESOLVABLE_WHY_IT_MATTERS",
    "UNRESOLVABLE_RECOMMENDATION",
    "classify_principal",
    "expand_conditionals",
    "resolve",
    "evaluate",
    "verdict_for",
    "unresolved_values",
    "dedupe_unresolved",
]


# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------

REF = "Ref"
FN_SUB = "Fn::Sub"
FN_GETATT = "Fn::GetAtt"
FN_IMPORT_VALUE = "Fn::ImportValue"
FN_IF = "Fn::If"

#: Prefix shared by every intrinsic function except ``Ref``. Any mapping key
#: with this prefix that this module does not resolve is still *recognised* as an
#: intrinsic, so an unknown or future function becomes an unresolvable value
#: rather than an ignored one.
_FUNCTION_PREFIX = "Fn::"

ACCOUNT_ID_PSEUDO_PARAMETER = "AWS::AccountId"

#: The ``Fn::Sub`` spelling of :data:`ACCOUNT_ID_PSEUDO_PARAMETER`.
ACCOUNT_ID_SUBSTITUTION = "${" + ACCOUNT_ID_PSEUDO_PARAMETER + "}"

#: ``Ref`` to this pseudo parameter removes the value, so there is nothing to
#: analyse and nothing unresolved either.
NO_VALUE_PSEUDO_PARAMETER = "AWS::NoValue"

#: Every pseudo parameter. Their values are supplied by CloudFormation from the
#: deployment itself (account, region, partition, stack identity), so none of
#: them can carry a wildcard or an attacker-chosen string. A negative verdict on
#: a value containing only pseudo parameters is therefore deterministic, which is
#: why they are candidates rather than blockers.
PSEUDO_PARAMETERS: FrozenSet[str] = frozenset(
    {
        ACCOUNT_ID_PSEUDO_PARAMETER,
        NO_VALUE_PSEUDO_PARAMETER,
        "AWS::NotificationARNs",
        "AWS::Partition",
        "AWS::Region",
        "AWS::StackId",
        "AWS::StackName",
        "AWS::URLSuffix",
    }
)

#: Suffix of an AWS service Principal, for example ``lambda.amazonaws.com``.
SERVICE_PRINCIPAL_SUFFIX = ".amazonaws.com"

PARAMETERS_KEY = "Parameters"
ALLOWED_VALUES_KEY = "AllowedValues"
DEFAULT_KEY = "Default"

#: How deep a value is walked before it is declared unresolvable. Untrusted
#: input may be nested arbitrarily; a limit keeps the traversal from raising
#: ``RecursionError`` on a Template built to do exactly that. No legitimate
#: Action / Resource / Principal value comes close to it.
MAX_NESTING_DEPTH = 24

#: ``RuleId`` and Finding prefix of the unresolvable-value disclosure.
UNRESOLVABLE_RULE_ID = "unresolvable_value"

#: ``WhyItMatters`` of that Finding, verbatim from design.md so the wording is
#: written once and Task 13.4 does not paraphrase it.
UNRESOLVABLE_WHY_IT_MATTERS = (
    "A value that cannot be resolved at review time may grant broader access "
    "than intended once the stack is deployed. This location was skipped by "
    "the deterministic IAM checks, so it is not covered by the Confirmed "
    "findings in this report."
)

#: ``Recommendation`` used unless :data:`_RECOMMENDATIONS` has a better one.
UNRESOLVABLE_RECOMMENDATION = (
    "Review this value manually, or replace the unresolved reference with a "
    "literal value or an explicit resource reference so that it can be "
    "evaluated statically."
)

#: Per-intrinsic ``Recommendation`` overrides, where a concrete remedy exists.
_RECOMMENDATIONS: Dict[str, str] = {
    FN_IMPORT_VALUE: (
        "Review this value manually, or replace the cross-stack import with an "
        "explicit resource reference so that it can be evaluated statically."
    ),
}

_ACCOUNT_ID = re.compile(r"^\d{12}$")
_ARN_ACCOUNT = re.compile(r"^arn:[^:]*:[^:]*:[^:]*:(\d{12}):")

#: One ``${...}`` substitution in an ``Fn::Sub`` template string. Inner braces
#: are excluded so a malformed string cannot make the match run away.
_SUB_VARIABLE = re.compile(r"\$\{([^{}]*)\}")

#: Prefix marking a ``${!Literal}`` escape: not a substitution at all, but the
#: literal text ``${Literal}``.
_SUB_ESCAPE = "!"

#: Phrases used where the unresolvable value is not an intrinsic function. They
#: sit in the same field as ``"Fn::ImportValue"`` and read as the subject of
#: "is produced by ..." in the Finding text.
_UNSUPPORTED_MAPPING = "a mapping that is not a supported intrinsic function"
_TOO_DEEP = "a value nested more deeply than the review limit"


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class PrincipalClass(str, Enum):
    """What a Principal value turned out to be.

    A ``str`` mixin for the same reason as
    :class:`iacreview.iam.locate.PolicyKind`: the value serializes into the
    Layer 2 JSON without a conversion table. Format with ``.value``.

    Members:
        STAR: ``"*"`` or ``{"AWS": "*"}`` -- anyone (Requirement 6 AC9).
        SAME_ACCOUNT: The account the stack is deployed into, named through the
            ``AWS::AccountId`` pseudo parameter (Requirement 6 AC8). Never
            cross-account, however it is spelled.
        CROSS_ACCOUNT: A literal 12-digit account ID, alone or embedded in an
            ARN, that is not the deploying account (Requirement 6 AC7).
        SERVICE: An AWS service Principal such as ``lambda.amazonaws.com``.
        UNRESOLVABLE: The value is not determined by the Template. Reported as
            an ``Informational`` Finding, never as a cross-account grant: a
            value that might name another account is not evidence that it does.
    """

    STAR = "star"
    SAME_ACCOUNT = "same_account"
    CROSS_ACCOUNT = "cross_account"
    SERVICE = "service"
    UNRESOLVABLE = "unresolvable"


class Verdict(str, Enum):
    """The outcome of applying a detector's predicate to a Template value.

    Members:
        MATCH: The predicate holds for the value as the Template defines it.
            Deterministic, so a Finding built on it carries
            ``Confidence: "Confirmed"``.
        NO_MATCH: The predicate does not hold, and no part of the value was left
            unexamined. Deterministically negative -- no Finding, no disclosure.
        UNRESOLVABLE: The predicate could not be decided because the value
            depends on deploy time. Not a match and not a clean result: the
            location is disclosed through :func:`unresolved_values`.
    """

    MATCH = "match"
    NO_MATCH = "no_match"
    UNRESOLVABLE = "unresolvable"


class ValueKind(str, Enum):
    """Which statement element a value came from.

    Names the unresolvable location in prose ("The Resource value at this
    location ..."), so the reader does not have to decode a ``TemplatePath``.
    Members are the IAM policy spellings, which is what a reviewer greps for.
    """

    ACTION = "Action"
    NOT_ACTION = "NotAction"
    RESOURCE = "Resource"
    NOT_RESOURCE = "NotResource"
    PRINCIPAL = "Principal"
    NOT_PRINCIPAL = "NotPrincipal"
    CONDITION = "Condition"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Branch:
    """One independently evaluated alternative of a value.

    Attributes:
        value: The value with its enclosing ``Fn::If`` removed.
        label: Which branches were taken to reach it, for example
            ``"Fn::If[IsProd] true branch"``, or ``None`` when the value was not
            inside any ``Fn::If``. Recorded in Evidence so a Finding says which
            deploy-time alternative is dangerous.
    """

    value: Any
    label: Optional[str] = None


@dataclass(frozen=True)
class Candidate:
    """One concrete string a value can take, as far as the Template says.

    Attributes:
        text: The string a predicate is applied to. For a literal this is the
            value itself. For ``Fn::Sub`` the substitutions are left standing as
            ``${Name}``: matching then sees the fixed parts and nothing
            fabricated, because a substitution variable's name cannot contain a
            wildcard.
        origin: Short provenance phrase for Evidence, for example
            ``"AllowedValues[1] of parameter 'Stage'"``.
        branch: :attr:`Branch.label` of the ``Fn::If`` alternative this came
            from, or ``None``.
    """

    text: str
    origin: str
    branch: Optional[str] = None


@dataclass(frozen=True)
class Unresolved:
    """A reason some part of a value could not be decided.

    Attributes:
        intrinsic: What stood in the way, named as it appears in the Template
            (``"Fn::ImportValue"``, ``"Ref"``) or as a phrase for the cases that
            are not intrinsic functions. Part of the deduplication key.
        detail: Complete sentence for ``Evidence[].Detail``, naming the
            parameter or the variables involved so the reader can act on it
            without opening the Template.
        branch: :attr:`Branch.label` this reason applies to, or ``None``.
    """

    intrinsic: str
    detail: str
    branch: Optional[str] = None


@dataclass(frozen=True)
class CandidateGroup:
    """Candidates that must be judged together, plus why they may not settle it.

    Attributes:
        candidates: Non-empty. Alternatives for one place in the value.
        all_required: ``False`` -- the ordinary case -- means a match on any
            candidate decides the group, which is how a list of Resources or the
            branches of an ``Fn::If`` behave. ``True`` means every candidate
            must match, which is the ``AllowedValues`` rule: certain only when
            no allowed choice escapes the pattern.
        blocker: The reason to report when the candidates do not settle the
            question: a ``Fn::Sub`` whose variables were not examined, or an
            ``AllowedValues`` set where only some values match. ``None`` when
            the candidates are exhaustive, and a non-match is then final.
    """

    candidates: Tuple[Candidate, ...]
    all_required: bool = False
    blocker: Optional[Unresolved] = None


@dataclass(frozen=True)
class Resolution:
    """Everything the Template says about one value, before any predicate.

    Attributes:
        groups: Candidate groups, in Template order. Independent of each other:
            a match in any one of them is a match for the value.
        unresolved: Reasons that hold whatever the predicate is, because no
            candidate could be derived at all (``Fn::GetAtt``,
            ``Fn::ImportValue``, a ``Ref`` whose value is a deploy-time choice).

    An empty resolution -- no groups, no reasons -- means the value contributes
    nothing to analyse, as with ``{"Ref": "AWS::NoValue"}``.
    """

    groups: Tuple[CandidateGroup, ...] = ()
    unresolved: Tuple[Unresolved, ...] = ()

    @property
    def candidates(self) -> Tuple[Candidate, ...]:
        """Every candidate, flattened, for inspection and for Evidence."""
        return tuple(
            candidate for group in self.groups for candidate in group.candidates
        )

    @property
    def is_fully_resolved(self) -> bool:
        """Whether the Template determines this value completely.

        ``True`` when no part of the value depends on deploy time, so both a
        match and a non-match are deterministic.
        """
        return not self.unresolved and all(
            group.blocker is None for group in self.groups
        )


@dataclass(frozen=True)
class Evaluation:
    """A :class:`Verdict` together with the evidence for it.

    Attributes:
        verdict: The decision.
        resolution: What the value was resolved to, kept so a detector can cite
            candidates without resolving twice.
        matched: The candidates the predicate matched, in resolution order.
            Their :attr:`Candidate.branch` and :attr:`Candidate.origin` are what
            an ``Fn::If`` or ``AllowedValues`` Finding cites as Evidence.
        blockers: The reasons parts of the value were not decided. Populated
            whenever such reasons exist, including alongside
            :attr:`Verdict.MATCH` when one alternative matched and another could
            not be read. :func:`unresolved_values` reports them only for
            :attr:`Verdict.UNRESOLVABLE`, where the location genuinely went
            unchecked.
    """

    verdict: Verdict
    resolution: Resolution
    matched: Tuple[Candidate, ...] = ()
    blockers: Tuple[Unresolved, ...] = ()


@dataclass(frozen=True)
class ResolutionContext:
    """The Template-level facts resolution needs.

    Attributes:
        parameters: The Template's ``Parameters`` section, used only to read
            ``AllowedValues`` and to tell a declared parameter from a resource
            reference when explaining why a ``Ref`` is unresolvable. A
            ``Default`` is never substituted.

    Optional throughout: with no context every ``Ref`` to something other than a
    pseudo parameter is unresolvable, which is the conservative answer and never
    a wrong one.
    """

    parameters: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_template(cls, doc: Any) -> "ResolutionContext":
        """Build a context from a parsed Template, accepting any shape.

        Args:
            doc: Normally :attr:`iacreview.template.LoadedTemplate.doc`.
                Untrusted; a missing or non-mapping ``Parameters`` section yields
                an empty context rather than an error.
        """
        if not isinstance(doc, dict):
            return cls()
        parameters = doc.get(PARAMETERS_KEY)
        if not isinstance(parameters, dict):
            return cls()
        return cls(
            parameters={
                name: value
                for name, value in parameters.items()
                if isinstance(name, str)
            }
        )


@dataclass(frozen=True)
class UnresolvedValue:
    """A located coverage gap, ready to become an ``Informational`` Finding.

    Task 13.4 maps one of these onto the Finding design.md specifies:
    ``FindingType: "Informational"``, ``Severity: "INFO"``,
    ``Confidence: "Confirmed"``, ``Source: ["IAM Review"]``, ``RuleId``
    :data:`UNRESOLVABLE_RULE_ID`. The wording lives here, next to the logic that
    decided the value was unresolvable, so the two cannot drift.

    Attributes:
        logical_id: Logical ID of the resource holding the value; the Finding's
            ``Resource``.
        template_path: Path to the value; the Finding's
            ``Location.TemplatePath``.
        value_kind: Which statement element it is, from :class:`ValueKind`.
        intrinsic: What could not be resolved.
        detail: ``Evidence[].Detail``.
        branch: ``Fn::If`` branch label, or ``None``.
    """

    logical_id: str
    template_path: Tuple[PathSegment, ...]
    value_kind: str
    intrinsic: str
    detail: str
    branch: Optional[str] = None

    @property
    def json_path(self) -> str:
        """Dotted path, spelled as :attr:`iacreview.iam.locate.PolicySite.json_path`."""
        return ".".join(str(segment) for segment in self.template_path)

    @property
    def rule_id(self) -> str:
        """``Evidence[].RuleId`` of this disclosure."""
        return UNRESOLVABLE_RULE_ID

    @property
    def finding_text(self) -> str:
        """The Finding's ``Finding`` field, prefixed with the rule ID."""
        return (
            "[{0}] The {1} value at this location{2} is produced by {3} and "
            "cannot be evaluated statically, so IAM checks were not applied "
            "to it."
        ).format(
            UNRESOLVABLE_RULE_ID,
            self.value_kind,
            "" if self.branch is None else " ({0})".format(self.branch),
            self.intrinsic,
        )

    @property
    def why_it_matters(self) -> str:
        """The Finding's ``WhyItMatters`` field."""
        return UNRESOLVABLE_WHY_IT_MATTERS

    @property
    def recommendation(self) -> str:
        """The Finding's ``Recommendation`` field."""
        return _RECOMMENDATIONS.get(self.intrinsic, UNRESOLVABLE_RECOMMENDATION)


# ---------------------------------------------------------------------------
# Principal classification (Requirement 6 AC7-AC9)
# ---------------------------------------------------------------------------


def classify_principal(
    value: Any, template_account_refs: Optional[AbstractSet[str]] = None
) -> PrincipalClass:
    """Classify one Principal value.

    Args:
        value: A single Principal value, already unwrapped from its Principal
            type key. A policy writes ``{"AWS": "123456789012"}`` or
            ``{"Service": ["a.amazonaws.com", "b.amazonaws.com"]}``; splitting
            that into individual values belongs to the caller, which knows
            whether it is looking at ``Principal`` or ``NotPrincipal``. The one
            exception is ``{"AWS": "*"}``, accepted whole because Requirement 6
            AC9 names that exact mapping. Untrusted: any type is accepted.
        template_account_refs: Account IDs the caller knows to be the deploying
            account. A literal account ID in this set is same-account rather
            than cross-account. Empty by default -- v0.1 has no way to learn the
            deploying account from a Template, so the default behaviour is
            exactly design.md's: every literal 12-digit ID is cross-account.

    Returns:
        One :class:`PrincipalClass`. Never raises; an unrecognised shape is
        :attr:`PrincipalClass.UNRESOLVABLE`, which is disclosed rather than
        treated as safe or as a violation.

    ``AWS::AccountId`` is same-account in every spelling (Requirement 6 AC8):
    ``{"Ref": "AWS::AccountId"}``, a bare string containing
    ``${AWS::AccountId}``, and an ``Fn::Sub`` whose only substitution is
    ``${AWS::AccountId}``. An ``Fn::Sub`` that also substitutes anything else is
    unresolvable, because that other variable could itself inject an account ID.
    """
    own_accounts = template_account_refs if template_account_refs is not None else frozenset()

    if value == "*" or value == {"AWS": "*"}:
        return PrincipalClass.STAR
    if isinstance(value, dict):
        if REF in value and value[REF] == ACCOUNT_ID_PSEUDO_PARAMETER:
            return PrincipalClass.SAME_ACCOUNT
        if FN_SUB in value:
            return _classify_sub(value[FN_SUB], own_accounts)
        if FN_GETATT in value or FN_IMPORT_VALUE in value:
            return PrincipalClass.UNRESOLVABLE
    if isinstance(value, str):
        return _classify_principal_string(value, own_accounts)
    return PrincipalClass.UNRESOLVABLE


def _classify_principal_string(
    text: str, own_accounts: AbstractSet[str]
) -> PrincipalClass:
    """Classify a Principal that is already a string."""
    if ACCOUNT_ID_SUBSTITUTION in text:
        return PrincipalClass.SAME_ACCOUNT
    account = _literal_account_id(text)
    if account is not None:
        if account in own_accounts:
            return PrincipalClass.SAME_ACCOUNT
        return PrincipalClass.CROSS_ACCOUNT
    if text.endswith(SERVICE_PRINCIPAL_SUFFIX):
        return PrincipalClass.SERVICE
    return PrincipalClass.UNRESOLVABLE


def _classify_sub(value: Any, own_accounts: AbstractSet[str]) -> PrincipalClass:
    """Classify an ``Fn::Sub`` Principal from its template string.

    Only the variable *names* are consulted. The two-element list form's
    variable map is not followed: a value supplied there may itself be an
    intrinsic, so a substitution other than ``${AWS::AccountId}`` stays
    unresolvable however it is defined.
    """
    text = _sub_template_string(value)
    if text is None:
        return PrincipalClass.UNRESOLVABLE
    variables = _substitution_variables(text)
    if any(name != ACCOUNT_ID_PSEUDO_PARAMETER for name in variables):
        return PrincipalClass.UNRESOLVABLE
    if ACCOUNT_ID_PSEUDO_PARAMETER in variables:
        return PrincipalClass.SAME_ACCOUNT
    return _classify_principal_string(_unescape_sub(text), own_accounts)


def _literal_account_id(text: str) -> Optional[str]:
    """Return the literal 12-digit account ID in ``text``, if there is one.

    Matches a bare account ID and an ARN embedding one (Requirement 6 AC7).
    """
    if _ACCOUNT_ID.match(text):
        return text
    match = _ARN_ACCOUNT.match(text)
    if match is not None:
        return match.group(1)
    return None


# ---------------------------------------------------------------------------
# Fn::If expansion
# ---------------------------------------------------------------------------


def expand_conditionals(value: Any) -> List[Branch]:
    """Split a value into the alternatives an ``Fn::If`` can produce.

    Args:
        value: Any Template value. Untrusted.

    Returns:
        One :class:`Branch` per alternative, in ``[true, false]`` order, with a
        label naming the conditions taken. A value containing no ``Fn::If`` is a
        single unlabelled branch, so callers need no special case.

    Nested ``Fn::If`` expands combinatorially, bounded by
    :data:`MAX_NESTING_DEPTH`: at the limit the value is returned unexpanded,
    and resolution then reports it as unresolvable rather than walking further.
    A malformed ``Fn::If`` -- not a three-element list, or a non-string condition
    name -- is likewise left unexpanded and reported, because guessing which
    element is a branch would invent a value the Template does not have.
    """
    branches: List[Branch] = []
    _expand_into(value, None, 0, branches)
    return branches


def _expand_into(
    value: Any, label: Optional[str], depth: int, out: List[Branch]
) -> None:
    condition = _conditional_parts(value)
    if condition is None or depth >= MAX_NESTING_DEPTH:
        out.append(Branch(value=value, label=label))
        return
    name, if_true, if_false = condition
    for branch_value, taken in ((if_true, "true"), (if_false, "false")):
        _expand_into(
            branch_value,
            _extend_label(label, "{0}[{1}] {2} branch".format(FN_IF, name, taken)),
            depth + 1,
            out,
        )


def _conditional_parts(value: Any) -> Optional[Tuple[str, Any, Any]]:
    """Return ``(condition_name, if_true, if_false)`` for a well-formed ``Fn::If``."""
    if not isinstance(value, dict) or FN_IF not in value:
        return None
    arguments = value[FN_IF]
    if not isinstance(arguments, list) or len(arguments) != 3:
        return None
    name = arguments[0]
    if not isinstance(name, str):
        return None
    return name, arguments[1], arguments[2]


def _extend_label(label: Optional[str], addition: str) -> str:
    if label is None:
        return addition
    return "{0} / {1}".format(label, addition)


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


def resolve(value: Any, context: Optional[ResolutionContext] = None) -> Resolution:
    """Enumerate what a Template value can be, without deciding anything.

    Args:
        value: An Action / Resource / Principal value, or a list of them, with
            intrinsics in long form as the parsers produce them. Untrusted.
        context: Template-level facts. Omit it to resolve nothing but literals
            and pseudo parameters.

    Returns:
        A :class:`Resolution`. Never raises: a value of an unexpected type
        contributes no candidate, and every intrinsic that cannot be read
        contributes a reason.

    A list is flattened, because ``Action`` and ``Resource`` accept one value or
    many and a detector asks the same question of each.
    """
    groups: List[CandidateGroup] = []
    unresolved: List[Unresolved] = []
    _resolve_into(
        value, None, 0, context or ResolutionContext(), groups, unresolved
    )
    return Resolution(groups=tuple(groups), unresolved=tuple(unresolved))


def _resolve_into(
    value: Any,
    label: Optional[str],
    depth: int,
    context: ResolutionContext,
    groups: List[CandidateGroup],
    unresolved: List[Unresolved],
) -> None:
    """Expand conditionals at this position, then resolve each alternative."""
    if depth >= MAX_NESTING_DEPTH:
        unresolved.append(
            Unresolved(
                intrinsic=_TOO_DEEP,
                detail=(
                    "Unresolved value: it is nested more than {0} levels deep, "
                    "beyond the review limit, so it was not evaluated.".format(
                        MAX_NESTING_DEPTH
                    )
                ),
                branch=label,
            )
        )
        return
    for branch in expand_conditionals(value):
        _resolve_branch(
            branch.value,
            _extend_label(label, branch.label) if branch.label else label,
            depth + 1,
            context,
            groups,
            unresolved,
        )


def _resolve_branch(
    value: Any,
    label: Optional[str],
    depth: int,
    context: ResolutionContext,
    groups: List[CandidateGroup],
    unresolved: List[Unresolved],
) -> None:
    if isinstance(value, str):
        _resolve_scalar(value, label, groups)
        return
    if isinstance(value, list):
        for element in value:
            _resolve_into(element, label, depth, context, groups, unresolved)
        return
    if isinstance(value, dict):
        _resolve_mapping(value, label, context, groups, unresolved)
        return
    # A number, a boolean or an empty value where IAM requires a string. There
    # is no string to match and nothing deploy-time about it, so it adds
    # neither a candidate nor a reason; whether the statement itself is
    # malformed is the detectors' judgement, not this module's.


def _resolve_scalar(
    value: str, label: Optional[str], groups: List[CandidateGroup]
) -> None:
    """A literal string: the first row of the table, evaluated as written."""
    groups.append(
        CandidateGroup(candidates=(Candidate(text=value, origin="literal", branch=label),))
    )


def _resolve_mapping(
    value: Dict[Any, Any],
    label: Optional[str],
    context: ResolutionContext,
    groups: List[CandidateGroup],
    unresolved: List[Unresolved],
) -> None:
    """Dispatch on the intrinsic function a mapping represents."""
    if REF in value:
        _resolve_ref(value[REF], label, context, groups, unresolved)
        return
    if FN_SUB in value:
        _resolve_sub(value[FN_SUB], label, groups, unresolved)
        return
    function = _function_key(value)
    if function is not None:
        # Fn::GetAtt and Fn::ImportValue by name in the table, and every other
        # function -- including an Fn::If too malformed to expand, and functions
        # this version does not know -- by the same rule, so an unreadable value
        # is never silently dropped.
        unresolved.append(
            Unresolved(
                intrinsic=function,
                detail="Unresolved intrinsic function: {0}.".format(function),
                branch=label,
            )
        )
        return
    unresolved.append(
        Unresolved(
            intrinsic=_UNSUPPORTED_MAPPING,
            detail=(
                "Unresolved value: a mapping was found where a string was "
                "expected, and it is not an intrinsic function this review "
                "resolves."
            ),
            branch=label,
        )
    )


def _function_key(value: Dict[Any, Any]) -> Optional[str]:
    """Return the first ``Fn::*`` key of a mapping, in Template order."""
    for key in value:
        if isinstance(key, str) and key.startswith(_FUNCTION_PREFIX):
            return key
    return None


def _resolve_ref(
    name: Any,
    label: Optional[str],
    context: ResolutionContext,
    groups: List[CandidateGroup],
    unresolved: List[Unresolved],
) -> None:
    """Resolve a ``Ref``: rows two, three and four of the table."""
    if not isinstance(name, str):
        unresolved.append(
            Unresolved(
                intrinsic=REF,
                detail="Unresolved intrinsic function: Ref with a non-string name.",
                branch=label,
            )
        )
        return

    if name == NO_VALUE_PSEUDO_PARAMETER:
        # The value is removed from the Template, so there is nothing here at
        # all -- neither something to match nor something left unexamined.
        return

    if name in PSEUDO_PARAMETERS:
        groups.append(
            CandidateGroup(
                candidates=(
                    Candidate(
                        text="${" + name + "}",
                        origin="Ref to pseudo parameter {0}".format(name),
                        branch=label,
                    ),
                )
            )
        )
        return

    allowed = _allowed_values(context, name)
    if allowed is not None:
        _resolve_allowed_values(name, allowed, label, groups, unresolved)
        return

    unresolved.append(
        Unresolved(intrinsic=REF, detail=_ref_detail(name, context), branch=label)
    )


def _resolve_allowed_values(
    name: str,
    allowed: Sequence[Any],
    label: Optional[str],
    groups: List[CandidateGroup],
    unresolved: List[Unresolved],
) -> None:
    """Turn ``AllowedValues`` into one all-or-nothing group.

    The deployer must pick from this set, so a pattern matching every entry is
    certain and a pattern matching some of them depends on a deploy-time choice.
    That is the group's ``all_required`` semantics, with the blocker used for
    exactly the partial case.
    """
    candidates = tuple(
        Candidate(
            text=entry,
            origin="AllowedValues[{0}] of parameter '{1}'".format(index, name),
            branch=label,
        )
        for index, entry in enumerate(allowed)
        if isinstance(entry, str)
    )
    if candidates:
        groups.append(
            CandidateGroup(
                candidates=candidates,
                all_required=True,
                blocker=Unresolved(
                    intrinsic=REF,
                    detail=(
                        "Unresolved intrinsic function: Ref to parameter '{0}'. "
                        "Only some of its AllowedValues match, so the outcome "
                        "depends on the value chosen at deploy time.".format(name)
                    ),
                    branch=label,
                ),
            )
        )
    if len(candidates) != len(allowed):
        unresolved.append(
            Unresolved(
                intrinsic=REF,
                detail=(
                    "Unresolved intrinsic function: Ref to parameter '{0}', "
                    "whose AllowedValues contain an entry that is not a "
                    "string.".format(name)
                ),
                branch=label,
            )
        )


def _resolve_sub(
    value: Any,
    label: Optional[str],
    groups: List[CandidateGroup],
    unresolved: List[Unresolved],
) -> None:
    """Resolve an ``Fn::Sub`` on its fixed parts: row five of the table.

    The substitutions stay in the candidate as ``${Name}`` text -- nothing is
    interpolated and no value is invented. A pattern the fixed parts already
    match, such as the trailing ``*`` of
    ``"arn:aws:iam::${AWS::AccountId}:role/*"``, is therefore certain.

    A substitution of a pseudo parameter is not a blocker, for the reason given
    at :data:`PSEUDO_PARAMETERS`: CloudFormation supplies its value from the
    deployment, so it can be neither a wildcard nor a chosen string, and row two
    of the table treats ``${AWS::AccountId}`` as determined. Any other variable
    does block, and a non-match then leaves part of the string unexamined rather
    than clean.
    """
    text = _sub_template_string(value)
    if text is None:
        unresolved.append(
            Unresolved(
                intrinsic=FN_SUB,
                detail=(
                    "Unresolved intrinsic function: Fn::Sub without a template "
                    "string."
                ),
                branch=label,
            )
        )
        return

    variables = _substitution_variables(text)
    undetermined = tuple(
        name for name in variables if name not in PSEUDO_PARAMETERS
    )
    blocker: Optional[Unresolved] = None
    if undetermined:
        blocker = Unresolved(
            intrinsic=FN_SUB,
            detail=(
                "Unresolved intrinsic function: Fn::Sub substitutes {0}, which "
                "is not determined by the Template, so only the fixed parts of "
                "the string were evaluated.".format(
                    ", ".join("${" + name + "}" for name in undetermined)
                )
            ),
            branch=label,
        )

    groups.append(
        CandidateGroup(
            candidates=(
                Candidate(
                    text=_unescape_sub(text),
                    origin=_sub_origin(variables, undetermined),
                    branch=label,
                ),
            ),
            blocker=blocker,
        )
    )


def _sub_origin(
    variables: Tuple[str, ...], undetermined: Tuple[str, ...]
) -> str:
    """Name what an ``Fn::Sub`` candidate is made of, for Evidence."""
    if not variables:
        return "Fn::Sub with no substitution variables"
    if not undetermined:
        return "Fn::Sub substituting pseudo parameters only"
    return "fixed parts of Fn::Sub"


def _sub_template_string(value: Any) -> Optional[str]:
    """Return an ``Fn::Sub``'s template string, from either accepted form."""
    if isinstance(value, str):
        return value
    if isinstance(value, list) and value and isinstance(value[0], str):
        return value[0]
    return None


def _substitution_variables(text: str) -> Tuple[str, ...]:
    """Names substituted by an ``Fn::Sub`` string, in order, without repeats.

    ``${!Name}`` is an escape for the literal text ``${Name}``, not a
    substitution, and is excluded.
    """
    names: List[str] = []
    for name in _SUB_VARIABLE.findall(text):
        if name.startswith(_SUB_ESCAPE):
            continue
        if name not in names:
            names.append(name)
    return tuple(names)


def _unescape_sub(text: str) -> str:
    """Turn ``${!Name}`` escapes into the literal ``${Name}`` they stand for."""
    return _SUB_VARIABLE.sub(_replace_escape, text)


def _replace_escape(match: "re.Match[str]") -> str:
    name = match.group(1)
    if name.startswith(_SUB_ESCAPE):
        return "${" + name[len(_SUB_ESCAPE) :] + "}"
    return match.group(0)


def _allowed_values(
    context: ResolutionContext, name: str
) -> Optional[Sequence[Any]]:
    """Return a parameter's non-empty ``AllowedValues`` list, if it has one."""
    parameter = context.parameters.get(name)
    if not isinstance(parameter, dict):
        return None
    allowed = parameter.get(ALLOWED_VALUES_KEY)
    if not isinstance(allowed, list) or not allowed:
        return None
    return allowed


def _ref_detail(name: str, context: ResolutionContext) -> str:
    """Explain why a ``Ref`` is unresolvable, in the terms the reader needs.

    Three cases worth distinguishing: a parameter with a ``Default`` (the value
    that looks resolvable and is not), a parameter without one, and a reference
    to a resource.
    """
    parameter = context.parameters.get(name)
    if isinstance(parameter, dict):
        if DEFAULT_KEY in parameter:
            return (
                "Unresolved intrinsic function: Ref to parameter '{0}'. Its "
                "Default value was not used, because a Default can be "
                "overridden at deploy time.".format(name)
            )
        return (
            "Unresolved intrinsic function: Ref to parameter '{0}', whose value "
            "is supplied at deploy time.".format(name)
        )
    return (
        "Unresolved intrinsic function: Ref to '{0}', which resolves to a value "
        "produced when the stack is deployed.".format(name)
    )


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def evaluate(
    value: Any,
    predicate: Callable[[str], bool],
    context: Optional[ResolutionContext] = None,
) -> Evaluation:
    """Apply a detector's predicate to a Template value.

    Args:
        value: The Action / Resource / Principal value, intrinsics included.
        predicate: Called with one candidate string at a time. It sees plain
            strings only, so a detector never handles an intrinsic itself.
        context: Template-level facts; see :class:`ResolutionContext`.

    Returns:
        An :class:`Evaluation`. :attr:`Verdict.MATCH` supports a ``Confirmed``
        Finding, :attr:`Verdict.NO_MATCH` supports silence, and
        :attr:`Verdict.UNRESOLVABLE` supports neither and is disclosed through
        :func:`unresolved_values`.
    """
    return verdict_for(resolve(value, context), predicate)


def verdict_for(
    resolution: Resolution, predicate: Callable[[str], bool]
) -> Evaluation:
    """Decide an already-computed :class:`Resolution`.

    Separate from :func:`evaluate` so several detectors can share one
    resolution of the same value.

    Groups are independent: a match in any group is a match for the value,
    which is what makes both a list of Resources and the branches of an
    ``Fn::If`` behave as design.md requires -- either branch being dangerous is
    reported. A group decides nothing only when its blocker applies, and the
    verdict is then unresolvable rather than clean.
    """
    matched: List[Candidate] = []
    blockers: List[Unresolved] = list(resolution.unresolved)
    decided = False

    for group in resolution.groups:
        hits = tuple(
            candidate for candidate in group.candidates if predicate(candidate.text)
        )
        if group.all_required:
            if not hits:
                # No allowed value matches, so no deploy-time choice can make
                # the pattern hold: deterministically negative.
                continue
            matched.extend(hits)
            if len(hits) == len(group.candidates):
                decided = True
            elif group.blocker is not None:
                # Some allowed values match and others do not, so the outcome
                # is the deployer's choice and nothing is confirmed.
                blockers.append(group.blocker)
            continue
        if hits:
            matched.extend(hits)
            decided = True
        elif group.blocker is not None:
            blockers.append(group.blocker)

    if decided:
        verdict = Verdict.MATCH
    elif blockers:
        verdict = Verdict.UNRESOLVABLE
    else:
        verdict = Verdict.NO_MATCH

    return Evaluation(
        verdict=verdict,
        resolution=resolution,
        matched=tuple(matched),
        blockers=tuple(blockers),
    )


# ---------------------------------------------------------------------------
# Recording unresolvable locations
# ---------------------------------------------------------------------------


def unresolved_values(
    evaluation: Evaluation,
    logical_id: str,
    template_path: Sequence[PathSegment],
    value_kind: Union[ValueKind, str],
) -> List[UnresolvedValue]:
    """Record the locations an evaluation left unchecked.

    Args:
        evaluation: The result of :func:`evaluate`.
        logical_id: Logical ID of the resource holding the value.
        template_path: Path to the value, as
            :attr:`iacreview.iam.locate.PolicySite.template_path` spells it,
            extended with the statement index and element name.
        value_kind: Which statement element the value is.

    Returns:
        One record per distinct reason, deduplicated, or an empty list when the
        verdict was decided. Empty for :attr:`Verdict.MATCH` as well as
        :attr:`Verdict.NO_MATCH`: a location that produced a Finding is not a
        gap in coverage, and the Finding already names it.

    This is the API that keeps ``UNRESOLVABLE`` from being silent. Task 13.4
    turns each record into the ``Informational`` / ``INFO`` / ``Confirmed``
    Finding of design.md using the record's own text.
    """
    if evaluation.verdict is not Verdict.UNRESOLVABLE:
        return []
    path = tuple(template_path)
    kind_text = value_kind.value if isinstance(value_kind, ValueKind) else str(value_kind)
    return dedupe_unresolved(
        UnresolvedValue(
            logical_id=logical_id,
            template_path=path,
            value_kind=kind_text,
            intrinsic=blocker.intrinsic,
            detail=blocker.detail,
            branch=blocker.branch,
        )
        for blocker in evaluation.blockers
    )


def dedupe_unresolved(
    values: Iterable[UnresolvedValue],
) -> List[UnresolvedValue]:
    """Collapse records describing the same gap, keeping first-seen order.

    Fifteen detectors examine the same statement, so one ``Fn::ImportValue``
    would otherwise be disclosed fifteen times. The key is the location, the
    element and the intrinsic -- not the wording -- so a reader sees each gap
    once.
    """
    seen = set()
    unique: List[UnresolvedValue] = []
    for value in values:
        key = (
            value.logical_id,
            value.json_path,
            value.value_kind,
            value.intrinsic,
            value.branch,
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(value)
    return unique
