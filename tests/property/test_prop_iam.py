"""Correctness Properties 26, 27 and 28: the three IAM claims stated universally.

The IAM Source needs no external tool, so these three run unconditionally: they
read a parsed Template, call :mod:`iacreview.iam.locate` and
:mod:`iacreview.iam.detectors`, and touch neither the filesystem nor a
subprocess.

What the example tests already own, and this module does not repeat
--------------------------------------------------------------------

``tests/unit/test_iam_detectors.py``
    Each of the fifteen detectors with one positive and one negative case, the
    design-table Severity of every row, and the ExternalId reduction at the
    level of :func:`~iacreview.iam.detectors.apply_external_id_mitigation`
    itself: HIGH to MEDIUM, the ``INFO`` floor, the exclusion of
    ``principal_star``, "in the same statement", the operator case-insensitivity,
    and ``lower_one_level`` on all five Severity values plus an unknown one.

``tests/unit/test_iam_intrinsics.py``
    :func:`~iacreview.iam.intrinsics.classify_principal` on individual values,
    including the ``Fn::Sub`` that substitutes something other than
    ``AWS::AccountId`` and is therefore unresolvable rather than same-account.

``tests/property/test_strategies_smoke.py``
    That the generators used below are not constant and land where they claim:
    every ``same_account_principals()`` value classifies as same-account, every
    ``cross_account_statements()`` draw carries a Principal and no Condition,
    every ``star_action_star_resource_documents()`` draw holds an ``Allow`` on
    ``*`` / ``*``, and ``iam_templates()`` reaches all four site kinds.

What this module owns
---------------------

**Property 26** is a claim of *absence*, and an absence is the easiest thing to
assert vacuously: a Template whose policy never reached a detector would satisfy
it. So each example runs the same drawn Template twice, differing in exactly one
value -- the Principal -- and requires the cross-account Finding to be **absent**
with the ``AWS::AccountId`` spelling and **present** with a literal foreign
account. The control arm is what makes the main arm's silence evidence rather
than an artefact. Both arms also force ``Effect: Allow``, because a ``Deny``
statement legitimately produces no grant Finding and would make the control arm
silent for a reason unrelated to the Principal.

The main arm additionally requires no ``Principal`` coverage gap to be recorded:
``AWS::AccountId`` is *decided*, not merely un-flagged, so a classifier that
answered ``UNRESOLVABLE`` for it would pass a Finding-only assertion while
quietly reporting the location as unchecked.

**Property 27** compares two scans of one Template that differ only by an added
``sts:ExternalId`` condition, and it asserts the reduction end to end -- through
:func:`~iacreview.iam.detectors.scan_sites`, which is where
``apply_external_id_mitigation`` actually runs -- rather than by calling the
mitigation directly as the unit test does. Beyond the one-level step it pins
what must *not* change: every other field of the Finding is compared with
:func:`dataclasses.replace`, the pre-existing Evidence entries must be preserved
in order, and no Finding from another detector may carry the mitigation note, so
a blanket reduction applied to every Severity in the report would fail here.

The ``INFO`` floor, and why "exactly one level" does not collide with it
-----------------------------------------------------------------------

The reduction is :func:`~iacreview.iam.detectors.lower_one_level`, which clamps:
``max(rank - 1, rank(INFO))``. So the implementation would return ``INFO`` for an
``INFO`` input, where "exactly one level lower" has nowhere to go.

That case is unreachable from this property's inputs, and the test asserts so
rather than assuming it. Only ``cross_account_principal`` Findings are reduced
(the mitigation checks the ``Evidence[].RuleId`` itself), and that detector's
Severity is fixed at ``HIGH`` by design.md's Layer 1 table, so every reduction
observed here is HIGH to MEDIUM. The test therefore asserts three separate
things per example: the step is exactly one level, the result is not below the
floor, and the *input* was above the floor -- which is the fact that makes the
first two consistent. The completion condition "no example falls below the
``INFO`` floor" is met because the input never reaches the floor, **and**
independently because the implementation clamps; the clamp is pinned as an
example in ``tests/unit/test_iam_detectors.py``
(``test_external_id_does_not_go_below_info``) and is not restated here.

Neither reading was weakened to avoid the question: if design.md's table ever
assigned ``cross_account_principal`` a Severity of ``INFO``, the
"input was above the floor" assertion would fail and this comment would be the
diagnosis.

**Property 28** quantifies over where the wildcard grant is *written*, not over
its shape alone. ``iam_templates`` puts the document at a trust policy, a Role
inline policy, a ManagedPolicy and a resource-based policy in turn, and the
statement itself varies in position among other statements, in scalar versus
list spelling, and in whether a Condition is attached. The four fixed fields are
read from :mod:`iacreview.iam.detectors` and :mod:`iacreview.finding` rather
than written out, and the Finding is additionally required to carry the
``star_action_star_resource`` rule ID -- without that, a CRITICAL from
``passrole_unrestricted`` or ``privesc_policy_mutation`` would satisfy the
assertion while the wildcard rule stayed silent.

No test here carries ``deadline=None``: every example is in-memory work over a
Template of at most a handful of statements, so per-example time is a property of
the code under test and the default deadline is a useful signal rather than a
flake.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Dict, List, Sequence, Tuple

from hypothesis import given, settings

import strategies as S
from iacreview.finding import (
    CONFIRMED,
    CRITICAL_SEVERITY,
    SEVERITIES,
    SEVERITY_ORDER,
    Finding,
)
from iacreview.iam import detectors, intrinsics, locate
from iacreview.iam.intrinsics import PrincipalClass

#: ``Location.File`` of every Finding these tests produce. Workspace-relative,
#: from the shared strategies module, so no path literal appears here.
TEMPLATE_FILE: str = S.TEMPLATE_FILES[0]

#: The Principal type key a Principal naming an account sits under. IAM's own
#: spelling, and the one ``strategies.cross_account_principals`` uses.
AWS_PRINCIPAL_KEY = "AWS"

#: IAM policy language version. Not read by anything under test; present so the
#: documents these tests build are the shape a Template really carries.
POLICY_VERSION = "2012-10-17"

#: The two detector names these properties are about, taken from the functions
#: themselves rather than written out. ``DetectorSpec.name`` equals the function
#: name -- ``tests/unit/test_iam_detectors.py`` pins that against design.md's
#: table -- and it is what each Finding records as ``Evidence[].RuleId``.
CROSS_ACCOUNT_RULE: str = detectors.cross_account_principal.__name__
STAR_RULE: str = detectors.star_action_star_resource.__name__

#: Rank of the lowest Severity the reduction may return.
FLOOR_RANK: int = SEVERITY_ORDER[detectors.SEVERITY_FLOOR]


# ---------------------------------------------------------------------------
# Running the Source, and reading its output
# ---------------------------------------------------------------------------


def _scan(template: Dict[str, Any]) -> Tuple[List[locate.PolicySite], detectors.ScanResult]:
    """Locate every policy site in ``template`` and run the deterministic scan.

    :func:`~iacreview.iam.detectors.scan_sites` rather than
    :func:`~iacreview.iam.detectors.scan`, because Property 26 asserts something
    about the coverage gaps as well as the Findings, and only the former returns
    them.

    Returns:
        ``(sites, result)``. The sites are returned so a test can assert its own
        premise -- that the Template it drew really does hold a policy the
        detectors saw.
    """
    sites = locate.find_policy_documents(template)
    result = detectors.scan_sites(
        sites,
        template_file=TEMPLATE_FILE,
        context=intrinsics.ResolutionContext.from_template(template),
    )
    return sites, result


def _rule_ids(f: Finding) -> List[str]:
    """Every ``Evidence[].RuleId`` of one Finding, which names the detectors."""
    return [entry.RuleId for entry in f.Evidence if entry.RuleId is not None]


def _from_detector(findings: Sequence[Finding], name: str) -> List[Finding]:
    """The Findings raised by the detector ``name``, in scan order."""
    return [f for f in findings if name in _rule_ids(f)]


# ---------------------------------------------------------------------------
# Rewriting a drawn Template so two scans differ in exactly one thing
# ---------------------------------------------------------------------------


def _with_principal(value: Any, principal: Any) -> Any:
    """Copy ``value``, replacing every ``Principal`` and forcing every ``Effect``.

    Used to build Property 26's two arms out of one drawn Template, so the only
    difference between them is the account the Principal names. ``Effect`` is
    forced to ``Allow`` in *both* arms: the detectors report grants only, so a
    drawn ``Deny`` would silence the control arm for a reason that has nothing to
    do with the Principal.

    A copy rather than a mutation, because the drawn Template is shared with
    Hypothesis and with the other arm.
    """
    if isinstance(value, dict):
        rewritten: Dict[Any, Any] = {}
        for key, item in value.items():
            if key == detectors.PRINCIPAL_KEY:
                rewritten[key] = {AWS_PRINCIPAL_KEY: principal}
            elif key == detectors.EFFECT_KEY:
                rewritten[key] = detectors.ALLOW_EFFECT
            else:
                rewritten[key] = _with_principal(item, principal)
        return rewritten
    if isinstance(value, list):
        return [_with_principal(item, principal) for item in value]
    return value


def _with_external_id(value: Any) -> Any:
    """Copy ``value``, adding the ``sts:ExternalId`` condition to each statement.

    A statement is recognised by its ``Effect`` key, which is the one element
    every statement has and no enclosing mapping does. Requirement 6 AC10 is
    about a condition "in the same statement", and
    ``strategies.cross_account_statements`` yields a single statement with no
    ``Condition`` at all, so adding the condition to every statement adds exactly
    one condition to exactly the statement that produced the Finding.
    """
    if isinstance(value, dict):
        rewritten = {key: _with_external_id(item) for key, item in value.items()}
        if detectors.EFFECT_KEY in rewritten:
            rewritten[detectors.CONDITION_KEY] = S.external_id_condition()
        return rewritten
    if isinstance(value, list):
        return [_with_external_id(item) for item in value]
    return value


def _as_document(statement: Dict[str, Any]) -> Dict[str, Any]:
    """Wrap one statement in a policy document, for ``iam_templates(document=)``."""
    return {"Version": POLICY_VERSION, detectors.STATEMENT_KEY: [statement]}


# ---------------------------------------------------------------------------
# Property 26
# ---------------------------------------------------------------------------


# Feature: aws-iac-review-agent-plugin, Property 26: *For any* IAM Principal value expressed via the `AWS::AccountId` pseudo parameter, whether as `{"Ref": "AWS::AccountId"}` or as a `Fn::Sub` string containing `${AWS::AccountId}` and no other substitution variable, the classification is same-account and never cross-account.
@settings(max_examples=100)
@given(
    template=S.iam_templates(
        document=S.policy_documents(principal=S.same_account_principals())
    ),
    same_account=S.same_account_principals(),
    cross_account=S.cross_account_principals(),
)
def test_account_id_pseudo_parameter_is_same_account_never_cross_account(
    template: Dict[str, Any], same_account: Any, cross_account: Any
) -> None:
    """**Validates: Requirements 6.8**

    Three claims, in order of strength.

    The classifier is asked directly, which is the property as design.md states
    it. Then the same value is pushed through the whole Source at one of the four
    policy sites, and no cross-account Finding may result. Then the identical
    Template with only the account changed must produce one -- the differential
    that makes the second claim non-vacuous, since a Template whose policy never
    reached a detector would satisfy an absence assertion by itself.

    The coverage-gap assertion is the part a Finding-only test would miss:
    ``AWS::AccountId`` has to be *decided* as same-account, not merely left
    un-flagged. A classifier answering ``UNRESOLVABLE`` would raise no
    cross-account Finding and would still be wrong, and it would show up here as
    a ``Principal`` entry among the unresolvable locations.
    """
    assert intrinsics.classify_principal(same_account) is PrincipalClass.SAME_ACCOUNT
    assert intrinsics.classify_principal(same_account) is not PrincipalClass.CROSS_ACCOUNT

    unwrapped = (
        cross_account[AWS_PRINCIPAL_KEY]
        if isinstance(cross_account, dict)
        else cross_account
    )
    assert intrinsics.classify_principal(unwrapped) is PrincipalClass.CROSS_ACCOUNT

    same_sites, same_result = _scan(_with_principal(template, same_account))
    cross_sites, cross_result = _scan(_with_principal(template, cross_account))

    # The premise: both arms really do carry a policy the detectors examined.
    assert same_sites
    assert len(cross_sites) == len(same_sites)

    assert _from_detector(same_result.findings, CROSS_ACCOUNT_RULE) == []
    assert [
        record
        for record in same_result.unresolved
        if record.value_kind == intrinsics.ValueKind.PRINCIPAL.value
    ] == []

    # Same Template, same sites, only the account differs.
    assert _from_detector(cross_result.findings, CROSS_ACCOUNT_RULE)


# ---------------------------------------------------------------------------
# Property 27
# ---------------------------------------------------------------------------


# Feature: aws-iac-review-agent-plugin, Property 27: *For any* statement that produces a cross-account Principal Finding, adding an `sts:ExternalId` condition to that same statement lowers the reported `Severity` by exactly one level under the ordering `CRITICAL > HIGH > MEDIUM > LOW > INFO`, never below `INFO`, and adds an Evidence entry recording the mitigating condition.
@settings(max_examples=100)
@given(
    template=S.iam_templates(
        document=S.cross_account_statements().map(_as_document)
    )
)
def test_external_id_lowers_cross_account_severity_by_exactly_one_level(
    template: Dict[str, Any]
) -> None:
    """**Validates: Requirements 6.10**

    Two scans of one Template, differing only by the added condition, compared
    Finding by Finding. The reduction is observed through ``scan_sites``, which
    is where the plugin actually applies it, rather than by calling
    ``apply_external_id_mitigation`` -- that call is what
    ``tests/unit/test_iam_detectors.py`` covers, and it cannot show that the
    normalizer stage runs the reduction before the report sees the Finding.

    ``base_rank > FLOOR_RANK`` is asserted alongside the one-level step, not
    instead of it: it is the fact that keeps "exactly one level" and "never below
    ``INFO``" from contradicting each other, and the module docstring explains
    why it holds. See the ``INFO`` floor section there.

    The last loop is the over-application guard. Adding a Condition legitimately
    silences ``sensitive_prefix_without_condition``, so the two arms do not hold
    the same Findings and a set comparison would be wrong; what must hold is that
    no Finding from another detector carries the mitigation note.
    """
    _, baseline = _scan(template)
    _, mitigated = _scan(_with_external_id(template))

    base_cross = _from_detector(baseline.findings, CROSS_ACCOUNT_RULE)
    reduced_cross = _from_detector(mitigated.findings, CROSS_ACCOUNT_RULE)

    # The property's premise, and this test's non-vacuity: the statement really
    # did produce a cross-account Finding before the condition was added.
    assert base_cross
    assert len(reduced_cross) == len(base_cross)

    for base, reduced in zip(base_cross, reduced_cross):
        base_rank = SEVERITY_ORDER[base.Severity]
        reduced_rank = SEVERITY_ORDER[reduced.Severity]
        context = (base.Severity, reduced.Severity, base.Location.TemplatePath)

        assert reduced.Severity in SEVERITIES, context
        assert base_rank - reduced_rank == 1, context
        assert reduced.Severity == detectors.lower_one_level(base.Severity), context
        # Never below the floor, and the input never at it -- see the docstring.
        assert reduced_rank >= FLOOR_RANK, context
        assert base_rank > FLOOR_RANK, context

        kept = list(reduced.Evidence)[: len(base.Evidence)]
        added = list(reduced.Evidence)[len(base.Evidence) :]
        assert kept == list(base.Evidence), context
        assert len(added) == 1, context
        assert added[0].Detail == detectors.EXTERNAL_ID_MITIGATION_DETAIL, context
        assert added[0].RuleId == CROSS_ACCOUNT_RULE, context
        assert added[0].Source == detectors.SOURCE_NAME, context

        # Nothing but the Severity and the Evidence moved.
        assert (
            replace(reduced, Severity=base.Severity, Evidence=list(base.Evidence))
            == base
        ), context

    for f in mitigated.findings:
        if CROSS_ACCOUNT_RULE in _rule_ids(f):
            continue
        assert all(
            entry.Detail != detectors.EXTERNAL_ID_MITIGATION_DETAIL
            for entry in f.Evidence
        ), _rule_ids(f)


# ---------------------------------------------------------------------------
# Property 28
# ---------------------------------------------------------------------------


# Feature: aws-iac-review-agent-plugin, Property 28: *For any* IAM policy document containing a statement with `Effect: Allow`, an Action list including `"*"`, and a Resource list including `"*"`, the deterministic IAM scan produces at least one Finding for the owning resource with `FindingType` `Security`, `Severity` `CRITICAL`, `Confidence` `Confirmed`, and `Normalized_Category` `IAM`.
@settings(max_examples=100)
@given(template=S.iam_templates(document=S.star_action_star_resource_documents()))
def test_star_action_star_resource_is_always_critical_security_confirmed(
    template: Dict[str, Any]
) -> None:
    """**Validates: Requirements 6.1, 6.4**

    The four fields are read from the modules that fix them, so the assertion
    cannot drift from the schema, and the ``Resource`` is required to be the
    logical ID of a site the locator found rather than any string.

    The rule ID assertion is what makes the four fields mean the wildcard rule
    fired: ``passrole_unrestricted``, ``privesc_policy_mutation`` and
    ``privesc_lambda_passrole`` are CRITICAL Security IAM Findings too, and the
    generated documents can contain the actions that raise them.
    """
    sites, result = _scan(template)

    # The premise: the wildcard document sits at a site the locator recognises.
    assert sites
    owners = {site.logical_id for site in sites}

    qualifying = [
        f
        for f in result.findings
        if f.FindingType == detectors.FINDING_TYPE
        and f.Severity == CRITICAL_SEVERITY
        and f.Confidence == CONFIRMED
        and f.Normalized_Category == detectors.CATEGORY
    ]
    assert qualifying
    assert all(f.Resource in owners for f in qualifying)
    assert [f for f in qualifying if STAR_RULE in _rule_ids(f)]
