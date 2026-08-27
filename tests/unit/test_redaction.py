"""Credential redaction of ``Evidence[].Excerpt`` (Task 14.2, design.md O-11).

``Excerpt`` is the only Finding field that reproduces Template text verbatim, so
it is the only way a credential written into a Template can reach the report.
Requirement 9 AC2 forbids that; Requirement 7 AC11 requires a non-``Confirmed``
Finding to carry an Excerpt at all. The two are reconciled by *replacing* the
quotation with a non-empty placeholder, and this file locks both halves:

(a) an Excerpt at, or referencing, a ``NoEcho: true`` Parameter is not reported,
(b) an Excerpt on a ``W1011`` location is not reported,
(c) an Excerpt on a ``W2501`` location is not reported,
(d) an ordinary Excerpt survives untouched -- redaction that fired everywhere
    would satisfy (a) to (c) while making Evidence useless,
(e) a redacted entry says so in its ``Detail``, so "nothing was quoted" and
    "something was quoted and withheld" stay distinguishable.

Plus the wiring: all three Source paths that produce Findings
(``cfnlint``, ``iam``, ``agentin``) pass through redaction, with the agent path
the only one that carries Excerpt text today.

Every credential-shaped value here is an obvious placeholder
(``EXAMPLE_SECRET_PLACEHOLDER``), per design.md's Security Design table: this
repository contains no value that could be mistaken for a real credential.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from iacreview import agentin, cfnlint, iam
from iacreview import finding as finding_module
from iacreview.finding import (
    CREDENTIAL_RULE_IDS,
    REDACTED_EXCERPT,
    REDACTION_DETAIL,
    REDACTION_REASONS,
    Evidence,
    Finding,
    Location,
    RedactionTrigger,
    noecho_parameter_names,
    redact_excerpt,
    redact_finding,
    redaction_trigger,
)

# tests/unit/test_redaction.py -> tests/unit -> tests -> plugin root
PLUGIN_ROOT: Path = Path(__file__).resolve().parents[2]
FIXTURES: Path = PLUGIN_ROOT / "tests" / "fixtures"

#: Stand-in for a credential value written into a Template. Not a credential,
#: and not shaped like one.
SECRET = "EXAMPLE_SECRET_PLACEHOLDER"

#: Logical name of the ``NoEcho: true`` Parameter used throughout.
NOECHO_PARAMETER = "DBPassword"

#: An Excerpt with nothing credential-related about it.
ORDINARY_EXCERPT = 'Action: ["s3:GetObject"]'


def noecho_template() -> Dict[str, Any]:
    """A Template declaring one ``NoEcho`` Parameter with a value in it.

    The ``Default`` is the leak this task exists for: the credential is *in the
    Template file*, at the Parameter's own location, where an Excerpt would
    quote it.
    """
    return {
        "Parameters": {
            NOECHO_PARAMETER: {
                "Type": "String",
                "NoEcho": True,
                "Default": SECRET,
            },
            "Environment": {"Type": "String", "Default": "prod"},
        },
        "Resources": {
            "Database": {
                "Type": "AWS::RDS::DBInstance",
                "Properties": {"MasterUserPassword": {"Ref": NOECHO_PARAMETER}},
            }
        },
    }


def finding_with_excerpt(
    excerpt: Optional[str],
    *,
    rule_id: Optional[str] = None,
    template_path: Optional[List[Any]] = None,
    confidence: str = "Likely",
    source: str = "Agent Review",
    detail: str = "The property receives the value quoted below.",
) -> Finding:
    """One Finding whose single Evidence entry quotes ``excerpt``."""
    return Finding(
        ID=1,
        Normalized_Category="DataProtection",
        FindingType="Security",
        Severity="HIGH",
        Confidence=confidence,
        Source=[source],
        Resource="Database",
        Location=Location(
            File="templates/db.yaml",
            Line=None,
            Column=None,
            TemplatePath=template_path,
        ),
        Finding="The database password may be readable from the Template.",
        WhyItMatters="A credential in the Template is stored in stack history.",
        Evidence=[
            Evidence(
                Source=source,
                Detail=detail,
                RuleId=rule_id,
                Excerpt=excerpt,
            )
        ],
        Recommendation="Supply the value from a secret store at deploy time.",
        SuggestedRemediation=None,
    )


def agent_entry(**overrides: Any) -> Dict[str, Any]:
    """One agent finding as JSON, the shape :mod:`iacreview.agentin` accepts."""
    entry: Dict[str, Any] = {
        "Normalized_Category": "DataProtection",
        "FindingType": "Security",
        "Severity": "HIGH",
        "Confidence": "Likely",
        "Source": ["Agent Review"],
        "Resource": "Database",
        "Location": {
            "File": "templates/db.yaml",
            "TemplatePath": ["Parameters", NOECHO_PARAMETER],
        },
        "Finding": "The Parameter may carry a credential in the Template itself.",
        "WhyItMatters": "A default value is stored in the Template and in stack history.",
        "Evidence": [
            {
                "Source": "Agent Review",
                "Detail": "The Parameter declares a default value.",
                "RuleId": None,
                "Excerpt": "Default: {0}".format(SECRET),
            }
        ],
        "Recommendation": "Remove the default and supply the value at deploy time.",
        "SuggestedRemediation": None,
    }
    entry.update(overrides)
    return entry


def excerpts(findings: List[Finding]) -> List[Optional[str]]:
    return [entry.Excerpt for f in findings for entry in f.Evidence]


def notice_for(trigger: RedactionTrigger) -> str:
    return REDACTION_DETAIL.format(reason=REDACTION_REASONS[trigger])


# ---------------------------------------------------------------------------
# The NoEcho Parameter set (the Template-side half of condition (a))
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("declaration", "expected"),
    [
        ({"Type": "String", "NoEcho": True}, True),
        # A Template is text: both formats allow the string, and CloudFormation
        # reads it as the boolean.
        ({"Type": "String", "NoEcho": "true"}, True),
        ({"Type": "String", "NoEcho": " TRUE "}, True),
        ({"Type": "String", "NoEcho": False}, False),
        ({"Type": "String", "NoEcho": "false"}, False),
        ({"Type": "String"}, False),
        ("not a mapping", False),
    ],
)
def test_noecho_parameter_names_reads_the_declaration(
    declaration: Any, expected: bool
) -> None:
    doc = {"Parameters": {NOECHO_PARAMETER: declaration}, "Resources": {}}

    names = noecho_parameter_names(doc)

    assert (NOECHO_PARAMETER in names) is expected


@pytest.mark.parametrize(
    "doc",
    [None, "text", [], {}, {"Parameters": None}, {"Parameters": []}],
    ids=["none", "text", "list", "empty", "null-parameters", "list-parameters"],
)
def test_noecho_parameter_names_is_empty_for_unreadable_input(doc: Any) -> None:
    """Untrusted input never raises here (Requirement 9 AC7)."""
    assert noecho_parameter_names(doc) == frozenset()


def test_noecho_parameter_names_collects_only_the_noecho_parameters() -> None:
    assert noecho_parameter_names(noecho_template()) == frozenset({NOECHO_PARAMETER})


# ---------------------------------------------------------------------------
# (a) NoEcho Parameter locations
# ---------------------------------------------------------------------------


def test_noecho_parameter_value_does_not_reach_the_reported_excerpt() -> None:
    """The end-to-end statement of Requirement 9 AC2 for condition (a)."""
    names = noecho_parameter_names(noecho_template())

    findings, errors = agentin.findings_from_payload(
        [agent_entry()], noecho_parameters=names
    )

    assert errors == []
    reported = json.dumps([finding_module.to_dict(f) for f in findings])
    assert SECRET not in reported
    assert findings[0].Evidence[0].Excerpt == REDACTED_EXCERPT


def test_excerpt_referencing_a_noecho_parameter_by_name_is_redacted() -> None:
    """A ``Ref`` to the Parameter is a reference to its value."""
    f = finding_with_excerpt(
        "MasterUserPassword: !Ref {0}".format(NOECHO_PARAMETER),
        template_path=["Resources", "Database", "Properties"],
    )

    redact_finding(f, noecho_parameters={NOECHO_PARAMETER})

    assert f.Evidence[0].Excerpt == REDACTED_EXCERPT


@pytest.mark.parametrize(
    "excerpt",
    [
        'MasterUserPassword: {"Ref": "DBPassword"}',
        "MasterUserPassword: !Sub '${DBPassword}'",
        "MasterUserPassword:\n  Ref: DBPassword",
    ],
    ids=["json-ref", "sub", "yaml-ref"],
)
def test_every_spelling_of_the_reference_is_redacted(excerpt: str) -> None:
    f = finding_with_excerpt(excerpt)

    redact_finding(f, noecho_parameters={NOECHO_PARAMETER})

    assert f.Evidence[0].Excerpt == REDACTED_EXCERPT


def test_a_finding_at_the_parameters_section_is_redacted() -> None:
    """A section-level Excerpt may quote the Parameter's ``Default``.

    Redacting it is the conservative side design.md asks for (O-11): the cost is
    one over-redacted Excerpt, the alternative cost is a leaked credential.
    """
    f = finding_with_excerpt(
        "Parameters:\n  {0}:\n    Default: {1}".format(NOECHO_PARAMETER, SECRET),
        template_path=["Parameters"],
    )

    redact_finding(f, noecho_parameters={NOECHO_PARAMETER})

    assert f.Evidence[0].Excerpt == REDACTED_EXCERPT


@pytest.mark.parametrize(
    "excerpt",
    [
        "Ref: DBPasswordRotation",
        "Ref: AppDBPassword",
        "Description: the database password is supplied at deploy time",
    ],
    ids=["longer-identifier", "prefixed-identifier", "prose"],
)
def test_a_name_is_matched_as_a_whole_identifier_only(excerpt: str) -> None:
    """Ordinary Template content that merely resembles the name is kept."""
    f = finding_with_excerpt(excerpt)

    redact_finding(f, noecho_parameters={NOECHO_PARAMETER})

    assert f.Evidence[0].Excerpt == excerpt


def test_without_the_parameter_names_condition_a_is_not_evaluated() -> None:
    """The caller owns the Template; a Source that has none claims nothing.

    Documents why :func:`iacreview.agentin.load_agent_findings` takes the names
    as an argument: omitting them leaves condition (a) unevaluated rather than
    silently satisfied.
    """
    findings, errors = agentin.findings_from_payload([agent_entry()])

    assert errors == []
    assert findings[0].Evidence[0].Excerpt == "Default: {0}".format(SECRET)


# ---------------------------------------------------------------------------
# (b) and (c) credential-detection rule locations
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("rule_id", sorted(CREDENTIAL_RULE_IDS))
def test_a_credential_rule_location_is_redacted(rule_id: str) -> None:
    f = finding_with_excerpt(
        "MasterUserPassword: {0}".format(SECRET), rule_id=rule_id
    )

    redact_finding(f)

    assert f.Evidence[0].Excerpt == REDACTED_EXCERPT
    assert SECRET not in json.dumps(finding_module.to_dict(f))


def test_the_credential_rule_set_is_exactly_the_two_design_names() -> None:
    """Widening the set is a design change, not an implementation detail."""
    assert CREDENTIAL_RULE_IDS == frozenset({"W1011", "W2501"})


# ---------------------------------------------------------------------------
# (d) everything else is left alone
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("rule_id", "template_path"),
    [
        (None, None),
        ("W3037", ["Resources", "AppRole", "Properties"]),
        ("W2010", ["Outputs", "DatabaseEndpoint"]),
        (None, ["Resources", "Database", "Properties"]),
    ],
    ids=["no-rule", "iam-rule", "noecho-exposure-rule", "resource-location"],
)
def test_an_untriggered_excerpt_and_detail_are_unchanged(
    rule_id: Optional[str], template_path: Optional[List[Any]]
) -> None:
    detail = "The policy grants the action quoted below."
    f = finding_with_excerpt(
        ORDINARY_EXCERPT, rule_id=rule_id, template_path=template_path, detail=detail
    )

    redact_finding(f, noecho_parameters={NOECHO_PARAMETER})

    assert f.Evidence[0].Excerpt == ORDINARY_EXCERPT
    assert f.Evidence[0].Detail == detail


def test_a_redacted_finding_still_satisfies_the_excerpt_requirement() -> None:
    """Requirement 7 AC11: the placeholder is non-empty on purpose."""
    f = finding_with_excerpt("Default: {0}".format(SECRET), rule_id="W1011")

    redact_finding(f)

    assert f.Evidence[0].Excerpt
    finding_module.validate(f)


@pytest.mark.parametrize("excerpt", [None, ""], ids=["none", "empty"])
def test_nothing_quoted_means_nothing_to_redact(excerpt: Optional[str]) -> None:
    f = finding_with_excerpt(excerpt, rule_id="W1011", confidence="Confirmed")
    detail = f.Evidence[0].Detail

    redact_finding(f)

    assert f.Evidence[0].Excerpt == excerpt
    assert f.Evidence[0].Detail == detail


def test_redact_excerpt_passes_the_text_through_when_nothing_triggered() -> None:
    assert redact_excerpt(ORDINARY_EXCERPT, RedactionTrigger.NONE) == ORDINARY_EXCERPT
    assert redact_excerpt(None, RedactionTrigger.NONE) is None


def test_redaction_is_idempotent() -> None:
    """Applying it twice is the same as once, in Excerpt and in Detail."""
    f = finding_with_excerpt("Default: {0}".format(SECRET), rule_id="W2501")

    redact_finding(f)
    once = (f.Evidence[0].Excerpt, f.Evidence[0].Detail)
    redact_finding(f)

    assert (f.Evidence[0].Excerpt, f.Evidence[0].Detail) == once
    assert f.Evidence[0].Detail.count(REDACTED_EXCERPT) == 0
    assert f.Evidence[0].Detail.endswith(notice_for(RedactionTrigger.CREDENTIAL_RULE))


@pytest.mark.parametrize(
    ("rule_id", "names", "expected"),
    [
        ("W1011", (), RedactionTrigger.CREDENTIAL_RULE),
        ("W2501", (), RedactionTrigger.CREDENTIAL_RULE),
        # Both conditions hold: the reported reason is fixed, not incidental.
        ("W1011", (NOECHO_PARAMETER,), RedactionTrigger.CREDENTIAL_RULE),
        (None, (NOECHO_PARAMETER,), RedactionTrigger.NO_ECHO_PARAMETER),
        ("W3037", (), RedactionTrigger.NONE),
        (None, (), RedactionTrigger.NONE),
    ],
    ids=["w1011", "w2501", "both", "noecho", "other-rule", "neither"],
)
def test_redaction_trigger_is_deterministic(
    rule_id: Optional[str], names: Any, expected: RedactionTrigger
) -> None:
    trigger = redaction_trigger(
        excerpt="Ref: {0}".format(NOECHO_PARAMETER),
        rule_id=rule_id,
        template_path=["Resources", "Database", "Properties"],
        noecho_parameters=names,
    )

    assert trigger is expected


# ---------------------------------------------------------------------------
# (e) a redacted entry says so
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("rule_id", "names", "trigger"),
    [
        ("W1011", (), RedactionTrigger.CREDENTIAL_RULE),
        (None, (NOECHO_PARAMETER,), RedactionTrigger.NO_ECHO_PARAMETER),
    ],
    ids=["credential-rule", "noecho"],
)
def test_a_redacted_entry_records_the_redaction_in_its_detail(
    rule_id: Optional[str], names: Any, trigger: RedactionTrigger
) -> None:
    original = "The property is set from the value quoted below."
    f = finding_with_excerpt(
        "MasterUserPassword: !Ref {0}".format(NOECHO_PARAMETER),
        rule_id=rule_id,
        detail=original,
    )

    redact_finding(f, noecho_parameters=names)

    detail = f.Evidence[0].Detail
    assert detail.startswith(original)
    assert notice_for(trigger) in detail
    assert REDACTION_REASONS[trigger] in detail


def test_the_notice_replaces_a_detail_that_carried_nothing() -> None:
    """An Evidence entry always ends up saying why its Excerpt is missing."""
    f = finding_with_excerpt("Default: {0}".format(SECRET), rule_id="W1011", detail="")

    redact_finding(f)

    assert f.Evidence[0].Detail == notice_for(RedactionTrigger.CREDENTIAL_RULE)


# ---------------------------------------------------------------------------
# Wiring: all three Source paths pass through redaction
# ---------------------------------------------------------------------------


def test_agent_findings_are_redacted_when_loaded_from_a_file(tmp_path: Path) -> None:
    path = tmp_path / "agent-findings.json"
    path.write_text(
        json.dumps({"schema_version": "1.0.0", "findings": [agent_entry()]}),
        encoding="utf-8",
    )

    findings, errors = agentin.load_agent_findings(
        path, noecho_parameters=noecho_parameter_names(noecho_template())
    )

    assert errors == []
    assert excerpts(findings) == [REDACTED_EXCERPT]


def cfnlint_result(rule_id: str) -> cfnlint.RawResult:
    return cfnlint.RawResult(
        rule_id=rule_id,
        rule_short_description="A credential value is stored in the Template.",
        rule_description="Do not hardcode credential values.",
        rule_source=None,
        level="Warning",
        message="Password should not be a plain string",
        line=12,
        column=7,
        template_path=("Resources", "Database", "Properties", "MasterUserPassword"),
        filename="templates/db.yaml",
    )


@pytest.mark.parametrize("rule_id", sorted(CREDENTIAL_RULE_IDS) + ["W3037"])
def test_cfnlint_findings_quote_no_template_text_to_redact(rule_id: str) -> None:
    """Why redaction is a no-op for this Source rather than absent from it.

    cfn-lint Findings are ``Confirmed`` and their ``RuleId`` is their evidence,
    so they set ``Excerpt`` to ``None`` -- including on the two credential rules,
    whose message never reaches ``Excerpt``. The redaction call in the Source is
    what keeps that true if an Excerpt is ever added.
    """
    findings = cfnlint.normalize_results(
        [cfnlint_result(rule_id)],
        template_file="templates/db.yaml",
        workspace_root=PLUGIN_ROOT,
    )

    assert excerpts(findings) == [None]
    assert REDACTED_EXCERPT not in findings[0].Evidence[0].Detail


def test_iam_findings_quote_no_template_text_to_redact() -> None:
    """Same for IAM Review, which supplies the NoEcho names it can compute."""
    result = iam.run_and_normalize(
        FIXTURES / "security" / "iam_dangerous_policies.yaml",
        workspace_root=PLUGIN_ROOT,
    )

    assert result.findings
    assert set(excerpts(result.findings)) == {None}
