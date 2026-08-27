"""Tests for :mod:`iacreview.iam` -- the IAM Source adapter (Task 13.4).

Four groups, matching the four things the Source promises:

1. A Template with IAM. The ``Confirmed`` Findings design.md's Layer 1 table
   specifies come out, in a ``SourceResult`` the orchestrator can consume, with
   nothing in it that would leak a host path into the report
   (Requirements 6 AC13, 7 AC9).
2. A Template without IAM. Zero Findings *and* an informational message, which
   is a different result from a Template that was examined and found clean
   (Requirement 6 AC12).
3. Values that cannot be resolved statically. Each becomes the
   ``Informational`` / ``INFO`` / ``Confirmed`` ``unresolvable_value``
   disclosure, and none becomes a Security Finding -- an unresolvable value is a
   coverage gap, not a vulnerability.
4. The Layer 2 input JSON. Its key structure is asserted against the constants
   the module exports *and* against design.md's spelling written out by hand
   here, so renaming a key in the implementation cannot quietly rename it in the
   contract Task 18.4's ``extract_policies.py`` publishes.

Expectations are written from the fixtures, never read back from the review
output. Where a group needs the Layer 1 detector list, it is compared against
:func:`iacreview.iam.detectors.scan_sites` rather than a hard-coded count, so a
new detector does not require editing this file -- the detector's own positive
and negative cases live in ``test_iam_detectors.py``.
"""

from __future__ import annotations

import json
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any, Dict, List

import pytest

# tests/unit/test_iam_source.py -> tests/unit -> tests -> plugin root
PLUGIN_ROOT: Path = Path(__file__).resolve().parents[2]
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

from iacreview import finding as finding_module
from iacreview import iam, template
from iacreview.errors import NotReviewableError, PathContainmentError, TemplateParseError
from iacreview.iam import detectors, locate
from iacreview.iam.intrinsics import UNRESOLVABLE_RULE_ID, ResolutionContext
from iacreview.iam.locate import PolicyKind

FIXTURES: Path = PLUGIN_ROOT / "tests" / "fixtures"

#: Dangerous IAM, one site of several kinds. See the fixture's own header for the
#: defects it contains.
DANGEROUS: Path = FIXTURES / "security" / "iam_dangerous_policies.yaml"

#: All nine ``PolicyKind`` values, every policy narrow.
ALL_KINDS: Path = FIXTURES / "valid" / "iam_all_policy_kinds.yaml"

#: ``Fn::ImportValue``, a ``Ref`` to a defaulted parameter, and a ``PolicyDocument``
#: written as a JSON string.
UNRESOLVABLE: Path = FIXTURES / "valid" / "iam_unresolvable_values.yaml"

#: Templates with no IAM-relevant resource at all, in both input formats.
NO_IAM = (
    FIXTURES / "valid" / "minimal_compliant_template.yaml",
    FIXTURES / "valid" / "minimal_template.json",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def review(path: Path):
    """Run the Source on ``path`` with the plugin root as the workspace."""
    return iam.run_and_normalize(path, workspace_root=PLUGIN_ROOT)


def rule_ids(findings) -> List[str]:
    """``Evidence[0].RuleId`` of each Finding, in order."""
    return [f.Evidence[0].RuleId for f in findings]


def layer1_findings(path: Path) -> List[Any]:
    """Layer 1's own output for ``path``, independent of the Source."""
    doc = template.load_template(path.resolve()).doc
    return detectors.scan_sites(
        locate.find_policy_documents(doc),
        template_file=str(path.relative_to(PLUGIN_ROOT).as_posix()),
        context=ResolutionContext.from_template(doc),
    ).findings


def assert_all_validate(findings) -> None:
    """Every Finding satisfies the schema once the report has assigned an ID.

    ``ID`` is :data:`~iacreview.finding.UNASSIGNED_ID` until the report sorts and
    numbers the Findings, and ``validate`` requires ``ID >= 1``, so the ID is
    supplied here rather than weakening the check.
    """
    for index, item in enumerate(findings, start=1):
        finding_module.validate(replace(item, ID=index))


# ---------------------------------------------------------------------------
# Group 1: a Template with IAM
# ---------------------------------------------------------------------------


def test_dangerous_template_yields_a_wellformed_source_result() -> None:
    result = review(DANGEROUS)

    assert result.source == detectors.SOURCE_NAME == "IAM Review"
    assert result.errors == []
    assert result.exit_status() == 0
    assert result.findings
    assert_all_validate(result.findings)


def test_every_finding_is_confirmed_and_attributed_to_the_iam_source() -> None:
    # Requirement 7 AC9: deterministic IAM matching is Confirmed, never a guess.
    for item in review(DANGEROUS).findings:
        assert item.Confidence == "Confirmed"
        assert item.Source == ["IAM Review"]
        assert item.Normalized_Category == "IAM"


def test_findings_carry_the_resource_and_statement_location() -> None:
    # Requirement 6 AC13: logical resource ID plus the statement's position.
    for item in review(DANGEROUS).findings:
        assert item.Resource
        assert item.Location.TemplatePath
        assert item.Location.TemplatePath[0] == "Resources"
        assert item.Location.TemplatePath[1] == item.Resource


def test_location_file_is_workspace_relative() -> None:
    # Requirement 16 AC11: a report must not carry the reviewer's directory
    # layout, or two machines produce different bytes for the same Template.
    expected = "tests/fixtures/security/iam_dangerous_policies.yaml"
    for item in review(DANGEROUS).findings:
        assert item.Location.File == expected


def test_source_reports_exactly_layer_1_plus_its_disclosures() -> None:
    result = review(DANGEROUS)
    security = [f for f in result.findings if f.FindingType == "Security"]

    assert rule_ids(security) == rule_ids(layer1_findings(DANGEROUS))


def test_external_id_reduction_survives_into_the_source_output() -> None:
    # Requirement 6 AC10. The fixture's cross-account Principal carries an
    # sts:ExternalId condition, so HIGH is reported as MEDIUM with the
    # mitigation recorded. Asserted here because the reduction happens in the
    # normalizer stage, which is the stage this Source is.
    reduced = [
        f
        for f in review(DANGEROUS).findings
        if f.Evidence[0].RuleId == "cross_account_principal"
    ]

    assert reduced, "fixture is expected to contain a cross-account principal"
    for item in reduced:
        assert item.Severity == "MEDIUM"
        assert any("sts:ExternalId" in entry.Detail for entry in item.Evidence)


def test_stats_have_the_documented_shape() -> None:
    result = review(DANGEROUS)

    assert tuple(sorted(result.stats)) == tuple(sorted(iam.STATS_KEYS))
    assert result.stats["informational_message"] is None
    assert result.stats["detectors_evaluated"] == len(detectors.DETECTOR_NAMES)
    assert result.stats["policy_sites"] == len(
        locate.find_policy_documents(template.load_template(DANGEROUS).doc)
    )


def test_narrow_policies_produce_no_critical_findings() -> None:
    # Negative test (steering/testing.md). The nine-kinds fixture grants one
    # named action per policy, so none of the CRITICAL rows of design.md's table
    # can apply: there is no "*" action, no "*" resource, no "*" Principal and no
    # policy-mutating action. The HIGH rows do apply -- a Condition-less
    # `s3:GetObject` is exactly what Requirement 6 AC2 asks about -- so this
    # asserts the ceiling rather than silence.
    result = review(ALL_KINDS)

    assert result.errors == []
    assert result.stats["informational_message"] is None
    assert [f for f in result.findings if f.Severity == "CRITICAL"] == []


def test_a_preloaded_template_gives_the_same_result() -> None:
    loaded = template.load_template(DANGEROUS.resolve())
    direct = review(DANGEROUS)
    reused = iam.run_and_normalize(
        DANGEROUS, workspace_root=PLUGIN_ROOT, loaded=loaded
    )

    assert reused == direct


def test_a_preloaded_template_for_another_file_is_refused() -> None:
    # Accepting it would attribute one Template's findings to another's path.
    other = template.load_template(ALL_KINDS.resolve())

    with pytest.raises(ValueError):
        iam.run_and_normalize(DANGEROUS, workspace_root=PLUGIN_ROOT, loaded=other)


def test_two_runs_agree() -> None:
    # Determinism (steering/testing.md): the deterministic layer must give the
    # same answer twice for the same input.
    assert review(DANGEROUS) == review(DANGEROUS)


# ---------------------------------------------------------------------------
# Group 2: a Template without IAM
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", NO_IAM, ids=lambda p: p.name)
def test_no_iam_resources_yields_zero_findings_and_a_message(path: Path) -> None:
    # Requirement 6 AC12.
    result = review(path)

    assert result.findings == []
    assert result.errors == []
    assert result.exit_status() == 0
    assert result.stats["informational_message"] == detectors.NO_IAM_RESOURCES_MESSAGE
    assert result.stats["policy_sites"] == 0


def test_reviewed_and_clean_is_distinguishable_from_nothing_to_review() -> None:
    # Both return zero Security findings; only one of them was never checked.
    absent = review(NO_IAM[0])
    present = review(ALL_KINDS)

    assert absent.stats["informational_message"] is not None
    assert present.stats["informational_message"] is None
    assert present.stats["policy_documents_analysed"] > 0


# ---------------------------------------------------------------------------
# Group 3: values that could not be resolved
# ---------------------------------------------------------------------------


def disclosures(findings, rule_id: str) -> List[Any]:
    return [f for f in findings if f.Evidence[0].RuleId == rule_id]


def test_unresolvable_values_are_disclosed_as_informational_info_confirmed() -> None:
    # design.md, "解決不能な intrinsic function の扱い": the disclosure is
    # Informational + INFO + Confirmed. Confirmed is right because "this could
    # not be evaluated" is itself a deterministic fact; INFO and Informational
    # are right because no risk is being asserted.
    found = disclosures(review(UNRESOLVABLE).findings, UNRESOLVABLE_RULE_ID)

    assert len(found) == 2, "fixture has one Fn::ImportValue and one Ref"
    for item in found:
        assert item.FindingType == "Informational"
        assert item.Severity == "INFO"
        assert item.Confidence == "Confirmed"
        assert item.Normalized_Category == "IAM"
        assert item.Source == ["IAM Review"]
        assert item.Finding.startswith("[{0}]".format(UNRESOLVABLE_RULE_ID))
        assert item.SuggestedRemediation is None
    assert_all_validate(found)


def test_the_disclosure_names_the_intrinsic_and_the_location() -> None:
    found = disclosures(review(UNRESOLVABLE).findings, UNRESOLVABLE_RULE_ID)
    by_intrinsic = {
        "Fn::ImportValue": "Resources.ImportingRole.Properties.Policies.0."
        "PolicyDocument.Statement.0.Resource",
        "Ref": "Resources.ImportingRole.Properties.Policies.1."
        "PolicyDocument.Statement.0.Resource",
    }

    for intrinsic, json_path in by_intrinsic.items():
        matching = [f for f in found if intrinsic in f.Finding]
        assert len(matching) == 1, intrinsic
        assert ".".join(str(s) for s in matching[0].Location.TemplatePath) == json_path


def test_an_unresolvable_value_is_never_reported_as_dangerous() -> None:
    # The fixture's values are all unresolvable and none is dangerous once
    # resolved. Requirement 6 AC7's cross-account rule asks for a *literal*
    # account ID, and steering/security.md forbids asserting a risk on a guess.
    result = review(UNRESOLVABLE)

    assert [f for f in result.findings if f.FindingType == "Security"] == []
    assert result.stats["unresolvable_locations"] == 2


def test_a_policy_document_that_is_not_a_mapping_is_disclosed_not_raised() -> None:
    # design.md, `iacreview.iam` / Failure modes.
    found = disclosures(review(UNRESOLVABLE).findings, iam.MALFORMED_DOCUMENT_RULE_ID)

    assert len(found) == 1
    assert found[0].FindingType == "Informational"
    assert found[0].Severity == "INFO"
    assert found[0].Confidence == "Confirmed"
    assert found[0].Resource == "MalformedRole"
    assert review(UNRESOLVABLE).stats["malformed_documents"] == 1


def test_the_malformed_disclosure_does_not_quote_the_document() -> None:
    # A malformed policy document is untrusted content and is exactly where a
    # pasted credential would sit, so the disclosure names the type and the path
    # and nothing else.
    found = disclosures(review(UNRESOLVABLE).findings, iam.MALFORMED_DOCUMENT_RULE_ID)

    assert "2012-10-17" not in found[0].Finding
    assert all(entry.Excerpt is None for entry in found[0].Evidence)


def test_a_readable_document_cannot_be_disclosed_as_malformed() -> None:
    site = locate.policy_document_sites(
        locate.find_policy_documents(template.load_template(ALL_KINDS).doc)
    )[0]

    with pytest.raises(ValueError):
        iam.malformed_document_finding(site, template_file="t.yaml")


# ---------------------------------------------------------------------------
# Group 4: the Layer 2 input JSON
# ---------------------------------------------------------------------------


def extract(path: Path) -> Dict[str, Any]:
    relative = path.relative_to(PLUGIN_ROOT).as_posix()
    return iam.extract_policy_sites(
        template.load_template(path.resolve()).doc, template_file=relative
    )


def test_layer2_top_level_keys_are_the_three_design_specifies() -> None:
    # Spelled out here as well as in the module so a rename has to be deliberate:
    # Task 18.4 publishes these names as the Agent's input contract.
    assert sorted(extract(ALL_KINDS)) == [
        "attached_to",
        "deterministic_findings_summary",
        "policy_sites",
    ]
    assert sorted(iam.LAYER2_KEYS) == sorted(extract(ALL_KINDS))


def test_every_policy_site_entry_has_the_nine_documented_keys() -> None:
    expected = [
        "actions",
        "has_conditions",
        "json_path",
        "kind",
        "logical_id",
        "principals",
        "resources",
        "statement_count",
        "unresolvable_locations",
    ]
    sites = extract(ALL_KINDS)["policy_sites"]

    assert len(sites) == len(PolicyKind), "fixture holds one site of each kind"
    for entry in sites:
        assert sorted(entry) == expected
        assert sorted(iam.POLICY_SITE_KEYS) == expected


def test_policy_site_entries_are_internally_consistent() -> None:
    for entry in extract(ALL_KINDS)["policy_sites"]:
        assert entry["kind"] in {kind.value for kind in PolicyKind}
        assert entry["json_path"].startswith("Resources." + entry["logical_id"])
        assert len(entry["has_conditions"]) == entry["statement_count"]
        assert all(isinstance(flag, bool) for flag in entry["has_conditions"])


def test_intrinsics_reach_the_agent_as_text_never_as_a_function() -> None:
    # An Fn::Sub arrives with its substitutions still standing, so the Agent
    # never has to interpret an intrinsic function itself.
    inline = next(
        entry
        for entry in extract(ALL_KINDS)["policy_sites"]
        if entry["kind"] == PolicyKind.INLINE_ROLE_POLICY.value
    )

    assert inline["actions"] == ["s3:GetObject"]
    assert inline["resources"] == ["arn:aws:s3:::app-bucket/*"]
    assert all(isinstance(value, str) for value in inline["resources"])


def test_principals_are_unwrapped_from_their_type_key() -> None:
    trust = next(
        entry
        for entry in extract(ALL_KINDS)["policy_sites"]
        if entry["kind"] == PolicyKind.TRUST_POLICY.value
    )

    assert trust["principals"] == ["lambda.amazonaws.com"]


def test_unresolvable_locations_are_attributed_to_their_own_site() -> None:
    sites = extract(UNRESOLVABLE)["policy_sites"]
    gaps = {
        entry["json_path"]: entry["unresolvable_locations"]
        for entry in sites
        if entry["unresolvable_locations"]
    }

    assert gaps == {
        "Resources.ImportingRole.Properties.Policies.0.PolicyDocument": [
            "Resources.ImportingRole.Properties.Policies.0.PolicyDocument."
            "Statement.0.Resource"
        ],
        "Resources.ImportingRole.Properties.Policies.1.PolicyDocument": [
            "Resources.ImportingRole.Properties.Policies.1.PolicyDocument."
            "Statement.0.Resource"
        ],
    }


def test_attached_to_reports_the_resources_that_reference_each_owner() -> None:
    # The fixture's AWS::IAM::Policy points at the Role through
    # `Roles: [!Ref AppExecutionRole]`, which is the attachment Layer 2 needs to
    # know: this Role's permissions are also this Policy's.
    attached = extract(ALL_KINDS)["attached_to"]

    assert attached["AppExecutionRole"] == ["AppStandalonePolicy"]
    assert attached["AppBucketPolicy"] == []
    assert set(attached) == {
        entry["logical_id"] for entry in extract(ALL_KINDS)["policy_sites"]
    }


@pytest.mark.parametrize(
    "body,expected",
    [
        ({"Properties": {"Role": {"Ref": "AppRole"}}}, ["AppFunction"]),
        (
            {"Properties": {"Role": {"Fn::GetAtt": "AppRole.Arn"}}},
            ["AppFunction"],
        ),
        (
            {"Properties": {"Role": {"Fn::GetAtt": ["AppRole", "Arn"]}}},
            ["AppFunction"],
        ),
        (
            {"Properties": {"Text": {"Fn::Sub": "${AppRole.Arn} in ${AWS::Region}"}}},
            ["AppFunction"],
        ),
        (
            {"Properties": {"Role": {"Fn::If": ["C", {"Ref": "AppRole"}, "none"]}}},
            ["AppFunction"],
        ),
        ({"Properties": {"Role": {"Ref": "AWS::AccountId"}}}, []),
        ({"Properties": {"Role": "AppRole"}}, []),
        ({"Properties": {"Role": {"Ref": ["AppRole"]}}}, []),
    ],
    ids=[
        "ref",
        "getatt-string",
        "getatt-list",
        "sub",
        "fn-if-branch",
        "pseudo-parameter-ignored",
        "plain-string-is-not-a-reference",
        "malformed-ref-ignored",
    ],
)
def test_attachments_reads_ref_getatt_and_sub(
    body: Dict[str, Any], expected: List[str]
) -> None:
    doc = {"Resources": {"AppRole": {"Type": "AWS::IAM::Role"}, "AppFunction": body}}

    assert iam.attachments(doc, ["AppRole"]) == {"AppRole": expected}


def test_attachments_never_lists_a_resource_as_its_own_referrer() -> None:
    doc = {
        "Resources": {
            "AppRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {"RoleName": {"Ref": "AppRole"}},
            }
        }
    }

    assert iam.attachments(doc, ["AppRole"]) == {"AppRole": []}


@pytest.mark.parametrize(
    "doc", [None, "text", {}, {"Resources": []}, {"Resources": {"A": None}}]
)
def test_attachments_accepts_an_untrusted_document(doc: Any) -> None:
    assert iam.attachments(doc, ["AppRole"]) == {"AppRole": []}


@pytest.mark.parametrize(
    "nest",
    [
        lambda inner: {"Nested": inner},
        lambda inner: [inner],
        lambda inner: {"Fn::Sub": ["${Local}", {"Local": inner}]},
    ],
    ids=["mapping", "sequence", "fn-sub-variable-map"],
)
def test_attachments_bounds_deeply_nested_input(nest) -> None:
    # A Template is untrusted input, so depth has to cost bounded work rather
    # than a RecursionError. The Fn::Sub variable map is the case worth naming:
    # it is walked as an ordinary expression, so its depth has to keep
    # accumulating instead of restarting.
    body: Any = {"Ref": "AppRole"}
    for _ in range(2000):
        body = nest(body)
    doc = {
        "Resources": {
            "AppRole": {"Type": "AWS::IAM::Role"},
            "AppFunction": {"Properties": body},
        }
    }

    assert iam.attachments(doc, ["AppRole"]) == {"AppRole": []}


def test_summary_entries_name_the_rule_resource_and_severity() -> None:
    summary = extract(DANGEROUS)["deterministic_findings_summary"]
    layer1 = layer1_findings(DANGEROUS)

    assert sorted(iam.SUMMARY_FINDING_KEYS) == ["resource", "rule", "severity"]
    assert summary == [
        {
            "rule": item.Evidence[0].RuleId,
            "resource": item.Resource,
            "severity": item.Severity,
        }
        for item in layer1
    ]


def test_summary_covers_every_layer_1_finding() -> None:
    # Requirement 2 AC14 / AC15 depend on this: the Agent is told not to restate
    # what Layer 1 found, which only works if it was told all of it.
    summary = extract(DANGEROUS)["deterministic_findings_summary"]

    assert len(summary) == len(layer1_findings(DANGEROUS))
    assert {entry["rule"] for entry in summary} <= set(detectors.DETECTOR_NAMES)


def test_the_layer2_json_is_serializable_and_byte_stable() -> None:
    # Requirement 16 AC11. Task 18.4's script writes this to stdout, so two runs
    # over the same Template must produce identical bytes.
    first = json.dumps(extract(ALL_KINDS), sort_keys=True, indent=2)
    second = json.dumps(extract(ALL_KINDS), sort_keys=True, indent=2)

    assert first == second


def test_a_template_with_no_iam_yields_an_empty_inventory() -> None:
    assert extract(NO_IAM[0]) == {
        "policy_sites": [],
        "attached_to": {},
        "deterministic_findings_summary": [],
    }


# ---------------------------------------------------------------------------
# Failing safely on input that is not reviewable
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,expected",
    [
        ("invalid/malformed_syntax.yaml", TemplateParseError),
        ("invalid/malformed_syntax.json", TemplateParseError),
        ("invalid/empty_file.yaml", TemplateParseError),
        ("invalid/no_resources.yaml", NotReviewableError),
        ("invalid/empty_resources.json", NotReviewableError),
    ],
)
def test_unreviewable_input_raises_rather_than_reporting_a_clean_review(
    name: str, expected: type
) -> None:
    # Folding these into `errors` would let an empty findings list read as "IAM
    # reviewed, nothing found". design.md's collect() loop catches them and the
    # other Sources still run.
    with pytest.raises(expected):
        review(FIXTURES / name)


def test_a_target_outside_the_workspace_is_refused(tmp_path: Path) -> None:
    outside = tmp_path / "template.yaml"
    outside.write_text("Resources: {}\n", encoding="utf-8")

    with pytest.raises(PathContainmentError):
        iam.run_and_normalize(outside, workspace_root=PLUGIN_ROOT)
