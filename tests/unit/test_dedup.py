"""Tests for :mod:`iacreview.dedup`.

The completion condition of Task 15.1 is design.md's worked example: four
Findings on ``AppExecutionRole``, one from each Source, become one entry with the
strongest classification and all four Evidence entries.
:data:`WORKED_EXAMPLE_INPUT` and :data:`WORKED_EXAMPLE_OUTPUT` are transcribed
from that section by hand rather than derived from the implementation, so the
test fails if the code and the design part ways.

One field of the transcribed output differs from what design.md originally
printed. The example showed ``Confidence: "Confirmed"`` alongside
``"Agent Review"`` in ``Source``, which Requirement 7 AC10 forbids and
``finding.validate`` rejects; the merge caps the maximum at ``Likely`` when the
Source union includes the agent. design.md records the correction as
[Correction] C-8, and :func:`test_the_worked_example_output_is_schema_valid`
pins the invariant so the two cannot drift apart again.

Beyond the example, the cases here are the ones the algorithm's guarantees rest
on: the two exclusions from matching (``Other``, and no ``Resource``),
permutation invariance, idempotence, and untouched pass-through of a Finding that
matches nothing. The same-Source group is from checkpoint 12, where IAM Review
produced 11 Findings on one resource from 11 independent detectors, all sharing a
``TemplatePath``: merging is not only a cross-Source phenomenon.
"""

from __future__ import annotations

import copy
import random
from typing import Any, Dict, List, Optional

import pytest

from iacreview import finding as fmod
from iacreview.dedup import dedup_key, deduplicate
from iacreview.finding import (
    UNASSIGNED_ID,
    Evidence,
    Finding,
    Location,
    to_dict,
    validate,
)

TEMPLATE_FILE = "templates/app.yaml"

POLICY_PATH = [
    "Resources",
    "AppExecutionRole",
    "Properties",
    "Policies",
    0,
    "PolicyDocument",
]
STATEMENT_PATH = POLICY_PATH + ["Statement", 0]
ACTION_PATH = STATEMENT_PATH + ["Action"]


# ---------------------------------------------------------------------------
# Payload helpers
# ---------------------------------------------------------------------------


def from_payload(payload: Dict[str, Any]) -> Finding:
    """Build a Finding from a report-shaped dict, without validating it.

    ``finding.from_dict`` cannot be used: it enforces ``ID >= 1``, and a Finding
    on its way into dedup carries :data:`~iacreview.finding.UNASSIGNED_ID`
    because IDs are assigned after sorting.
    """
    data = copy.deepcopy(payload)
    return Finding(
        ID=data.get("ID", UNASSIGNED_ID),
        Normalized_Category=data["Normalized_Category"],
        FindingType=data["FindingType"],
        Severity=data["Severity"],
        Confidence=data["Confidence"],
        Source=list(data["Source"]),
        Resource=data["Resource"],
        Location=Location(**data["Location"]),
        Finding=data["Finding"],
        WhyItMatters=data["WhyItMatters"],
        Evidence=[Evidence(**entry) for entry in data["Evidence"]],
        Recommendation=data["Recommendation"],
        SuggestedRemediation=data["SuggestedRemediation"],
    )


def location(
    *,
    line: Optional[int] = None,
    column: Optional[int] = None,
    template_path: Optional[List[Any]] = None,
) -> Dict[str, Any]:
    return {
        "File": TEMPLATE_FILE,
        "Line": line,
        "Column": column,
        "TemplatePath": template_path,
    }


def payload(**overrides: Any) -> Dict[str, Any]:
    """A minimal report-shaped Finding payload, overridable field by field."""
    base: Dict[str, Any] = {
        "ID": UNASSIGNED_ID,
        "Normalized_Category": "Encryption",
        "FindingType": "Security",
        "Severity": "MEDIUM",
        "Confidence": "Confirmed",
        "Source": ["cfn-guard"],
        "Resource": "AppBucket",
        "Location": location(template_path=["Resources", "AppBucket"]),
        "Finding": "[s3_bucket_encryption] Default encryption is not configured.",
        "WhyItMatters": "Unencrypted objects are readable from a raw storage copy.",
        "Evidence": [
            {
                "Source": "cfn-guard",
                "Detail": "provided: absent, expected: present",
                "RuleId": "s3_bucket_encryption",
                "Excerpt": None,
            }
        ],
        "Recommendation": "Configure BucketEncryption on the bucket.",
        "SuggestedRemediation": None,
    }
    base.update(overrides)
    return base


def agent_payload(**overrides: Any) -> Dict[str, Any]:
    """An agent Finding payload: not ``Confirmed``, and carrying an Excerpt."""
    base = payload(
        Confidence="Likely",
        Source=["Agent Review"],
        FindingType="BestPractice",
        Finding="The bucket may hold data that policy requires to be encrypted.",
        Evidence=[
            {
                "Source": "Agent Review",
                "Detail": "AppBucket is written to by AppFunction.",
                "RuleId": None,
                "Excerpt": "AppBucket:\n  Type: AWS::S3::Bucket",
            }
        ],
    )
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# design.md worked example, transcribed
# ---------------------------------------------------------------------------

WORKED_EXAMPLE_INPUT: List[Dict[str, Any]] = [
    {
        "ID": UNASSIGNED_ID,
        "Normalized_Category": "IAM",
        "FindingType": "Security",
        "Severity": "HIGH",
        "Confidence": "Confirmed",
        "Source": ["cfn-lint"],
        "Resource": "AppExecutionRole",
        "Location": location(line=42, column=9, template_path=ACTION_PATH),
        "Finding": '[W3037] IAM action "s3:GetObjects" is not a valid action.',
        "WhyItMatters": (
            "An invalid or malformed IAM action prevents the policy from granting "
            "the intended access, or grants access that was not intended."
        ),
        "Evidence": [
            {
                "Source": "cfn-lint",
                "Detail": "Rule W3037 (https://github.com/aws-cloudformation/cfn-lint/...)",
                "RuleId": "W3037",
                "Excerpt": None,
            }
        ],
        "Recommendation": "Correct the IAM action name to a valid service action.",
        "SuggestedRemediation": None,
    },
    {
        "ID": UNASSIGNED_ID,
        "Normalized_Category": "IAM",
        "FindingType": "Security",
        "Severity": "MEDIUM",
        "Confidence": "Confirmed",
        "Source": ["cfn-guard"],
        "Resource": "AppExecutionRole",
        "Location": location(template_path=POLICY_PATH),
        "Finding": (
            "[iam_policy_no_star_star] A policy statement allows all actions on "
            "all resources."
        ),
        "WhyItMatters": (
            'A statement with Action "*" and Resource "*" grants unrestricted access.'
        ),
        "Evidence": [
            {
                "Source": "cfn-guard",
                "Detail": 'provided: "*", expected: not "*"',
                "RuleId": "iam_policy_no_star_star",
                "Excerpt": None,
            }
        ],
        "Recommendation": "Restrict Action and Resource to the minimum required.",
        "SuggestedRemediation": (
            'Replace Action "*" with the specific actions the role needs.'
        ),
    },
    {
        "ID": UNASSIGNED_ID,
        "Normalized_Category": "IAM",
        "FindingType": "Security",
        "Severity": "CRITICAL",
        "Confidence": "Confirmed",
        "Source": ["IAM Review"],
        "Resource": "AppExecutionRole",
        "Location": location(template_path=STATEMENT_PATH),
        "Finding": (
            '[star_action_star_resource] Statement 0 allows Action "*" on Resource "*".'
        ),
        "WhyItMatters": (
            "This grants every permission in the account to any principal that can "
            "assume the role."
        ),
        "Evidence": [
            {
                "Source": "IAM Review",
                "Detail": 'Effect=Allow, Action=["*"], Resource=["*"]',
                "RuleId": "star_action_star_resource",
                "Excerpt": None,
            }
        ],
        "Recommendation": (
            "Enumerate the specific actions and resource ARNs the role requires."
        ),
        "SuggestedRemediation": (
            "Replace the wildcard statement with least-privilege statements."
        ),
    },
    {
        "ID": UNASSIGNED_ID,
        "Normalized_Category": "IAM",
        "FindingType": "BestPractice",
        "Severity": "MEDIUM",
        "Confidence": "Likely",
        "Source": ["Agent Review"],
        "Resource": "AppExecutionRole",
        "Location": location(template_path=["Resources", "AppExecutionRole"]),
        "Finding": (
            "The role is attached to AppFunction, which only reads from AppBucket, "
            "so the granted permissions may be far broader than the function "
            "requires."
        ),
        "WhyItMatters": (
            "Excess permissions increase the blast radius if the function is "
            "compromised."
        ),
        "Evidence": [
            {
                "Source": "Agent Review",
                "Detail": (
                    "AppExecutionRole is referenced by AppFunction.Properties.Role"
                ),
                "RuleId": None,
                "Excerpt": (
                    "AppFunction:\n  Type: AWS::Lambda::Function\n  Properties:\n"
                    "    Role: !GetAtt AppExecutionRole.Arn"
                ),
            }
        ],
        "Recommendation": (
            "Scope the policy to s3:GetObject on AppBucket and the CloudWatch Logs "
            "actions the runtime needs."
        ),
        "SuggestedRemediation": None,
    },
]

#: The merged entry design.md prints, with ``ID`` as dedup leaves it and
#: ``Confidence`` as [Correction] C-8 requires.
WORKED_EXAMPLE_OUTPUT: Dict[str, Any] = {
    "ID": UNASSIGNED_ID,
    "Normalized_Category": "IAM",
    "FindingType": "Security",
    "Severity": "CRITICAL",
    "Confidence": "Likely",
    "Source": ["cfn-lint", "cfn-guard", "IAM Review", "Agent Review"],
    "Resource": "AppExecutionRole",
    "Location": location(line=42, column=9, template_path=ACTION_PATH),
    "Finding": '[W3037] IAM action "s3:GetObjects" is not a valid action.',
    "WhyItMatters": (
        "An invalid or malformed IAM action prevents the policy from granting the "
        "intended access, or grants access that was not intended."
    ),
    "Evidence": [
        WORKED_EXAMPLE_INPUT[0]["Evidence"][0],
        WORKED_EXAMPLE_INPUT[1]["Evidence"][0],
        WORKED_EXAMPLE_INPUT[2]["Evidence"][0],
        WORKED_EXAMPLE_INPUT[3]["Evidence"][0],
    ],
    "Recommendation": "Correct the IAM action name to a valid service action.",
    "SuggestedRemediation": (
        'Replace Action "*" with the specific actions the role needs.'
    ),
}


@pytest.fixture
def worked_example() -> List[Finding]:
    return [from_payload(entry) for entry in WORKED_EXAMPLE_INPUT]


# ---------------------------------------------------------------------------
# (a) the worked example
# ---------------------------------------------------------------------------


def test_the_worked_example_merges_into_the_documented_finding(
    worked_example: List[Finding],
) -> None:
    """Task 15.1 completion condition: 4 in, exactly the documented 1 out."""
    (merged,) = deduplicate(worked_example)

    assert to_dict(merged) == WORKED_EXAMPLE_OUTPUT


def test_the_worked_example_output_is_schema_valid(
    worked_example: List[Finding],
) -> None:
    """The merged entry survives ``validate`` once the report numbers it.

    The reason ``Confidence`` is capped: with ``Confirmed`` this raises, because
    ``Agent Review`` is in ``Source`` (Requirement 7 AC10).
    """
    (merged,) = deduplicate(worked_example)
    merged.ID = 1

    validate(merged)


def test_a_confirmed_maximum_is_capped_when_an_agent_detected_it() -> None:
    """AC9's maximum, then AC10's ceiling ([Correction] C-8)."""
    merged_findings = deduplicate(
        [from_payload(payload()), from_payload(agent_payload())]
    )

    (merged,) = merged_findings
    assert merged.Source == ["cfn-guard", "Agent Review"]
    assert merged.Confidence == "Likely"


def test_the_cap_does_not_promote_a_lower_confidence() -> None:
    """A ``Contextual`` group with an agent in it stays ``Contextual``."""
    contextual = agent_payload(Confidence="Contextual")
    other_contextual = agent_payload(
        Confidence="Contextual",
        Finding="The bucket may be subject to a retention policy.",
    )
    (merged,) = deduplicate(
        [from_payload(contextual), from_payload(other_contextual)]
    )

    assert merged.Confidence == "Contextual"


def test_a_confirmed_maximum_survives_without_an_agent_source() -> None:
    """The cap is conditional: deterministic-only groups keep ``Confirmed``."""
    lint = payload(
        Source=["cfn-lint"],
        Confidence="Confirmed",
        Finding="[W3045] Both AccessControl and BucketPolicy are configured.",
        Evidence=[
            {
                "Source": "cfn-lint",
                "Detail": "Rule W3045",
                "RuleId": "W3045",
                "Excerpt": None,
            }
        ],
    )
    (merged,) = deduplicate([from_payload(payload()), from_payload(lint)])

    assert merged.Confidence == "Confirmed"
    assert merged.Source == ["cfn-lint", "cfn-guard"]


# ---------------------------------------------------------------------------
# (b) Other, (c) Resource: null
# ---------------------------------------------------------------------------


def test_two_other_findings_on_one_resource_stay_separate() -> None:
    """Requirement 14 AC3: ``Other`` matched nothing, so it merges with nothing."""
    first = agent_payload(
        Normalized_Category="Other",
        Finding="The bucket name encodes an environment, which may be a convention.",
    )
    second = agent_payload(
        Normalized_Category="Other",
        Finding="The bucket has no lifecycle configuration.",
    )

    result = deduplicate([from_payload(first), from_payload(second)])

    assert len(result) == 2
    assert [f.Source for f in result] == [["Agent Review"], ["Agent Review"]]
    assert sorted(f.Finding for f in result) == sorted(
        [first["Finding"], second["Finding"]]
    )


def test_two_resourceless_findings_in_one_category_stay_separate() -> None:
    """Requirement 14 AC6: ``null`` does not match ``null``."""
    parse_error = payload(
        Resource=None,
        Normalized_Category="TemplateQuality",
        Finding="[E0000] Template section Outputs is malformed.",
        Location=location(line=3),
    )
    unused_parameter = payload(
        Resource=None,
        Normalized_Category="TemplateQuality",
        Finding="[W2001] Parameter Unused is not used.",
        Location=location(line=9),
    )

    result = deduplicate(
        [from_payload(parse_error), from_payload(unused_parameter)]
    )

    assert len(result) == 2
    assert all(f.Resource is None for f in result)
    assert sorted(f.Finding for f in result) == sorted(
        [parse_error["Finding"], unused_parameter["Finding"]]
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"Normalized_Category": "Other"},
        {"Resource": None},
        {"Normalized_Category": "Other", "Resource": None},
    ],
    ids=["other", "no-resource", "both"],
)
def test_excluded_findings_have_no_dedup_key(overrides: Dict[str, Any]) -> None:
    """The exclusions are visible on the key function itself."""
    assert dedup_key(from_payload(agent_payload(**overrides))) is None


def test_an_eligible_finding_keys_on_resource_and_category() -> None:
    """Requirement 14 AC5."""
    assert dedup_key(from_payload(payload())) == ("AppBucket", "Encryption")


# ---------------------------------------------------------------------------
# (d) permutation invariance
# ---------------------------------------------------------------------------


def mixed_input() -> List[Finding]:
    """A group to merge, a lone group, an ``Other``, and two resourceless ones."""
    return [from_payload(entry) for entry in WORKED_EXAMPLE_INPUT] + [
        from_payload(payload()),
        from_payload(agent_payload()),
        from_payload(payload(Resource="OtherBucket", Normalized_Category="Logging")),
        from_payload(agent_payload(Normalized_Category="Other")),
        from_payload(
            agent_payload(
                Normalized_Category="Other",
                Finding="A second unmapped observation on the same bucket.",
            )
        ),
        from_payload(payload(Resource=None, Normalized_Category="TemplateQuality")),
        from_payload(
            payload(
                Resource=None,
                Normalized_Category="TemplateQuality",
                Finding="[W2001] Parameter Unused is not used.",
            )
        ),
    ]


def test_permuting_the_input_does_not_change_the_output() -> None:
    """Requirement 16 AC11: the result depends on contents, not arrival order.

    Seeded shuffles rather than every permutation: the input has 11 Findings, and
    the seed keeps the cases reproducible when one of them fails.
    """
    expected = [to_dict(f) for f in deduplicate(mixed_input())]
    rng = random.Random(20240115)

    for _ in range(200):
        shuffled = mixed_input()
        rng.shuffle(shuffled)
        assert [to_dict(f) for f in deduplicate(shuffled)] == expected


def test_reversing_the_input_does_not_change_the_output() -> None:
    """The permutation most likely to expose an input-order dependence."""
    forward = deduplicate(mixed_input())
    backward = deduplicate(list(reversed(mixed_input())))

    assert [to_dict(f) for f in backward] == [to_dict(f) for f in forward]


# ---------------------------------------------------------------------------
# (e) idempotence
# ---------------------------------------------------------------------------


def test_deduplicating_twice_is_the_same_as_once() -> None:
    """Property 3: ``deduplicate(deduplicate(x)) == deduplicate(x)``."""
    once = deduplicate(mixed_input())
    twice = deduplicate(once)

    assert [to_dict(f) for f in twice] == [to_dict(f) for f in once]


def test_a_merged_finding_re_merged_is_unchanged(
    worked_example: List[Finding],
) -> None:
    """A merged entry is its own group of one on the second pass."""
    (merged,) = deduplicate(worked_example)

    assert deduplicate([merged])[0] is merged


# ---------------------------------------------------------------------------
# (f) untouched pass-through
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "entry",
    [payload(), agent_payload(), agent_payload(Normalized_Category="Other"),
     payload(Resource=None, Normalized_Category="TemplateQuality")],
    ids=["unique-key", "unique-key-agent", "other", "no-resource"],
)
def test_a_finding_that_matches_nothing_passes_through_untouched(
    entry: Dict[str, Any],
) -> None:
    """Requirement 14 AC13 / Property 11: the same object, field for field."""
    original = from_payload(entry)
    before = to_dict(original)

    (result,) = deduplicate([original])

    assert result is original
    assert to_dict(result) == before


# ---------------------------------------------------------------------------
# Merge rules, one field at a time (Requirement 14 AC8-AC12)
# ---------------------------------------------------------------------------


def test_severity_is_the_maximum_across_sources() -> None:
    """Requirement 14 AC8."""
    low = payload(Severity="LOW", Source=["cfn-lint"], Finding="[W1] a")
    high = payload(Severity="HIGH", Finding="[G1] b")

    (merged,) = deduplicate([from_payload(low), from_payload(high)])

    assert merged.Severity == "HIGH"


def test_finding_type_uses_merge_precedence_not_schema_order() -> None:
    """Requirement 14 AC10: ``Security`` outranks ``Validity``."""
    validity = payload(
        FindingType="Validity", Source=["cfn-lint"], Finding="[E3002] a"
    )
    security = payload(FindingType="Security", Finding="[G1] b")

    (merged,) = deduplicate([from_payload(validity), from_payload(security)])

    assert merged.FindingType == "Security"


def test_evidence_is_concatenated_in_source_order() -> None:
    """Requirement 14 AC11, whatever order the Findings arrived in."""
    findings = [from_payload(entry) for entry in reversed(WORKED_EXAMPLE_INPUT)]

    (merged,) = deduplicate(findings)

    assert [entry.Source for entry in merged.Evidence] == [
        "cfn-lint",
        "cfn-guard",
        "IAM Review",
        "Agent Review",
    ]


def test_the_source_union_is_sorted_and_deduplicated() -> None:
    """Requirement 14 AC12, with two Findings from the same Source."""
    findings = [
        from_payload(payload(Source=["IAM Review"], Finding="[iam_a] a")),
        from_payload(payload(Source=["IAM Review"], Finding="[iam_b] b")),
        from_payload(payload(Source=["cfn-lint"], Finding="[W1] c")),
    ]

    (merged,) = deduplicate(findings)

    assert merged.Source == ["cfn-lint", "IAM Review"]


def test_the_location_with_a_line_number_wins() -> None:
    """Design judgement: a clickable Location beats a Source-order one."""
    guard = payload(Finding="[G1] a")
    lint = payload(
        Source=["cfn-lint"],
        Finding="[W1] b",
        Location=location(line=17, column=3, template_path=["Resources", "AppBucket"]),
    )
    # cfn-guard first in the list, cfn-lint first in Source order: the Line is
    # what decides, not either of those.
    (merged,) = deduplicate([from_payload(guard), from_payload(lint)])

    assert merged.Location.Line == 17


def test_the_representative_wording_comes_from_the_first_source() -> None:
    """Design judgement: deterministic phrasing over agent phrasing."""
    (merged,) = deduplicate(
        [from_payload(agent_payload()), from_payload(payload())]
    )

    assert merged.Finding == payload()["Finding"]
    assert merged.WhyItMatters == payload()["WhyItMatters"]
    assert merged.Recommendation == payload()["Recommendation"]


def test_suggested_remediation_is_the_first_non_null_in_source_order() -> None:
    """Design judgement, including the all-``null`` case."""
    lint = payload(Source=["cfn-lint"], Finding="[W1] a", SuggestedRemediation=None)
    guard = payload(Finding="[G1] b", SuggestedRemediation="Set BucketEncryption.")

    (merged,) = deduplicate([from_payload(lint), from_payload(guard)])
    assert merged.SuggestedRemediation == "Set BucketEncryption."

    (all_null,) = deduplicate(
        [from_payload(lint), from_payload(payload(Finding="[G1] b"))]
    )
    assert all_null.SuggestedRemediation is None


def test_a_merged_finding_carries_the_unassigned_id() -> None:
    """``ID`` is the report's to assign, after sorting (Requirement 7 AC1)."""
    (merged,) = deduplicate(
        [from_payload(payload()), from_payload(payload(Finding="[G2] b"))]
    )

    assert merged.ID == UNASSIGNED_ID


# ---------------------------------------------------------------------------
# Same Source, same location: the checkpoint 12 case
# ---------------------------------------------------------------------------


def iam_detector_findings(count: int) -> List[Finding]:
    """``count`` IAM Review Findings on one statement, one per detector.

    The shape checkpoint 12 produced: 11 independent detectors firing on one
    resource, every Finding with the same Source and the same ``TemplatePath``.
    """
    return [
        from_payload(
            payload(
                Normalized_Category="IAM",
                Source=["IAM Review"],
                Resource="AppExecutionRole",
                Severity="LOW" if index else "CRITICAL",
                Location=location(template_path=STATEMENT_PATH),
                Finding="[detector_{0:02d}] Statement 0 is over-permissive.".format(index),
                Evidence=[
                    {
                        "Source": "IAM Review",
                        "Detail": "detector {0:02d} matched".format(index),
                        "RuleId": "detector_{0:02d}".format(index),
                        "Excerpt": None,
                    }
                ],
            )
        )
        for index in range(count)
    ]


def test_one_source_detecting_a_location_many_times_merges_to_one() -> None:
    """Same-Source merging is a real case, not only a cross-Source one."""
    findings = iam_detector_findings(11)

    (merged,) = deduplicate(findings)

    assert merged.Source == ["IAM Review"]
    assert merged.Severity == "CRITICAL"
    assert len(merged.Evidence) == 11
    assert [entry.RuleId for entry in merged.Evidence] == [
        "detector_{0:02d}".format(index) for index in range(11)
    ]


def test_a_same_source_group_is_order_independent() -> None:
    """The ``Finding`` tie-breaker is what fixes the order inside one Source."""
    forward = deduplicate(iam_detector_findings(11))
    backward = deduplicate(list(reversed(iam_detector_findings(11))))

    assert to_dict(backward[0]) == to_dict(forward[0])


def test_identical_findings_merge_without_ordering_ambiguity() -> None:
    """Two Findings equal in every field: the result cannot depend on order."""
    duplicated = [from_payload(payload()), from_payload(payload())]

    (merged,) = deduplicate(duplicated)

    assert len(merged.Evidence) == 2
    assert merged.Source == ["cfn-guard"]


# ---------------------------------------------------------------------------
# Shape of the operation
# ---------------------------------------------------------------------------


def test_deduplicate_returns_a_new_list_and_does_not_mutate_the_input() -> None:
    """The caller's list and Findings are left alone."""
    findings = mixed_input()
    before = [to_dict(f) for f in findings]

    result = deduplicate(findings)

    assert result is not findings
    assert [to_dict(f) for f in findings] == before


def test_an_empty_input_produces_an_empty_output() -> None:
    assert deduplicate([]) == []


def test_every_merged_finding_validates_after_id_assignment() -> None:
    """Nothing dedup produces can be unrepresentable in a report."""
    for index, f in enumerate(deduplicate(mixed_input()), start=1):
        f.ID = index
        validate(f)


def test_the_category_hook_state_does_not_change_the_result() -> None:
    """dedup reads ``Normalized_Category`` as an opaque string.

    Guards against the exclusion of ``Other`` accidentally being routed through
    the categories mapping file, which would make dedup depend on installation
    state.
    """
    findings = mixed_input()
    with_hook = [to_dict(f) for f in deduplicate(findings)]

    fmod.set_category_validator(lambda name: False)
    try:
        without_hook = [to_dict(f) for f in deduplicate(mixed_input())]
    finally:
        fmod.set_category_validator(None)

    assert without_hook == with_hook
