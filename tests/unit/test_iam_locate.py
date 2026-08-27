"""Tests for :mod:`iacreview.iam.locate` (Task 13.1; Requirement 6 AC1, AC12).

Three groups, in the order the module's contract matters:

1. :data:`FIXTURE_SITES` -- the completion condition. ``iam_all_policy_kinds.yaml``
   holds one site of each of the nine ``PolicyKind`` values, and each is asserted
   by ``logical_id`` and ``json_path``. The parametrization is generated *from
   the enum*, so a tenth kind added to ``PolicyKind`` without a fixture entry
   fails collection rather than passing unnoticed.
2. Malformed documents. A ``PolicyDocument`` that is a JSON string, a bare list
   of statements, or an empty YAML value must produce a site carrying a reason,
   never an exception (design.md, ``iacreview.iam`` / Failure modes).
3. Untrusted structure. Every traversal step is fed the wrong type to confirm it
   contributes fewer sites instead of raising.

The fixture is loaded through :func:`iacreview.template.load_template` rather
than ``yaml.safe_load`` so the tests exercise the same document shape the review
pipeline sees, including intrinsics in long form.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest

# tests/unit/test_iam_locate.py -> tests/unit -> tests -> plugin root
PLUGIN_ROOT: Path = Path(__file__).resolve().parents[2]
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

from iacreview import template
from iacreview.iam import locate
from iacreview.iam.locate import PolicyKind, PolicySite

FIXTURE: Path = PLUGIN_ROOT / "tests" / "fixtures" / "valid" / "iam_all_policy_kinds.yaml"


# ---------------------------------------------------------------------------
# The nine kinds
# ---------------------------------------------------------------------------

#: kind -> (logical_id, json_path) expected from the fixture. Written by hand
#: from the fixture, not read back from the implementation.
FIXTURE_SITES: Dict[PolicyKind, Tuple[str, str]] = {
    PolicyKind.TRUST_POLICY: (
        "AppExecutionRole",
        "Resources.AppExecutionRole.Properties.AssumeRolePolicyDocument",
    ),
    PolicyKind.INLINE_ROLE_POLICY: (
        "AppExecutionRole",
        "Resources.AppExecutionRole.Properties.Policies.0.PolicyDocument",
    ),
    PolicyKind.PERMISSIONS_BOUNDARY: (
        "AppExecutionRole",
        "Resources.AppExecutionRole.Properties.PermissionsBoundary",
    ),
    PolicyKind.MANAGED_POLICY: (
        "AppManagedPolicy",
        "Resources.AppManagedPolicy.Properties.PolicyDocument",
    ),
    PolicyKind.STANDALONE_POLICY: (
        "AppStandalonePolicy",
        "Resources.AppStandalonePolicy.Properties.PolicyDocument",
    ),
    PolicyKind.INLINE_USER_POLICY: (
        "AppUser",
        "Resources.AppUser.Properties.Policies.0.PolicyDocument",
    ),
    PolicyKind.INLINE_GROUP_POLICY: (
        "AppGroup",
        "Resources.AppGroup.Properties.Policies.0.PolicyDocument",
    ),
    PolicyKind.RESOURCE_POLICY: (
        "AppBucketPolicy",
        "Resources.AppBucketPolicy.Properties.PolicyDocument",
    ),
    PolicyKind.LAMBDA_PERMISSION: (
        "AppInvokePermission",
        "Resources.AppInvokePermission.Properties",
    ),
}


@pytest.fixture(scope="module")
def fixture_sites() -> List[PolicySite]:
    loaded = template.load_template(FIXTURE)
    return locate.find_policy_documents(loaded.doc)


def _only(sites: List[PolicySite], kind: PolicyKind) -> PolicySite:
    matching = [site for site in sites if site.kind is kind]
    assert len(matching) == 1, "expected exactly one {0} site, got {1}".format(
        kind.value, [site.json_path for site in matching]
    )
    return matching[0]


def test_every_policy_kind_has_a_fixture_expectation() -> None:
    """A new PolicyKind must come with a fixture entry, or this fails first."""
    assert set(FIXTURE_SITES) == set(PolicyKind)
    assert len(PolicyKind) == 9


@pytest.mark.parametrize(
    "kind", list(FIXTURE_SITES), ids=[kind.value for kind in FIXTURE_SITES]
)
def test_each_kind_is_located_with_its_logical_id_and_json_path(
    kind: PolicyKind, fixture_sites: List[PolicySite]
) -> None:
    """Task 13.1 completion condition, one kind per case."""
    expected_logical_id, expected_json_path = FIXTURE_SITES[kind]
    site = _only(fixture_sites, kind)

    assert site.logical_id == expected_logical_id
    assert site.json_path == expected_json_path


def test_fixture_yields_exactly_the_nine_expected_sites(
    fixture_sites: List[PolicySite],
) -> None:
    """No extra sites: a duplicated or spurious site would skew every detector."""
    assert len(fixture_sites) == len(FIXTURE_SITES)


def test_sites_are_returned_in_template_order(fixture_sites: List[PolicySite]) -> None:
    """Requirement 16 AC11: the same file always yields the same order."""
    logical_ids = [site.logical_id for site in fixture_sites]

    assert logical_ids == [
        "AppExecutionRole",
        "AppExecutionRole",
        "AppExecutionRole",
        "AppManagedPolicy",
        "AppStandalonePolicy",
        "AppUser",
        "AppGroup",
        "AppBucketPolicy",
        "AppInvokePermission",
    ]


def test_repeated_calls_return_equal_results(fixture_sites: List[PolicySite]) -> None:
    again = locate.find_policy_documents(template.load_template(FIXTURE).doc)

    assert [(s.logical_id, s.kind, s.json_path) for s in again] == [
        (s.logical_id, s.kind, s.json_path) for s in fixture_sites
    ]


def test_document_is_the_parsed_value_at_the_path(
    fixture_sites: List[PolicySite],
) -> None:
    trust = _only(fixture_sites, PolicyKind.TRUST_POLICY)

    assert trust.document["Statement"][0]["Action"] == "sts:AssumeRole"


def test_intrinsics_reach_the_site_unevaluated(
    fixture_sites: List[PolicySite],
) -> None:
    """``!Ref AWS::AccountId`` stays data; nothing here resolves it."""
    permission = _only(fixture_sites, PolicyKind.LAMBDA_PERMISSION)

    assert permission.document["SourceAccount"] == {"Ref": "AWS::AccountId"}


def test_lambda_permission_document_is_the_properties_mapping(
    fixture_sites: List[PolicySite],
) -> None:
    """Principal / SourceAccount / SourceArn must arrive together."""
    permission = _only(fixture_sites, PolicyKind.LAMBDA_PERMISSION)

    assert permission.document["Principal"] == "events.amazonaws.com"
    assert permission.expects_policy_document is False
    assert permission.has_policy_document is False
    assert permission.malformed_reason is None


def test_permissions_boundary_records_an_arn_not_a_document(
    fixture_sites: List[PolicySite],
) -> None:
    """The boundary policy lives outside the Template: location only."""
    boundary = _only(fixture_sites, PolicyKind.PERMISSIONS_BOUNDARY)

    assert boundary.document == "arn:aws:iam::123456789012:policy/AppBoundary"
    assert boundary.expects_policy_document is False
    assert boundary.malformed_reason is None


def test_seven_kinds_carry_an_analysable_document(
    fixture_sites: List[PolicySite],
) -> None:
    analysable = locate.policy_document_sites(fixture_sites)

    assert {site.kind for site in analysable} == locate.POLICY_DOCUMENT_KINDS
    assert locate.malformed_document_sites(fixture_sites) == []


def test_template_path_splits_json_path_into_location_segments(
    fixture_sites: List[PolicySite],
) -> None:
    """Requirement 6 AC13 needs the statement location as path segments."""
    inline = _only(fixture_sites, PolicyKind.INLINE_ROLE_POLICY)

    assert inline.template_path == [
        "Resources",
        "AppExecutionRole",
        "Properties",
        "Policies",
        0,
        "PolicyDocument",
    ]


def test_template_path_keeps_a_numeric_logical_id_as_a_key() -> None:
    doc = _role_with_inline_documents("123", [{"Version": "2012-10-17"}])
    site = locate.find_policy_documents(doc)[0]

    assert site.template_path[:2] == ["Resources", "123"]
    assert site.template_path[4] == 0


# ---------------------------------------------------------------------------
# The resource-based policy table
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("resource_type", "property_name"),
    sorted(locate.RESOURCE_POLICY_PROPERTIES.items()),
    ids=sorted(locate.RESOURCE_POLICY_PROPERTIES),
)
def test_every_table_entry_is_located_as_a_resource_policy(
    resource_type: str, property_name: str
) -> None:
    """Adding a line to the table must be all it takes to support a type."""
    doc = {
        "Resources": {
            "Target": {
                "Type": resource_type,
                "Properties": {property_name: {"Version": "2012-10-17", "Statement": []}},
            }
        }
    }

    sites = locate.find_policy_documents(doc)

    assert len(sites) == 1
    assert sites[0].kind is PolicyKind.RESOURCE_POLICY
    assert sites[0].logical_id == "Target"
    assert sites[0].json_path == "Resources.Target.Properties.{0}".format(property_name)


def test_resource_policy_table_covers_the_six_v01_types() -> None:
    assert set(locate.RESOURCE_POLICY_PROPERTIES) == {
        "AWS::S3::BucketPolicy",
        "AWS::KMS::Key",
        "AWS::SQS::QueuePolicy",
        "AWS::SNS::TopicPolicy",
        "AWS::ECR::Repository",
        "AWS::SecretsManager::ResourcePolicy",
    }


def test_iam_resource_types_is_derived_from_the_tables() -> None:
    """A type in a table but missing from the set would never be visited."""
    for resource_type in locate.RESOURCE_POLICY_PROPERTIES:
        assert resource_type in locate.IAM_RESOURCE_TYPES
    for resource_type in locate.POLICY_DOCUMENT_PROPERTIES:
        assert resource_type in locate.IAM_RESOURCE_TYPES
    for resource_type in locate.INLINE_POLICY_KINDS:
        assert resource_type in locate.IAM_RESOURCE_TYPES
    assert locate.LAMBDA_PERMISSION_TYPE in locate.IAM_RESOURCE_TYPES


# ---------------------------------------------------------------------------
# Malformed documents are reported, not raised
# ---------------------------------------------------------------------------


def _role_with_inline_documents(logical_id: str, documents: List[Any]) -> Dict[str, Any]:
    return {
        "Resources": {
            logical_id: {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "Policies": [
                        {"PolicyName": "P{0}".format(index), "PolicyDocument": document}
                        for index, document in enumerate(documents)
                    ]
                },
            }
        }
    }


MALFORMED_DOCUMENTS: Tuple[Tuple[str, Any, str], ...] = (
    ("json-string", '{"Version": "2012-10-17"}', "a str"),
    ("plain-string", "see the wiki", "a str"),
    ("statement-list", [{"Effect": "Allow", "Action": "*"}], "a list"),
    ("empty-value", None, "an empty value"),
    ("number", 42, "an int"),
    ("boolean", True, "a bool"),
)


@pytest.mark.parametrize(
    ("document", "described"),
    [(document, described) for _, document, described in MALFORMED_DOCUMENTS],
    ids=[case_id for case_id, _, _ in MALFORMED_DOCUMENTS],
)
def test_non_mapping_policy_document_is_recorded_not_raised(
    document: Any, described: str
) -> None:
    """Failure mode: report it as Informational, keep reviewing the Template."""
    sites = locate.find_policy_documents(
        _role_with_inline_documents("BadRole", [document])
    )

    assert len(sites) == 1
    site = sites[0]
    assert site.kind is PolicyKind.INLINE_ROLE_POLICY
    assert site.logical_id == "BadRole"
    assert site.json_path == "Resources.BadRole.Properties.Policies.0.PolicyDocument"
    assert site.has_policy_document is False

    reason = site.malformed_reason
    assert reason is not None
    # The reason must be usable verbatim: it names the kind, the path, and what
    # was found, and does not echo the untrusted value itself.
    assert site.json_path in reason
    assert site.kind.value in reason
    assert described in reason


def test_malformed_and_valid_documents_are_separated() -> None:
    doc = _role_with_inline_documents(
        "MixedRole", ["not a document", {"Version": "2012-10-17", "Statement": []}]
    )

    sites = locate.find_policy_documents(doc)

    assert [site.json_path for site in locate.malformed_document_sites(sites)] == [
        "Resources.MixedRole.Properties.Policies.0.PolicyDocument"
    ]
    assert [site.json_path for site in locate.policy_document_sites(sites)] == [
        "Resources.MixedRole.Properties.Policies.1.PolicyDocument"
    ]


def test_malformed_trust_policy_is_reported_for_its_own_kind() -> None:
    doc = {
        "Resources": {
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {"AssumeRolePolicyDocument": "*"},
            }
        }
    }

    site = locate.find_policy_documents(doc)[0]

    assert site.kind is PolicyKind.TRUST_POLICY
    assert site.malformed_reason is not None
    assert "trust_policy" in site.malformed_reason


def test_malformed_reason_does_not_echo_template_content() -> None:
    """Untrusted content stays out of the message; the path locates it."""
    secret_looking = "AKIAIOSFODNN7EXAMPLE"
    doc = _role_with_inline_documents("Role", [secret_looking])

    reason = locate.find_policy_documents(doc)[0].malformed_reason

    assert reason is not None
    assert secret_looking not in reason


# ---------------------------------------------------------------------------
# Untrusted structure: fewer sites, never an exception
# ---------------------------------------------------------------------------


MALFORMED_TEMPLATES: Tuple[Tuple[str, Any], ...] = (
    ("not-a-mapping", "Resources: everything"),
    ("none", None),
    ("list", [{"Resources": {}}]),
    ("no-resources", {"Outputs": {}}),
    ("resources-is-a-string", {"Resources": "MyRole"}),
    ("resources-is-a-list", {"Resources": [{"Type": "AWS::IAM::Role"}]}),
    ("resource-is-a-string", {"Resources": {"Role": "AWS::IAM::Role"}}),
    ("resource-has-no-type", {"Resources": {"Role": {"Properties": {}}}}),
    ("type-is-not-a-string", {"Resources": {"Role": {"Type": ["AWS::IAM::Role"]}}}),
    ("properties-missing", {"Resources": {"Role": {"Type": "AWS::IAM::Role"}}}),
    (
        "properties-is-a-string",
        {"Resources": {"Role": {"Type": "AWS::IAM::Role", "Properties": "none"}}},
    ),
    (
        "policies-is-a-string",
        {
            "Resources": {
                "Role": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {"Policies": "ReadOnly"},
                }
            }
        },
    ),
    (
        "policies-entry-is-a-string",
        {
            "Resources": {
                "Role": {"Type": "AWS::IAM::Role", "Properties": {"Policies": ["p"]}}
            }
        },
    ),
    (
        "policies-entry-has-no-document",
        {
            "Resources": {
                "Role": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {"Policies": [{"PolicyName": "P"}]},
                }
            }
        },
    ),
    (
        "non-string-logical-id",
        {
            "Resources": {
                7: {
                    "Type": "AWS::IAM::Role",
                    "Properties": {"AssumeRolePolicyDocument": {}},
                }
            }
        },
    ),
)


@pytest.mark.parametrize(
    "doc",
    [doc for _, doc in MALFORMED_TEMPLATES],
    ids=[case_id for case_id, _ in MALFORMED_TEMPLATES],
)
def test_unexpected_structure_yields_no_sites_without_raising(doc: Any) -> None:
    assert locate.find_policy_documents(doc) == []


def test_template_without_iam_resources_yields_no_sites() -> None:
    """Requirement 6 AC12: nothing IAM-related means an empty result."""
    doc = {
        "Resources": {
            "Bucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {"BucketName": "app-bucket"},
            }
        }
    }

    assert locate.find_policy_documents(doc) == []


def test_empty_inline_policies_list_yields_no_sites() -> None:
    doc = {
        "Resources": {
            "Role": {"Type": "AWS::IAM::Role", "Properties": {"Policies": []}}
        }
    }

    assert locate.find_policy_documents(doc) == []


def test_multiple_inline_policies_are_indexed_in_order() -> None:
    doc = _role_with_inline_documents(
        "Role", [{"Version": "2012-10-17"}, {"Version": "2012-10-17"}]
    )

    sites = locate.find_policy_documents(doc)

    assert [site.json_path for site in sites] == [
        "Resources.Role.Properties.Policies.0.PolicyDocument",
        "Resources.Role.Properties.Policies.1.PolicyDocument",
    ]


def test_user_permissions_boundary_is_located() -> None:
    """Both Role and User can reference a boundary."""
    doc = {
        "Resources": {
            "User": {
                "Type": "AWS::IAM::User",
                "Properties": {"PermissionsBoundary": {"Ref": "BoundaryArn"}},
            }
        }
    }

    site = locate.find_policy_documents(doc)[0]

    assert site.kind is PolicyKind.PERMISSIONS_BOUNDARY
    assert site.json_path == "Resources.User.Properties.PermissionsBoundary"
    assert site.document == {"Ref": "BoundaryArn"}


def test_group_is_not_scanned_for_a_permissions_boundary() -> None:
    """Groups have no boundary; a stray property must not become a site."""
    doc = {
        "Resources": {
            "Group": {
                "Type": "AWS::IAM::Group",
                "Properties": {"PermissionsBoundary": "arn:aws:iam::123456789012:policy/B"},
            }
        }
    }

    assert locate.find_policy_documents(doc) == []


def test_site_is_frozen() -> None:
    """Detectors share one site list; none of them may rewrite it."""
    site = locate.find_policy_documents(
        _role_with_inline_documents("Role", [{"Version": "2012-10-17"}])
    )[0]

    with pytest.raises(Exception):
        site.logical_id = "Other"  # type: ignore[misc]


def test_policy_kind_values_serialize_as_their_spelling() -> None:
    """``kind`` goes into the Layer 2 JSON without a conversion table."""
    import json

    assert json.dumps({"kind": PolicyKind.RESOURCE_POLICY}) == '{"kind": "resource_policy"}'


@pytest.mark.parametrize("kind", list(PolicyKind), ids=[k.value for k in PolicyKind])
def test_only_document_kinds_expect_a_policy_document(kind: PolicyKind) -> None:
    expected: Optional[bool] = kind not in (
        PolicyKind.PERMISSIONS_BOUNDARY,
        PolicyKind.LAMBDA_PERMISSION,
    )

    assert (kind in locate.POLICY_DOCUMENT_KINDS) is expected
