"""Where IAM policy documents live inside a CloudFormation Template.

This module answers one question and nothing else: given a parsed Template,
which places in it hold something an IAM detector should look at, and how do we
name those places. It performs no analysis -- no wildcard matching, no Principal
classification -- so that :mod:`iacreview.iam.detectors` receives a flat list of
sites and never has to walk the Template again (design.md, IAM Review
Architecture / Policy document の所在).

The nine kinds of site are enumerated by :class:`PolicyKind`. Seven of them hold
a policy document proper; two do not, and the difference matters:

``permissions_boundary``
    Holds an ARN, not a document. The boundary policy itself lives outside the
    Template, so the site records only *that* a boundary is attached and where
    it is referenced. There is nothing to analyse inside it.

``lambda_permission``
    ``AWS::Lambda::Permission`` has no policy document at all, but it does carry
    ``Principal`` / ``SourceAccount`` / ``SourceArn``, which is exactly what
    ``cross_account_principal`` and ``cross_service_missing_condition`` examine.
    Its ``document`` is therefore the resource's ``Properties`` mapping.

:attr:`PolicySite.expects_policy_document` is the single place that distinction
is encoded, so a detector can filter on it rather than re-listing kinds.

Three design decisions worth knowing before using the module:

resource-based policies are a one-line table
    :data:`RESOURCE_POLICY_PROPERTIES` maps resource type to the property that
    holds its policy. Requirement-driven growth (v0.1 covers six types; more
    exist) is then an added line rather than a new code path, which is what
    design.md asks for. The same shape is used by
    :data:`POLICY_DOCUMENT_PROPERTIES` for the two IAM policy resources.

a malformed document is data, not an exception
    ``PolicyDocument: "see wiki"`` is legal YAML and illegal IAM. Raising on it
    would abort the review of an otherwise analysable Template, so the site is
    returned with :attr:`PolicySite.malformed_reason` set and
    :attr:`PolicySite.has_policy_document` ``False``. The IAM Source turns those
    into ``Informational`` Findings (design.md, ``iacreview.iam`` / Failure
    modes; Requirement 6 AC12 keeps a Template with nothing analysable from
    looking like a clean review).

nothing here evaluates intrinsic functions
    ``document`` holds whatever the parser produced, with intrinsics still in
    long form (``{"Ref": "X"}``). Resolving them is
    :mod:`iacreview.iam.intrinsics`' job, and a Template value is never
    executed or interpolated here.

Every input is untrusted, so no traversal step assumes a shape: a ``Resources``
section that is a string, a resource that is a list, a ``Policies`` entry that
is ``None`` all yield fewer sites rather than an exception.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Sequence, Tuple, Union

from iacreview.finding import canonical_template_path

__all__ = [
    "PolicyKind",
    "PolicySite",
    "PathSegment",
    "RESOURCES_KEY",
    "PROPERTIES_KEY",
    "TYPE_KEY",
    "TRUST_POLICY_PROPERTY",
    "PERMISSIONS_BOUNDARY_PROPERTY",
    "INLINE_POLICIES_PROPERTY",
    "INLINE_POLICY_DOCUMENT_PROPERTY",
    "TRUST_POLICY_TYPES",
    "PERMISSIONS_BOUNDARY_TYPES",
    "INLINE_POLICY_KINDS",
    "POLICY_DOCUMENT_PROPERTIES",
    "RESOURCE_POLICY_PROPERTIES",
    "LAMBDA_PERMISSION_TYPE",
    "POLICY_DOCUMENT_KINDS",
    "IAM_RESOURCE_TYPES",
    "find_policy_documents",
    "policy_document_sites",
    "malformed_document_sites",
]


class PolicyKind(str, Enum):
    """The nine places an IAM-relevant document or value can sit.

    A ``str`` mixin, so a kind serializes into the Layer 2 JSON
    (``policy_sites[].kind``) without a conversion table and compares equal to
    its own spelling. Format with ``kind.value``: the ``Enum`` mixin's ``str()``
    is not stable across Python versions, while ``.value`` always is.
    """

    INLINE_ROLE_POLICY = "inline_role_policy"
    TRUST_POLICY = "trust_policy"
    PERMISSIONS_BOUNDARY = "permissions_boundary"
    MANAGED_POLICY = "managed_policy"
    STANDALONE_POLICY = "standalone_policy"
    INLINE_USER_POLICY = "inline_user_policy"
    INLINE_GROUP_POLICY = "inline_group_policy"
    RESOURCE_POLICY = "resource_policy"
    LAMBDA_PERMISSION = "lambda_permission"


#: One element of a path into the Template document: mapping key or list index.
PathSegment = Union[str, int]

# ---------------------------------------------------------------------------
# Template vocabulary
# ---------------------------------------------------------------------------

RESOURCES_KEY = "Resources"
PROPERTIES_KEY = "Properties"
TYPE_KEY = "Type"

#: Property holding a Role's trust policy.
TRUST_POLICY_PROPERTY = "AssumeRolePolicyDocument"

#: Property holding the ARN of an attached permissions boundary.
PERMISSIONS_BOUNDARY_PROPERTY = "PermissionsBoundary"

#: Property holding the list of inline policies on a Role / User / Group.
INLINE_POLICIES_PROPERTY = "Policies"

#: Key inside one :data:`INLINE_POLICIES_PROPERTY` entry holding the document.
INLINE_POLICY_DOCUMENT_PROPERTY = "PolicyDocument"

#: Resource types carrying a trust policy. Only Roles have one; kept as a table
#: for symmetry with the others and because it is the natural extension point.
TRUST_POLICY_TYPES: Tuple[str, ...] = ("AWS::IAM::Role",)

#: Resource types that can reference a permissions boundary.
PERMISSIONS_BOUNDARY_TYPES: Tuple[str, ...] = ("AWS::IAM::Role", "AWS::IAM::User")

#: Resource type -> kind of its ``Policies[*].PolicyDocument`` entries.
INLINE_POLICY_KINDS: Dict[str, PolicyKind] = {
    "AWS::IAM::Role": PolicyKind.INLINE_ROLE_POLICY,
    "AWS::IAM::User": PolicyKind.INLINE_USER_POLICY,
    "AWS::IAM::Group": PolicyKind.INLINE_GROUP_POLICY,
}

#: Resource type -> (kind, property) for the IAM resources whose whole purpose
#: is to carry one policy document.
POLICY_DOCUMENT_PROPERTIES: Dict[str, Tuple[PolicyKind, str]] = {
    "AWS::IAM::ManagedPolicy": (PolicyKind.MANAGED_POLICY, "PolicyDocument"),
    "AWS::IAM::Policy": (PolicyKind.STANDALONE_POLICY, "PolicyDocument"),
}

#: Resource type -> property holding its resource-based policy.
#:
#: The extension point named in design.md: supporting another resource-based
#: policy is one line here and no change anywhere else. v0.1 deliberately covers
#: only these six, and the ``iam-review`` SKILL.md Limitations section says so,
#: because silently ignoring an unlisted type would otherwise read as "no
#: resource policy problems found".
RESOURCE_POLICY_PROPERTIES: Dict[str, str] = {
    "AWS::S3::BucketPolicy": "PolicyDocument",
    "AWS::KMS::Key": "KeyPolicy",
    "AWS::SQS::QueuePolicy": "PolicyDocument",
    "AWS::SNS::TopicPolicy": "PolicyDocument",
    "AWS::ECR::Repository": "RepositoryPolicyText",
    "AWS::SecretsManager::ResourcePolicy": "ResourcePolicy",
}

#: The resource type handled as :attr:`PolicyKind.LAMBDA_PERMISSION`.
LAMBDA_PERMISSION_TYPE = "AWS::Lambda::Permission"

#: Kinds whose ``document`` is expected to be a policy document mapping.
#:
#: The two excluded kinds are not malformed when their value is not a document:
#: ``permissions_boundary`` holds an ARN and ``lambda_permission`` holds the
#: resource's ``Properties``.
POLICY_DOCUMENT_KINDS: FrozenSet[PolicyKind] = frozenset(
    {
        PolicyKind.INLINE_ROLE_POLICY,
        PolicyKind.TRUST_POLICY,
        PolicyKind.MANAGED_POLICY,
        PolicyKind.STANDALONE_POLICY,
        PolicyKind.INLINE_USER_POLICY,
        PolicyKind.INLINE_GROUP_POLICY,
        PolicyKind.RESOURCE_POLICY,
    }
)

#: Every resource type this module inspects, derived from the tables above so it
#: cannot drift from them. Used to answer "does this Template contain anything
#: IAM-related at all" (Requirement 6 AC12) without a second list.
IAM_RESOURCE_TYPES: FrozenSet[str] = frozenset(
    set(TRUST_POLICY_TYPES)
    | set(PERMISSIONS_BOUNDARY_TYPES)
    | set(INLINE_POLICY_KINDS)
    | set(POLICY_DOCUMENT_PROPERTIES)
    | set(RESOURCE_POLICY_PROPERTIES)
    | {LAMBDA_PERMISSION_TYPE}
)

#: Merged view used by the traversal: resource type -> (kind, property) for the
#: resources that hold exactly one document in one property. Built from the two
#: public tables, so adding a line to either is enough.
_SINGLE_DOCUMENT_PROPERTIES: Dict[str, Tuple[PolicyKind, str]] = dict(
    POLICY_DOCUMENT_PROPERTIES
)
_SINGLE_DOCUMENT_PROPERTIES.update(
    {
        resource_type: (PolicyKind.RESOURCE_POLICY, property_name)
        for resource_type, property_name in RESOURCE_POLICY_PROPERTIES.items()
    }
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PolicySite:
    """One IAM-relevant location in the Template.

    Attributes:
        logical_id: Logical ID of the resource the site belongs to. This is the
            value a Finding reports as ``Resource``.
        kind: Which of the nine locations this is.
        json_path: Dotted path to the site, list indices included as plain
            numbers, for example
            ``Resources.AppRole.Properties.Policies.0.PolicyDocument``. This
            exact spelling is what the Layer 2 input JSON carries, so an Agent
            and a human read the same address.
        document: The value found at ``json_path``, exactly as parsed:
            a policy document mapping for the seven document kinds, an ARN (or
            an unresolved intrinsic) for ``permissions_boundary``, and the
            resource's ``Properties`` mapping for ``lambda_permission``.
            Intrinsic functions are left in long form and never evaluated.

    Frozen, because every detector sees the same site list and one detector
    rewriting a site would make results depend on detector order. Freezing binds
    the attributes only; ``document`` is shared with the loaded Template and is
    read-only by convention, as with
    :class:`iacreview.template.LoadedTemplate`.
    """

    logical_id: str
    kind: PolicyKind
    json_path: str
    document: Any

    @property
    def expects_policy_document(self) -> bool:
        """Whether ``document`` is supposed to be a policy document mapping."""
        return self.kind in POLICY_DOCUMENT_KINDS

    @property
    def has_policy_document(self) -> bool:
        """Whether ``document`` is a policy document a detector can walk.

        The predicate detectors filter on: ``False`` both for a malformed
        document and for the two kinds that never hold one.
        """
        return self.expects_policy_document and isinstance(self.document, dict)

    @property
    def malformed_reason(self) -> Optional[str]:
        """Why this site's document cannot be analysed, or ``None``.

        Non-``None`` only where a policy document was expected and something
        else was found -- a JSON string, a list of statements written at the
        wrong level, ``None`` from an empty YAML value. The text is a complete
        sentence naming the path and the type found, so the IAM Source can use
        it verbatim as an ``Informational`` Finding's description without
        re-deriving anything.
        """
        if not self.expects_policy_document or isinstance(self.document, dict):
            return None
        return (
            "The {0} at {1} is not an IAM policy document: expected a mapping "
            "with Version and Statement, found {2}. This location was not "
            "analysed.".format(self.kind.value, self.json_path, _describe(self.document))
        )

    @property
    def template_path(self) -> List[PathSegment]:
        """``json_path`` as the segment list a Finding's ``Location`` carries.

        ``Resources.AppRole.Properties.Policies.0.PolicyDocument`` becomes
        ``["Resources", "AppRole", "Properties", "Policies", 0,
        "PolicyDocument"]``. A digit-only segment is a list index everywhere
        except the logical ID position, where a numeric-looking name is still a
        mapping key.

        The index typing itself is
        :func:`iacreview.finding.canonical_template_path`, shared with the other
        Sources that reconstruct a path from a delimited string, so all of them
        spell one position the same way.
        """
        return canonical_template_path(self.json_path.split("."))


def _describe(value: Any) -> str:
    """Name ``value``'s type for a message, without echoing its content.

    Template content is untrusted and may be long, so only the type is
    reported; the ``json_path`` in the same message says where to look.
    """
    if value is None:
        return "an empty value"
    name = type(value).__name__
    article = "an" if name[:1].lower() in "aeiou" else "a"
    return "{0} {1}".format(article, name)


def _join_path(segments: Sequence[PathSegment]) -> str:
    return ".".join(str(segment) for segment in segments)


def _site(
    logical_id: str,
    kind: PolicyKind,
    segments: Sequence[PathSegment],
    document: Any,
) -> PolicySite:
    """Build a :class:`PolicySite`, deriving ``json_path`` from ``segments``.

    The one construction site, so the dotted spelling is produced in exactly
    one place and cannot drift between kinds.
    """
    return PolicySite(
        logical_id=logical_id,
        kind=kind,
        json_path=_join_path(segments),
        document=document,
    )


# ---------------------------------------------------------------------------
# Traversal
# ---------------------------------------------------------------------------


def find_policy_documents(doc: Dict[str, Any]) -> List[PolicySite]:
    """Collect every IAM-relevant site in a parsed Template.

    Args:
        doc: A parsed Template, normally :attr:`iacreview.template.LoadedTemplate.doc`.
            Untrusted: any shape is accepted.

    Returns:
        The sites found, in Template order -- resources in declaration order
        and, within one resource, trust policy, then inline policies by index,
        then permissions boundary, then single-document property, then Lambda
        permission. Declaration order is preserved by both the JSON and the YAML
        loader, so the same file always yields the same list (Requirement 16
        AC11). Sites whose document is malformed are *included*, carrying
        :attr:`PolicySite.malformed_reason`; filter with
        :func:`policy_document_sites` when only analysable documents are wanted.

        An empty list means the Template declares nothing IAM-related, which
        Requirement 6 AC12 turns into zero findings plus an informational
        message.

    Never raises. A Template with no ``Resources`` mapping, a resource that is
    not a mapping, or a ``Policies`` value that is not a list simply contributes
    fewer sites: this runs on untrusted input, and a structural oddity is a
    thing to report, not a thing to crash on.
    """
    if not isinstance(doc, dict):
        return []
    resources = doc.get(RESOURCES_KEY)
    if not isinstance(resources, dict):
        return []

    sites: List[PolicySite] = []
    for logical_id, resource in resources.items():
        if not isinstance(logical_id, str) or not isinstance(resource, dict):
            continue
        resource_type = resource.get(TYPE_KEY)
        if not isinstance(resource_type, str) or resource_type not in IAM_RESOURCE_TYPES:
            continue
        properties = resource.get(PROPERTIES_KEY)
        if not isinstance(properties, dict):
            # A resource with no usable Properties has no policy to look at.
            # Whether the omission is itself a problem is cfn-lint's judgement,
            # not this module's.
            continue
        sites.extend(_sites_in_resource(logical_id, resource_type, properties))
    return sites


def _sites_in_resource(
    logical_id: str, resource_type: str, properties: Dict[str, Any]
) -> List[PolicySite]:
    """Collect the sites contributed by one resource."""
    base: Tuple[PathSegment, ...] = (RESOURCES_KEY, logical_id, PROPERTIES_KEY)
    sites: List[PolicySite] = []

    if resource_type in TRUST_POLICY_TYPES and TRUST_POLICY_PROPERTY in properties:
        sites.append(
            _site(
                logical_id,
                PolicyKind.TRUST_POLICY,
                base + (TRUST_POLICY_PROPERTY,),
                properties[TRUST_POLICY_PROPERTY],
            )
        )

    inline_kind = INLINE_POLICY_KINDS.get(resource_type)
    if inline_kind is not None:
        sites.extend(_inline_policy_sites(logical_id, inline_kind, properties, base))

    if (
        resource_type in PERMISSIONS_BOUNDARY_TYPES
        and PERMISSIONS_BOUNDARY_PROPERTY in properties
    ):
        sites.append(
            _site(
                logical_id,
                PolicyKind.PERMISSIONS_BOUNDARY,
                base + (PERMISSIONS_BOUNDARY_PROPERTY,),
                properties[PERMISSIONS_BOUNDARY_PROPERTY],
            )
        )

    single = _SINGLE_DOCUMENT_PROPERTIES.get(resource_type)
    if single is not None:
        kind, property_name = single
        if property_name in properties:
            sites.append(
                _site(
                    logical_id, kind, base + (property_name,), properties[property_name]
                )
            )

    if resource_type == LAMBDA_PERMISSION_TYPE:
        # The whole Properties mapping is the site: Principal, SourceAccount and
        # SourceArn are siblings, and the detectors need them together.
        sites.append(
            _site(logical_id, PolicyKind.LAMBDA_PERMISSION, base, properties)
        )

    return sites


def _inline_policy_sites(
    logical_id: str,
    kind: PolicyKind,
    properties: Dict[str, Any],
    base: Tuple[PathSegment, ...],
) -> List[PolicySite]:
    """Collect ``Policies[*].PolicyDocument`` sites of one Role / User / Group.

    An entry with no ``PolicyDocument`` key yields no site: there is no
    location to report and nothing to analyse. An entry *with* the key but a
    non-mapping value does yield one, so it can be reported as malformed.
    """
    policies = properties.get(INLINE_POLICIES_PROPERTY)
    if not isinstance(policies, list):
        return []

    sites: List[PolicySite] = []
    for index, entry in enumerate(policies):
        if not isinstance(entry, dict) or INLINE_POLICY_DOCUMENT_PROPERTY not in entry:
            continue
        sites.append(
            _site(
                logical_id,
                kind,
                base + (INLINE_POLICIES_PROPERTY, index, INLINE_POLICY_DOCUMENT_PROPERTY),
                entry[INLINE_POLICY_DOCUMENT_PROPERTY],
            )
        )
    return sites


# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------


def policy_document_sites(sites: Sequence[PolicySite]) -> List[PolicySite]:
    """Return the sites holding an analysable policy document mapping.

    What a detector that walks ``Statement`` iterates over. Excludes malformed
    documents and the two kinds that hold no document.
    """
    return [site for site in sites if site.has_policy_document]


def malformed_document_sites(sites: Sequence[PolicySite]) -> List[PolicySite]:
    """Return the sites whose expected policy document is not a mapping.

    The input to the ``Informational`` Findings the IAM Source reports, so that
    a location skipped by every detector is still visible in the report rather
    than silently absent.
    """
    return [site for site in sites if site.malformed_reason is not None]
