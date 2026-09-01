"""Canonical Finding representation and schema validation.

Every review Source (cfn-lint, cfn-guard, IAM Review, Agent Review) produces
its own shape of output. This module defines the one shape they all normalize
to, and the one function that decides whether an instance of that shape is
legal (design.md, Data Models / Finding schema (authoritative); Requirement 7
AC1-AC13).

Four decisions in here are worth reading before using the module:

field names are PascalCase, deliberately
    ``Finding.Normalized_Category`` rather than ``normalized_category``. The
    field names are exactly the JSON keys of the report schema, so
    :func:`to_dict` and :func:`from_dict` need no name mapping table, and the
    pseudocode in design.md (``f.Severity``, ``e.Source``) transcribes into
    working code. One vocabulary spans schema, design, dataclass, and report.
    The cost is a documented PEP 8 deviation confined to this module's
    dataclasses.

validation is a separate step, not a constructor invariant
    Constructing a ``Finding`` never raises. ``dedup`` builds merged Findings
    with ``ID=0`` (:data:`UNASSIGNED_ID`) because IDs are assigned only after
    sorting (Requirement 7 AC1), so a constructor that enforced ``ID >= 1``
    would reject a legitimate intermediate value. :func:`validate` is therefore
    called at boundaries: when parsing untrusted input (:func:`from_dict`) and
    before serializing a report, after IDs exist.

the four orderings live here and nowhere else
    :data:`SEVERITY_ORDER`, :data:`CONFIDENCE_ORDER`,
    :data:`FINDING_TYPE_ORDER`, and :data:`SOURCE_ORDER` are imported by
    ``dedup`` (merge by maximum), ``report`` (sort), and ``iam`` (severity
    adjustment). A second copy anywhere would let merge order and sort order
    drift apart, which Requirement 16 AC11 (byte-identical output) forbids.
    The design pseudocode names them ``_SEV_ORDER`` / ``_CONF_ORDER`` /
    ``_TYPE_ORDER`` / ``_SOURCE_ORDER``; those names exist below as aliases so
    design.md transcribes literally.

two constraints need knowledge this module does not own
    ``Normalized_Category``'s closed set is data in ``category_map.json``, and
    whether a cfn-lint rule blocks deployment is the ``blocks_deployment`` flag
    in the same file. Neither is copied here -- copying would create a second
    place to update when the mapping file changes. Both arrive through hooks
    (:func:`set_category_validator`, :func:`set_blocks_deployment_resolver`),
    and the category hook resolves itself through :mod:`iacreview.categories`
    when that module is present, so no caller has to wire it up. Until it is
    present, a category is checked for being a non-empty string only; the
    stricter check switches on by itself, with no change at any call site.

credential redaction lives here, not in the one Source that needs it today
    ``Excerpt`` is the only Finding field that reproduces Template text
    verbatim, so it is the only field through which a secret written into a
    Template can reach the report (design.md, Security Design / Credential;
    Requirement 9 AC2). The rule about what may be reproduced belongs to the
    field, not to a Source: every Source fills ``Excerpt``, and today's
    deterministic Sources leave it ``None`` only because a ``Confirmed``
    Finding's ``RuleId`` is already its evidence. Putting
    :func:`redact_excerpt` and :func:`redaction_trigger` next to the field they
    constrain means all four Sources apply one rule, and a Source that starts
    quoting Template text inherits it rather than reinventing it. See
    :func:`redact_finding` for what is deliberately *not* detected.

``SchemaViolationError`` carries ``field`` and ``reason`` attributes here
(design.md describes the failure mode as ``SchemaViolationError(field, reason)``)
in addition to the standard StructuredError payload from
:mod:`iacreview.errors`. Build it through :func:`schema_violation` so both
attributes are always set.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from dataclasses import fields as _dataclass_fields
from enum import Enum
from typing import (
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

from iacreview.errors import SchemaViolationError

__all__ = [
    "FINDING_TYPES",
    "SEVERITIES",
    "CONFIDENCES",
    "SOURCES",
    "SEVERITY_ORDER",
    "CONFIDENCE_ORDER",
    "FINDING_TYPE_ORDER",
    "SOURCE_ORDER",
    "CONFIRMED",
    "AGENT_SOURCE",
    "AGENT_MAX_CONFIDENCE",
    "OTHER_CATEGORY",
    "VALIDITY_TYPE",
    "CRITICAL_SEVERITY",
    "UNASSIGNED_ID",
    "LOCATION_FIELDS",
    "LOCATION_REQUIRED_FIELDS",
    "EVIDENCE_FIELDS",
    "EVIDENCE_REQUIRED_FIELDS",
    "FINDING_FIELDS",
    "Location",
    "Evidence",
    "Finding",
    "schema_violation",
    "set_category_validator",
    "set_blocks_deployment_resolver",
    "sorted_sources",
    "canonical_template_path",
    "is_dedup_eligible",
    "REDACTED_EXCERPT",
    "REDACTION_DETAIL",
    "REDACTION_REASONS",
    "CREDENTIAL_RULE_IDS",
    "PARAMETERS_KEY",
    "NO_ECHO_KEY",
    "RedactionTrigger",
    "noecho_parameter_names",
    "redaction_trigger",
    "redact_excerpt",
    "redact_finding",
    "redact_findings",
    "validate",
    "to_dict",
    "from_dict",
]

# ---------------------------------------------------------------------------
# Closed value sets
# ---------------------------------------------------------------------------

#: Permitted ``FindingType`` values (Requirement 7 AC2), in schema order.
FINDING_TYPES: Tuple[str, ...] = ("Validity", "Security", "BestPractice", "Informational")

#: Permitted ``Severity`` values (Requirement 7 AC3), most severe first.
SEVERITIES: Tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

#: Permitted ``Confidence`` values (Requirement 7 AC7), most certain first.
CONFIDENCES: Tuple[str, ...] = ("Confirmed", "Likely", "Contextual")

#: Permitted ``Source`` values (Requirement 7 AC13) in the canonical order that
#: ``Source`` lists and ``Evidence`` lists are sorted by. Deterministic Sources
#: come before ``Agent Review`` so that merge rules preferring "the first
#: Source" prefer deterministic wording over agent wording.
SOURCES: Tuple[str, ...] = ("cfn-lint", "cfn-guard", "IAM Review", "Network Review", "Secret Review", "Agent Review")

# ---------------------------------------------------------------------------
# Orderings (single definition site; see module docstring)
# ---------------------------------------------------------------------------

#: Severity ranking used for merge maxima and descending report sort.
SEVERITY_ORDER: Dict[str, int] = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

#: Confidence ranking used when merging (Requirement 14 AC9).
CONFIDENCE_ORDER: Dict[str, int] = {"Confirmed": 2, "Likely": 1, "Contextual": 0}

#: FindingType priority used when merging (Requirement 14 AC10).
#:
#: Intentionally *not* the same order as :data:`FINDING_TYPES`: that tuple is
#: the schema's enumeration order, while this is merge priority, in which
#: ``Security`` outranks ``Validity``.
FINDING_TYPE_ORDER: Dict[str, int] = {
    "Security": 3,
    "Validity": 2,
    "BestPractice": 1,
    "Informational": 0,
}

#: Source ranking, derived from :data:`SOURCES` so the two cannot disagree.
SOURCE_ORDER: Dict[str, int] = {name: index for index, name in enumerate(SOURCES)}

# design.md pseudocode names for the four orderings above. Same objects, not
# copies, so there is still exactly one definition of each ranking.
_SEV_ORDER = SEVERITY_ORDER
_CONF_ORDER = CONFIDENCE_ORDER
_TYPE_ORDER = FINDING_TYPE_ORDER
_SOURCE_ORDER = SOURCE_ORDER

#: The one ``Confidence`` value deterministic Sources may claim.
CONFIRMED = "Confirmed"

#: The one non-deterministic ``Source``.
AGENT_SOURCE = "Agent Review"

#: Highest ``Confidence`` a Finding may carry once :data:`AGENT_SOURCE` is among
#: its ``Source`` values. Requirement 7 AC10 states the prohibition
#: (``Confirmed`` is closed to agent reasoning) and this is the other side of it:
#: the strongest claim still open, so anything that has to be weakened is
#: weakened as little as the rule allows. Two places need it -- ``agentin``
#: demoting an agent's own overstated ``Confidence``, and ``dedup`` capping the
#: maximum taken across a merged group -- so it is defined once, here, with the
#: constraint it belongs to.
AGENT_MAX_CONFIDENCE = "Likely"

#: Residual category for findings that map to nothing in the closed set.
OTHER_CATEGORY = "Other"

#: ``FindingType`` whose CRITICAL use is restricted (Requirement 7 AC6).
VALIDITY_TYPE = "Validity"

#: ``Severity`` whose ``Validity`` use is restricted (Requirement 7 AC6).
CRITICAL_SEVERITY = "CRITICAL"

#: ``ID`` value of a Finding that has not been through report ID assignment.
#: ``validate`` rejects it; it exists so intermediate values are readable
#: rather than magic zeros in ``dedup``.
UNASSIGNED_ID = 0

#: Keys of ``Location`` that must be present (JSON Schema ``required``).
LOCATION_REQUIRED_FIELDS: Tuple[str, ...] = ("File",)

#: Keys of an ``Evidence`` entry that must be present.
EVIDENCE_REQUIRED_FIELDS: Tuple[str, ...] = ("Source", "Detail")

#: Windows drive prefix, for example ``C:\\`` or ``C:/``.
_WINDOWS_DRIVE_PATTERN = re.compile(r"^[A-Za-z]:[\\/]")

#: Position in a ``TemplatePath`` that names a member of a top-level Template
#: section (``["Resources", "MyBucket", ...]``). Exempt from index typing in
#: :func:`canonical_template_path`: those sections are mappings, and a logical
#: ID may consist of digits only.
_LOGICAL_ID_INDEX = 1


# ---------------------------------------------------------------------------
# Failure construction
# ---------------------------------------------------------------------------


def schema_violation(field: str, reason: str) -> SchemaViolationError:
    """Build a :class:`~iacreview.errors.SchemaViolationError` for ``field``.

    Args:
        field: Dotted path of the offending field, for example ``"Severity"``,
            ``"Location.Line"``, or ``"Evidence[0].Source"``.
        reason: What is wrong with it, phrased so it can be read on its own.

    Returns:
        The exception, not raised, carrying ``field`` and ``reason`` as
        attributes alongside the usual ``message``. The StructuredError payload
        is untouched: ``field`` and ``reason`` are already joined into
        ``message``, so no new key appears in the report's error entries.
    """
    error = SchemaViolationError("{0}: {1}".format(field, reason))
    error.field = field
    error.reason = reason
    return error


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

#: A ``TemplatePath`` element: mapping key or sequence index.
TemplatePathItem = Union[str, int]


@dataclass
class Location:
    """Where in the reviewed Template a Finding was detected.

    ``File`` is workspace-relative and never an absolute host path, so a report
    does not leak the reviewer's directory layout and stays byte-identical
    across machines (Requirement 16 AC11).

    ``Line`` and ``Column`` are ``None`` for Sources that do not report a
    position (cfn-guard, and IAM Review, which works on the parsed document).
    ``TemplatePath`` is the path into the Template document, for example
    ``["Resources", "MyBucket", "Properties", "BucketEncryption"]``.
    """

    File: str
    Line: Optional[int] = None
    Column: Optional[int] = None
    TemplatePath: Optional[List[TemplatePathItem]] = None


@dataclass
class Evidence:
    """One Source's justification for a Finding.

    ``Excerpt`` holds verbatim Template content and is mandatory, on at least
    one entry, whenever ``Confidence`` is not ``Confirmed`` (Requirement 7
    AC11): a conclusion drawn by reasoning has to point at what it was drawn
    from. Deterministic Sources leave it ``None`` because their ``RuleId``
    already identifies the check that fired.
    """

    Source: str
    Detail: str
    RuleId: Optional[str] = None
    Excerpt: Optional[str] = None


@dataclass
class Finding:
    """One normalized review finding: the 13 fields of Requirement 7 AC1.

    Field order matches the schema's ``required`` list. No field has a default:
    every one is part of the contract, and omitting one should fail at the
    construction site rather than produce a half-built Finding that only
    :func:`validate` catches later.

    ``Severity`` is comparable only among Findings sharing the same
    ``FindingType`` (Requirement 7 AC5). :data:`SEVERITY_ORDER` therefore ranks
    Severity *within* a FindingType; it is not a global importance score.
    """

    ID: int
    Normalized_Category: str
    FindingType: str
    Severity: str
    Confidence: str
    Source: List[str]
    Resource: Optional[str]
    Location: Location
    Finding: str
    WhyItMatters: str
    Evidence: List[Evidence]
    Recommendation: str
    SuggestedRemediation: Optional[str]


#: The 13 Finding keys, in schema order. Derived from the dataclass so the
#: constant cannot drift from the definition.
FINDING_FIELDS: Tuple[str, ...] = tuple(f.name for f in _dataclass_fields(Finding))

#: All ``Location`` keys, in schema order.
LOCATION_FIELDS: Tuple[str, ...] = tuple(f.name for f in _dataclass_fields(Location))

#: All ``Evidence`` keys, in schema order.
EVIDENCE_FIELDS: Tuple[str, ...] = tuple(f.name for f in _dataclass_fields(Evidence))


# ---------------------------------------------------------------------------
# Hooks for constraints owned by other modules
# ---------------------------------------------------------------------------

#: ``is_valid_category``-style predicate: category name -> is it in the closed set.
CategoryValidator = Callable[[str], bool]

#: Rule ID -> does violating that rule prevent deployment entirely.
BlocksDeploymentResolver = Callable[[str], bool]

_category_validator: Optional[CategoryValidator] = None
_blocks_deployment_resolver: Optional[BlocksDeploymentResolver] = None

# Sentinel distinguishing "auto-resolution not attempted yet" from "attempted
# and unavailable"; the latter is a legitimate cached result.
_UNRESOLVED = object()
_auto_category_validator: Any = _UNRESOLVED


def set_category_validator(validator: Optional[CategoryValidator]) -> None:
    """Install the predicate that decides whether a category name is legal.

    Args:
        validator: Typically ``categories.load_map().is_valid_category``.
            ``None`` clears the override and re-enables auto-resolution, which
            is what tests use to undo an injected validator.
    """
    global _category_validator, _auto_category_validator
    _category_validator = validator
    if validator is None:
        _auto_category_validator = _UNRESOLVED


def set_blocks_deployment_resolver(resolver: Optional[BlocksDeploymentResolver]) -> None:
    """Install the predicate behind the ``Validity`` + ``CRITICAL`` constraint.

    The flag lives per rule in ``category_map.json`` and reaches this module
    only through this hook, because :mod:`iacreview.categories` exposes it as
    part of classification rather than as a standalone lookup.

    Args:
        resolver: Rule ID -> ``blocks_deployment``. ``None`` clears it, leaving
            the weaker check described in :func:`validate`.
    """
    global _blocks_deployment_resolver
    _blocks_deployment_resolver = resolver


def _import_category_validator() -> Optional[CategoryValidator]:
    """Try to obtain a category validator from :mod:`iacreview.categories`.

    Returns ``None`` while that module (or its expected API) is absent, so the
    Finding schema stays usable before the categories module exists. A corrupt
    mapping file is *not* swallowed: ``MappingFileError`` propagates, because a
    broken installation must not silently downgrade validation.
    """
    try:
        from iacreview import categories
    except ImportError:
        return None
    load_map = getattr(categories, "load_map", None)
    if load_map is None:
        return None
    validator = getattr(load_map(), "is_valid_category", None)
    if not callable(validator):
        return None
    return validator


def _resolve_category_validator() -> Optional[CategoryValidator]:
    """Return the active category validator, or ``None`` if there is none."""
    global _auto_category_validator
    if _category_validator is not None:
        return _category_validator
    if _auto_category_validator is _UNRESOLVED:
        _auto_category_validator = _import_category_validator()
    return _auto_category_validator


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def sorted_sources(sources: Iterable[str]) -> List[str]:
    """Return ``sources`` de-duplicated and in :data:`SOURCE_ORDER` order.

    The canonical way to build a ``Source`` list, including the union produced
    by a dedup merge (Requirement 14 AC12).

    Raises:
        SchemaViolationError: A value is outside :data:`SOURCES`.
    """
    unique = set()
    for source in sources:
        if source not in SOURCE_ORDER:
            raise schema_violation(
                "Source", "{0!r} is not one of {1}".format(source, list(SOURCES))
            )
        unique.add(source)
    return sorted(unique, key=SOURCE_ORDER.__getitem__)


def canonical_template_path(segments: Iterable[object]) -> List[TemplatePathItem]:
    """Return ``segments`` with sequence indices typed as :class:`int`.

    Every Source addresses a position in the Template document, but they arrive
    at the segments differently: cfn-lint hands over a list that already
    distinguishes keys from indices, while cfn-guard writes a ``/``-separated
    string and IAM Review a ``.``-separated one, in which an index is
    indistinguishable from a key until it is inspected. Without a single
    canonical form, ``["...", "Statement", 0]`` and ``["...", "Statement", "0"]``
    would name the same statement in two spellings, so two Sources reporting one
    position would look like two positions -- to a reader, to a report diff, and
    to any comparison of Locations.

    A digit-only segment becomes an ``int`` everywhere except index 1. Index 1
    is a member name of a top-level Template section (a logical resource ID, a
    Parameter name, an Output name); every one of those sections is a mapping,
    so a digit-only name there is a key. Logical IDs consisting only of digits
    are legal CloudFormation, and turning one into an index would address
    nothing.

    Args:
        segments: Path segments. Strings are inspected; anything else, including
            an ``int`` a Source already typed correctly, passes through
            untouched.

    Returns:
        A new list, safe for the caller to keep or mutate.
    """
    canonical: List[TemplatePathItem] = []
    for index, segment in enumerate(segments):
        if (
            index != _LOGICAL_ID_INDEX
            and isinstance(segment, str)
            and segment.isdigit()
        ):
            canonical.append(int(segment))
        else:
            canonical.append(segment)  # type: ignore[arg-type]
    return canonical


def is_dedup_eligible(f: Finding) -> bool:
    """Whether ``f`` may be matched against other Findings during dedup.

    ``False`` for ``Normalized_Category == "Other"`` (Requirement 14 AC3):
    ``Other`` means "mapped to nothing in the closed set", so two ``Other``
    Findings on one resource share no subject and merging them would fuse two
    unrelated problems into one entry with the higher Severity and both
    Evidence lists. ``False`` also for template-level Findings
    (``Resource is None``), which have no resource key to match on.

    This is the single definition of that exclusion; ``dedup.dedup_key`` builds
    on it, and :func:`validate` uses it to reject a Finding that shows evidence
    of having been merged despite being ineligible.
    """
    return f.Normalized_Category != OTHER_CATEGORY and f.Resource is not None


# ---------------------------------------------------------------------------
# Credential redaction (design.md, Open Design Decisions O-11)
# ---------------------------------------------------------------------------

#: What a redacted ``Excerpt`` says instead of quoting the Template. Spelled
#: exactly as design.md's Security Design table specifies, and non-empty on
#: purpose: Requirement 7 AC11 requires a non-Confirmed Finding to carry an
#: ``Excerpt``, so redaction *replaces* the quotation rather than dropping the
#: field, which would turn a credential into a schema violation.
REDACTED_EXCERPT = "[redacted: this location may contain a credential value]"

#: Sentence appended to ``Evidence[].Detail`` when that entry's ``Excerpt`` was
#: replaced. design.md requires a redacted Finding to say so: a reader comparing
#: two Findings must be able to tell "nothing was quoted here" (a deterministic
#: Source that had no need to quote) from "something was quoted and withheld".
REDACTION_DETAIL = (
    "The Excerpt for this evidence was redacted before reporting because "
    "{reason}; the Template text at this location is not reproduced."
)

#: cfn-lint rules that fire *because* a location holds or exposes a credential
#: (design.md, O-11 condition (b); the same two rules ``category_map.json``
#: marks ``security_relevant`` for ``DataProtection``).
#:
#: Deliberately just these two. ``W2010`` (a ``NoEcho`` Parameter referenced from
#: ``Metadata`` or ``Outputs``) reports a credential exposure too, but its
#: locations are exactly the ones :data:`RedactionTrigger.NO_ECHO_PARAMETER`
#: already covers, so widening this set would add a second path to the same
#: decision. Rules about Template quality are not credential locations and stay
#: out (see :func:`redact_finding` on what is not detected).
CREDENTIAL_RULE_IDS: FrozenSet[str] = frozenset(("W1011", "W2501"))

#: Top-level Template section holding Parameter declarations.
PARAMETERS_KEY = "Parameters"

#: Parameter attribute that suppresses display of the value.
NO_ECHO_KEY = "NoEcho"

#: Characters that continue an identifier, for the whole-word match in
#: :func:`_mentions_identifier`.
_IDENTIFIER_CHARACTER = "[0-9A-Za-z_]"


class RedactionTrigger(Enum):
    """Why an ``Excerpt`` may not be reproduced, or that it may.

    An enum rather than a bool so the reason survives into
    ``Evidence[].Detail``, and so :func:`redact_excerpt` is total: there is a
    member for "nothing triggered", which is the answer for most Findings.

    Members other than :attr:`NONE` all produce the same
    :data:`REDACTED_EXCERPT`; they differ only in the sentence recorded on the
    Evidence entry.
    """

    #: Nothing about this location suggests a credential. Keep the Excerpt.
    NONE = "none"

    #: The location references, or is part of the declaration of, a Parameter
    #: declared ``NoEcho: true`` (design.md, O-11 condition (a)).
    NO_ECHO_PARAMETER = "no_echo_parameter"

    #: A cfn-lint rule in :data:`CREDENTIAL_RULE_IDS` flagged this location
    #: (design.md, O-11 condition (b)).
    CREDENTIAL_RULE = "credential_rule"


#: Reason phrase per trigger, substituted into :data:`REDACTION_DETAIL`.
REDACTION_REASONS: Dict[RedactionTrigger, str] = {
    RedactionTrigger.NO_ECHO_PARAMETER: (
        "the location references a Parameter declared NoEcho: true"
    ),
    RedactionTrigger.CREDENTIAL_RULE: (
        "a credential-detection rule ({0}) reported this location".format(
            ", ".join(sorted(CREDENTIAL_RULE_IDS))
        )
    ),
}


def _is_no_echo(value: object) -> bool:
    """Whether a ``NoEcho`` attribute value means true.

    ``True`` and the string ``"true"`` are both accepted because a Template is
    untrusted text: JSON and YAML both allow ``"true"``, CloudFormation reads it
    as the boolean, and treating it as "not NoEcho" here would leave a Parameter
    the deployer marked secret unredacted. Case and surrounding whitespace are
    ignored for the same reason.
    """
    if value is True:
        return True
    return isinstance(value, str) and value.strip().lower() == "true"


def noecho_parameter_names(doc: object) -> FrozenSet[str]:
    """Names of the Parameters ``doc`` declares ``NoEcho: true``.

    The Template-side half of :attr:`RedactionTrigger.NO_ECHO_PARAMETER`: a
    caller that has the parsed Template computes the set once and hands it to
    :func:`redact_finding` for every Finding, so the Parameters section is walked
    once per Template rather than once per Evidence entry.

    Args:
        doc: A parsed Template. Any other value, and any malformed
            ``Parameters`` section, yields an empty set: this is untrusted input
            (Requirement 9 AC7), and a document with no readable Parameters
            declares no ``NoEcho`` Parameter to protect.

    Returns:
        The names, as a frozenset. Empty when there is nothing to redact for,
        which makes the trigger check a single emptiness test in that case.
    """
    if not isinstance(doc, dict):
        return frozenset()
    parameters = doc.get(PARAMETERS_KEY)
    if not isinstance(parameters, dict):
        return frozenset()
    names = set()
    for name, body in parameters.items():
        if not isinstance(name, str) or not name:
            continue
        if isinstance(body, dict) and _is_no_echo(body.get(NO_ECHO_KEY)):
            names.add(name)
    return frozenset(names)


def _mentions_identifier(text: str, name: str) -> bool:
    """Whether ``name`` occurs in ``text`` as a whole identifier.

    ``Ref: DBPassword``, ``!Ref DBPassword``, ``${DBPassword}`` and
    ``{"Ref": "DBPassword"}`` all spell the same reference, and an ``Excerpt`` is
    a text fragment rather than a parsed value, so the reference is recognized by
    the name itself rather than by enumerating the syntaxes it can appear in.

    Whole-identifier matching is what keeps this off ordinary Template content:
    a Parameter named ``DBPassword`` does not match the prose "database password"
    and does not match a longer identifier such as ``DBPasswordRotation``.
    ``name`` is regex-escaped because it comes from an untrusted Template.
    """
    if not name:
        return False
    pattern = "(?<!{0}){1}(?!{0})".format(_IDENTIFIER_CHARACTER, re.escape(name))
    return re.search(pattern, text) is not None


def _in_parameters_section(
    template_path: Optional[Sequence[object]], names: FrozenSet[str]
) -> bool:
    """Whether ``template_path`` addresses a ``NoEcho`` Parameter's declaration.

    Covers the case a name match cannot: an ``Excerpt`` quoting a Parameter's
    ``Default`` value, where the credential is the quoted text and the Parameter
    name may not appear in it at all.

    A path naming the ``Parameters`` section as a whole also counts while any
    ``NoEcho`` Parameter exists, because such an Excerpt may quote that
    Parameter's ``Default``. That is the conservative side design.md asks for
    (O-11, 保守的な既定): the cost is one over-redacted Excerpt on a
    section-level Finding, and the alternative cost is a leaked credential.
    """
    if not names:
        return False
    if not isinstance(template_path, (list, tuple)) or not template_path:
        return False
    if template_path[0] != PARAMETERS_KEY:
        return False
    if len(template_path) == 1:
        return True
    return template_path[1] in names


def redaction_trigger(
    *,
    excerpt: Optional[str] = None,
    rule_id: Optional[str] = None,
    template_path: Optional[Sequence[object]] = None,
    noecho_parameters: Iterable[str] = (),
) -> RedactionTrigger:
    """Decide whether the quoted location may hold a credential.

    The two conditions design.md fixes for O-11, and only those two:

    (a) the location references a Parameter declared ``NoEcho: true``, either by
        naming it in the quoted text or by addressing its declaration, and
    (b) a rule in :data:`CREDENTIAL_RULE_IDS` reported the location.

    Args:
        excerpt: The Template text the Evidence entry quotes, if any.
        rule_id: ``Evidence[].RuleId``, checked against
            :data:`CREDENTIAL_RULE_IDS`.
        template_path: ``Location.TemplatePath`` of the Finding the entry
            belongs to.
        noecho_parameters: Output of :func:`noecho_parameter_names` for the
            reviewed Template. Empty (the default) leaves condition (a)
            unevaluated, which is correct for a caller that has no parsed
            Template: nothing is known about ``NoEcho``, and nothing is claimed.

    Returns:
        The trigger, or :attr:`RedactionTrigger.NONE`. Condition (b) is reported
        in preference to (a) when both hold, which is an arbitrary but fixed
        choice: the placeholder is identical either way, so the order affects
        only the recorded reason, and fixing it keeps output byte-identical
        between runs (Requirement 16 AC11).
    """
    if isinstance(rule_id, str) and rule_id in CREDENTIAL_RULE_IDS:
        return RedactionTrigger.CREDENTIAL_RULE

    names = (
        noecho_parameters
        if isinstance(noecho_parameters, frozenset)
        else frozenset(noecho_parameters)
    )
    if _in_parameters_section(template_path, names):
        return RedactionTrigger.NO_ECHO_PARAMETER
    if isinstance(excerpt, str) and excerpt:
        # sorted() only to keep the scan order fixed; the answer is a boolean,
        # so it does not depend on which name matched.
        for name in sorted(names):
            if _mentions_identifier(excerpt, name):
                return RedactionTrigger.NO_ECHO_PARAMETER
    return RedactionTrigger.NONE


def redact_excerpt(excerpt: Optional[str], trigger: RedactionTrigger) -> Optional[str]:
    """Return the ``Excerpt`` that may be reported, given ``trigger``.

    Args:
        excerpt: The Template text a Source wants to quote.
        trigger: Output of :func:`redaction_trigger`.

    Returns:
        ``excerpt`` unchanged when nothing triggered, otherwise
        :data:`REDACTED_EXCERPT`. ``None`` and the empty string pass through even
        when a trigger fired: the Source quoted nothing, so there is nothing to
        withhold, and substituting the placeholder would announce a suppression
        that never happened. Applying the function to its own output is
        therefore a no-op.
    """
    if trigger is RedactionTrigger.NONE or not excerpt:
        return excerpt
    return REDACTED_EXCERPT


def _with_redaction_notice(detail: object, trigger: RedactionTrigger) -> str:
    """Append the redaction notice to ``detail``, once."""
    notice = REDACTION_DETAIL.format(reason=REDACTION_REASONS[trigger])
    if not isinstance(detail, str) or not detail:
        return notice
    if notice in detail:
        return detail
    return "{0} {1}".format(detail, notice)


def redact_finding(f: Finding, *, noecho_parameters: Iterable[str] = ()) -> Finding:
    """Redact every ``Evidence[].Excerpt`` of ``f`` that may hold a credential.

    The one call each Source makes on the way out, so that the four Sources
    cannot disagree about what may be reproduced. An entry whose ``Excerpt`` is
    replaced also has :data:`REDACTION_DETAIL` appended to its ``Detail``;
    entries that quote nothing are left exactly as they were, which is why
    wiring this into the deterministic Sources changes none of their output
    today (they set ``Excerpt`` to ``None``).

    Args:
        f: The Finding, mutated in place -- Sources call this on a Finding they
            have just built and still own, and returning a copy would leave the
            un-redacted original reachable from the construction site.
        noecho_parameters: Output of :func:`noecho_parameter_names` for the
            reviewed Template, when the caller has the parsed Template.

    Returns:
        ``f``, so the call can wrap a constructor expression.

    **Not detected, deliberately.** Key names that suggest a secret
    (``password``, ``secret``, ``token``, ``apikey``) do not trigger redaction in
    v0.1. design.md leaves the question open (O-11) pending an assessment of the
    trade-off, and the two conditions implemented here are decidable from the
    Template's own declarations, while a key-name pattern is a guess: it would
    redact ``PasswordPolicy`` and every IAM Finding that quotes it, blunting the
    Evidence that makes a Finding actionable, and it would still miss a
    credential under an unrelated key name. The decision and its reasoning are
    recorded in ``docs/security-model.md``.
    """
    names = (
        noecho_parameters
        if isinstance(noecho_parameters, frozenset)
        else frozenset(noecho_parameters)
    )
    template_path = f.Location.TemplatePath if isinstance(f.Location, Location) else None
    for entry in f.Evidence:
        if not isinstance(entry, Evidence):
            continue
        trigger = redaction_trigger(
            excerpt=entry.Excerpt,
            rule_id=entry.RuleId,
            template_path=template_path,
            noecho_parameters=names,
        )
        redacted = redact_excerpt(entry.Excerpt, trigger)
        if redacted == entry.Excerpt:
            continue
        entry.Excerpt = redacted
        entry.Detail = _with_redaction_notice(entry.Detail, trigger)
    return f


def redact_findings(
    findings: Iterable[Finding], *, noecho_parameters: Iterable[str] = ()
) -> List[Finding]:
    """Apply :func:`redact_finding` to each of ``findings``.

    Args:
        findings: The Findings, mutated in place as by :func:`redact_finding`.
        noecho_parameters: Output of :func:`noecho_parameter_names`, converted
            once for the whole batch.

    Returns:
        The same Findings as a list, in input order.
    """
    names = frozenset(noecho_parameters)
    return [redact_finding(f, noecho_parameters=names) for f in findings]


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _validate_enum(field: str, value: object, permitted: Sequence[str]) -> None:
    if not isinstance(value, str):
        raise schema_violation(field, "expected a string, got {0}".format(_type_name(value)))
    if value not in permitted:
        raise schema_violation(field, "{0!r} is not one of {1}".format(value, list(permitted)))


def _type_name(value: object) -> str:
    return type(value).__name__


def _validate_text(field: str, value: object) -> None:
    """Require a non-empty string (JSON Schema ``minLength: 1``)."""
    if not isinstance(value, str):
        raise schema_violation(field, "expected a string, got {0}".format(_type_name(value)))
    if not value:
        raise schema_violation(field, "must not be empty")


def _validate_optional_text(field: str, value: object) -> None:
    """Require ``None`` or a non-empty string.

    An empty string is rejected rather than treated as absent: two spellings of
    "no value" would make otherwise identical reports differ byte for byte.
    """
    if value is None:
        return
    _validate_text(field, value)


def _validate_positive_int(field: str, value: object, minimum: int) -> None:
    # bool is a subclass of int; True would otherwise pass as 1.
    if isinstance(value, bool) or not isinstance(value, int):
        raise schema_violation(field, "expected an integer, got {0}".format(_type_name(value)))
    if value < minimum:
        raise schema_violation(field, "must be >= {0}, got {1}".format(minimum, value))


def _is_absolute_path(value: str) -> bool:
    """Whether ``value`` looks absolute on any platform.

    Deliberately not :func:`os.path.isabs`: a report written on Windows may be
    read on Linux, so the check must not depend on the host separator.
    """
    if value.startswith("/") or value.startswith("\\"):
        return True
    return bool(_WINDOWS_DRIVE_PATTERN.match(value))


def _validate_category(value: object) -> None:
    """Check ``Normalized_Category`` against the closed set, when known.

    Without a validator (see module docstring) only the string shape is
    checked. The closed set is never duplicated here.
    """
    _validate_text("Normalized_Category", value)
    validator = _resolve_category_validator()
    if validator is None:
        return
    if not validator(str(value)):
        raise schema_violation(
            "Normalized_Category",
            "{0!r} is not a permitted Normalized_Category".format(value),
        )


def _validate_source(value: object) -> None:
    if not isinstance(value, list):
        raise schema_violation("Source", "expected a list, got {0}".format(_type_name(value)))
    if not value:
        raise schema_violation("Source", "must contain at least one Source")
    for index, source in enumerate(value):
        _validate_enum("Source[{0}]".format(index), source, SOURCES)
    if len(set(value)) != len(value):
        raise schema_violation("Source", "must not contain duplicates, got {0}".format(value))
    expected = sorted(value, key=SOURCE_ORDER.__getitem__)
    if list(value) != expected:
        raise schema_violation(
            "Source",
            "must be sorted as {0}, got {1}".format(expected, list(value)),
        )


def _validate_location(value: object) -> None:
    if not isinstance(value, Location):
        raise schema_violation(
            "Location", "expected a Location, got {0}".format(_type_name(value))
        )
    _validate_text("Location.File", value.File)
    if _is_absolute_path(value.File):
        raise schema_violation(
            "Location.File",
            "must be a workspace-relative path, got the absolute path {0!r}".format(value.File),
        )
    for field, number in (("Location.Line", value.Line), ("Location.Column", value.Column)):
        if number is not None:
            _validate_positive_int(field, number, 1)
    _validate_template_path(value.TemplatePath)


def _validate_template_path(value: object) -> None:
    if value is None:
        return
    if not isinstance(value, list):
        raise schema_violation(
            "Location.TemplatePath", "expected a list, got {0}".format(_type_name(value))
        )
    for index, item in enumerate(value):
        field = "Location.TemplatePath[{0}]".format(index)
        if isinstance(item, bool) or not isinstance(item, (str, int)):
            raise schema_violation(
                field,
                "expected a mapping key or sequence index, got {0}".format(_type_name(item)),
            )


def _validate_evidence(value: object) -> None:
    if not isinstance(value, list):
        raise schema_violation("Evidence", "expected a list, got {0}".format(_type_name(value)))
    if not value:
        raise schema_violation("Evidence", "must contain at least one entry")
    for index, entry in enumerate(value):
        prefix = "Evidence[{0}]".format(index)
        if not isinstance(entry, Evidence):
            raise schema_violation(
                prefix, "expected an Evidence, got {0}".format(_type_name(entry))
            )
        _validate_enum("{0}.Source".format(prefix), entry.Source, SOURCES)
        _validate_text("{0}.Detail".format(prefix), entry.Detail)
        _validate_optional_text("{0}.RuleId".format(prefix), entry.RuleId)
        _validate_optional_text("{0}.Excerpt".format(prefix), entry.Excerpt)


def _validate_confirmed_excludes_agent(f: Finding) -> None:
    """Requirement 7 AC10: agent reasoning never claims ``Confirmed``."""
    if f.Confidence == CONFIRMED and AGENT_SOURCE in f.Source:
        raise schema_violation(
            "Confidence",
            "{0!r} is not allowed when Source includes {1!r}".format(CONFIRMED, AGENT_SOURCE),
        )


def _validate_excerpt_present(f: Finding) -> None:
    """Requirement 7 AC11: a non-Confirmed Finding shows what it read."""
    if f.Confidence == CONFIRMED:
        return
    if not any(entry.Excerpt for entry in f.Evidence):
        raise schema_violation(
            "Evidence",
            "Confidence {0!r} requires at least one entry with an Excerpt".format(f.Confidence),
        )


def _validate_validity_critical(f: Finding) -> None:
    """Requirement 7 AC6: ``Validity`` + ``CRITICAL`` needs a blocking rule.

    Two levels of checking. The rule ID is what ``blocks_deployment`` is keyed
    by, so a Finding claiming this combination without any ``RuleId`` in its
    Evidence can be rejected outright -- nothing could justify it. Whether a
    present rule ID actually blocks deployment is only decidable with the
    resolver hook installed; without it the claim is left standing rather than
    guessed at.
    """
    if not (f.FindingType == VALIDITY_TYPE and f.Severity == CRITICAL_SEVERITY):
        return
    rule_ids = [entry.RuleId for entry in f.Evidence if entry.RuleId]
    if not rule_ids:
        raise schema_violation(
            "Severity",
            "{0} {1} requires Evidence carrying the RuleId that blocks deployment".format(
                VALIDITY_TYPE, CRITICAL_SEVERITY
            ),
        )
    resolver = _blocks_deployment_resolver
    if resolver is None:
        return
    if not any(resolver(rule_id) for rule_id in rule_ids):
        raise schema_violation(
            "Severity",
            "{0} {1} is only allowed for a deployment-blocking rule; none of {2} is".format(
                VALIDITY_TYPE, CRITICAL_SEVERITY, rule_ids
            ),
        )


def _validate_other_not_merged(f: Finding) -> None:
    """Requirement 14 AC3: ``Other`` stays out of dedup matching.

    A Finding is produced by exactly one Source; more than one ``Source`` entry
    means it came out of a dedup merge. Combined with
    :func:`is_dedup_eligible`, a multi-Source ``Other`` Finding is proof that
    the exclusion was bypassed, and rejecting it here keeps the rule enforced
    at the schema boundary instead of only inside ``dedup``.
    """
    if f.Normalized_Category != OTHER_CATEGORY:
        return
    if len(f.Source) > 1:
        raise schema_violation(
            "Normalized_Category",
            "{0!r} is excluded from dedup matching, so it cannot carry the merged "
            "Source list {1}".format(OTHER_CATEGORY, list(f.Source)),
        )


def validate(f: Finding) -> None:
    """Check ``f`` against the Finding schema and its structural constraints.

    Covers the JSON Schema in design.md (types, closed value sets,
    ``minLength``, ``minItems``, ``uniqueItems``, ``ID >= 1``) plus the four
    constraints JSON Schema cannot express:

    1. ``Confirmed`` excludes ``Agent Review`` from ``Source``.
    2. Any Confidence other than ``Confirmed`` requires an ``Excerpt``.
    3. ``Validity`` + ``CRITICAL`` requires a deployment-blocking rule.
    4. ``Other`` cannot appear with a merged ``Source`` list.

    ``ID >= 1`` means a Finding straight out of a dedup merge
    (``ID`` = :data:`UNASSIGNED_ID`) does not validate; call this after report
    ID assignment, not before.

    Args:
        f: The Finding to check.

    Raises:
        SchemaViolationError: First violation found, with ``field`` naming the
            offending path (``"Evidence[1].Detail"``) and ``reason`` describing
            the problem. Validation stops at the first violation: the caller
            drops or rejects the Finding either way, so collecting the rest
            would add no decision value.
        MappingFileError: The category mapping file exists but is unreadable or
            malformed, which is a broken installation rather than bad input.
    """
    if not isinstance(f, Finding):
        raise schema_violation("Finding", "expected a Finding, got {0}".format(_type_name(f)))

    _validate_positive_int("ID", f.ID, 1)
    _validate_category(f.Normalized_Category)
    _validate_enum("FindingType", f.FindingType, FINDING_TYPES)
    _validate_enum("Severity", f.Severity, SEVERITIES)
    _validate_enum("Confidence", f.Confidence, CONFIDENCES)
    _validate_source(f.Source)
    _validate_optional_text("Resource", f.Resource)
    _validate_location(f.Location)
    _validate_text("Finding", f.Finding)
    _validate_text("WhyItMatters", f.WhyItMatters)
    _validate_evidence(f.Evidence)
    _validate_text("Recommendation", f.Recommendation)
    _validate_optional_text("SuggestedRemediation", f.SuggestedRemediation)

    _validate_confirmed_excludes_agent(f)
    _validate_excerpt_present(f)
    _validate_validity_critical(f)
    _validate_other_not_merged(f)


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def _location_to_dict(location: Location) -> Dict[str, Any]:
    template_path = location.TemplatePath
    return {
        "File": location.File,
        "Line": location.Line,
        "Column": location.Column,
        # Copied so a mutation of the report cannot reach the Finding.
        "TemplatePath": None if template_path is None else list(template_path),
    }


def _evidence_to_dict(entry: Evidence) -> Dict[str, Any]:
    return {
        "Source": entry.Source,
        "Detail": entry.Detail,
        "RuleId": entry.RuleId,
        "Excerpt": entry.Excerpt,
    }


def to_dict(f: Finding) -> Dict[str, Any]:
    """Render ``f`` as a JSON-serializable dict.

    Every key is always present, including the ones whose value is ``None``.
    A fixed key set lets report consumers index without existence checks, and
    keeps output byte-stable (Requirement 16 AC11).

    Serialization only: call :func:`validate` first if ``f`` came from
    somewhere untrusted.
    """
    return {
        "ID": f.ID,
        "Normalized_Category": f.Normalized_Category,
        "FindingType": f.FindingType,
        "Severity": f.Severity,
        "Confidence": f.Confidence,
        "Source": list(f.Source),
        "Resource": f.Resource,
        "Location": _location_to_dict(f.Location),
        "Finding": f.Finding,
        "WhyItMatters": f.WhyItMatters,
        "Evidence": [_evidence_to_dict(entry) for entry in f.Evidence],
        "Recommendation": f.Recommendation,
        "SuggestedRemediation": f.SuggestedRemediation,
    }


def _require_mapping(field: str, value: object) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise schema_violation(field, "expected an object, got {0}".format(_type_name(value)))
    for key in value:
        if not isinstance(key, str):
            raise schema_violation(field, "keys must be strings, got {0}".format(_type_name(key)))
    return value


def _require_keys(prefix: str, payload: Dict[str, Any], required: Sequence[str]) -> None:
    for key in required:
        if key not in payload:
            raise schema_violation(_join(prefix, key), "required field is missing")


def _reject_unknown_keys(prefix: str, payload: Dict[str, Any], permitted: Sequence[str]) -> None:
    """Enforce ``additionalProperties: false``.

    Unknown keys are an error rather than something to ignore: silently
    dropping them would let a producer believe it had supplied information the
    report never carried.
    """
    for key in sorted(payload):
        if key not in permitted:
            raise schema_violation(
                _join(prefix, key), "is not one of the permitted fields {0}".format(list(permitted))
            )


def _join(prefix: str, key: str) -> str:
    return "{0}.{1}".format(prefix, key) if prefix else key


def _location_from_dict(value: object) -> Location:
    payload = _require_mapping("Location", value)
    _reject_unknown_keys("Location", payload, LOCATION_FIELDS)
    _require_keys("Location", payload, LOCATION_REQUIRED_FIELDS)
    template_path = payload.get("TemplatePath")
    return Location(
        File=payload["File"],
        Line=payload.get("Line"),
        Column=payload.get("Column"),
        TemplatePath=list(template_path) if isinstance(template_path, list) else template_path,
    )


def _evidence_from_dict(value: object, index: int) -> Evidence:
    prefix = "Evidence[{0}]".format(index)
    payload = _require_mapping(prefix, value)
    _reject_unknown_keys(prefix, payload, EVIDENCE_FIELDS)
    _require_keys(prefix, payload, EVIDENCE_REQUIRED_FIELDS)
    return Evidence(
        Source=payload["Source"],
        Detail=payload["Detail"],
        RuleId=payload.get("RuleId"),
        Excerpt=payload.get("Excerpt"),
    )


def from_dict(d: Dict[str, Any]) -> Finding:
    """Build a Finding from a JSON-derived dict, validating it.

    The entry point for untrusted structured input (agent-produced Findings, a
    stored report being re-read). Structural problems are reported before value
    problems, so a missing field is named as missing rather than surfacing as a
    type error somewhere else.

    Args:
        d: Mapping with exactly the 13 keys of :data:`FINDING_FIELDS`.

    Returns:
        A Finding that has passed :func:`validate`.

    Raises:
        SchemaViolationError: ``d`` is not an object, has an unknown or missing
            key, or holds a value the schema forbids.
        MappingFileError: The category mapping file is present but unusable.
    """
    payload = _require_mapping("Finding", d)
    _reject_unknown_keys("", payload, FINDING_FIELDS)
    _require_keys("", payload, FINDING_FIELDS)

    raw_source = payload["Source"]
    raw_evidence = payload["Evidence"]
    if not isinstance(raw_evidence, list):
        raise schema_violation(
            "Evidence", "expected a list, got {0}".format(_type_name(raw_evidence))
        )

    finding = Finding(
        ID=payload["ID"],
        Normalized_Category=payload["Normalized_Category"],
        FindingType=payload["FindingType"],
        Severity=payload["Severity"],
        Confidence=payload["Confidence"],
        Source=list(raw_source) if isinstance(raw_source, list) else raw_source,
        Resource=payload["Resource"],
        Location=_location_from_dict(payload["Location"]),
        Finding=payload["Finding"],
        WhyItMatters=payload["WhyItMatters"],
        Evidence=[
            _evidence_from_dict(entry, index) for index, entry in enumerate(raw_evidence)
        ],
        Recommendation=payload["Recommendation"],
        SuggestedRemediation=payload["SuggestedRemediation"],
    )
    validate(finding)
    return finding
