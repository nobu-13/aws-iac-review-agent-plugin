"""Shared Hypothesis strategies for the 31 Correctness Properties.

design.md ("Correctness Properties / 実装規約") puts every Finding, Template and
policy-document generator in one module so that 31 property tests draw from one
definition of "an input the pipeline accepts". This is that module. Task 23's
tests import from here and add only the assertions of their own property.

**Vocabularies are imported, never restated.** ``Severity``, ``FindingType``,
``Confidence``, ``Source`` and ``Normalized_Category`` all come from
:mod:`iacreview` -- the last one through :func:`iacreview.categories.load_map`,
whose closed set lives in ``category_map.json``. A value added or removed there
changes what these strategies generate on the next run rather than leaving a
second, silently stale copy in the test suite. :mod:`tests.property` has no
literal ``"CRITICAL"`` or ``"IAM"`` anywhere that a vocabulary is meant.

**Valid by construction, invalid by name.** A strategy whose name does not say
otherwise generates values the corresponding validator accepts:
:func:`findings` passes :func:`iacreview.finding.validate`, :func:`templates`
passes :func:`iacreview.template.is_reviewable`, :func:`relative_paths` survives
:func:`iacreview.pathguard.resolve_within`. Where a property is *about*
rejection, the generator says so in its name --
:func:`invalid_findings`, :func:`unreviewable_documents`,
:func:`arbitrary_input_bytes`, :func:`paths_escaping_root`,
:func:`strings_with_shell_metacharacters`, :func:`invalid_argument_vectors` --
so a test that draws from one cannot be misread as asserting the happy path.

Four structural rules are enforced by construction rather than by filtering,
because each is a rule some property is meant to *verify* and a generator that
produced violations would make the verification vacuous.

``Confidence`` follows ``Source``
    ``Confirmed`` if and only if ``Agent Review`` is absent (Requirement 7 AC9,
    AC10; Property 6). An agent-only Finding draws from
    :data:`iacreview.agentin.AGENT_CONFIDENCES`, and a mixed Source union -- the
    shape a dedup merge produces -- is capped at
    :data:`iacreview.finding.AGENT_MAX_CONFIDENCE` exactly as design.md
    [Correction] C-8 requires.

Non-``Confirmed`` Findings carry an ``Excerpt``
    Requirement 7 AC11, Property 7. Some draws use
    :data:`iacreview.finding.REDACTED_EXCERPT` instead of Template text, which is
    the redaction branch that property has to cover.

``CRITICAL`` carries a deployment-blocking ``RuleId``
    Requirement 7 AC6 constrains ``Validity`` + ``CRITICAL`` only, but the
    constraint has to hold for every Finding a *merge* of the generated list
    could produce: merging ``BestPractice`` + ``CRITICAL`` with ``Validity`` +
    ``LOW`` yields ``Validity`` + ``CRITICAL``, whose justification can only
    come from the Evidence its inputs carried. Every ``CRITICAL`` Finding
    therefore carries a rule ID that :meth:`iacreview.categories.CategoryMap.blocks_deployment`
    resolves to true, and the blocking IDs are discovered from the mapping file
    (:func:`_blocking_rule_ids`) rather than listed here.

``Other`` never carries a merged ``Source`` list
    Requirement 14 AC3 keeps that category out of dedup matching, so a
    multi-Source ``Other`` Finding is one no pipeline can produce and
    :func:`iacreview.finding.validate` rejects it.

**Collisions are the point.** ``Resource`` is drawn from
:data:`RESOURCE_POOL` (``"A"``, ``"B"``, ``"C"``, ``None``) and
``Normalized_Category`` from the closed set, so a list of five Findings routinely
holds two that share a dedup key. design.md asks for exactly this: without the
small pool, ``deduplicate`` would almost never take its merge path and Properties
3, 4, 5 and 11 would pass on inputs that never merged anything.

**Reproducing a failure.** Hypothesis prints the failing example and stores it in
``.hypothesis/examples`` (gitignored, since it is a per-machine cache and not a
test fixture). To re-run one deterministically, add
``@seed(<the printed seed>)`` from :mod:`hypothesis` to the test, or pin the
counterexample as a plain example in ``tests/regression/`` -- which is what
steering/testing.md asks for once a property has found a real bug.

**Settings.** design.md fixes ``@settings(max_examples=100)`` per property test;
:data:`MAX_EXAMPLES` is that number, for a test that would otherwise restate it.
A property that runs a subprocess or touches the filesystem should also pass
``deadline=None``: the default per-example deadline measures wall-clock time and
would turn a slow machine into a test failure.

Importing this module from a test in ``tests/property/`` works through pytest's
default ``prepend`` import mode, which puts the test file's own directory on
``sys.path`` (there is no ``__init__.py`` here, matching every other directory
under ``tests/``): ``import strategies``.
"""

from __future__ import annotations

import json
from dataclasses import replace
from typing import Any, Dict, List, Optional, Sequence, Tuple

from hypothesis import strategies as st

from benchmark.harness import metrics
from iacreview import categories, errors, exitcodes, yamlcfn
from iacreview.agentin import AGENT_CONFIDENCES
from iacreview.finding import (
    AGENT_MAX_CONFIDENCE,
    AGENT_SOURCE,
    CONFIDENCES,
    CONFIRMED,
    CRITICAL_SEVERITY,
    FINDING_TYPES,
    OTHER_CATEGORY,
    REDACTED_EXCERPT,
    SEVERITIES,
    SOURCES,
    UNASSIGNED_ID,
    Evidence,
    Finding,
    Location,
    sorted_sources,
    to_dict,
)
from iacreview.iam.detectors import CONFUSED_DEPUTY_CONDITION_KEYS
from iacreview.iam.locate import RESOURCE_POLICY_PROPERTIES
from iacreview.pathguard import SHELL_METACHARACTERS
from iacreview.report import ReportMeta, ToolStatus
from iacreview.source import PARENT_DIRECTORY

__all__ = [
    "MAX_EXAMPLES",
    "RESOURCE_POOL",
    "CFNLINT_LEVELS",
    "TEMPLATE_FILES",
    "categories_pool",
    "severities",
    "finding_types",
    "confidences",
    "source_lists",
    "source_subsets",
    "rule_ids",
    "blocking_rule_ids",
    "cfnlint_levels",
    "locations",
    "findings",
    "finding_lists",
    "mergeable_finding_groups",
    "finding_payloads",
    "invalid_findings",
    "structured_errors",
    "report_metas",
    "templates",
    "unreviewable_documents",
    "documents",
    "template_texts",
    "arbitrary_input_bytes",
    "unsupported_yaml_tag_texts",
    "credential_templates",
    "policy_documents",
    "star_action_star_resource_documents",
    "same_account_principals",
    "cross_account_principals",
    "cross_account_statements",
    "external_id_condition",
    "iam_templates",
    "relative_paths",
    "paths_escaping_root",
    "paths",
    "strings_with_shell_metacharacters",
    "strings_without_shell_metacharacters",
    "temp_file_suffixes",
    "exit_codes",
    "defined_exit_codes",
    "stderr_texts",
    "invalid_argument_vectors",
    "failure_classes",
    "cdk_layouts",
    "expectations",
    "expected_actual_pairs",
    "detection_rates",
    "dump_yaml",
    "dump_json",
]

# ---------------------------------------------------------------------------
# Shared vocabulary and pools
# ---------------------------------------------------------------------------

#: Iterations design.md fixes for every property test.
MAX_EXAMPLES: int = 100

#: Resource logical IDs a Finding is generated for, plus ``None`` for a
#: template-level Finding. Deliberately tiny: see the module docstring on why
#: collisions have to be frequent.
RESOURCE_POOL: Tuple[Optional[str], ...] = ("A", "B", "C", None)

#: cfn-lint's three result levels, from :mod:`iacreview.categories`.
CFNLINT_LEVELS: Tuple[str, ...] = categories.CFNLINT_LEVELS

#: ``Location.File`` values: one plain name and one nested path, both
#: workspace-relative as the schema requires.
TEMPLATE_FILES: Tuple[str, ...] = ("app.yaml", "templates/nested/stack.json")

#: Prose fragments. Findings need three non-empty text fields and the wording
#: itself is irrelevant to every property, so a handful of fixed sentences beats
#: generated text that would only make counterexamples harder to read.
_SENTENCES: Tuple[str, ...] = (
    "The resource does not configure the property this check requires.",
    "The policy grants more authority than the workload appears to need.",
    "The setting deviates from the documented baseline.",
)

#: cfn-lint rule ID shapes. ``E``/``W``/``I`` plus four digits is cfn-lint's own
#: identifier scheme; which of them block deployment is the mapping file's
#: business and is asked of it in :func:`_blocking_rule_ids`.
_RULE_ID_LETTERS: Tuple[str, ...] = ("E", "W", "I")
_RULE_ID_SERIALS: Tuple[int, ...] = (1, 2, 3, 10, 55)
_CANDIDATE_RULE_IDS: Tuple[str, ...] = tuple(
    "{0}{1}{2:03d}".format(letter, group, serial)
    for letter in _RULE_ID_LETTERS
    for group in range(10)
    for serial in _RULE_ID_SERIALS
)


def _blocking_rule_ids() -> Tuple[str, ...]:
    """Candidate rule IDs the mapping file resolves as deployment-blocking.

    Asked of :meth:`iacreview.categories.CategoryMap.blocks_deployment` rather
    than listed, so the set follows ``category_map.json``. Non-empty for any
    mapping file that marks anything as blocking; the smoke test asserts that,
    since an empty result would silently stop ``CRITICAL`` Findings from being
    generated at all.
    """
    cmap = categories.load_map()
    return tuple(rule_id for rule_id in _CANDIDATE_RULE_IDS if cmap.blocks_deployment(rule_id))


def _category_names() -> Tuple[str, ...]:
    """The closed ``Normalized_Category`` set, from the mapping file."""
    return categories.load_map().categories


def categories_pool() -> st.SearchStrategy[str]:
    """A ``Normalized_Category`` from the closed set (Property 2)."""
    return st.sampled_from(_category_names())


def severities() -> st.SearchStrategy[str]:
    """A ``Severity`` from :data:`iacreview.finding.SEVERITIES`."""
    return st.sampled_from(SEVERITIES)


def finding_types() -> st.SearchStrategy[str]:
    """A ``FindingType`` from :data:`iacreview.finding.FINDING_TYPES`."""
    return st.sampled_from(FINDING_TYPES)


def confidences() -> st.SearchStrategy[str]:
    """A ``Confidence`` from :data:`iacreview.finding.CONFIDENCES`.

    The whole set, unconditioned. A Finding's Confidence is *derived* from its
    Source (see :func:`findings`); this strategy is for a test that needs the
    vocabulary itself, such as one ranking the values.
    """
    return st.sampled_from(CONFIDENCES)


def source_lists(*, agent: Optional[bool] = None) -> st.SearchStrategy[List[str]]:
    """A schema-valid ``Source`` list: non-empty, unique, in Source order.

    Args:
        agent: ``True`` restricts to lists containing ``Agent Review``, ``False``
            to lists without it, ``None`` (the default) draws both. The two
            halves are what Property 6 contrasts, so each is directly available.

    Returns:
        Lists ordered by :data:`iacreview.finding.SOURCE_ORDER` through
        :func:`iacreview.finding.sorted_sources`, which is what ``validate``
        requires and what a merge produces.
    """
    deterministic = tuple(name for name in SOURCES if name != AGENT_SOURCE)
    if agent is False:
        return st.lists(
            st.sampled_from(deterministic), min_size=1, unique=True
        ).map(sorted_sources)
    with_agent = st.lists(st.sampled_from(deterministic), unique=True).map(
        lambda names: sorted_sources(list(names) + [AGENT_SOURCE])
    )
    if agent is True:
        return with_agent
    return st.one_of(source_lists(agent=False), with_agent)


def source_subsets(*, min_size: int = 0) -> st.SearchStrategy[List[str]]:
    """Any subset of the four Sources, in Source order (Property 24).

    Args:
        min_size: Smallest subset to draw. ``0`` includes the empty subset,
            which for orchestration means "no Source was asked to fail".
    """
    return st.lists(st.sampled_from(SOURCES), min_size=min_size, unique=True).map(
        sorted_sources
    )


def rule_ids() -> st.SearchStrategy[str]:
    """A rule ID: a plausible cfn-lint identifier or arbitrary text.

    Property 9 asks about *any* rule ID string, including ones the mapping file
    has never heard of, so unstructured text is part of the space rather than a
    separate generator.
    """
    return st.one_of(
        st.sampled_from(_CANDIDATE_RULE_IDS),
        st.text(min_size=1, max_size=12),
    )


def blocking_rule_ids() -> st.SearchStrategy[str]:
    """A rule ID whose violation blocks deployment (Requirement 7 AC6)."""
    return st.sampled_from(_blocking_rule_ids())


def cfnlint_levels() -> st.SearchStrategy[str]:
    """One of cfn-lint's three result levels."""
    return st.sampled_from(CFNLINT_LEVELS)


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


def _template_paths() -> st.SearchStrategy[Optional[List[Any]]]:
    """A ``Location.TemplatePath``: canonical, sometimes absent.

    Sequence indices are ``int`` and mapping keys are ``str``, which is the one
    canonical form design.md [Correction] C-9 fixes. Index 1 -- the logical ID
    position -- includes an all-digit *string*, the case that correction exists
    for: a numeric logical ID is a mapping key and must not be turned into an
    index.
    """
    logical_ids = st.sampled_from(("A", "B", "C", "0", "42"))
    tails = st.lists(
        st.one_of(
            st.sampled_from(("Properties", "PolicyDocument", "Statement", "Action")),
            st.integers(min_value=0, max_value=3),
        ),
        max_size=4,
    )
    present = st.builds(
        lambda logical_id, tail: ["Resources", logical_id] + list(tail),
        logical_ids,
        tails,
    )
    return st.one_of(st.none(), present)


def locations() -> st.SearchStrategy[Location]:
    """A schema-valid :class:`iacreview.finding.Location`.

    ``File`` is always workspace-relative, and ``Line`` / ``Column`` are either
    both absent (cfn-guard, IAM Review) or a 1-based position (cfn-lint), which
    are the only two shapes a Source produces.
    """
    positioned = st.tuples(
        st.integers(min_value=1, max_value=500), st.integers(min_value=1, max_value=80)
    )
    return st.builds(
        lambda file_name, position, template_path: Location(
            File=file_name,
            Line=None if position is None else position[0],
            Column=None if position is None else position[1],
            TemplatePath=template_path,
        ),
        st.sampled_from(TEMPLATE_FILES),
        st.one_of(st.none(), positioned),
        _template_paths(),
    )


def _confidence_for(source: Sequence[str]) -> st.SearchStrategy[str]:
    """The Confidence values ``source`` permits (Property 6, [Correction] C-8).

    Without ``Agent Review`` the answer is forced: a deterministic Source states
    facts, so ``Confirmed`` is the only legal value. With the agent involved the
    value is capped at :data:`~iacreview.finding.AGENT_MAX_CONFIDENCE`, which
    leaves the two agent Confidences.
    """
    if AGENT_SOURCE not in source:
        return st.just(CONFIRMED)
    return st.sampled_from(AGENT_CONFIDENCES)


def _excerpts() -> st.SearchStrategy[str]:
    """Template text an Evidence entry quotes, or the redaction marker.

    The marker is drawn as often as real text because Property 7 has a branch
    for it: a redacted Excerpt still satisfies "carries template evidence".
    """
    return st.one_of(
        st.sampled_from(('Action: "*"\nResource: "*"', "BucketEncryption: null")),
        st.just(REDACTED_EXCERPT),
    )


def _evidence_for(
    draw: Any, source: Sequence[str], severity: str, confidence: str
) -> List[Evidence]:
    """One Evidence entry per Source, in Source order.

    Source order is what a merge produces (Requirement 14 AC11), so a generated
    multi-Source Finding is indistinguishable from a merged one -- which is the
    input Properties 3, 4 and 11 need in order to test idempotence on output
    that has already been through a merge.

    An ``Excerpt`` is attached whenever ``confidence`` is not ``Confirmed``
    (Requirement 7 AC11) and a deployment-blocking ``RuleId`` whenever
    ``severity`` is ``CRITICAL`` (see the module docstring).
    """
    entries: List[Evidence] = []
    for index, name in enumerate(sorted_sources(source)):
        rule_id: Optional[str] = None
        if severity == CRITICAL_SEVERITY and index == 0:
            rule_id = draw(blocking_rule_ids())
        elif name != AGENT_SOURCE:
            rule_id = draw(st.sampled_from(_CANDIDATE_RULE_IDS))
        excerpt: Optional[str] = None
        if confidence != CONFIRMED and (name == AGENT_SOURCE or len(source) == 1):
            excerpt = draw(_excerpts())
        entries.append(
            Evidence(
                Source=name,
                Detail=draw(st.sampled_from(_SENTENCES)),
                RuleId=rule_id,
                Excerpt=excerpt,
            )
        )
    if confidence != CONFIRMED and not any(entry.Excerpt for entry in entries):
        entries[-1] = Evidence(
            Source=entries[-1].Source,
            Detail=entries[-1].Detail,
            RuleId=entries[-1].RuleId,
            Excerpt=draw(_excerpts()),
        )
    return entries


@st.composite
def findings(
    draw: Any,
    *,
    resource: Optional[st.SearchStrategy[Optional[str]]] = None,
    category: Optional[st.SearchStrategy[str]] = None,
    identifier: Optional[st.SearchStrategy[int]] = None,
) -> Finding:
    """A Finding that passes :func:`iacreview.finding.validate`.

    Args:
        resource: ``Resource`` values to draw from. Defaults to
            :data:`RESOURCE_POOL`, whose ``None`` member produces the
            template-level Findings dedup passes through untouched.
        category: ``Normalized_Category`` values. Defaults to the closed set.
        identifier: ``ID`` values. Defaults to 1..5 -- small, so that two
            Findings in a list can share an ID, which is legal before
            ``report.assign_ids`` runs and must not be assumed unique by
            anything downstream of it.

    Returns:
        One Finding, valid by construction under all four structural constraints
        described in the module docstring.
    """
    category_value = draw(category if category is not None else categories_pool())
    source = draw(source_lists())
    if category_value == OTHER_CATEGORY:
        # Requirement 14 AC3: excluded from matching, so it cannot have been
        # merged, so it carries exactly one Source.
        source = [draw(st.sampled_from(source))]
    confidence = draw(_confidence_for(source))
    severity = draw(severities())
    evidence = _evidence_for(draw, source, severity, confidence)
    return Finding(
        ID=draw(identifier if identifier is not None else st.integers(1, 5)),
        Normalized_Category=category_value,
        FindingType=draw(finding_types()),
        Severity=severity,
        Confidence=confidence,
        Source=source,
        Resource=draw(resource if resource is not None else st.sampled_from(RESOURCE_POOL)),
        Location=draw(locations()),
        Finding=draw(st.sampled_from(_SENTENCES)),
        WhyItMatters=draw(st.sampled_from(_SENTENCES)),
        Evidence=evidence,
        Recommendation=draw(st.sampled_from(_SENTENCES)),
        SuggestedRemediation=draw(st.one_of(st.none(), st.just("Set the property."))),
    )


def finding_lists(
    *, min_size: int = 0, max_size: int = 6
) -> st.SearchStrategy[List[Finding]]:
    """A list of valid Findings, drawn to collide on the dedup key.

    Args:
        min_size: Shortest list. ``0`` by default: an empty review is a legal
            input to ``deduplicate`` and to ``build_report``, and a property that
            holds only for non-empty lists is not the property.
        max_size: Longest list. Six is enough for several groups of two or three
            over a four-value ``Resource`` pool while keeping a counterexample
            small enough to read.

    Returns:
        Lists ready for :func:`iacreview.dedup.deduplicate`; every element also
        passes ``validate`` on its own.
    """
    return st.lists(findings(), min_size=min_size, max_size=max_size)


@st.composite
def mergeable_finding_groups(draw: Any, *, min_size: int = 2) -> List[Finding]:
    """Two or more Findings that :func:`iacreview.dedup.deduplicate` must merge.

    Every member shares one non-``Other`` ``Normalized_Category`` and one
    non-null ``Resource``, which is the equivalence key of Requirement 14 AC5.
    Property 5 needs the merge path taken on *every* example, and drawing an
    unconstrained list would take it only sometimes.

    Args:
        min_size: Smallest group. Two, the smallest group a merge applies to.
    """
    mergeable = tuple(name for name in _category_names() if name != OTHER_CATEGORY)
    category = st.just(draw(st.sampled_from(mergeable)))
    resource = st.just(draw(st.sampled_from(tuple(r for r in RESOURCE_POOL if r is not None))))
    return draw(
        st.lists(
            findings(resource=resource, category=category),
            min_size=min_size,
            max_size=4,
        )
    )


def finding_payloads() -> st.SearchStrategy[Dict[str, Any]]:
    """A Finding as a report-shaped dict (:func:`iacreview.finding.to_dict`).

    What the benchmark harness and any consumer of stdout actually read, and the
    form :mod:`benchmark.harness.metrics` compares against ground truth.
    """
    return findings().map(to_dict)


def invalid_findings() -> st.SearchStrategy[Finding]:
    """A Finding that :func:`iacreview.finding.validate` **must** reject.

    One violation per draw, each of a different rule, so a test asserting
    rejection cannot pass by accident on a Finding that happens to be malformed
    in some other way:

    * ``ID`` below the first assigned value.
    * A ``Severity`` / ``FindingType`` / ``Confidence`` / category outside its
      closed set.
    * ``Confirmed`` together with ``Agent Review`` (Requirement 7 AC10).
    * A non-``Confirmed`` Finding with no ``Excerpt`` (Requirement 7 AC11).
    * An absolute ``Location.File`` (Requirement 16 AC11).
    * An empty ``Evidence`` list, and an empty ``Source`` list.
    """

    def break_it(f: Finding, which: str) -> Finding:
        if which == "id":
            return replace(f, ID=UNASSIGNED_ID)
        if which == "severity":
            return replace(f, Severity="SEVERE")
        if which == "finding_type":
            return replace(f, FindingType="Correctness")
        if which == "confidence":
            return replace(f, Confidence="Certain")
        if which == "category":
            return replace(f, Normalized_Category="Networking")
        if which == "confirmed_agent":
            return replace(
                f, Confidence=CONFIRMED, Source=sorted_sources(list(SOURCES))
            )
        if which == "missing_excerpt":
            return replace(
                f,
                Confidence=AGENT_MAX_CONFIDENCE,
                Source=[AGENT_SOURCE],
                Evidence=[
                    Evidence(Source=AGENT_SOURCE, Detail="No quotation.", RuleId=None,
                             Excerpt=None)
                ],
            )
        if which == "absolute_file":
            return replace(f, Location=replace(f.Location, File="/tmp/app.yaml"))
        if which == "no_evidence":
            return replace(f, Evidence=[])
        return replace(f, Source=[])

    breakages = st.sampled_from(
        (
            "id",
            "severity",
            "finding_type",
            "confidence",
            "category",
            "confirmed_agent",
            "missing_excerpt",
            "absolute_file",
            "no_evidence",
            "no_source",
        )
    )
    return st.builds(break_it, findings(), breakages)


# ---------------------------------------------------------------------------
# Report inputs
# ---------------------------------------------------------------------------


def structured_errors() -> st.SearchStrategy[Dict[str, Any]]:
    """A StructuredError carrying exactly :data:`iacreview.errors.STRUCTURED_ERROR_KEYS`.

    ``error_class`` is drawn from the closed set in :mod:`iacreview.errors`, and
    ``stderr_head`` respects the bound of Property 23.
    """
    return st.builds(
        lambda error_class, source, exit_code, head: {
            "error_class": error_class,
            "source": source,
            "tool": None if source is None else source.lower(),
            "exit_code": exit_code,
            "message": "The Source did not complete.",
            "required_min_version": None,
            "detected_version": None,
            "remediation": None,
            "stderr_head": head,
        },
        st.sampled_from(sorted(errors.ERROR_CLASSES)),
        st.one_of(st.none(), st.sampled_from(SOURCES)),
        st.one_of(st.none(), st.integers(min_value=0, max_value=255)),
        st.lists(
            st.text(min_size=0, max_size=20),
            max_size=errors.STDERR_HEAD_MAX_LINES,
        ),
    )


def report_metas() -> st.SearchStrategy[ReportMeta]:
    """A :class:`iacreview.report.ReportMeta` :func:`~iacreview.report.build_report` accepts.

    Both Template groups of Requirement 8 AC10 occur: ``synthesized_templates``
    is sometimes non-empty, which is what makes ``summary.by_template_group``
    interesting to Property 13.
    """
    tools = st.lists(
        st.builds(
            ToolStatus,
            st.sampled_from(("cfn-lint", "cfn-guard", "cdk")),
            st.booleans(),
            st.one_of(st.none(), st.just("1.0.0")),
        ),
        max_size=3,
        unique_by=lambda tool: tool.name,
    )
    return st.builds(
        ReportMeta,
        files=st.lists(st.sampled_from(TEMPLATE_FILES), max_size=2, unique=True),
        sources_enabled=source_subsets(),
        tools=tools,
        cdk_detected=st.booleans(),
        synthesized_templates=st.lists(
            st.just("cdk.out/Stack.template.json"), max_size=1
        ),
    )


# ---------------------------------------------------------------------------
# Templates and documents
# ---------------------------------------------------------------------------

#: The one IAM-relevant type the generated Templates use, from the table
#: :mod:`iacreview.iam.locate` traverses.
_ROLE_TYPE = "AWS::IAM::Role"

#: Resource types the generated Templates use. One is IAM-relevant, so a
#: generated Template sometimes has policy sites and sometimes has none, which is
#: the Requirement 6 AC12 case ("no IAM resources at all").
_RESOURCE_TYPES: Tuple[str, ...] = ("AWS::S3::Bucket", _ROLE_TYPE, "AWS::SQS::Queue")


def _resource_properties() -> st.SearchStrategy[Dict[str, Any]]:
    """A small ``Properties`` mapping, sometimes holding an intrinsic function."""
    return st.dictionaries(
        st.sampled_from(("BucketName", "Description", "Tags")),
        st.one_of(
            st.text(min_size=0, max_size=8),
            st.integers(min_value=-5, max_value=5),
            st.booleans(),
            st.none(),
            st.just({"Ref": "AWS::StackName"}),
            st.lists(st.text(max_size=4), max_size=2),
        ),
        max_size=3,
    )


@st.composite
def templates(draw: Any) -> Dict[str, Any]:
    """A document :func:`iacreview.template.is_reviewable` accepts.

    A mapping whose ``Resources`` holds at least one entry (Requirement 3 AC1).
    Logical IDs come from :data:`RESOURCE_POOL` so a Finding's ``Resource`` and a
    Template's resources are drawn from one namespace, and an all-digit ID is
    included because that is the case [Correction] C-9 turns on.
    """
    logical_ids = draw(
        st.lists(st.sampled_from(("A", "B", "C", "0")), min_size=1, max_size=3, unique=True)
    )
    resources: Dict[str, Any] = {}
    for logical_id in logical_ids:
        resource_type = draw(st.sampled_from(_RESOURCE_TYPES))
        properties = draw(_resource_properties())
        if resource_type == _ROLE_TYPE and draw(st.booleans()):
            # A Role with no trust policy has no policy site, so half of them get
            # one: a generated Template then sometimes has IAM content for the
            # IAM Source to find and sometimes has none at all, which is the
            # Requirement 6 AC12 case.
            properties["AssumeRolePolicyDocument"] = draw(policy_documents())
        resources[logical_id] = {"Type": resource_type, "Properties": properties}
    document: Dict[str, Any] = {"Resources": resources}
    if draw(st.booleans()):
        document["AWSTemplateFormatVersion"] = "2010-09-09"
    if draw(st.booleans()):
        document["Description"] = "A generated template."
    if draw(st.booleans()):
        document["Parameters"] = {"Name": {"Type": "String"}}
    return document


def unreviewable_documents() -> st.SearchStrategy[Any]:
    """A parsed document :func:`iacreview.template.is_reviewable` **must** reject.

    Every shape the predicate has to say no to (Property 16): a non-mapping, a
    mapping with no ``Resources``, a ``Resources`` that is not a mapping, and an
    empty ``Resources`` -- the stub file whose review would otherwise read as
    "no problems found".
    """
    return st.one_of(
        st.none(),
        st.integers(),
        st.text(max_size=8),
        st.lists(st.text(max_size=4), max_size=2),
        st.just({}),
        st.just({"Description": "No resources here."}),
        st.just({"Resources": None}),
        st.just({"Resources": []}),
        st.just({"Resources": {}}),
        st.just({"Resources": "MyBucket"}),
    )


def documents() -> st.SearchStrategy[Any]:
    """Any parsed document: reviewable or not (Property 16 draws both halves)."""
    return st.one_of(templates(), unreviewable_documents())


def dump_yaml(document: Any) -> str:
    """Serialize ``document`` as YAML text.

    Uses the PyYAML import guarded by :func:`iacreview.yamlcfn.import_yaml`, so a
    property test depends on the same YAML the plugin depends on and on no other.
    """
    yaml = yamlcfn.import_yaml()
    return yaml.safe_dump(document, default_flow_style=False, sort_keys=True)


def dump_json(document: Any) -> str:
    """Serialize ``document`` as JSON text (Property 15's other half)."""
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def template_texts() -> st.SearchStrategy[Tuple[str, str]]:
    """A reviewable Template as ``(yaml_text, json_text)`` of one document.

    Property 15 reviews both serializations and requires identical Findings, so
    the pair has to come from a single draw rather than from two.
    """
    return templates().map(lambda doc: (dump_yaml(doc), dump_json(doc)))


def arbitrary_input_bytes() -> st.SearchStrategy[bytes]:
    """Arbitrary bytes for an input file (Property 17).

    Unrestricted :func:`hypothesis.strategies.binary`, plus fragments that reach
    specific failure paths more often than random bytes would: an invalid UTF-8
    sequence, a truncated document, a YAML tab, a BOM, and text that parses to a
    document which is simply not reviewable.
    """
    seeds = st.sampled_from(
        (
            b"",
            b"\xff\xfe\x00",
            b"{",
            b"Resources:\n\tA: {}\n",
            b"\xef\xbb\xbfResources:\n  A:\n    Type: AWS::S3::Bucket\n",
            b"[1, 2, 3]",
            b"Resources: []\n",
            b"!!python/object:os.system []\n",
        )
    )
    return st.one_of(st.binary(max_size=64), seeds)


def unsupported_yaml_tag_texts() -> st.SearchStrategy[str]:
    """YAML text carrying a tag outside the CloudFormation allowlist (Property 21).

    The tag names are generated *around* :data:`iacreview.yamlcfn.SHORT_TAGS`
    rather than listed, so extending the allowlist cannot leave this strategy
    generating a tag that is now legal.
    """
    unsupported = st.text(
        alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        min_size=1,
        max_size=10,
    ).filter(lambda name: name not in yamlcfn.SHORT_TAGS)
    known_unsafe = st.sampled_from(
        ("python/object:os.system", "python/object/apply:os.system", "!ruby/object:Foo")
    )
    return st.one_of(unsupported, known_unsafe).map(
        lambda tag: "Resources:\n  A:\n    Type: AWS::S3::Bucket\n"
        "    Properties:\n      BucketName: !{0} value\n".format(tag)
    )


#: A value a redaction rule must keep out of ``Evidence[].Excerpt``.
_CREDENTIAL_VALUES: Tuple[str, ...] = (
    "hunter2-not-a-real-secret",
    "AKIAIOSFODNN7EXAMPLE-placeholder",
    "pa55phrase-placeholder",
)


def credential_templates() -> st.SearchStrategy[Tuple[Dict[str, Any], str]]:
    """A Template with a credential at a redaction-triggering location.

    Returns ``(document, secret)`` where ``secret`` is the value Property 29
    requires to be absent from every ``Evidence[].Excerpt``. The trigger is a
    ``NoEcho`` Parameter -- the location
    :func:`iacreview.finding.noecho_parameter_names` recognizes -- with the
    secret appearing both as the Parameter's default and in a resource property,
    so a redaction that only covers the declaration is not enough.

    The values are obvious placeholders, never anything resembling a real
    credential (steering/security.md: no credential-like string in tests).
    """
    return st.sampled_from(_CREDENTIAL_VALUES).map(
        lambda secret: (
            {
                "Parameters": {
                    "DbPassword": {"Type": "String", "NoEcho": True, "Default": secret}
                },
                "Resources": {
                    "A": {
                        "Type": "AWS::SecretsManager::Secret",
                        "Properties": {"SecretString": secret},
                    }
                },
            },
            secret,
        )
    )


# ---------------------------------------------------------------------------
# IAM policy documents
# ---------------------------------------------------------------------------

#: ``Action`` values, spanning the three cases the detectors distinguish: the
#: full wildcard, a wildcard within a service, and a single named action.
_ACTIONS: Tuple[str, ...] = ("*", "s3:*", "iam:PassRole", "sts:AssumeRole", "s3:GetObject")

#: ``Resource`` values: the full wildcard, a wildcard ARN, and a specific ARN.
_RESOURCES: Tuple[str, ...] = (
    "*",
    "arn:aws:s3:::example-bucket/*",
    "arn:aws:iam::123456789012:role/AppRole",
)

#: An account ID that is not the deploying account, so a literal Principal built
#: from it classifies as cross-account (Requirement 6 AC7).
_OTHER_ACCOUNT_ID = "210987654321"


def same_account_principals() -> st.SearchStrategy[Any]:
    """A Principal that names the deploying account (Property 26).

    Every spelling of the ``AWS::AccountId`` pseudo parameter that Requirement 6
    AC8 covers: the ``Ref``, an ``Fn::Sub`` whose only substitution is that
    parameter, and a bare string containing it. All three must classify as
    same-account and none as cross-account.
    """
    return st.sampled_from(
        (
            {"Ref": "AWS::AccountId"},
            {"Fn::Sub": "${AWS::AccountId}"},
            {"Fn::Sub": "arn:aws:iam::${AWS::AccountId}:root"},
            "${AWS::AccountId}",
            "arn:aws:iam::${AWS::AccountId}:root",
        )
    )


def cross_account_principals() -> st.SearchStrategy[Any]:
    """A Principal naming a literal account other than the deploying one."""
    return st.sampled_from(
        (
            _OTHER_ACCOUNT_ID,
            "arn:aws:iam::{0}:root".format(_OTHER_ACCOUNT_ID),
            "arn:aws:iam::{0}:role/PeerRole".format(_OTHER_ACCOUNT_ID),
            {"AWS": _OTHER_ACCOUNT_ID},
        )
    )


#: ``sts:ExternalId`` as a Template writes it. IAM's own condition-key spelling
#: rather than an ``iacreview`` vocabulary, so it is written out here; the smoke
#: test pins it against :data:`~iacreview.iam.detectors.EXTERNAL_ID_CONDITION_KEY`,
#: which is the lower-cased form the detector matches on.
_EXTERNAL_ID_KEY = "sts:ExternalId"

#: Placeholder ExternalId value. Not a credential and not credential-shaped
#: (steering/security.md), and its content is irrelevant: the detector asks only
#: whether the key is required.
_EXTERNAL_ID_VALUE = "external-id-placeholder"


def external_id_condition() -> Dict[str, Any]:
    """The ``sts:ExternalId`` condition Property 27 adds to a statement.

    A plain value rather than a strategy: Property 27 compares one statement with
    and without it, so the two runs have to differ in exactly this.
    """
    return {"StringEquals": {_EXTERNAL_ID_KEY: _EXTERNAL_ID_VALUE}}


def _conditions() -> st.SearchStrategy[Optional[Dict[str, Any]]]:
    """A statement ``Condition`` block, or ``None``.

    Three cases: absent, the mitigating ``sts:ExternalId`` condition of
    Requirement 6 AC10, and a confused-deputy condition key drawn from
    :data:`~iacreview.iam.detectors.CONFUSED_DEPUTY_CONDITION_KEYS`. The third
    exists so a test can tell "some condition is present" apart from "the
    mitigating condition is present" -- those have different consequences, and a
    generator that only produced the mitigating one would hide a detector that
    accepted any condition at all.
    """
    confused_deputy = st.sampled_from(tuple(sorted(CONFUSED_DEPUTY_CONDITION_KEYS))).map(
        lambda key: {"StringEquals": {key: "placeholder"}}
    )
    return st.one_of(st.none(), st.just(external_id_condition()), confused_deputy)


@st.composite
def _statements(draw: Any, *, principal: Optional[st.SearchStrategy[Any]] = None) -> Dict[str, Any]:
    """One policy statement: Effect, Action, Resource, optional Principal / Condition."""
    statement: Dict[str, Any] = {
        "Effect": draw(st.sampled_from(("Allow", "Deny"))),
        "Action": draw(
            st.one_of(
                st.sampled_from(_ACTIONS),
                st.lists(st.sampled_from(_ACTIONS), min_size=1, max_size=3, unique=True),
            )
        ),
        "Resource": draw(
            st.one_of(
                st.sampled_from(_RESOURCES),
                st.lists(st.sampled_from(_RESOURCES), min_size=1, max_size=2, unique=True),
            )
        ),
    }
    if principal is not None:
        statement["Principal"] = {"AWS": draw(principal)}
    elif draw(st.booleans()):
        statement["Principal"] = draw(
            st.one_of(
                st.just("*"),
                st.just({"Service": "lambda.amazonaws.com"}),
                same_account_principals().map(lambda value: {"AWS": value}),
                cross_account_principals().map(
                    lambda value: value if isinstance(value, dict) else {"AWS": value}
                ),
            )
        )
    condition = draw(_conditions())
    if condition is not None:
        statement["Condition"] = condition
    return statement


@st.composite
def policy_documents(
    draw: Any, *, principal: Optional[st.SearchStrategy[Any]] = None
) -> Dict[str, Any]:
    """An IAM policy document combining Action, Resource, Principal and Condition.

    Args:
        principal: Principal values every statement carries under its ``AWS``
            key. ``None`` lets each statement decide, including having no
            ``Principal`` at all.

    Returns:
        ``{"Version": ..., "Statement": [...]}``. ``Statement`` is sometimes a
        single mapping rather than a list, which IAM accepts and
        :mod:`iacreview.iam.detectors` handles as a separate code path.
    """
    statements = draw(
        st.lists(_statements(principal=principal), min_size=1, max_size=3)
    )
    document: Dict[str, Any] = {"Version": "2012-10-17"}
    if len(statements) == 1 and draw(st.booleans()):
        document["Statement"] = statements[0]
    else:
        document["Statement"] = statements
    return document


def star_action_star_resource_documents() -> st.SearchStrategy[Dict[str, Any]]:
    """A policy document that always contains ``Allow`` on ``*`` / ``*`` (Property 28).

    The wildcard statement is present in every draw; what varies is what
    surrounds it -- its position among other statements, whether Action and
    Resource are scalars or lists, and whether a Condition is attached. Property
    28 requires the CRITICAL Security Confirmed Finding regardless.
    """
    wildcard = st.builds(
        lambda action_as_list, resource_as_list, condition: dict(
            [
                ("Effect", "Allow"),
                ("Action", ["*", "s3:GetObject"] if action_as_list else "*"),
                ("Resource", ["*"] if resource_as_list else "*"),
            ]
            + ([("Condition", condition)] if condition is not None else [])
        ),
        st.booleans(),
        st.booleans(),
        _conditions(),
    )
    return st.builds(
        lambda star, others, before: {
            "Version": "2012-10-17",
            "Statement": (list(others) + [star]) if before else ([star] + list(others)),
        },
        wildcard,
        st.lists(_statements(), max_size=2),
        st.booleans(),
    )


@st.composite
def cross_account_statements(draw: Any) -> Dict[str, Any]:
    """A statement whose Principal is a literal foreign account, with no Condition.

    The input half of Property 27: the same statement with an ``sts:ExternalId``
    condition added must report a Severity exactly one level lower. Returned
    without any Condition so the test can add exactly one.
    """
    return {
        "Effect": "Allow",
        "Action": draw(st.sampled_from(("sts:AssumeRole", "s3:GetObject", "*"))),
        "Resource": draw(st.sampled_from(_RESOURCES)),
        "Principal": {"AWS": draw(cross_account_principals())},
    }


@st.composite
def iam_templates(
    draw: Any, *, document: Optional[st.SearchStrategy[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """A Template carrying one policy document at a real policy site.

    The site kind varies over the ones :mod:`iacreview.iam.locate` recognizes --
    a Role trust policy, a Role inline policy, a ManagedPolicy, and a
    resource-based policy -- because a detector that only ever sees inline
    policies is a detector tested on one of nine code paths.

    Args:
        document: Policy documents to embed. Defaults to
            :func:`policy_documents`.
    """
    policy = draw(document if document is not None else policy_documents())
    logical_id = draw(st.sampled_from(("A", "B", "C")))
    kind = draw(st.sampled_from(("trust", "inline", "managed", "resource")))
    if kind == "trust":
        resource = {
            "Type": "AWS::IAM::Role",
            "Properties": {"AssumeRolePolicyDocument": policy},
        }
    elif kind == "inline":
        resource = {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": []},
                "Policies": [{"PolicyName": "inline", "PolicyDocument": policy}],
            },
        }
    elif kind == "managed":
        resource = {
            "Type": "AWS::IAM::ManagedPolicy",
            "Properties": {"PolicyDocument": policy},
        }
    else:
        resource_type = draw(st.sampled_from(tuple(sorted(RESOURCE_POLICY_PROPERTIES))))
        resource = {
            "Type": resource_type,
            "Properties": {RESOURCE_POLICY_PROPERTIES[resource_type]: policy},
        }
    return {"Resources": {logical_id: resource}}


# ---------------------------------------------------------------------------
# Paths and arguments
# ---------------------------------------------------------------------------

#: Directory segments a candidate path may pass through. ``"."`` is included
#: because ``./app.yaml`` and ``app.yaml`` are two spellings of one file and path
#: handling has to collapse them.
_DIRECTORY_SEGMENTS: Tuple[str, ...] = ("templates", "nested", ".")

#: Final segments: the path names a file, which is what a Source hands to
#: :func:`iacreview.pathguard.resolve_within`.
_FILE_SEGMENTS: Tuple[str, ...] = ("app.yaml", "stack.json")


def relative_paths() -> st.SearchStrategy[str]:
    """A relative path naming a file inside its root.

    No :data:`~iacreview.source.PARENT_DIRECTORY` segment and no shell
    metacharacter, so containment holds and argument validation passes. The path
    always ends in a file name rather than a directory: that is the shape a
    Source passes to :func:`iacreview.pathguard.resolve_within`, and a candidate
    that named a directory would make a test that writes to it fail for a reason
    that has nothing to do with the path.
    """
    return st.builds(
        lambda directories, file_name: "/".join(list(directories) + [file_name]),
        st.lists(st.sampled_from(_DIRECTORY_SEGMENTS), max_size=2),
        st.sampled_from(_FILE_SEGMENTS),
    )


def paths_escaping_root() -> st.SearchStrategy[str]:
    """A path that leaves its root, which containment **must** reject (Property 18).

    Both ways out: ``..`` traversal, and an absolute path. Every traversal draw
    *starts* with ``..`` and adds no leading segment to climb back out of, so it
    escapes for certain -- ``templates/../app.yaml`` also contains ``..`` and is
    still contained, and generating it here would make the strategy's name a
    false claim.

    Symlinked candidates are not generated: the link has to exist on disk, so
    Property 18's symlink case builds that candidate itself and draws the rest
    from here.
    """
    traversal = st.builds(
        lambda ups, tail: "/".join([PARENT_DIRECTORY] * ups + list(tail)),
        st.integers(min_value=1, max_value=3),
        st.lists(st.sampled_from(("templates", "app.yaml")), max_size=2),
    )
    absolute = st.sampled_from(("/etc/passwd", "/tmp", "/"))
    return st.one_of(traversal, absolute)


def paths() -> st.SearchStrategy[str]:
    """Any candidate path string: contained or escaping, safe or unsafe.

    The full input space of :func:`iacreview.pathguard.resolve_within`, which is
    what a property about it has to draw from. Use the narrower strategies when
    the property is about one half.
    """
    return st.one_of(
        relative_paths(),
        paths_escaping_root(),
        strings_with_shell_metacharacters(),
        st.text(max_size=12),
    )


def strings_with_shell_metacharacters() -> st.SearchStrategy[str]:
    """A string containing at least one character from :data:`~iacreview.pathguard.SHELL_METACHARACTERS`.

    The characters come from the module that rejects them, so adding one to the
    set immediately widens what this generates (Property 19).
    """
    metacharacters = st.sampled_from(tuple(sorted(SHELL_METACHARACTERS)))
    return st.builds(
        lambda before, char, after: before + char + after,
        st.text(max_size=6).filter(lambda t: not (set(t) & SHELL_METACHARACTERS)),
        metacharacters,
        st.text(max_size=6).filter(lambda t: not (set(t) & SHELL_METACHARACTERS)),
    )


def strings_without_shell_metacharacters() -> st.SearchStrategy[str]:
    """A string containing none of those characters, which must be accepted."""
    return st.one_of(
        relative_paths(),
        st.text(max_size=12).filter(lambda text: not (set(text) & SHELL_METACHARACTERS)),
    )


def temp_file_suffixes() -> st.SearchStrategy[str]:
    """A suffix :func:`iacreview.pathguard.secure_temp_file` accepts (Property 22).

    No path separator and no NUL, which are the two things that helper refuses;
    the empty suffix is included because it is legal and is the boundary case.
    """
    return st.one_of(
        st.just(""),
        st.sampled_from((".yaml", ".json", ".template", "-guard.json")),
        st.text(alphabet="abcdefghijklmnopqrstuvwxyz.-_", max_size=8),
    )


def exit_codes() -> st.SearchStrategy[int]:
    """Any integer, as a process exit code (Property 10).

    Negative values and values far above 255 included: the bit-mask decoder has
    to classify every integer, and Property 10 is stated over all of them.
    """
    return st.one_of(
        st.integers(),
        st.integers(min_value=-8, max_value=32),
        st.sampled_from((0, 2, 4, 6, 8, 14, 15, 16, -1, 255, 256)),
    )


def defined_exit_codes() -> st.SearchStrategy[int]:
    """One of the plugin's own exit codes (:data:`iacreview.exitcodes.EXIT_CODES`)."""
    return st.sampled_from(sorted(set(exitcodes.EXIT_CODES.values())))


def stderr_texts() -> st.SearchStrategy[str]:
    """External-tool stderr text, with line counts around the transcription bound.

    Property 23 caps ``stderr_head`` at
    :data:`iacreview.errors.STDERR_HEAD_MAX_LINES` elements and requires element
    ``i`` to equal line ``i``, so the generated text spans fewer, exactly, and
    more lines than the bound, and includes ``\\r\\n`` endings and blank lines --
    the cases ``splitlines`` treats differently from a naive split.
    """
    line = st.text(
        alphabet=st.characters(exclude_categories=("Cs",), exclude_characters="\r\n"),
        max_size=24,
    )
    joined = st.builds(
        lambda lines, ending, trailing: ending.join(lines) + (ending if trailing else ""),
        st.lists(line, max_size=errors.STDERR_HEAD_MAX_LINES * 2),
        st.sampled_from(("\n", "\r\n")),
        st.booleans(),
    )
    return st.one_of(st.just(""), joined)


def invalid_argument_vectors() -> st.SearchStrategy[List[str]]:
    """An argv an entry point **must** refuse before doing anything (Property 20).

    Missing required options, unknown flags, options with no value, and a value
    carrying a shell metacharacter. Property 20 asserts a documented non-zero
    exit code and no side effect: no subprocess started, no file written.
    """
    unsafe_value = strings_with_shell_metacharacters()
    return st.one_of(
        st.just([]),
        st.just(["--target"]),
        st.just(["--unknown-flag", "value"]),
        st.just(["--target", "app.yaml", "--sources"]),
        st.just(["app.yaml"]),
        unsafe_value.map(lambda value: ["--target", value]),
        st.lists(st.text(max_size=8), min_size=1, max_size=3),
    )


#: The four failure classes Property 24 injects into a Source.
_FAILURE_CLASSES: Tuple[str, ...] = (
    "tool_unavailable",
    "tool_execution",
    "tool_timeout",
    "unexpected",
)


def failure_classes() -> st.SearchStrategy[str]:
    """One injected failure class, all four drawn from :data:`iacreview.errors.ERROR_CLASSES`."""
    return st.sampled_from(_FAILURE_CLASSES)


def cdk_layouts() -> st.SearchStrategy[Dict[str, Any]]:
    """An input directory layout, with and without CDK markers (Property 25).

    Returns a mapping of relative path to file content, where a value of ``None``
    means "create this directory". All four combinations of ``cdk.json`` and
    ``cdk.out/`` occur, which is what Property 25 needs in order to assert that
    none of them invokes ``cdk`` without the confirmation flag.
    """
    return st.builds(
        lambda has_config, has_out, has_template: dict(
            [("cdk.json", '{"app": "python3 app.py"}')] * int(has_config)
            + [
                ("cdk.out", None),
                ("cdk.out/Stack.template.json", '{"Resources": {"A": {"Type": "AWS::S3::Bucket"}}}'),
            ]
            * int(has_out)
            + [("app.yaml", "Resources:\n  A:\n    Type: AWS::S3::Bucket\n")]
            * int(has_template)
        ),
        st.booleans(),
        st.booleans(),
        st.booleans(),
    )


# ---------------------------------------------------------------------------
# Benchmark
# ---------------------------------------------------------------------------


def expectations() -> st.SearchStrategy[Dict[str, Any]]:
    """One ``expected_findings`` entry, in ground truth's snake_case spelling.

    Field names come from :data:`benchmark.harness.metrics.FIELD_ALIASES` and
    ``detection_class`` values from
    :data:`benchmark.harness.metrics.DETECTION_CLASSES`, so a rename in the
    ground truth schema surfaces here rather than as unmatchable expectations.
    """
    return st.builds(
        lambda resource, category, finding_type, severity, detection_class, detected_by: {
            "resource": resource,
            "normalized_category": category,
            "finding_type": finding_type,
            "severity": severity,
            "detection_class": detection_class,
            "detected_by": detected_by,
            "note": "Generated expectation.",
        },
        st.sampled_from(RESOURCE_POOL),
        categories_pool(),
        finding_types(),
        severities(),
        st.sampled_from(metrics.DETECTION_CLASSES),
        source_lists(),
    )


def _finding_for(expectation: Dict[str, Any], severity: Optional[str] = None) -> Dict[str, Any]:
    """The Finding that detects ``expectation``, in the report's spelling.

    Only the five fields :mod:`benchmark.harness.metrics` reads, translated
    through :data:`~benchmark.harness.metrics.FIELD_ALIASES`' report-side
    spellings, so a rename on either side of that table surfaces here.

    Args:
        expectation: One ground-truth entry.
        severity: Severity to report, when it should differ from the expected
            one. A matched pair with a different Severity is a detection with a
            severity miss (Requirement 11 AC6), which is the case severity
            accuracy exists to count.
    """
    return {
        "Resource": expectation["resource"],
        "FindingType": expectation["finding_type"],
        "Normalized_Category": expectation["normalized_category"],
        "Severity": expectation["severity"] if severity is None else severity,
        "Source": list(expectation["detected_by"]),
    }


@st.composite
def expected_actual_pairs(
    draw: Any, *, exact: Optional[bool] = None, min_size: int = 0
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """An ``(expected, actual)`` pair for the benchmark harness (Properties 30, 31).

    Args:
        exact: ``True`` derives one Finding from every expectation, so every
            expectation is matched and nothing is a false positive -- the case
            Property 30 requires ``"100.0"`` and ``0`` for. ``False`` detects only
            part of the expectations and adds unrelated Findings. ``None`` draws
            both situations.
        min_size: Fewest expectations. ``1`` is what the ``exact`` case of
            Property 30 needs: with no expectations at all every rate is
            ``"N/A"``, which is correct but is not the ``"100.0"`` the property
            talks about.

    Returns:
        ``(expected, actual)``: ground-truth entries in snake_case, report
        Findings in the report schema's own spelling.

    The inexact case is *derived* from the expectations rather than drawn
    independently. Two independent draws over a match key of
    ``(resource, finding_type, category)`` almost never collide, so the pair
    would measure the same thing every time -- nothing detected, everything a
    false positive -- and Properties 30 and 31 would never see a matched pair, a
    severity miss, or a partial detection rate. Deriving them produces all of
    those, and the unrelated Findings still supply the false positives.
    """
    exact_match = draw(st.booleans()) if exact is None else exact
    # Duplicate match keys make matching one-to-many, which would leave a
    # derived Finding unmatched and break the guarantee ``exact`` promises.
    expected = draw(
        st.lists(
            expectations(), min_size=min_size, max_size=4, unique_by=metrics.match_key
        )
    )
    if exact_match:
        return (expected, [_finding_for(item) for item in expected])

    detected = draw(st.lists(st.booleans(), min_size=len(expected), max_size=len(expected)))
    wrong_severity = draw(
        st.lists(st.one_of(st.none(), severities()), min_size=len(expected),
                 max_size=len(expected))
    )
    actual = [
        _finding_for(item, severity)
        for item, found, severity in zip(expected, detected, wrong_severity)
        if found
    ]
    # Findings no expectation claims: the false positives.
    actual.extend(draw(st.lists(finding_payloads(), max_size=2)))
    return (expected, actual)


def detection_rates() -> st.SearchStrategy[Optional[float]]:
    """A detection rate as :func:`benchmark.harness.metrics.percentage` returns it.

    ``None`` (nothing measured) and the whole ``[0, 100]`` range, with the
    threshold boundary drawn explicitly: Property 31's rule turns exactly at
    100 percent, and a generator that never produced 100.0 would leave the
    boundary untested.
    """
    return st.one_of(
        st.none(),
        st.floats(min_value=0.0, max_value=100.0, allow_nan=False, allow_infinity=False),
        st.sampled_from((0.0, 50.0, 99.9, 100.0)),
    )
