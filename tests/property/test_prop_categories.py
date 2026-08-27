"""Correctness Properties 2, 8 and 9: the Normalized_Category boundary.

Three properties about what the normalization layer is allowed to say about a
category, a Severity and a FindingType.

Property 2 (category closure)
    Every Source's normalizer is asked directly, not through the orchestrator:
    :func:`iacreview.cfnlint.finding_from_result`,
    :func:`iacreview.cfnguard.finding_from_result`,
    :func:`iacreview.iam.detectors.scan`, and
    :func:`iacreview.agentin.findings_from_payload`. Those four functions are the
    only places a ``Normalized_Category`` is decided, and each decides it from a
    different source of truth -- ``category_map.json`` prefix rules, the
    ``rules/**/_meta.json`` sidecars, a module constant, and untrusted agent
    input. A property stated over the pipeline would pass while any one of them
    was wrong, because a Source that produced no Finding would satisfy it
    vacuously.

Property 8 (Validity CRITICAL requires a deployment-blocking rule)
    Checked at all three points the claim can be made: the classification, the
    Finding the cfn-lint Source builds from it, and the output of a dedup merge.
    The third is not redundant. ``deduplicate`` takes the maximum Severity and
    the highest-precedence FindingType *independently*, so merging a
    ``BestPractice`` + ``CRITICAL`` Finding with a ``Validity`` + ``LOW`` one
    yields ``Validity`` + ``CRITICAL`` -- a combination neither input claimed.
    Requirement 7 AC6 has to hold for that Finding too, and the only thing that
    can justify it is a deployment-blocking ``RuleId`` carried in the merged
    Evidence. ``tests/property/strategies.py`` constrains every generated
    ``CRITICAL`` Finding for exactly this reason; this test is what the
    constraint exists to make checkable.

Property 9 (cfn-lint classification totality)
    ``rule_ids()`` generates arbitrary text alongside plausible cfn-lint
    identifiers, and the empty string is added here, so "any rule ID string" is
    the input space rather than "any well-formed rule ID". Totality is asserted
    by the call itself: ``classify_cfnlint`` returning at all is the property, and
    a raise fails the test with the offending pair.

**No vocabulary is restated.** The closed category set comes from
:meth:`iacreview.categories.CategoryMap.categories`, the FindingType and Severity
sets from :mod:`iacreview.finding`, the levels from
:data:`iacreview.categories.CFNLINT_LEVELS`, and the level defaults Property 9's
last two clauses name ("BestPractice and MEDIUM", "Informational and LOW") from
:meth:`~iacreview.categories.CategoryMap.cfnlint_level_default`. Reading them
from the mapping file is what makes the assertion about ``classify_cfnlint``
rather than about the file: the interesting content is that the classifier leaves
those defaults *alone* for an un-overridden Warning or Informational, when it
does apply a prefix Category and could have applied a promotion.

``tests/unit/test_categories.py`` pins the concrete values on the other side of
that line -- that ``Warning`` means MEDIUM, that the 26 surveyed rules block
deployment, that the 7 surveyed rules are security-relevant -- against literal
lists, and is not duplicated here. What the unit tests cannot do is quantify over
rule IDs the mapping file has never seen, which is Property 9's subject and the
reason design.md asks for it (Open Question 5: an unknown rule ID must always
resolve through the prefix rules).
"""

from __future__ import annotations

import json
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

from hypothesis import given, settings
from hypothesis import strategies as st

import strategies as S
from iacreview import agentin, categories, cfnguard, cfnlint, pathguard
from iacreview.categories import SECURITY_FINDING_TYPE, CategoryMap
from iacreview.dedup import deduplicate
from iacreview.finding import (
    AGENT_MAX_CONFIDENCE,
    AGENT_SOURCE,
    CRITICAL_SEVERITY,
    FINDING_TYPES,
    SEVERITIES,
    VALIDITY_TYPE,
    Finding,
    to_dict,
)
from iacreview.iam import detectors, locate

#: ``Location.File`` every constructed Finding carries. Workspace-relative, from
#: the shared strategies module, so no path literal appears here.
TEMPLATE_FILE: str = S.TEMPLATE_FILES[0]

#: ``Evidence[].Excerpt`` supplied when an agent entry needs one. Agent Findings
#: must quote Template text (design.md, Layer 2 constraint 3); the content is
#: irrelevant to these properties, only its presence is.
QUOTED_EXCERPT = 'Action: "*"'


def _cmap() -> CategoryMap:
    """The bundled mapping file. Cached by the loader, so this is not disk I/O."""
    return categories.load_map()


@lru_cache(maxsize=1)
def _guard_metadata() -> cfnguard.RuleMetadata:
    """The bundled ``rules/**/_meta.json`` sidecars.

    Cached because :func:`~iacreview.cfnguard.load_rule_metadata` walks the rules
    directory on every call, and 100 examples would walk it 100 times without
    changing what any of them assert.
    """
    return cfnguard.load_rule_metadata()


# ---------------------------------------------------------------------------
# Inputs the shared strategies module does not carry
# ---------------------------------------------------------------------------
#
# Each of these is a Source's *raw result* type rather than a Finding, which
# ``strategies.py`` has no generator for. They are built here rather than added
# there because only these three properties consume them.


def _cfnlint_result(rule_id: str, level: str) -> cfnlint.RawResult:
    """One cfn-lint result carrying only the fields classification reads.

    Everything else is the minimum the Finding schema accepts, so a failure names
    the rule ID and level rather than some incidental field.
    """
    return cfnlint.RawResult(
        rule_id=rule_id,
        rule_short_description=None,
        rule_description=None,
        rule_source=None,
        level=level,
        message="a generated cfn-lint result",
        line=1,
        column=1,
        template_path=(cfnlint.RESOURCES_SECTION, "A"),
        filename=None,
    )


def _guard_result(rule_name: str) -> cfnguard.RawResult:
    """One violated cfn-guard check, with no clause text or values.

    All the optional fields are absent on purpose: the Category comes from the
    rule name alone, and populating the rest would only exercise the wording
    fallbacks, which belong to a different property.
    """
    return cfnguard.RawResult(
        rule_name=rule_name,
        resource="A",
        template_path=(cfnguard.RESOURCES_SECTION, "A"),
        provided_value=None,
        expected_value=None,
        custom_message=None,
        error_message=None,
        context=None,
    )


def _agent_entry(source: Finding, category: Optional[str]) -> Dict[str, Any]:
    """One entry of an agent findings file, derived from a valid Finding.

    Derived rather than built from scratch so the entry satisfies the structural
    constraints :func:`iacreview.finding.validate` enforces -- in particular that
    a ``Validity`` + ``CRITICAL`` entry carries a deployment-blocking ``RuleId``,
    which the generator already arranged. Building one here would mean
    reimplementing that arrangement, and an entry that failed validation would be
    dropped, leaving Property 2 with nothing from this Source to assert on.

    Three fields are rewritten into what the agent boundary accepts: the Source
    is Agent Review alone, the Confidence is capped at
    :data:`~iacreview.finding.AGENT_MAX_CONFIDENCE` (Requirement 7 AC10), and
    every Evidence entry names the agent and quotes something.

    Args:
        source: A valid Finding to derive the entry from.
        category: The ``Normalized_Category`` the agent claims. May be a name
            outside the closed set, or ``None``; both are what Requirement 14 AC3
            falls back to ``Other`` for, and Property 2 is the check that the
            fallback lands inside the set.
    """
    payload = to_dict(source)
    payload["Source"] = [AGENT_SOURCE]
    payload["Confidence"] = AGENT_MAX_CONFIDENCE
    payload["Normalized_Category"] = category
    payload["Evidence"] = [
        dict(
            entry,
            Source=AGENT_SOURCE,
            Excerpt=entry["Excerpt"] or QUOTED_EXCERPT,
        )
        for entry in payload["Evidence"]
    ]
    return payload


def _guard_rule_names() -> st.SearchStrategy[str]:
    """A cfn-guard rule name: one the sidecars know, or arbitrary text.

    The known names are discovered from the loaded metadata rather than listed,
    so a rule added under ``rules/`` is covered without editing this file. The
    arbitrary half reaches the ``Other`` fallback of
    :meth:`~iacreview.categories.CategoryMap.for_guard_rule`.
    """
    return st.one_of(
        st.sampled_from(_guard_metadata().rule_names()),
        st.text(min_size=1, max_size=12),
    )


def _any_rule_ids() -> st.SearchStrategy[str]:
    """Any rule ID string, the empty one included.

    :func:`strategies.rule_ids` covers plausible identifiers and arbitrary text
    from one character up; Property 9 is stated over *any* string, and the empty
    string is the boundary that phrase includes.
    """
    return st.one_of(S.rule_ids(), st.just(""))


@lru_cache(maxsize=1)
def _mapping_document() -> Dict[str, Any]:
    """The bundled mapping file as raw JSON, for discovering its rule IDs.

    :class:`~iacreview.categories.CategoryMap` answers questions *about* a rule
    ID and exposes no way to enumerate the ones it has entries for, which is what
    a generator needs. Read through
    :func:`iacreview.pathguard.resolve_plugin_owned` so no path literal appears
    here, and the same way ``tests/unit/test_categories.py`` reads it for its
    drift checks.
    """
    source = pathguard.resolve_plugin_owned(categories.DEFAULT_MAP_RELATIVE_PATH)
    return json.loads(source.read_text(encoding="utf-8"))


def _overridden_rule_ids() -> Tuple[str, ...]:
    """Every cfn-lint rule ID the mapping file states something about."""
    return tuple(sorted(_mapping_document()["cfnlint"]["rule_overrides"]))


def _security_relevant_rule_ids() -> Tuple[str, ...]:
    """Every rule ID marked ``security_relevant`` (Requirement 4 AC9).

    Discovered rather than listed, so the clause of Property 9 that quantifies
    over them widens with the mapping file. Without this branch the clause is
    unreachable in practice: the plausible-identifier pool of
    :func:`strategies.rule_ids` spans 150 shapes and reaches a marked rule in
    well under one example in a hundred, which would leave the clause passing
    without ever being evaluated.
    """
    overrides = _mapping_document()["cfnlint"]["rule_overrides"]
    return tuple(
        sorted(
            rule_id
            for rule_id, entry in overrides.items()
            if entry.get("security_relevant") is True
        )
    )


def _classifiable_rule_ids() -> st.SearchStrategy[str]:
    """Property 9's input space: any string, weighted toward the mapped rules.

    Three branches of equal weight. The arbitrary one is what totality is stated
    over, and it is also where the un-overridden rules come from, which the last
    two clauses need. The two discovered ones carry the rules the mapping file
    has an opinion about, which the ``security_relevant`` clause needs and which
    an unweighted draw reaches too rarely to count as tested.
    """
    return st.one_of(
        _any_rule_ids(),
        st.sampled_from(_overridden_rule_ids()),
        st.sampled_from(_security_relevant_rule_ids()),
    )


def _claimed_categories() -> st.SearchStrategy[Optional[str]]:
    """A ``Normalized_Category`` an agent might claim: valid, unknown, or absent."""
    return st.one_of(S.categories_pool(), st.text(max_size=10), st.none())


def _blocking_rule_ids_in(f: Finding, cmap: CategoryMap) -> List[str]:
    """Every ``Evidence[].RuleId`` of ``f`` that blocks deployment."""
    return [
        entry.RuleId
        for entry in f.Evidence
        if entry.RuleId and cmap.blocks_deployment(entry.RuleId)
    ]


# ---------------------------------------------------------------------------
# Property 2
# ---------------------------------------------------------------------------


# Feature: aws-iac-review-agent-plugin, Property 2: *For any* Finding emitted by
# any Source through the normalization layer, `Normalized_Category` is a member
# of the closed set declared in `category_map.json` (`IAM`, `Encryption`,
# `PublicAccess`, `Logging`, `Tagging`, `Availability`, `Backup`,
# `NetworkSecurity`, `DataProtection`, `TemplateQuality`, `Other`).
@settings(max_examples=100, deadline=None)
@given(
    rule_id=_any_rule_ids(),
    level=st.one_of(S.cfnlint_levels(), st.text(max_size=10)),
    guard_rule=_guard_rule_names(),
    iam_template=S.iam_templates(),
    agent_source=S.findings(),
    claimed_category=_claimed_categories(),
)
def test_every_source_emits_a_declared_normalized_category(
    rule_id: str,
    level: str,
    guard_rule: str,
    iam_template: Dict[str, Any],
    agent_source: Finding,
    claimed_category: Optional[str],
) -> None:
    """All four Sources, on one draw each, must stay inside the closed set.

    The three deterministic Sources always contribute at least one Finding, so
    the assertion is never vacuous; the IAM detectors and the agent boundary
    contribute a varying number, including none, which is a legitimate outcome
    for both.
    """
    cmap = _cmap()

    emitted: List[Finding] = [
        cfnlint.finding_from_result(
            _cfnlint_result(rule_id, level),
            template_file=TEMPLATE_FILE,
            cmap=cmap,
        ),
        cfnguard.finding_from_result(
            _guard_result(guard_rule),
            template_file=TEMPLATE_FILE,
            metadata=_guard_metadata(),
        ),
    ]
    emitted.extend(
        detectors.scan(
            locate.find_policy_documents(iam_template), template_file=TEMPLATE_FILE
        )
    )
    accepted, _rejected = agentin.findings_from_payload(
        [_agent_entry(agent_source, claimed_category)]
    )
    emitted.extend(accepted)

    for f in emitted:
        assert f.Normalized_Category in cmap.categories
        assert cmap.is_valid_category(f.Normalized_Category)


# ---------------------------------------------------------------------------
# Property 8
# ---------------------------------------------------------------------------


# Feature: aws-iac-review-agent-plugin, Property 8: *For any* cfn-lint result
# classified by the normalization layer, if the resulting `FindingType` is
# `Validity` and the resulting `Severity` is `CRITICAL`, then the resolved
# `blocks_deployment` flag for that rule ID is true.
@settings(max_examples=100, deadline=None)
@given(
    rule_id=st.one_of(_any_rule_ids(), S.blocking_rule_ids()),
    level=S.cfnlint_levels(),
    items=S.finding_lists(),
)
def test_validity_critical_requires_a_deployment_blocking_rule(
    rule_id: str, level: str, items: List[Finding]
) -> None:
    """The claim is checked wherever it can be made.

    ``blocking_rule_ids()`` is drawn alongside the general rule IDs so the
    implication has a true antecedent on a good share of the examples: a rule the
    mapping file marks, at ``Error`` level, is the only way to reach ``Validity``
    + ``CRITICAL`` at all.

    The dedup pass is the case a single classification cannot show, and the one
    the strategies module constrains its ``CRITICAL`` Findings for: a merge
    combines the maximum Severity with the highest-precedence FindingType, so it
    can produce a ``Validity`` + ``CRITICAL`` Finding out of two inputs that were
    each something else.
    """
    cmap = _cmap()

    classification = categories.classify_cfnlint(rule_id, level, cmap)
    if (
        classification.finding_type == VALIDITY_TYPE
        and classification.severity == CRITICAL_SEVERITY
    ):
        assert cmap.blocks_deployment(rule_id) is True

    emitted = cfnlint.finding_from_result(
        _cfnlint_result(rule_id, level), template_file=TEMPLATE_FILE, cmap=cmap
    )
    if emitted.FindingType == VALIDITY_TYPE and emitted.Severity == CRITICAL_SEVERITY:
        assert _blocking_rule_ids_in(emitted, cmap)

    for merged in deduplicate(items):
        if merged.FindingType == VALIDITY_TYPE and merged.Severity == CRITICAL_SEVERITY:
            assert _blocking_rule_ids_in(merged, cmap)


# ---------------------------------------------------------------------------
# Property 9
# ---------------------------------------------------------------------------


# Feature: aws-iac-review-agent-plugin, Property 9: *For any* pair of a rule ID
# string and a cfn-lint level (`Error`, `Warning`, `Informational`), the
# classification function returns a `FindingType`, a `Severity`, and a
# `Normalized_Category` all drawn from their respective closed sets, and never
# raises. Additionally: a `security_relevant` rule ID always yields `FindingType`
# `Security`; a `Warning` level with no override yields `BestPractice` and
# `MEDIUM`; an `Informational` level with no override yields `Informational` and
# `LOW`.
@settings(max_examples=100, deadline=None)
@given(rule_id=_classifiable_rule_ids(), level=S.cfnlint_levels())
def test_cfnlint_classification_is_total(rule_id: str, level: str) -> None:
    """Totality first, then the three clauses that name a specific outcome.

    The call not raising is the totality half of the property: ``rule_id`` is
    arbitrary text, so an identifier the mapping file has never seen has to
    resolve through the prefix rules instead of failing the review (design.md,
    Open Question 5).

    ``BestPractice`` / ``MEDIUM`` and ``Informational`` / ``LOW`` are read from
    ``cfnlint.level_defaults`` rather than written here, so the assertion is that
    the classifier *leaves the level default alone* for an un-overridden rule at
    those levels. It could have done otherwise: it applies a prefix Category on
    the same call, and it promotes to ``CRITICAL`` on another. The concrete
    values behind those names are pinned literally in
    ``tests/unit/test_categories.py``.
    """
    cmap = _cmap()

    result = categories.classify_cfnlint(rule_id, level, cmap)

    assert result.category in cmap.categories
    assert result.finding_type in FINDING_TYPES
    assert result.severity in SEVERITIES

    override = cmap.cfnlint_override(rule_id)
    if override is not None and override.get("security_relevant"):
        assert result.finding_type == SECURITY_FINDING_TYPE

    if override is None and level != categories.ERROR_LEVEL:
        default = cmap.cfnlint_level_default(level)
        assert result.finding_type == default.finding_type
        assert result.severity == default.severity
