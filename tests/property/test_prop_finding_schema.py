"""Properties 1, 6 and 7: what every Finding in a Review_Report satisfies.

The three properties in this file are the ones stated over *the report*, not over
a single function. Each therefore runs the deterministic pipeline that produces a
report -- agent input through :func:`iacreview.agentin.findings_from_payload`,
then :func:`iacreview.dedup.deduplicate`, then
:func:`iacreview.report.build_report` -- and asserts its claim on the Finding
objects the report actually carries, in the serialized form a consumer reads.
Asserting on ``report["findings"]`` rather than on the ``Finding`` dataclasses is
deliberate: ``build_report`` validates before serializing, so a claim checked
only against the pre-serialization objects would not cover the step that turns
them into the report.

**Where the Sources are.** Property 1 is stated over "any Template document, any
cfn-lint output, any cfn-guard output, and any Agent finding input". The three
deterministic Sources enter here as the normalized Findings they produce
(``strategies.finding_lists()``), because that is the value the report is built
from and the only place their raw output shapes matter is in the classification
and decoding properties (9 and 10, tasks 23.2 and 23.5). Agent input enters as
the file format it really arrives in, through ``agentin``, so its normalization
layer -- the ``Confirmed`` demotion, the per-entry ``Excerpt`` requirement, and
credential redaction -- is inside the pipeline under test rather than assumed.

**Not duplicated from the smoke test.** ``test_strategies_smoke.py`` already
asserts that the *generators* satisfy several closely related things:
``findings()`` passes :func:`iacreview.finding.validate`
(``test_findings_pass_finding_validate``), respects the Confidence/Source rule by
construction (``test_findings_respect_the_confidence_source_rule``), and reaches
both a real quoted ``Excerpt`` and :data:`iacreview.finding.REDACTED_EXCERPT`
(``test_findings_reach_the_redaction_marker_and_real_excerpts``). Those are
statements about the inputs. The tests here are statements about the code under
test: the same invariants have to survive dedup's merge, report ID assignment,
sorting and serialization, which is where they could be lost and where the
generator checks say nothing.

**The agent payloads are built here.** ``strategies.findings()`` draws its
``Source`` list freely, and an agent findings *file* accepts exactly
``["Agent Review"]``; filtering for that case would discard most draws. So
:func:`_as_agent_payload` re-shapes a generated Finding into the agent file's
shape, and :func:`_credential_agent_payload` builds the one payload whose
``Excerpt`` is redacted on the way in -- Property 7's redaction branch, which has
to be reached on every example rather than occasionally.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from hypothesis import given, settings
from hypothesis import strategies as st

import strategies as S
from iacreview import agentin
from iacreview.dedup import deduplicate
from iacreview.finding import (
    AGENT_MAX_CONFIDENCE,
    AGENT_SOURCE,
    CONFIDENCE_ORDER,
    CONFIDENCES,
    CONFIRMED,
    CRITICAL_SEVERITY,
    FINDING_FIELDS,
    FINDING_TYPES,
    PARAMETERS_KEY,
    REDACTED_EXCERPT,
    SEVERITIES,
    SOURCES,
    Finding,
    from_dict,
    noecho_parameter_names,
    to_dict,
)
from iacreview.report import ReportMeta, build_report

#: The number of Finding fields Property 1 names. Pinned against
#: :data:`~iacreview.finding.FINDING_FIELDS` so that a field added to the schema
#: without updating the property is a failure here rather than a silent
#: divergence between design.md and the code.
REQUIRED_FIELD_COUNT = 13

#: Template text an agent Evidence entry quotes when the Finding it came from
#: carried no ``Excerpt``. Agent evidence must quote something
#: (``agentin._normalize_evidence``), and the wording is irrelevant to all three
#: properties -- only its presence is.
_AGENT_EXCERPT = "BucketEncryption: null"

#: Prose for the fields a Finding needs non-empty. Same reasoning as
#: ``strategies._SENTENCES``: generated text would only make a counterexample
#: harder to read.
_SENTENCE = "The quoted Parameter default may hold a credential value."

#: The ``Parameters`` attribute a credential is written into. CloudFormation's own
#: spelling, not an ``iacreview`` vocabulary, so it is written out here; the
#: section name comes from :data:`~iacreview.finding.PARAMETERS_KEY`.
_DEFAULT_KEY = "Default"


# ---------------------------------------------------------------------------
# Agent findings file payloads
# ---------------------------------------------------------------------------


def _non_critical_severities() -> st.SearchStrategy[str]:
    """A Severity other than ``CRITICAL``.

    Requirement 7 AC6 makes ``Validity`` + ``CRITICAL`` legal only for a
    deployment-blocking rule ID, and a hand-built payload carries no rule ID.
    Excluding the value is therefore a property of the payload builder, not a
    narrowing of any property: :func:`_as_agent_payload` still produces
    ``CRITICAL`` agent Findings, with the blocking rule ID its input carried.
    """
    return st.sampled_from(tuple(name for name in SEVERITIES if name != CRITICAL_SEVERITY))


def _as_agent_payload(f: Finding) -> Dict[str, Any]:
    """Re-shape ``f`` into an entry of an agent findings file.

    Three changes, each required by :mod:`iacreview.agentin`: the ``Source`` is
    ``["Agent Review"]`` and nothing else, every ``Evidence`` entry names that
    Source, and every entry quotes Template content. ``Confirmed`` is replaced
    rather than left for ``agentin`` to demote, so the file under test is one an
    honest agent could have written and stderr stays quiet.

    Everything else is preserved, including a blocking ``RuleId`` on a
    ``CRITICAL`` Finding, so the payload is accepted whole rather than dropped.
    """
    payload = to_dict(f)
    payload["Source"] = [AGENT_SOURCE]
    if payload["Confidence"] == CONFIRMED:
        payload["Confidence"] = AGENT_MAX_CONFIDENCE
    payload["Evidence"] = [
        dict(entry, Source=AGENT_SOURCE, Excerpt=entry["Excerpt"] or _AGENT_EXCERPT)
        for entry in payload["Evidence"]
    ]
    return payload


def agent_payloads() -> st.SearchStrategy[Dict[str, Any]]:
    """An agent findings file entry :mod:`iacreview.agentin` accepts."""
    return S.findings().map(_as_agent_payload)


def _credential_agent_payload(
    document: Dict[str, Any],
    secret: str,
    *,
    category: str,
    finding_type: str,
    severity: str,
) -> Dict[str, Any]:
    """An agent entry whose ``Excerpt`` quotes a ``NoEcho`` Parameter's default.

    The one input for which redaction fires: ``Location.TemplatePath`` addresses
    the declaration of a Parameter ``document`` declares ``NoEcho: true``, which
    is condition (a) of :func:`iacreview.finding.redaction_trigger`. ``agentin``
    applies :func:`iacreview.finding.redact_finding` to every accepted Finding,
    so the Excerpt that reaches the report is
    :data:`~iacreview.finding.REDACTED_EXCERPT`.

    ``Resource`` is ``None`` so the Finding is template-level and
    :func:`iacreview.finding.is_dedup_eligible` keeps it out of matching: it
    reaches the report as its own entry on every example, which is what makes
    Property 7's redaction branch reliably reachable rather than occasionally
    reachable.
    """
    parameter = sorted(noecho_parameter_names(document))[0]
    return {
        "ID": None,
        "Normalized_Category": category,
        "FindingType": finding_type,
        "Severity": severity,
        "Confidence": AGENT_MAX_CONFIDENCE,
        "Source": [AGENT_SOURCE],
        "Resource": None,
        "Location": {
            "File": S.TEMPLATE_FILES[0],
            "Line": None,
            "Column": None,
            "TemplatePath": [PARAMETERS_KEY, parameter, _DEFAULT_KEY],
        },
        "Finding": _SENTENCE,
        "WhyItMatters": _SENTENCE,
        "Evidence": [
            {
                "Source": AGENT_SOURCE,
                "Detail": _SENTENCE,
                "RuleId": None,
                "Excerpt": secret,
            }
        ],
        "Recommendation": _SENTENCE,
        "SuggestedRemediation": None,
    }


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


def _review_report(
    deterministic: List[Finding],
    agent: List[Dict[str, Any]],
    *,
    noecho_parameters: Tuple[str, ...] = (),
    meta: Optional[ReportMeta] = None,
) -> Dict[str, Any]:
    """Run the report-producing pipeline over the two kinds of Source output.

    Args:
        deterministic: Normalized Findings as cfn-lint, cfn-guard and IAM Review
            hand them over.
        agent: Entries of the agent findings file.
        noecho_parameters: ``NoEcho`` Parameter names of the reviewed Template,
            which is how credential redaction learns condition (a).
        meta: Report metadata. Defaults to an empty :class:`ReportMeta`.

    Returns:
        The report. Every agent entry is required to be accepted: the payloads
        are agent-shaped by construction, so a dropped entry means the payload
        builder and ``agentin`` disagree, and reviewing fewer Findings than were
        generated would quietly weaken all three properties.
    """
    accepted, dropped = agentin.findings_from_payload(
        {"findings": agent}, noecho_parameters=noecho_parameters
    )
    assert not dropped, dropped
    assert len(accepted) == len(agent)
    return build_report(
        deduplicate(list(deterministic) + accepted),
        [],
        ReportMeta() if meta is None else meta,
    )


def _excerpts(payload: Dict[str, Any]) -> List[str]:
    """The non-null, non-empty ``Evidence[].Excerpt`` values of ``payload``."""
    return [entry["Excerpt"] for entry in payload["Evidence"] if entry["Excerpt"]]


# ---------------------------------------------------------------------------
# Property 1
# ---------------------------------------------------------------------------


# Feature: aws-iac-review-agent-plugin, Property 1: Finding schema validity
#
# *For any* Template document, *for any* cfn-lint output, *for any* cfn-guard
# output, and *for any* Agent finding input accepted by the pipeline, every
# Finding present in the resulting Review_Report satisfies the Finding schema:
# all 13 required fields are present, `FindingType` is one of `Validity` /
# `Security` / `BestPractice` / `Informational`, `Severity` is one of `CRITICAL`
# / `HIGH` / `MEDIUM` / `LOW` / `INFO`, `Confidence` is one of `Confirmed` /
# `Likely` / `Contextual`, `Source` is a non-empty list of recognized source
# names, `ID` is a positive integer, and `Evidence` is a non-empty list.
#
# Validates: Requirements 3.2, 7.1, 7.2, 7.3, 7.7, 7.13
@settings(max_examples=100)
@given(
    deterministic=S.finding_lists(),
    agent=st.lists(agent_payloads(), max_size=3),
    meta=S.report_metas(),
)
def test_property_1_every_report_finding_satisfies_the_finding_schema(
    deterministic: List[Finding], agent: List[Dict[str, Any]], meta: ReportMeta
) -> None:
    """Each clause of the property, asserted on the serialized report.

    The closed sets are the ones :mod:`iacreview.finding` declares, so the test
    cannot pass by agreeing with a stale copy of a vocabulary. ``from_dict`` runs
    last and covers the rest of the schema -- ``additionalProperties: false``,
    ``minLength``, the ``Source`` ordering, and the four structural constraints
    JSON Schema cannot express -- against the report's own dict rather than
    against the object it was rendered from.
    """
    assert len(FINDING_FIELDS) == REQUIRED_FIELD_COUNT

    report = _review_report(deterministic, agent, meta=meta)

    for payload in report["findings"]:
        assert set(payload) == set(FINDING_FIELDS)
        assert payload["FindingType"] in FINDING_TYPES
        assert payload["Severity"] in SEVERITIES
        assert payload["Confidence"] in CONFIDENCES
        assert isinstance(payload["Source"], list) and payload["Source"]
        assert all(source in SOURCES for source in payload["Source"])
        # bool is a subclass of int, so "positive integer" has to exclude True.
        assert isinstance(payload["ID"], int) and not isinstance(payload["ID"], bool)
        assert payload["ID"] > 0
        assert isinstance(payload["Evidence"], list) and payload["Evidence"]
        # The whole schema, including what the clauses above do not name.
        from_dict(payload)


# ---------------------------------------------------------------------------
# Property 6
# ---------------------------------------------------------------------------


# Feature: aws-iac-review-agent-plugin, Property 6: Confidence is determined by Source
#
# *For any* Finding in a Review_Report, if `Source` contains only `Agent Review`
# then `Confidence` is not `Confirmed`; and if `Source` contains no
# `Agent Review` entry then `Confidence` is `Confirmed`.
#
# Validates: Requirements 7.8, 7.9, 7.10
@settings(max_examples=100)
@given(
    deterministic=S.finding_lists(),
    agent=st.lists(agent_payloads(), min_size=1, max_size=3),
)
def test_property_6_confidence_is_determined_by_source(
    deterministic: List[Finding], agent: List[Dict[str, Any]]
) -> None:
    """Both clauses, plus the mixed ``Source`` case design.md fixes as C-8.

    The property names the two pure cases. A merged Finding carries both kinds of
    Source at once, and neither clause reaches it, so the report would satisfy
    the property as written while claiming ``Confirmed`` for a conclusion resting
    partly on agent reasoning -- which Requirement 7 AC10 forbids and
    [Correction] C-8 resolves by capping the merged Confidence at
    :data:`~iacreview.finding.AGENT_MAX_CONFIDENCE`. The biconditional asserted
    here is that resolution: ``Confirmed`` if and only if ``Agent Review`` is
    absent, whatever else the ``Source`` list holds.

    The agent list is non-empty so that at least one Finding whose Source
    involves the agent reaches every report; whether it stays agent-only or
    merges into a deterministic Finding is up to ``deduplicate``, and both
    outcomes are cases the assertion covers.
    """
    report = _review_report(deterministic, agent)

    for payload in report["findings"]:
        sources = payload["Source"]
        confidence = payload["Confidence"]
        if sources == [AGENT_SOURCE]:
            assert confidence != CONFIRMED
        if AGENT_SOURCE not in sources:
            assert confidence == CONFIRMED
        else:
            # [Correction] C-8: the other side of the same rule.
            assert confidence != CONFIRMED
            assert CONFIDENCE_ORDER[confidence] <= CONFIDENCE_ORDER[AGENT_MAX_CONFIDENCE]


# ---------------------------------------------------------------------------
# Property 7
# ---------------------------------------------------------------------------


# Feature: aws-iac-review-agent-plugin, Property 7: Non-Confirmed Findings carry template evidence
#
# *For any* Finding whose `Confidence` is `Likely` or `Contextual`, at least one
# entry in `Evidence` has a non-null `Excerpt` field, unless that Excerpt was
# redacted for credential protection, in which case the redaction marker is
# present.
#
# Validates: Requirements 7.11
@settings(max_examples=100)
@given(
    deterministic=S.finding_lists(),
    agent=st.lists(agent_payloads(), max_size=2),
    credential=S.credential_templates(),
    category=S.categories_pool(),
    finding_type=S.finding_types(),
    severity=_non_critical_severities(),
)
def test_property_7_non_confirmed_findings_carry_template_evidence(
    deterministic: List[Finding],
    agent: List[Dict[str, Any]],
    credential: Tuple[Dict[str, Any], str],
    category: str,
    finding_type: str,
    severity: str,
) -> None:
    """Evidence survives both the merge and the redaction of an Excerpt.

    Every example includes one agent Finding whose ``Excerpt`` quotes a
    ``NoEcho`` Parameter's default, so redaction fires on every example and the
    property's ``unless`` branch is exercised rather than merely allowed for. The
    branch's claim is that redaction does not cost the Finding its evidence: the
    quotation is replaced by :data:`~iacreview.finding.REDACTED_EXCERPT`, which is
    non-empty, so "at least one entry has a non-null ``Excerpt``" still holds and
    the marker is what holds it.
    """
    document, secret = credential
    noecho = tuple(sorted(noecho_parameter_names(document)))
    redacted_entry = _credential_agent_payload(
        document,
        secret,
        category=category,
        finding_type=finding_type,
        severity=severity,
    )

    report = _review_report(
        deterministic, list(agent) + [redacted_entry], noecho_parameters=noecho
    )

    for payload in report["findings"]:
        if payload["Confidence"] == CONFIRMED:
            continue
        excerpts = _excerpts(payload)
        assert excerpts, payload
        # Neither ``None`` nor the empty string counts as evidence, and the
        # marker is a string like any other quotation, so one check covers the
        # redaction branch and the ordinary one.
        assert all(isinstance(excerpt, str) and excerpt for excerpt in excerpts)

    # The redaction branch is taken on every example rather than occasionally:
    # the Finding whose input Excerpt quoted the NoEcho Parameter's default
    # reaches the report carrying the marker, and went through the assertion
    # above on that basis.
    redacted = [
        payload
        for payload in report["findings"]
        if REDACTED_EXCERPT in _excerpts(payload)
    ]
    assert redacted
