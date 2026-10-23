"""Property tests for the Finding Delta matching invariants (v1.1 Task 9, Design 6-4).

Findings are drawn from small pools of Resources, Categories and Evidence so
that Identity_Key groups and Fingerprints collide often. For every generated
pair of Reports:

* I-1  a group never has both ``head_only`` and ``base_only`` entries;
* I-2  ``head_only`` <= max(0, |H| - |B|) and ``base_only`` <= max(0, |B| - |H|)
  per group;
* I-3  a stage-2 match pairs equal Fingerprints that occur once on each side;
* I-4  reordering ``findings[]`` and ``Evidence[]`` gives the same result;
* I-5  swapping Base and Head swaps the sides and New / Resolved only;
* I-6  every Finding appears in exactly one entry.

A further test checks that the output lower bound of the Delta_Report
(RC Blocker P0) never exceeds the serialized bytes, and two that the C1 /
bidi escapes (RC Blocker D-14) keep any value and any Template path after
``json.loads``. A last test records how
the matching time grows when the Finding count doubles. It is a diagnostic
(Requirement 14 AC10) and asserts nothing about time.
"""

from __future__ import annotations

import dataclasses
import json
import random
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from iacreview import delta, deltaio, deltareport, deltaschema, semdiff
from iacreview.delta import DeltaEntry, FindingDeltaResult, IdentityKey
from iacreview.deltaio import ParsedTemplate
from iacreview.deltareport import DeltaRequest, TemplateInput
from iacreview.finding import Evidence, Finding, Location
from iacreview.reportcheck import CheckedReport, ToolRecord

MAX_EXAMPLES = 150
FILE = "templates/app.yaml"
SOURCES = ("cfn-lint", "cfn-guard", "IAM Review", "Network Review", "Secret Review", "Quality Review")
RESOURCES = (None, "A", "B")
CATEGORIES = ("Encryption", "Logging", "Other")
EVIDENCE = (("cfn-guard", "g1"), ("cfn-guard", "g2"), ("cfn-lint", "W1"), ("cfn-guard", None))
PATHS = (None, ("Resources", "A"), ("Resources", "A", "Properties"))
DECLARATION_SETS = (frozenset(), frozenset(delta.REPORT_DECLARATIONS))
SWAP = {
    "head_only": "base_only",
    "base_only": "head_only",
    "New": "Resolved",
    "Resolved": "New",
}


@st.composite
def _findings(draw: Any) -> Finding:
    evidence = draw(st.lists(st.sampled_from(EVIDENCE), min_size=1, max_size=3))
    category = draw(st.sampled_from(CATEGORIES))
    sources = sorted({source for source, _ in evidence}, key=SOURCES.index)
    if category == "Other":
        # ``Other`` cannot carry a merged Source list (finding.validate).
        evidence = [item for item in evidence if item[0] == sources[0]]
        sources = sources[:1]
    path = draw(st.sampled_from(PATHS))
    return Finding(
        ID=0,
        Normalized_Category=category,
        FindingType=draw(st.sampled_from(("Security", "BestPractice"))),
        Severity=draw(st.sampled_from(("HIGH", "LOW"))),
        Confidence="Confirmed",
        Source=sources,
        Resource=draw(st.sampled_from(RESOURCES)),
        Location=Location(File=FILE, TemplatePath=None if path is None else list(path)),
        Finding="text",
        WhyItMatters="why",
        Evidence=[Evidence(Source=s, Detail="d", RuleId=r) for s, r in evidence],
        Recommendation="fix",
        SuggestedRemediation=None,
    )


def _numbered(findings: Sequence[Finding]) -> Tuple[Finding, ...]:
    out = []
    for index, f in enumerate(findings, start=1):
        out.append(
            Finding(**{**f.__dict__, "ID": index})  # type: ignore[arg-type]
        )
    return tuple(out)


def _report(findings: Sequence[Finding], tools: Tuple[ToolRecord, ...] = ()) -> CheckedReport:
    return CheckedReport(
        schema_version="1.0.0",
        files=(FILE,),
        synthesized_templates=(),
        cdk_detected=False,
        cdk_synthesis="not_applicable",
        sources_enabled=SOURCES,
        tools=tools or (ToolRecord("cfn-guard", True, "3.2.1"), ToolRecord("cfn-lint", True, "1.46.0")),
        errors=(),
        findings=tuple(findings),
        integrity_failures=(),
    )


_lists = st.lists(_findings(), max_size=8)


def _run(base: CheckedReport, head: CheckedReport, declarations: frozenset = frozenset()) -> FindingDeltaResult:
    return delta.match_and_classify(base, head, declarations=declarations, correspondence="not_applicable")


def _groups(result: FindingDeltaResult) -> Dict[IdentityKey, List[DeltaEntry]]:
    groups: Dict[IdentityKey, List[DeltaEntry]] = {}
    for entry in result.entries:
        groups.setdefault(entry.key, []).append(entry)
    return groups


def _sizes(findings: Sequence[Finding]) -> Counter:
    return Counter(delta.identity_key(f) for f in findings)


@settings(max_examples=MAX_EXAMPLES, deadline=None)
@given(_lists, _lists, st.sampled_from(DECLARATION_SETS))
def test_i1_i2_i6_group_invariants(base_list: List[Finding], head_list: List[Finding], declarations: frozenset) -> None:
    base_findings, head_findings = _numbered(base_list), _numbered(head_list)
    result = _run(_report(base_findings), _report(head_findings), declarations)
    base_sizes, head_sizes = _sizes(base_findings), _sizes(head_findings)
    for key, entries in _groups(result).items():
        observations = Counter(entry.observation for entry in entries)
        assert not (observations["head_only"] and observations["base_only"])  # I-1
        assert observations["head_only"] <= max(0, head_sizes[key] - base_sizes[key])  # I-2
        assert observations["base_only"] <= max(0, base_sizes[key] - head_sizes[key])  # I-2
    base_ids = Counter(e.base.ID for e in result.entries if e.base is not None)
    head_ids = Counter(e.head.ID for e in result.entries if e.head is not None)
    assert base_ids == Counter(f.ID for f in base_findings)  # I-6
    assert head_ids == Counter(f.ID for f in head_findings)  # I-6
    for entry in result.entries:
        assert entry.observation in deltaschema.ENTRY_OBSERVATIONS
        assert entry.classification in deltaschema.DELTA_CLASSIFICATIONS
        assert (entry.match_stage is not None) == (entry.observation == "matched")
        if entry.classification in ("New", "Resolved"):
            assert declarations == DECLARATION_SETS[1]


@settings(max_examples=MAX_EXAMPLES, deadline=None)
@given(_lists, _lists)
def test_i3_stage_two_pairs_unique_equal_fingerprints(base_list: List[Finding], head_list: List[Finding]) -> None:
    base_findings, head_findings = _numbered(base_list), _numbered(head_list)
    result = _run(_report(base_findings), _report(head_findings))
    base_counts = Counter(delta.fingerprint(f) for f in base_findings)
    head_counts = Counter(delta.fingerprint(f) for f in head_findings)
    for entry in result.entries:
        if entry.match_stage == 2:
            assert entry.base is not None and entry.head is not None
            fingerprint = entry.base.fingerprint
            assert fingerprint == entry.head.fingerprint
            assert base_counts[fingerprint] == 1 and head_counts[fingerprint] == 1
            assert entry.changes == () or set(entry.changes) <= {"Severity", "Confidence", "Source"}
        if entry.match_stage == 1:
            assert entry.key.Resource is not None and entry.key.Normalized_Category != "Other"


@settings(max_examples=MAX_EXAMPLES, deadline=None)
@given(_lists, _lists, st.randoms(use_true_random=False))
def test_i4_input_order_does_not_matter(base_list: List[Finding], head_list: List[Finding], rng: random.Random) -> None:
    base_findings, head_findings = _numbered(base_list), _numbered(head_list)

    def shuffled(findings: Sequence[Finding]) -> List[Finding]:
        out = []
        for f in findings:
            evidence = list(f.Evidence)
            rng.shuffle(evidence)
            out.append(Finding(**{**f.__dict__, "Evidence": evidence}))  # type: ignore[arg-type]
        rng.shuffle(out)
        return out

    first = _run(_report(base_findings), _report(head_findings), DECLARATION_SETS[1])
    second = _run(_report(shuffled(base_findings)), _report(shuffled(head_findings)), DECLARATION_SETS[1])
    assert first == second


def _swapped(entry: DeltaEntry) -> Tuple[Any, ...]:
    return (
        SWAP.get(entry.observation, entry.observation),
        SWAP.get(entry.classification, entry.classification),
        entry.reasons,
        entry.missing_declarations,
        entry.match_stage,
        entry.head,
        entry.base,
        entry.changes,
        entry.evidence_absent_in_base,
        entry.evidence_absent_in_head,
    )


def _plain(entry: DeltaEntry) -> Tuple[Any, ...]:
    return (
        entry.observation,
        entry.classification,
        entry.reasons,
        entry.missing_declarations,
        entry.match_stage,
        entry.base,
        entry.head,
        entry.changes,
        entry.evidence_absent_in_head,
        entry.evidence_absent_in_base,
    )


@settings(max_examples=MAX_EXAMPLES, deadline=None)
@given(_lists, _lists, st.sampled_from(DECLARATION_SETS))
def test_i5_swapping_sides(base_list: List[Finding], head_list: List[Finding], declarations: frozenset) -> None:
    base, head = _report(_numbered(base_list)), _report(_numbered(head_list))
    forward = _run(base, head, declarations)
    backward = _run(head, base, declarations)
    assert Counter(_swapped(e) for e in forward.entries) == Counter(_plain(e) for e in backward.entries)
    assert forward.observation == backward.observation
    assert forward.classification_completeness == backward.classification_completeness


@settings(max_examples=MAX_EXAMPLES, deadline=None)
@given(_lists)
def test_self_comparison_is_unchanged_or_ambiguous(findings: List[Finding]) -> None:
    numbered = _numbered(findings)
    result = _run(_report(numbered), _report(numbered), DECLARATION_SETS[1])
    for entry in result.entries:
        assert entry.classification in ("Unchanged", "Ambiguous")
        assert entry.changes == () and entry.evidence_absent_in_head == () and entry.evidence_absent_in_base == ()


@settings(max_examples=MAX_EXAMPLES, deadline=None)
@given(_lists, _lists)
def test_unavailable_tool_never_gives_new_or_resolved_for_its_source(
    base_list: List[Finding], head_list: List[Finding]
) -> None:
    head_tools = (ToolRecord("cfn-guard", False, None), ToolRecord("cfn-lint", True, "1.46.0"))
    result = _run(_report(_numbered(base_list)), _report(_numbered(head_list), head_tools), DECLARATION_SETS[1])
    for entry in result.entries:
        side = entry.base if entry.base is not None else entry.head
        assert side is not None
        if "cfn-guard" in side.Source and entry.classification in ("New", "Resolved"):
            pytest.fail("a cfn-guard Finding was decided while cfn-guard was unavailable")


def _diagnostic_findings(count: int) -> List[Finding]:
    rng = random.Random(1234)
    out = []
    for index in range(count):
        resource: Optional[str] = None if index % 3 == 0 else "R{0}".format(index % 50)
        out.append(
            Finding(
                ID=index + 1,
                Normalized_Category="Other" if index % 5 == 0 else "Encryption",
                FindingType="Security",
                Severity="HIGH",
                Confidence="Confirmed",
                Source=["cfn-guard"],
                Resource=resource,
                Location=Location(File=FILE, TemplatePath=["Resources", "R", rng.randrange(1000)]),
                Finding="t",
                WhyItMatters="w",
                Evidence=[Evidence(Source="cfn-guard", Detail="d", RuleId="r{0}".format(rng.randrange(20)))],
                Recommendation="r",
                SuggestedRemediation=None,
            )
        )
    return out


def test_matching_time_growth_is_recorded(record_property: Any) -> None:
    """Diagnostic only (R14.7, R14.10): the ratio is recorded, never asserted."""
    timings: Dict[int, float] = {}
    for count in (2000, 4000):
        findings = _diagnostic_findings(count)
        base, head = _report(findings), _report(list(reversed(findings)))
        start = time.perf_counter()
        result = _run(base, head)
        timings[count] = time.perf_counter() - start
        assert len(result.entries) <= 2 * count
    ratio = timings[4000] / timings[2000] if timings[2000] else 0.0
    record_property("delta_match_seconds_2000", round(timings[2000], 4))
    record_property("delta_match_seconds_4000", round(timings[4000], 4))
    record_property("delta_match_growth_ratio", round(ratio, 2))


# ---------------------------------------------------------------------------
# RC Blocker P0: the output lower bound never exceeds the real output
# ---------------------------------------------------------------------------

_BOUND_KEYS = ("", "0", "7", "12", "a", "Type", "Properties", "Ref", "Fn::If", "日本")
_BOUND_LEAVES = st.one_of(
    st.integers(min_value=0, max_value=20),
    st.sampled_from(("", "x", "日本", "v")),
    st.booleans(),
    st.none(),
)
_BOUND_VALUES = st.recursive(
    _BOUND_LEAVES,
    lambda inner: st.one_of(
        st.lists(inner, max_size=3),
        st.dictionaries(st.sampled_from(_BOUND_KEYS), inner, max_size=3),
    ),
    max_leaves=12,
)
_BOUND_RESOURCES = st.dictionaries(
    st.sampled_from(("A", "B", "0", "12", "Bucket")),
    st.fixed_dictionaries(
        {"Type": st.sampled_from(("AWS::S3::Bucket", "AWS::SNS::Topic", "Custom::X", "odd"))},
        optional={"Properties": _BOUND_VALUES},
    ),
    min_size=1,
    max_size=3,
)
_BOUND_DOCS = st.fixed_dictionaries(
    {"Resources": _BOUND_RESOURCES},
    optional={"Outputs": st.dictionaries(st.sampled_from(_BOUND_KEYS), _BOUND_VALUES, max_size=2)},
)
_BOUND_PATH_ITEMS = st.one_of(st.sampled_from(_BOUND_KEYS), st.integers(min_value=0, max_value=1_000_000))
_BOUND_UNCOMPARED = st.lists(
    st.tuples(st.lists(_BOUND_PATH_ITEMS, max_size=5), st.sampled_from(deltaschema.UNCOMPARED_REASONS)),
    max_size=4,
)


def _bound_parsed(doc: Dict[str, Any], side: str) -> Any:
    return deltaio.parse_template(json.dumps(doc), Path(side + ".json"), side)


@settings(max_examples=MAX_EXAMPLES, deadline=None)
@given(_BOUND_DOCS, _BOUND_DOCS, _BOUND_UNCOMPARED)
def test_output_lower_bound_is_at_most_the_serialized_bytes(
    base_doc: Dict[str, Any], head_doc: Dict[str, Any], uncompared: List[Tuple[List[Any], str]]
) -> None:
    base, head = _bound_parsed(base_doc, "base"), _bound_parsed(head_doc, "head")
    assume(isinstance(base, ParsedTemplate) and isinstance(head, ParsedTemplate))
    result = semdiff.diff(base, head)
    assume(isinstance(result, semdiff.SemanticDiffResult))
    extra = tuple(semdiff.UncomparedPath(tuple(path), reason) for path, reason in uncompared)
    result = dataclasses.replace(result, uncompared_paths=result.uncompared_paths + extra)
    request = DeltaRequest(
        templates=(TemplateInput("base.json", base), TemplateInput("head.json", head)),
        reports=None,
        semantic_diff=result,
        finding_delta=None,
    )
    bound = deltareport._output_lower_bound(request, ())
    for mode in deltaschema.IDENTIFIER_MODES:
        rendered = deltareport.render_delta_report(request, mode)
        assert rendered.exit_code == 0
        assert bound <= len(rendered.text.encode("utf-8"))


# ---------------------------------------------------------------------------
# RC Blocker D-14: C1 / bidi escapes keep the JSON value
# ---------------------------------------------------------------------------

#: Any character but a lone surrogate (UTF-8 cannot carry one), with the
#: D-14 code points drawn often.
_ANY_CHARS = st.one_of(
    st.characters(blacklist_categories=("Cs",)),
    st.sampled_from(sorted(chr(code) for code in deltareport.DISPLAY_ESCAPED_CODE_POINTS)),
    st.sampled_from(("\\", '"', "\n", "\x00", "u", "2", "e")),
)
_ANY_TEXT = st.text(_ANY_CHARS, max_size=12)
_ANY_JSON = st.recursive(
    st.one_of(_ANY_TEXT, st.integers(), st.booleans(), st.none()),
    lambda inner: st.one_of(st.lists(inner, max_size=3), st.dictionaries(_ANY_TEXT, inner, max_size=3)),
    max_leaves=10,
)


def _raw_display_unsafe(text: str) -> List[str]:
    return [hex(ord(c)) for c in text if ord(c) in deltareport.DISPLAY_ESCAPED_CODE_POINTS]


@settings(max_examples=MAX_EXAMPLES, deadline=None)
@given(_ANY_JSON)
def test_dump_round_trips_and_writes_no_raw_display_control(value: Any) -> None:
    from iacreview import report

    text = deltareport.dump(value)
    assert json.loads(text) == value
    assert _raw_display_unsafe(text) == []
    assert text.endswith("\n")
    expected = report.dump(value)
    if not _raw_display_unsafe(expected):
        assert text == expected
    size = len(text.encode("utf-8"))
    assert deltareport._serialize(value, size) == text
    assert deltareport._serialize(value, size - 1) is None


@settings(max_examples=MAX_EXAMPLES, deadline=None)
@given(_ANY_TEXT.filter(bool), _ANY_TEXT.filter(bool), st.sampled_from(deltaschema.IDENTIFIER_MODES))
def test_any_template_path_round_trips_through_the_delta_report(base_path: str, head_path: str, mode: str) -> None:
    doc = {"Resources": {"A": {"Type": "AWS::S3::Bucket"}}}
    base, head = _bound_parsed(doc, "base"), _bound_parsed(doc, "head")
    assert isinstance(base, ParsedTemplate) and isinstance(head, ParsedTemplate)
    result = semdiff.diff(base, head)
    assert isinstance(result, semdiff.SemanticDiffResult)
    request = DeltaRequest(
        templates=(TemplateInput(base_path, base), TemplateInput(head_path, head)),
        reports=None,
        semantic_diff=result,
        finding_delta=None,
    )
    rendered = deltareport.render_delta_report(request, mode)
    assert rendered.exit_code == 0
    assert _raw_display_unsafe(rendered.text) == []
    built = json.loads(rendered.text)
    assert built["inputs"]["base"]["template"]["path"] == base_path
    assert built["inputs"]["head"]["template"]["path"] == head_path
    assert rendered.text == deltareport.render_delta_report(request, mode).text
