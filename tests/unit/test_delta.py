"""Unit tests for :mod:`iacreview.delta` (v1.1 Task 9).

* The Task 2 Report fixtures, each with its declaration sets (all / none / one
  missing for the classification cases), against the hand-written expected
  Delta_Entries.
* Design E-1 to E-7 on small Reports built with ``report.build_report``.
* Classification safety: a tool that is missing or unavailable, a Source that
  did not run, a tool version mismatch, Source errors, a failed
  internal-consistency check, a rename hint or a Template / Report mismatch
  never give ``New`` / ``Resolved``, even with every declaration; a partial
  loss of Evidence never gives ``Resolved``.
* The result carries no free text and records declarations as declared, not
  verified.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Sequence, Tuple

import pytest

from iacreview import delta, deltaio, deltaschema, report, reportcheck, semdiff
from iacreview.delta import DeltaEntry, EvidenceDelta, FindingDeltaResult
from iacreview.finding import Evidence, Finding, Location
from iacreview.reportcheck import CheckedReport

REPO_ROOT = Path(__file__).resolve().parents[2]
DELTA_REPORTS = REPO_ROOT / "tests" / "fixtures" / "delta" / "reports"
REPORT_CASES = sorted(path.name for path in DELTA_REPORTS.iterdir() if path.is_dir())
DETERMINISTIC = ["cfn-lint", "cfn-guard", "IAM Review", "Network Review", "Secret Review", "Quality Review"]
FILE = "templates/app.yaml"
ALL = frozenset(delta.REPORT_DECLARATIONS)
ALL_WITH_TEMPLATES = frozenset(deltaschema.DECLARATION_CODES)


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def _finding(
    text: str,
    resource: Optional[str] = "Bucket",
    category: str = "Encryption",
    evidence: Sequence[Tuple[str, Optional[str]]] = (("cfn-guard", "s3_bucket_encryption"),),
    path: Optional[List[Any]] = None,
    severity: str = "HIGH",
    confidence: str = "Confirmed",
    finding_type: str = "Security",
    file: str = FILE,
) -> Finding:
    sources = sorted({source for source, _ in evidence}, key=DETERMINISTIC_ORDER.index)
    agent = "Agent Review" in sources
    return Finding(
        ID=0,
        Normalized_Category=category,
        FindingType=finding_type,
        Severity=severity,
        Confidence="Likely" if agent else confidence,
        Source=sources,
        Resource=resource,
        Location=Location(File=file, TemplatePath=["Resources", resource or "X"] if path is None else path),
        Finding=text,
        WhyItMatters="CanaryWhy",
        Evidence=[
            Evidence(Source=source, Detail="CanaryDetail", RuleId=rule, Excerpt="CanaryExcerpt" if agent else None)
            for source, rule in evidence
        ],
        Recommendation="CanaryRecommendation",
        SuggestedRemediation=None,
    )


DETERMINISTIC_ORDER = DETERMINISTIC + ["Agent Review"]


def _tools(**versions: Optional[str]) -> List[report.ToolStatus]:
    defaults: Dict[str, Optional[str]] = {"cfn-guard": "3.2.1", "cfn-lint": "1.46.0"}
    defaults.update(versions)
    return [report.ToolStatus(name, version is not None, version) for name, version in defaults.items()]


def _checked(
    findings: Sequence[Finding] = (),
    *,
    sources: Sequence[str] = DETERMINISTIC,
    tools: Optional[Sequence[report.ToolStatus]] = None,
    errors: Sequence[Dict[str, Any]] = (),
    files: Sequence[str] = (FILE,),
) -> CheckedReport:
    meta = report.ReportMeta(
        files=tuple(files), sources_enabled=tuple(sources), tools=tuple(_tools() if tools is None else tools)
    )
    obj = json.loads(report.dump(report.build_report(list(findings), list(errors), meta)))
    checked = reportcheck.check_report(obj)
    assert isinstance(checked, CheckedReport), checked
    return checked


def _run(
    base: CheckedReport,
    head: CheckedReport,
    declarations: FrozenSet[str] = ALL,
    correspondence: str = "not_applicable",
    rename_hints: FrozenSet[str] = frozenset(),
) -> FindingDeltaResult:
    return delta.match_and_classify(
        base, head, declarations=declarations, correspondence=correspondence, rename_hints=rename_hints
    )


def _label(entry: DeltaEntry, base: CheckedReport, head: CheckedReport) -> Tuple[Optional[str], Optional[str]]:
    texts_base = {f.ID: f.Finding for f in base.findings}
    texts_head = {f.ID: f.Finding for f in head.findings}
    return (
        None if entry.base is None else texts_base[entry.base.ID],
        None if entry.head is None else texts_head[entry.head.ID],
    )


def _summary(result: FindingDeltaResult, base: CheckedReport, head: CheckedReport) -> Dict[Tuple[Any, Any], Tuple[str, str, Tuple[str, ...], Optional[int]]]:
    return {
        _label(e, base, head): (e.observation, e.classification, e.reasons, e.match_stage) for e in result.entries
    }


def _error(source: Optional[str]) -> Dict[str, Any]:
    return {
        "error_class": "tool_execution",
        "source": source,
        "tool": None,
        "exit_code": None,
        "message": "m",
        "required_min_version": None,
        "detected_version": None,
        "remediation": None,
        "stderr_head": [],
    }


# ---------------------------------------------------------------------------
# Task 2 Report fixtures (R15.5, R15.6)
# ---------------------------------------------------------------------------


def _fixture_run(case: str) -> List[Tuple[str, Dict[str, Any], Dict[str, Any]]]:
    expected = json.loads((DELTA_REPORTS / case / "expected.json").read_text(encoding="utf-8"))
    objs = {
        side: json.loads((DELTA_REPORTS / case / expected["inputs"][side]).read_text(encoding="utf-8"))
        for side in ("base", "head")
    }
    labels = {side: {f["ID"]: f["Finding"] for f in objs[side]["findings"]} for side in objs}
    checked = {side: reportcheck.check_report(objs[side], side) for side in objs}
    assert all(isinstance(value, CheckedReport) for value in checked.values())
    base, head = checked["base"], checked["head"]
    assert isinstance(base, CheckedReport) and isinstance(head, CheckedReport)
    pair = expected["template_pair"]
    if pair is None:
        correspondence = "not_applicable"
    else:
        templates = {
            side: deltaio.parse_template(
                (DELTA_REPORTS / case / pair[side]["file"]).read_text(encoding="utf-8"), Path("t"), side
            )
            for side in ("base", "head")
        }
        correspondence = reportcheck.correspondence(
            templates["base"],
            templates["head"],
            base,
            head,
            (pair["base"]["workspace_path"], pair["head"]["workspace_path"]),
        )
    assert correspondence == expected["expected"]["template_report_correspondence"]
    runs = []
    for mode, want in expected["expected"]["by_declarations"].items():
        result = _run(base, head, frozenset(expected["declarations"][mode]), correspondence)
        got = {
            "observation": result.observation,
            "classification_completeness": result.classification_completeness,
            "comparable": result.comparable,
            "integrity": {"base": list(result.report_integrity.base), "head": list(result.report_integrity.head)},
            "entries": sorted(_entry_json(entry, labels) for entry in result.entries),
        }
        runs.append((mode, got, _want(expected["expected"], want)))
    return runs


def _deltas(items: Sequence[EvidenceDelta]) -> List[str]:
    return sorted(
        json.dumps({"Source": d.Source, "RuleId": d.RuleId, "source_comparable": d.source_comparable}, sort_keys=True)
        for d in items
    )


def _entry_json(entry: DeltaEntry, labels: Dict[str, Dict[int, str]]) -> str:
    return json.dumps(
        {
            "observation": entry.observation,
            "classification": entry.classification,
            "reasons": sorted(entry.reasons),
            "missing_declarations": sorted(entry.missing_declarations),
            "match_stage": entry.match_stage,
            "base": None if entry.base is None else labels["base"][entry.base.ID],
            "head": None if entry.head is None else labels["head"][entry.head.ID],
            "changes": sorted(entry.changes),
            "evidence_absent_in_head": _deltas(entry.evidence_absent_in_head),
            "evidence_absent_in_base": _deltas(entry.evidence_absent_in_base),
        },
        sort_keys=True,
    )


def _want(expected: Dict[str, Any], mode: Dict[str, Any]) -> Dict[str, Any]:
    def norm(entry: Dict[str, Any]) -> str:
        return json.dumps(
            dict(
                entry,
                reasons=sorted(entry["reasons"]),
                missing_declarations=sorted(entry["missing_declarations"]),
                changes=sorted(entry["changes"]),
                evidence_absent_in_head=sorted(json.dumps(d, sort_keys=True) for d in entry["evidence_absent_in_head"]),
                evidence_absent_in_base=sorted(json.dumps(d, sort_keys=True) for d in entry["evidence_absent_in_base"]),
            ),
            sort_keys=True,
        )

    return {
        "observation": mode["observation"],
        "classification_completeness": mode["classification_completeness"],
        "comparable": expected["comparable"],
        "integrity": expected["report_integrity"],
        "entries": sorted(norm(entry) for entry in mode["entries"]),
    }


def test_every_report_case_is_run() -> None:
    assert len(REPORT_CASES) == 28


@pytest.mark.parametrize("case", REPORT_CASES)
def test_report_fixture_matches_expected(case: str) -> None:
    runs = _fixture_run(case)
    assert runs
    for mode, got, want in runs:
        assert got == want, mode


@pytest.mark.parametrize("case", [c for c in REPORT_CASES if c.startswith(("classify_", "correspondence_"))])
def test_classification_cases_run_all_three_declaration_sets(case: str) -> None:
    """R15.6: all / none / one missing."""
    assert sorted(mode for mode, _, _ in _fixture_run(case)) == ["all", "none", "one_missing"]


# ---------------------------------------------------------------------------
# Design E-1 .. E-7
# ---------------------------------------------------------------------------


def test_e1_stage_one_matches_despite_evidence_and_path_changes() -> None:
    base = _checked([_finding("x", evidence=[("cfn-guard", "a")], path=["Resources", "Bucket", "P"])])
    head = _checked([_finding("y", evidence=[("cfn-guard", "b")], path=["Resources", "Bucket", "Q"])])
    (entry,) = _run(base, head).entries
    assert (entry.observation, entry.classification, entry.match_stage) == ("matched", "Unchanged", 1)
    assert entry.changes == ("Location.TemplatePath", "Evidence")
    assert entry.evidence_absent_in_head == (EvidenceDelta("cfn-guard", "a", True),)
    assert entry.evidence_absent_in_base == (EvidenceDelta("cfn-guard", "b", True),)


def test_e2_null_resource_same_fingerprint_matches_in_stage_two() -> None:
    base = _checked([_finding("x", resource=None)])
    head = _checked([_finding("y", resource=None, severity="LOW")])
    (entry,) = _run(base, head).entries
    assert (entry.observation, entry.match_stage, entry.changes) == ("matched", 2, ("Severity",))


def test_e3_null_resource_different_fingerprint_is_ambiguous() -> None:
    base = _checked([_finding("x", resource=None, evidence=[("cfn-guard", "a")])])
    head = _checked([_finding("y", resource=None, evidence=[("cfn-guard", "b")])])
    summary = _summary(_run(base, head), base, head)
    assert summary == {
        ("x", None): ("unmatched", "Ambiguous", ("identity_undetermined",), None),
        (None, "y"): ("unmatched", "Ambiguous", ("identity_undetermined",), None),
    }


def test_e4_one_of_two_matches_and_the_other_is_head_only() -> None:
    base = _checked([_finding("x", resource=None, evidence=[("cfn-guard", "f")])])
    head = _checked(
        [
            _finding("y", resource=None, evidence=[("cfn-guard", "f")]),
            _finding("z", resource=None, evidence=[("cfn-guard", "g")]),
        ]
    )
    summary = _summary(_run(base, head), base, head)
    assert summary == {
        ("x", "y"): ("matched", "Unchanged", (), 2),
        (None, "z"): ("head_only", "New", (), None),
    }


def test_e5_neither_matches_so_all_three_are_ambiguous() -> None:
    base = _checked([_finding("x", resource=None, evidence=[("cfn-guard", "f")])])
    head = _checked(
        [
            _finding("y", resource=None, evidence=[("cfn-guard", "g")]),
            _finding("z", resource=None, evidence=[("cfn-guard", "h")]),
        ]
    )
    result = _run(base, head)
    assert len(result.entries) == 3
    assert all(
        (e.observation, e.classification, e.reasons) == ("unmatched", "Ambiguous", ("identity_undetermined",))
        for e in result.entries
    )


def test_e6_duplicate_fingerprints_are_ambiguous() -> None:
    def two(prefix: str) -> List[Finding]:
        return [_finding(prefix + "1", category="Other"), _finding(prefix + "2", category="Other")]

    base, head = _checked(two("b")), _checked(two("h"))
    result = _run(base, head)
    assert len(result.entries) == 4
    assert all(
        e.reasons == ("identity_undetermined", "duplicate_fingerprint") and e.classification == "Ambiguous"
        for e in result.entries
    )


def test_e7_duplicated_dedup_identity_goes_through_stage_two() -> None:
    base = _checked([_finding("x", evidence=[("cfn-guard", "f")])])
    head = _checked([_finding("y", evidence=[("cfn-guard", "f")]), _finding("z", evidence=[("cfn-guard", "g")])])
    assert head.integrity_failures == ("dedup_invariant_violated",)
    summary = _summary(_run(base, head), base, head)
    assert summary == {
        ("x", "y"): ("matched", "Unchanged", (), 2),
        (None, "z"): ("head_only", "Ambiguous", ("report_integrity_failed",), None),
    }


def test_no_stage_three_on_partial_fingerprint_agreement() -> None:
    """R6.6: same TemplatePath, different Evidence -> still not paired."""
    base = _checked([_finding("x", resource=None, evidence=[("cfn-guard", "a")], path=["Parameters", "P"])])
    head = _checked([_finding("y", resource=None, evidence=[("cfn-guard", "b")], path=["Parameters", "P"])])
    assert {e.observation for e in _run(base, head).entries} == {"unmatched"}


def test_different_identity_keys_are_never_paired() -> None:
    """R6.1"""
    base = _checked([_finding("x", resource="A")])
    head = _checked([_finding("y", resource="B")])
    summary = _summary(_run(base, head), base, head)
    assert summary == {("x", None): ("base_only", "Resolved", (), None), (None, "y"): ("head_only", "New", (), None)}


def test_fingerprint_ignores_free_text_ids_and_severity() -> None:
    """R6.2"""
    one = _finding("first wording", resource=None, severity="HIGH")
    two = _finding("second wording", resource=None, severity="LOW", confidence="Confirmed")
    assert delta.fingerprint(one) == delta.fingerprint(two)
    assert delta.identity_key(one) == delta.IdentityKey(FILE, None, "Encryption")


def test_fingerprint_canonicalizes_template_path_and_counts_null_rule() -> None:
    """R6.3"""
    one = _finding("a", resource=None, path=["Resources", "R", "Tags", "0"], evidence=[("cfn-guard", None)])
    two = _finding("b", resource=None, path=["Resources", "R", "Tags", 0], evidence=[("cfn-guard", None)])
    three = _finding("c", resource=None, path=["Resources", "R", "Tags", 0], evidence=[("cfn-guard", "x")])
    assert delta.fingerprint(one) == delta.fingerprint(two) != delta.fingerprint(three)


# ---------------------------------------------------------------------------
# Classification safety (R7)
# ---------------------------------------------------------------------------


def _decided(result: FindingDeltaResult) -> List[DeltaEntry]:
    return [e for e in result.entries if e.classification in ("New", "Resolved")]


@pytest.mark.parametrize("declarations", [frozenset(), ALL])
def test_tool_unavailable_never_resolves(declarations: FrozenSet[str]) -> None:
    base = _checked([_finding("guard finding")])
    head = _checked([], tools=_tools(**{"cfn-guard": None}))
    (entry,) = _run(base, head, declarations).entries
    assert (entry.observation, entry.classification, entry.reasons) == (
        "base_only",
        "Ambiguous",
        ("source_not_comparable",),
    )


def test_tool_absent_from_tools_never_resolves() -> None:
    base = _checked([_finding("guard finding")])
    head = _checked([], tools=[report.ToolStatus("cfn-lint", True, "1.46.0")])
    assert _decided(_run(base, head, ALL)) == []


def test_source_not_run_never_resolves() -> None:
    base = _checked([_finding("guard finding")])
    head = _checked([], sources=[s for s in DETERMINISTIC if s != "cfn-guard"])
    (entry,) = _run(base, head, ALL).entries
    assert entry.classification == "Ambiguous" and entry.reasons == ("source_not_comparable",)


def test_tool_version_mismatch_never_gives_new() -> None:
    base = _checked([])
    head = _checked([_finding("guard finding")], tools=_tools(**{"cfn-guard": "3.3.0"}))
    (entry,) = _run(base, head, ALL).entries
    assert (entry.classification, entry.reasons) == (
        "Ambiguous",
        ("source_not_comparable", "tool_version_mismatch"),
    )


@pytest.mark.parametrize("source", ["cfn-guard", None])
def test_source_error_never_resolves(source: Optional[str]) -> None:
    base = _checked([_finding("guard finding")])
    head = _checked([], errors=[_error(source)])
    (entry,) = _run(base, head, ALL).entries
    assert entry.classification == "Ambiguous"
    assert not _run(base, head, ALL).comparable


def test_error_of_another_source_does_not_block() -> None:
    base = _checked([_finding("guard finding")])
    head = _checked([], errors=[_error("cfn-lint")])
    (entry,) = _run(base, head, ALL).entries
    assert entry.classification == "Resolved"


def test_merged_finding_needs_every_source_comparable() -> None:
    merged = _finding("merged", evidence=[("cfn-lint", "W1"), ("cfn-guard", "g")])
    base = _checked([merged])
    head = _checked([], tools=_tools(**{"cfn-lint": None}))
    (entry,) = _run(base, head, ALL).entries
    assert entry.classification == "Ambiguous" and entry.reasons == ("source_not_comparable",)


def test_agent_only_finding_is_ambiguous() -> None:
    sources = DETERMINISTIC + ["Agent Review"]
    base = _checked([], sources=sources)
    head = _checked([_finding("agent note", evidence=[("Agent Review", None)])], sources=sources)
    (entry,) = _run(base, head, ALL).entries
    assert (entry.classification, entry.reasons) == ("Ambiguous", ("non_deterministic_source",))


def test_rename_hint_is_ambiguous() -> None:
    base = _checked([_finding("old", resource="OldBucket")])
    head = _checked([_finding("new", resource="NewBucket")])
    result = _run(base, head, ALL_WITH_TEMPLATES, "consistent_by_name_only", frozenset({"OldBucket", "NewBucket"}))
    assert [(e.classification, e.reasons) for e in result.entries] == [
        ("Ambiguous", ("possible_logical_id_rename",)),
        ("Ambiguous", ("possible_logical_id_rename",)),
    ]


@pytest.mark.parametrize("value", ["inconsistent", "unknown"])
def test_template_report_mismatch_applies_to_both_sides(value: str) -> None:
    base = _checked([_finding("gone", resource="A")])
    head = _checked([_finding("came", resource="B")])
    result = _run(base, head, ALL_WITH_TEMPLATES, value)
    assert {(e.observation, e.reasons) for e in result.entries} == {
        ("base_only", ("template_report_mismatch",)),
        ("head_only", ("template_report_mismatch",)),
    }


def test_every_applicable_reason_is_listed() -> None:
    sources = DETERMINISTIC + ["Agent Review"]
    base = _checked([], sources=sources, tools=_tools(**{"cfn-guard": None}))
    head = _checked(
        [_finding("agent", resource="R", evidence=[("Agent Review", None)])],
        sources=[s for s in sources if s != "Agent Review"],
    )
    (entry,) = _run(base, head, ALL_WITH_TEMPLATES, "unknown", frozenset({"R"})).entries
    assert entry.reasons == (
        "source_not_comparable",
        "non_deterministic_source",
        "possible_logical_id_rename",
        "template_report_mismatch",
    )


def test_partial_evidence_loss_is_not_resolved() -> None:
    """R6.14: a vanished Evidence element is an observation, never Resolved."""
    base = _checked([_finding("x", evidence=[("cfn-guard", "a"), ("cfn-guard", "b"), ("cfn-guard", "b")])])
    head = _checked([_finding("x", evidence=[("cfn-guard", "b")])])
    result = _run(base, head, ALL)
    (entry,) = result.entries
    assert entry.classification == "Unchanged" and _decided(result) == []
    assert entry.evidence_absent_in_head == (
        EvidenceDelta("cfn-guard", "a", True),
        EvidenceDelta("cfn-guard", "b", True),
    )
    assert entry.evidence_absent_in_base == ()
    text = repr(result)
    assert "Resolved" not in text and "resolved" not in text and "fixed" not in text


@pytest.mark.parametrize("category,resource", [("Other", "Bucket"), ("Encryption", None)])
def test_partial_evidence_loss_in_stage_two_is_not_resolved(category: str, resource: Optional[str]) -> None:
    """R6.14, second path: outside stage 1 the Fingerprint changes and nothing resolves."""
    base = _checked(
        [_finding("x", resource=resource, category=category, evidence=[("cfn-guard", "a"), ("cfn-guard", "b")])]
    )
    head = _checked([_finding("x", resource=resource, category=category, evidence=[("cfn-guard", "b")])])
    result = _run(base, head, ALL)
    assert [(e.observation, e.classification, e.reasons) for e in result.entries] == [
        ("unmatched", "Ambiguous", ("identity_undetermined",)),
        ("unmatched", "Ambiguous", ("identity_undetermined",)),
    ]
    assert _decided(result) == []


def test_rename_to_an_uncompared_resource_is_ambiguous() -> None:
    """Regression (Phase 2 review P2-1): Semantic Diff hints reach Finding Delta.

    The Head Resource holds a duplicate key, so it is not compared; the rename
    from ``Old`` cannot be ruled out and neither side may be New / Resolved.
    """
    templates = []
    for text, side in (
        ("Resources:\n  Old: {Type: AWS::S3::Bucket, Properties: {BucketName: a}}\n", "base"),
        (
            "Resources:\n  New:\n    Type: AWS::S3::Bucket\n"
            "    Properties: {BucketName: a}\n    Properties: {BucketName: b}\n",
            "head",
        ),
    ):
        parsed = deltaio.parse_template(text, Path(FILE), side)
        assert isinstance(parsed, deltaio.ParsedTemplate), parsed
        templates.append(parsed)
    diff = semdiff.diff(templates[0], templates[1])
    assert isinstance(diff, semdiff.SemanticDiffResult), diff
    base = _checked([_finding("old", resource="Old")])
    head = _checked([_finding("new", resource="New")])
    result = _run(base, head, ALL_WITH_TEMPLATES, "consistent_by_name_only", diff.rename_hints)
    assert sorted((e.observation, e.classification, e.reasons) for e in result.entries) == [
        ("base_only", "Ambiguous", ("possible_logical_id_rename",)),
        ("head_only", "Ambiguous", ("possible_logical_id_rename",)),
    ]


def test_evidence_of_a_non_comparable_source_is_marked() -> None:
    base = _checked([_finding("x", evidence=[("cfn-lint", "W1"), ("cfn-guard", "g")])])
    head = _checked([_finding("x", evidence=[("cfn-lint", "W1")])], tools=_tools(**{"cfn-guard": None}))
    (entry,) = _run(base, head, ALL).entries
    assert entry.changes == ("Source", "Evidence")
    assert entry.evidence_absent_in_head == (EvidenceDelta("cfn-guard", "g", False),)


# ---------------------------------------------------------------------------
# Declarations (R7.3, R7.5, R8.3-R8.5)
# ---------------------------------------------------------------------------


def _simple() -> Tuple[CheckedReport, CheckedReport]:
    return _checked([_finding("gone", resource="A")]), _checked([_finding("came", resource="B")])


def test_declarations_all_none_and_one_missing() -> None:
    base, head = _simple()
    assert {e.classification for e in _run(base, head, ALL).entries} == {"New", "Resolved"}
    none = _run(base, head, frozenset())
    assert all(
        e.classification == "Unconfirmed"
        and e.reasons == ("input_declaration_absent",)
        and e.missing_declarations == delta.REPORT_DECLARATIONS
        for e in none.entries
    )
    missing = _run(base, head, ALL - {"same_rule_set"})
    assert all(e.missing_declarations == ("same_rule_set",) for e in missing.entries)
    assert missing.classification_completeness == "partial"


def test_template_pair_needs_reports_match_templates() -> None:
    base, head = _simple()
    result = _run(base, head, ALL, "consistent_by_name_only")
    assert all(e.missing_declarations == ("reports_match_templates",) for e in result.entries)
    assert result.input_declarations.missing == ("reports_match_templates",)
    decided = _run(base, head, ALL_WITH_TEMPLATES, "consistent_by_name_only")
    assert {e.classification for e in decided.entries} == {"New", "Resolved"}
    assert decided.classification_completeness == "complete"


def test_declarations_are_recorded_not_verified() -> None:
    base, head = _simple()
    result = _run(base, head, frozenset({"same_rule_set", "reports_unmodified"}))
    assert result.input_declarations.declared == ("reports_unmodified", "same_rule_set")
    assert result.input_declarations.status == "declared_not_verified"
    assert result.unverified_assumptions == deltaschema.UNVERIFIED_ASSUMPTIONS
    assert result.report_authenticity == "unverified"


def test_declarations_do_not_affect_matched_entries() -> None:
    base = _checked([_finding("x")])
    head = _checked([_finding("x")])
    for declarations in (frozenset(), ALL):
        (entry,) = _run(base, head, declarations).entries
        assert entry.classification == "Unchanged" and entry.missing_declarations == ()


def test_unknown_declaration_or_correspondence_is_rejected() -> None:
    base, head = _simple()
    with pytest.raises(ValueError):
        _run(base, head, frozenset({"all"}))
    with pytest.raises(ValueError):
        _run(base, head, ALL, "verified")


# ---------------------------------------------------------------------------
# Result properties
# ---------------------------------------------------------------------------


def test_identical_reports_are_no_changes_observed() -> None:
    findings = [_finding("x"), _finding("y", resource=None)]
    result = _run(_checked(findings), _checked(findings))
    assert result.observation == "no_changes_observed"
    assert result.classification_completeness == "complete"
    assert sorted(e.match_stage or 0 for e in result.entries) == [1, 2]


def test_matched_with_changes_is_changes_observed() -> None:
    result = _run(_checked([_finding("x")]), _checked([_finding("x", severity="LOW")]))
    assert result.observation == "changes_observed"


def test_empty_reports() -> None:
    result = _run(_checked([]), _checked([]))
    assert result.entries == ()
    assert (result.observation, result.classification_completeness) == ("no_changes_observed", "complete")


def test_every_finding_appears_once() -> None:
    """R6.11"""
    base = _checked([_finding("a"), _finding("b", resource=None), _finding("c", resource=None, evidence=[("cfn-guard", "z")])])
    head = _checked([_finding("d", resource="Q"), _finding("e", resource=None)])
    result = _run(base, head)
    base_ids = sorted(e.base.ID for e in result.entries if e.base is not None)
    head_ids = sorted(e.head.ID for e in result.entries if e.head is not None)
    assert base_ids == [f.ID for f in base.findings] and head_ids == [f.ID for f in head.findings]


def test_result_carries_no_free_text() -> None:
    """R16.3, R12.1: Finding text, Detail, Excerpt and Recommendation stay out."""
    sources = DETERMINISTIC + ["Agent Review"]
    base = _checked([_finding("CanaryFindingText"), _finding("a", evidence=[("Agent Review", None)], resource="R")], sources=sources)
    head = _checked([_finding("CanaryOtherText", severity="LOW")], sources=sources)
    text = repr(_run(base, head))
    assert "Canary" not in text


def test_entries_are_ordered_independently_of_input_order() -> None:
    findings = [_finding("a", resource="A"), _finding("b", resource="B"), _finding("c", resource=None)]
    one = _run(_checked(findings), _checked(findings[:1]))
    two = _run(_checked(list(reversed(findings))), _checked(findings[:1]))
    assert one == two


def test_projection_is_frozen_and_sorted() -> None:
    projection = delta.project(
        _finding("x", evidence=[("cfn-lint", "W2"), ("cfn-guard", None), ("cfn-guard", "a")])
    )
    assert projection.Evidence == (
        delta.EvidenceKey("cfn-guard", None),
        delta.EvidenceKey("cfn-guard", "a"),
        delta.EvidenceKey("cfn-lint", "W2"),
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        projection.ID = 3  # type: ignore[misc]


def test_projection_keeps_a_non_decimal_digit_segment_as_a_string() -> None:
    """A-3b, R10.4: ``"\u00b2"`` passes ``isdigit()`` but ``int()`` refuses it."""
    path = ["Resources", "Bucket", "Metadata", "\u00b2", "0", "\u0661\u0662\u0663"]
    projection = delta.project(_finding("x", path=path))
    assert projection.TemplatePath == ("Resources", "Bucket", "Metadata", "\u00b2", 0, 123)
    base = _checked([_finding("x", path=path)])
    head = _checked([_finding("x", path=path)])
    result = _run(base, head)
    assert [(e.observation, e.classification, e.match_stage) for e in result.entries] == [
        ("matched", "Unchanged", 1)
    ]
