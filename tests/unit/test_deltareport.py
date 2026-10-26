"""Unit tests for :mod:`iacreview.deltareport` (v1.1 Task 10).

* Envelope, comparison, entry and projection key sets are the documented ones.
* Every closed-set value written is a member of its set; summary counts equal
  the counted entries and every closed-set value is present (0-filled).
* Identifier_Token rules: code point order, one namespace, width, no original
  text or digest; Base / Head swap keeps the table.
* Plain closed sets (sections, attributes, intrinsics, AWS Types, Custom::
  prefix, Categories, RuleIds per Source, tool names / versions) and Tokens
  for everything else, including digit-only mapping keys.
* No Template value and no Finding free text in the output.
* Output size limit: over the limit gives ``output_size_limit_exceeded`` and
  the minimal Delta_Report.
* No forbidden key (``improved``, ``fixed``, ``passed`` ...).
"""

from __future__ import annotations

import dataclasses
import hashlib
import io
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

import pytest

from iacreview import delta, deltaio, deltareport, deltaschema, errors, report, reportcheck, semdiff
from iacreview.deltaio import Failure, ParsedTemplate
from iacreview.deltareport import DeltaRequest, FailureRecord, ReportInput, TemplateInput
from iacreview.finding import Evidence, Finding, Location
from iacreview.reportcheck import CheckedReport

FILE = "templates/app.yaml"
SOURCES = ("cfn-lint", "cfn-guard", "IAM Review", "Network Review", "Secret Review", "Quality Review")
ALL_DECLARATIONS = frozenset(deltaschema.DECLARATION_CODES)

BASE_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  CanaryParamName:
    Type: String
    NoEcho: true
    Default: CanaryNoEchoDefaultValue
Mappings:
  CanaryMapName:
    "123456789012":
      CanaryThirdKey: CanaryMappingValue
Resources:
  CanaryBucketLogicalId:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: CanaryOldBucketName
      Tags:
        - Key: CanaryTagKey
          Value: CanaryTagValue
  CanaryCustomThing:
    Type: Custom::CanaryCustomTypeName
    Properties:
      ServiceToken: !GetAtt CanaryFunction.Arn
  CanaryOddType:
    Type: CanaryVendor::Thing
"""

HEAD_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  CanaryParamName:
    Type: String
    NoEcho: true
    Default: CanaryNoEchoDefaultChanged
Mappings:
  CanaryMapName:
    "123456789012":
      CanaryThirdKey: CanaryMappingValueChanged
Resources:
  CanaryBucketLogicalId:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: CanaryNewBucketName
      Tags:
        - Key: CanaryTagKey
          Value: CanaryTagValueChanged
  CanaryCustomThing:
    Type: Custom::CanaryCustomTypeName
    Properties:
      ServiceToken: !GetAtt CanaryFunction2.Arn
  CanaryOddType:
    Type: CanaryVendor::Thing
    Properties:
      Size: 2
"""

FREE_TEXT_CANARIES = (
    "CanaryFindingText",
    "CanaryWhyText",
    "CanaryRecommendationText",
    "CanaryRemediationText",
    "CanaryDetailText",
    "CanaryExcerptText",
)
VALUE_CANARIES = (
    "CanaryNoEchoDefaultValue",
    "CanaryNoEchoDefaultChanged",
    "CanaryMappingValue",
    "CanaryOldBucketName",
    "CanaryNewBucketName",
    "CanaryTagValue",
    "CanaryFunction",
)
IDENTIFIER_CANARIES = (
    "CanaryParamName",
    "CanaryMapName",
    "CanaryThirdKey",
    "CanaryBucketLogicalId",
    "CanaryCustomThing",
    "CanaryCustomTypeName",
    "CanaryOddType",
    "CanaryVendor",
    "123456789012",
)


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def _finding(
    text: str,
    resource: Optional[str],
    category: str = "Encryption",
    evidence: Sequence[Tuple[str, Optional[str]]] = (("cfn-guard", "s3_bucket_encryption"),),
    path: Optional[List[Any]] = None,
) -> Finding:
    sources = sorted({source for source, _ in evidence}, key=list(SOURCES + ("Agent Review",)).index)
    agent = "Agent Review" in sources
    return Finding(
        ID=0,
        Normalized_Category=category,
        FindingType="Security",
        Severity="HIGH",
        Confidence="Likely" if agent else "Confirmed",
        Source=sources,
        Resource=resource,
        Location=Location(File=FILE, TemplatePath=["Resources", resource or "X"] if path is None else path),
        Finding=text,
        WhyItMatters="CanaryWhyText",
        Evidence=[
            Evidence(Source=s, Detail="CanaryDetailText", RuleId=r, Excerpt="CanaryExcerptText") for s, r in evidence
        ],
        Recommendation="CanaryRecommendationText",
        SuggestedRemediation="CanaryRemediationText",
    )


def _report_obj(
    findings: Sequence[Finding],
    tools: Optional[Sequence[report.ToolStatus]] = None,
    errors: Sequence[Dict[str, Any]] = (),
) -> Dict[str, Any]:
    meta = report.ReportMeta(
        files=(FILE,),
        sources_enabled=SOURCES,
        tools=tuple(
            tools
            if tools is not None
            else (report.ToolStatus("cfn-guard", True, "3.2.1"), report.ToolStatus("cfn-lint", True, "1.46.0"))
        ),
    )
    return json.loads(report.dump(report.build_report(list(findings), list(errors), meta)))


def _checked(obj: Dict[str, Any]) -> CheckedReport:
    checked = reportcheck.check_report(obj)
    assert isinstance(checked, CheckedReport)
    return checked


def _parsed(text: str, side: str) -> ParsedTemplate:
    parsed = deltaio.parse_template(text, Path("t.yaml"), side)
    assert isinstance(parsed, ParsedTemplate), parsed
    return parsed


def _request(
    base_text: Optional[str] = BASE_TEMPLATE,
    head_text: Optional[str] = HEAD_TEMPLATE,
    base_findings: Optional[Sequence[Finding]] = None,
    head_findings: Optional[Sequence[Finding]] = None,
    declarations: frozenset = ALL_DECLARATIONS,
    guard_names: frozenset = frozenset({"s3_bucket_encryption"}),
    base_tools: Optional[Sequence[report.ToolStatus]] = None,
) -> DeltaRequest:
    templates = None
    diff_result = None
    if base_text is not None and head_text is not None:
        base_t, head_t = _parsed(base_text, "base"), _parsed(head_text, "head")
        result = semdiff.diff(base_t, head_t)
        assert isinstance(result, semdiff.SemanticDiffResult)
        diff_result = result
        # The Findings are in FILE, so both Templates are at FILE: a TemplatePath
        # is walked only in the Template its Finding is in (RC Blocker D-13).
        templates = (TemplateInput(FILE, base_t), TemplateInput(FILE, head_t))
    reports = None
    delta_result = None
    if base_findings is not None and head_findings is not None:
        base_obj, head_obj = _report_obj(base_findings, base_tools), _report_obj(head_findings)
        base_r, head_r = _checked(base_obj), _checked(head_obj)
        digest = [hashlib.sha256(report.dump(o).encode("utf-8")).hexdigest() for o in (base_obj, head_obj)]
        reports = (ReportInput("base.json", digest[0], base_r), ReportInput("head.json", digest[1], head_r))
        delta_result = delta.match_and_classify(
            base_r,
            head_r,
            declarations=declarations,
            correspondence="not_applicable" if templates is None else "consistent_by_name_only",
            rename_hints=frozenset() if diff_result is None else diff_result.rename_hints,
        )
    return DeltaRequest(
        templates=templates,
        reports=reports,
        semantic_diff=diff_result,
        finding_delta=delta_result,
        declarations=declarations if reports is not None else frozenset(),
        guard_rule_names=guard_names,
    )


BASE_FINDINGS = [
    _finding("CanaryFindingText one", "CanaryBucketLogicalId", path=["Resources", "CanaryBucketLogicalId", "Properties"]),
    _finding("gone", "CanaryCustomThing", category="Logging", evidence=(("cfn-lint", "W3005"),)),
    _finding(
        "net",
        "CanaryOddType",
        category="NetworkSecurity",
        evidence=(("Network Review", "CanaryNetworkRuleId"), ("IAM Review", "wildcard_action")),
    ),
]
HEAD_FINDINGS = [
    _finding("CanaryFindingText one", "CanaryBucketLogicalId", path=["Resources", "CanaryBucketLogicalId", "Properties"]),
    _finding("new", "CanaryBucketLogicalId", category="Tagging", evidence=(("cfn-guard", "CanaryUnknownGuardRule"),)),
    _finding(
        "net",
        "CanaryOddType",
        category="NetworkSecurity",
        evidence=(("Network Review", "CanaryNetworkRuleId"), ("IAM Review", "wildcard_action")),
    ),
]


def _full_request() -> DeltaRequest:
    return _request(base_findings=BASE_FINDINGS, head_findings=HEAD_FINDINGS)


def _build(request: DeltaRequest, mode: str = "anonymized") -> Dict[str, Any]:
    built = deltareport.build_delta_report(request, mode)
    assert isinstance(built, dict), built
    return built


def _keys(value: Any) -> Iterator[str]:
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            for key, child in current.items():
                yield key
                stack.append(child)
        elif isinstance(current, list):
            stack.extend(current)


def _strings(value: Any) -> Iterator[str]:
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            for key, child in current.items():
                yield key
                stack.append(child)
        elif isinstance(current, list):
            stack.extend(current)
        elif isinstance(current, str):
            yield current


# ---------------------------------------------------------------------------
# Key sets and closed sets
# ---------------------------------------------------------------------------


def test_envelope_and_nested_key_sets() -> None:
    built = _build(_full_request())
    assert set(built) == set(deltareport.ENVELOPE_KEYS)
    assert built["delta_schema_version"] == "1.0.0"
    assert built["scope"] == "declared_template"
    assert built["identifier_mode"] == "anonymized"
    for side in ("base", "head"):
        assert set(built["inputs"][side]) == set(deltareport.SIDE_INPUT_KEYS)
        assert set(built["inputs"][side]["template"]) == set(deltareport.TEMPLATE_INPUT_KEYS)
        assert set(built["inputs"][side]["report"]) == set(deltareport.REPORT_INPUT_KEYS)
    diff = built["semantic_diff"]
    assert set(diff) == set(deltareport.SEMANTIC_DIFF_KEYS)
    assert diff["changes"]
    for change in diff["changes"]:
        assert set(change) == set(deltareport.CHANGE_ENTRY_KEYS)
    findings = built["finding_delta"]
    assert set(findings) == set(deltareport.FINDING_DELTA_KEYS)
    assert findings["entries"]
    for entry in findings["entries"]:
        assert set(entry) == set(deltareport.DELTA_ENTRY_KEYS)
        for side in ("base", "head"):
            if entry[side] is not None:
                assert set(entry[side]) == set(deltareport.PROJECTION_KEYS)
                for item in entry[side]["Evidence"]:
                    assert set(item) == set(deltareport.EVIDENCE_KEYS)
        for item in entry["evidence_absent_in_head"] + entry["evidence_absent_in_base"]:
            assert set(item) == set(deltareport.EVIDENCE_DELTA_KEYS)
    assert set(built["summary"]) == set(deltareport.SUMMARY_KEYS)
    assert set(built["summary"]["semantic_diff"]) == set(deltareport.SUMMARY_SEMANTIC_DIFF_KEYS)
    assert set(built["summary"]["finding_delta"]) == set(deltareport.SUMMARY_FINDING_DELTA_KEYS)
    assert built["errors"] == []


def test_closed_set_values() -> None:
    built = _build(_full_request())
    diff = built["semantic_diff"]
    assert diff["analysis_state"] in deltaschema.ANALYSIS_STATES
    assert diff["observation"] in deltaschema.OBSERVATIONS
    assert diff["structural_completeness"] in deltaschema.STRUCTURAL_COMPLETENESS
    assert set(diff["semantic_limitations"]) <= set(deltaschema.SEMANTIC_LIMITATIONS)
    for change in diff["changes"]:
        assert change["change"] in deltaschema.CHANGE_KINDS
        assert set(change["qualifiers"]) <= set(deltaschema.CHANGE_QUALIFIERS)
        assert set(change["hints"]) <= set(deltaschema.CHANGE_HINTS)
    findings = built["finding_delta"]
    assert findings["report_authenticity"] == "unverified"
    assert findings["template_report_correspondence"] in deltaschema.TEMPLATE_REPORT_CORRESPONDENCE
    assert findings["input_declarations"]["status"] == "declared_not_verified"
    assert findings["unverified_assumptions"] == list(deltaschema.UNVERIFIED_ASSUMPTIONS)
    for entry in findings["entries"]:
        assert entry["classification"] in deltaschema.DELTA_CLASSIFICATIONS
        assert entry["observation"] in deltaschema.ENTRY_OBSERVATIONS
        assert set(entry["reasons"]) <= set(deltaschema.AMBIGUOUS_REASONS + deltaschema.UNCONFIRMED_REASONS)
        assert entry["match_stage"] in (None,) + deltaschema.MATCH_STAGES


def test_summary_counts_equal_entries_and_are_zero_filled() -> None:
    built = _build(_full_request())
    diff, findings, summary = built["semantic_diff"], built["finding_delta"], built["summary"]
    sd = summary["semantic_diff"]
    assert sd["changes"] == len(diff["changes"])
    assert set(sd["by_change_kind"]) == set(deltaschema.CHANGE_KINDS)
    assert set(sd["by_qualifier"]) == set(deltaschema.CHANGE_QUALIFIERS)
    assert set(sd["by_hint"]) == set(deltaschema.CHANGE_HINTS)
    assert set(sd["by_semantic_limitation"]) == set(deltaschema.SEMANTIC_LIMITATIONS)
    assert set(sd["by_uncompared_reason"]) == set(deltaschema.UNCOMPARED_REASONS)
    for kind in deltaschema.CHANGE_KINDS:
        assert sd["by_change_kind"][kind] == sum(1 for c in diff["changes"] if c["change"] == kind)
    for code in deltaschema.CHANGE_QUALIFIERS:
        assert sd["by_qualifier"][code] == sum(1 for c in diff["changes"] if code in c["qualifiers"])
    for code in deltaschema.SEMANTIC_LIMITATIONS:
        assert sd["by_semantic_limitation"][code] == (1 if code in diff["semantic_limitations"] else 0)
    assert sd["uncompared_paths"] == len(diff["uncompared_paths"])
    fd = summary["finding_delta"]
    entries = findings["entries"]
    assert fd["entries"] == len(entries)
    assert set(fd["by_classification"]) == set(deltaschema.DELTA_CLASSIFICATIONS)
    assert set(fd["by_observation"]) == set(deltaschema.ENTRY_OBSERVATIONS)
    assert set(fd["by_reason"]) == set(deltaschema.AMBIGUOUS_REASONS + deltaschema.UNCONFIRMED_REASONS)
    assert set(fd["by_match_stage"]) == {"1", "2"}
    for code in deltaschema.DELTA_CLASSIFICATIONS:
        assert fd["by_classification"][code] == sum(1 for e in entries if e["classification"] == code)
    for code in deltaschema.ENTRY_OBSERVATIONS:
        assert fd["by_observation"][code] == sum(1 for e in entries if e["observation"] == code)
    for code in fd["by_reason"]:
        assert fd["by_reason"][code] == sum(1 for e in entries if code in e["reasons"])
    assert summary["errors"] == 0


def test_summary_without_pairs_is_all_zero() -> None:
    built = _build(_request(base_findings=None, head_findings=None))
    assert built["finding_delta"] is None
    fd = built["summary"]["finding_delta"]
    assert fd["entries"] == 0
    assert all(v == 0 for v in fd["by_classification"].values())
    assert built["inputs"]["base"]["report"] is None


def test_no_forbidden_key_anywhere() -> None:
    for request in (_full_request(), _request(base_text=None, head_text=None, base_findings=[], head_findings=[])):
        for mode in deltaschema.IDENTIFIER_MODES:
            keys = set(_keys(_build(request, mode)))
            assert not keys & set(deltareport.FORBIDDEN_KEYS)


# ---------------------------------------------------------------------------
# Identifier_Tokens
# ---------------------------------------------------------------------------


def test_token_table_is_code_point_ordered_and_padded() -> None:
    table = deltareport.build_token_table(["b", "a", "B", "a", "\u00e9"])
    assert table == {"B": "id-000001", "a": "id-000002", "b": "id-000003", "\u00e9": "id-000004"}
    wide = deltareport.build_token_table(str(n) for n in range(1000000))
    assert len(wide) == 1000000
    assert all(len(token) == len("id-") + 7 for token in list(wide.values())[:3])
    assert deltareport.build_token_table([]) == {}


def test_tokens_hold_no_original_text_or_digest() -> None:
    text = deltareport.dump(_build(_full_request()))
    for canary in IDENTIFIER_CANARIES:
        assert canary not in text, canary
        for digest in (hashlib.sha256(canary.encode()).hexdigest(), hashlib.md5(canary.encode()).hexdigest()):
            assert digest[:12] not in text


def test_one_namespace_for_paths_and_findings() -> None:
    built = _build(_full_request())
    bucket = [c for c in built["semantic_diff"]["changes"] if c["section"] == "Resources"][0]["path"][1]
    resources = {e["key"]["Resource"] for e in built["finding_delta"]["entries"]}
    assert bucket.startswith("id-")
    assert bucket in resources
    projection = next(e["head"] for e in built["finding_delta"]["entries"] if e["head"] is not None)
    assert projection["TemplatePath"][1] == projection["Resource"]


def test_swapping_base_and_head_keeps_every_token() -> None:
    forward = _build(_full_request())
    swapped = _build(
        _request(HEAD_TEMPLATE, BASE_TEMPLATE, base_findings=HEAD_FINDINGS, head_findings=BASE_FINDINGS)
    )
    flip = {"added": "removed", "removed": "added", "modified": "modified"}

    def changes(built: Dict[str, Any], flipped: bool) -> List[Tuple[Any, ...]]:
        return sorted(
            (c["section"], json.dumps(c["path"]), flip[c["change"]] if flipped else c["change"])
            for c in built["semantic_diff"]["changes"]
        )

    assert changes(forward, False) == changes(swapped, True)
    keys = lambda built: sorted(json.dumps(e["key"], sort_keys=True) for e in built["finding_delta"]["entries"])  # noqa: E731
    assert keys(forward) == keys(swapped)


def test_plain_mode_writes_identifiers_but_keeps_closed_set_tokens() -> None:
    built = _build(_full_request(), "plain")
    assert built["identifier_mode"] == "plain"
    text = deltareport.dump(built)
    for canary in ("CanaryBucketLogicalId", "CanaryParamName", "CanaryMapName", "CanaryCustomTypeName"):
        assert canary in text
    for canary in VALUE_CANARIES + FREE_TEXT_CANARIES:
        assert canary not in text, canary
    # RuleIds outside their closed set stay Tokens in plain mode.
    assert "CanaryNetworkRuleId" not in text
    assert "CanaryUnknownGuardRule" not in text


# ---------------------------------------------------------------------------
# Plain closed sets
# ---------------------------------------------------------------------------


def test_section_attribute_and_property_names() -> None:
    built = _build(_request(base_findings=None, head_findings=None))
    paths = {json.dumps(c["path"]) for c in built["semantic_diff"]["changes"]}
    by_section: Dict[str, List[List[Any]]] = {}
    for change in built["semantic_diff"]["changes"]:
        by_section.setdefault(change["section"], []).append(change["path"])
    assert set(by_section) <= set(deltareport.TOP_LEVEL_SECTIONS)
    resources = by_section["Resources"]
    for path in resources:
        assert path[0] == "Resources" and path[1].startswith("id-")
        if len(path) > 2:
            assert path[2] in ("Properties", "Type")
        if len(path) > 3:
            assert path[3].startswith("id-"), path  # Property names are Tokens
    # Parameter attribute ``Default`` is plain at position 2.
    assert any(p[0] == "Parameters" and p[2] == "Default" for p in by_section["Parameters"])
    # Fn::GetAtt is an intrinsic name below position 2.
    assert any("Fn::GetAtt" in p for p in resources)
    # The list index of Tags stays an integer.
    assert any(isinstance(item, int) for p in resources for item in p)
    assert paths


def test_digit_only_mapping_key_is_a_token_not_an_index() -> None:
    built = _build(_request(base_findings=None, head_findings=None))
    mapping = [c["path"] for c in built["semantic_diff"]["changes"] if c["section"] == "Mappings"]
    assert mapping
    for path in mapping:
        assert all(isinstance(item, str) for item in path), path
        assert 123456789012 not in path
    assert "123456789012" not in deltareport.dump(built)


MAPPING_PATH = ["Mappings", "CanaryMapName", "123456789012", "CanaryThirdKey"]
TAGS_PATH = ["Resources", "CanaryBucketLogicalId", "Properties", "Tags", "0", "Key"]
ABSENT_PATH = ["Resources", "CanaryAbsentLogicalId", "Properties", "Items", "3"]


def _path_findings() -> List[Finding]:
    return [
        _finding("map", None, category="DataProtection", evidence=(("cfn-lint", "W7001"),), path=MAPPING_PATH),
        _finding("tags", "CanaryBucketLogicalId", category="Tagging", evidence=(("cfn-lint", "W3005"),), path=TAGS_PATH),
        _finding("absent", "CanaryAbsentLogicalId", category="Logging", evidence=(("cfn-lint", "W3005"),), path=ABSENT_PATH),
    ]


def _projection_paths(built: Dict[str, Any]) -> Dict[str, List[List[Any]]]:
    paths: Dict[str, List[List[Any]]] = {"base": [], "head": []}
    for entry in built["finding_delta"]["entries"]:
        for side in paths:
            if entry[side] is not None:
                paths[side].append(entry[side]["TemplatePath"])
    return paths


@pytest.mark.parametrize("mode", deltaschema.IDENTIFIER_MODES)
def test_digit_only_mapping_key_in_finding_template_path_is_a_token(mode: str) -> None:
    """P4-1: with a Template_Pair the Finding TemplatePath is walked like a Change_Entry path."""
    built = _build(_request(base_findings=_path_findings(), head_findings=_path_findings()), mode)
    change = next(c["path"] for c in built["semantic_diff"]["changes"] if c["section"] == "Mappings")
    for side, paths in _projection_paths(built).items():
        mapping = [p for p in paths if p[0] == "Mappings"]
        assert len(mapping) == 1, side
        assert 123456789012 not in mapping[0]
        assert all(isinstance(item, str) for item in mapping[0]), mapping[0]
        # The same key gets the same Token as in the Change_Entry path.
        assert mapping[0][:3] == change[:3]
    if mode == "anonymized":
        assert "123456789012" not in deltareport.dump(built)


def test_finding_template_path_keeps_list_indexes_and_tokenizes_unplaced_integers() -> None:
    built = _build(_request(base_findings=_path_findings(), head_findings=_path_findings()))
    for paths in _projection_paths(built).values():
        tags = next(p for p in paths if len(p) == len(TAGS_PATH))
        assert tags[4] == 0 and tags[3].startswith("id-"), tags
        absent = next(p for p in paths if len(p) == len(ABSENT_PATH))
        # Position absent from the Template: the integer cannot be shown to be a list index.
        assert all(isinstance(item, str) for item in absent), absent
        assert absent[4].startswith("id-")


def test_finding_template_path_walks_the_template_of_its_own_side() -> None:
    """A mapping on one side and a list on the other: each Projection follows its side."""
    base = "Resources:\n  R:\n    Type: AWS::S3::Bucket\n    Properties:\n      P: {'0': a}\n"
    head = "Resources:\n  R:\n    Type: AWS::S3::Bucket\n    Properties:\n      P: [a]\n"
    findings = [_finding("p", "R", path=["Resources", "R", "Properties", "P", "0"])]
    built = _build(_request(base, head, base_findings=findings, head_findings=findings))
    paths = _projection_paths(built)
    assert isinstance(paths["base"][0][4], str) and paths["base"][0][4].startswith("id-")
    assert paths["head"][0][4] == 0


def test_finding_template_path_is_walked_only_in_the_template_of_its_file() -> None:
    """D-13: a Finding in another file, or an index outside the list, is not
    walked; the declared path (H-M1-1 approved) is the path compared."""
    text = "Resources:\n  R:\n    Type: AWS::S3::Bucket\n    Properties:\n      P: [a, b]\n"
    in_range = ["Resources", "R", "Properties", "P", "1"]
    out_of_range = ["Resources", "R", "Properties", "P", "2"]
    findings = [_finding("in", "R", path=in_range), _finding("out", "R", category="Logging", path=out_of_range)]
    request = _request(text, text, base_findings=findings, head_findings=findings)
    assert request.templates is not None

    def items(req: DeltaRequest) -> List[Any]:
        paths = _projection_paths(_build(req))
        assert sorted(map(str, paths["base"])) == sorted(map(str, paths["head"]))
        return sorted((p[4] for p in paths["base"]), key=str)

    walked = items(request)
    assert 1 in walked and not [i for i in walked if isinstance(i, int) and i != 1], walked
    other = tuple(TemplateInput("other.yaml", t.parsed) for t in request.templates)
    assert not [i for i in items(dataclasses.replace(request, templates=other)) if isinstance(i, int)]
    declared = dataclasses.replace(request, templates=other, reviewed_template_path=FILE)
    assert items(declared) == walked
    wrong = dataclasses.replace(request, reviewed_template_path="other.yaml")
    assert not [i for i in items(wrong) if isinstance(i, int)]


@pytest.mark.parametrize("mode", deltaschema.IDENTIFIER_MODES)
def test_report_pair_alone_tokenizes_template_path_integers(mode: str) -> None:
    """A-3 (HD-P4-1 (b), R12.2, D-H11): with no Template to walk, an integer
    cannot be shown to be a list index, so it is written like a key: a Token,
    or its decimal string in plain mode. A digit-only key is never plain."""
    built = _build(_request(None, None, base_findings=_path_findings(), head_findings=_path_findings()), mode)
    paths = _projection_paths(built)
    for side_paths in paths.values():
        assert len(side_paths) == 3
        for path in side_paths:
            assert not any(isinstance(item, int) for item in path), path
        mapping = next(p for p in side_paths if p[0] == "Mappings")
        tags = next(p for p in side_paths if len(p) == len(TAGS_PATH))
        absent = next(p for p in side_paths if len(p) == len(ABSENT_PATH))
        if mode == "anonymized":
            assert mapping[2].startswith("id-") and tags[4].startswith("id-") and absent[4].startswith("id-")
        else:
            assert (mapping[2], tags[4], absent[4]) == ("123456789012", "0", "3")
    # The same number gets the same Token on both sides (R12.5 (b)).
    assert sorted(paths["base"]) == sorted(paths["head"])
    if mode == "anonymized":
        assert "123456789012" not in deltareport.dump(built)


def test_unanalyzable_side_tokenizes_its_template_path_integers_only() -> None:
    """A-3: the Head Template does not parse; the Base side is still walked."""
    request = _request(base_findings=_path_findings(), head_findings=_path_findings())
    failure = deltaio.parse_template("Resources: [unclosed\n", Path("t.yaml"), "head")
    assert isinstance(failure, Failure)
    assert request.templates is not None
    request = dataclasses.replace(
        request,
        templates=(request.templates[0], TemplateInput("head.yaml", None)),
        semantic_diff=None,
        failures=(FailureRecord(failure),),
    )
    built = _build(request)
    paths = _projection_paths(built)
    base_tags = next(p for p in paths["base"] if len(p) == len(TAGS_PATH))
    assert base_tags[4] == 0  # a list index the Base Template confirms
    for path in paths["head"]:
        assert not any(isinstance(item, int) for item in path), path
    head_mapping = next(p for p in paths["head"] if p[0] == "Mappings")
    base_mapping = next(p for p in paths["base"] if p[0] == "Mappings")
    assert head_mapping[2] == base_mapping[2] and head_mapping[2].startswith("id-")
    assert "123456789012" not in deltareport.dump(built)


@pytest.mark.parametrize("mode", deltaschema.IDENTIFIER_MODES)
def test_non_decimal_digit_sibling_key_does_not_break_index_walk(mode: str) -> None:
    """A-3b, R10.4: ``"\u00b2"`` next to ``"\u0661\u0662\u0663"`` (canonical 123)."""
    bucket = "Resources:\n  B:\n    Type: AWS::S3::Bucket\n"
    base = bucket + "Mappings:\n  M:\n    \"\u00b2\": a\n    \"\u0661\u0662\u0663\": b\n"
    head = bucket + "Mappings:\n  M:\n    \"\u00b2\": a\n    \"\u0661\u0662\u0663\": c\n"
    built = _build(_request(base, head, base_findings=None, head_findings=None), mode)
    paths = [c["path"] for c in built["semantic_diff"]["changes"]]
    assert len(paths) == 1
    path = paths[0]
    assert path[0] == "Mappings" and all(isinstance(item, str) for item in path), path
    if mode == "plain":
        assert path == ["Mappings", "M", "\u0661\u0662\u0663"]
    else:
        assert path[2].startswith("id-")
        text = deltareport.dump(built)
        assert "\u0661\u0662\u0663" not in text and "\u00b2" not in text


def test_resource_types() -> None:
    built = _build(_request(base_findings=None, head_findings=None))
    types = set()
    for change in built["semantic_diff"]["changes"]:
        if change["resource_type"] is not None:
            types.update(v for v in change["resource_type"].values() if v is not None)
    assert "AWS::S3::Bucket" in types
    custom = [t for t in types if t.startswith("Custom::")]
    assert custom and all(t[len("Custom::") :].startswith("id-") for t in custom)
    assert any(t.startswith("id-") for t in types)  # CanaryVendor::Thing
    assert not any("Canary" in t for t in types)


def test_rule_ids_are_plain_only_in_their_closed_set_for_their_source() -> None:
    built = _build(_full_request())
    rules: Dict[str, set] = {}
    for entry in built["finding_delta"]["entries"]:
        for side in ("base", "head"):
            if entry[side] is not None:
                for item in entry[side]["Evidence"]:
                    rules.setdefault(item["Source"], set()).add(item["RuleId"])
    assert "s3_bucket_encryption" in rules["cfn-guard"]
    assert any(r.startswith("id-") for r in rules["cfn-guard"])  # unknown Guard rule
    assert rules["cfn-lint"] == {"W3005"}
    assert rules["IAM Review"] == {"wildcard_action"}
    assert all(r.startswith("id-") for r in rules["Network Review"])


def test_cfn_lint_pattern_needs_cfn_lint_source_and_a_full_match() -> None:
    findings = [
        _finding("a", "R1", evidence=(("Quality Review", "E1234"),)),
        _finding("b", "R2", evidence=(("cfn-lint", "E1234\n"),)),
        _finding("c", "R3", evidence=(("cfn-lint", "E12345"),)),
    ]
    built = _build(_request(None, None, base_findings=findings, head_findings=findings))
    rule_ids = {
        item["RuleId"] for e in built["finding_delta"]["entries"] for item in e["base"]["Evidence"]
    }
    assert all(r.startswith("id-") for r in rule_ids), rule_ids


def test_tool_names_and_versions() -> None:
    tools = (
        report.ToolStatus("cfn-guard", True, "3.2.1"),
        report.ToolStatus("cfn-lint", True, "1.46.0"),
        report.ToolStatus("CanaryToolName", True, "CanaryToolVersion"),
        report.ToolStatus("cdk", False, None),
    )
    built = _build(_request(None, None, base_findings=[], head_findings=[], base_tools=tools))
    rendered = built["inputs"]["base"]["report"]["tools"]
    names = [t["name"] for t in rendered]
    versions = [t["version"] for t in rendered]
    assert "cfn-guard" in names and "cfn-lint" in names and "cdk" in names
    assert "3.2.1" in versions and "1.46.0" in versions and None in versions
    assert "CanaryToolName" not in deltareport.dump(built)
    assert "CanaryToolVersion" not in deltareport.dump(built)
    assert sum(1 for n in names if n.startswith("id-")) == 1
    assert sum(1 for v in versions if isinstance(v, str) and v.startswith("id-")) == 1


def test_non_ascii_digit_version_is_a_token() -> None:
    tools = (report.ToolStatus("cfn-lint", True, "\u0661.\u0662"),)
    built = _build(_request(None, None, base_findings=[], head_findings=[], base_tools=tools))
    assert built["inputs"]["base"]["report"]["tools"][0]["version"].startswith("id-")


def test_error_summary_has_class_and_source_only() -> None:
    error = {
        "error_class": "tool_execution",
        "source": "cfn-lint",
        "tool": "CanaryErrorTool",
        "exit_code": 2,
        "message": "CanaryErrorMessage",
        "required_min_version": None,
        "detected_version": None,
        "remediation": "CanaryErrorRemediation",
        "stderr_head": ["CanaryStderrHead"],
    }
    obj = _report_obj([], errors=[error])
    checked = _checked(obj)
    other = _checked(_report_obj([]))
    result = delta.match_and_classify(checked, other, declarations=frozenset(), correspondence="not_applicable")
    request = DeltaRequest(
        templates=None,
        reports=(ReportInput("a.json", "0" * 64, checked), ReportInput("b.json", "1" * 64, other)),
        semantic_diff=None,
        finding_delta=result,
    )
    built = _build(request)
    assert built["inputs"]["base"]["report"]["error_summary"] == [{"error_class": "tool_execution", "source": "cfn-lint"}]
    text = deltareport.dump(built)
    assert "CanaryError" not in text and "CanaryStderr" not in text
    assert built["finding_delta"]["comparable"] is False


# ---------------------------------------------------------------------------
# No values, no free text
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode", deltaschema.IDENTIFIER_MODES)
def test_no_template_value_and_no_free_text(mode: str) -> None:
    text = deltareport.dump(_build(_full_request(), mode))
    for canary in VALUE_CANARIES + FREE_TEXT_CANARIES:
        assert canary not in text, canary


def test_projection_fields_only() -> None:
    built = _build(_full_request())
    for entry in built["finding_delta"]["entries"]:
        for side in ("base", "head"):
            projection = entry[side]
            if projection is not None:
                assert "Finding" not in projection and "WhyItMatters" not in projection
                assert isinstance(projection["ID"], int)
                assert projection["File"] == FILE


# ---------------------------------------------------------------------------
# Order, determinism
# ---------------------------------------------------------------------------


def test_changes_are_in_the_documented_order() -> None:
    changes = _build(_request(base_findings=None, head_findings=None))["semantic_diff"]["changes"]
    keys = [deltareport._change_sort_key(c) for c in changes]
    assert keys == sorted(keys)


def test_output_is_byte_identical_for_the_same_request() -> None:
    first = deltareport.render_delta_report(_full_request())
    second = deltareport.render_delta_report(_full_request())
    assert first.text == second.text
    assert first.text == deltareport.dump(_build(_full_request()))
    assert first.text.endswith("\n")
    assert first.exit_code == 0


def test_permuting_report_findings_keeps_entries() -> None:
    forward = _build(_request(None, None, base_findings=BASE_FINDINGS, head_findings=HEAD_FINDINGS))
    reversed_ = _build(
        _request(None, None, base_findings=list(reversed(BASE_FINDINGS)), head_findings=list(reversed(HEAD_FINDINGS)))
    )
    assert forward["finding_delta"] == reversed_["finding_delta"]


# ---------------------------------------------------------------------------
# Failures and the output limit
# ---------------------------------------------------------------------------


def test_unanalyzable_comparisons_and_error_order() -> None:
    head_failure = Failure("template_parse_failure", "head", "template", 7, 1)
    base_failure = Failure("template_alias_cycle", "base", "template")
    report_failure = Failure("report_schema_violation", "base", "report")
    request = DeltaRequest(
        templates=(TemplateInput("b.yaml", None), TemplateInput("h.yaml", None)),
        reports=(ReportInput("b.json", "0" * 64, None), ReportInput("h.json", None, None)),
        semantic_diff=None,
        finding_delta=None,
        failures=(
            FailureRecord(report_failure, "findings[0].Location.File"),
            FailureRecord(head_failure),
            FailureRecord(base_failure),
        ),
        declarations=frozenset({"reports_unmodified"}),
    )
    rendered = deltareport.render_delta_report(request)
    built = json.loads(rendered.text)
    messages = [e["message"] for e in built["errors"]]
    assert messages == [
        "base template: template_alias_cycle",
        "head template: template_parse_failure at line 7, column 1",
        "base report: report_schema_violation at field findings[0].Location.File",
    ]
    assert rendered.exit_code == 4
    diff = built["semantic_diff"]
    assert diff["analysis_state"] == "unanalyzable"
    assert diff["observation"] is None and diff["structural_completeness"] is None
    assert diff["changes"] == [] and diff["uncompared_paths"] == []
    assert diff["failure"] == {"side": "base", "input": "template", "code": "template_alias_cycle", "error_index": 0}
    findings = built["finding_delta"]
    assert findings["analysis_state"] == "unanalyzable"
    assert findings["observation"] is None and findings["classification_completeness"] is None
    assert findings["entries"] == []
    assert findings["failure"]["error_index"] == 2
    assert findings["input_declarations"]["declared"] == ["reports_unmodified"]
    assert "reports_match_templates" in findings["input_declarations"]["missing"]
    for error in built["errors"]:
        assert tuple(sorted(error)) == tuple(sorted(errors.STRUCTURED_ERROR_KEYS))
        assert error["stderr_head"] == []
    assert built["inputs"]["base"]["report"]["sha256"] == "0" * 64
    assert built["inputs"]["base"]["report"]["target"] is None


def test_reviewed_template_path_key_position_and_values() -> None:
    """H-M1-1 approved (Design 11-1): the key follows
    ``template_report_correspondence``; ``null`` without a declaration, the
    declared path with ``declared_not_verified`` otherwise, also when the
    Finding Delta is unanalyzable. No ``verified`` state exists."""
    keys = deltareport.FINDING_DELTA_KEYS
    assert keys[keys.index("template_report_correspondence") + 1] == "reviewed_template_path"
    assert _build(_full_request())["finding_delta"]["reviewed_template_path"] is None
    declared = dataclasses.replace(_full_request(), reviewed_template_path="stack/template.yaml")
    value = _build(declared)["finding_delta"]["reviewed_template_path"]
    assert value == {"path": "stack/template.yaml", "status": "declared_not_verified"}
    assert value["status"] == deltaschema.INPUT_DECLARATION_STATUSES[0]
    failure = Failure("report_schema_violation", "base", "report")
    request = DeltaRequest(
        templates=(TemplateInput("b.yaml", None), TemplateInput("h.yaml", None)),
        reports=(ReportInput("b.json", "0" * 64, None), ReportInput("h.json", None, None)),
        semantic_diff=None,
        finding_delta=None,
        failures=(FailureRecord(Failure("template_parse_failure", "base", "template")), FailureRecord(failure)),
        reviewed_template_path="stack/template.yaml",
    )
    findings = json.loads(deltareport.render_delta_report(request).text)["finding_delta"]
    assert findings["analysis_state"] == "unanalyzable"
    assert findings["reviewed_template_path"] == {"path": "stack/template.yaml", "status": "declared_not_verified"}


def test_unverified_assumptions_without_template_pair() -> None:
    built = _build(_request(None, None, base_findings=[], head_findings=[]))
    assumptions = built["finding_delta"]["unverified_assumptions"]
    assert "reports_match_templates" not in assumptions
    assert assumptions == [c for c in deltaschema.UNVERIFIED_ASSUMPTIONS if c != "reports_match_templates"]


def test_missing_failure_for_an_absent_result_is_a_programming_error() -> None:
    request = DeltaRequest(
        templates=(TemplateInput("b.yaml", None), TemplateInput("h.yaml", None)),
        reports=None,
        semantic_diff=None,
        finding_delta=None,
    )
    with pytest.raises(ValueError):
        deltareport.build_delta_report(request)
    with pytest.raises(ValueError):
        deltareport.build_delta_report(_full_request(), "verbose")


def test_limit_value_in_message(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(deltaschema, "MAX_TEMPLATE_NODES", 17)
    message = deltareport.failure_message(FailureRecord(Failure("template_node_limit_exceeded", "head", "template")))
    assert message == "head template: template_node_limit_exceeded (limit 17)"
    comparison = deltareport.failure_message(FailureRecord(Failure("change_entry_limit_exceeded", None, "template")))
    assert comparison.startswith("template comparison: change_entry_limit_exceeded (limit ")


def test_output_limit_gives_the_minimal_delta_report(monkeypatch: pytest.MonkeyPatch) -> None:
    request = _full_request()
    full = deltareport.render_delta_report(request)
    size = len(full.text.encode("utf-8"))
    monkeypatch.setattr(deltaschema, "MAX_OUTPUT_BYTES", size)
    assert deltareport.render_delta_report(request).text == full.text  # exactly at the limit
    monkeypatch.setattr(deltaschema, "MAX_OUTPUT_BYTES", size - 1)
    built = deltareport.build_delta_report(request)
    assert isinstance(built, Failure) and built.code == "output_size_limit_exceeded"
    rendered = deltareport.render_delta_report(request)
    assert rendered.exit_code == 3
    minimal = json.loads(rendered.text)
    assert set(minimal) == set(deltareport.ENVELOPE_KEYS)
    assert [e["error_class"] for e in minimal["errors"]] == ["input_too_large"]
    assert minimal["errors"][0]["message"].startswith("output: output_size_limit_exceeded")
    for name in ("semantic_diff", "finding_delta"):
        comparison = minimal[name]
        assert comparison["analysis_state"] == "unanalyzable"
        assert comparison["failure"] == {"side": None, "input": "output", "code": "output_size_limit_exceeded", "error_index": 0}
    assert minimal["semantic_diff"]["changes"] == [] and minimal["finding_delta"]["entries"] == []
    assert minimal["summary"]["semantic_diff"]["changes"] == 0
    assert minimal["summary"]["finding_delta"]["entries"] == 0
    assert minimal["inputs"] == json.loads(full.text)["inputs"]


def test_output_limit_keeps_earlier_failures_first(monkeypatch: pytest.MonkeyPatch) -> None:
    request = _full_request()
    failing = DeltaRequest(
        templates=request.templates,
        reports=request.reports,
        semantic_diff=None,
        finding_delta=request.finding_delta,
        failures=(FailureRecord(Failure("change_entry_limit_exceeded", None, "template")),),
        declarations=request.declarations,
        guard_rule_names=request.guard_rule_names,
    )
    monkeypatch.setattr(deltaschema, "MAX_OUTPUT_BYTES", 10)
    rendered = deltareport.render_delta_report(failing)
    minimal = json.loads(rendered.text)
    assert [e["message"].split(":")[1].strip().split(" ")[0] for e in minimal["errors"]] == [
        "change_entry_limit_exceeded",
        "output_size_limit_exceeded",
    ]
    assert minimal["semantic_diff"]["failure"]["code"] == "change_entry_limit_exceeded"
    assert minimal["finding_delta"]["failure"]["code"] == "output_size_limit_exceeded"
    assert rendered.exit_code == 3


# ---------------------------------------------------------------------------
# Bounded serialization and staged limit checks (RC Blocker P0)
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DELTA_FIXTURES = _REPO_ROOT / "tests" / "fixtures" / "delta"
_REPORT_DECLARATIONS = list(delta.REPORT_DECLARATIONS)


def _fixture_argvs() -> List[Tuple[str, List[str]]]:
    """CLI arguments (from the plugin root) for every delta fixture with the shipped limits."""
    cases: List[Tuple[str, List[str]]] = []
    for case in sorted(p for p in (_DELTA_FIXTURES / "templates").iterdir() if p.is_dir()):
        expected = json.loads((case / "expected.json").read_text(encoding="utf-8"))
        if expected.get("limits"):
            continue
        inputs = expected["inputs"]
        rel = case.relative_to(_REPO_ROOT).as_posix()
        head = inputs["head_ref"] if "head_ref" in inputs else rel + "/" + inputs["head"]
        cases.append((case.name, ["--base-template", rel + "/" + inputs["base"], "--head-template", head]))
    for case in sorted(p for p in (_DELTA_FIXTURES / "reports").iterdir() if p.is_dir()):
        rel = case.relative_to(_REPO_ROOT).as_posix()
        argv = ["--base-report", rel + "/base.json", "--head-report", rel + "/head.json"]
        for code in _REPORT_DECLARATIONS:
            argv += ["--declare", code]
        cases.append((case.name, argv))
    return cases


_FIXTURE_ARGVS = _fixture_argvs()


def _old_path_key(path: Optional[Sequence[Any]]) -> Tuple[Any, ...]:
    """The sort key before RC Blocker P0: one triple per item (the oracle)."""
    if path is None:
        return (0,)
    return (1, tuple((0, item, "") if isinstance(item, int) else (1, 0, item) for item in path))


def _cli_in_process(argv: Sequence[str], monkeypatch: pytest.MonkeyPatch) -> Tuple[int, str, str]:
    from iacreview import deltacli

    monkeypatch.chdir(_REPO_ROOT)
    out, err = io.StringIO(), io.StringIO()
    code = deltacli.main(list(argv), stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def test_fixture_list_is_not_empty() -> None:
    assert len(_FIXTURE_ARGVS) == 43 + 28  # 45 Template cases less the 2 with patched limits


@pytest.mark.parametrize("mode", deltaschema.IDENTIFIER_MODES)
def test_dump_is_report_dump(mode: str) -> None:
    built = _build(_full_request(), mode)
    assert deltareport.dump(built) == report.dump(built)
    odd = {"b": ["日本語", "²", "\U0001f600", 0, None, True, 1.5], "a": {"z": [], "y": {}}, "": ""}
    assert deltareport.dump(odd) == report.dump(odd)


def test_display_escapes_are_the_stderr_set_and_c1() -> None:
    """D-14 escapes in JSON what stderr replaces, less C0 (the serializer
    escapes C0 already) and DEL (outside the D-14 set)."""
    from iacreview import deltacli

    assert deltareport.DISPLAY_ESCAPED_CODE_POINTS == frozenset(range(0x80, 0xA0)) | deltacli._BIDI_CONTROLS
    assert len(deltareport.DISPLAY_ESCAPED_CODE_POINTS) == 32 + 5 + 4 + 3


@pytest.mark.parametrize("code", sorted(deltareport.DISPLAY_ESCAPED_CODE_POINTS))
def test_dump_escapes_each_display_code_point(code: int) -> None:
    char = chr(code)
    value = {"k" + char: ["a" + char + "b", "\\" + char, char + '"']}
    text = deltareport.dump(value)
    assert char not in text
    assert json.loads(text) == value
    escape = "\\u{0:04x}".format(code)
    assert text.count(escape) == 4
    assert text == report.dump(value).replace(char, escape)


def test_dump_keeps_other_non_ascii_raw() -> None:
    # Neighbours of the escaped ranges and other format characters stay as report.dump writes them.
    value = ["\x7f", "\xa0", "\u200b", "\u200d", "\u2029", "\u206a", "\u202f", "\u0661", "日本語"]
    assert deltareport.dump(value) == report.dump(value)


def test_bounded_text_counts_bytes_after_escaping() -> None:
    obj = {"k": ["\x85", "\u202e", "日本"]}
    text = deltareport.dump(obj)
    assert text == report.dump(obj).replace("\x85", "\\u0085").replace("\u202e", "\\u202e")
    size = len(text.encode("utf-8"))
    assert size == len(report.dump(obj).encode("utf-8")) + (6 - 2) + (6 - 3)
    assert deltareport._serialize(obj, size) == text
    assert deltareport._serialize(obj, size - 1) is None


@pytest.mark.parametrize("name,argv", _FIXTURE_ARGVS, ids=[name for name, _ in _FIXTURE_ARGVS])
@pytest.mark.parametrize("plain", [False, True])
def test_fixture_output_is_report_dump_and_limit_exact(
    name: str, argv: List[str], plain: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    argv = argv + (["--plain-identifiers"] if plain else [])
    code, out, err = _cli_in_process(argv, monkeypatch)
    assert out == report.dump(json.loads(out))
    size = len(out.encode("utf-8"))
    monkeypatch.setattr(deltaschema, "MAX_OUTPUT_BYTES", size)
    assert _cli_in_process(argv, monkeypatch) == (code, out, err)  # exactly at the limit
    monkeypatch.setattr(deltaschema, "MAX_OUTPUT_BYTES", size - 1)
    over_code, over_out, over_err = _cli_in_process(argv, monkeypatch)
    minimal = json.loads(over_out)
    assert "output_size_limit_exceeded" in [e["message"].split(": ")[1].split(" ")[0] for e in minimal["errors"]]
    assert over_err.splitlines()[-1] == "deltacli: output: output_size_limit_exceeded (limit {0})".format(size - 1)
    assert over_code == (code if code != 0 else 3)


def test_bounded_text_counts_utf8_bytes() -> None:
    obj = {"k": ["日本語", "²", "\U0001f600", "ascii"]}
    expected = report.dump(obj)
    size = len(expected.encode("utf-8"))
    assert size > len(expected)
    assert deltareport._serialize(obj, size) == expected
    assert deltareport._serialize(obj, size - 1) is None
    assert deltareport._serialize(obj, None) == expected


def test_bounded_text_stops_at_the_first_chunk_over_the_limit() -> None:
    consumed = []

    def chunks() -> Iterator[str]:
        for n in range(10_000):
            consumed.append(n)
            yield "ab"

    # 1 byte for the final newline, then 2 per chunk: 51 chunks make 103 > 101.
    assert deltareport._bounded_text(chunks(), 101) is None
    assert len(consumed) == 51


def test_bounded_text_joins_many_blocks_in_order() -> None:
    parts = [str(n % 10) for n in range(3 * deltareport._CHUNKS_PER_BLOCK + 7)]
    assert deltareport._bounded_text(iter(parts), None) == "".join(parts) + "\n"
    exact = len(parts) + 1
    assert deltareport._bounded_text(iter(parts), exact) == "".join(parts) + "\n"
    assert deltareport._bounded_text(iter(parts), exact - 1) is None


_SORT_PATHS: List[Optional[List[Any]]] = [
    None,
    [],
    [0],
    [1],
    [10],
    [""],
    ["0"],
    ["a"],
    ["a", 0],
    ["a", 1],
    ["a", "0"],
    ["a", ""],
    ["a", 0, "b"],
    ["a", 0, 0],
    ["a", "b", "c"],
    ["b"],
    [0, "a"],
    ["Resources", "id-000002", "Properties", 3],
    ["Resources", "id-000002", "Properties", "id-000001"],
    ["Resources", "id-000002"],
    ["Resources", "id-000001", "Properties", 3, 4],
]


def test_flat_path_key_orders_like_the_previous_key() -> None:
    for left in _SORT_PATHS:
        for right in _SORT_PATHS:
            old = (_old_path_key(left) > _old_path_key(right)) - (_old_path_key(left) < _old_path_key(right))
            new = (deltareport._path_key(left) > deltareport._path_key(right)) - (
                deltareport._path_key(left) < deltareport._path_key(right)
            )
            assert new == old, (left, right)


def _envelope_with(changes: List[Dict[str, Any]], uncompared: List[Dict[str, Any]]) -> int:
    built = _build(_request(base_findings=None, head_findings=None))
    built["semantic_diff"]["changes"] = changes
    built["semantic_diff"]["uncompared_paths"] = uncompared
    return len(deltareport.dump(built).encode("utf-8"))


def _min_change(path: List[Any]) -> Dict[str, Any]:
    shortest = min(deltaschema.CHANGE_KINDS, key=len)
    return {
        "section": "",
        "path": path,
        "change": shortest,
        "type_changed": True,
        "resource_type": None,
        "qualifiers": [],
        "hints": [],
    }


def _min_uncompared(path: List[Any]) -> Dict[str, Any]:
    return {"path": path, "reason": min(deltaschema.UNCOMPARED_REASONS, key=len)}


def test_lower_bound_constants_are_the_fewest_bytes_of_an_entry() -> None:
    empty = _envelope_with([], [])
    # One more entry adds its bytes plus the "," between elements.
    for make, constant, key in (
        (_min_change, deltareport._CHANGE_ENTRY_MIN_BYTES, "changes"),
        (_min_uncompared, deltareport._UNCOMPARED_MIN_BYTES, "uncompared"),
    ):
        lists = {"changes": [], "uncompared": []}
        lists[key] = [make([])]
        one = _envelope_with(lists["changes"], lists["uncompared"])
        lists[key] = [make([]), make([])]
        two = _envelope_with(lists["changes"], lists["uncompared"])
        assert two - one == constant + 1
        assert one - empty >= constant
        # n one-digit path items add 13 * n + 8 bytes: the bound is 13 per item.
        for n in (1, 2, 5):
            lists[key] = [make([0] * n)]
            with_path = _envelope_with(lists["changes"], lists["uncompared"])
            assert with_path - one == deltareport._PATH_ITEM_MIN_BYTES * n + 8


def _cli_request(argv: Sequence[str], monkeypatch: pytest.MonkeyPatch) -> DeltaRequest:
    from iacreview import deltacli

    monkeypatch.chdir(_REPO_ROOT)
    parsed = deltacli._parse(list(argv), io.StringIO())
    assert not isinstance(parsed, int)
    return deltacli._request(parsed, _REPO_ROOT)


@pytest.mark.parametrize("name,argv", _FIXTURE_ARGVS, ids=[name for name, _ in _FIXTURE_ARGVS])
def test_lower_bound_is_at_most_the_output_of_every_fixture(
    name: str, argv: List[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _cli_request(argv, monkeypatch)
    failures = deltareport._ordered_failures(request.failures)
    bound = deltareport._output_lower_bound(request, failures)
    for mode in deltaschema.IDENTIFIER_MODES:
        assert bound <= len(deltareport.render_delta_report(request, mode).text.encode("utf-8"))


def _deep_list_request(elements: int) -> DeltaRequest:
    levels = "".join('{{"k{0}": '.format(n) for n in range(20))
    close = "}" * 20

    def text(offset: int) -> str:
        items = json.dumps([n + offset for n in range(elements)])
        return '{"Resources": {"R": {"Type": "AWS::S3::Bucket", "Properties": ' + levels + items + close + "}}}"

    base = deltaio.parse_template(text(0), Path("b.json"), "base")
    head = deltaio.parse_template(text(1), Path("h.json"), "head")
    assert isinstance(base, ParsedTemplate) and isinstance(head, ParsedTemplate)
    result = semdiff.diff(base, head)
    assert isinstance(result, semdiff.SemanticDiffResult)
    return DeltaRequest(
        templates=(TemplateInput("b.json", base), TemplateInput("h.json", head)),
        reports=None,
        semantic_diff=result,
        finding_delta=None,
    )


@pytest.mark.parametrize("mode", deltaschema.IDENTIFIER_MODES)
def test_lower_bound_over_the_limit_gives_the_result_of_serializing(
    mode: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = _deep_list_request(50)
    bound = deltareport._output_lower_bound(request, ())
    assert bound == 50 * (deltareport._CHANGE_ENTRY_MIN_BYTES + deltareport._PATH_ITEM_MIN_BYTES * 24)
    full = deltareport.render_delta_report(request, mode)
    assert full.exit_code == 0 and bound <= len(full.text.encode("utf-8"))
    monkeypatch.setattr(deltaschema, "MAX_OUTPUT_BYTES", bound - 1)
    early = deltareport.render_delta_report(request, mode)
    early_built = deltareport.build_delta_report(request, mode)
    monkeypatch.setattr(deltareport, "_output_lower_bound", lambda request, failures: 0)
    late = deltareport.render_delta_report(request, mode)
    late_built = deltareport.build_delta_report(request, mode)
    assert early.text == late.text and early.failures == late.failures
    assert early.exit_code == 3
    assert json.loads(early.text)["semantic_diff"]["changes"] == []
    assert early_built == late_built == Failure("output_size_limit_exceeded", None, "output")


def test_lower_bound_is_zero_when_no_semantic_diff_is_written() -> None:
    request = _deep_list_request(5)
    assert deltareport._output_lower_bound(request, ()) > 0
    failed = (FailureRecord(Failure("change_entry_limit_exceeded", None, "template")),)
    assert deltareport._output_lower_bound(request, failed) == 0
    no_pair = dataclasses.replace(request, templates=None)
    assert deltareport._output_lower_bound(no_pair, ()) == 0
    # A Report_Pair without a Finding Delta or a report failure: rendering
    # raises the programming error as before, whatever the limit.
    reports = (ReportInput("b.json", None, None), ReportInput("h.json", None, None))
    broken = dataclasses.replace(request, reports=reports)
    assert deltareport._output_lower_bound(broken, ()) == 0


def test_programming_errors_are_raised_whatever_the_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    request = _deep_list_request(5)
    reports = (ReportInput("b.json", None, None), ReportInput("h.json", None, None))
    broken = dataclasses.replace(request, reports=reports)
    monkeypatch.setattr(deltaschema, "MAX_OUTPUT_BYTES", 10)
    with pytest.raises(ValueError):
        deltareport.render_delta_report(broken)
    with pytest.raises(ValueError):
        deltareport.build_delta_report(broken)
    with pytest.raises(ValueError):
        deltareport.render_delta_report(request, "verbose")
    with pytest.raises(ValueError):
        deltareport.build_delta_report(request, "verbose")


def test_collecting_pass_keeps_no_entry_and_collects_every_token() -> None:
    from iacreview import categories

    request = _full_request()
    collector = deltareport._Names(False, None)
    assert collector.collecting
    collected = deltareport._Renderer(request, collector, "anonymized", categories.load_map()).render((), False)
    assert collected["semantic_diff"]["changes"] == [] and collected["finding_delta"]["entries"] == []
    table = deltareport.build_token_table(collector.collected)
    assert not deltareport._Names(False, table).collecting
    text = deltareport.render_delta_report(request).text
    written = set(re.findall(r"id-[0-9]{6,}", text))
    assert written == set(table.values())


# ---------------------------------------------------------------------------
# Plugin data and module text
# ---------------------------------------------------------------------------


def test_guard_rule_names_are_the_bundled_rules() -> None:
    names = deltaio.load_guard_rule_names()
    assert "s3_bucket_encryption" in names
    assert all(isinstance(name, str) and name for name in names)


def test_module_text_and_imports() -> None:
    import ast

    path = Path(deltareport.__file__)
    text = path.read_text(encoding="utf-8")
    assert "hypothesis" not in text and ".kiro" not in text
    forbidden = {"subprocess", "socket", "urllib", "http", "ssl", "ftplib", "smtplib", "asyncio"}
    allowed = {"__future__", "json", "re", "dataclasses", "typing", "iacreview"}
    for node in ast.walk(ast.parse(text)):
        names: List[str] = []
        if isinstance(node, ast.Import):
            names = [alias.name.split(".")[0] for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [(node.module or "").split(".")[0]]
        for name in names:
            assert name not in forbidden
            assert name in allowed, name
