"""Inventory of the v1.1 acceptance fixtures under ``tests/fixtures/delta`` (Task 2).

Checks that every item of Requirements R15.4, R15.5 and R15.6 has a case,
that the README case table and the directory agree, and that every expected
value is well formed: closed-set values only, consistent states, no
Identifier_Token values, and every Finding of a Report fixture accounted for
exactly once. The item lists below are transcribed from requirements.md, so a
missing case fails here rather than going unnoticed.

This test does not run the Delta_Tool; it checks the fixtures that the
implementation is later tested against (R15.3).
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, List, Optional, Set, Tuple

import pytest

from iacreview import deltaschema

REPO_ROOT = Path(__file__).resolve().parents[2]
DELTA = REPO_ROOT / "tests" / "fixtures" / "delta"
TEMPLATES = DELTA / "templates"
REPORTS = DELTA / "reports"
README = DELTA / "README.md"
ALIAS_BOMB = REPO_ROOT / "tests" / "fixtures" / "invalid" / "billion_laughs.yaml"
SECRET_SCANNER = REPO_ROOT / ".github" / "scripts" / "scan_secrets.py"

#: R15.4, item by item -> the cases that cover it.
R15_4: Dict[str, Tuple[str, ...]] = {
    "notation: YAML / JSON": ("notation_yaml_vs_json",),
    "notation: short form / long form": ("notation_short_vs_long_form",),
    "notation: key order": ("notation_key_order",),
    "notation: comments": ("notation_comments_and_quoting",),
    "notation: anchor": ("notation_anchor_alias",),
    "Resource added / removed": ("resource_added_removed",),
    "Resource Type change": ("resource_type_changed",),
    "Property change": ("property_changed",),
    "Resource Attribute change": ("resource_attribute_changed",),
    "list order change": ("list_order_changed",),
    "scalar type difference": ("scalar_type_difference",),
    "unquoted date (N-3)": ("normalization_unquoted_date",),
    "timestamp with time (N-4)": ("normalization_yaml_timestamp",),
    "non-string key (N-5)": ("normalization_non_string_key",),
    "Parameter Default change": ("parameter_default_changed",),
    "Condition change": ("condition_changed",),
    "change inside Fn::If": ("fn_if_changed",),
    "equivalent intrinsic rewrite": ("intrinsic_equivalent_rewrite",),
    "Transform without change": ("transform_unchanged",),
    "Transform with change": ("transform_changed",),
    "AWS::Include": ("aws_include",),
    "dynamic reference without change": ("dynamic_reference_unchanged",),
    "dynamic reference string change": ("dynamic_reference_changed",),
    "Fn::ImportValue": ("import_value",),
    "Nested Stack": ("nested_stack",),
    "Logical ID rename": ("logical_id_rename",),
    "CDK synth format": ("cdk_synth_format",),
    "duplicate key: section name": ("duplicate_key_section_yaml", "duplicate_key_json"),
    "duplicate key: inside a Resource": ("duplicate_key_in_resource_yaml", "duplicate_key_json"),
    "duplicate key: deep level": ("duplicate_key_deep_yaml",),
    "duplicate key: inside a tag": ("duplicate_key_in_tag_yaml",),
    "duplicate key: alias shared": ("duplicate_key_alias_shared_yaml",),
    "duplicate key: YAML": ("duplicate_key_in_resource_yaml",),
    "duplicate key: JSON": ("duplicate_key_json",),
    "duplicate key with another change": ("duplicate_key_with_other_change_yaml",),
    "syntax error": ("syntax_error_yaml",),
    "no Resources": ("no_resources",),
    "alias cycle: list": ("cycle_list",),
    "alias cycle: mapping": ("cycle_mapping",),
    "alias cycle: inside a Resource": ("cycle_inside_resource",),
    "billion_laughs.yaml reference": ("billion_laughs_reference",),
    "logical node count at / over the limit": ("node_limit_boundary",),
    "depth at / over the limit": ("depth_limit_boundary",),
}

#: Template cases beyond R15.4 (other ACs that also need a fixture).
EXTRA_TEMPLATE_CASES: Tuple[str, ...] = (
    "alias_forward_reference",
    "cycle_inside_short_tag",
    "section_level_changes",
)

#: R15.5, item by item.
R15_5: Dict[str, Tuple[str, ...]] = {
    "identical Reports": ("match_identical_reports",),
    "findings[] / Evidence[] order only": ("match_reordered_findings_and_evidence",),
    "dedup-eligible Evidence partly removed": ("match_evidence_partially_removed",),
    "non-Comparable Source Evidence removed": ("match_non_comparable_evidence_removed",),
    "dedup-eligible TemplatePath and Evidence changed": ("match_templatepath_and_evidence_changed",),
    "Resource null, 1:1, same Fingerprint": ("match_null_resource_same_fingerprint",),
    "Resource null, 1:1, Evidence changed": ("match_null_resource_evidence_changed",),
    "Resource null, 1:1, TemplatePath changed": ("match_null_resource_templatepath_changed",),
    "Resource null, 1:2, one matches": ("match_null_resource_one_of_two_matches",),
    "Resource null, 1:2, none matches": ("match_null_resource_none_matches",),
    "Other, several on one Resource": ("match_other_category_multiple",),
    "duplicated Fingerprint": ("match_duplicate_fingerprint",),
    "duplicated dedup-eligible Identity_Key": ("match_dedup_identity_duplicated",),
    "merged and single-Source Finding": ("match_merged_and_single_source",),
}

#: R15.6, item by item.
R15_6: Dict[str, Tuple[str, ...]] = {
    "recorded conditions met": ("classify_recorded_conditions_met",),
    "tool unavailable": ("classify_tool_unavailable",),
    "Source not in sources_enabled": ("classify_source_not_enabled",),
    "tools[].version mismatch": ("classify_tool_version_mismatch",),
    "errors[] with / without Source": ("classify_error_attributed", "classify_error_unattributed"),
    "Template not reviewed": ("classify_template_not_reviewed",),
    "Agent Review only": ("classify_agent_review_only",),
    "internal consistency: ID gap": ("classify_integrity_id_gap",),
    "internal consistency: order": ("classify_integrity_order_violation",),
    "internal consistency: summary": ("classify_integrity_summary_mismatch",),
    "correspondence inconsistent": ("correspondence_inconsistent",),
    "correspondence unknown": ("correspondence_unknown",),
    "correspondence consistent_by_name_only": ("correspondence_consistent_by_name_only",),
}

R15_6_MODES = ("all", "none", "one_missing")
REPORT_DECLARATIONS = tuple(c for c in deltaschema.DECLARATION_CODES if c != "reports_match_templates")
TOKEN_PATTERN = re.compile(r"\bid-[0-9]+\b")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _case_dirs(root: Path) -> List[str]:
    return sorted(p.name for p in root.iterdir() if p.is_dir())


def _expected(directory: Path) -> Dict[str, Any]:
    return json.loads((directory / "expected.json").read_text(encoding="utf-8"))


def _readme_cases() -> Set[str]:
    found: Set[str] = set()
    for line in README.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^\| `((?:templates|reports)/[a-z0-9_]+)` \|", line)
        if match:
            found.add(match.group(1))
    return found


def _strings(value: Any) -> List[str]:
    out: List[str] = []
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return out


def _load_scanner() -> ModuleType:
    name = "delta_inventory_scan_secrets"
    spec = importlib.util.spec_from_file_location(name, SECRET_SCANNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


TEMPLATE_CASES = _case_dirs(TEMPLATES)
REPORT_CASES = _case_dirs(REPORTS)


# ---------------------------------------------------------------------------
# coverage of R15.4 / R15.5 / R15.6
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kind,items,root",
    [("R15.4", R15_4, TEMPLATES), ("R15.5", R15_5, REPORTS), ("R15.6", R15_6, REPORTS)],
)
def test_every_requirement_item_has_a_case(kind: str, items: Dict[str, Tuple[str, ...]], root: Path) -> None:
    existing = set(_case_dirs(root))
    for item, cases in items.items():
        assert cases, (kind, item)
        for name in cases:
            assert name in existing, "{0} item {1!r}: missing case {2}".format(kind, item, name)


def test_every_case_directory_is_accounted_for() -> None:
    templates = {c for cases in R15_4.values() for c in cases} | set(EXTRA_TEMPLATE_CASES)
    reports = {c for cases in list(R15_5.values()) + list(R15_6.values()) for c in cases}
    assert set(TEMPLATE_CASES) == templates
    assert set(REPORT_CASES) == reports


def test_readme_case_table_matches_the_directories() -> None:
    on_disk = {"templates/" + c for c in TEMPLATE_CASES} | {"reports/" + c for c in REPORT_CASES}
    assert _readme_cases() == on_disk


def test_readme_is_ascii_english() -> None:
    README.read_text(encoding="utf-8").encode("ascii")


def test_case_counts() -> None:
    assert len(TEMPLATE_CASES) == 45
    assert len(REPORT_CASES) == 28


# ---------------------------------------------------------------------------
# Template cases
# ---------------------------------------------------------------------------


def _template_inputs(name: str) -> Dict[str, Path]:
    directory = TEMPLATES / name
    inputs = _expected(directory)["inputs"]
    paths: Dict[str, Path] = {}
    if "base" in inputs:
        paths["base"] = directory / inputs["base"]
    if "head" in inputs:
        paths["head"] = directory / inputs["head"]
    if "head_ref" in inputs:
        paths["head"] = REPO_ROOT / inputs["head_ref"]
    return paths


@pytest.mark.parametrize("name", TEMPLATE_CASES)
def test_template_case_files(name: str) -> None:
    directory = TEMPLATES / name
    doc = _expected(directory)
    assert doc["case"] == name
    assert doc["covers"]
    paths = _template_inputs(name)
    assert set(paths) == {"base", "head"}
    for side, path in paths.items():
        assert path.is_file(), (name, side)
        assert path.suffix in (".yaml", ".json"), (name, side)
    listed = {p.name for p in directory.iterdir()}
    own = {paths[s].name for s in paths if paths[s].parent == directory}
    assert listed == own | {"expected.json"}, name


def test_billion_laughs_is_referenced_not_copied() -> None:
    inputs = _expected(TEMPLATES / "billion_laughs_reference")["inputs"]
    assert inputs["head_ref"] == "tests/fixtures/invalid/billion_laughs.yaml"
    bomb = ALIAS_BOMB.read_bytes()
    for path in DELTA.rglob("*"):
        if path.is_file():
            assert path.read_bytes() != bomb, path


@pytest.mark.parametrize("name", TEMPLATE_CASES)
def test_template_expected_values_are_well_formed(name: str) -> None:
    doc = _expected(TEMPLATES / name)
    for key in doc["limits"]:
        assert key in deltaschema.LIMIT_FAILURE_CODES, key
        assert isinstance(doc["limits"][key], int) and doc["limits"][key] > 0
    e = doc["expected"]
    assert e["analysis_state"] in deltaschema.ANALYSIS_STATES
    assert set(e["semantic_limitations"]) <= set(deltaschema.SEMANTIC_LIMITATIONS)
    for entry in e["uncompared_paths"]:
        assert set(entry) == {"path", "reason"}
        assert entry["reason"] in deltaschema.UNCOMPARED_REASONS
        assert entry["path"] and isinstance(entry["path"][0], str)
    for change in e["changes"]:
        assert set(change) == {"section", "path", "change", "type_changed", "resource_type", "qualifiers", "hints"}
        assert change["section"] == change["path"][0]
        assert change["change"] in deltaschema.CHANGE_KINDS
        assert set(change["qualifiers"]) <= set(deltaschema.CHANGE_QUALIFIERS)
        assert set(change["hints"]) <= set(deltaschema.CHANGE_HINTS)
        assert isinstance(change["type_changed"], bool)
        if change["section"] == "Resources":
            assert set(change["resource_type"]) == {"base", "head"}
        else:
            assert change["resource_type"] is None
        for segment in change["path"]:
            assert isinstance(segment, (str, int)) and not isinstance(segment, bool)
    if e["analysis_state"] == "unanalyzable":
        # R5.3, R5.9: nothing but the failure.
        assert e["observation"] is None and e["structural_completeness"] is None
        assert e["changes"] == [] and e["uncompared_paths"] == []
        failure = e["failure"]
        assert failure["side"] in deltaschema.SIDES
        assert failure["input"] == "template"
        assert failure["code"] in deltaschema.FAILURE_CODES
    else:
        assert e["failure"] is None
        # R5.6 and R5.4.
        assert e["observation"] == ("changes_observed" if e["changes"] else "no_changes_observed")
        assert e["structural_completeness"] == ("partial" if e["uncompared_paths"] else "complete")


@pytest.mark.parametrize("name", TEMPLATE_CASES)
def test_template_shapes_are_consistent_with_limits(name: str) -> None:
    doc = _expected(TEMPLATES / name)
    shapes: Optional[Dict[str, Any]] = doc["expected"].get("shapes")
    if not shapes:
        return
    limits = dict(doc["limits"])
    nodes_limit = limits.get("MAX_TEMPLATE_NODES", deltaschema.MAX_TEMPLATE_NODES)
    depth_limit = limits.get("MAX_TEMPLATE_DEPTH", deltaschema.MAX_TEMPLATE_DEPTH)
    failure = doc["expected"]["failure"]
    for side, shape in shapes.items():
        assert shape["containers"] <= shape["nodes"]
        over_depth = shape["depth"] > depth_limit
        over_nodes = shape["nodes"] > nodes_limit
        if failure is not None and failure["side"] == side:
            expected_code = (
                "template_depth_limit_exceeded" if over_depth else "template_node_limit_exceeded"
            )
            assert over_depth or over_nodes
            assert failure["code"] == expected_code
        else:
            assert not over_depth and not over_nodes, (name, side)


# ---------------------------------------------------------------------------
# Report cases
# ---------------------------------------------------------------------------


def _labels(path: Path) -> List[str]:
    report = json.loads(path.read_text(encoding="utf-8"))
    return [f["Finding"] for f in report["findings"]]


@pytest.mark.parametrize("name", REPORT_CASES)
def test_report_case_files(name: str) -> None:
    directory = REPORTS / name
    doc = _expected(directory)
    assert doc["case"] == name
    assert doc["inputs"] == {"base": "base.json", "head": "head.json"}
    expected_files = {"base.json", "head.json", "expected.json"}
    pair = doc["template_pair"]
    if pair is not None:
        for side in ("base", "head"):
            assert (directory / pair[side]["file"]).is_file()
            expected_files.add(pair[side]["file"])
            assert not pair[side]["workspace_path"].startswith("/")
    assert {p.name for p in directory.iterdir()} == expected_files
    for side in ("base", "head"):
        labels = _labels(directory / "{0}.json".format(side))
        assert len(labels) == len(set(labels)), (name, side)


@pytest.mark.parametrize("name", REPORT_CASES)
def test_report_declaration_modes(name: str) -> None:
    doc = _expected(REPORTS / name)
    modes = doc["declarations"]
    is_classification = name in {c for cases in R15_6.values() for c in cases}
    assert tuple(sorted(modes)) == (tuple(sorted(R15_6_MODES)) if is_classification else ("all",))
    required = (
        deltaschema.DECLARATION_CODES if doc["template_pair"] is not None else REPORT_DECLARATIONS
    )
    assert sorted(modes["all"]) == sorted(required)
    if is_classification:
        assert modes["none"] == []
        assert len(modes["one_missing"]) == len(required) - 1
        assert set(modes["one_missing"]) < set(required)
    assert set(doc["expected"]["by_declarations"]) == set(modes)


@pytest.mark.parametrize("name", REPORT_CASES)
def test_report_expected_values_are_well_formed(name: str) -> None:
    directory = REPORTS / name
    doc = _expected(directory)
    e = doc["expected"]
    assert e["analysis_state"] == "analyzed"
    assert e["template_report_correspondence"] in deltaschema.TEMPLATE_REPORT_CORRESPONDENCE
    assert (e["template_report_correspondence"] == "not_applicable") == (doc["template_pair"] is None)
    assert isinstance(e["comparable"], bool)
    for side in ("base", "head"):
        assert set(e["report_integrity"][side]) <= set(deltaschema.REPORT_INTEGRITY_CHECKS)
    labels = {side: _labels(directory / "{0}.json".format(side)) for side in ("base", "head")}
    for mode, outcome in e["by_declarations"].items():
        declared = set(doc["declarations"][mode])
        entries = outcome["entries"]
        seen: Dict[str, List[str]] = {"base": [], "head": []}
        for entry in entries:
            assert entry["observation"] in deltaschema.ENTRY_OBSERVATIONS
            assert entry["classification"] in deltaschema.DELTA_CLASSIFICATIONS
            for side in ("base", "head"):
                if entry[side] is not None:
                    seen[side].append(entry[side])
            _check_entry(entry, declared)
        # R6.11: every Finding of both Reports appears in exactly one entry.
        for side in ("base", "head"):
            assert sorted(seen[side]) == sorted(labels[side]), (name, mode, side)
        # R5.5, R5.6.
        changed = any(x["observation"] != "matched" or x["changes"] for x in entries)
        complete = all(x["classification"] in ("New", "Resolved", "Unchanged") for x in entries)
        assert outcome["observation"] == ("changes_observed" if changed else "no_changes_observed")
        assert outcome["classification_completeness"] == ("complete" if complete else "partial")


def _check_entry(entry: Dict[str, Any], declared: Set[str]) -> None:
    observation = entry["observation"]
    classification = entry["classification"]
    present = tuple(side for side in ("base", "head") if entry[side] is not None)
    if observation == "matched":
        assert present == ("base", "head")
        assert classification == "Unchanged"
        assert entry["match_stage"] in deltaschema.MATCH_STAGES
        assert entry["reasons"] == [] and entry["missing_declarations"] == []
        fields = {"Severity", "FindingType", "Confidence", "Source", "Location.TemplatePath", "Evidence"}
        assert set(entry["changes"]) <= fields
        assert ("Evidence" in entry["changes"]) == bool(
            entry["evidence_absent_in_head"] or entry["evidence_absent_in_base"]
        )
        for element in entry["evidence_absent_in_head"] + entry["evidence_absent_in_base"]:
            assert set(element) == {"Source", "RuleId", "source_comparable"}
            assert isinstance(element["source_comparable"], bool)
        return
    assert entry["match_stage"] is None
    assert entry["changes"] == []
    assert entry["evidence_absent_in_head"] == [] and entry["evidence_absent_in_base"] == []
    assert len(present) == 1
    if observation == "unmatched":
        assert classification == "Ambiguous"
        assert entry["reasons"]
        assert set(entry["reasons"]) <= {"identity_undetermined", "duplicate_fingerprint"}
        return
    assert observation == ("head_only" if present == ("head",) else "base_only")
    # R7.4: New only for head_only, Resolved only for base_only.
    if classification == "New":
        assert observation == "head_only"
    if classification == "Resolved":
        assert observation == "base_only"
    if classification == "Ambiguous":
        assert entry["reasons"]
        assert set(entry["reasons"]) <= set(deltaschema.AMBIGUOUS_REASONS) - {
            "identity_undetermined",
            "duplicate_fingerprint",
        }
        assert entry["missing_declarations"] == []
    elif classification == "Unconfirmed":
        assert entry["reasons"] == list(deltaschema.UNCONFIRMED_REASONS)
        assert entry["missing_declarations"]
        assert set(entry["missing_declarations"]) <= set(deltaschema.DECLARATION_CODES)
        assert not set(entry["missing_declarations"]) & declared
    else:
        assert classification in ("New", "Resolved")
        assert entry["reasons"] == [] and entry["missing_declarations"] == []


# ---------------------------------------------------------------------------
# Every fixture
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["templates/" + c for c in TEMPLATE_CASES] + ["reports/" + c for c in REPORT_CASES])
def test_expected_values_hold_no_identifier_token(name: str) -> None:
    doc = _expected(DELTA / name)
    for text in _strings(doc["expected"]):
        assert not TOKEN_PATTERN.search(text), (name, text)


def test_fixtures_pass_the_secret_scan() -> None:
    """R12.18: the repository secret scanner reports nothing on the fixtures."""
    scanner = _load_scanner()
    findings = []
    files = sorted(p for p in DELTA.rglob("*") if p.is_file())
    assert files
    for path in files:
        findings.extend(scanner.scan_file(REPO_ROOT, path))
    assert findings == []
