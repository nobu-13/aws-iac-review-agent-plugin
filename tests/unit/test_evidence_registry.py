"""Acceptance Definition Registry: strict validation, fail-closed (Phase 2 M1 WP1-4).

Source: docs/v2/phase2/m1/wp0/m1-acceptance-test-matrix.md (M1-02) and the WP1
instruction's ten abnormal cases. Each case starts from the shipped Definition
(iacreview/evidence/definitions/phase1-app-demo-s7.v1.json), changes one thing,
and expects the registry to refuse it. Nothing here reads .agents/ or calls git
for writing.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Callable, Dict, List

import pytest

from iacreview.evidence import registry, rules

ROOT = Path(__file__).resolve().parents[2]
DEFINITION = ROOT / "iacreview" / "evidence" / "definitions" / "phase1-app-demo-s7.v1.json"
SCHEMA = ROOT / "iacreview" / "evidence" / "schema" / "acceptance-definition.v1.schema.json"
NAME = DEFINITION.name


@pytest.fixture()
def doc() -> Dict[str, Any]:
    return json.loads(DEFINITION.read_text(encoding="utf-8"))


def criteria(d: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [c for ac in d["acceptance_criteria"] for c in ac["criteria"]]


def crit(d: Dict[str, Any], cid: str) -> Dict[str, Any]:
    return next(c for c in criteria(d) if c["criterion_id"] == cid)


def refused(d: Any, needle: str, name: str = NAME) -> List[str]:
    problems = registry.validate_definition(d, name)
    assert problems, "the registry accepted an invalid definition"
    assert any(needle in p for p in problems), problems
    return problems


def test_the_shipped_definition_is_valid(doc: Dict[str, Any]) -> None:
    assert registry.validate_definition(doc, NAME) == []
    assert registry.check_test_references(doc, ROOT) == []


def test_load_definition_runs_every_check_against_the_repository() -> None:
    loaded = registry.load_definition(DEFINITION, ROOT)
    assert loaded["definition_id"] == "phase1-app-demo-s7" and registry.definition_files() == [DEFINITION]


# ---------------------------------------------------------------------------
# The ten abnormal cases of WP1-4
# ---------------------------------------------------------------------------


def test_01_duplicate_ac_id_is_refused(doc: Dict[str, Any]) -> None:
    doc["acceptance_criteria"][1]["ac_id"] = doc["acceptance_criteria"][0]["ac_id"]
    refused(doc, "duplicate AC ID")


def test_02_duplicate_criterion_id_is_refused(doc: Dict[str, Any]) -> None:
    crit(doc, "S7-09")["criterion_id"] = "S7-08"
    refused(doc, "duplicate criterion ID 'S7-08'")


def test_03_unknown_evaluator_rule_is_refused(doc: Dict[str, Any]) -> None:
    crit(doc, "S7-08")["evaluator_rule_id"] = "s7.required.does_not_exist"
    refused(doc, "is not in the catalog")


def test_04_a_test_marked_implemented_that_does_not_exist_is_refused(doc: Dict[str, Any]) -> None:
    test = crit(doc, "S7-01")["tests"][0]
    assert test["status"] == "IMPLEMENTED"
    test["test_id"] = "tests/unit/test_evidence_store.py::test_no_such_function_wp2"
    assert registry.validate_definition(doc, NAME) == []  # structurally fine; existence is a filesystem fact
    problems = registry.check_test_references(doc, ROOT)
    assert any("marked IMPLEMENTED but does not exist" in p for p in problems), problems


def test_04b_a_missing_test_file_is_refused_too(doc: Dict[str, Any]) -> None:
    crit(doc, "S7-02")["tests"].append({"test_id": "tests/unit/test_no_such_file_wp1.py::test_x", "kind": "rule_behaviour",
                                        "status": "IMPLEMENTED", "planned_wp": None})
    assert any("does not exist" in p for p in registry.check_test_references(doc, ROOT))


def test_04c_a_planned_test_that_already_exists_is_refused(doc: Dict[str, Any]) -> None:
    fidelity = next(t for t in crit(doc, "S7-19")["tests"] if t["status"] == "IMPLEMENTED")
    fidelity.update(status="PLANNED", planned_wp="WP4")
    assert any("exists but is marked PLANNED" in p for p in registry.check_test_references(doc, ROOT))


@pytest.mark.parametrize("value", [[], ["not_an_evidence_type"], ["github_actions_run", "github_actions_run"]])
def test_05_required_evidence_missing_or_unknown_is_refused(doc: Dict[str, Any], value: List[str]) -> None:
    crit(doc, "S7-03")["required_evidence_types"] = value
    refused(doc, "required_evidence_types")


def test_05b_required_evidence_field_absent_is_refused(doc: Dict[str, Any]) -> None:
    del crit(doc, "S7-03")["required_evidence_types"]
    refused(doc, "missing field(s) ['required_evidence_types']")


@pytest.mark.parametrize("path,value,needle", [
    (("expected_result", "satisfied"), "PROVEN", "unknown status"),
    (("expected_result", "violated"), "PASS", "a violation can never be PASS"),
    (("expected_result", "evidence_missing"), "PASS", "always NOT_PROVEN"),
    (("historical_classification", 0, "status"), "MAYBE", "unknown status"),
    (("tests", 0, "status"), "DONE", "unknown status"),
    (("tests", 0, "kind"), "smoke", "unknown kind"),
])
def test_06_unknown_status_is_refused(doc: Dict[str, Any], path: Any, value: str, needle: str) -> None:
    target: Any = crit(doc, "S7-03")
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    refused(doc, needle)


@pytest.mark.parametrize("value", ["24b7a6e", "24B7A6EAE6F6B55813F71E1418BD56F3425019C6", "g" * 40, None, 42])
def test_07_malformed_source_commit_sha_is_refused(doc: Dict[str, Any], value: Any) -> None:
    doc["historical_sources"][0]["commit"] = value
    refused(doc, "source commit SHA must be 40 lowercase hex")


def test_07b_a_source_commit_outside_the_verified_list_is_refused(doc: Dict[str, Any]) -> None:
    doc["historical_sources"][0]["commit"] = "0" * 40
    refused(doc, "must include the source commit")


def test_07c_a_decision_record_cannot_claim_a_commit(doc: Dict[str, Any]) -> None:
    rev2 = next(s for s in doc["historical_sources"] if s["source_id"] == "p1-rev2-summary")
    rev2["commit"] = "4bd6e015d88b01d34dc83dc2b2d2ffb0058358b2"
    refused(doc, "is not a committed criterion")


@pytest.mark.parametrize("version,name,needle", [
    (2, NAME, "does not match the registry index version 1"),
    (1, "phase1-app-demo-s7.v2.json", "does not match definition"),
    (1, "phase1-app-demo-s7.json", "does not match definition"),
    ("1", NAME, "must be a positive integer"),
    (True, NAME, "must be a positive integer"),
])
def test_08_definition_version_mismatch_is_refused(doc: Dict[str, Any], version: Any, name: str, needle: str) -> None:
    doc["definition_version"] = version
    refused(doc, needle, name)


def test_08b_an_unknown_definition_id_is_refused(doc: Dict[str, Any]) -> None:
    doc["definition_id"] = "phase1-app-demo-s7-copy"
    refused(doc, "is not in the registry index")


@pytest.mark.parametrize("scenario", ["G3", "G3S", "G6"])
@pytest.mark.parametrize("axis_ac,cid,new", [
    ("P1S7-REQUIRED", "S7-08", "NOT_PROVEN"),   # the helper's view (PARTIAL / NOT_PROVEN) must not replace FAILED
    ("P1S7-REQUIRED", "S7-15", "PARTIAL"),
    ("P1S7-MERGE", "S7-10", "FAILED"),
    ("P2-ISSUER", "P2-IP-01", "PASS"),
])
def test_09_historical_classification_of_g3_g3s_g6_cannot_be_altered(doc: Dict[str, Any], scenario: str, axis_ac: str, cid: str, new: str) -> None:
    entry = next(h for h in crit(doc, cid)["historical_classification"] if h["subject"] == scenario)
    entry["status"] = new
    refused(doc, "Phase 1 fixed it as")


@pytest.mark.parametrize("mutate", [
    lambda d: d["phase1_locked_classifications"][0].update(status="PARTIAL"),
    lambda d: d["phase1_locked_classifications"].pop(),
    lambda d: d["phase1_locked_classifications"].append(dict(d["phase1_locked_classifications"][0])),
], ids=["changed", "removed", "duplicated"])
def test_09b_the_locked_list_itself_cannot_be_altered(doc: Dict[str, Any], mutate: Callable[[Dict[str, Any]], None]) -> None:
    mutate(doc)
    refused(doc, "phase1_locked_classifications")


@pytest.mark.parametrize("mutate,needle", [
    (lambda d: d["phase1_final_results"]["scenarios"].update(G3="PARTIAL"), "scenarios differ"),
    (lambda d: d["phase1_final_results"]["scenarios"].update(G11="PASS"), "scenarios differ"),
    (lambda d: d["phase1_final_results"]["scenarios"].update(G12="PASS"), "scenarios differ"),
    (lambda d: d["phase1_final_results"]["ac_rev3_counts"].update(FAILED=0), "ac_rev3_counts differ"),
    (lambda d: d["historical_evaluator"].update(version_at_evidence_time="493177b4"), "must stay 'UNKNOWN'"),
    (lambda d: d["machine_readable_origin"].update(committed_in_phase1=True), "committed_in_phase1 must be false"),
])
def test_09c_phase1_final_results_and_provenance_cannot_be_altered(doc: Dict[str, Any], mutate: Callable[[Dict[str, Any]], None],
                                                                     needle: str) -> None:
    mutate(doc)
    refused(doc, needle)


def test_10_a_catalog_rule_without_a_criterion_is_refused(doc: Dict[str, Any]) -> None:
    ac = next(a for a in doc["acceptance_criteria"] if a["ac_id"] == "P1S7-REQUIRED")
    ac["criteria"] = [c for c in ac["criteria"] if c["criterion_id"] != "S7-09"]
    refused(doc, "rule 's7.required.app_check_required' in the catalog has no criterion")


@pytest.mark.parametrize("value", ["", None])
def test_10b_a_criterion_without_a_rule_is_refused(doc: Dict[str, Any], value: Any) -> None:
    crit(doc, "S7-09")["evaluator_rule_id"] = value
    refused(doc, "every criterion maps to a rule")


def test_10c_a_criterion_without_a_rule_behaviour_test_is_refused(doc: Dict[str, Any]) -> None:
    c = crit(doc, "S7-09")
    c["tests"] = [t for t in c["tests"] if t["kind"] != "rule_behaviour"]
    refused(doc, "at least one rule_behaviour test")


def test_10d_an_axis_without_criteria_is_refused(doc: Dict[str, Any]) -> None:
    doc["acceptance_criteria"] = [a for a in doc["acceptance_criteria"] if a["axis"] != "artifact_integrity"]
    problems = registry.validate_definition(doc, NAME)
    assert any("required axis 'artifact_integrity'" in p for p in problems), problems


def test_10e_one_rule_on_two_axes_is_refused(doc: Dict[str, Any]) -> None:
    crit(doc, "S7-10")["evaluator_rule_id"] = "s7.required.impostor_not_required"
    refused(doc, "is used on more than one axis")


# ---------------------------------------------------------------------------
# Structure, parsing and provenance
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("where", ["top", "source", "ac", "criterion", "test", "historical"])
def test_unknown_fields_are_refused_everywhere(doc: Dict[str, Any], where: str) -> None:
    target = {"top": doc, "source": doc["historical_sources"][0], "ac": doc["acceptance_criteria"][0],
              "criterion": crit(doc, "S7-08"), "test": crit(doc, "S7-08")["tests"][0],
              "historical": crit(doc, "S7-08")["historical_classification"][0]}[where]
    target["extra_field"] = "x"
    refused(doc, "unknown field(s) ['extra_field']")


@pytest.mark.parametrize("data,needle", [
    (b'{"a": 1, "a": 2}', "duplicate key"),
    (b'{"a": NaN}', "non-standard JSON constant"),
    (b"\xff\xfe", "not strict JSON"),
    (b"[1,", "not strict JSON"),
])
def test_non_strict_json_is_refused(data: bytes, needle: str) -> None:
    with pytest.raises(registry.RegistryError) as err:
        registry.parse_definition_bytes(data)
    assert needle in str(err.value)


def test_an_oversized_definition_is_refused() -> None:
    with pytest.raises(registry.RegistryError, match="larger than"):
        registry.parse_definition_bytes(b" " * (registry.MAX_DEFINITION_BYTES + 1))


@pytest.mark.parametrize("value", [None, [], "definition", 3])
def test_a_non_object_definition_is_refused(value: Any) -> None:
    assert registry.validate_definition(value, NAME) == ["definition: must be an object"]


def test_load_definition_raises_with_every_problem(tmp_path: Path, doc: Dict[str, Any]) -> None:
    crit(doc, "S7-09")["criterion_id"] = "S7-08"
    crit(doc, "S7-03")["required_evidence_types"] = []
    path = tmp_path / NAME
    path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(registry.RegistryError) as err:
        registry.load_definition(path)
    assert len(err.value.problems) >= 2


def test_load_definition_refuses_an_unreadable_file(tmp_path: Path) -> None:
    with pytest.raises(registry.RegistryError, match="cannot read"):
        registry.load_definition(tmp_path / NAME)


def test_a_historical_text_criterion_must_quote_a_pre_fixed_source(doc: Dict[str, Any]) -> None:
    crit(doc, "S7-08")["source_id"] = "p1-rev2-summary"
    refused(doc, "historical_text must quote a pre-fixed criterion source")


def test_a_phase2_criterion_cannot_pose_as_a_phase1_criterion(doc: Dict[str, Any]) -> None:
    crit(doc, "P2-IP-01")["source_id"] = "app-demo-plan-s7"
    refused(doc, "phase2_added criterion cannot cite a pre-fixed criterion")


def test_the_phase1_helper_cannot_be_declared_public(doc: Dict[str, Any]) -> None:
    doc["historical_evaluator"]["public"] = True
    refused(doc, "the Phase 1 helper is not public")


def test_the_definition_files_carry_no_private_path_except_as_historical_records(doc: Dict[str, Any]) -> None:
    """Paths under .agents/ appear only as non-public historical sources and the helper path, never as tests or rules."""
    for src in doc["historical_sources"]:
        assert src["path"].startswith(".agents/") == (not src["public"]), src["source_id"]
    for c in criteria(doc):
        assert all(t["test_id"].startswith("tests/") for t in c["tests"])


# ---------------------------------------------------------------------------
# Rule catalog and coverage: a registry row is not a result
# ---------------------------------------------------------------------------


def _planned_s7_19(monkeypatch: pytest.MonkeyPatch) -> None:
    """A catalog in which S7-19's rule is still PLANNED (the WP4 state), for the refusal tests below."""
    spec = rules.RULE_CATALOG["s7.open_questions.recorded"]
    fake = dict(rules.RULE_CATALOG)
    fake[spec.rule_id] = rules.RuleSpec(spec.rule_id, "PLANNED", "WP5", spec.summary)
    monkeypatch.setattr(rules, "RULE_CATALOG", fake)


def test_all_twenty_four_rules_are_implemented() -> None:
    """WP5 state: 3 rules from WP2/WP3, 20 from WP4 and S7-19's rule from WP5 implemented; none planned.
    Changed from the WP4 state (23 / 1) by WP5-1. Implemented is code that exists, not a result."""
    assert rules.catalog_problems() == []
    statuses = {s.rule_id: s.status for s in rules.RULE_CATALOG.values()}
    assert {r for r, st in statuses.items() if st == "PLANNED"} == set()
    assert sum(1 for st in statuses.values() if st == "IMPLEMENTED") == 24
    assert set(rules.IMPLEMENTATIONS) == {r for r, st in statuses.items() if st == "IMPLEMENTED"}
    assert rules.RULE_CATALOG["s7.open_questions.recorded"].planned_wp == "WP5"


def test_11_an_implemented_rule_whose_rule_test_is_planned_is_refused(doc: Dict[str, Any]) -> None:
    crit(doc, "S7-01")["tests"][0].update(status="PLANNED", planned_wp="WP2")
    refused(doc, "is IMPLEMENTED but none of its rule_behaviour tests is")


def test_11b_a_planned_rule_with_an_implemented_rule_test_is_refused(doc: Dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    _planned_s7_19(monkeypatch)
    assert crit(doc, "S7-19")["tests"][0]["status"] == "IMPLEMENTED"
    refused(doc, "is PLANNED but a rule_behaviour test is IMPLEMENTED")


def test_a_rule_marked_implemented_without_a_callable_is_inconsistent(monkeypatch: pytest.MonkeyPatch) -> None:
    impl = dict(rules.IMPLEMENTATIONS)
    del impl["s7.open_questions.recorded"]
    monkeypatch.setattr(rules, "IMPLEMENTATIONS", impl)
    assert any("does not match the implementations" in p for p in rules.catalog_problems())


def test_coverage_never_reports_a_criterion_as_proven(doc: Dict[str, Any]) -> None:
    rows = registry.coverage(doc)
    assert len(rows) == len(criteria(doc)) and all(r["proven"] is False for r in rows)
    by_status = {r["criterion_id"]: (r["rule_status"], tuple(r["rule_test_statuses"])) for r in rows}
    assert by_status["S7-19"] == ("IMPLEMENTED", ("IMPLEMENTED",))  # WP5 state; WP4 had PLANNED
    assert set(by_status.values()) == {("IMPLEMENTED", ("IMPLEMENTED",))}
    assert {s for r in rows for s in r["fidelity_test_statuses"]} == {"IMPLEMENTED"}


def test_coverage_rows_carry_every_registry_field(doc: Dict[str, Any]) -> None:
    row = next(r for r in registry.coverage(doc) if r["criterion_id"] == "S7-08")
    assert row["ac_id"] == "P1S7-REQUIRED" and row["definition_version"] == 1
    assert row["definition_source"] == "docs/v2/phase1/app-demo-plan.md"
    assert row["source_commit"] == "24b7a6eae6f6b55813f71e1418bd56f3425019c6"
    assert row["evaluator_rule_id"] == "s7.required.impostor_not_required" and row["rule_planned_wp"] == "WP4"
    assert row["required_evidence_types"] and row["expected_result"]["violated"] == "FAILED"
    assert {h["subject"]: h["status"] for h in row["historical_classification"]} == {"G3": "FAILED", "G3S": "FAILED", "G6": "FAILED"}
    assert row["historical_alignment"] == "NOT_IMPLEMENTED"


# ---------------------------------------------------------------------------
# The JSON Schema documents the same vocabulary the validator enforces
# ---------------------------------------------------------------------------


def test_the_schema_and_the_validator_agree_on_fields_and_vocabularies() -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    props = schema["properties"]
    assert set(schema["required"]) == set(props) == registry.TOP_KEYS and schema["additionalProperties"] is False
    ac = props["acceptance_criteria"]["items"]
    assert set(ac["properties"]) == registry.AC_KEYS and set(ac["properties"]["axis"]["enum"]) == registry.AXES
    c = ac["properties"]["criteria"]["items"]
    assert set(c["properties"]) == registry.CRITERION_KEYS
    assert set(c["properties"]["required_evidence_types"]["items"]["enum"]) == registry.EVIDENCE_TYPES
    assert set(c["properties"]["tests"]["items"]["properties"]) == registry.TEST_KEYS
    assert set(c["properties"]["historical_classification"]["items"]["properties"]["status"]["enum"]) == registry.HISTORICAL_STATUSES
    assert set(props["historical_sources"]["items"]["properties"]) == registry.SOURCE_KEYS


def test_clause_check_reports_unquoted_and_duplicated_text() -> None:
    d = {"historical_sources": [{"source_id": "s", "coverage": "complete"}],
         "acceptance_criteria": [{"ac_id": "A", "criteria": [{"criterion_id": "C", "origin": "historical_text", "source_id": "s",
                                                               "criterion_text": "alpha"}], "historical_source_text": []}],
         "non_normative_text": []}
    assert registry.clause_problems(d, {"s": "alpha | beta"}) and "beta" in registry.clause_problems(d, {"s": "alpha | beta"})[0]
    assert "occurs 2 times" in registry.clause_problems(d, {"s": "alpha alpha"})[0]
    assert registry.clause_problems(d, {"s": "| alpha |"}) == []
    excerpt = copy.deepcopy(d)
    excerpt["historical_sources"][0]["coverage"] = "excerpt"
    assert registry.clause_problems(excerpt, {"s": "alpha | beta"}) == []
