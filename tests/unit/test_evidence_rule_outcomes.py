"""Reachable outcomes of every rule and their agreement with the Definition (Phase 2 M1 Pre-Commit Remediation C-2).

Each catalog entry declares the statuses its rule can produce (``rules.RuleSpec.outcomes``). The registry refuses
a Definition whose ``expected_result`` names a status the rule never produces, or omits one it can produce. The
declarations themselves are checked against the rule code: an AST scan collects every status a rule function (and
the module functions it calls) can return. Comparisons such as ``x == "FAILED"`` are not outputs and are skipped.
"""

from __future__ import annotations

import ast
import copy
import inspect
import json
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Dict, Set

import pytest

from iacreview.evidence import artifact, open_questions, registry, replay, rule_s7_evidence, rules, rules_s7

STATUSES = {"PASS", "FAILED", "NOT_PROVEN"}
HELPERS = {"PASS": "PASS", "FAILED": "FAILED", "MISSING": "NOT_PROVEN"}  # rules_s7 constructors


def _module_functions(module: ModuleType) -> Dict[str, ast.FunctionDef]:
    tree = ast.parse(Path(inspect.getsourcefile(module) or "").read_text(encoding="utf-8"))
    return {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}


def _outputs(fn: Callable[..., Any]) -> Set[str]:
    """Upper bound of the statuses ``fn`` can produce, from its source and the same-module functions it calls."""
    module = inspect.getmodule(fn)
    assert module is not None
    funcs = _module_functions(module)
    seen: Set[str] = set()
    found: Set[str] = set()

    def visit(name: str) -> None:
        if name in seen or name not in funcs or name in HELPERS:
            return
        seen.add(name)
        compares = {id(c) for node in ast.walk(funcs[name]) if isinstance(node, ast.Compare)
                    for c in ast.walk(node)}
        for node in ast.walk(funcs[name]):
            if id(node) in compares:
                continue
            if isinstance(node, ast.Constant) and node.value in STATUSES:
                found.add(node.value)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in HELPERS and module is rules_s7:
                    found.add(HELPERS[node.func.id])
                else:
                    visit(node.func.id)

    visit(fn.__name__)
    return found


def test_every_declared_outcome_set_matches_the_rule_code() -> None:
    assert rules.catalog_problems() == []
    for rule_id, fn in sorted(rules.IMPLEMENTATIONS.items()):
        assert _outputs(fn) == set(rules.RULE_CATALOG[rule_id].outcomes), rule_id


def test_the_limits_and_the_open_questions_never_produce_failed() -> None:
    """S7-17, S7-18: limits (always NOT_PROVEN). S7-19: no violation condition in §7 (I-1)."""
    assert rules.RULE_CATALOG["s7.limit.same_app_with_key"].outcomes == {"NOT_PROVEN"}
    assert rules.RULE_CATALOG["s7.limits.recorded_not_proven"].outcomes == {"NOT_PROVEN"}
    assert rules.RULE_CATALOG[open_questions.RULE_ID].outcomes == {"PASS", "NOT_PROVEN"}
    assert _outputs(rules_s7.same_app_with_key) == {"NOT_PROVEN"} and _outputs(rules_s7.limits_recorded) == {"NOT_PROVEN"}
    assert _outputs(open_questions.open_questions_recorded) == {"PASS", "NOT_PROVEN"}
    assert _outputs(rule_s7_evidence.raw_api_data_stored) == STATUSES and _outputs(artifact.published_matches_source) == STATUSES


def test_the_shipped_definition_agrees_with_the_reachable_outcomes() -> None:
    definition, _ = replay.load_definition()
    assert registry._check_reachable_outcomes(definition) == []
    exp = {c["criterion_id"]: c["expected_result"] for ac in definition["acceptance_criteria"] for c in ac["criteria"]}
    assert exp["S7-17"] == exp["S7-18"] == {"satisfied": "NOT_PROVEN", "violated": "NOT_PROVEN", "evidence_missing": "NOT_PROVEN"}
    assert exp["S7-19"] == {"satisfied": "PASS", "violated": "NOT_PROVEN", "evidence_missing": "NOT_PROVEN"}


def _doc() -> Dict[str, Any]:
    return json.loads(replay.DEFINITION_PATH.read_text(encoding="utf-8"))


def _set(doc: Dict[str, Any], cid: str, **values: str) -> None:
    c = next(c for ac in doc["acceptance_criteria"] for c in ac["criteria"] if c["criterion_id"] == cid)
    c["expected_result"].update(values)


@pytest.mark.parametrize("cid,values,needle", [
    ("S7-19", {"violated": "FAILED"}, "can never produce ['FAILED']"),
    ("S7-17", {"violated": "FAILED"}, "can never produce ['FAILED']"),
    ("S7-18", {"satisfied": "PASS"}, "can never produce ['PASS']"),
    ("S7-08", {"violated": "NOT_PROVEN"}, "can produce ['FAILED'], which the Definition does not name"),
    ("S7-19", {"satisfied": "NOT_PROVEN"}, "can produce ['PASS'], which the Definition does not name"),
])
def test_an_intentional_mismatch_is_refused(cid: str, values: Dict[str, str], needle: str) -> None:
    doc = _doc()
    _set(doc, cid, **values)
    problems = registry.validate_definition(doc, replay.DEFINITION_PATH.name)
    assert any(cid in p and needle in p for p in problems), problems


def test_a_catalog_entry_without_not_proven_is_inconsistent(monkeypatch: pytest.MonkeyPatch) -> None:
    spec = rules.RULE_CATALOG["s7.limit.same_app_with_key"]
    bad = rules.RuleSpec(spec.rule_id, spec.status, spec.planned_wp, spec.summary, frozenset({"PASS"}))
    monkeypatch.setattr(rules, "_SPECS", tuple(bad if s.rule_id == spec.rule_id else s for s in rules._SPECS))
    assert any("outcomes must be a subset" in p for p in rules.catalog_problems())


def test_the_definition_is_not_changed_to_fit_a_rule() -> None:
    """The criterion texts stay the quoted §7 clauses; only expected_result of the three criteria changed."""
    doc = _doc()
    texts = {c["criterion_id"]: c["criterion_text"] for ac in doc["acceptance_criteria"] for c in ac["criteria"]}
    assert texts["S7-19"].startswith("Not verified until the run:")
    assert "stays a limit (`same_app_with_key`), not a pass" in texts["S7-17"].replace("\n  ", " ").replace("\n", " ")
    assert texts["S7-18"].startswith("Recorded as NOT_PROVEN with the reason")
    other = copy.deepcopy(doc)
    assert registry.validate_definition(other, replay.DEFINITION_PATH.name) == []
