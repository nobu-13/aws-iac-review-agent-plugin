"""Acceptance Definition Registry: strict loader and validator (Phase 2 M1 WP1).

Source: ``docs/v2/phase2/m1/wp0/m1-architecture-proposal.md`` §3-1 and §4-1,
``acceptance-alignment-audit.md`` §2 (clause ids S7-xx). Purpose: Phase 1's
helper drifted from the pre-fixed criterion (section 7 ``isRequired``) because
no artifact tied a clause of the criterion to the code and the test that judge
it. A Definition does that, and this module refuses any Definition that is
incomplete, ambiguous or inconsistent.

What a valid Definition shows: every clause has one rule id from the catalog,
at least one test id, required evidence types, an expected result per outcome
and its historical classification. What it does NOT show: that the rule or the
test exists or passed. :func:`coverage` reports the status of each separately.

Fail-closed: every problem is collected and :func:`load_definition` raises
:class:`RegistryError` if there is any. Nothing is defaulted.

Standard library only. No network, no git write; the optional git cross-check
(:func:`git_source_problems`) runs ``git show`` / ``git rev-parse`` through
:func:`iacreview.proc.run_bounded`.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Callable, Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Tuple

from iacreview.evidence import rules

SCHEMA_VERSION = 1

#: Largest Definition file accepted (bytes).
MAX_DEFINITION_BYTES = 1024 * 1024

DEFINITIONS_DIR = Path(__file__).resolve().parent / "definitions"

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------

TOP_KEYS: FrozenSet[str] = frozenset({
    "schema_version", "definition_id", "definition_version", "title", "purpose", "machine_readable_origin",
    "historical_sources", "historical_evaluator", "phase1_locked_classifications", "phase1_final_results",
    "acceptance_criteria", "non_normative_text",
})
ORIGIN_KEYS: FrozenSet[str] = frozenset({"phase", "created_by_work_package", "committed_in_phase1", "statement"})
SOURCE_KEYS: FrozenSet[str] = frozenset({
    "source_id", "kind", "path", "section", "coverage", "commit", "verified_commits", "blob_ids", "sha256_at_wp0", "public",
    "note",
})
#: How much of a pre-fixed section a Definition must quote: all of it, or named excerpts only.
SOURCE_COVERAGE: FrozenSet[str] = frozenset({"complete", "excerpt"})
SOURCE_KINDS: FrozenSet[str] = frozenset({"pre_fixed_criterion", "phase1_decision_record", "phase2_document"})
EVALUATOR_KEYS: FrozenSet[str] = frozenset({"helper_path", "public", "sha256_at_wp0", "version_at_evidence_time", "reason"})
LOCK_KEYS: FrozenSet[str] = frozenset({"subject", "axis", "status", "basis_source_id", "basis"})
FINAL_KEYS: FrozenSet[str] = frozenset({"scenarios", "scenario_counts", "ac_rev3_counts", "basis_source_ids"})
AC_KEYS: FrozenSet[str] = frozenset({"ac_id", "axis", "title", "phase1_ac_refs", "historical_source_text", "criteria"})
SOURCE_TEXT_KEYS: FrozenSet[str] = frozenset({"source_id", "text"})
NON_NORMATIVE_KEYS: FrozenSet[str] = frozenset({"source_id", "text", "reason"})
CRITERION_KEYS: FrozenSet[str] = frozenset({
    "criterion_id", "criterion_text", "origin", "source_id", "evaluator_rule_id", "tests", "required_evidence_types",
    "expected_result", "historical_classification", "historical_implementation",
})
TEST_KEYS: FrozenSet[str] = frozenset({"test_id", "kind", "status", "planned_wp"})
#: rule_behaviour: the test judges the rule. definition_fidelity: the test checks the Definition itself
#: (quoted text, locked history). Only the first kind can ever show that a rule behaves as defined.
TEST_KINDS: FrozenSet[str] = frozenset({"rule_behaviour", "definition_fidelity"})
EXPECTED_KEYS: FrozenSet[str] = frozenset({"satisfied", "violated", "evidence_missing"})
HISTORICAL_KEYS: FrozenSet[str] = frozenset({"subject", "status", "basis_source_id", "basis"})
IMPLEMENTATION_KEYS: FrozenSet[str] = frozenset({"helper_function", "alignment", "audit_ref"})

CRITERION_ORIGINS: FrozenSet[str] = frozenset({"historical_text", "phase2_added"})
AXES: FrozenSet[str] = frozenset({
    "evidence_recording", "scenario_composition", "gate_provenance", "app_check_provenance", "required_check",
    "merge_blocking", "issuer_pinning_independent_proof", "g11_environment_boundary", "artifact_integrity",
})
#: Decision statuses an evaluator may produce (M1).
DECISION_STATUSES: FrozenSet[str] = frozenset({"PASS", "FAILED", "NOT_PROVEN"})
#: Statuses Phase 1 recorded (rev2 §0), plus NOT_CLASSIFIED: Phase 1 gave this clause no separate result.
HISTORICAL_STATUSES: FrozenSet[str] = frozenset({
    "PASS", "FAILED", "PARTIAL", "NOT_PROVEN", "NOT_APPLICABLE", "OBSERVED", "NOT_CLASSIFIED",
})
TEST_STATUSES: FrozenSet[str] = frozenset({"PLANNED", "IMPLEMENTED"})
ALIGNMENTS: FrozenSet[str] = frozenset({
    "ALIGNED", "NOT_IMPLEMENTED", "DIVERGENT", "PARTIAL_DEFAULTS", "CRITERION_ABSENT", "NOT_AUDITED",
})
EVIDENCE_TYPES: FrozenSet[str] = frozenset({
    "github_actions_run", "github_actions_jobs", "github_actions_job_log", "github_actions_artifact",
    "github_rest_check_runs", "github_rest_check_run_annotations", "github_rest_commit_statuses",
    "github_rest_branch_rules", "github_rest_contents", "github_graphql_status_rollup", "local_git_tree",
    "approved_source_definition", "evidence_store_manifest", "acceptance_definition",
})

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_SHA64 = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_TEST_ID = re.compile(r"^(tests/[A-Za-z0-9_/]+\.py)::(test_[A-Za-z0-9_]+)$")
_FILE_NAME = re.compile(r"^([a-z0-9][a-z0-9-]*)\.v([1-9][0-9]*)\.json$")

# ---------------------------------------------------------------------------
# Known Definitions and their locked historical facts
# ---------------------------------------------------------------------------

#: Every Definition the registry accepts, with its current version and the axes it must hold.
DEFINITION_INDEX: Mapping[str, Mapping[str, Any]] = {
    "phase1-app-demo-s7": {
        "version": 1,
        "required_axes": (
            "gate_provenance", "app_check_provenance", "required_check", "merge_blocking",
            "issuer_pinning_independent_proof", "g11_environment_boundary", "artifact_integrity",
        ),
    },
}

#: Phase 1 results fixed by the Phase 1 final acceptance (rev2 §3-1, §4; rev3 AC27). A Definition that
#: disagrees with any of them is rejected: a Phase 2 artifact may quote Phase 1, never re-decide it.
PHASE1_LOCKED: Mapping[str, Mapping[str, Any]] = {
    "phase1-app-demo-s7": {
        "classifications": frozenset({
            ("G3", "required_check", "FAILED"), ("G3S", "required_check", "FAILED"), ("G6", "required_check", "FAILED"),
            ("G3", "merge_blocking", "PASS"), ("G3S", "merge_blocking", "PASS"), ("G6", "merge_blocking", "PASS"),
            ("G3", "issuer_pinning_independent_proof", "NOT_PROVEN"), ("G3S", "issuer_pinning_independent_proof", "NOT_PROVEN"),
            ("G6", "issuer_pinning_independent_proof", "NOT_PROVEN"),
        }),
        "scenarios": {
            "G0": "PASS", "G1": "PASS", "G2": "PASS", "G4": "PASS", "G5": "PASS", "G9": "PASS", "G10": "PASS", "G11b": "PASS",
            "G3": "FAILED", "G3S": "FAILED", "G6": "FAILED", "G12": "PARTIAL", "G7": "NOT_PROVEN", "G8": "NOT_PROVEN",
            "G11": "NOT_PROVEN",
        },
        "ac_rev3_counts": {"PASS": 40, "PARTIAL": 4, "FAILED": 1, "NOT_PROVEN": 3},
        "historical_evaluator_version": "UNKNOWN",
    },
}


class RegistryError(Exception):
    """A Definition was refused. ``problems`` lists every reason found."""

    def __init__(self, problems: Sequence[str]) -> None:
        super().__init__("; ".join(problems))
        self.problems = list(problems)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def _no_duplicate_keys(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate key {0!r}".format(key))
        out[key] = value
    return out


def _no_constant(name: str) -> Any:
    raise ValueError("non-standard JSON constant {0}".format(name))


def parse_definition_bytes(data: bytes) -> Any:
    """Parse strict JSON: UTF-8, no duplicate keys, no NaN / Infinity, bounded size."""
    if len(data) > MAX_DEFINITION_BYTES:
        raise RegistryError(["definition is larger than {0} bytes".format(MAX_DEFINITION_BYTES)])
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_no_duplicate_keys, parse_constant=_no_constant)
    except (UnicodeDecodeError, ValueError) as exc:
        raise RegistryError(["definition is not strict JSON: {0}".format(exc)]) from None


# ---------------------------------------------------------------------------
# Field checks (each returns problems; none raises)
# ---------------------------------------------------------------------------


def _keys(obj: Any, allowed: FrozenSet[str], where: str) -> List[str]:
    if not isinstance(obj, dict):
        return ["{0}: must be an object".format(where)]
    problems = []
    missing = sorted(allowed - set(obj))
    unknown = sorted(set(obj) - allowed)
    if missing:
        problems.append("{0}: missing field(s) {1}".format(where, missing))
    if unknown:
        problems.append("{0}: unknown field(s) {1}".format(where, unknown))
    return problems


def _text(value: Any, where: str) -> List[str]:
    return [] if isinstance(value, str) and value.strip() else ["{0}: must be a non-empty string".format(where)]


def _list(value: Any, where: str, allow_empty: bool = False) -> List[str]:
    if not isinstance(value, list):
        return ["{0}: must be a list".format(where)]
    if not value and not allow_empty:
        return ["{0}: must not be empty".format(where)]
    return []


def _int(value: Any, where: str) -> List[str]:
    ok = isinstance(value, int) and not isinstance(value, bool) and value >= 1
    return [] if ok else ["{0}: must be a positive integer".format(where)]


def _check_origin(origin: Any) -> List[str]:
    problems = _keys(origin, ORIGIN_KEYS, "machine_readable_origin")
    if problems:
        return problems
    if origin["committed_in_phase1"] is not False:
        problems.append("machine_readable_origin.committed_in_phase1 must be false: this file did not exist in Phase 1")
    for key in ("phase", "created_by_work_package", "statement"):
        problems += _text(origin[key], "machine_readable_origin." + key)
    return problems


def _check_source(src: Any, index: int) -> List[str]:
    where = "historical_sources[{0}]".format(index)
    problems = _keys(src, SOURCE_KEYS, where)
    if problems:
        return problems
    for key in ("source_id", "path", "note"):
        problems += _text(src[key], "{0}.{1}".format(where, key))
    if src["kind"] not in SOURCE_KINDS:
        problems.append("{0}.kind: unknown kind {1!r}".format(where, src["kind"]))
    if not isinstance(src["public"], bool):
        problems.append("{0}.public: must be true or false".format(where))
    if src["section"] is not None and not (isinstance(src["section"], str) and re.fullmatch(r"[1-9][0-9]?", src["section"])):
        problems.append("{0}.section: must be a section number or null".format(where))
    if src["sha256_at_wp0"] is not None and not (isinstance(src["sha256_at_wp0"], str) and _SHA64.match(src["sha256_at_wp0"])):
        problems.append("{0}.sha256_at_wp0: must be 64 lowercase hex or null".format(where))
    if src["kind"] == "pre_fixed_criterion":
        problems += _check_committed_source(src, where)
        if src["coverage"] not in SOURCE_COVERAGE:
            problems.append("{0}.coverage: must be one of {1}".format(where, sorted(SOURCE_COVERAGE)))
    elif src["commit"] is not None or src["verified_commits"] or src["blob_ids"] or src["coverage"] is not None:
        problems.append("{0}: a {1} source is not a committed criterion; commit must be null and no commits listed".format(where, src["kind"]))
    return problems


def _check_committed_source(src: Dict[str, Any], where: str) -> List[str]:
    problems = []
    if not (isinstance(src["commit"], str) and _SHA40.match(src["commit"])):
        problems.append("{0}.commit: source commit SHA must be 40 lowercase hex".format(where))
    verified = src["verified_commits"]
    blobs = src["blob_ids"]
    if not isinstance(verified, list) or not verified or not all(isinstance(c, str) and _SHA40.match(c) for c in verified):
        problems.append("{0}.verified_commits: must list 40-hex commit SHAs".format(where))
        return problems
    if src["commit"] not in verified:
        problems.append("{0}.verified_commits: must include the source commit".format(where))
    if not isinstance(blobs, dict) or set(blobs) != set(verified) or not all(isinstance(b, str) and _SHA40.match(b) for b in blobs.values()):
        problems.append("{0}.blob_ids: must give one 40-hex blob id per verified commit".format(where))
    if not src["section"]:
        problems.append("{0}.section: a pre-fixed criterion names its section".format(where))
    return problems


def _check_evaluator(ev: Any) -> List[str]:
    problems = _keys(ev, EVALUATOR_KEYS, "historical_evaluator")
    if problems:
        return problems
    for key in ("helper_path", "version_at_evidence_time", "reason"):
        problems += _text(ev[key], "historical_evaluator." + key)
    if ev["public"] is not False:
        problems.append("historical_evaluator.public: the Phase 1 helper is not public")
    if not (isinstance(ev["sha256_at_wp0"], str) and _SHA64.match(ev["sha256_at_wp0"])):
        problems.append("historical_evaluator.sha256_at_wp0: must be 64 lowercase hex")
    return problems


def _check_test(test: Any, where: str) -> List[str]:
    problems = _keys(test, TEST_KEYS, where)
    if problems:
        return problems
    if not (isinstance(test["test_id"], str) and _TEST_ID.match(test["test_id"])):
        problems.append("{0}.test_id: must be tests/<path>.py::test_<name>".format(where))
    if test["kind"] not in TEST_KINDS:
        problems.append("{0}.kind: unknown kind {1!r}".format(where, test["kind"]))
    if test["status"] not in TEST_STATUSES:
        problems.append("{0}.status: unknown status {1!r}".format(where, test["status"]))
    elif test["status"] == "PLANNED" and test["planned_wp"] not in rules.PLANNED_WPS:
        problems.append("{0}.planned_wp: a planned test names its WP".format(where))
    elif test["status"] == "IMPLEMENTED" and test["planned_wp"] is not None:
        problems.append("{0}.planned_wp: must be null for an implemented test".format(where))
    return problems


def _check_expected(exp: Any, where: str) -> List[str]:
    problems = _keys(exp, EXPECTED_KEYS, where)
    if problems:
        return problems
    for key in sorted(EXPECTED_KEYS):
        if exp[key] not in DECISION_STATUSES:
            problems.append("{0}.{1}: unknown status {2!r}".format(where, key, exp[key]))
    if exp["evidence_missing"] != "NOT_PROVEN":
        problems.append("{0}.evidence_missing: missing evidence is always NOT_PROVEN (fail-closed)".format(where))
    if exp["violated"] == "PASS":
        problems.append("{0}.violated: a violation can never be PASS".format(where))
    return problems


def _check_historical(entries: Any, where: str, sources: Mapping[str, Dict[str, Any]]) -> List[str]:
    problems = _list(entries, where)
    if problems:
        return problems
    for i, h in enumerate(entries):
        w = "{0}[{1}]".format(where, i)
        p = _keys(h, HISTORICAL_KEYS, w)
        if p:
            problems += p
            continue
        problems += _text(h["subject"], w + ".subject") + _text(h["basis"], w + ".basis")
        if h["status"] not in HISTORICAL_STATUSES:
            problems.append("{0}.status: unknown status {1!r}".format(w, h["status"]))
        if h["basis_source_id"] not in sources:
            problems.append("{0}.basis_source_id: unknown source {1!r}".format(w, h["basis_source_id"]))
    return problems


def _check_criterion(c: Any, where: str, sources: Mapping[str, Dict[str, Any]]) -> List[str]:
    problems = _keys(c, CRITERION_KEYS, where)
    if problems:
        return problems
    if not (isinstance(c["criterion_id"], str) and _ID.match(c["criterion_id"])):
        problems.append("{0}.criterion_id: invalid id".format(where))
    problems += _text(c["criterion_text"], where + ".criterion_text")
    if c["origin"] not in CRITERION_ORIGINS:
        problems.append("{0}.origin: unknown origin {1!r}".format(where, c["origin"]))
    src = sources.get(c["source_id"])
    if src is None:
        problems.append("{0}.source_id: unknown source {1!r}".format(where, c["source_id"]))
    elif c["origin"] == "historical_text" and src["kind"] != "pre_fixed_criterion":
        problems.append("{0}: historical_text must quote a pre-fixed criterion source".format(where))
    elif c["origin"] == "phase2_added" and src["kind"] == "pre_fixed_criterion":
        problems.append("{0}: a phase2_added criterion cannot cite a pre-fixed criterion as its source".format(where))
    rule = c["evaluator_rule_id"]
    if not isinstance(rule, str) or not rule:
        problems.append("{0}.evaluator_rule_id: every criterion maps to a rule".format(where))
    elif rule not in rules.RULE_CATALOG:
        problems.append("{0}.evaluator_rule_id: rule {1!r} is not in the catalog".format(where, rule))
    p = _list(c["tests"], where + ".tests")
    problems += p or [x for i, t in enumerate(c["tests"]) for x in _check_test(t, "{0}.tests[{1}]".format(where, i))]
    if not p and not any(isinstance(t, dict) and t.get("kind") == "rule_behaviour" for t in c["tests"]):
        problems.append("{0}.tests: every criterion needs at least one rule_behaviour test (planned or implemented)".format(where))
    p = _list(c["required_evidence_types"], where + ".required_evidence_types")
    problems += p or ["{0}.required_evidence_types: unknown type {1!r}".format(where, t)
                      for t in c["required_evidence_types"] if t not in EVIDENCE_TYPES]
    if not p and len(set(c["required_evidence_types"])) != len(c["required_evidence_types"]):
        problems.append("{0}.required_evidence_types: duplicate type".format(where))
    problems += _check_expected(c["expected_result"], where + ".expected_result")
    problems += _check_historical(c["historical_classification"], where + ".historical_classification", sources)
    impl = c["historical_implementation"]
    p = _keys(impl, IMPLEMENTATION_KEYS, where + ".historical_implementation")
    if not p:
        if impl["alignment"] not in ALIGNMENTS:
            p.append("{0}.historical_implementation.alignment: unknown {1!r}".format(where, impl["alignment"]))
        if impl["helper_function"] is not None and not isinstance(impl["helper_function"], str):
            p.append("{0}.historical_implementation.helper_function: string or null".format(where))
        p += _text(impl["audit_ref"], where + ".historical_implementation.audit_ref")
    return problems + p


def _check_ac(ac: Any, index: int, sources: Mapping[str, Dict[str, Any]]) -> List[str]:
    where = "acceptance_criteria[{0}]".format(index)
    problems = _keys(ac, AC_KEYS, where)
    if problems:
        return problems
    if not (isinstance(ac["ac_id"], str) and _ID.match(ac["ac_id"])):
        problems.append("{0}.ac_id: invalid id".format(where))
    if ac["axis"] not in AXES:
        problems.append("{0}.axis: unknown axis {1!r}".format(where, ac["axis"]))
    problems += _text(ac["title"], where + ".title")
    problems += _list(ac["phase1_ac_refs"], where + ".phase1_ac_refs", allow_empty=True)
    p = _list(ac["historical_source_text"], where + ".historical_source_text", allow_empty=True)
    problems += p or [x for i, t in enumerate(ac["historical_source_text"])
                      for x in _source_text(t, "{0}.historical_source_text[{1}]".format(where, i), SOURCE_TEXT_KEYS, sources)]
    p = _list(ac["criteria"], where + ".criteria")
    problems += p or [x for i, c in enumerate(ac["criteria"]) for x in _check_criterion(c, "{0}.criteria[{1}]".format(where, i), sources)]
    return problems


def _source_text(t: Any, where: str, keys: FrozenSet[str], sources: Mapping[str, Dict[str, Any]]) -> List[str]:
    problems = _keys(t, keys, where)
    if problems:
        return problems
    problems += _text(t["text"], where + ".text")
    src = sources.get(t["source_id"])
    if src is None or src["kind"] != "pre_fixed_criterion":
        problems.append("{0}.source_id: must name a pre-fixed criterion source".format(where))
    if "reason" in keys:
        problems += _text(t["reason"], where + ".reason")
    return problems


# ---------------------------------------------------------------------------
# Cross-field checks
# ---------------------------------------------------------------------------


def _duplicates(values: Iterable[Any]) -> List[Any]:
    seen, dup = set(), []
    for v in values:
        if v in seen and v not in dup:
            dup.append(v)
        seen.add(v)
    return dup


def _iter_criteria(doc: Mapping[str, Any]) -> Iterable[Tuple[Dict[str, Any], Dict[str, Any]]]:
    for ac in doc.get("acceptance_criteria") or []:
        if isinstance(ac, dict):
            for c in ac.get("criteria") or []:
                if isinstance(c, dict):
                    yield ac, c


def _check_ids(doc: Mapping[str, Any]) -> List[str]:
    acs = [ac.get("ac_id") for ac in doc.get("acceptance_criteria") or [] if isinstance(ac, dict)]
    crits = [c.get("criterion_id") for _, c in _iter_criteria(doc)]
    srcs = [s.get("source_id") for s in doc.get("historical_sources") or [] if isinstance(s, dict)]
    problems = ["duplicate AC ID {0!r}".format(d) for d in _duplicates(acs)]
    problems += ["duplicate criterion ID {0!r}".format(d) for d in _duplicates(crits)]
    problems += ["duplicate source ID {0!r}".format(d) for d in _duplicates(srcs)]
    return problems


def _check_rule_mapping(doc: Mapping[str, Any]) -> List[str]:
    """Every catalog rule is used by a criterion, and a rule is used within a single axis."""
    used: Dict[str, set] = {}
    for ac, c in _iter_criteria(doc):
        if isinstance(c.get("evaluator_rule_id"), str):
            used.setdefault(c["evaluator_rule_id"], set()).add(ac.get("axis"))
    problems = ["rule {0!r} in the catalog has no criterion".format(r) for r in sorted(rules.RULE_CATALOG) if r not in used]
    for _, c in _iter_criteria(doc):
        rule_id = c.get("evaluator_rule_id")
        spec = rules.RULE_CATALOG.get(rule_id) if isinstance(rule_id, str) else None
        behaviour = [t.get("status") for t in c.get("tests") or [] if isinstance(t, dict) and t.get("kind") == "rule_behaviour"]
        if spec is None or not behaviour:
            continue
        if spec.status == "IMPLEMENTED" and "IMPLEMENTED" not in behaviour:
            problems.append("{0}: rule {1} is IMPLEMENTED but none of its rule_behaviour tests is".format(c.get("criterion_id"), spec.rule_id))
        if spec.status == "PLANNED" and "IMPLEMENTED" in behaviour:
            problems.append("{0}: rule {1} is PLANNED but a rule_behaviour test is IMPLEMENTED".format(c.get("criterion_id"), spec.rule_id))
    problems += _check_reachable_outcomes(doc)
    problems += ["rule {0!r} is used on more than one axis {1}".format(r, sorted(map(str, a))) for r, a in sorted(used.items()) if len(a) > 1]
    return problems + ["rule catalog: " + p for p in rules.catalog_problems()]


def _check_reachable_outcomes(doc: Mapping[str, Any]) -> List[str]:
    """The statuses an expected_result names are exactly those its rule can reach (rules.RuleSpec.outcomes).
    A value the rule never produces (e.g. violated = FAILED for a limit) and an outcome the Definition does not
    name are both refused."""
    problems: List[str] = []
    for _, c in _iter_criteria(doc):
        rule_id, exp = c.get("evaluator_rule_id"), c.get("expected_result")
        spec = rules.RULE_CATALOG.get(rule_id) if isinstance(rule_id, str) else None
        if spec is None or not isinstance(exp, dict) or set(exp) != set(EXPECTED_KEYS):
            continue
        named = {v for v in exp.values() if isinstance(v, str)}
        unreachable = sorted(named - spec.outcomes)
        unnamed = sorted(spec.outcomes - named)
        if unreachable:
            problems.append("{0}.expected_result: rule {1} can never produce {2}".format(c.get("criterion_id"), spec.rule_id, unreachable))
        if unnamed:
            problems.append("{0}.expected_result: rule {1} can produce {2}, which the Definition does not name".format(
                c.get("criterion_id"), spec.rule_id, unnamed))
    return problems


def _check_axes(doc: Mapping[str, Any], required: Sequence[str]) -> List[str]:
    present = {ac.get("axis") for ac in doc.get("acceptance_criteria") or [] if isinstance(ac, dict)}
    return ["required axis {0!r} has no acceptance criterion".format(a) for a in required if a not in present]


def _check_locked(doc: Mapping[str, Any], lock: Mapping[str, Any]) -> List[str]:
    problems: List[str] = []
    entries = doc.get("phase1_locked_classifications")
    if not isinstance(entries, list):
        return ["phase1_locked_classifications: must be a list"]
    got = set()
    for i, e in enumerate(entries):
        p = _keys(e, LOCK_KEYS, "phase1_locked_classifications[{0}]".format(i))
        if p:
            problems += p
            continue
        got.add((e["subject"], e["axis"], e["status"]))
    if len(got) != len(entries):
        problems.append("phase1_locked_classifications: duplicate entry")
    if got != set(lock["classifications"]):
        problems.append("phase1_locked_classifications differ from the Phase 1 final acceptance: missing {0}, unexpected {1}".format(
            sorted(set(lock["classifications"]) - got), sorted(got - set(lock["classifications"]))))
    by_subject_axis = {(s, a): st for s, a, st in lock["classifications"]}
    for ac, c in _iter_criteria(doc):
        for h in c.get("historical_classification") or []:
            if isinstance(h, dict):
                want = by_subject_axis.get((h.get("subject"), ac.get("axis")))
                if want is not None and h.get("status") != want:
                    problems.append("{0}: historical {1} on {2} is {3!r}, Phase 1 fixed it as {4!r}".format(
                        c.get("criterion_id"), h.get("subject"), ac.get("axis"), h.get("status"), want))
    return problems


def _check_final(doc: Mapping[str, Any], lock: Mapping[str, Any], sources: Mapping[str, Dict[str, Any]]) -> List[str]:
    final: Any = doc.get("phase1_final_results")
    problems = _keys(final, FINAL_KEYS, "phase1_final_results")
    if problems:
        return problems
    if final["scenarios"] != dict(lock["scenarios"]):
        problems.append("phase1_final_results.scenarios differ from the Phase 1 final scenario results")
    counts: Dict[str, int] = {}
    for status in (final["scenarios"] or {}).values() if isinstance(final["scenarios"], dict) else ():
        counts[status] = counts.get(status, 0) + 1
    if final["scenario_counts"] != counts:
        problems.append("phase1_final_results.scenario_counts do not match the scenarios")
    if final["ac_rev3_counts"] != dict(lock["ac_rev3_counts"]):
        problems.append("phase1_final_results.ac_rev3_counts differ from AC Traceability rev3")
    ids = final["basis_source_ids"]
    if not isinstance(ids, list) or not ids or any(i not in sources for i in ids):
        problems.append("phase1_final_results.basis_source_ids: must name known sources")
    return problems


def _check_name_and_version(doc: Mapping[str, Any], file_name: Optional[str]) -> List[str]:
    problems: List[str] = []
    did, ver = doc.get("definition_id"), doc.get("definition_version")
    entry = DEFINITION_INDEX.get(did) if isinstance(did, str) else None
    if entry is None:
        return ["definition_id {0!r} is not in the registry index".format(did)]
    problems += _int(ver, "definition_version")
    if ver != entry["version"]:
        problems.append("definition_version {0!r} does not match the registry index version {1}".format(ver, entry["version"]))
    if file_name is not None:
        m = _FILE_NAME.match(file_name)
        if not m or m.group(1) != did or int(m.group(2)) != ver:
            problems.append("file name {0!r} does not match definition {1!r} version {2!r} (<id>.v<version>.json)".format(file_name, did, ver))
    return problems


def validate_definition(doc: Any, file_name: Optional[str] = None) -> List[str]:
    """Every problem with ``doc``; empty means valid. Does not touch the filesystem or git."""
    problems = _keys(doc, TOP_KEYS, "definition")
    if problems:
        return problems
    if doc["schema_version"] != SCHEMA_VERSION or isinstance(doc["schema_version"], bool):
        problems.append("schema_version must be {0}".format(SCHEMA_VERSION))
    problems += _check_name_and_version(doc, file_name)
    problems += _text(doc["title"], "title") + _text(doc["purpose"], "purpose")
    problems += _check_origin(doc["machine_readable_origin"])
    p = _list(doc["historical_sources"], "historical_sources")
    problems += p or [x for i, s in enumerate(doc["historical_sources"]) for x in _check_source(s, i)]
    sources = {s["source_id"]: s for s in doc["historical_sources"] or [] if isinstance(s, dict) and "source_id" in s
               and "kind" in s} if not p else {}
    problems += _check_evaluator(doc["historical_evaluator"])
    p = _list(doc["acceptance_criteria"], "acceptance_criteria")
    problems += p or [x for i, ac in enumerate(doc["acceptance_criteria"]) for x in _check_ac(ac, i, sources)]
    p = _list(doc["non_normative_text"], "non_normative_text", allow_empty=True)
    problems += p or [x for i, t in enumerate(doc["non_normative_text"])
                      for x in _source_text(t, "non_normative_text[{0}]".format(i), NON_NORMATIVE_KEYS, sources)]
    problems += _check_ids(doc)
    problems += _check_rule_mapping(doc)
    entry = DEFINITION_INDEX.get(doc["definition_id"]) if isinstance(doc["definition_id"], str) else None
    if entry is not None:
        problems += _check_axes(doc, entry["required_axes"])
    lock = PHASE1_LOCKED.get(doc["definition_id"]) if isinstance(doc["definition_id"], str) else None
    if lock is not None:
        problems += _check_locked(doc, lock)
        problems += _check_final(doc, lock, sources)
        ev = doc["historical_evaluator"]
        if isinstance(ev, dict) and ev.get("version_at_evidence_time") != lock["historical_evaluator_version"]:
            problems.append("historical_evaluator.version_at_evidence_time must stay {0!r}".format(lock["historical_evaluator_version"]))
    return problems


# ---------------------------------------------------------------------------
# Filesystem checks: tests and source text
# ---------------------------------------------------------------------------


def _test_functions(path: Path) -> Optional[set]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return None
    return {n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def check_test_references(doc: Mapping[str, Any], repo_root: Path) -> List[str]:
    """IMPLEMENTED tests must exist as a top-level function; PLANNED tests must not exist yet.

    Existence is all this shows. Whether a test passes is shown only by running it.
    """
    problems: List[str] = []
    cache: Dict[str, Optional[set]] = {}
    found: Optional[set]
    for _, c in _iter_criteria(doc):
        for t in c.get("tests") or []:
            m = _TEST_ID.match(str(t.get("test_id"))) if isinstance(t, dict) else None
            if not m:
                continue
            rel, name = m.group(1), m.group(2)
            if rel not in cache:
                path = repo_root / rel
                cache[rel] = _test_functions(path) if path.is_file() else None
            found = cache[rel]
            exists = found is not None and name in found
            if t.get("status") == "IMPLEMENTED" and not exists:
                problems.append("{0}: test {1} is marked IMPLEMENTED but does not exist".format(c.get("criterion_id"), t["test_id"]))
            if t.get("status") == "PLANNED" and exists:
                problems.append("{0}: test {1} exists but is marked PLANNED".format(c.get("criterion_id"), t["test_id"]))
    return problems


def extract_section(markdown: str, number: str) -> Optional[str]:
    """The text of ``## <number>. ...`` up to the next ``## `` heading; None if absent or ambiguous."""
    lines = markdown.split("\n")
    starts = [i for i, ln in enumerate(lines) if ln.startswith("## {0}. ".format(number))]
    if len(starts) != 1:
        return None
    end = next((i for i in range(starts[0] + 1, len(lines)) if lines[i].startswith("## ")), len(lines))
    return "\n".join(lines[starts[0]:end])


def git_blob_id(data: bytes) -> str:
    """The git (SHA-1) blob id of ``data``."""
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()  # noqa: S324 - git object id, not a security hash


#: Characters a section may keep outside every quoted clause: whitespace and Markdown structure.
_RESIDUE_ALLOWED = frozenset(" \t\n|-*;,.:")


def clause_problems(doc: Mapping[str, Any], sections: Mapping[str, str], complete: Optional[Iterable[str]] = None) -> List[str]:
    """Each quoted text occurs exactly once in its section and spans do not overlap.

    ``sections`` maps source_id to that source's section text. For the source ids in ``complete``
    (default: every source whose ``coverage`` is ``complete``), nothing normative may be left unquoted.
    """
    if complete is None:
        complete = [str(s.get("source_id")) for s in doc.get("historical_sources") or [] if isinstance(s, dict) and s.get("coverage") == "complete"]
    complete = set(complete)
    problems: List[str] = []
    spans: Dict[str, List[Tuple[int, int, str]]] = {sid: [] for sid in sections}
    quoted: List[Tuple[Any, Any, str]] = []
    for _, c in _iter_criteria(doc):
        if c.get("origin") == "historical_text":
            quoted.append((c.get("source_id"), c.get("criterion_text"), "criterion " + str(c.get("criterion_id"))))
    for ac in doc.get("acceptance_criteria") or []:
        for t in ac.get("historical_source_text") or []:
            quoted.append((t.get("source_id"), t.get("text"), "source column of " + str(ac.get("ac_id"))))
    for t in doc.get("non_normative_text") or []:
        quoted.append((t.get("source_id"), t.get("text"), "non-normative text"))
    for sid, text, what in quoted:
        section = sections.get(sid)
        if section is None:
            problems.append("{0}: section of source {1!r} not provided".format(what, sid))
            continue
        count = section.count(text) if isinstance(text, str) and text else 0
        if count != 1:
            problems.append("{0}: occurs {1} times in source {2!r} (must be exactly once)".format(what, count, sid))
            continue
        start = section.index(text)
        spans[sid].append((start, start + len(text), what))
    for sid, items in spans.items():
        items.sort()
        for (s1, e1, w1), (s2, e2, w2) in zip(items, items[1:]):
            if s2 < e1:
                problems.append("{0} overlaps {1} in source {2!r}".format(w1, w2, sid))
        if sid not in complete:
            continue
        covered = [False] * len(sections[sid])
        for s, e, _ in items:
            for i in range(s, e):
                covered[i] = True
        residue = "".join(ch for ch, cov in zip(sections[sid], covered) if not cov)
        stray = "".join(sorted({ch for ch in residue if ch not in _RESIDUE_ALLOWED}))
        if stray:
            left = " ".join("".join(ch if not cov else "\0" for ch, cov in zip(sections[sid], covered)).replace("\0", " ").split())
            problems.append("source {0!r}: text not covered by any criterion or non-normative entry: {1!r}".format(sid, left[:200]))
    return problems


def worktree_sections(doc: Mapping[str, Any], repo_root: Path) -> Tuple[Dict[str, str], List[str]]:
    """Sections of every pre-fixed source, read from the working tree.

    The file is used only if its git blob id equals the blob of one of the source's verified commits,
    so the text checked is byte-identical to a committed version. Otherwise it is a problem.
    """
    sections: Dict[str, str] = {}
    problems: List[str] = []
    for src in doc.get("historical_sources") or []:
        if not isinstance(src, dict) or src.get("kind") != "pre_fixed_criterion":
            continue
        path = repo_root / str(src.get("path"))
        try:
            data = path.read_bytes()
        except OSError:
            problems.append("source {0!r}: {1} cannot be read".format(src.get("source_id"), src.get("path")))
            continue
        if git_blob_id(data) not in set((src.get("blob_ids") or {}).values()):
            problems.append("source {0!r}: {1} differs from every verified commit".format(src.get("source_id"), src.get("path")))
            continue
        section = extract_section(data.decode("utf-8"), str(src.get("section")))
        if section is None:
            problems.append("source {0!r}: section {1} not found exactly once".format(src.get("source_id"), src.get("section")))
            continue
        sections[str(src["source_id"])] = section
    return sections, problems


Runner = Callable[[List[str]], Tuple[Optional[int], bytes]]


def _default_runner(argv: List[str]) -> Tuple[Optional[int], bytes]:
    from iacreview import proc  # local import: only the git cross-check needs a subprocess

    result = proc.run_bounded(argv, timeout_s=30, max_output_bytes=8 * 1024 * 1024)
    if result.timed_out or result.output_exceeded:
        return None, b""
    return result.exit_code, result.stdout


def git_source_problems(doc: Mapping[str, Any], repo_root: Path, runner: Optional[Runner] = None) -> Tuple[List[str], List[str]]:
    """Cross-check against git history: (problems, commits not available locally).

    For each verified commit: the recorded blob id is the file's blob at that commit, the section exists,
    and every quoted text occurs exactly once in it. A commit missing from the local history (a shallow
    clone) is returned separately, never counted as verified.
    """
    run = runner or _default_runner
    problems: List[str] = []
    unavailable: List[str] = []
    for src in doc.get("historical_sources") or []:
        if not isinstance(src, dict) or src.get("kind") != "pre_fixed_criterion":
            continue
        sid = str(src.get("source_id"))
        for commit in src.get("verified_commits") or []:
            code, out = run(["git", "-C", str(repo_root), "cat-file", "-e", "{0}^{{commit}}".format(commit)])
            if code != 0:
                unavailable.append(commit)
                continue
            code, out = run(["git", "-C", str(repo_root), "rev-parse", "{0}:{1}".format(commit, src.get("path"))])
            if code != 0 or out.decode("ascii", "replace").strip() != (src.get("blob_ids") or {}).get(commit):
                problems.append("source {0!r}: blob of {1} at {2} is not the recorded one".format(sid, src.get("path"), commit[:12]))
                continue
            code, out = run(["git", "-C", str(repo_root), "show", "{0}:{1}".format(commit, src.get("path"))])
            section = extract_section(out.decode("utf-8", "replace"), str(src.get("section"))) if code == 0 else None
            if section is None:
                problems.append("source {0!r}: section {1} not readable at {2}".format(sid, src.get("section"), commit[:12]))
                continue
            complete = [sid] if src.get("coverage") == "complete" else []
            problems += ["{0} @ {1}".format(p, commit[:12]) for p in clause_problems(_only_source(doc, sid), {sid: section}, complete)]
    return problems, unavailable


def _only_source(doc: Mapping[str, Any], sid: str) -> Dict[str, Any]:
    """``doc`` reduced to the quoted texts of one source (for a per-source clause check)."""
    acs = []
    for ac in doc.get("acceptance_criteria") or []:
        acs.append({"ac_id": ac.get("ac_id"),
                    "criteria": [c for c in ac.get("criteria") or [] if c.get("origin") == "historical_text" and c.get("source_id") == sid],
                    "historical_source_text": [t for t in ac.get("historical_source_text") or [] if t.get("source_id") == sid]})
    return {"acceptance_criteria": acs, "non_normative_text": [t for t in doc.get("non_normative_text") or [] if t.get("source_id") == sid]}


# ---------------------------------------------------------------------------
# Loading and coverage
# ---------------------------------------------------------------------------


def load_definition(path: Path, repo_root: Optional[Path] = None) -> Dict[str, Any]:
    """Load and validate one Definition file. With ``repo_root``, also check test references and source text.

    Raises RegistryError with every problem found.
    """
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise RegistryError(["cannot read {0}: {1}".format(path.name, exc.strerror)]) from None
    doc = parse_definition_bytes(data)
    problems = validate_definition(doc, path.name)
    if not problems and repo_root is not None:
        problems += check_test_references(doc, repo_root)
        sections, p = worktree_sections(doc, repo_root)
        problems += p or clause_problems(doc, sections)
    if problems:
        raise RegistryError(problems)
    return doc


def definition_files(directory: Path = DEFINITIONS_DIR) -> List[Path]:
    """Every ``*.json`` under ``directory``, sorted."""
    return sorted(p for p in directory.glob("*.json") if p.is_file())


def coverage(doc: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """One row per criterion with every registry field and the separate rule / test status.

    ``proven`` is always False: a registry row is a plan of how a criterion is judged, not a result.
    """
    sources = {s["source_id"]: s for s in doc["historical_sources"]}
    rows = []
    for ac, c in _iter_criteria(doc):
        spec = rules.RULE_CATALOG.get(c["evaluator_rule_id"])
        src = sources[c["source_id"]]
        rows.append({
            "ac_id": ac["ac_id"], "axis": ac["axis"], "criterion_id": c["criterion_id"], "criterion_text": c["criterion_text"],
            "origin": c["origin"], "definition_id": doc["definition_id"], "definition_version": doc["definition_version"],
            "definition_source": src["path"], "source_commit": src["commit"], "evaluator_rule_id": c["evaluator_rule_id"],
            "rule_status": spec.status if spec else "UNKNOWN", "rule_planned_wp": spec.planned_wp if spec else None,
            "test_ids": [t["test_id"] for t in c["tests"]],
            "rule_test_statuses": sorted({t["status"] for t in c["tests"] if t["kind"] == "rule_behaviour"}),
            "fidelity_test_statuses": sorted({t["status"] for t in c["tests"] if t["kind"] == "definition_fidelity"}),
            "required_evidence_types": list(c["required_evidence_types"]), "expected_result": dict(c["expected_result"]),
            "historical_classification": [dict(h) for h in c["historical_classification"]],
            "historical_alignment": c["historical_implementation"]["alignment"], "proven": False,
        })
    return rows
