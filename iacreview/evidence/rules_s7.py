"""Evaluator rules for ``docs/v2/phase1/app-demo-plan.md`` §6-§7 (Phase 2 M1 WP4-2, WP4-3).

Source: the clauses quoted in ``definitions/phase1-app-demo-s7.v1.json`` (S7-02 ... S7-18, S6-G3/G3S/G6,
P2-IP-01), WP0 ``acceptance-alignment-audit.md`` §3 (where the Phase 1 helper diverged). Purpose: one pure
function per rule id, each deciding PASS / FAILED / NOT_PROVEN from normalized *facts* only
(:mod:`iacreview.evidence.facts`), so that native raw evidence and legacy derived evidence are judged by the
same code.

Fixed rules of this module:

* missing evidence is NOT_PROVEN, never PASS (a fact that is ``None`` is missing)
* a confirmed violation is FAILED; it is never offset by another part's PASS
* an impostor (same-named context not from the App) with ``isRequired = true`` makes S7-08, S7-14a, S7-15
  and the S6 row FAILED, whatever the merge state (WP0 alignment audit §3-1)
* BLOCKED that an App failure on the same head explains is not an independent issuer-pinning proof (P2-IP-01)
* the origin of a check run is the App id from the REST check run of the same id; GraphQL ``app`` may be null
  for a private App. A same-named check run known to neither is ``unknown`` and makes origin-based rules
  NOT_PROVEN
* Phase 1 historical classifications are never read here
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

CHECK_NAME = "remediation-gate/verified"
GATE_PATH = ".github/workflows/remediation-gate.yml"
VERIFY_STEP = "Verify the candidate against the approved contract"
DERIVE_STEP = "Derive the outputs from the report"
GATE_DECISION_FAIL_STEPS = sorted([VERIFY_STEP, DERIVE_STEP])
TOKEN_PERMISSIONS = ["Contents: read", "Metadata: read"]
#: Pins named by S7-03 (short commit ids as written in the criterion).
VALIDATOR_PIN = "5412a73"
GATE_SCRIPTS_PIN = "f77a58c"
MERGEABLE_STATES = ("CLEAN", "UNSTABLE", "HAS_HOOKS")
_EXTERNAL_ID = re.compile(r"([0-9]+)\.([0-9]+):([0-9a-f]{64})")

#: §6 table (fixed before any run): expected App conclusion and merge state per scenario.
SCENARIO_EXPECTATIONS: Mapping[str, Tuple[str, str]] = {
    "G0": ("success", "mergeable"), "G9": ("failure", "mergeable_then_blocked"), "G1": ("success", "clean"),
    "G2": ("failure", "blocked"), "G3": ("failure", "blocked"), "G3S": ("failure", "blocked"), "G4": ("failure", "blocked"),
    "G5": ("failure", "blocked"), "G6": ("failure", "blocked"), "G10": ("failure", "blocked"), "G11": ("failure", "blocked"),
}
#: §6 Impostors column for the spoof scenarios: (context kind, impostor state).
SPOOF_IMPOSTOR: Mapping[str, Tuple[str, str]] = {"G3": ("check_run", "success"), "G3S": ("status", "success"), "G6": ("check_run", "skipped")}
SPOOF_SCENARIOS = tuple(sorted(SPOOF_IMPOSTOR))


@dataclass(frozen=True)
class Outcome:
    status: str  # PASS, FAILED, NOT_PROVEN
    reason_code: str


def PASS(reason: str) -> Outcome:
    return Outcome("PASS", reason)


def FAILED(reason: str) -> Outcome:
    return Outcome("FAILED", reason)


def MISSING(reason: str) -> Outcome:
    return Outcome("NOT_PROVEN", reason)


Facts = Mapping[str, Any]


# ---------------------------------------------------------------------------
# Context origins
# ---------------------------------------------------------------------------


def resolve_contexts(facts: Facts) -> Optional[List[Dict[str, Any]]]:
    """Same-named contexts with ``origin`` (app / other_app / commit_status / unknown); None if not observable."""
    contexts, rest = facts.get("contexts"), facts.get("rest_checks")
    if contexts is None or rest is None:
        return None
    app_id = facts.get("app_id")
    by_id = {c.get("check_run_id"): c for c in rest if c.get("check_run_id") is not None}
    out = []
    for c in contexts:
        if c.get("name") != CHECK_NAME:
            continue
        r = dict(c)
        if c.get("kind") == "status":
            r["origin"] = "commit_status"
        elif c.get("check_run_id") in by_id:
            rest_app = by_id[c["check_run_id"]].get("app_id")
            r["origin"] = "app" if rest_app == app_id else "other_app"
            r["state"] = by_id[c["check_run_id"]].get("conclusion") or r.get("state")
        elif c.get("graphql_app_id") is not None:
            r["origin"] = "app" if c["graphql_app_id"] == app_id else "other_app"
        else:
            r["origin"] = "unknown"
        out.append(r)
    return out


def _split(facts: Facts) -> Optional[Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]]:
    ctx = resolve_contexts(facts)
    if ctx is None:
        return None
    app = [c for c in ctx if c["origin"] == "app"]
    impostors = [c for c in ctx if c["origin"] in ("other_app", "commit_status")]
    unknown = [c for c in ctx if c["origin"] == "unknown"]
    return app, impostors, unknown


# ---------------------------------------------------------------------------
# Required check / isRequired  (S7-08, S7-09, S7-14a, S7-15, S6 rows)
# ---------------------------------------------------------------------------


def impostor_not_required(facts: Facts, scenario: str) -> Outcome:
    """S7-08: every same-named check run or status not from the App has isRequired = false."""
    split = _split(facts)
    if split is None:
        return MISSING("rollup_or_check_source_missing")
    _, impostors, unknown = split
    if any(c.get("is_required") is True for c in impostors):
        return FAILED("impostor_is_required")
    if unknown:
        return MISSING("context_origin_unknown")
    if any(c.get("is_required") is None for c in impostors):
        return MISSING("impostor_is_required_missing")
    return PASS("impostors_not_required" if impostors else "no_impostor_present")


def app_check_required(facts: Facts, scenario: str) -> Outcome:
    """S7-09: the App's check has isRequired = true."""
    split = _split(facts)
    if split is None:
        return MISSING("rollup_or_check_source_missing")
    app, _, unknown = split
    if len(app) != 1:
        return MISSING("app_check_not_unique_in_rollup" if app else ("context_origin_unknown" if unknown else "app_check_absent"))
    value = app[0].get("is_required")
    if value is True:
        return PASS("app_check_required")
    if value is False:
        return FAILED("app_check_not_required")
    return MISSING("app_is_required_missing")


def same_name_other_source(facts: Facts, scenario: str) -> Outcome:
    """S7-14a: the impostor exists on the head with isRequired = false, and the App's check is the required one."""
    split = _split(facts)
    if split is None:
        return MISSING("rollup_or_check_source_missing")
    app, impostors, unknown = split
    if any(c.get("is_required") is True for c in impostors):
        return FAILED("impostor_is_required")
    if unknown:
        return MISSING("context_origin_unknown")
    if not impostors:
        return MISSING("impostor_not_observed")
    if len(app) == 1 and app[0].get("is_required") is False:
        return FAILED("app_check_not_required")
    if any(c.get("is_required") is None for c in impostors) or len(app) != 1 or app[0].get("is_required") is None:
        return MISSING("is_required_missing")
    return PASS("impostor_present_not_required_app_required")


def impostor_required_fails_scenario(facts: Facts, scenario: str) -> Outcome:
    """S7-15: if GitHub reports isRequired = true for an impostor, the scenario is FAILED."""
    split = _split(facts)
    if split is None:
        return MISSING("rollup_or_check_source_missing")
    _, impostors, unknown = split
    if any(c.get("is_required") is True for c in impostors):
        return FAILED("impostor_is_required")
    if unknown:
        return MISSING("context_origin_unknown")
    if not impostors:
        return MISSING("impostor_not_observed")
    if any(c.get("is_required") is None for c in impostors):
        return MISSING("impostor_is_required_missing")
    return PASS("no_impostor_required")


def s6_impostor_not_required(facts: Facts, scenario: str) -> Outcome:
    """S6 row of G3 / G3S / G6: the scenario's own impostor (kind and state from §6) is present and not required."""
    if scenario not in SPOOF_IMPOSTOR:
        return MISSING("not_a_spoof_scenario")
    kind, state = SPOOF_IMPOSTOR[scenario]
    split = _split(facts)
    if split is None:
        return MISSING("rollup_or_check_source_missing")
    _, impostors, unknown = split
    wanted = [c for c in impostors if c.get("kind") == kind and str(c.get("state")).lower() == state]
    if any(c.get("is_required") is True for c in wanted):
        return FAILED("impostor_is_required")
    if not wanted:
        return MISSING("context_origin_unknown" if unknown else "expected_impostor_not_observed")
    if any(c.get("is_required") is None for c in wanted):
        return MISSING("impostor_is_required_missing")
    return PASS("expected_impostor_not_required")


# ---------------------------------------------------------------------------
# Merge blocking (S7-10, S7-14b)
# ---------------------------------------------------------------------------


def merge_state_as_expected(facts: Facts, scenario: str) -> Outcome:
    """S7-10: merge state as expected (§6)."""
    if scenario not in SCENARIO_EXPECTATIONS:
        return MISSING("no_expectation")
    want = SCENARIO_EXPECTATIONS[scenario][1]
    merge, mergeable = facts.get("merge_state"), facts.get("mergeable")
    if want == "mergeable":
        if mergeable is None:
            return MISSING("merge_state_missing")
        if mergeable == "MERGEABLE":
            return PASS("mergeable")
        return FAILED("not_mergeable_without_ruleset") if mergeable == "CONFLICTING" or merge == "BLOCKED" else MISSING("mergeability_unsettled")
    if want == "mergeable_then_blocked":
        before = facts.get("mergeable_before_ruleset")
        if before is None or merge is None:
            return MISSING("merge_state_missing")
        if before != "MERGEABLE":
            return MISSING("not_mergeable_before_ruleset")
        return _blocked(merge, mergeable)
    if merge is None:
        return MISSING("merge_state_missing")
    if want == "clean":
        if merge == "CLEAN":
            return PASS("clean")
        return FAILED("correct_change_blocked") if merge == "BLOCKED" else MISSING("merge_state_unsettled")
    return _blocked(merge, mergeable)


def _blocked(merge: Any, mergeable: Any) -> Outcome:
    if merge == "BLOCKED":
        return PASS("blocked")
    if merge in MERGEABLE_STATES:
        return FAILED("prohibited_change_mergeable")
    return MISSING("merge_state_unsettled")


def spoof_scenario_blocked(facts: Facts, scenario: str) -> Outcome:
    """S7-14b: the merge state is BLOCKED (G3 / G3S / G6)."""
    merge = facts.get("merge_state")
    if merge is None:
        return MISSING("merge_state_missing")
    return _blocked(merge, facts.get("mergeable"))


# ---------------------------------------------------------------------------
# Issuer pinning (P2-IP-01, added in Phase 2)
# ---------------------------------------------------------------------------


def issuer_pinning_independent(facts: Facts, scenario: str) -> Outcome:
    """P2-IP-01: an impostor is shown not to satisfy the rule on a head where the App check does not explain the state."""
    split = _split(facts)
    if split is None:
        return MISSING("rollup_or_check_source_missing")
    app, impostors, unknown = split
    if unknown:
        return MISSING("context_origin_unknown")
    passing = [c for c in impostors if str(c.get("state")).lower() in ("success", "skipped", "neutral")]
    if not passing:
        return MISSING("no_passing_impostor")
    app_states = [str(c.get("state")).lower() for c in app]
    if "failure" in app_states:
        return MISSING("app_failure_explains_block")
    if facts.get("rules_main") is None:
        return MISSING("effective_rules_missing")
    merge = facts.get("merge_state")
    if merge is None:
        return MISSING("merge_state_missing")
    if merge == "BLOCKED" and not app:
        return PASS("blocked_with_only_an_impostor")
    if merge in MERGEABLE_STATES and not app:
        return FAILED("impostor_satisfied_the_rule")
    return MISSING("app_check_present_or_state_unsettled")


# ---------------------------------------------------------------------------
# Gate provenance (S7-03, S7-03b)
# ---------------------------------------------------------------------------


def select_gate_run(facts: Facts) -> Optional[Mapping[str, Any]]:
    """The last completed gate run recorded on the PR head; None if the runs were not observed."""
    runs = facts.get("gate_runs")
    if runs is None:
        return None
    head = facts.get("head_sha")
    chosen = [r for r in runs if r.get("run_head_sha") == head and r.get("status") == "completed"]
    return chosen[-1] if chosen else {}


GATE_CONDITIONS = ("event", "workflow_path", "run_head_sha", "subject_is_base", "validator_pinned", "validator_checked_out",
                   "gate_scripts_pinned", "head_env_is_pr_head", "trusted_contract", "no_relaxed_contract", "token_permissions")


def gate_conditions(run: Mapping[str, Any], head: Optional[str]) -> Dict[str, Optional[bool]]:
    """Each S7-03 condition: True, False or None (fact missing — never defaulted)."""
    log = run.get("log") or {}

    def fact(key: str) -> Optional[bool]:
        v = log.get(key)
        return v if isinstance(v, bool) else None

    relaxed = fact("relaxed_contract")
    perms = log.get("token_permissions")
    return {
        "event": None if run.get("event") is None else run.get("event") == "pull_request_target",
        "workflow_path": None if run.get("workflow_path") is None else str(run["workflow_path"]).startswith(GATE_PATH),
        "run_head_sha": None if run.get("run_head_sha") is None or head is None else run["run_head_sha"] == head,
        "subject_is_base": fact("subject_is_base"), "validator_pinned": fact("validator_pinned"),
        "validator_checked_out": fact("validator_checked_out"), "gate_scripts_pinned": fact("gate_scripts_pinned"),
        "head_env_is_pr_head": fact("head_env_is_pr_head"), "trusted_contract": fact("trusted_contract"),
        "no_relaxed_contract": None if relaxed is None else not relaxed,
        "token_permissions": None if not isinstance(perms, list) else perms == TOKEN_PERMISSIONS,
    }


def base_gate_provenance(facts: Facts, scenario: str) -> Outcome:
    """S7-03: the run is the base gate (event, path, PR head, base checked out, pins, HEAD_SHA, trusted contract, token)."""
    run = select_gate_run(facts)
    if run is None:
        return MISSING("gate_runs_missing")
    if not run:
        return MISSING("no_completed_gate_run_on_head")
    conds = gate_conditions(run, facts.get("head_sha"))
    failed = [k for k in GATE_CONDITIONS if conds[k] is False]
    if failed:
        return FAILED("gate_condition_false:" + failed[0])
    missing = [k for k in GATE_CONDITIONS if conds[k] is None]
    if missing:
        return MISSING("gate_fact_missing:" + missing[0])
    return PASS("base_gate")


def verify_step_as_expected(facts: Facts, scenario: str) -> Outcome:
    """S7-03b: the verify step decided as §6 expects; the expected steps failed; the decision was published."""
    if scenario not in SCENARIO_EXPECTATIONS:
        return MISSING("no_expectation")
    run = select_gate_run(facts)
    if run is None:
        return MISSING("gate_runs_missing")
    if not run:
        return MISSING("no_completed_gate_run_on_head")
    want = SCENARIO_EXPECTATIONS[scenario][0]
    verify, failed, publish = run.get("verify_step"), run.get("failed_steps"), run.get("publish_job")
    if verify is None or failed is None:
        return MISSING("verify_step_missing")
    expected_failed = [] if want == "success" else GATE_DECISION_FAIL_STEPS
    if verify != want or sorted(failed) != expected_failed:
        return FAILED("verify_step_not_as_expected")
    if publish is None:
        return MISSING("publish_job_missing")
    if publish != "success":
        return FAILED("decision_not_published")
    return PASS("verify_step_as_expected")


# ---------------------------------------------------------------------------
# App check provenance (S7-04 ... S7-07)
# ---------------------------------------------------------------------------


def _app_checks(facts: Facts) -> Optional[List[Mapping[str, Any]]]:
    rest = facts.get("rest_checks")
    if rest is None:
        return None
    return [c for c in rest if c.get("name") == CHECK_NAME and c.get("app_id") == facts.get("app_id")]


def exactly_one_app_check(facts: Facts, scenario: str) -> Outcome:
    """S7-04: exactly one check named remediation-gate/verified from the App on the head."""
    checks = _app_checks(facts)
    if checks is None:
        return MISSING("check_runs_missing")
    on_head = [c for c in checks if c.get("head_sha") == facts.get("head_sha")]
    if len(on_head) == 1:
        return PASS("one_app_check")
    return FAILED("several_app_checks") if on_head else MISSING("app_check_absent")


def _the_app_check(facts: Facts) -> Optional[Mapping[str, Any]]:
    checks = _app_checks(facts) or []
    on_head = [c for c in checks if c.get("head_sha") == facts.get("head_sha")]
    return on_head[0] if len(on_head) == 1 else None


def external_id_names_gate_run(facts: Facts, scenario: str) -> Outcome:
    """S7-05: external_id <run>.<attempt>:<digest> names that gate run (a completed gate run on the head)."""
    if facts.get("rest_checks") is None or facts.get("gate_runs") is None:
        return MISSING("check_runs_or_gate_runs_missing")
    check = _the_app_check(facts)
    if check is None:
        return MISSING("app_check_not_unique")
    m = _EXTERNAL_ID.fullmatch(str(check.get("external_id") or ""))
    if not m:
        return FAILED("external_id_malformed")
    run = select_gate_run(facts) or {}
    if not run:
        return MISSING("no_completed_gate_run_on_head")
    if int(m.group(1)) != run.get("run_id") or int(m.group(2)) != run.get("run_attempt"):
        return FAILED("external_id_names_another_run")
    return PASS("external_id_names_gate_run")


def report_digest_matches(facts: Facts, scenario: str) -> Outcome:
    """S7-06: the downloaded report's recomputed digest equals the digest in external_id."""
    check = _the_app_check(facts)
    if check is None:
        return MISSING("app_check_not_unique")
    m = _EXTERNAL_ID.fullmatch(str(check.get("external_id") or ""))
    if not m:
        return MISSING("external_id_malformed")
    digests = facts.get("report_digests")
    if digests is None or int(m.group(1)) not in digests:
        return MISSING("report_artifact_missing")
    got = digests[int(m.group(1))]
    if got is None:
        return FAILED("report_payload_digest_inconsistent")
    return PASS("report_digest_matches") if got == m.group(3) else FAILED("report_digest_differs")


def conclusion_as_expected(facts: Facts, scenario: str) -> Outcome:
    """S7-07: the App check's conclusion is the §6 expectation."""
    if scenario not in SCENARIO_EXPECTATIONS:
        return MISSING("no_expectation")
    if facts.get("rest_checks") is None:
        return MISSING("check_runs_missing")
    check = _the_app_check(facts)
    if check is None:
        return MISSING("app_check_not_unique")
    if check.get("conclusion") is None:
        return MISSING("conclusion_missing")
    return PASS("conclusion_as_expected") if check["conclusion"] == SCENARIO_EXPECTATIONS[scenario][0] else FAILED("conclusion_differs")


# ---------------------------------------------------------------------------
# G11 environment boundary (S7-12, S7-13, S7-16, S7-17)
# ---------------------------------------------------------------------------


def no_step_executed(facts: Facts, scenario: str) -> Outcome:
    """S7-12: every steal.yml run concluded and no job executed any step."""
    runs = facts.get("steal_runs")
    if runs is None:
        return MISSING("steal_runs_missing")
    if not runs:
        return MISSING("no_steal_run")
    if any(j.get("steps_run") for r in runs for j in r.get("jobs") or []) or any(j.get("token_step_reached") for r in runs for j in r.get("jobs") or []):
        return FAILED("a_step_executed")
    if any(r.get("conclusion") is None for r in runs) or any(not r.get("jobs") for r in runs):
        return MISSING("run_not_concluded_or_jobs_missing")
    return PASS("no_step_executed")


def app_checks_name_gate_runs(facts: Facts, scenario: str) -> Outcome:
    """S7-13: every App check on the head names a gate run."""
    checks, runs = _app_checks(facts), facts.get("gate_runs")
    if checks is None or runs is None:
        return MISSING("check_runs_or_gate_runs_missing")
    gate_ids = {r.get("run_id") for r in runs}
    for c in checks:
        m = _EXTERNAL_ID.fullmatch(str(c.get("external_id") or ""))
        if not m or int(m.group(1)) not in gate_ids:
            return FAILED("app_check_names_a_non_gate_run")
    return PASS("all_app_checks_name_gate_runs") if checks else MISSING("app_check_absent")


def environment_refuses_both_events(facts: Facts, scenario: str) -> Outcome:
    """S7-16: the environment refuses both pull_request and push (no step, no token, no foreign App check)."""
    runs = facts.get("steal_runs")
    if runs is None:
        return MISSING("steal_runs_missing")
    step = no_step_executed(facts, scenario)
    if step.status == "FAILED":
        return step
    foreign = app_checks_name_gate_runs(facts, scenario)
    if foreign.status == "FAILED":
        return foreign
    events = {r.get("event") for r in runs}
    if not {"pull_request", "push"} <= events:
        return MISSING("not_both_events_observed")
    if any(not (r.get("environment_denied") or {}).get("denied") for r in runs if r.get("event") in ("pull_request", "push")):
        return MISSING("denial_reason_not_observed")
    if step.status != "PASS" or foreign.status != "PASS":
        return MISSING("steps_or_app_checks_not_shown")
    return PASS("environment_refused_both_events")


def same_app_with_key(facts: Facts, scenario: str) -> Outcome:
    """S7-17: a key holder can post a same-App success; this stays a limit, never a pass."""
    return MISSING("limit_same_app_with_key")


def limits_recorded(facts: Facts, scenario: str) -> Outcome:
    """S7-18: G8, AC28, admin bypass and same_app_with_key are NOT_PROVEN with the reason."""
    return MISSING({"G8": "needs_a_merge", "AC28": "needs_a_write_only_second_account", "admin_bypass": "needs_a_merge_attempt",
                    "same_app_with_key": "limit_same_app_with_key"}.get(scenario, "limit"))


# ---------------------------------------------------------------------------
# Composition (S7-02)
# ---------------------------------------------------------------------------


def compose(statuses: Sequence[str]) -> str:
    """S7-02: PROVEN (PASS) only if every part is; any FAILED part makes it FAILED; otherwise NOT_PROVEN."""
    if "FAILED" in statuses:
        return "FAILED"
    if statuses and all(s == "PASS" for s in statuses):
        return "PASS"
    return "NOT_PROVEN"


RULES: Mapping[str, Callable[[Facts, str], Outcome]] = {
    "s7.required.impostor_not_required": impostor_not_required,
    "s7.required.app_check_required": app_check_required,
    "s7.required.same_name_other_source": same_name_other_source,
    "s7.required.impostor_required_fails_scenario": impostor_required_fails_scenario,
    "s6.expected.impostor_not_required": s6_impostor_not_required,
    "s7.required.merge_state_as_expected": merge_state_as_expected,
    "s7.merge.spoof_scenario_blocked": spoof_scenario_blocked,
    "phase2.issuer_pinning.independent_proof": issuer_pinning_independent,
    "s7.gate.base_gate_provenance": base_gate_provenance,
    "s7.gate.verify_step_as_expected": verify_step_as_expected,
    "s7.app_check.exactly_one_app_check": exactly_one_app_check,
    "s7.app_check.external_id_names_gate_run": external_id_names_gate_run,
    "s7.app_check.report_digest_matches": report_digest_matches,
    "s7.app_check.conclusion_as_expected": conclusion_as_expected,
    "s7.steal.no_step_executed": no_step_executed,
    "s7.steal.app_checks_name_gate_runs": app_checks_name_gate_runs,
    "s7.steal.environment_refuses_both_events": environment_refuses_both_events,
    "s7.limit.same_app_with_key": same_app_with_key,
    "s7.limits.recorded_not_proven": limits_recorded,
}
COMPOSE_RULE = "s7.compose.all_parts"
