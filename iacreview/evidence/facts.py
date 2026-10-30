"""Facts: the normalized input of the §7 rules, from native raw evidence or from legacy derived evidence (WP4-2, WP4-5).

Source: the GitHub answers named by §7's Source column (GraphQL ``isRequired`` / ``mergeStateStatus``,
Checks API, Actions runs, jobs and per-job logs, the report artifact) and, for legacy evidence, the
Phase 1 helper's ``app-evidence`` rows (E18 and its siblings). Purpose: one shape of input for the rules,
so that a native replay and a legacy re-evaluation are judged by the same rule code, and so that a fact
the evidence does not hold is ``None`` (missing), never a default.

Facts of one scenario::

    scenario, head_sha, base_sha, app_id
    contexts                  same-named and other contexts of the head rollup (GraphQL), or None
    merge_state, mergeable    GraphQL mergeStateStatus / mergeable, or None
    mergeable_before_ruleset  G9 only: mergeable before the ruleset, or None
    rest_checks               Checks API check runs on the head, or None
    gate_runs                 gate runs with jobs and log facts, or None
    report_digests            {run id: recomputed payload digest (None if inconsistent)}, or None
    rules_main                effective rules of main, or None
    steal_runs                G11: steal.yml runs with jobs and denial reasons, or None

Native parsing reads only bytes returned by :meth:`iacreview.evidence.snapshot.Snapshot.read`; JSON is
parsed strictly and a parse failure makes the fact missing.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from iacreview.evidence import rules_s7

ROLE = re.compile(r"^(rollup|rollup_before|check_runs|gate_run|gate_jobs|gate_log_verify|report_artifact|rules_main|steal_runs|"
                  r"steal_jobs/[0-9]{1,20}|steal_annotations/[0-9]{1,20})$")


def report_payload_digest(raw: bytes) -> Optional[str]:
    """The report's payload digest, recomputed (canonical JSON as in iacreview.remediation.report); None if inconsistent."""
    try:
        rep = json.loads(raw.decode("utf-8"))
        payload, recorded = rep["payload"], rep["metadata"]["payload_sha256"]
    except (UnicodeDecodeError, ValueError, KeyError, TypeError):
        return None
    canon = json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    digest = hashlib.sha256(canon).hexdigest()
    return digest if digest == recorded else None


# ---------------------------------------------------------------------------
# Native raw evidence
# ---------------------------------------------------------------------------


def _json(raw: Optional[bytes]) -> Any:
    if raw is None:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None


def contexts_from_graphql(doc: Any) -> Tuple[Optional[List[Dict[str, Any]]], Optional[str], Optional[str]]:
    """(contexts, mergeStateStatus, mergeable) from the GraphQL answer of the §7 query; contexts None if absent."""
    try:
        pr = doc["data"]["repository"]["pullRequest"]
        nodes = pr["commits"]["nodes"][-1]["commit"]["statusCheckRollup"]["contexts"]["nodes"]
    except (KeyError, IndexError, TypeError):
        return None, None, None
    out = []
    for n in nodes:
        if not isinstance(n, dict):
            return None, None, None
        if n.get("__typename") == "CheckRun":
            app = (n.get("checkSuite") or {}).get("app") or {}
            out.append({"kind": "check_run", "name": n.get("name"), "check_run_id": n.get("databaseId"), "graphql_app_id": app.get("databaseId"),
                        "state": str(n.get("conclusion") or n.get("status") or "").lower() or None,
                        "is_required": n.get("isRequired") if isinstance(n.get("isRequired"), bool) else None})
        elif n.get("__typename") == "StatusContext":
            out.append({"kind": "status", "name": n.get("context"), "check_run_id": None, "graphql_app_id": None,
                        "state": str(n.get("state") or "").lower() or None,
                        "is_required": n.get("isRequired") if isinstance(n.get("isRequired"), bool) else None})
    return out, pr.get("mergeStateStatus"), pr.get("mergeable")


def check_runs_from_rest(docs: Sequence[Any]) -> Optional[List[Dict[str, Any]]]:
    out = []
    for doc in docs:
        if not isinstance(doc, dict) or not isinstance(doc.get("check_runs"), list):
            return None
        for c in doc["check_runs"]:
            out.append({"check_run_id": c.get("id"), "name": c.get("name"), "app_id": (c.get("app") or {}).get("id"),
                        "conclusion": c.get("conclusion"), "external_id": c.get("external_id"), "head_sha": c.get("head_sha")})
    return out


def _permissions(log: str) -> Optional[List[str]]:
    out: List[str] = []
    inside, seen = False, False
    for line in log.splitlines():
        text = re.sub(r"^\S+Z ", "", line.split("\t")[-1])
        if "##[group]GITHUB_TOKEN Permissions" in text:
            inside = seen = True
            continue
        if inside:
            if text.startswith("##[endgroup]"):
                break
            out.append(text.strip())
    return out if seen else None


def log_facts(log: str, base_sha: Optional[str], head_sha: Optional[str], trusted_contract: str, untrusted_markers: Sequence[str]) -> Dict[str, Any]:
    """S7-03 facts from a verify-job log. A fact that cannot be decided (no SHA given) is None."""
    return {
        "validator_pinned": re.search(r"\b{0}[0-9a-f]{{33}}\b".format(rules_s7.VALIDATOR_PIN), log) is not None,
        "validator_checked_out": "HEAD is now at {0}".format(rules_s7.VALIDATOR_PIN) in log,
        "gate_scripts_pinned": "HEAD is now at {0}".format(rules_s7.GATE_SCRIPTS_PIN) in log,
        "subject_is_base": None if not base_sha else ("git checkout --progress --force {0}".format(base_sha) in log
                                                      and "HEAD is now at {0}".format(base_sha[:7]) in log),
        "head_env_is_pr_head": None if not head_sha else "HEAD_SHA: {0}".format(head_sha) in log,
        "trusted_contract": trusted_contract in log if trusted_contract else None,
        "relaxed_contract": any(m in log for m in untrusted_markers),
        "token_permissions": _permissions(log),
    }


Reader = Callable[[str], Tuple[Dict[str, Any], Optional[bytes]]]


def native_facts(bundle: Mapping[str, Any], read: Reader, is_bound: Callable[[str], bool]) -> Tuple[Dict[str, Any], List[str]]:
    """Facts of one scenario bundle from bound raw evidence. Returns (facts, evidence ids actually read).

    An unbound id makes its role missing. ``read`` raises SnapshotDrift on any change after the snapshot.
    """
    used: List[str] = []
    roles: Mapping[str, Sequence[str]] = bundle.get("roles") or {}

    def raws(role: str) -> Optional[List[bytes]]:
        ids = list(roles.get(role) or [])
        if not ids or not all(is_bound(i) for i in ids):
            return None
        out = []
        for i in ids:
            _, raw = read(i)
            used.append(i)
            if raw is None:
                return None
            out.append(raw)
        return out

    head, base = bundle.get("head_sha"), bundle.get("base_sha")
    facts: Dict[str, Any] = {"scenario": bundle["scenario"], "head_sha": head, "base_sha": base, "app_id": bundle.get("app_id"),
                             "contexts": None, "merge_state": None, "mergeable": None, "mergeable_before_ruleset": None,
                             "rest_checks": None, "gate_runs": None, "report_digests": None, "rules_main": None, "steal_runs": None}
    r = raws("rollup")
    if r and len(r) == 1:
        facts["contexts"], facts["merge_state"], facts["mergeable"] = contexts_from_graphql(_json(r[0]))
    r = raws("rollup_before")
    if r and len(r) == 1:
        facts["mergeable_before_ruleset"] = contexts_from_graphql(_json(r[0]))[2]
    r = raws("check_runs")
    if r:
        facts["rest_checks"] = check_runs_from_rest([_json(x) for x in r])
    r = raws("rules_main")
    if r and len(r) == 1 and isinstance(_json(r[0]), list):
        facts["rules_main"] = _json(r[0])
    run_raw, jobs_raw, log_raw = raws("gate_run"), raws("gate_jobs"), raws("gate_log_verify")
    if run_raw and jobs_raw and log_raw and len(run_raw) == 1:
        facts["gate_runs"] = _gate_runs(_json(run_raw[0]), [_json(x) for x in jobs_raw], b"".join(log_raw), bundle)
    art = raws("report_artifact")
    if art and len(art) == 1 and facts["gate_runs"]:
        facts["report_digests"] = {facts["gate_runs"][0]["run_id"]: report_payload_digest(art[0])}
    steal = raws("steal_runs")
    if steal:
        facts["steal_runs"] = _steal_runs([_json(x) for x in steal], raws)
    return facts, used


def _gate_runs(run: Any, jobs_docs: List[Any], log: bytes, bundle: Mapping[str, Any]) -> Optional[List[Dict[str, Any]]]:
    if not isinstance(run, dict):
        return None
    jobs: List[Dict[str, Any]] = []
    for d in jobs_docs:
        if not isinstance(d, dict) or not isinstance(d.get("jobs"), list):
            return None
        jobs += d["jobs"]
    verify = next((j for j in jobs if j.get("name") == "verify"), None)
    publish = next((j for j in jobs if j.get("name") == "publish"), None)
    steps = {s.get("name"): s.get("conclusion") for s in (verify or {}).get("steps") or []}
    try:
        text = log.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return [{"run_id": run.get("id"), "run_attempt": run.get("run_attempt"), "event": run.get("event"), "workflow_path": run.get("path"),
             "run_head_sha": run.get("head_sha"), "status": run.get("status"),
             "verify_step": steps.get(rules_s7.VERIFY_STEP) if verify else None,
             "failed_steps": sorted(k for k, v in steps.items() if v == "failure") if verify else None,
             "publish_job": publish.get("conclusion") if publish else None,
             "log": log_facts(text, bundle.get("base_sha"), bundle.get("head_sha"), str(bundle.get("trusted_contract") or ""),
                              list(bundle.get("untrusted_contract_markers") or []))}]


def _steal_runs(docs: List[Any], raws: Callable[[str], Optional[List[bytes]]]) -> Optional[List[Dict[str, Any]]]:
    out = []
    for doc in docs:
        if not isinstance(doc, dict) or not isinstance(doc.get("workflow_runs"), list):
            return None
        for r in doc["workflow_runs"]:
            if str(r.get("path", "")).startswith(rules_s7.GATE_PATH):
                continue
            jobs_raw = raws("steal_jobs/{0}".format(r.get("id")))
            ann_raw = raws("steal_annotations/{0}".format(r.get("id")))
            jobs = None
            if jobs_raw:
                parsed = [_json(x) for x in jobs_raw]
                if all(isinstance(p, dict) and isinstance(p.get("jobs"), list) for p in parsed):
                    jobs = [{"name": j.get("name"), "steps_run": [s.get("name") for s in j.get("steps") or []
                                                                  if s.get("conclusion") not in (None, "skipped")],
                             "token_step_reached": any("create-github-app-token" in str(s.get("name") or "").lower()
                                                       and s.get("conclusion") not in (None, "skipped") for s in j.get("steps") or [])}
                            for p in parsed for j in p["jobs"]]
            denied = None
            if ann_raw:
                text = " ".join(str(a.get("message") or "") for x in ann_raw for a in (_json(x) or []) if isinstance(a, dict)).lower()
                denied = {"denied": "not allowed to deploy" in text or ("environment" in text and "protection rule" in text)}
            out.append({"id": r.get("id"), "event": r.get("event"), "conclusion": r.get("conclusion"), "jobs": jobs or [],
                        "environment_denied": denied})
    return out


# ---------------------------------------------------------------------------
# Legacy derived evidence (Phase 1 helper output, E18 and siblings)
# ---------------------------------------------------------------------------


def legacy_facts(scenario: str, row: Mapping[str, Any], app_id: int, rules_main: Any, w0_views: Optional[Mapping[str, Any]],
                 report_digest_of: Callable[[int], Optional[str]]) -> Dict[str, Any]:
    """Facts of one scenario from a helper ``app-evidence`` row. Values come from the helper's transcription;
    their completeness and authenticity at capture time stay NOT_PROVEN (no raw response exists)."""
    if not row.get("pr"):
        return {"scenario": scenario, "head_sha": None, "base_sha": None, "app_id": app_id, "contexts": None, "merge_state": None,
                "mergeable": None, "mergeable_before_ruleset": None, "rest_checks": None, "gate_runs": None, "report_digests": None,
                "rules_main": None, "steal_runs": None}
    head = row.get("head_sha")
    view = row.get("required_view") or {}
    contexts = None
    if isinstance(view.get("contexts"), list):
        contexts = [{"kind": c.get("kind"), "name": c.get("name"), "check_run_id": c.get("check_run_id"), "graphql_app_id": c.get("app_id"),
                     "state": str(c.get("state") or "").lower() or None,
                     "is_required": c.get("is_required") if isinstance(c.get("is_required"), bool) else None} for c in view["contexts"]]
    rest = (row.get("checks_by_head") or {}).get(head)
    rest_checks = None if rest is None else [{"check_run_id": c.get("check_run_id"), "name": c.get("name"), "app_id": c.get("app_id"),
                                              "conclusion": c.get("conclusion"), "external_id": c.get("external_id"),
                                              "head_sha": c.get("head_sha")} for c in rest]
    gate_runs = None
    if isinstance(row.get("gate_runs"), list):
        gate_runs = []
        for g in row["gate_runs"]:
            gate_runs.append({"run_id": g.get("run_id"), "run_attempt": g.get("run_attempt"), "event": g.get("event"),
                              "workflow_path": g.get("workflow_path"), "run_head_sha": g.get("run_head_sha"), "status": g.get("status"),
                              "verify_step": g.get("verify_step"), "failed_steps": g.get("failed_steps"), "publish_job": g.get("publish_job"),
                              "log": {"validator_pinned": g.get("log_has_validator_pin"), "validator_checked_out": g.get("log_validator_checked_out"),
                                      "gate_scripts_pinned": g.get("log_gate_scripts_pinned"), "subject_is_base": g.get("log_subject_is_base"),
                                      "head_env_is_pr_head": g.get("log_head_env_is_pr_head"), "trusted_contract": g.get("log_has_trusted_contract"),
                                      "relaxed_contract": g.get("log_has_relaxed_contract"), "token_permissions": g.get("token_permissions")}})
    digests = None
    if gate_runs:
        digests = {}
        for g in gate_runs:
            if isinstance(g.get("run_id"), int):
                d = report_digest_of(g["run_id"])
                if d != "MISSING":
                    digests[g["run_id"]] = d
    steal = None
    others = row.get("other_runs")
    if scenario == "G11" and isinstance(others, list):
        steal = [{"id": r.get("id"), "event": r.get("event"), "conclusion": r.get("conclusion"),
                  "jobs": [{"name": j.get("name"), "steps_run": j.get("steps_run"), "token_step_reached": j.get("token_step_reached")}
                           for j in r.get("jobs") or []],
                  "environment_denied": {"denied": bool((r.get("environment_denied") or {}).get("denied"))} if r.get("environment_denied") else None}
                 for r in others if str(r.get("path", "")).startswith(".github/workflows/steal.yml")]
    before = None
    if scenario == "G9" and w0_views and isinstance(w0_views.get("G9"), dict) and w0_views["G9"].get("head_sha") == head:
        before = w0_views["G9"].get("mergeable")
    return {"scenario": scenario, "head_sha": head, "base_sha": row.get("base_sha"), "app_id": app_id, "contexts": contexts,
            "merge_state": view.get("merge_state"), "mergeable": view.get("mergeable"), "mergeable_before_ruleset": before,
            "rest_checks": rest_checks, "gate_runs": gate_runs, "report_digests": digests,
            "rules_main": rules_main if isinstance(rules_main, list) else None, "steal_runs": steal}
