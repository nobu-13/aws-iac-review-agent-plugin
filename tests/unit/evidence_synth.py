"""Synthetic GitHub answers for the WP4 evaluator and replay tests (not a test module).

Everything here is invented: owner/repo names, ids, SHAs, the App id, log lines. Shapes follow the GitHub
answers named by app-demo-plan §7 (GraphQL status rollup with isRequired, Checks API, Actions runs/jobs, a
verify-job log, the report artifact, branch rules). Nothing reaches GitHub; responses go through the WP2
collector with a fake transport, then into a WP2 store.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from iacreview.evidence import artifact, collector, envelope, integrity, store

REPO = "synthetic-owner/synthetic-repo"
APP_ID = 1000001
ACTIONS_APP_ID = 15368
VALIDATOR = "5412a73" + "0" * 33
SCRIPTS = "f77a58c" + "1" * 33
CONTRACT = ".iac-remediation/contracts/billing-mode-orders.yaml"
T0 = datetime.datetime(2026, 10, 29, 6, 0, 0, tzinfo=datetime.timezone.utc)
CHECK = "remediation-gate/verified"


def sha(seed: str) -> str:
    return hashlib.sha1(seed.encode()).hexdigest()  # noqa: S324 - synthetic id only


def report(decision: str) -> Tuple[bytes, str]:
    payload = {"decision": decision, "exit_code": 0 if decision == "VERIFIED" else 20}
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")).hexdigest()
    return json.dumps({"payload": payload, "metadata": {"payload_sha256": digest}}, sort_keys=True).encode(), digest


def verify_log(base: str, head: str, permissions: Tuple[str, ...] = ("Contents: read", "Metadata: read"), relaxed: bool = False) -> bytes:
    lines = ["2026-10-29T06:00:00.0000000Z ##[group]GITHUB_TOKEN Permissions"]
    lines += ["2026-10-29T06:00:00.0000000Z " + p for p in permissions]
    lines += ["2026-10-29T06:00:00.0000000Z ##[endgroup]",
              "2026-10-29T06:00:01.0000000Z git checkout --progress --force " + base,
              "2026-10-29T06:00:01.0000000Z HEAD is now at " + base[:7] + " base",
              "2026-10-29T06:00:02.0000000Z validator " + VALIDATOR,
              "2026-10-29T06:00:02.0000000Z HEAD is now at " + VALIDATOR[:7] + " validator",
              "2026-10-29T06:00:02.0000000Z HEAD is now at " + SCRIPTS[:7] + " gate scripts",
              "2026-10-29T06:00:03.0000000Z HEAD_SHA: " + head,
              "2026-10-29T06:00:03.0000000Z contract " + (".iac-remediation/contracts/relaxed.yaml" if relaxed else CONTRACT)]
    return ("\n".join(lines) + "\n").encode()


def scenario_spec(gid: str, **over: Any) -> Dict[str, Any]:
    """Default observations for ``gid`` as §6 expects them; ``over`` changes single observations."""
    app = "success" if gid in ("G0", "G1") else "failure"
    spec: Dict[str, Any] = {
        "gid": gid, "head": sha("head-" + gid), "base": sha("base"), "pr": 100 + len(gid),
        "app_conclusion": app, "app_required": True, "app_check_present": True, "app_in_graphql": True,
        "merge_state": "CLEAN" if gid == "G1" else ("UNSTABLE" if gid == "G0" else "BLOCKED"),
        "mergeable": "MERGEABLE",
        "impostor": None, "impostor_required": False,
        "run_id": 900000 + sum(map(ord, gid)), "run_attempt": 1, "event": "pull_request_target",
        "path": ".github/workflows/remediation-gate.yml", "run_on_head": True,
        "verify": app, "permissions": ("Contents: read", "Metadata: read"), "relaxed": False,
        "external_id_run": None, "report_tamper": False, "steal": gid == "G11", "steal_step": False,
        "omit": (),
    }
    if gid in ("G3", "G6"):
        spec["impostor"] = ("check_run", "success" if gid == "G3" else "skipped")
    if gid == "G3S":
        spec["impostor"] = ("status", "success")
    spec.update(over)
    return spec


def answers(spec: Dict[str, Any]) -> Dict[str, Tuple[str, str, bytes, str]]:
    """role -> (method, endpoint, body, content type) for one scenario."""
    head, base = spec["head"], spec["base"]
    nodes = []
    app_check_id = 500000 + spec["run_id"]
    if spec["app_check_present"]:
        nodes.append({"__typename": "CheckRun", "databaseId": app_check_id, "name": CHECK, "status": "COMPLETED",
                      "conclusion": spec["app_conclusion"].upper(), "isRequired": spec["app_required"],
                      "checkSuite": {"databaseId": 1, "app": None}})  # private App: GraphQL shows no app
    imp = spec["impostor"]
    if imp and imp[0] == "check_run":
        nodes.append({"__typename": "CheckRun", "databaseId": app_check_id + 1, "name": CHECK, "status": "COMPLETED",
                      "conclusion": imp[1].upper(), "isRequired": spec["impostor_required"],
                      "checkSuite": {"databaseId": 2, "app": {"databaseId": ACTIONS_APP_ID, "slug": "github-actions"}}})
    if imp and imp[0] == "status":
        nodes.append({"__typename": "StatusContext", "context": CHECK, "state": imp[1].upper(), "isRequired": spec["impostor_required"],
                      "creator": {"login": "github-actions"}})
    rollup = {"data": {"repository": {"pullRequest": {"headRefOid": head, "mergeable": spec["mergeable"], "mergeStateStatus": spec["merge_state"],
                                                     "commits": {"nodes": [{"commit": {"oid": head, "statusCheckRollup": {"contexts": {
                                                         "nodes": nodes, "pageInfo": {"hasNextPage": False}}}}}]}}}}}
    report_bytes, digest = report("VERIFIED" if spec["verify"] == "success" else "BLOCKED")
    if spec["report_tamper"]:
        digest = "e" * 64
    ext_run = spec["external_id_run"] or spec["run_id"]
    checks = []
    if spec["app_check_present"]:
        checks.append({"id": app_check_id, "name": CHECK, "app": {"id": APP_ID}, "conclusion": spec["app_conclusion"], "head_sha": head,
                       "external_id": "{0}.{1}:{2}".format(ext_run, spec["run_attempt"], digest)})
    if imp and imp[0] == "check_run":
        checks.append({"id": app_check_id + 1, "name": CHECK, "app": {"id": ACTIONS_APP_ID}, "conclusion": imp[1], "head_sha": head, "external_id": None})
    failed = spec["verify"] != "success"
    steps = [{"name": "Install pinned tools (from the validator, not from the PR)", "conclusion": "success"},
             {"name": "Verify the candidate against the approved contract", "conclusion": "failure" if failed else "success"},
             {"name": "Derive the outputs from the report", "conclusion": "failure" if failed else "success"}]
    run = {"id": spec["run_id"], "run_attempt": spec["run_attempt"], "event": spec["event"], "path": spec["path"],
           "head_sha": head if spec["run_on_head"] else sha("other"), "status": "completed", "conclusion": "failure" if failed else "success"}
    jobs = {"jobs": [{"name": "verify", "conclusion": "failure" if failed else "success", "steps": steps},
                     {"name": "publish", "conclusion": "success", "steps": [{"name": "Publish", "conclusion": "success"}]}]}
    rules = [{"type": "pull_request", "parameters": {"required_approving_review_count": 0}},
             {"type": "required_status_checks", "parameters": {"required_status_checks": [{"context": CHECK, "integration_id": APP_ID}]}}]
    base_ep = "/repos/" + REPO
    out = {
        "rollup": ("POST", "graphql", json.dumps(rollup).encode(), "application/json"),
        "check_runs": ("GET", base_ep + "/commits/{0}/check-runs?per_page=100".format(head), json.dumps({"total_count": len(checks), "check_runs": checks}).encode(), "application/json"),
        "gate_run": ("GET", base_ep + "/actions/runs/{0}".format(spec["run_id"]), json.dumps(run).encode(), "application/json"),
        "gate_jobs": ("GET", base_ep + "/actions/runs/{0}/jobs".format(spec["run_id"]), json.dumps(jobs).encode(), "application/json"),
        "gate_log_verify": ("GET", base_ep + "/actions/jobs/{0}/logs".format(spec["run_id"] + 1), verify_log(base, head, spec["permissions"], spec["relaxed"]), "text/plain"),
        "rules_main": ("GET", base_ep + "/rules/branches/main", json.dumps(rules).encode(), "application/json"),
        "report_artifact": ("LOCAL", "artifact remediation-report of run {0}".format(spec["run_id"]), report_bytes, ""),
    }
    if spec["steal"]:
        steal_runs = [{"id": 700001, "event": "pull_request", "path": ".github/workflows/steal.yml", "status": "completed", "conclusion": "failure"},
                      {"id": 700002, "event": "push", "path": ".github/workflows/steal.yml", "status": "completed", "conclusion": "failure"}]
        out["steal_runs"] = ("GET", base_ep + "/actions/runs?head_sha={0}&per_page=100".format(head), json.dumps({"workflow_runs": steal_runs}).encode(), "application/json")
        for r in steal_runs:
            steps2 = [{"name": "Request publisher environment", "conclusion": "success"}] if spec["steal_step"] else []
            out["steal_jobs/{0}".format(r["id"])] = ("GET", base_ep + "/actions/runs/{0}/jobs".format(r["id"]),
                                                     json.dumps({"jobs": [{"name": "steal", "conclusion": "failure", "steps": steps2}]}).encode(), "application/json")
            out["steal_annotations/{0}".format(r["id"])] = ("GET", base_ep + "/check-runs/{0}/annotations".format(r["id"] + 10),
                                                            json.dumps([{"message": "Branch is not allowed to deploy to remediation-publisher due to environment protection rules."}]).encode(), "application/json")
    for role in spec["omit"]:
        out.pop(role, None)
    return out


class Builder:
    """Captures synthetic answers into one store revision and returns the replay spec pieces."""

    def __init__(self, tmp: Path) -> None:
        self.base = tmp / "work"
        self.base.mkdir(parents=True, exist_ok=True)
        self.store = store.EvidenceStore(self.base / "evidence-store", self.base, now=lambda: T0)
        self._n = 0
        self.captured: List[collector.CapturedEvidence] = []
        self.groups: Dict[str, Dict[str, Any]] = {}
        self.bundles: List[Dict[str, Any]] = []

    def _id(self) -> str:
        self._n += 1
        return "cap-syn-{0:04d}".format(self._n)

    def capture(self, method: str, endpoint: str, body: bytes, ctype: str, subject: Optional[str]) -> List[str]:
        if method == "LOCAL":
            cid = self._id()
            ev, refusal = collector.non_api_evidence("LOCAL", cid + "-l", cid, endpoint, body, T0, REPO, subject)
            assert refusal is None and ev is not None
            self.captured.append(ev)
            return [ev.evidence_id]
        queue = [collector.HttpResponse(200, {"Content-Type": ctype}, body)]
        cap = collector.Collector(lambda r: queue.pop(0), REPO, now=lambda: T0, id_factory=self._id).capture(
            method, endpoint, subject_commit_sha=subject, body=b"{}" if method == "POST" else None)
        assert cap.complete and not cap.refusals, (endpoint, cap.refusals)
        self.captured.extend(cap.evidence)
        return [e.evidence_id for e in cap.evidence]

    def add_scenario(self, spec: Dict[str, Any], extra_roles: Optional[Dict[str, List[str]]] = None) -> Dict[str, Any]:
        roles: Dict[str, List[str]] = {}
        gid, head = spec["gid"], spec["head"]
        for role, (method, ep, body, ctype) in sorted(answers(spec).items()):
            subject = None if role == "rules_main" else head
            roles[role] = self.capture(method, ep, body, ctype, subject)
        api = sorted(i for r, ids in roles.items() if r not in ("rules_main", "report_artifact") for i in ids)
        self.groups[gid + "-api"] = {"evidence_ids": api, "requirement": {"source_type": "API", "subject_commit_sha": head}}
        if "rules_main" in roles:
            self.groups[gid + "-rules"] = {"evidence_ids": roles["rules_main"], "requirement": {"source_type": "API"}}
        if "report_artifact" in roles:
            self.groups[gid + "-local"] = {"evidence_ids": roles["report_artifact"], "requirement": {"source_type": "LOCAL", "subject_commit_sha": head}}
        roles.update(extra_roles or {})
        bundle = {"scenario": gid, "head_sha": head, "base_sha": spec["base"], "app_id": APP_ID, "trusted_contract": CONTRACT,
                  "untrusted_contract_markers": ["relaxed.yaml"], "roles": roles}
        self.bundles.append(bundle)
        return bundle

    def add_artifact(self, head: str, files: Dict[str, bytes], served: Dict[str, bytes]) -> Dict[str, List[str]]:
        """LOCAL artifact record (MATCH) and one Contents API answer per served file (P2-AI-01 / 02)."""
        sums = {p: hashlib.sha256(b).hexdigest() for p, b in files.items()}
        comp = artifact.Comparison("MATCH", [], sums, head, sha("tree"))
        rec = self.capture("LOCAL", "artifact integrity record", envelope.canonical_bytes(comp.record()), "", head)
        path, data = sorted(served.items())[0]
        body = json.dumps({"type": "file", "encoding": "base64", "path": path, "sha": artifact.git_blob_id(data),
                           "content": base64.b64encode(data).decode()}).encode()
        pub = self.capture("GET", "/repos/{0}/contents/{1}?ref={2}".format(REPO, path, head), body, "application/json", head)
        self.groups["artifact-local"] = {"evidence_ids": rec, "requirement": {"source_type": "LOCAL", "subject_commit_sha": head}}
        self.groups["artifact-api"] = {"evidence_ids": pub, "requirement": {"source_type": "API", "subject_commit_sha": head}}
        return {"artifact_record": rec, "published_contents": pub}

    def seal(self) -> Dict[str, Any]:
        w = self.store.begin_revision("synthetic WP4 evidence")
        for e in self.captured:
            w.add(e)
        w.seal()
        assert self.store.verify().valid
        return {"store_root": str(self.store.root), "containment_base": str(self.base), "groups": self.groups, "bundles": self.bundles}


def direct_facts(spec: Dict[str, Any]) -> Dict[str, Any]:
    """Facts parsed from the synthetic answers without a store (same parser as the native replay)."""
    from iacreview.evidence import facts as facts_mod

    ans = answers(spec)
    roles = {role: [role.replace("/", "-")] for role in ans}
    data = {role.replace("/", "-"): body for role, (_, _, body, _) in ans.items()}
    bundle = {"scenario": spec["gid"], "head_sha": spec["head"], "base_sha": spec["base"], "app_id": APP_ID, "trusted_contract": CONTRACT,
              "untrusted_contract_markers": ["relaxed.yaml"], "roles": roles}
    facts, _ = facts_mod.native_facts(bundle, lambda i: ({}, data[i]), lambda i: i in data)
    return facts


def requirement(group: Dict[str, Any]) -> integrity.Requirement:
    r = group["requirement"]
    return integrity.Requirement(r.get("source_type", "API"), r.get("subject_commit_sha"), True)
