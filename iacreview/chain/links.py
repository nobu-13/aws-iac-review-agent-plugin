"""The six links of a chain (WP1: subject, contract, review, verification, github; gate is WP2).

Source: ``docs/v2/phase2/m2/wp0/m2-schemas.md`` rev1 §1, §3, §4 and ``m2-acceptance-test-matrix.md``
M2-02..M2-05. Each check returns reason codes; the link status is derived from them
(:func:`iacreview.chain.status.link_status`). A check never accepts a manifest value as established:

* subject / contract: the commits and the contract blob are read from git (``gitsnap``: plumbing only,
  hooks, filters and textconv disabled); the contract is read from the config commit, never from the head
  or a work tree;
* review: the Review_Report is re-read and checked by ``iacreview.reportcheck``; completeness is
  ``errors[] == []`` and every listed tool available, never the summary's pass flag;
* verification: the report is re-read and its payload digest recomputed, and the verification is run again
  (Phase 1 ``verify``) and compared field by field except ``validator``, which names the code and Python
  that produced it; a recomputation that cannot run every pinned tool is ``recompute_unavailable``;
* github: the M1 store is verified by the M1 code and the named evidence must pass the M1 integrity
  validator; ``capture_authenticity`` is always NOT_PROVEN.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from iacreview import reportcheck
from iacreview.chain import manifest as mf
from iacreview.chain import status as st
from iacreview.evidence import integrity as m1_integrity
from iacreview.evidence import store as m1_store
from iacreview.remediation import contract as contract_mod
from iacreview.remediation import gitsnap, rschema, verify
from iacreview.remediation import report as remediation_report

MAX_REVIEW_REPORT_BYTES = 16 * 1024 * 1024
_REPOSITORY = re.compile(r"^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$")
REGULAR_MODES = gitsnap.REGULAR_MODES


@dataclass
class LinkResult:
    """Codes and observations of one link. ``present`` is False for an optional link the manifest leaves out."""

    link: str
    codes: List[str] = field(default_factory=list)
    observed: Dict[str, Any] = field(default_factory=dict)
    present: bool = True
    #: Environment-dependent notes (never reason codes, never in the payload): see ``status.DIAGNOSTICS``.
    diagnostics: List[Dict[str, Any]] = field(default_factory=list)

    def add(self, code: str) -> None:
        if code not in self.codes:
            self.codes.append(code)

    @property
    def status(self) -> str:
        return st.link_status(self.codes) if self.present else st.NOT_PRESENT

    def as_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"link": self.link, "status": self.status, "codes": sorted(self.codes)}
        if self.observed:
            out["observed"] = dict(sorted(self.observed.items()))
        return out


@dataclass
class Context:
    """What the checks share. ``report`` is the verification report when it passed the shape check."""

    root: Path
    repo: Optional[Path]
    doc: Dict[str, Any]
    report: Optional[Dict[str, Any]] = None
    contract_bytes: Optional[bytes] = None


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def repository_id(owner_repo: str) -> str:
    """``r:`` + the first 12 hex digits of SHA-256(``owner/name``)."""
    return "r:" + _sha(owner_repo.encode("utf-8"))[:12]


# ---------------------------------------------------------------------------
# verification report (read first: the subject and contract checks compare against it)
# ---------------------------------------------------------------------------


#: The payload key that names the code and interpreter that produced a report. Its shape is checked when the
#: report is loaded, and it is covered by the three digest checks (file, metadata, manifest). It is excluded
#: only from the comparison with the recomputation: two runs of the same verification by another plugin
#: revision or Python version agree on everything else. Whether the identity is true is never shown.
_VALIDATOR_KEY = "validator"

#: The ``payload.validator`` object of a Remediation_Verification_Report 0.1.0
#: (docs/v2/phase1/verification-report-schema.md; ``iacreview.remediation.report.validator_identity``).
VALIDATOR_KEYS = ("name", "plugin_version", "source_sha256", "python")
_VALIDATOR_NAME = re.compile(r"^[A-Za-z0-9._/-]{1,200}$")
_PLUGIN_VERSION = re.compile(r"^[A-Za-z0-9.+-]{1,64}$")
_SOURCE_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PYTHON = re.compile(r"^[0-9]{1,3}\.[0-9]{1,3}$")


def validator_identity_problems(value: Any) -> List[str]:
    """Why ``payload.validator`` is not the schema's object (empty: well formed). Shape only, never authenticity."""
    if not isinstance(value, dict):
        return ["not_an_object"]
    problems = []
    if set(value) != set(VALIDATOR_KEYS):
        problems.append("keys")
    if not (isinstance(value.get("name"), str) and _VALIDATOR_NAME.match(value["name"])):
        problems.append("name")
    version = value.get("plugin_version")
    if not (version is None or (isinstance(version, str) and _PLUGIN_VERSION.match(version))):
        problems.append("plugin_version")
    if not (isinstance(value.get("source_sha256"), str) and _SOURCE_SHA256.match(value["source_sha256"])):
        problems.append("source_sha256")
    if not (isinstance(value.get("python"), str) and _PYTHON.match(value["python"])):
        problems.append("python")
    return problems


def load_report(ctx: Context, res: LinkResult) -> None:
    ref = ctx.doc["verification"]["report"]
    try:
        data = mf.read_below(ctx.root, ref["locator"], rschema.MAX_REPORT_BYTES)
    except mf.ReadError as exc:
        res.add("verification_artifact_missing" if exc.kind == "missing" else "report_invalid")
        return
    if _sha(data) != ref["sha256"]:
        res.add("verification_digest_mismatch")
    try:
        obj = mf.strict_json(data)
        remediation_report.validate(obj)
    except remediation_report.ReportError as exc:
        res.add("metadata_digest_mismatch" if exc.reason == "payload_sha256" else "report_invalid")
        return
    except (ValueError, KeyError, TypeError):
        res.add("report_invalid")
        return
    payload = obj["payload"]
    if not isinstance(payload.get("subject"), dict) or not isinstance(payload.get("trust"), dict):
        res.add("report_invalid")
        return
    if validator_identity_problems(payload.get(_VALIDATOR_KEY)):
        res.add("report_invalid")
        return
    ctx.report = obj


# ---------------------------------------------------------------------------
# subject
# ---------------------------------------------------------------------------


def check_subject(ctx: Context) -> LinkResult:
    res = LinkResult("subject")
    base, head = ctx.doc["subject"]["base_commit"], ctx.doc["subject"]["head_commit"]
    if ctx.repo is None:
        res.add("link_check_error")
        return res
    try:
        if gitsnap.resolve_commit(ctx.repo, base) != base or gitsnap.resolve_commit(ctx.repo, head) != head:
            res.add("revision_not_found")
            return res
        if not gitsnap.is_ancestor(ctx.repo, base, head):
            res.add("base_not_ancestor_of_head")
    except gitsnap.GitError as exc:
        res.add("revision_not_found" if exc.code == "revision_not_found" else "link_check_error")
        return res
    if ctx.report is not None:
        subject = ctx.report["payload"]["subject"]
        b, h = subject.get("base") or {}, subject.get("head") or {}
        if b.get("commit") != base or h.get("commit") != head or h.get("kind") != "commit":
            res.add("subject_mismatch")
    return res


# ---------------------------------------------------------------------------
# contract
# ---------------------------------------------------------------------------


def check_contract(ctx: Context) -> LinkResult:
    res = LinkResult("contract")
    c = ctx.doc["contract"]
    config, path, want = c["config_commit"], c["contract_path"], c["contract_sha256"]
    base = ctx.doc["subject"]["base_commit"]
    if ctx.repo is None:
        res.add("link_check_error")
        return res
    try:
        if gitsnap.resolve_commit(ctx.repo, config) != config:
            res.add("revision_not_found")
            return res
        if not gitsnap.is_ancestor(ctx.repo, config, base):
            res.add("config_not_ancestor_of_base")
        entry = gitsnap.commit_snapshot(ctx.repo, config).entries.get(path)
        if entry is None or entry.mode not in REGULAR_MODES:
            res.add("contract_blob_missing")
            return res
        data = gitsnap.read_blob(ctx.repo, entry.oid, rschema.MAX_CONTRACT_BYTES)
    except gitsnap.GitError as exc:
        res.add("revision_not_found" if exc.code == "revision_not_found" else "link_check_error")
        return res
    if data is None:
        res.add("contract_blob_missing")
        return res
    ctx.contract_bytes = data
    if _sha(data) != want:
        res.add("contract_digest_mismatch")
    if ctx.report is not None:
        trust = ctx.report["payload"]["trust"]
        if (trust.get("contract_source") != "git_revision" or trust.get("trusted_config_commit") != config
                or trust.get("contract_path") != path or trust.get("contract_sha256") != _sha(data)):
            res.add("contract_mismatch_with_report")
    return res


# ---------------------------------------------------------------------------
# review
# ---------------------------------------------------------------------------


def identity_key_sha256(raw_finding: Dict[str, Any]) -> str:
    """Digest of the v1.1 Identity_Key ``{File, Resource, Normalized_Category}`` of a raw finding dict."""
    found = raw_finding.get("Location")
    location: Dict[str, Any] = found if isinstance(found, dict) else {}
    key = {"File": location.get("File"), "Resource": raw_finding.get("Resource"),
           "Normalized_Category": raw_finding.get("Normalized_Category")}
    return mf.canonical_sha256(key)


def review_evidence_complete(checked: reportcheck.CheckedReport) -> List[str]:
    """Why a checked Review_Report is not complete evidence (empty: complete).

    ``errors[]`` must be empty and ``tools[]`` non-empty with every tool available. ``findings`` and the
    summary's pass flag are deliberately not consulted (passed-all-checks-investigation.md §4).
    """
    reasons = []
    if checked.errors:
        reasons.append("review_report_has_errors")
    if not checked.tools or not all(t.available for t in checked.tools):
        reasons.append("review_tool_unavailable")
    return reasons


def check_review(ctx: Context) -> LinkResult:
    res = LinkResult("review")
    review = ctx.doc["review"]
    if review is None:
        res.present = False
        return res
    ref = review["review_report"]
    try:
        data = mf.read_below(ctx.root, ref["locator"], MAX_REVIEW_REPORT_BYTES)
    except mf.ReadError as exc:
        res.add("review_artifact_missing" if exc.kind == "missing" else "review_report_invalid")
        return res
    if _sha(data) != ref["sha256"]:
        res.add("review_digest_mismatch")
    try:
        obj = mf.strict_json(data)
    except ValueError:
        res.add("review_report_invalid")
        return res
    checked = reportcheck.check_report(obj)
    if not isinstance(checked, reportcheck.CheckedReport) or checked.integrity_failures or checked.schema_version != "1.0.0":
        res.add("review_report_invalid")
        return res
    for code in review_evidence_complete(checked):
        res.add(code)
    raw_findings = obj["findings"]
    contract_resource = _contract_resource(ctx)
    matches: List[bool] = []
    for ref_f in review["finding_refs"]:
        found = [f for f in raw_findings if isinstance(f, dict) and f.get("ID") == ref_f["finding_id"] and not isinstance(f.get("ID"), bool)]
        if len(found) != 1:
            res.add("finding_missing")
            continue
        raw = found[0]
        if mf.canonical_sha256(raw) != ref_f["finding_sha256"]:
            res.add("finding_digest_mismatch")
        if identity_key_sha256(raw) != ref_f["identity_key_sha256"]:
            res.add("identity_key_mismatch")
        if contract_resource is not None:
            matches.append(raw.get("Resource") == contract_resource)
    if contract_resource is not None and matches:
        res.observed["finding_resource_matches_contract"] = all(matches)
    return res


def _contract_resource(ctx: Context) -> Optional[str]:
    if ctx.contract_bytes is None:
        return None
    try:
        return contract_mod.parse_contract_bytes(ctx.contract_bytes).resource
    except Exception:  # noqa: BLE001 - an unusable contract only removes the observation
        return None


# ---------------------------------------------------------------------------
# verification
# ---------------------------------------------------------------------------

def identity_diagnostic(claimed: Dict[str, Any], recomputed: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Whether the report's validator identity equals the recomputation's. A diagnostic: it never changes a status.

    The identity names the environment (plugin source digest, Python version), so it is kept out of the
    deterministic payload (the validator puts it in the result's metadata). Equal identities do not make the
    claim authentic, and different ones do not show that the two implementations differ in behaviour.
    """
    entry: Dict[str, Any] = {"link": "verification", "authenticity": st.NOT_PROVEN, "implementation_equivalence": st.NOT_PROVEN}
    if recomputed is None:
        entry.update(code="validator_identity_not_compared", fields=[])
        return entry
    fields = sorted(k for k in VALIDATOR_KEYS if claimed.get(k) != recomputed.get(k))
    entry.update(code="validator_identity_differs" if fields else "validator_identity_matches", fields=fields)
    return entry


def recompute(ctx: Context) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Run the Phase 1 verification again for the manifest's subject and contract. (payload, unavailable reason)."""
    assert ctx.repo is not None and ctx.report is not None
    payload = ctx.report["payload"]
    claimed_repo = payload["subject"].get("repository_id")
    mode = payload.get("execution_mode")
    req = verify.Request(
        repo=ctx.repo,
        base=ctx.doc["subject"]["base_commit"],
        head=ctx.doc["subject"]["head_commit"],
        config_rev=ctx.doc["contract"]["config_commit"],
        contract_path=ctx.doc["contract"]["contract_path"],
        contract_file=None,
        execution_mode=mode if mode in rschema.EXECUTION_MODES else "local_preview",
        repository_id=claimed_repo if isinstance(claimed_repo, str) and _REPOSITORY.match(claimed_repo) else None,
    )
    result = verify.run(req)
    again = remediation_report.build_payload(result)
    if any(t.get("state") != "PASS" for t in again["tools"]) or not again["tools"]:
        return None, "tool"
    if any(d.get("code") == "internal_error" for d in again["diagnostics"]):
        return None, "internal_error"
    return again, None


def check_verification(ctx: Context, loaded: LinkResult) -> LinkResult:
    res = loaded  # codes from load_report
    if ctx.report is None:
        return res
    payload = ctx.report["payload"]
    if mf.canonical_sha256(payload) != ctx.doc["verification"]["payload_sha256"]:
        res.add("payload_digest_mismatch")
    subject = payload["subject"]
    if ((subject.get("base") or {}).get("commit") != ctx.doc["subject"]["base_commit"]
            or (subject.get("head") or {}).get("commit") != ctx.doc["subject"]["head_commit"]):
        res.add("report_subject_mismatch")
    res.observed["decision"] = payload["decision"]
    res.observed["execution_mode"] = payload["execution_mode"]
    res.observed["validator_identity"] = st.NOT_PROVEN  # constant: the claim is never authenticated
    if ctx.repo is None:
        res.add("recompute_unavailable")
        res.diagnostics.append(identity_diagnostic(payload[_VALIDATOR_KEY], None))
        return res
    again, unavailable = recompute(ctx)
    res.diagnostics.append(identity_diagnostic(payload[_VALIDATOR_KEY], again[_VALIDATOR_KEY] if again is not None else None))
    if again is None:
        res.add("recompute_unavailable")
        return res
    mine = {k: v for k, v in payload.items() if k != _VALIDATOR_KEY}
    theirs = {k: v for k, v in again.items() if k != _VALIDATOR_KEY}
    if remediation_report.canonical(mine) != remediation_report.canonical(theirs):
        res.add("payload_digest_mismatch")
    return res


# ---------------------------------------------------------------------------
# gate (WP2)
# ---------------------------------------------------------------------------


def check_gate(ctx: Context) -> LinkResult:
    """WP1: never LINKED. No record is INCOMPLETE (gate_record_missing); records are not evaluated yet."""
    res = LinkResult("gate")
    if not ctx.doc["gate_records"]:
        res.add("gate_record_missing")
    else:
        res.add("gate_evaluation_not_implemented")
    return res


# ---------------------------------------------------------------------------
# github (M1 store)
# ---------------------------------------------------------------------------


def check_github(ctx: Context) -> LinkResult:
    res = LinkResult("github")
    gh = ctx.doc["github_evidence"]
    if gh is None:
        res.present = False
        return res
    res.observed["capture_authenticity"] = "NOT_PROVEN"
    try:
        store_dir = mf.directory_below(ctx.root, gh["store_locator"])
    except mf.ReadError:
        res.add("evidence_id_missing")
        return res
    if store_dir is None:
        res.add("evidence_id_missing")
        return res
    try:
        store = m1_store.EvidenceStore(store_dir, ctx.root)
        report = store.verify()
    except (m1_store.StoreError, OSError):
        res.add("integrity_not_pass")
        return res
    revision = next((r for r in report.revisions if r.revision_id == gh["revision"]), None)
    if revision is None:
        res.add("evidence_id_missing")
        return res
    if revision.manifest_sha256 != gh["manifest_sha256"]:
        res.add("store_manifest_mismatch")
    ids = list(gh["evidence_ids"])
    for eid in ids:
        holder = report.located(eid)
        if holder is None:
            res.add("evidence_id_missing")
        elif holder.revision_id != gh["revision"]:
            res.add("store_manifest_mismatch")
        else:
            repo = holder.envelopes[eid].get("repository")
            if not isinstance(repo, str) or repository_id(repo) != ctx.doc["repository_id"]:
                res.add("repository_mismatch")
    result = m1_integrity.validate(store, ids, m1_integrity.Requirement("API", None, True), report)
    if result["overall_status"] != "PASS":
        checks = {c["check_id"]: c for c in result["checks"]}
        if "named_evidence_missing" in checks["W1"]["reason_codes"]:
            res.add("evidence_id_missing")
        if checks["V5"]["status"] != "PASS":
            res.add("capture_incomplete")
        only_missing = set(checks["W1"]["reason_codes"]) <= {"named_evidence_missing"}
        others = [c for cid, c in checks.items()
                  if cid not in ("V5", "V9") and not (cid == "W1" and only_missing) and c["status"] not in ("PASS", "NOT_APPLICABLE")]
        if others or not (set(res.codes) & {"evidence_id_missing", "capture_incomplete"}):
            res.add("integrity_not_pass")
    return res
