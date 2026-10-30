"""One verification: trust binding, snapshots, boundary, checks, decision.

:func:`run` never raises for bad input: every failure becomes a diagnostic with
a closed code, and the caller gets a :class:`Result` that ``report`` turns into
a Remediation_Verification_Report. Order matters (Design 3): trusted inputs are
established before anything from the candidate is compared, so an unapproved
contract or a forged artefact cannot be the basis of a BLOCKED either.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from iacreview import deltaio, semdiff, template
from iacreview.remediation import boundary, checks, decide, gitsnap, profiles, rschema
from iacreview.remediation.boundary import Finding
from iacreview.remediation.contract import Contract, ContractError, bind_profile, parse_contract_bytes


@dataclass(frozen=True)
class Request:
    repo: Path
    base: str
    head: Optional[str]  # None: worktree preview
    config_rev: Optional[str]
    contract_path: Optional[str]  # inside config_rev
    contract_file: Optional[Path]  # a draft on disk
    execution_mode: str = "local_preview"
    repository_id: Optional[str] = None


@dataclass
class Side:
    commit: Optional[str] = None
    tree: Optional[str] = None
    snapshot_sha256: Optional[str] = None
    kind: str = "commit"
    blob: Optional[str] = None
    template_sha256: Optional[str] = None
    template_format: Optional[str] = None
    raw: Optional[bytes] = field(default=None, repr=False)


@dataclass
class Result:
    request: Request
    findings: List[Finding] = field(default_factory=list)
    contract: Optional[Contract] = None
    profile: Optional[profiles.Profile] = None
    contract_source: Optional[str] = None
    contract_sha256: Optional[str] = None
    config_commit: Optional[str] = None
    base: Side = field(default_factory=Side)
    head: Side = field(default_factory=Side)
    snapshot_notes: List[str] = field(default_factory=list)
    tools: List[checks.ToolIdentity] = field(default_factory=list)
    check_runs: List[checks.CheckRun] = field(default_factory=list)
    outcomes: List[Dict[str, Any]] = field(default_factory=list)
    invariants: List[Dict[str, Any]] = field(default_factory=list)
    task_outcome: str = "not_evaluated"
    decision: str = rschema.ERROR
    stage_reached: str = "start"

    def add(self, code: str, scope: str = "verification", path: Tuple[object, ...] = (), detail: Optional[str] = None) -> None:
        self.findings.append(Finding(code, scope, path, detail))

    @property
    def codes(self) -> List[str]:
        return decide.sorted_codes(f.code for f in self.findings)


class _Stop(Exception):
    """Ends the pipeline early; the diagnostics are already recorded."""


def _sha(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Stages
# ---------------------------------------------------------------------------


def _load_contract(res: Result, repo: Path) -> None:
    req = res.request
    if req.contract_file is not None:
        res.contract_source = "draft_file"
        try:
            path = req.contract_file.resolve(strict=True)
            if not path.is_file():
                raise OSError
            raw = path.read_bytes()[: rschema.MAX_CONTRACT_BYTES + 1]
        except (OSError, RuntimeError):
            res.add("contract_not_found", "contract")
            raise _Stop() from None
    else:
        res.contract_source = "git_revision"
        assert req.config_rev is not None and req.contract_path is not None
        res.config_commit = gitsnap.resolve_commit(repo, req.config_rev)
        snap = gitsnap.commit_snapshot(repo, res.config_commit)
        entry = snap.entries.get(req.contract_path)
        if entry is None or entry.mode != gitsnap.MODE_FILE:
            res.add("contract_not_found", "contract")
            raise _Stop()
        raw = gitsnap.read_blob(repo, entry.oid, rschema.MAX_CONTRACT_BYTES) or b"\x00" * (rschema.MAX_CONTRACT_BYTES + 1)
    res.contract_sha256 = _sha(raw)
    try:
        contract = parse_contract_bytes(raw)
        res.profile = bind_profile(contract, profiles.load_all())
    except ContractError as exc:
        res.add(exc.code, "contract", (exc.field,), exc.reason)
        raise _Stop() from None
    res.contract = contract


def _bind(res: Result, repo: Path) -> Tuple[gitsnap.Snapshot, gitsnap.Snapshot]:
    req = res.request
    base_commit = gitsnap.resolve_commit(repo, req.base)
    head_commit = gitsnap.resolve_commit(repo, req.head if req.head is not None else "HEAD")
    res.base.commit = base_commit
    if res.config_commit is not None and not gitsnap.is_ancestor(repo, res.config_commit, base_commit):
        res.add("config_not_ancestor_of_base", "trust")
    if not gitsnap.is_ancestor(repo, base_commit, head_commit):
        res.add("base_not_ancestor_of_head", "trust")
    if any(f.scope == "trust" for f in res.findings):
        raise _Stop()
    res.stage_reached = "trust_established"
    base_snap = gitsnap.commit_snapshot(repo, base_commit)
    res.base.tree = base_snap.tree
    res.base.snapshot_sha256 = base_snap.digest
    if req.head is None:
        head_snap = gitsnap.worktree_snapshot(repo)
        res.head.kind = "worktree"
        res.head.commit = None
        res.snapshot_notes = list(head_snap.notes)
        res.snapshot_notes.append("worktree_parent:" + head_commit)
    else:
        head_snap = gitsnap.commit_snapshot(repo, head_commit)
        res.head.commit = head_commit
        res.head.tree = head_snap.tree
    res.head.snapshot_sha256 = head_snap.digest
    return base_snap, head_snap


def _read_target(res: Result, repo: Path, snap: gitsnap.Snapshot, side: Side, name: str) -> Optional[deltaio.ParsedTemplate]:
    assert res.contract is not None
    entry = snap.entries.get(res.contract.template_path)
    if entry is None or entry.mode not in gitsnap.REGULAR_MODES:
        return None
    limit = template.MAX_TEMPLATE_BYTES
    if snap.kind == "commit":
        data = gitsnap.read_blob(repo, entry.oid, limit)
    else:
        data = gitsnap.read_worktree_file(repo, res.contract.template_path, limit)
        if data is not None and _blob_id(repo, data) != entry.oid:
            res.add("snapshot_changed", "snapshot")
            return None
    side.blob = entry.oid
    if data is None:
        res.add("template_not_comparable", "template", (), name)
        return None
    side.template_sha256 = _sha(data)
    side.raw = data
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        res.add("template_not_comparable", "template", (), name)
        return None
    parsed = deltaio.parse_template(text, Path(res.contract.template_path), name)
    if isinstance(parsed, deltaio.Failure):
        res.add("template_not_comparable", "template", (), name)
        return None
    side.template_format = parsed.fmt
    return parsed


def _blob_id(repo: Path, data: bytes) -> str:
    import hashlib

    fmt = gitsnap.object_format(repo)
    h = hashlib.sha1() if fmt == "sha1" else hashlib.sha256()  # noqa: S324 - git object id
    h.update(b"blob " + str(len(data)).encode("ascii") + b"\x00" + data)
    return h.hexdigest()


def _statements(doc: Any, resource: str, sid: str) -> Optional[List[str]]:
    """Canonical JSON of each statement with ``sid`` in the Role's inline Policies."""
    try:
        policies = doc["Resources"][resource]["Properties"]["Policies"]
    except (KeyError, TypeError):
        return []
    found: List[str] = []
    if not isinstance(policies, list):
        return None
    for policy in policies:
        statements = policy.get("PolicyDocument", {}).get("Statement") if isinstance(policy, dict) else None
        if isinstance(statements, dict):
            statements = [statements]
        if not isinstance(statements, list):
            continue
        for statement in statements:
            if isinstance(statement, dict) and statement.get("Sid") == sid:
                try:
                    found.append(json.dumps(statement, sort_keys=True, ensure_ascii=True, separators=(",", ":")))
                except (TypeError, ValueError):
                    return None
    return found


def _checks(res: Result, base: deltaio.ParsedTemplate, head: Optional[deltaio.ParsedTemplate], head_bytes_fmt: Tuple[bytes, str]) -> None:
    assert res.contract is not None and res.profile is not None
    contract, profile = res.contract, res.profile
    lint = checks.identify(checks.CFN_LINT, profile.tools[checks.CFN_LINT])
    guard = checks.identify(checks.CFN_GUARD, profile.tools[checks.CFN_GUARD])
    res.tools = [lint, guard]
    for tool in res.tools:
        if tool.state != rschema.CHECK_PASS:
            res.add(checks.STATE_CODES[tool.state], "check", (tool.name,))
    names = {profile.outcomes[o] for o in contract.required_outcomes}
    for invariant_id in contract.preserve_invariants:
        guard_rule = profile.invariants[invariant_id].guard_rule
        if guard_rule is not None:
            names.add(guard_rule)
    rule_names = sorted(names)
    runs: Dict[str, checks.CheckRun] = {}
    for side_name, parsed in (("base", base), ("head", head)):
        if parsed is None:
            run = checks.CheckRun("profile-guard", side_name)
            run.rule_states = {n: "NOT_RUN" for n in rule_names}
        else:
            try:
                data = checks.projection(parsed.doc, contract.resource, contract.parameters)
            except (TypeError, ValueError):
                run = checks.CheckRun("profile-guard", side_name, state="NOT_RUN")
                res.add("comparison_incomplete", "check", ("profile-guard",), side_name)
            else:
                run = checks.run_guard(guard, profile.rules_path, data, rule_names, side_name)
        runs[side_name] = run
        res.check_runs.append(run)
    if head is not None:
        lint_run = checks.run_cfn_lint(lint, head_bytes_fmt[0], head_bytes_fmt[1], "head")
    else:
        lint_run = checks.CheckRun("cfn-lint", "head")
    res.check_runs.append(lint_run)
    if lint_run.state == rschema.CHECK_FAIL:
        res.add("check_failed", "check", ("cfn-lint",))
    elif lint_run.state != rschema.CHECK_PASS:
        res.add(checks.STATE_CODES[lint_run.state], "check", ("cfn-lint",))
    for run in runs.values():
        if run.state not in (rschema.CHECK_PASS, rschema.CHECK_FAIL):
            res.add(checks.STATE_CODES.get(run.state, "tool_failed"), "check", ("profile-guard",), run.side)

    pairs = []
    for outcome_id in contract.required_outcomes:
        rule = profile.outcomes[outcome_id]
        b = checks.rule_state(runs["base"], rule)
        h = checks.rule_state(runs["head"], rule)
        pairs.append((b, h))
        res.outcomes.append({"outcome_id": outcome_id, "base": b, "head": h})
        if h == rschema.CHECK_FAIL:
            res.add("outcome_not_achieved", "outcome", (outcome_id,))
        elif h != rschema.CHECK_PASS or b not in (rschema.CHECK_PASS, rschema.CHECK_FAIL):
            res.add("outcome_not_evaluated", "outcome", (outcome_id,))
    res.task_outcome = decide.task_outcome(pairs)

    for invariant_id in contract.preserve_invariants:
        inv = profile.invariants[invariant_id]
        if inv.kind == "boundary":
            blocked = any(rschema.CODES[f.code][0] == rschema.BLOCKED and f.scope in ("repository", "template") for f in res.findings)
            incomplete = any(f.code in ("comparison_incomplete", "unsupported_construct", "template_not_comparable") for f in res.findings)
            head_state = rschema.CHECK_FAIL if blocked else ("NOT_EVALUATED" if incomplete or head is None else rschema.CHECK_PASS)
            res.invariants.append({"invariant_id": invariant_id, "base": rschema.CHECK_PASS, "head": head_state})
            continue
        assert inv.guard_rule is not None
        b = checks.rule_state(runs["base"], inv.guard_rule)
        h = checks.rule_state(runs["head"], inv.guard_rule)
        sid = contract.parameters.get("required_statement_sid", "")
        base_statements = _statements(base.doc, contract.resource, sid)
        head_statements = _statements(head.doc, contract.resource, sid) if head is not None else None
        if b == rschema.CHECK_PASS and base_statements is not None and len(base_statements) != 1:
            b = rschema.CHECK_FAIL
        if h == rschema.CHECK_PASS and (head_statements is None or head_statements != base_statements):
            h = rschema.CHECK_FAIL
        res.invariants.append({"invariant_id": invariant_id, "base": b, "head": h})
        if b == rschema.CHECK_FAIL:
            res.add("invariant_failed_on_base", "invariant", (invariant_id,))
        elif b == rschema.CHECK_PASS and h == rschema.CHECK_FAIL:
            res.add("invariant_violated", "invariant", (invariant_id,))
        elif h != rschema.CHECK_PASS or b != rschema.CHECK_PASS:
            res.add("outcome_not_evaluated", "invariant", (invariant_id,))


def run(req: Request) -> Result:
    res = Result(req)
    try:
        repo = gitsnap.check_repo(req.repo)
        _load_contract(res, repo)
        res.stage_reached = "contract_loaded"
        base_snap, head_snap = _bind(res, repo)
        assert res.contract is not None and res.profile is not None
        res.findings.extend(boundary.repository(res.contract, base_snap, head_snap))
        base_t = _read_target(res, repo, base_snap, res.base, "base")
        head_t = _read_target(res, repo, head_snap, res.head, "head")
        res.stage_reached = "boundary_checked"
        if base_t is not None and head_t is not None:
            diff = semdiff.diff(base_t, head_t)
            if isinstance(diff, deltaio.Failure):
                res.add("template_not_comparable", "template", (), "change_entry_limit")
            else:
                res.findings.extend(boundary.template(res.contract, res.profile.resource_type, base_t, head_t, diff))
        if base_t is not None:
            _checks(res, base_t, head_t, (res.head.raw or b"", res.head.template_format or "yaml"))
            res.stage_reached = "checks_run"
        if head_snap.kind == "worktree" and gitsnap.worktree_snapshot(repo).digest != head_snap.digest:
            res.add("snapshot_changed", "snapshot")
    except _Stop:
        pass
    except gitsnap.GitError as exc:
        res.add(exc.code if exc.code in rschema.CODES else "repository_unreadable", "git", (), exc.step)
    except profiles.ProfileError:
        res.add("internal_error", "validator", (), "profile")
    except Exception:  # noqa: BLE001 - fail closed without a traceback
        res.add("internal_error", "validator")
    decision = decide.decision_of(f.code for f in res.findings)
    if res.contract_source == "draft_file" and decision != rschema.ERROR:
        res.add("contract_not_approved", "trust")
        decision = decide.cap_for_draft(decide.decision_of(f.code for f in res.findings))
    res.decision = decision
    return res

