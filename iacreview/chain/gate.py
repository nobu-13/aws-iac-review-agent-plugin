"""Human Gate Records (Phase 2 M2 WP2): build them from raw evidence, check the presented ones, judge GV-1..GV-4.

Source: ``docs/v2/phase2/m2/wp0/m2-schemas.md`` rev2 §2 (records, evidence range, review aggregation, GV
rules), ``wp0-revision-2.md`` §8 (R2-1..R2-3). What this module shows is an observation of the raw GitHub
answers in the M1 store, nothing more:

* the records are regenerated from the raw bytes of the captures the chain manifest names (one revision,
  every page) and from git facts; a presented record is accepted only when it equals the regeneration, so
  a self-declared approval never counts;
* each presented record is judged on its own (``docs/v2/phase2/m2/wp2/wp2-gate-record-decision-table.md``):
  a contradiction the raw or the manifest shows is BROKEN, a record that is absent, left out or cannot be
  read is INCOMPLETE, a self-declaration is NOT_PROVEN, and a good record never hides a bad one;
* reviews are aggregated in two stages: per review id (checks, duplicates, conflicts, dismissal), then per
  reviewer, ordered by ``(submitted_at, id)`` and never by the API's array order; an order that cannot be
  shown is NOT_PROVEN;
* ``author_association`` is copied into a record as an observation and decides nothing;
* an account that differs from the PR author's is not shown to hold approval authority
  (``observed.approval_authority`` is always NOT_PROVEN); ruleset enforcement and the authenticity of the
  raw answers are never claimed (``status.NOT_CLAIMED``).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from iacreview.chain import links as lk
from iacreview.chain import manifest as mf
from iacreview.chain import status as st
from iacreview.evidence import integrity as m1_integrity
from iacreview.evidence import store as m1_store

RECORD_FORMAT = "iacreview.chain.gate_record/1"
MAX_RECORD_BYTES = 64 * 1024
ASPECTS = ("integrity", "account_separation", "revision_binding", "staleness")

STATES = ("APPROVED", "CHANGES_REQUESTED", "COMMENTED", "DISMISSED", "PENDING")
DECIDING = ("APPROVED", "CHANGES_REQUESTED")
SOURCE_TYPES = {"contract_approval": "git_ancestry", "candidate_review": "github_pull_review", "merge_decision": "github_pull"}
DECISIONS = {"contract_approval": ("approved",), "candidate_review": ("approved", "changes_requested", "none"),
             "merge_decision": ("merged", "closed_unmerged", "open")}
RELATIONS = ("distinct_actor", "same_actor", "unknown")
ASSOCIATIONS = ("OWNER", "MEMBER", "COLLABORATOR", "CONTRIBUTOR", "FIRST_TIMER", "FIRST_TIME_CONTRIBUTOR", "MANNEQUIN", "NONE")

_PULL = re.compile(r"^/repos/[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}/pulls/([0-9]{1,10})$")
_REVIEWS = re.compile(r"^/repos/[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}/pulls/([0-9]{1,10})/reviews(\?[A-Za-z0-9._~=&%,-]{0,400})?$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_STAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_ACTOR = re.compile(r"^u:[0-9a-f]{12}$")
_ITEM = re.compile(r"^(reviewer:u:[0-9a-f]{12}|pull:[0-9]{1,10}|git:[0-9a-f]{40})$")
_REVIEW_REF = re.compile(r"^review:[0-9]{1,20}$")
_EVIDENCE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{2,95}$")
_REVISION = re.compile(r"^rev-[0-9]{4}$")


def _int_id(value: Any) -> Optional[int]:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 1 else None


def actor_ref(user_id: int) -> str:
    """``u:`` + the first 12 hex digits of SHA-256(str(user id)): a pseudonym, not an anonymisation."""
    return "u:" + hashlib.sha256(str(user_id).encode("ascii")).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Raw captures (m2-schemas.md §2-1, E-1..E-7)
# ---------------------------------------------------------------------------


@dataclass
class Capture:
    capture_id: str
    kind: str  # "pull" or "reviews"
    number: int
    evidence_ids: List[str]  # page order
    raw_sha256: List[str]
    pages: List[bytes]


@dataclass
class Sources:
    """The gate's raw sources and the GV-1 codes their checks produced."""

    revision: Optional[str] = None
    pull: Optional[Capture] = None
    reviews: Optional[Capture] = None
    codes: List[str] = field(default_factory=list)

    def add(self, code: str) -> None:
        if code not in self.codes:
            self.codes.append(code)


def _endpoint_kind(endpoint: str) -> Optional[Tuple[str, int]]:
    m = _PULL.match(endpoint)
    if m:
        return "pull", int(m.group(1))
    m = _REVIEWS.match(endpoint)
    if m:
        return "reviews", int(m.group(1))
    return None


def page_sequence_problem(indexes: Sequence[Any], has_next: Sequence[Any]) -> Optional[str]:
    """E-5: page numbers 1..n without a repeat, ``has_next`` true on every page but the last. None when it holds."""
    if len(set(indexes)) != len(indexes):  # E-5 duplicate
        return "review_capture_duplicate"
    if list(indexes) != list(range(1, len(indexes) + 1)):  # E-5 gap
        return "review_capture_incomplete"
    if not has_next or has_next[-1] is not False or any(f is not True for f in has_next[:-1]):
        return "review_capture_incomplete"
    return None


def load_sources(ctx: lk.Context) -> Sources:
    """Read the pull and review captures among the manifest's evidence, checking E-1..E-7."""
    out = Sources()
    gh = ctx.doc["github_evidence"]
    if gh is None:
        return out
    out.revision = gh["revision"]
    try:
        store_dir = mf.directory_below(ctx.root, gh["store_locator"])
        if store_dir is None:
            raise mf.ReadError("missing")
        store = m1_store.EvidenceStore(store_dir, ctx.root)
        report = store.verify()
    except (mf.ReadError, m1_store.StoreError, OSError):
        out.add("gate_source_integrity_not_pass")
        return out
    revision = next((r for r in report.revisions if r.revision_id == gh["revision"]), None)
    if revision is None or revision.status != "VALID":
        out.add("gate_source_integrity_not_pass")
        return out
    listed = set(gh["evidence_ids"])
    groups: Dict[str, List[Tuple[str, Dict[str, Any]]]] = {}
    for eid, env in sorted(revision.envelopes.items()):
        groups.setdefault(str(env.get("capture_id")), []).append((eid, env))
    captures: Dict[str, List[Capture]] = {"pull": [], "reviews": []}
    for capture_id, members in sorted(groups.items()):
        named = [m for m in members if m[0] in listed]
        if not named:
            continue
        ordered = sorted(members, key=lambda m: (m[1]["page"]["index"] if isinstance(m[1].get("page"), dict) else 0, m[0]))
        first_endpoint = ordered[0][1]["api"]["endpoint"] if isinstance(ordered[0][1].get("api"), dict) else ""
        kind = _endpoint_kind(str(first_endpoint))
        if kind is None:
            continue
        if len(named) != len(members):  # E-4: a page of the capture is not named by the manifest
            out.add("review_capture_incomplete")
            continue
        problem = page_sequence_problem([m[1]["page"]["index"] for m in ordered], [m[1]["page"]["has_next"] for m in ordered])
        if problem is not None:  # E-5 (checked here even though M1 V5 also checks the page numbers)
            out.add(problem)
            continue
        if any(m[1].get("completeness_status") != "COMPLETE" or m[1].get("pagination_complete") is not True
               or m[1].get("http_status") != 200 for m in ordered):  # E-6
            out.add("review_capture_incomplete")
            continue
        pages = []
        for eid, _ in ordered:
            raw = store.read_raw(report, eid)
            if raw is None:
                out.add("gate_source_integrity_not_pass")
                break
            pages.append(raw)
        else:
            captures[kind[0]].append(Capture(capture_id, kind[0], kind[1], [m[0] for m in ordered],
                                             [str(m[1]["raw_content_sha256"]) for m in ordered], pages))
    gate_ids = [e for kind in captures.values() for c in kind for e in c.evidence_ids]
    if gate_ids:  # E-1
        result = m1_integrity.validate(store, gate_ids, m1_integrity.Requirement("API", None, True), report)
        if result["overall_status"] != "PASS":
            v5 = next(c for c in result["checks"] if c["check_id"] == "V5")
            out.add("review_capture_incomplete" if v5["status"] != "PASS" else "gate_source_integrity_not_pass")
            return out
    if len(captures["pull"]) > 1 or len(captures["reviews"]) > 1:
        out.add("gate_source_missing")  # ambiguous: two captures of the same kind
        return out
    out.pull = captures["pull"][0] if captures["pull"] else None
    out.reviews = captures["reviews"][0] if captures["reviews"] else None
    if out.pull is not None and out.reviews is not None and out.pull.number != out.reviews.number:  # E-7
        out.add("gate_source_missing")
        out.pull = out.reviews = None
    return out


def _json_pages(capture: Capture, want: type) -> Optional[List[Any]]:
    values: List[Any] = []
    for page in capture.pages:
        try:
            value = mf.strict_json(page)
        except ValueError:
            return None
        if want is list and isinstance(value, list):
            values.extend(value)
        elif want is dict and isinstance(value, dict):
            values.append(value)
        else:
            return None
    return values


# ---------------------------------------------------------------------------
# Review aggregation (m2-schemas.md §2-2)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Review:
    review_id: int
    state: str
    user_id: Optional[int]
    submitted_at: Optional[str]
    commit_id: Optional[str]
    author_association: Optional[str]

    @property
    def key(self) -> Tuple[str, int]:
        return (self.submitted_at or "", self.review_id)


@dataclass
class ReviewerState:
    user_id: int
    state: str  # approved, changes_requested, none
    deciding: Optional[Review]
    author_association: Optional[str]


@dataclass
class Aggregation:
    reviewers: Dict[int, ReviewerState] = field(default_factory=dict)
    integrity: List[str] = field(default_factory=list)  # GV-1 codes
    unknown_actor: bool = False
    usable: bool = True


def _review(raw: Any) -> Optional[Review]:
    if not isinstance(raw, dict):
        return None
    rid = _int_id(raw.get("id"))
    state = raw.get("state")
    submitted = raw.get("submitted_at")
    commit = raw.get("commit_id")
    if rid is None or state not in STATES:
        return None
    if submitted is None:
        if state != "PENDING":
            return None
    elif not (isinstance(submitted, str) and _STAMP.match(submitted)):
        return None
    if commit is not None and not (isinstance(commit, str) and _COMMIT.match(commit)):
        return None
    user = raw.get("user")
    uid = _int_id(user.get("id")) if isinstance(user, dict) else None
    assoc = raw.get("author_association")
    return Review(rid, state, uid, submitted, commit, assoc if assoc in ASSOCIATIONS else None)


def aggregate(raw_reviews: Sequence[Any]) -> Aggregation:
    """Stage A per review id, stage B per reviewer. The input order does not matter."""
    agg = Aggregation()
    by_id: Dict[int, Tuple[bytes, Review]] = {}
    for raw in raw_reviews:
        review = _review(raw)
        if review is None:
            agg.integrity.append("gate_source_unrecognized")
            agg.usable = False
            continue
        canon = mf.canonical_sha256(raw).encode("ascii")
        seen = by_id.get(review.review_id)
        if seen is not None:
            agg.integrity.append("review_capture_duplicate" if seen[0] == canon else "review_conflict")
            agg.usable = False
            continue
        by_id[review.review_id] = (canon, review)
    if not agg.usable:
        return agg
    per_user: Dict[int, List[Review]] = {}
    for _, review in sorted(by_id.values(), key=lambda x: x[1].review_id):
        if review.state == "PENDING":
            continue  # not submitted (stage A)
        if review.user_id is None:
            if review.state in DECIDING:
                agg.unknown_actor = True
            continue
        per_user.setdefault(review.user_id, []).append(review)
    for uid, reviews in sorted(per_user.items()):
        agg.reviewers[uid] = _reviewer_state(uid, reviews, agg)
    return agg


def _reviewer_state(uid: int, reviews: List[Review], agg: Aggregation) -> ReviewerState:
    ordering = [r for r in reviews if r.state in DECIDING or r.state == "DISMISSED"]
    latest_assoc = max(reviews, key=lambda r: r.key).author_association  # observation only; reviews is never empty
    none = ReviewerState(uid, "none", None, latest_assoc)
    by_time: Dict[str, List[Review]] = {}
    for r in ordering:
        by_time.setdefault(r.submitted_at or "", []).append(r)
    for group in by_time.values():
        states = {r.state for r in group}
        if len(states) > 1:  # R-10, R-23
            agg.integrity.append("review_order_ambiguous")
            return none
    for a in ordering:
        for b in ordering:
            if (a.submitted_at or "") < (b.submitted_at or "") and a.review_id > b.review_id:  # R-12
                agg.integrity.append("review_order_inconsistent")
                return none
    deciding = sorted((r for r in ordering if r.state in DECIDING), key=lambda r: r.key)
    if not deciding:
        return none
    last = deciding[-1]
    if any(r.state == "DISMISSED" and r.key > last.key for r in ordering):  # R-20
        agg.integrity.append("review_dismissal_effect_unknown")
        return none
    decided = "approved" if last.state == "APPROVED" else "changes_requested"
    return ReviewerState(uid, decided, last, last.author_association)


# ---------------------------------------------------------------------------
# Records (m2-schemas.md §2)
# ---------------------------------------------------------------------------


@dataclass
class Facts:
    """Everything regenerated from the raw sources and git: the records and what GV-2..GV-4 need."""

    records: Dict[Tuple[str, str], Dict[str, Any]] = field(default_factory=dict)
    aggregation: Optional[Aggregation] = None
    pr_author: Optional[int] = None
    pr_head: Optional[str] = None
    pr_seen: bool = False
    merge_decision: Optional[str] = None
    #: Kinds whose raw capture was found in the evidence range (contract_approval: git, always).
    loaded: List[str] = field(default_factory=lambda: ["contract_approval"])
    #: Kinds whose raw evidence was read completely, so every record of that kind is regenerated: a presented
    #: record without a regenerated twin then contradicts the raw (decision table G-09).
    complete: List[str] = field(default_factory=lambda: ["contract_approval"])


def _record(kind: str, decision: str, source: Dict[str, Any], commit: Optional[str], role: str,
            actor: Dict[str, Any], deciding: Optional[str], observed_at: Optional[str]) -> Dict[str, Any]:
    return {"record_format": RECORD_FORMAT, "kind": kind, "decision": decision, "source": source,
            "binds_to": {"commit": commit, "role": role}, "actor": actor, "deciding_review_ref": deciding,
            "observed_at": observed_at}


def _source(kind: str, revision: Optional[str], capture: Optional[Capture], item_ref: str) -> Dict[str, Any]:
    if capture is None:
        return {"type": SOURCE_TYPES[kind], "store_revision": None, "capture_id": None, "evidence_ids": None,
                "raw_sha256": None, "item_ref": item_ref}
    return {"type": SOURCE_TYPES[kind], "store_revision": revision, "capture_id": capture.capture_id,
            "evidence_ids": list(capture.evidence_ids), "raw_sha256": list(capture.raw_sha256), "item_ref": item_ref}


def _relation(user_id: int, pr_author: Optional[int]) -> str:
    """The reviewer's relation to the PR author (R2-3): unknown without a valid author id."""
    if pr_author is None:
        return "unknown"
    if user_id == pr_author:
        return "same_actor"
    return "distinct_actor"


def build(doc: Dict[str, Any], sources: Sources) -> Facts:
    """Regenerate every gate record from the raw sources and the manifest's config commit (deterministic)."""
    facts = Facts()
    config = doc["contract"]["config_commit"]
    facts.records[("contract_approval", "git:" + config)] = _record(
        "contract_approval", "approved", _source("contract_approval", None, None, "git:" + config), config, "config",
        {"actor_ref": None, "relation_to_head_author": "unknown", "author_association": None}, None, None)
    pull_obj: Optional[Dict[str, Any]] = None
    if sources.pull is not None:
        facts.loaded.append("merge_decision")
        values = _json_pages(sources.pull, dict)
        if values is None or len(values) != 1:
            sources.add("review_capture_incomplete")
        else:
            pull_obj = values[0]
    if pull_obj is not None:
        facts.pr_seen = True
        user = pull_obj.get("user")
        facts.pr_author = _int_id(user.get("id")) if isinstance(user, dict) else None
        head = pull_obj.get("head")
        sha = head.get("sha") if isinstance(head, dict) else None
        facts.pr_head = sha if isinstance(sha, str) and _COMMIT.match(sha) else None
        merged, state = pull_obj.get("merged"), pull_obj.get("state")
        decision = "merged" if merged is True else ("closed_unmerged" if state == "closed" else ("open" if state == "open" else None))
        if decision is not None and sources.pull is not None:
            facts.complete.append("merge_decision")
            facts.merge_decision = decision
            ref = "pull:{0}".format(sources.pull.number)
            facts.records[("merge_decision", ref)] = _record(
                "merge_decision", decision, _source("merge_decision", sources.revision, sources.pull, ref), facts.pr_head, "head",
                {"actor_ref": None, "relation_to_head_author": "unknown", "author_association": None}, None,
                pull_obj.get("merged_at") if isinstance(pull_obj.get("merged_at"), str) and _STAMP.match(pull_obj["merged_at"]) else None)
        elif decision is None:
            sources.add("gate_source_unrecognized")
    if sources.reviews is not None:
        facts.loaded.append("candidate_review")
        values = _json_pages(sources.reviews, list)
        if values is None:
            sources.add("review_capture_incomplete")
            return facts
        agg = aggregate(values)
        facts.aggregation = agg
        if not agg.usable:
            return facts
        facts.complete.append("candidate_review")
        for uid, state in sorted(agg.reviewers.items()):
            ref = actor_ref(uid)
            relation = _relation(uid, facts.pr_author)
            deciding = state.deciding
            facts.records[("candidate_review", "reviewer:" + ref)] = _record(
                "candidate_review", state.state, _source("candidate_review", sources.revision, sources.reviews, "reviewer:" + ref),
                deciding.commit_id if deciding else None, "head",
                {"actor_ref": ref, "relation_to_head_author": relation, "author_association": state.author_association},
                "review:{0}".format(deciding.review_id) if deciding else None, deciding.submitted_at if deciding else None)
    return facts


def record_schema_ok(rec: Any) -> bool:
    """A record in the closed schema (types and vocabularies). Content is compared with the regeneration later."""
    try:
        if not isinstance(rec, dict) or set(rec) != {"record_format", "kind", "decision", "source", "binds_to", "actor",
                                                     "deciding_review_ref", "observed_at"}:
            return False
        kind = rec["kind"]
        if rec["record_format"] != RECORD_FORMAT or kind not in SOURCE_TYPES or rec["decision"] not in DECISIONS[kind]:
            return False
        src, binds, actor = rec["source"], rec["binds_to"], rec["actor"]
        if not isinstance(src, dict) or set(src) != {"type", "store_revision", "capture_id", "evidence_ids", "raw_sha256", "item_ref"}:
            return False
        if src["type"] != SOURCE_TYPES[kind] or not (isinstance(src["item_ref"], str) and _ITEM.match(src["item_ref"])):
            return False
        git = kind == "contract_approval"
        for key in ("store_revision", "capture_id", "evidence_ids", "raw_sha256"):
            if git != (src[key] is None):
                return False
        if not git:
            if not (isinstance(src["store_revision"], str) and _REVISION.match(src["store_revision"])):
                return False
            if not (isinstance(src["capture_id"], str) and _EVIDENCE_ID.match(src["capture_id"])):
                return False
            ids, shas = src["evidence_ids"], src["raw_sha256"]
            if not (isinstance(ids, list) and ids and all(isinstance(i, str) and _EVIDENCE_ID.match(i) for i in ids)):
                return False
            if not (isinstance(shas, list) and len(shas) == len(ids) and all(isinstance(s, str) and _SHA256.match(s) for s in shas)):
                return False
        if not isinstance(binds, dict) or set(binds) != {"commit", "role"} or binds["role"] not in ("head", "config"):
            return False
        if binds["commit"] is not None and not (isinstance(binds["commit"], str) and _COMMIT.match(binds["commit"])):
            return False
        if not isinstance(actor, dict) or set(actor) != {"actor_ref", "relation_to_head_author", "author_association"}:
            return False
        if actor["actor_ref"] is not None and not (isinstance(actor["actor_ref"], str) and _ACTOR.match(actor["actor_ref"])):
            return False
        if actor["relation_to_head_author"] not in RELATIONS or actor["author_association"] not in ASSOCIATIONS + (None,):
            return False
        if rec["deciding_review_ref"] is not None and not (isinstance(rec["deciding_review_ref"], str) and _REVIEW_REF.match(rec["deciding_review_ref"])):
            return False
        return rec["observed_at"] is None or (isinstance(rec["observed_at"], str) and bool(_STAMP.match(rec["observed_at"])))
    except (KeyError, TypeError):
        return False


# ---------------------------------------------------------------------------
# GV-1..GV-4 (m2-schemas.md §2-4)
# ---------------------------------------------------------------------------


#: Top-level keys that name an approver in a self-declaration (exact, lower case; decision table G-05).
APPROVER_KEYS = ("approved_by", "approver", "approvers")


def states_an_approval(value: Any) -> bool:
    """A self-declaration (G-05): a JSON object outside the schema that states an approval in one of three forms.

    ``decision`` is the string ``"approved"``; ``approved`` is ``true``; or a key of :data:`APPROVER_KEYS`
    holds a non-empty string or a non-empty list. Any other wording (other keys, other case, free text) is
    not read as an approval: the record is a schema violation (G-04), which is never weaker than this.
    Used only on records that already failed :func:`record_schema_ok`; it never makes a record count.
    """
    if not isinstance(value, dict):
        return False
    if value.get("decision") == "approved" or value.get("approved") is True:
        return True
    return any(isinstance(value.get(k), (str, list)) and len(value[k]) > 0 for k in APPROVER_KEYS)


@dataclass
class Presented:
    """The presented records, read entry by entry. Each anomalous entry leaves exactly one cause code."""

    good: List[Tuple[Dict[str, Any], Dict[str, Any]]] = field(default_factory=list)  # (manifest entry, record)
    codes: List[str] = field(default_factory=list)  # GV-1
    self_declared: bool = False
    #: Entries that could not be used (G-02, G-03, G-04, G-06), counted by the manifest's ``kind``: each may be
    #: the regenerated record of that kind, so it accounts for one record left out (G-13, secondary).
    unusable: Dict[str, int] = field(default_factory=dict)

    def refuse(self, entry: Dict[str, Any], code: str) -> None:
        self.codes.append(code)
        kind = str(entry.get("kind"))
        self.unusable[kind] = self.unusable.get(kind, 0) + 1


def _read_presented(ctx: lk.Context) -> Presented:
    """Read every record the manifest names (decision table: ``wp2-gate-record-decision-table.md`` G-02..G-07)."""
    out = Presented()
    keys = set()
    for entry in ctx.doc["gate_records"]:
        try:
            data = mf.read_below(ctx.root, entry["locator"], MAX_RECORD_BYTES)
        except mf.ReadError as exc:  # G-02 absent; G-04 not a regular file, too large, unreadable
            out.refuse(entry, "gate_record_missing" if exc.kind == "missing" else "gate_record_invalid")
            continue
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:  # G-03 changed after the manifest
            out.refuse(entry, "gate_record_mismatch")
            continue
        try:
            rec = mf.strict_json(data, mf.MAX_DEPTH)
        except ValueError:  # G-04
            out.refuse(entry, "gate_record_invalid")
            continue
        if not record_schema_ok(rec):
            if states_an_approval(rec):  # G-05 self-declaration (not counted as unusable: NOT_PROVEN is weaker)
                out.self_declared = True
            else:  # G-04
                out.refuse(entry, "gate_record_invalid")
            continue
        if rec["kind"] != entry["kind"]:  # G-06
            out.refuse(entry, "gate_record_mismatch")
            continue
        key = (rec["kind"], rec["source"]["item_ref"])
        if key in keys:  # G-07 one record per kind and item (§2: one candidate_review per reviewer); still compared
            out.codes.append("gate_record_invalid")
        keys.add(key)
        out.good.append((entry, rec))
    return out


def check(ctx: lk.Context) -> lk.LinkResult:
    res = lk.LinkResult("gate")
    aspects: Dict[str, List[str]] = {a: [] for a in ASPECTS}

    def add(aspect: str, code: str) -> None:
        if code not in aspects[aspect]:
            aspects[aspect].append(code)

    head = ctx.doc["subject"]["head_commit"]
    config = ctx.doc["contract"]["config_commit"]
    read = _read_presented(ctx)
    presented, self_declared = read.good, read.self_declared
    for code in read.codes:
        add("integrity", code)
    sources = load_sources(ctx)
    facts = build(ctx.doc, sources)
    for code in sources.codes:
        add("integrity", code)
    agg = facts.aggregation
    if agg is not None:
        for code in agg.integrity:
            add("integrity", code)

    # GV-1 (decision table G-01..G-12 in docs/v2/phase2/m2/wp2/wp2-gate-record-decision-table.md): every
    # presented record must be in the evidence range and equal the regeneration (a contradiction that the
    # raw shows is BROKEN); a record that cannot be checked or is left out is INCOMPLETE. Each record is
    # judged on its own, so a good record never hides a bad one.
    gh = ctx.doc["github_evidence"]
    listed = set(gh["evidence_ids"]) if gh else set()
    revision = gh["revision"] if gh else None
    presented_keys = set()
    contract_presented = False
    backed_approval = False
    for _, rec in presented:
        src = rec["source"]
        key = (rec["kind"], src["item_ref"])
        presented_keys.add(key)
        if rec["kind"] == "contract_approval":
            contract_presented = True
            if rec["binds_to"]["commit"] != config:
                add("revision_binding", "gate_binds_other_commit")
        elif src["store_revision"] != revision or not set(src["evidence_ids"]) <= listed:  # G-08 (E-2, E-3)
            add("integrity", "gate_source_missing")
            continue
        regenerated = facts.records.get(key)
        if regenerated is None:
            if rec["kind"] in facts.complete:  # G-09: the complete raw has no such item
                add("integrity", "gate_record_mismatch")
            elif rec["kind"] not in facts.loaded:  # G-10: no raw to check the record against
                add("integrity", "gate_source_missing")
            # G-11: the raw was found but cannot be read; its own code (E-6, R-13..R-15) is already there
            continue
        if mf.canonical_sha256(rec) != mf.canonical_sha256(regenerated):  # G-12
            add("integrity", "gate_record_mismatch")
            if rec["kind"] == "candidate_review" and rec["binds_to"]["commit"] != regenerated["binds_to"]["commit"]:
                add("revision_binding", "approval_revision_misrecorded")
        elif rec["kind"] == "candidate_review" and rec["decision"] == "approved":
            backed_approval = True
    left_out: Dict[str, int] = {}
    for key in facts.records:
        if key[0] != "contract_approval" and key not in presented_keys:
            left_out[key[0]] = left_out.get(key[0], 0) + 1
    for kind, count in sorted(left_out.items()):
        # G-13: left out, nothing contradicted. Up to one left-out record per unusable entry of the same kind
        # is the secondary effect of that entry's own (primary) code, at least as severe, and adds nothing.
        if count > read.unusable.get(kind, 0):  # G-13: left out, nothing contradicted
            add("integrity", "gate_record_missing")
    if self_declared:  # G-05, whatever the other records show
        add("integrity", "approval_self_declared_only")
    if not contract_presented:
        add("revision_binding", "gate_record_missing")

    # GV-2: account separation (an observation). The association GitHub reports is never read here.
    reviewers = list(agg.reviewers.values()) if agg is not None and agg.usable else []
    approved = [r for r in reviewers if r.state == "approved"]
    if any(r.state == "changes_requested" for r in reviewers):
        add("account_separation", "changes_requested_outstanding")
    if (agg is not None and agg.unknown_actor) or (approved and facts.pr_author is None):
        add("account_separation", "actor_relation_unknown")
    distinct = [r for r in approved if facts.pr_author is not None and r.user_id != facts.pr_author]
    if not approved:
        add("account_separation", "approval_not_shown")
    elif not distinct and facts.pr_author is not None:
        add("account_separation", "separation_of_duty_not_shown")

    # GV-3: revision binding of the counted approvals (R-2-1: an old approval is not counted, not BROKEN).
    if distinct:
        effective = [r for r in distinct if r.deciding is not None and r.deciding.commit_id == head]
        if not effective:
            if any(r.deciding is None or r.deciding.commit_id is None for r in distinct):
                add("revision_binding", "approval_revision_unverifiable")
            else:
                add("revision_binding", "approval_on_previous_head_only")

    # GV-4: the PR's head at capture time against the chain's head.
    if not facts.pr_seen or facts.pr_head is None:
        add("staleness", "approval_revision_unverifiable")
    elif facts.pr_head != head:
        add("staleness", "pr_head_mismatch")
    if self_declared and not backed_approval:  # an approval record the raw backs is the only alternative
        add("staleness", "approval_self_declared_only")

    for aspect in ASPECTS:
        for code in aspects[aspect]:
            res.add(code)
    res.aspects = aspects
    res.observed["approval_authority"] = st.NOT_PROVEN
    if facts.merge_decision is not None:
        res.observed["merge_decision"] = facts.merge_decision
    return res


def regenerate(manifest_path: Path) -> List[Dict[str, Any]]:
    """The gate records the raw evidence of a chain gives, in a stable order (for builders and tests)."""
    loaded = mf.load(Path(manifest_path))
    ctx = lk.Context(root=Path(manifest_path).parent, repo=None, doc=loaded.doc)
    facts = build(loaded.doc, load_sources(ctx))
    return [facts.records[k] for k in sorted(facts.records)]
