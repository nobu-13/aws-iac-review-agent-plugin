"""M2-08..M2-10: Human Gate Records, GV-1..GV-4 (Phase 2 M2 WP2).

Source: docs/v2/phase2/m2/wp0/m2-schemas.md rev2 §2-1..§2-6, m2-acceptance-test-matrix.md rev2 (TC-08-*,
TC-09-*, TC-10-*), wp0-revision-2.md §8 (R2-1..R2-3). The GitHub answers are synthetic, captured by the M1
collector with a fake transport into an M1 store; the chain is the frozen Phase 1 case C02. Most tests run
the gate check alone (no recomputation); TC-10-07 runs the whole validator.
"""

from __future__ import annotations

import copy
import inspect
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest

import chain_synth as cs
from iacreview.chain import gate
from iacreview.chain import links as lk
from iacreview.chain import manifest as mf
from iacreview.chain import status as st
from iacreview.chain import validator
from iacreview.evidence import collector

SUBJECT = json.loads((cs.FIXTURES / "sc02" / "subject.json").read_text(encoding="utf-8"))
HEAD, BASE = SUBJECT["head"], SUBJECT["base"]
OLD = "e" * 40
A, B, AUTHOR = cs.REVIEWER_A, cs.REVIEWER_B, cs.PR_AUTHOR
R = cs.review
T = cs.stamp


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    cs.block_network(monkeypatch)


def chain(tmp: Path, reviews: List[Dict[str, Any]], **over: Any) -> cs.GateChain:
    g = cs.GateChain(tmp, reviews, **over)
    assert g.setup.head == HEAD and g.setup.base == BASE
    return g


def judge(path: Path) -> Tuple[str, List[str], Dict[str, Tuple[str, List[str]]], Dict[str, Any]]:
    loaded = mf.load(path)
    ctx = lk.Context(root=path.parent, repo=None, doc=loaded.doc)
    out = lk.check_gate(ctx).as_dict()
    aspects = {k: (v["status"], v["codes"]) for k, v in out.get("gate_aspects", {}).items()}
    return out["status"], out["codes"], aspects, out.get("observed", {})


def records_of(g: cs.GateChain) -> List[Dict[str, Any]]:
    return copy.deepcopy(g.records)


def candidate(records: List[Dict[str, Any]], user: int) -> Dict[str, Any]:
    ref = "reviewer:" + gate.actor_ref(user)
    return next(r for r in records if r["kind"] == "candidate_review" and r["source"]["item_ref"] == ref)


def approved_at_head(user: int = A, rid: int = 10, minute: int = 10) -> Dict[str, Any]:
    return R(rid, "APPROVED", user, T(minute), HEAD)


# ===================================================================================== M2-08 GV-1


def test_tc_08_01_the_builder_is_deterministic(tmp_path: Path) -> None:
    g = chain(tmp_path, [approved_at_head(), R(11, "COMMENTED", B, T(11), HEAD)])
    first = [mf.canonical_sha256(r) for r in gate.regenerate(g.path)]
    second = [mf.canonical_sha256(r) for r in gate.regenerate(g.path)]
    assert first == second == [mf.canonical_sha256(r) for r in g.records]


@pytest.mark.parametrize("state,merged,decision", [("open", False, "open"), ("closed", True, "merged"), ("closed", False, "closed_unmerged")])
def test_tc_08_02_every_kind_and_decision_is_linked(tmp_path: Path, state: str, merged: bool, decision: str) -> None:
    reviews = [approved_at_head(A, 10, 10), R(20, "CHANGES_REQUESTED", B, T(11), HEAD), R(30, "COMMENTED", 5000004, T(12), HEAD)]
    g = chain(tmp_path, reviews, state=state, merged=merged)
    kinds = {(r["kind"], r["decision"]) for r in g.records}
    assert {("contract_approval", "approved"), ("candidate_review", "approved"), ("candidate_review", "changes_requested"),
            ("candidate_review", "none"), ("merge_decision", decision)} == kinds
    _, _, aspects, observed = judge(g.path)
    assert aspects["integrity"] == ("LINKED", []) and observed["merge_decision"] == decision


def test_tc_08_03_the_array_order_and_the_page_split_do_not_matter(tmp_path: Path) -> None:
    reviews = [R(1, "APPROVED", A, T(1), OLD), R(2, "COMMENTED", B, T(2), HEAD), R(3, "CHANGES_REQUESTED", B, T(3), HEAD),
               R(4, "APPROVED", B, T(4), HEAD), R(5, "APPROVED", A, T(5), HEAD)]
    one = chain(tmp_path / "one", reviews)
    rev = chain(tmp_path / "rev", list(reversed(reviews)))
    paged = chain(tmp_path / "paged", list(reversed(reviews)), pages=3)

    def decisions(g: cs.GateChain) -> List[Tuple[str, str, Any, Any]]:
        return [(r["source"]["item_ref"], r["decision"], r["deciding_review_ref"], r["binds_to"]["commit"]) for r in g.records]

    assert [mf.canonical_sha256(r) for r in one.records] != [] and decisions(one) == decisions(rev) == decisions(paged)
    assert judge(one.path)[:3] == judge(rev.path)[:3] == judge(paged.path)[:3]
    assert judge(one.path)[0] == "LINKED"


def test_tc_08_04_a_forged_decision_is_broken(tmp_path: Path) -> None:
    g = chain(tmp_path, [approved_at_head(A), R(20, "COMMENTED", B, T(11), HEAD)])
    records = records_of(g)
    candidate(records, B)["decision"] = "approved"
    status, codes, aspects, _ = judge(g.with_records(records, "forged-decision"))
    assert status == "BROKEN" and aspects["integrity"][1] == ["gate_record_mismatch"]


def test_tc_08_05_another_kind_or_digest_in_the_manifest_is_broken(tmp_path: Path) -> None:
    g = chain(tmp_path, [approved_at_head()])
    doc = copy.deepcopy(g.doc)
    entry = next(e for e in doc["gate_records"] if e["kind"] == "merge_decision")
    entry["kind"] = "candidate_review"
    assert "gate_record_mismatch" in judge(cs.write_manifest(g.root, doc, "kind-manifest.json"))[2]["integrity"][1]
    doc = copy.deepcopy(g.doc)
    doc["gate_records"][0]["sha256"] = "0" * 64
    status, codes, _, _ = judge(cs.write_manifest(g.root, doc, "digest-manifest.json"))
    assert status == "BROKEN" and "gate_record_mismatch" in codes


SELF_DECLARED = [{"approved_by": "agent"},
                 {"record_format": gate.RECORD_FORMAT, "kind": "candidate_review", "decision": "approved", "source": {"type": "agent_statement"}},
                 {"kind": "candidate_review", "approver": "a free-text approver"}]


@pytest.mark.parametrize("junk", SELF_DECLARED)
def test_tc_08_06_a_self_declared_approval_is_never_an_approval(tmp_path: Path, junk: Dict[str, Any]) -> None:
    """Every record the raw gives is presented, so the self-declaration is the only anomaly (NOT_PROVEN, not INCOMPLETE)."""
    g = chain(tmp_path, [R(20, "COMMENTED", B, T(11), HEAD)])
    status, codes, aspects, _ = judge(g.with_records(records_of(g) + [junk], "self-declared"))
    assert status == "NOT_PROVEN" and aspects["integrity"] == ("NOT_PROVEN", ["approval_self_declared_only"])
    assert aspects["staleness"] == ("NOT_PROVEN", ["approval_self_declared_only"])
    assert aspects["account_separation"] == ("NOT_PROVEN", ["approval_not_shown"])
    assert "gate_record_invalid" not in codes


def test_tc_08_07_a_source_outside_the_manifest_list_is_missing(tmp_path: Path) -> None:
    g = chain(tmp_path, [approved_at_head()])
    doc = copy.deepcopy(g.doc)
    reviews_ids = candidate(g.records, A)["source"]["evidence_ids"]
    doc["github_evidence"]["evidence_ids"] = [e for e in doc["github_evidence"]["evidence_ids"] if e not in reviews_ids]
    status, codes, aspects, _ = judge(cs.write_manifest(g.root, doc, "unlisted-manifest.json"))
    assert status == "INCOMPLETE" and "gate_source_missing" in aspects["integrity"][1]


def test_tc_08_08_a_source_in_another_revision_is_missing(tmp_path: Path) -> None:
    g = chain(tmp_path, [approved_at_head()])
    records = records_of(g)
    candidate(records, A)["source"]["store_revision"] = "rev-0002"
    assert "gate_source_missing" in judge(g.with_records(records, "other-revision"))[2]["integrity"][1]


def test_tc_08_09_pull_and_reviews_of_different_prs_are_missing(tmp_path: Path) -> None:
    g = chain(tmp_path, [approved_at_head()], review_number=8)
    status, codes, aspects, _ = judge(g.path)
    assert status == "INCOMPLETE" and "gate_source_missing" in aspects["integrity"][1]


def test_tc_08_10_raw_that_fails_the_m1_integrity_is_not_used(tmp_path: Path) -> None:
    g = chain(tmp_path, [approved_at_head()])
    rev = g.root / g.doc["github_evidence"]["store_locator"] / g.doc["github_evidence"]["revision"]
    raw = sorted(rev.glob("*.raw"))[-1]
    raw.chmod(0o600)
    data = bytearray(raw.read_bytes())
    data[-1] ^= 0x01
    raw.write_bytes(bytes(data))
    status, codes, aspects, _ = judge(g.path)
    assert status == "INCOMPLETE" and "gate_source_integrity_not_pass" in aspects["integrity"][1]


def _drop(index: int) -> Any:
    def mutate(captured: List[collector.CapturedEvidence]) -> List[collector.CapturedEvidence]:
        pages = [c for c in captured if "/reviews" in c.envelope["api"]["endpoint"]]
        drop = pages[index]
        return [c for c in captured if c is not drop]
    return mutate


@pytest.mark.parametrize("index", [1, 2])
def test_tc_08_11_a_missing_page_is_incomplete(tmp_path: Path, index: int) -> None:
    reviews = [R(i, "COMMENTED", B, T(i), HEAD) for i in range(1, 6)] + [approved_at_head(A, 20, 20)]
    g = chain(tmp_path, reviews, pages=3, mutate=_drop(index))
    status, codes, aspects, _ = judge(g.path)
    assert status == "INCOMPLETE" and "review_capture_incomplete" in aspects["integrity"][1]


@pytest.mark.parametrize("indexes,has_next,want", [
    ([1], [False], None), ([1, 2, 3], [True, True, False], None),
    ([1, 3], [True, False], "review_capture_incomplete"), ([2], [False], "review_capture_incomplete"),
    ([1, 2], [False, False], "review_capture_incomplete"), ([1, 2], [True, True], "review_capture_incomplete"),
    ([1, 1, 2], [True, True, False], "review_capture_duplicate"), ([], [], "review_capture_incomplete"),
])
def test_tc_08_11_the_page_sequence_rule(indexes: List[int], has_next: List[bool], want: Optional[str]) -> None:
    """E-5 holds in the gate itself, not only through the M1 integrity check (defence in depth)."""
    assert gate.page_sequence_problem(indexes, has_next) == want


def test_tc_08_11_a_page_the_manifest_does_not_name_is_incomplete(tmp_path: Path) -> None:
    reviews = [R(i, "COMMENTED", B, T(i), HEAD) for i in range(1, 6)] + [approved_at_head(A, 20, 20)]
    g = chain(tmp_path, reviews, pages=3)
    doc = copy.deepcopy(g.doc)
    page2 = candidate(g.records, A)["source"]["evidence_ids"][1]
    doc["github_evidence"]["evidence_ids"].remove(page2)
    status, codes, aspects, _ = judge(cs.write_manifest(g.root, doc, "page-unnamed-manifest.json"))
    assert status == "INCOMPLETE" and "review_capture_incomplete" in aspects["integrity"][1]


def test_tc_08_12_a_duplicated_page_number_is_a_duplicate(tmp_path: Path) -> None:
    def mutate(captured: List[collector.CapturedEvidence]) -> List[collector.CapturedEvidence]:
        out = []
        for c in captured:
            if c.envelope["evidence_id"].endswith("-p002") and "/reviews" in c.envelope["api"]["endpoint"]:
                env = dict(c.envelope, page=dict(c.envelope["page"], index=1))
                c = collector.CapturedEvidence(env, c.raw)
            out.append(c)
        return out

    reviews = [R(i, "COMMENTED", B, T(i), HEAD) for i in range(1, 6)] + [approved_at_head(A, 20, 20)]
    g = chain(tmp_path, reviews, pages=3, mutate=mutate)
    assert "review_capture_duplicate" in judge(g.path)[2]["integrity"][1]


def test_tc_08_12_the_same_review_on_two_pages_is_a_duplicate(tmp_path: Path) -> None:
    same = approved_at_head()
    g = chain(tmp_path, [same, R(2, "COMMENTED", B, T(2), HEAD), copy.deepcopy(same), R(3, "COMMENTED", B, T(3), HEAD)], pages=2)
    status, codes, aspects, _ = judge(g.path)
    assert status == "INCOMPLETE" and "review_capture_duplicate" in aspects["integrity"][1]


def test_tc_08_13_one_review_id_with_two_contents_is_a_conflict(tmp_path: Path) -> None:
    g = chain(tmp_path, [approved_at_head(A, 10), R(10, "CHANGES_REQUESTED", A, T(10), HEAD)], pages=2)
    status, codes, aspects, _ = judge(g.path)
    assert status == "BROKEN" and "review_conflict" in aspects["integrity"][1]


@pytest.mark.parametrize("bad", [R(1, "SUPERSEDED", A, T(1), HEAD), R(1, "APPROVED", A, "2026-10-30 06:01", HEAD),
                                 dict(R(1, "APPROVED", A, T(1), HEAD), id="1"), R(1, "APPROVED", A, T(1), "HEAD"),
                                 R(1, "APPROVED", A, None, HEAD)])
def test_tc_08_14_an_unrecognised_review_is_not_proven(tmp_path: Path, bad: Dict[str, Any]) -> None:
    g = chain(tmp_path, [bad, approved_at_head(B, 20, 20)])
    status, codes, aspects, _ = judge(g.path)
    assert status == "NOT_PROVEN" and "gate_source_unrecognized" in aspects["integrity"][1]


def test_tc_08_15_conflicting_reviews_at_the_same_time_are_ambiguous(tmp_path: Path) -> None:
    g = chain(tmp_path, [R(1, "APPROVED", A, T(5), HEAD), R(2, "CHANGES_REQUESTED", A, T(5), HEAD)])
    status, codes, aspects, _ = judge(g.path)
    assert "review_order_ambiguous" in aspects["integrity"][1] and candidate(g.records, A)["decision"] == "none"
    assert aspects["account_separation"] == ("NOT_PROVEN", ["approval_not_shown"])


def test_tc_08_16_time_order_against_id_order_is_inconsistent(tmp_path: Path) -> None:
    g = chain(tmp_path, [R(9, "APPROVED", A, T(1), HEAD), R(3, "CHANGES_REQUESTED", A, T(2), HEAD)])
    _, _, aspects, _ = judge(g.path)
    assert "review_order_inconsistent" in aspects["integrity"][1] and candidate(g.records, A)["decision"] == "none"


DECISION_TABLE = [
    ("R-01", [R(1, "APPROVED", A, T(1), HEAD)], "approved", True),
    ("R-02", [R(1, "APPROVED", A, T(1), HEAD), R(2, "COMMENTED", A, T(2), HEAD)], "approved", True),
    ("R-04", [R(1, "CHANGES_REQUESTED", A, T(1), HEAD), R(2, "APPROVED", A, T(2), HEAD)], "approved", True),
    ("R-06", [R(1, "DISMISSED", A, T(1), HEAD), R(2, "APPROVED", A, T(2), HEAD)], "approved", True),
    ("R-07", [R(1, "DISMISSED", A, T(1), HEAD)], "none", False),
    ("R-08", [R(1, "COMMENTED", A, T(1), HEAD), R(2, "PENDING", A, None, HEAD)], "none", False),
    ("R-09", [R(1, "APPROVED", A, T(1), HEAD), R(2, "PENDING", A, None, HEAD)], "approved", True),
    ("R-11", [R(1, "APPROVED", A, T(1), HEAD), R(2, "APPROVED", A, T(1), HEAD)], "approved", True),
    ("R-17", [R(1, "APPROVED", A, T(1), OLD)], "approved", False),
    ("R-18", [R(1, "APPROVED", A, T(1), OLD), R(2, "APPROVED", A, T(2), HEAD)], "approved", True),
    ("R-19", [R(1, "APPROVED", A, T(1), HEAD), R(2, "APPROVED", A, T(2), OLD)], "approved", False),
    ("R-21", [R(1, "CHANGES_REQUESTED", A, T(1), OLD)], "changes_requested", False),
    ("R-22", [R(1, "APPROVED", AUTHOR, T(1), HEAD)], "approved", False),
]


@pytest.mark.parametrize("row,reviews,state,effective", DECISION_TABLE, ids=[r[0] for r in DECISION_TABLE])
def test_tc_08_17_the_decision_table(tmp_path: Path, row: str, reviews: List[Dict[str, Any]], state: str, effective: bool) -> None:
    g = chain(tmp_path, reviews)
    user = AUTHOR if row == "R-22" else A
    assert candidate(g.records, user)["decision"] == state
    status, codes, aspects, _ = judge(g.path)
    assert (status == "LINKED") is effective, (status, codes)
    if row in ("R-17", "R-19"):
        assert aspects["revision_binding"] == ("NOT_PROVEN", ["approval_on_previous_head_only"]) and status == "NOT_PROVEN"
    if row == "R-21":
        assert "changes_requested_outstanding" in aspects["account_separation"][1]
    if row == "R-22":
        assert aspects["account_separation"] == ("NOT_PROVEN", ["separation_of_duty_not_shown"])


def test_tc_08_18_login_avatar_and_email_never_leave_the_store(tmp_path: Path) -> None:
    canary = "zqx-canary-login-7f3c9a"
    reviews = [R(1, "APPROVED", A, T(1), HEAD)]
    reviews[0]["user"].update(login=canary, avatar_url="https://example.invalid/" + canary)
    reviews[0]["body"] = canary
    g = chain(tmp_path, reviews, pull_extra={"user": {"id": AUTHOR, "login": canary}})
    text = json.dumps(g.records) + json.dumps(judge(g.path)) + json.dumps(validator.validate(g.path, g.setup.repo))
    assert canary not in text  # login, avatar URL and body stay in the private store
    assert canary in "".join(p.read_text(encoding="utf-8", errors="replace") for p in (g.root / "gate-store").rglob("*.raw"))
    email = [R(1, "APPROVED", A, T(1), HEAD)]
    email[0]["user"]["email"] = canary + "@example.invalid"
    (tmp_path / "email").mkdir()
    with pytest.raises(cs.store.StoreError, match="empty revision"):  # the M1 secret gate refused the page
        cs.make_gate_store(tmp_path / "email", BASE, HEAD, email, with_pull=False)


def test_tc_08_19_a_later_dismissed_review_makes_the_reviewer_unknown(tmp_path: Path) -> None:
    g = chain(tmp_path, [R(1, "APPROVED", A, T(1), HEAD), R(2, "DISMISSED", A, T(2), HEAD)])
    _, _, aspects, _ = judge(g.path)
    assert "review_dismissal_effect_unknown" in aspects["integrity"][1] and candidate(g.records, A)["decision"] == "none"


@pytest.mark.parametrize("reviews,code", [
    ([R(1, "APPROVED", A, T(3), HEAD), R(2, "DISMISSED", A, T(3), HEAD)], "review_order_ambiguous"),
    ([R(9, "DISMISSED", A, T(1), HEAD), R(3, "APPROVED", A, T(2), HEAD)], "review_order_inconsistent"),
])
def test_tc_08_20_a_dismissal_whose_order_cannot_be_shown(tmp_path: Path, reviews: List[Dict[str, Any]], code: str) -> None:
    g = chain(tmp_path, reviews)
    assert code in judge(g.path)[2]["integrity"][1] and candidate(g.records, A)["decision"] == "none"


def test_tc_08_21_a_dismissal_acts_on_its_own_review_only(tmp_path: Path) -> None:
    g = chain(tmp_path, [R(10, "DISMISSED", B, T(1), HEAD), R(11, "APPROVED", A, T(2), HEAD)])
    assert candidate(g.records, B)["decision"] == "none" and candidate(g.records, A)["decision"] == "approved"
    status, codes, _, _ = judge(g.path)
    assert (status, codes) == ("LINKED", [])


# ------------------------------------------------------------------ WP2 review N2-2 / N2-3: record decision table
# docs/v2/phase2/m2/wp2/wp2-gate-record-decision-table.md G-01..G-13. A missing record without a contradiction
# is INCOMPLETE, a contradiction the raw shows is BROKEN, a schema violation is not a self-declaration, and a
# good record never hides a bad one.


def with_entries(g: cs.GateChain, name: str, records: List[Dict[str, Any]], extra: List[Tuple[bytes, str]]) -> Path:
    """The manifest naming ``records`` (canonical JSON) and then each raw ``(bytes, kind)`` file of ``extra``."""
    doc = copy.deepcopy(g.doc)
    entries = cs.write_gate_records(g.root, records, "gate-" + name)
    for i, (data, kind) in enumerate(extra):
        rel = cs.write(g.root, "gate-{0}/extra-{1:02d}.json".format(name, i), data)
        entries.append({"locator": rel, "sha256": cs.sha256(data), "kind": kind})
    doc["gate_records"] = entries
    return cs.write_manifest(g.root, doc, name + "-manifest.json")


def good_chain(tmp: Path) -> cs.GateChain:
    """A LINKED gate: A approved the head, B commented."""
    g = chain(tmp, [approved_at_head(A), R(20, "COMMENTED", B, T(11), HEAD)])
    assert judge(g.path)[:2] == ("LINKED", [])
    return g


def test_g_02_an_absent_record_file_is_missing_not_a_missing_raw(tmp_path: Path) -> None:
    g = good_chain(tmp_path)
    doc = copy.deepcopy(g.doc)
    entry = next(e for e in doc["gate_records"] if e["kind"] == "merge_decision")
    (g.root / entry["locator"]).unlink()
    status, codes, aspects, _ = judge(cs.write_manifest(g.root, doc, "absent-manifest.json"))
    assert status == "INCOMPLETE" and aspects["integrity"] == ("INCOMPLETE", ["gate_record_missing"])
    assert "gate_source_missing" not in codes and "gate_record_mismatch" not in codes


INVALID = [
    (b"approved: yes\n", "not JSON"),
    (b"[1, 2]", "not an object"),
    (b'{"kind": "candidate_review", "decision": "none"}', "outside the schema, states no approval"),
    (b'{"a": 1, "a": 2}', "duplicate key"),
    (b'{"approved_by": 1.5}', "a float (strict JSON)"),
    (b'{"approval_state": "rejected"}', "a non-approval field that starts like an approval"),
    (b'{"approved": false, "approvers": []}', "an approval that is denied or empty"),
    (b'{"approvedBy": "alice", "Approver": "bob"}', "an undefined spelling of an approver"),
    (b'{"note": "approved by alice", "decision": "APPROVED"}', "free text and another case"),
    (b" " * (gate.MAX_RECORD_BYTES + 1), "too large"),
]


@pytest.mark.parametrize("data,why", INVALID, ids=[w for _, w in INVALID])
def test_g_04_a_record_outside_the_schema_is_invalid_not_a_self_declaration(tmp_path: Path, data: bytes, why: str) -> None:
    g = good_chain(tmp_path)
    status, codes, aspects, _ = judge(with_entries(g, "invalid", records_of(g), [(data, "candidate_review")]))
    assert status == "INCOMPLETE" and aspects["integrity"] == ("INCOMPLETE", ["gate_record_invalid"]), why
    assert "approval_self_declared_only" not in codes


SELF_DECLARATION_FORMS = [{"decision": "approved"}, {"approved": True}, {"approved_by": "x"}, {"approver": "x"},
                          {"approvers": ["x"]}, {"approved_by": ["x", "y"]}, {"kind": "candidate_review", "approver": "x", "extra": 1}]
NOT_SELF_DECLARATIONS = [
    {"decision": "none"}, {"decision": "APPROVED"}, {"decision": ["approved"]}, {"kind": "candidate_review"},
    {"approved": False}, {"approved": "yes"}, {"approved": 1}, {"approved_by": ""}, {"approvers": []}, {"approved_by": 7},
    {"approved_by": None}, {"approval_state": "rejected"}, {"approvals_count": 2}, {"approve": "x"}, {"Approver": "x"},
    {"approvedBy": "x"}, {"APPROVED_BY": "x"}, {"note": "approved by alice"}, {"reviewer": {"approved_by": "x"}},
    [], [{"approved_by": "x"}], "approved", None, 1,
]


@pytest.mark.parametrize("value", SELF_DECLARATION_FORMS)
def test_g_05_the_three_self_declaration_forms(value: Any) -> None:
    assert gate.states_an_approval(value), value


@pytest.mark.parametrize("value", NOT_SELF_DECLARATIONS)
def test_g_05_other_fields_and_undefined_wording_are_not_self_declarations(value: Any) -> None:
    """Non-approval fields (no false positive) and the limit: undefined wording is G-04 (INCOMPLETE), never an approval."""
    assert not gate.states_an_approval(value), value


@pytest.mark.parametrize("junk", SELF_DECLARED)
def test_g_05_a_self_declaration_next_to_a_real_approval_is_not_hidden(tmp_path: Path, junk: Dict[str, Any]) -> None:
    g = good_chain(tmp_path)
    status, codes, aspects, _ = judge(g.with_records(records_of(g) + [junk], "self-and-real"))
    assert status == "NOT_PROVEN" and aspects["integrity"] == ("NOT_PROVEN", ["approval_self_declared_only"])
    assert aspects["staleness"] == ("LINKED", [])  # a raw-backed approval record is presented (GV-4 row 4 does not apply)


def test_g_07_a_record_presented_twice_is_invalid_and_each_copy_is_compared(tmp_path: Path) -> None:
    g = good_chain(tmp_path)
    twice = records_of(g) + [copy.deepcopy(candidate(g.records, A))]
    status, codes, aspects, _ = judge(g.with_records(twice, "twice"))
    assert status == "INCOMPLETE" and aspects["integrity"] == ("INCOMPLETE", ["gate_record_invalid"])
    forged = copy.deepcopy(candidate(g.records, B))
    forged["decision"] = "approved"
    status, codes, aspects, _ = judge(g.with_records(records_of(g) + [forged], "twice-forged"))
    assert status == "BROKEN" and set(aspects["integrity"][1]) == {"gate_record_invalid", "gate_record_mismatch"}


def test_g_09_a_reviewer_the_complete_raw_does_not_have_is_broken(tmp_path: Path) -> None:
    g = good_chain(tmp_path)
    ghost = copy.deepcopy(candidate(g.records, A))
    ref = gate.actor_ref(5000099)
    ghost["source"]["item_ref"], ghost["actor"]["actor_ref"] = "reviewer:" + ref, ref
    status, codes, aspects, _ = judge(g.with_records(records_of(g) + [ghost], "ghost"))
    assert status == "BROKEN" and aspects["integrity"] == ("BROKEN", ["gate_record_mismatch"])
    assert "gate_source_missing" not in codes


def test_g_09_a_merge_decision_of_another_pull_is_broken(tmp_path: Path) -> None:
    g = good_chain(tmp_path)
    records = records_of(g)
    other = copy.deepcopy(next(r for r in records if r["kind"] == "merge_decision"))
    other["source"]["item_ref"] = "pull:999"
    status, codes, aspects, _ = judge(g.with_records(records + [other], "other-pull"))
    assert status == "BROKEN" and aspects["integrity"] == ("BROKEN", ["gate_record_mismatch"])


def test_g_10_g_11_a_record_whose_raw_cannot_be_read_is_never_broken_by_the_record(tmp_path: Path) -> None:
    """G-10: no usable capture (E-7) gives gate_source_missing; G-11: an unreadable review list keeps its own code."""
    status, codes, _, _ = judge(chain(tmp_path / "e7", [approved_at_head()], review_number=8).path)
    assert status == "INCOMPLETE" and "gate_record_mismatch" not in codes and "gate_source_missing" in codes
    status, codes, _, _ = judge(chain(tmp_path / "r15", [R(1, "SUPERSEDED", A, T(1), HEAD), approved_at_head(B, 20, 20)]).path)
    assert status == "NOT_PROVEN" and "gate_source_unrecognized" in codes
    assert "gate_record_mismatch" not in codes and "gate_source_missing" not in codes


@pytest.mark.parametrize("omit", ["changes_requested", "merge_decision", "approved"])
def test_g_13_a_record_left_out_is_missing_not_broken(tmp_path: Path, omit: str) -> None:
    g = chain(tmp_path, [approved_at_head(A), R(20, "CHANGES_REQUESTED", B, T(11), HEAD)])
    records = records_of(g)
    if omit == "merge_decision":
        kept = [r for r in records if r["kind"] != "merge_decision"]
    else:
        kept = [r for r in records if not (r["kind"] == "candidate_review" and r["decision"] == omit)]
    assert len(kept) == len(records) - 1
    status, codes, aspects, _ = judge(g.with_records(kept, "omit-" + omit))
    assert status == "INCOMPLETE" and aspects["integrity"] == ("INCOMPLETE", ["gate_record_missing"])
    assert "gate_record_mismatch" not in codes
    assert "changes_requested_outstanding" in aspects["account_separation"][1]  # the raw still shows the change request


#: anomaly -> (gate status, integrity codes). Every code is a primary cause: a changed or absent record file
#: also leaves its regenerated twin unpresented, which is secondary and adds no code (G-13a).
ANOMALIES = {
    "forged": ("BROKEN", ["gate_record_mismatch"]),
    "omitted": ("INCOMPLETE", ["gate_record_missing"]),
    "invalid": ("INCOMPLETE", ["gate_record_invalid"]),
    "self_declared": ("NOT_PROVEN", ["approval_self_declared_only"]),
    "absent_file": ("INCOMPLETE", ["gate_record_missing"]),
    "digest": ("BROKEN", ["gate_record_mismatch"]),
}


def _with_anomaly(g: cs.GateChain, name: str, anomaly: str) -> Path:
    records = records_of(g)
    b = candidate(records, B)
    extra: List[Tuple[bytes, str]] = []
    if anomaly == "forged":
        b["observed_at"] = T(59)
    elif anomaly == "omitted":
        records.remove(b)
    elif anomaly == "invalid":
        extra = [(b"[]", "candidate_review")]
    elif anomaly == "self_declared":
        extra = [(b'{"approved_by": "agent"}', "candidate_review")]
    path = with_entries(g, name, records, extra)
    if anomaly in ("absent_file", "digest"):
        doc = mf.load(path).doc
        entry = next(e for e in doc["gate_records"] if e["locator"].endswith("-merge_decision.json"))
        if anomaly == "absent_file":
            (g.root / entry["locator"]).unlink()
        else:
            entry["sha256"] = "0" * 64
        path = cs.write_manifest(g.root, doc, name + "-manifest.json")
    return path


def _replace_file(g: cs.GateChain, name: str, user: int, data: bytes, omit: Optional[int] = None) -> Path:
    """The correct manifest, with ``user``'s record file replaced by ``data`` (digest updated) and ``omit``'s entry removed."""
    doc = copy.deepcopy(g.doc)
    for i, rec in enumerate(g.records):
        if rec["kind"] == "candidate_review" and rec["source"]["item_ref"] == "reviewer:" + gate.actor_ref(user):
            rel = cs.write(g.root, "gate-{0}/replaced.json".format(name), data)
            doc["gate_records"][i] = dict(doc["gate_records"][i], locator=rel, sha256=cs.sha256(data))
    if omit is not None:
        ref = "reviewer:" + gate.actor_ref(omit)
        doc["gate_records"] = [e for e, r in zip(doc["gate_records"], g.records) if r["source"]["item_ref"] != ref]
    return cs.write_manifest(g.root, doc, name + "-manifest.json")


def test_g_13a_the_primary_cause_is_not_doubled_by_a_secondary_missing_code(tmp_path: Path) -> None:
    g = chain(tmp_path, [approved_at_head(A), R(20, "COMMENTED", B, T(11), HEAD), R(30, "COMMENTED", 5000004, T(12), HEAD)])
    status, codes, aspects, _ = judge(_replace_file(g, "replaced", B, b"[]"))
    assert (status, aspects["integrity"]) == ("INCOMPLETE", ("INCOMPLETE", ["gate_record_invalid"]))  # primary only
    status, codes, aspects, _ = judge(_replace_file(g, "replaced-and-omitted", B, b"[]", omit=5000004))
    assert aspects["integrity"] == ("INCOMPLETE", ["gate_record_invalid", "gate_record_missing"])  # a real omission besides
    status, codes, aspects, _ = judge(_replace_file(g, "self-declared-in-place", B, b'{"approved_by": "agent"}'))
    assert aspects["integrity"] == ("INCOMPLETE", ["approval_self_declared_only", "gate_record_missing"])  # never weaker


@pytest.mark.parametrize("anomaly", sorted(ANOMALIES))
def test_g_one_bad_record_among_good_ones_decides_the_gate(tmp_path: Path, anomaly: str) -> None:
    g = good_chain(tmp_path)
    status, codes, aspects, _ = judge(_with_anomaly(g, anomaly, anomaly))
    want_status, want_codes = ANOMALIES[anomaly]
    assert status == want_status and aspects["integrity"] == (want_status, want_codes), (status, codes)
    assert aspects["account_separation"] == ("LINKED", [])  # the good approval is still seen, and hides nothing


def test_g_several_bad_records_keep_every_cause(tmp_path: Path) -> None:
    g = chain(tmp_path, [approved_at_head(A), R(20, "COMMENTED", B, T(11), HEAD), R(30, "COMMENTED", 5000004, T(12), HEAD)])
    records = records_of(g)
    candidate(records, B)["observed_at"] = T(59)  # forged
    records.remove(candidate(records, 5000004))  # omitted (no unusable candidate_review entry accounts for it)
    path = with_entries(g, "several", records, [(b"[]", "merge_decision"), (b'{"approved_by": "agent"}', "candidate_review")])
    status, codes, aspects, _ = judge(path)
    assert status == "BROKEN"
    assert aspects["integrity"] == ("BROKEN", sorted(["gate_record_mismatch", "gate_record_missing", "gate_record_invalid",
                                                      "approval_self_declared_only"]))


# ===================================================================================== M2-09 GV-3 / GV-4


def test_tc_09_01_approval_contract_and_pr_head_agree(tmp_path: Path) -> None:
    status, codes, aspects, _ = judge(chain(tmp_path, [approved_at_head()]).path)
    assert aspects["revision_binding"] == ("LINKED", []) and aspects["staleness"] == ("LINKED", []) and status == "LINKED"


def test_tc_09_02_an_approval_of_an_old_head_only_is_not_proven_not_broken(tmp_path: Path) -> None:
    status, codes, aspects, _ = judge(chain(tmp_path, [R(1, "APPROVED", A, T(1), OLD)]).path)
    assert status == "NOT_PROVEN" and aspects["revision_binding"] == ("NOT_PROVEN", ["approval_on_previous_head_only"])


def test_tc_09_03_an_old_approval_next_to_a_head_approval_is_ignored(tmp_path: Path) -> None:
    status, codes, aspects, _ = judge(chain(tmp_path, [R(1, "APPROVED", A, T(1), OLD), R(2, "APPROVED", B, T(2), HEAD)]).path)
    assert (status, codes) == ("LINKED", [])


def test_tc_09_04_a_pr_head_after_the_chain_head_is_broken(tmp_path: Path) -> None:
    status, codes, aspects, _ = judge(chain(tmp_path, [approved_at_head()], pr_head="f" * 40).path)
    assert status == "BROKEN" and aspects["staleness"] == ("BROKEN", ["pr_head_mismatch"])


def test_tc_09_05_a_contract_approval_of_another_commit_is_broken(tmp_path: Path) -> None:
    g = chain(tmp_path, [approved_at_head()])
    records = records_of(g)
    next(r for r in records if r["kind"] == "contract_approval")["binds_to"]["commit"] = HEAD
    _, _, aspects, _ = judge(g.with_records(records, "contract-other"))
    assert aspects["revision_binding"][0] == "BROKEN" and "gate_binds_other_commit" in aspects["revision_binding"][1]


def test_tc_09_06_no_contract_approval_is_incomplete(tmp_path: Path) -> None:
    g = chain(tmp_path, [approved_at_head()])
    records = [r for r in records_of(g) if r["kind"] != "contract_approval"]
    _, _, aspects, _ = judge(g.with_records(records, "no-contract"))
    assert aspects["revision_binding"] == ("INCOMPLETE", ["gate_record_missing"])


@pytest.mark.parametrize("over", [{"with_pull": False}, {"pull_extra": {"head": {"ref": "x"}}}])
def test_tc_09_07_without_the_pr_head_staleness_is_not_proven(tmp_path: Path, over: Dict[str, Any]) -> None:
    _, _, aspects, _ = judge(chain(tmp_path, [approved_at_head()], **over).path)
    assert aspects["staleness"] == ("NOT_PROVEN", ["approval_revision_unverifiable"])


def test_tc_09_08_an_approval_without_a_commit_is_not_proven(tmp_path: Path) -> None:
    _, _, aspects, _ = judge(chain(tmp_path, [R(1, "APPROVED", A, T(1), None)]).path)
    assert aspects["revision_binding"] == ("NOT_PROVEN", ["approval_revision_unverifiable"])


def test_tc_09_09_self_declaration_only_is_not_proven_for_staleness(tmp_path: Path) -> None:
    g = chain(tmp_path, [])
    status, _, aspects, _ = judge(g.with_records(records_of(g) + [{"approved_by": "agent"}], "self-only"))
    assert aspects["staleness"] == ("NOT_PROVEN", ["approval_self_declared_only"])
    assert aspects["integrity"] == ("NOT_PROVEN", ["approval_self_declared_only"]) and status == "NOT_PROVEN"


def test_tc_09_10_a_push_after_the_approval_is_never_complete(tmp_path: Path) -> None:
    status, _, aspects, _ = judge(chain(tmp_path, [R(1, "APPROVED", A, T(1), OLD)]).path)
    assert aspects["staleness"] == ("LINKED", []) and aspects["revision_binding"][1] == ["approval_on_previous_head_only"]
    assert status == "NOT_PROVEN"


def test_tc_09_11_a_record_that_moves_an_old_approval_to_the_head_is_broken(tmp_path: Path) -> None:
    g = chain(tmp_path, [R(1, "APPROVED", A, T(1), OLD)])
    records = records_of(g)
    candidate(records, A)["binds_to"]["commit"] = HEAD
    status, _, aspects, _ = judge(g.with_records(records, "misrecorded"))
    assert status == "BROKEN" and "approval_revision_misrecorded" in aspects["revision_binding"][1]
    assert "gate_record_mismatch" in aspects["integrity"][1]


def test_tc_09_12_outstanding_changes_old_approvals_and_missing_pages_have_their_own_codes(tmp_path: Path) -> None:
    cr = judge(chain(tmp_path / "a", [approved_at_head(A), R(20, "CHANGES_REQUESTED", B, T(11), HEAD)]).path)
    old = judge(chain(tmp_path / "b", [R(1, "APPROVED", A, T(1), OLD)]).path)
    reviews = [R(i, "COMMENTED", B, T(i), HEAD) for i in range(1, 6)] + [approved_at_head(A, 20, 20)]
    gap = judge(chain(tmp_path / "c", reviews, pages=3, mutate=_drop(1)).path)
    assert cr[1] == ["changes_requested_outstanding"]
    assert old[1] == ["approval_on_previous_head_only"]
    assert "review_capture_incomplete" in gap[1]
    assert "changes_requested_outstanding" not in old[1] + gap[1] and "approval_on_previous_head_only" not in cr[1] + gap[1]
    assert "review_capture_incomplete" not in cr[1] + old[1]


# ===================================================================================== M2-10 GV-2 and the claims


def test_tc_10_01_another_account_approving_the_head_is_linked_but_not_authority(tmp_path: Path) -> None:
    status, codes, aspects, observed = judge(chain(tmp_path, [approved_at_head()]).path)
    assert aspects["account_separation"] == ("LINKED", []) and observed["approval_authority"] == "NOT_PROVEN"


def test_tc_10_02_the_authors_own_approval_is_recorded_but_not_counted(tmp_path: Path) -> None:
    g = chain(tmp_path, [R(1, "APPROVED", AUTHOR, T(1), HEAD)])
    rec = candidate(g.records, AUTHOR)
    assert rec["decision"] == "approved" and rec["actor"]["relation_to_head_author"] == "same_actor"
    assert judge(g.path)[2]["account_separation"] == ("NOT_PROVEN", ["separation_of_duty_not_shown"])


@pytest.mark.parametrize("reviews,over", [
    ([dict(R(1, "APPROVED", A, T(1), HEAD), user=None), approved_at_head(B, 2, 2)], {}),
    ([dict(R(1, "APPROVED", A, T(1), HEAD), user={"id": "5000002"})], {}),
    ([approved_at_head()], {"pr_author": None}),
])
def test_tc_10_03_an_unknown_account_is_not_proven(tmp_path: Path, reviews: List[Dict[str, Any]], over: Dict[str, Any]) -> None:
    _, _, aspects, _ = judge(chain(tmp_path, reviews, **over).path)
    assert "actor_relation_unknown" in aspects["account_separation"][1] and aspects["account_separation"][0] == "NOT_PROVEN"


@pytest.mark.parametrize("reviews", [
    [R(1, "COMMENTED", A, T(1), HEAD)],
    [R(1, "PENDING", A, None, HEAD)],
    [R(1, "DISMISSED", A, T(1), HEAD)],
    [],
])
def test_tc_10_04_no_approval_is_not_proven(tmp_path: Path, reviews: List[Dict[str, Any]]) -> None:
    _, _, aspects, _ = judge(chain(tmp_path, reviews).path)
    assert aspects["account_separation"] == ("NOT_PROVEN", ["approval_not_shown"])


@pytest.mark.parametrize("reviews", [
    [approved_at_head(A), R(20, "APPROVED", B, T(11), HEAD), R(21, "CHANGES_REQUESTED", B, T(12), HEAD)],
    [approved_at_head(A), R(20, "CHANGES_REQUESTED", B, T(1), OLD)],
])
def test_tc_10_05_an_outstanding_change_request_is_never_complete(tmp_path: Path, reviews: List[Dict[str, Any]]) -> None:
    status, _, aspects, _ = judge(chain(tmp_path, reviews).path)
    assert aspects["account_separation"] == ("NOT_PROVEN", ["changes_requested_outstanding"]) and status == "NOT_PROVEN"


@pytest.mark.parametrize("assoc", ["OWNER", "COLLABORATOR", "CONTRIBUTOR", "NONE", None])
def test_tc_10_06_author_association_decides_nothing(tmp_path: Path, assoc: Optional[str]) -> None:
    g = chain(tmp_path, [R(1, "APPROVED", A, T(1), HEAD, assoc=assoc)])
    assert candidate(g.records, A)["actor"]["author_association"] == assoc
    assert judge(g.path) == ("LINKED", [], {a: ("LINKED", []) for a in gate.ASPECTS}, {"approval_authority": "NOT_PROVEN", "merge_decision": "open"})


def test_tc_10_07_a_full_chain_is_complete_and_claims_nothing_more(tmp_path: Path) -> None:
    g = chain(tmp_path, [approved_at_head()])
    result = validator.validate(g.path, g.setup.repo)
    payload = result["payload"]
    assert payload["chain_status"] == st.COMPLETE and validator.exit_code(result) == 0
    assert [e["status"] for e in payload["links"]] == ["LINKED"] * 6
    gate_link = next(e for e in payload["links"] if e["link"] == "gate")
    assert gate_link["observed"] == {"approval_authority": "NOT_PROVEN", "merge_decision": "open"}
    assert payload["not_claimed"] == list(st.NOT_CLAIMED) and "merge_enforcement" in payload["not_claimed"]
    assert "author_association" not in json.dumps(payload)


def test_tc_10_08_the_gate_has_no_write_path_and_no_authority_branch() -> None:
    source = Path(gate.__file__).read_text(encoding="utf-8")
    for forbidden in ("subprocess", "--method", "gh pr", "graphql", "git push", "git commit", "git merge", "requests", "urllib"):
        assert forbidden not in source, forbidden
    assert "author_association" not in inspect.getsource(gate.check)
    for fn in (gate._reviewer_state, gate.aggregate, gate.build):  # copied as an observation, never compared
        for line in inspect.getsource(fn).splitlines():
            if "author_association" in line:
                assert not any(op in line for op in (" if ", "==", "!=", " in (", "elif", "while")), line


def test_tc_10_09_the_builder_reads_only_store_evidence_and_git_facts() -> None:
    assert list(inspect.signature(gate.build).parameters) == ["doc", "sources"]
    assert list(inspect.signature(gate.regenerate).parameters) == ["manifest_path"]
    assert set(gate.Sources.__dataclass_fields__) == {"revision", "pull", "reviews", "codes"}


def test_tc_10_11_a_chain_without_gate_records_keeps_the_wp1_shape(tmp_path: Path) -> None:
    g = chain(tmp_path, [approved_at_head()])
    doc = copy.deepcopy(g.doc)
    doc["gate_records"] = []
    out = lk.check_gate(lk.Context(root=g.root, repo=None, doc=doc)).as_dict()
    assert out == {"link": "gate", "status": "INCOMPLETE", "codes": ["gate_record_missing"]}
    assert "gate_evaluation_not_implemented" in st.REASONS
