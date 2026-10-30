"""Phase 1 decision rules as properties (Design 7)."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from iacreview.remediation import decide, rschema

CODES = sorted(rschema.CODES)
STATES = ["PASS", "FAIL", "NOT_RUN", "NOT_PASSED", "TIMEOUT", "TOOL_UNAVAILABLE"]


@given(st.lists(st.sampled_from(CODES), max_size=12))
def test_the_representative_value_follows_the_priority(codes: list) -> None:
    decision = decide.decision_of(codes)
    forced = {rschema.CODES[c][0] for c in codes}
    if not codes:
        assert decision == rschema.VERIFIED
    else:
        assert decision == next(d for d in rschema.DECISION_PRIORITY if d in forced)
    assert decision != rschema.VERIFIED or not codes


@given(st.lists(st.sampled_from(CODES), max_size=12))
def test_order_and_repetition_do_not_change_the_decision(codes: list) -> None:
    assert decide.decision_of(codes) == decide.decision_of(list(reversed(codes)) + codes)


@given(st.sampled_from(list(rschema.DECISION_EXIT_CODES)))
def test_a_draft_never_verifies_or_blocks(decision: str) -> None:
    assert decide.cap_for_draft(decision) not in (rschema.VERIFIED, rschema.BLOCKED)


@given(st.lists(st.tuples(st.sampled_from(STATES), st.sampled_from(STATES)), min_size=1, max_size=4))
def test_task_outcome_never_claims_success_without_head_pass(pairs: list) -> None:
    outcome = decide.task_outcome(pairs)
    if outcome in ("resolved", "already_satisfied"):
        assert all(h == "PASS" for _, h in pairs)
        assert all(b in ("PASS", "FAIL") for b, _ in pairs)
    if outcome == "resolved":
        assert any(b == "FAIL" for b, _ in pairs)
    if outcome == "already_satisfied":
        assert all(b == "PASS" for b, _ in pairs)
    if any(h == "FAIL" for _, h in pairs):
        assert outcome == "not_resolved"


def test_every_code_maps_to_a_decision_and_every_decision_has_an_exit_code() -> None:
    assert {d for d, _ in rschema.CODES.values()} <= set(rschema.DECISION_EXIT_CODES)
    assert rschema.DECISION_EXIT_CODES == {"VERIFIED": 0, "BLOCKED": 20, "UNVERIFIED": 21, "ERROR": 22}
    assert decide.task_outcome([]) == "not_evaluated"
