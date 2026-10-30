"""Decision and task outcome (Design 7)."""

from __future__ import annotations

from typing import Iterable, List, Sequence, Tuple

from iacreview.remediation import rschema


def decision_of(codes: Iterable[str]) -> str:
    """The representative decision: ERROR > BLOCKED > UNVERIFIED > VERIFIED."""
    forced = {rschema.CODES[code][0] for code in codes}
    for decision in rschema.DECISION_PRIORITY:
        if decision in forced:
            return decision
    return rschema.VERIFIED


def cap_for_draft(decision: str) -> str:
    """A draft contract can never produce VERIFIED or BLOCKED (Design 3)."""
    if decision in (rschema.VERIFIED, rschema.BLOCKED):
        return rschema.UNVERIFIED
    return decision


def task_outcome(pairs: Sequence[Tuple[str, str]]) -> str:
    """``(base_state, head_state)`` per required outcome -> task_outcome."""
    if not pairs:
        return "not_evaluated"
    heads = [h for _, h in pairs]
    bases = [b for b, _ in pairs]
    if any(h == rschema.CHECK_FAIL for h in heads):
        return "not_resolved"
    if all(h == rschema.CHECK_PASS for h in heads) and all(b in (rschema.CHECK_PASS, rschema.CHECK_FAIL) for b in bases):
        if any(b == rschema.CHECK_FAIL for b in bases):
            return "resolved"
        return "already_satisfied"
    return "not_evaluated"


def sorted_codes(codes: Iterable[str]) -> List[str]:
    """Codes ordered by decision priority, then by the CODES table order."""
    order = {code: i for i, code in enumerate(rschema.CODES)}
    rank = {d: i for i, d in enumerate(rschema.DECISION_PRIORITY)}
    return sorted(set(codes), key=lambda c: (rank[rschema.CODES[c][0]], order[c]))
