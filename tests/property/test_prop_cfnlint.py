"""Property 10: how :func:`iacreview.cfnlint.decode_cfnlint_exit` reads a status.

cfn-lint's exit status is a bit mask, not a magnitude: 2 means an Error-level
finding was reported, 4 a Warning, 8 an Informational, and they are OR-ed. So the
run succeeded exactly when the status sets no bit outside ``{2, 4, 8}``
(Requirement 4 AC11), and any other status -- exit 1 above all, which is a crash
or a usage error rather than a count of findings (Requirement 4 AC12) -- is a
failure.

``tests/unit/test_cfnlint_exit.py`` pins the decoding for 0 through 16 one code at
a time, and ``tests/integration/test_fakebin_drives_sources.py`` drives the same
decision end to end through a fake cfn-lint. Neither is repeated here. What this
file adds is the *universally quantified* statement: over the whole integer range,
the decision agrees with a subset test computed independently of the mask
arithmetic the decoder uses. A decoder that special-cased the sixteen codes the
unit test enumerates, or that compared magnitudes above them, would pass there and
fail here.

**Negative statuses.** The property talks about "the set bits of that code", and
for a negative integer that phrase needs a definition, because Python's ``int`` is
conceptually an infinite two's-complement value: ``-2`` is ``...1111110``, so all
but finitely many of its bits are set. Under that reading a negative code has
infinitely many set bits, which can never be a subset of a three-element set, so
every negative status is a failure. That is also the answer the requirement wants
for the situation negatives arise from -- CPython reports "killed by signal N" as
``-N``, and a tool that died on a signal reported nothing (:mod:`iacreview.proc`
passes the status through unchanged). The alternative reading, masking a negative
down to some fixed width, would classify ``-6`` as a successful run that found
Errors and Warnings, which is exactly wrong. :func:`_set_bit_values` below states
the definition rather than leaving it to the ``&`` operator's behaviour, so the
test would still hold a position if the decoder's arithmetic changed.

The generator is :func:`strategies.exit_codes`, which reaches negative values,
zero, the seven successful masks, and values far above 255; its own coverage is
asserted in ``test_strategies_smoke.py``, not here.
"""

from __future__ import annotations

from typing import Optional, Set

from hypothesis import given, settings

import strategies as S
from iacreview.cfnlint import decode_cfnlint_exit

#: The bit values cfn-lint sets to report that findings exist, as Requirement 4
#: AC11 and Property 10 name them: 2 (Error), 4 (Warning), 8 (Informational).
#: Written out as the three-element set the property is stated over rather than
#: taken from :data:`iacreview.cfnlint.CFNLINT_FINDING_BITS`, whose value is the
#: OR the decoder computes with -- an oracle built from it would agree with the
#: implementation by construction. That constant is pinned separately in
#: ``tests/unit/test_cfnlint_exit.py``.
FINDING_BITS = frozenset((2, 4, 8))


def _set_bit_values(code: int) -> Optional[Set[int]]:
    """The bit values set in ``code``, or ``None`` when there are infinitely many.

    Read off the binary representation digit by digit instead of masking, so the
    oracle shares no arithmetic with the decoder under test.

    Args:
        code: Any integer.

    Returns:
        For a non-negative ``code``, ``{2 ** i for each set bit i}``; the empty
        set for 0. ``None`` for a negative ``code``: its two's-complement form
        has an infinite tail of set bits, so no finite set of bit values
        describes it (see the module docstring).
    """
    if code < 0:
        return None
    return {
        1 << index
        for index, digit in enumerate(reversed(bin(code)[2:]))
        if digit == "1"
    }


def _is_finding_bit_subset(code: int) -> bool:
    """Whether ``code``'s set bits form a subset of :data:`FINDING_BITS`."""
    values = _set_bit_values(code)
    return values is not None and values <= FINDING_BITS


# Feature: aws-iac-review-agent-plugin, Property 10: For any integer exit code,
# the decoder classifies the invocation as successful if and only if the set bits
# of that code form a subset of {2, 4, 8}.
@settings(max_examples=100)
@given(S.exit_codes())
def test_success_holds_exactly_when_the_set_bits_are_finding_bits(code: int) -> None:
    """**Validates: Requirements 4.11, 4.12**

    An equivalence, asserted in both directions by one comparison: a code whose
    bits stay inside the mask must decode as a success, and every other code --
    including 1, 3, 16, anything above 255, and every negative status -- must
    not.
    """
    assert decode_cfnlint_exit(code).ok is _is_finding_bit_subset(code)
