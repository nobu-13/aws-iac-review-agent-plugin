"""Exit code table checks.

Locks the exit code values from design.md (Error Handling / Exit code) so that
a later refactor cannot silently renumber them: the values are part of the
Plugin's contract with host Agents and CI scripts (Requirement 16 AC8).
"""

from __future__ import annotations

import pytest

from iacreview import exitcodes

# Name -> value exactly as documented in design.md. Written out literally here
# rather than derived from the module, so the assertion fails if the module
# changes.
EXPECTED = {
    "OK": 0,
    "UNEXPECTED": 1,
    "INVALID_ARGUMENTS": 2,
    "INPUT_NOT_FOUND": 3,
    "PARSE_FAILURE": 4,
    "TOOL_UNAVAILABLE": 5,
    "TOOL_EXECUTION_FAILURE": 6,
    "PATH_VIOLATION": 7,
    "NO_REVIEWABLE_TEMPLATE": 8,
}


@pytest.mark.parametrize(("name", "value"), sorted(EXPECTED.items()))
def test_constant_has_documented_value(name: str, value: int) -> None:
    assert getattr(exitcodes, name) == value


def test_all_nine_constants_are_defined() -> None:
    assert len(EXPECTED) == 9
    for name in EXPECTED:
        assert isinstance(getattr(exitcodes, name), int)


def test_exit_code_values_are_unique() -> None:
    values = list(exitcodes.EXIT_CODES.values())
    assert len(set(values)) == len(values)


def test_mapping_matches_module_constants() -> None:
    assert dict(exitcodes.EXIT_CODES) == EXPECTED


def test_mapping_is_read_only() -> None:
    with pytest.raises(TypeError):
        exitcodes.EXIT_CODES["OK"] = 99  # type: ignore[index]


def test_public_api_covers_every_constant() -> None:
    assert set(exitcodes.__all__) == set(EXPECTED) | {"EXIT_CODES"}
