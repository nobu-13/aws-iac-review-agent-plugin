"""Machine-checked coverage of the 16 requirements and the 31 correctness properties.

Two claims are asserted here, and both are the kind that decays silently.

1. Every property in design.md's "Correctness Properties" section is implemented
   exactly once under ``tests/property/``, found by the tag comment
   ``Feature: aws-iac-review-agent-plugin, Property N:`` that section fixes as the
   marking convention. A property that loses its implementation in a refactor, or
   gains a second one in a different file, fails here.

2. ``docs/traceability.md`` maps all 182 acceptance criteria of the 16
   requirements onto a test file or a document that realizes them, every
   referenced path exists, and no criterion is left blank.

The tag search is the same technique as
``tests/unit/test_ci.py::property_14_test_file``, generalized from one property to
all 31. That helper stays where it is: the workflow needs the *path* of the
Property 14 file in order to assert that CI re-runs it with a randomized hash
seed, and locating it by tag is what makes that assertion about the real
implementation. This module needs only the counts, so the two do not overlap
beyond the shared tag format.

Why the criterion counts are literals
-------------------------------------

:data:`EXPECTED_CRITERION_COUNTS` is the one table in this module that is not read
from something else, and that is deliberate. Elsewhere in this suite an expected
value is derived from the implementation, because a literal is a second place for
the same fact to go stale. Here the fact is not an implementation detail: "there
are 16 acceptance criteria under Requirement 2" is a property of the requirements
document, and the whole point of the check is to notice when the traceability
table stops agreeing with it. Reading the count out of the same table it is meant
to validate would make the assertion vacuous.

The literals are still cross-checked. ``requirements.md`` lives under ``.kiro/``,
which is not part of the distributed package, so
:func:`test_expected_counts_match_the_requirements_document` reads it when it is
present and skips when it is not. That keeps the table honest in a development
checkout without making the rest of the module depend on a directory the package
does not ship.

Covers:
- Requirement 12 AC1, AC9  : the coverage claims of the suite are traceable to
                             the criteria they are claimed for
- Requirement 12 AC10      : every regression case is reachable from the table
- Requirement 13 AC9, AC11 : ``docs/traceability.md`` is a reference under
                             ``docs/`` and points only at paths that exist
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

import pytest

# tests/unit/test_traceability.py -> tests/unit -> tests -> repository root
REPO_ROOT: Path = Path(__file__).resolve().parents[2]

PROPERTY_TESTS_DIR: Path = REPO_ROOT / "tests" / "property"
TRACEABILITY_PATH: Path = REPO_ROOT / "docs" / "traceability.md"

#: ``requirements.md``, for the cross-check that may skip. Under ``.kiro/``, which
#: the distributed package does not contain.
REQUIREMENTS_PATH: Path = (
    REPO_ROOT / ".kiro" / "specs" / "aws-iac-review-agent-plugin" / "requirements.md"
)

#: The number of properties design.md's "Correctness Properties" section defines.
PROPERTY_COUNT = 31

#: Acceptance criteria per requirement, as ``requirements.md`` numbers them. See
#: the module docstring for why these are literals.
EXPECTED_CRITERION_COUNTS: Dict[int, int] = {
    1: 11,
    2: 16,
    3: 6,
    4: 13,
    5: 8,
    6: 13,
    7: 17,
    8: 11,
    9: 8,
    10: 9,
    11: 16,
    12: 12,
    13: 11,
    14: 13,
    15: 7,
    16: 11,
    # v0.8.0 (Robustness, Determinism, Measurement).
    17: 9,
    18: 4,
    19: 7,
    # v0.9.0 (redaction reach, timing as data, settled positions).
    20: 6,
    21: 5,
    22: 6,
}

#: The v0.1 total (182), plus the 20 criteria of the three v0.8.0 requirements,
#: plus the 17 criteria of the three v0.9.0 requirements (R20 6, R21 5, R22 6).
EXPECTED_TOTAL_CRITERIA = 219

#: A level-2 heading of ``docs/traceability.md`` that opens a requirement's table.
REQUIREMENT_HEADING_PATTERN = re.compile(r"^##\s+Requirement\s+(\d+):")

#: The first cell of a criterion row.
CRITERION_CELL_PATTERN = re.compile(r"^AC(\d+)$")

#: A repository-relative path in backticks, as the table writes them.
BACKTICKED_PATH_PATTERN = re.compile(r"`([A-Za-z0-9_][A-Za-z0-9_./-]*/[A-Za-z0-9_./-]+)`")

#: A numbered heading in ``requirements.md``.
REQUIREMENTS_HEADING_PATTERN = re.compile(r"^### Requirement (\d+):")

#: A numbered acceptance criterion in ``requirements.md``.
REQUIREMENTS_CRITERION_PATTERN = re.compile(r"^(\d+)\. ")

_FENCE = "```"


# ---------------------------------------------------------------------------
# The property tags
# ---------------------------------------------------------------------------


def property_tag(number: int) -> str:
    """The tag comment that marks the implementation of one property."""
    return "Feature: aws-iac-review-agent-plugin, Property {0}:".format(number)


@pytest.fixture(scope="module")
def property_test_sources() -> Dict[Path, str]:
    """Every property test module under ``tests/property/``, by path.

    Read once: 31 parametrized cases over a dozen files is a dozen reads, not
    several hundred.
    """
    sources = {
        path: path.read_text(encoding="utf-8")
        for path in sorted(PROPERTY_TESTS_DIR.rglob("test_*.py"))
    }
    assert sources, "no property test modules under {0}".format(PROPERTY_TESTS_DIR)
    return sources


def files_carrying(sources: Dict[Path, str], tag: str) -> List[str]:
    """Repository-relative paths of the modules containing ``tag``."""
    return sorted(
        str(path.relative_to(REPO_ROOT)) for path, text in sources.items() if tag in text
    )


@pytest.mark.parametrize("number", range(1, PROPERTY_COUNT + 1))
def test_each_property_is_implemented_exactly_once(
    property_test_sources: Dict[Path, str], number: int
) -> None:
    """One property, one implementation, located by its tag rather than by name.

    Zero matches means the property was dropped or its tag was reworded; two
    means the same property is asserted in two places, which is how one of them
    quietly stops being maintained.
    """
    carriers = files_carrying(property_test_sources, property_tag(number))
    assert len(carriers) == 1, (
        "Property {0} is tagged in {1} files under tests/property/, expected 1: "
        "{2}".format(number, len(carriers), carriers)
    )


def test_no_property_tag_names_a_number_outside_the_defined_range(
    property_test_sources: Dict[Path, str]
) -> None:
    """A tag for Property 32 is a property design.md does not define.

    The per-number test above cannot see such a tag, so it is checked from the
    other direction: every tag found has to name a number in range.
    """
    pattern = re.compile(r"Feature: aws-iac-review-agent-plugin, Property (\d+):")
    tagged = {
        int(match)
        for text in property_test_sources.values()
        for match in pattern.findall(text)
    }
    unexpected = sorted(number for number in tagged if not 1 <= number <= PROPERTY_COUNT)
    assert not unexpected, "tags name undefined properties: {0}".format(unexpected)


# ---------------------------------------------------------------------------
# Reading docs/traceability.md
# ---------------------------------------------------------------------------


def body_lines(text: str) -> List[str]:
    """Lines of ``text`` with fenced code blocks removed.

    Same reason as ``tests/unit/test_docs.py::body_lines``: a table pipe or a
    ``#`` inside a fence is not structure.
    """
    lines: List[str] = []
    inside_fence = False
    for line in text.splitlines():
        if line.startswith(_FENCE):
            inside_fence = not inside_fence
            continue
        if not inside_fence:
            lines.append(line)
    return lines


def table_row_cells(line: str) -> List[str]:
    """The cells of one Markdown table row, or an empty list for anything else."""
    stripped = line.strip()
    if not (stripped.startswith("|") and stripped.endswith("|")):
        return []
    return [cell.strip() for cell in stripped.strip("|").split("|")]


@pytest.fixture(scope="module")
def criterion_rows() -> Dict[int, List[Tuple[int, List[str]]]]:
    """Criterion rows of ``docs/traceability.md``, grouped by requirement.

    A row counts only when it sits under a ``## Requirement N:`` heading and its
    first cell is ``ACn``. That keeps the reader's tables at the top of the
    document -- the column legend and the count summary -- out of the data, and it
    means a row moved under the wrong heading is a miscount rather than a silent
    reassignment.
    """
    assert TRACEABILITY_PATH.is_file(), "Task 29.1 requires {0}".format(TRACEABILITY_PATH)
    grouped: Dict[int, List[Tuple[int, List[str]]]] = {}
    current: int = 0
    for line in body_lines(TRACEABILITY_PATH.read_text(encoding="utf-8")):
        heading = REQUIREMENT_HEADING_PATTERN.match(line)
        if heading:
            current = int(heading.group(1))
            grouped.setdefault(current, [])
            continue
        if line.startswith("## "):
            current = 0
            continue
        if not current:
            continue
        cells = table_row_cells(line)
        if not cells:
            continue
        match = CRITERION_CELL_PATTERN.match(cells[0])
        if match:
            grouped[current].append((int(match.group(1)), cells))
    return grouped


def verified_by(cells: Sequence[str]) -> str:
    """The "Verified by" cell of a criterion row."""
    return cells[2] if len(cells) > 2 else ""


# ---------------------------------------------------------------------------
# (a) every requirement appears
# ---------------------------------------------------------------------------


def test_the_document_covers_exactly_the_sixteen_requirements(
    criterion_rows: Dict[int, List[Tuple[int, List[str]]]]
) -> None:
    """No requirement is missing, and no seventeenth one is invented."""
    assert sorted(criterion_rows) == sorted(EXPECTED_CRITERION_COUNTS)


# ---------------------------------------------------------------------------
# (b) the criterion counts agree
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("requirement", sorted(EXPECTED_CRITERION_COUNTS))
def test_criterion_numbers_run_from_one_to_the_expected_count(
    criterion_rows: Dict[int, List[Tuple[int, List[str]]]], requirement: int
) -> None:
    """Every criterion of a requirement is present, exactly once, in order.

    Asserted as the sequence rather than as the length: a table with the right
    number of rows but a duplicated ``AC3`` and a missing ``AC7`` would pass a
    count check and hide a real gap.
    """
    numbers = [number for number, _ in criterion_rows[requirement]]
    expected = list(range(1, EXPECTED_CRITERION_COUNTS[requirement] + 1))
    assert numbers == expected, (
        "Requirement {0} lists {1}, expected AC1 to AC{2}".format(
            requirement, numbers, EXPECTED_CRITERION_COUNTS[requirement]
        )
    )


def test_the_document_maps_the_expected_total(
    criterion_rows: Dict[int, List[Tuple[int, List[str]]]]
) -> None:
    """182 criteria, as the completion condition of Task 29.1 states."""
    mapped = sum(len(rows) for rows in criterion_rows.values())
    assert mapped == EXPECTED_TOTAL_CRITERIA


def test_the_expected_counts_sum_to_the_expected_total() -> None:
    """The two literals in this module agree with each other.

    Cheap, and it catches the mistake of editing one requirement's count without
    revisiting whether the total still holds.
    """
    assert sum(EXPECTED_CRITERION_COUNTS.values()) == EXPECTED_TOTAL_CRITERIA


def test_expected_counts_match_the_requirements_document() -> None:
    """The literal table against ``requirements.md``, when it is available.

    Skipped rather than failed when ``.kiro/`` is absent: the specification is not
    part of the distributed package, and a test that fails outside a development
    checkout would be measuring the packaging rather than the requirement.
    """
    if not REQUIREMENTS_PATH.is_file():
        pytest.skip("{0} is not present in this checkout".format(REQUIREMENTS_PATH))

    counted: Dict[int, int] = {}
    current = 0
    for line in body_lines(REQUIREMENTS_PATH.read_text(encoding="utf-8")):
        heading = REQUIREMENTS_HEADING_PATTERN.match(line)
        if heading:
            current = int(heading.group(1))
            counted[current] = 0
            continue
        if line.startswith("## ") and not line.startswith("###"):
            current = 0  # past the requirements, into the assumptions
            continue
        if current and REQUIREMENTS_CRITERION_PATTERN.match(line):
            counted[current] += 1
    assert counted == EXPECTED_CRITERION_COUNTS


# ---------------------------------------------------------------------------
# (c) referenced paths exist
# ---------------------------------------------------------------------------


def test_every_path_the_table_references_exists(
    criterion_rows: Dict[int, List[Tuple[int, List[str]]]]
) -> None:
    """A mapping onto a file that is not there is not a mapping.

    Both columns that can name a path are read -- "Verified by" and "Notes" --
    because a note that points at a deleted document is the same failure as a
    "Verified by" cell that points at a deleted test.
    """
    missing: List[str] = []
    for requirement, rows in sorted(criterion_rows.items()):
        for number, cells in rows:
            for cell in cells[2:]:
                for referenced in BACKTICKED_PATH_PATTERN.findall(cell):
                    if not (REPO_ROOT / referenced).exists():
                        missing.append(
                            "R{0} AC{1} -> {2}".format(requirement, number, referenced)
                        )
    assert not missing, "the table references paths that do not exist: {0}".format(missing)


def test_every_criterion_is_verified_by_at_least_one_real_file(
    criterion_rows: Dict[int, List[Tuple[int, List[str]]]]
) -> None:
    """The "Verified by" column names a path, not prose.

    Separate from the existence check above so that "this cell names nothing" and
    "this cell names something that is gone" report as different problems.
    """
    pathless: List[str] = []
    for requirement, rows in sorted(criterion_rows.items()):
        for number, cells in rows:
            if not BACKTICKED_PATH_PATTERN.findall(verified_by(cells)):
                pathless.append("R{0} AC{1}".format(requirement, number))
    assert not pathless, (
        "criteria whose Verified by column names no path: {0}".format(pathless)
    )


# ---------------------------------------------------------------------------
# (d) nothing is left blank
# ---------------------------------------------------------------------------


def test_no_criterion_row_is_blank(
    criterion_rows: Dict[int, List[Tuple[int, List[str]]]]
) -> None:
    """Every cell of every criterion row carries something.

    A blank cell is the failure mode this document exists to prevent: it reads as
    "not yet mapped" to a person and as "fine" to a naive parser. An unmapped
    criterion is a finding to be written down, in the Notes column and in the
    document's "Gaps and conflicts" section, not an empty cell.
    """
    problems: List[str] = []
    for requirement, rows in sorted(criterion_rows.items()):
        for number, cells in rows:
            label = "R{0} AC{1}".format(requirement, number)
            if len(cells) != 4:
                problems.append("{0}: {1} cells, expected 4".format(label, len(cells)))
                continue
            blank = [index for index, cell in enumerate(cells) if not cell]
            if blank:
                problems.append("{0}: blank columns {1}".format(label, blank))
    assert not problems, "malformed or blank criterion rows: {0}".format(problems)


def test_the_qualified_rows_are_explained_in_the_document(
    criterion_rows: Dict[int, List[Tuple[int, List[str]]]]
) -> None:
    """A row marked PARTIAL or GAP points at prose that says what is missing.

    The marker is what stops a qualified mapping from reading like a complete one,
    and it is worth nothing unless the document explains it. Checked as "the
    document has a section for the gaps, and every marked row is discussed there
    by requirement and criterion", so a marker added without an explanation fails.
    """
    text = TRACEABILITY_PATH.read_text(encoding="utf-8")
    assert "## Gaps and conflicts" in text, "the document has no gaps section"
    unexplained: List[str] = []
    for requirement, rows in sorted(criterion_rows.items()):
        for number, cells in rows:
            joined = " ".join(cells[2:])
            if not any(marker in joined for marker in ("PARTIAL", "GAP", "CONFLICT")):
                continue
            reference = "Requirement {0} AC{1}".format(requirement, number)
            paired = "AC{0} and AC{1}".format(number - 1, number)
            if reference not in text and paired not in text:
                unexplained.append(reference)
    assert not unexplained, (
        "qualified rows with no explanation in the document: {0}".format(unexplained)
    )
