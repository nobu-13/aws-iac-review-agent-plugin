"""Machine-checked traceability of the v1.1 Delta_Tool specification.

The v1.1 tasks document (section 2-1, "AC and Task") maps every acceptance
criterion of the v1.1 requirements onto the Tasks that verify it and the kind of
verification (unit, property, regression, integration, contract, document,
Quality Gate, measurement). This module asserts that the table still agrees with
the requirements and with the test files that exist:

1. every acceptance criterion of the 16 v1.1 requirements appears in the table,
   and the table names no criterion the requirements do not define
2. every Task in the table is a Task the tasks document defines
3. every (criterion, Task) pair of the table is listed in that Task's
   ``_Requirements_`` line, so the two places cannot drift apart
4. every test file a Task names exists
5. every criterion verified by a test (U, P, R, I, C, D) has at least one
   implemented Task (0.x, 1-14) that names an existing test file
6. the criteria whose only Tasks lie after Task 14 are exactly the known set,
   so a criterion cannot silently lose its v1.1 verification

The specification lives under ``.kiro/``, which the distributed package and the
CI checkout do not contain. The module skips when it is absent; that skip is not
a PASS, and Task 14 runs it in a development checkout.

Covers: v1.1 Requirement 15 AC1 (tasks.md Task 14).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, FrozenSet, List, Set, Tuple

import pytest

# tests/unit/test_delta_traceability.py -> tests/unit -> tests -> repository root
REPO_ROOT: Path = Path(__file__).resolve().parents[2]

SPEC_DIR: Path = REPO_ROOT / ".kiro" / "specs" / "aws-iac-bounded-remediation-v1.1"
REQUIREMENTS_PATH: Path = SPEC_DIR / "requirements.md"
TASKS_PATH: Path = SPEC_DIR / "tasks.md"

#: Acceptance criteria per v1.1 requirement. A literal on purpose: reading the
#: count from the document it validates would make the check vacuous. It is
#: cross-checked against ``requirements.md`` below.
EXPECTED_CRITERION_COUNTS: Dict[int, int] = {
    1: 11,
    2: 12,
    3: 12,
    4: 15,
    5: 11,
    6: 15,
    7: 10,
    8: 8,
    9: 10,
    10: 6,
    11: 10,
    12: 18,
    13: 7,
    14: 12,
    15: 9,
    16: 7,
}
EXPECTED_TOTAL_CRITERIA = 173

#: Tasks of Phase 0 to Phase 5, the scope of the v1.1 implementation (Task 14).
IMPLEMENTED_TASKS: FrozenSet[str] = frozenset(
    ["0.1", "0.2", "0.3", "0.4", "0.5"] + [str(n) for n in range(1, 15)]
)

#: Criteria whose Tasks are all after Task 14 (or the Human Gate H1): R13.7 is
#: the README / CHANGELOG of Task 15, R14.11 the M1 measurement of Task 16.
DEFERRED_CRITERIA: FrozenSet[Tuple[int, int]] = frozenset([(13, 7), (14, 11)])

#: Verification letters that the table uses for a check made by a test file.
TEST_LETTERS: FrozenSet[str] = frozenset("UPRICD")

#: All verification letters of the table's legend, plus the two worded forms.
KNOWN_LETTERS: FrozenSet[str] = frozenset("UPRICDGM")
KNOWN_WORDS: FrozenSet[str] = frozenset(["確認記録", "Gate"])

REQUIREMENT_HEADING = re.compile(r"^### Requirement (\d+):")
CRITERION_LINE = re.compile(r"^(\d+)\. ")
TASK_LINE = re.compile(r"^- \[[ x]\] (\d+(?:\.\d+)?)\.? ")
TEST_PATH = re.compile(r"`(tests/[A-Za-z0-9_/]+/test_[A-Za-z0-9_]+\.py)`")
REQUIREMENTS_LINE = re.compile(r"^\s*- _Requirements: (.+)_\s*$")
AC_REF = re.compile(r"^(\d+)\.(\d+)$")
TABLE_HEADING = "### 2-1."
REQ_CELL = re.compile(r"^R(\d+)\b")
TASK_CELL = re.compile(r"^(?:\d+(?:\.\d+)?|H\d)$")
LETTER_TOKEN = re.compile(r"^([A-Z]+|確認記録)")

_FENCE = "```"

Criterion = Tuple[int, int]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def spec() -> Tuple[str, str]:
    if not REQUIREMENTS_PATH.is_file() or not TASKS_PATH.is_file():
        pytest.skip("the v1.1 specification under .kiro/ is absent (not a PASS)")
    return _read(REQUIREMENTS_PATH), _read(TASKS_PATH)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def requirement_criteria(text: str) -> Dict[int, List[int]]:
    """The criterion numbers under each requirement's Acceptance Criteria."""
    found: Dict[int, List[int]] = {}
    requirement = None
    in_criteria = False
    in_fence = False
    for line in text.splitlines():
        if line.startswith(_FENCE):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        heading = REQUIREMENT_HEADING.match(line)
        if heading:
            requirement = int(heading.group(1))
            in_criteria = False
            continue
        if line.startswith("## ") or line.startswith("### "):
            requirement = None
            in_criteria = False
            continue
        if line.startswith("#### "):
            in_criteria = requirement is not None and "Acceptance Criteria" in line
            continue
        if in_criteria and requirement is not None:
            criterion = CRITERION_LINE.match(line)
            if criterion:
                found.setdefault(requirement, []).append(int(criterion.group(1)))
    return found


def _numbers(cell: str) -> List[int]:
    """``"1, 4-8, 10"`` -> ``[1, 4, 5, 6, 7, 8, 10]``."""
    out: List[int] = []
    for part in cell.split(","):
        part = part.strip()
        if "-" in part:
            low, high = (int(p) for p in part.split("-"))
            assert low <= high, cell
            out.extend(range(low, high + 1))
        else:
            out.append(int(part))
    return out


def _letters(cell: str) -> Set[str]:
    """``"U（file 非生成）、U（AST）"`` -> ``{"U"}``; ``"M、Gate"`` -> ``{"M", "Gate"}``."""
    out: Set[str] = set()
    for part in cell.split("、"):
        token = LETTER_TOKEN.match(part.strip())
        assert token, cell
        out.add(token.group(1))
    return out


def traceability_rows(text: str) -> List[Tuple[int, List[int], List[str], Set[str]]]:
    """The rows of section 2-1: (requirement, criteria, Tasks, verification)."""
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith(TABLE_HEADING))
    rows: List[Tuple[int, List[int], List[str], Set[str]]] = []
    requirement = None
    for line in lines[start + 1 :]:
        if line.startswith("#"):
            break
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) != 4 or cells[0] == "Req" or set(cells[1]) <= set("-: "):
            continue
        if cells[0]:
            match = REQ_CELL.match(cells[0])
            assert match, line
            requirement = int(match.group(1))
        assert requirement is not None, line
        tasks = [t.strip() for t in cells[2].split(",")]
        rows.append((requirement, _numbers(cells[1]), tasks, _letters(cells[3])))
    assert rows, "section 2-1 has no rows"
    return rows


def task_sections(text: str) -> Dict[str, Tuple[List[str], Set[Criterion]]]:
    """Each Task of section 1: (named test files, ``_Requirements_`` criteria)."""
    sections: Dict[str, Tuple[List[str], Set[Criterion]]] = {}
    current = None
    for line in text.splitlines():
        if line.startswith("## ") and current is not None:
            break
        task = TASK_LINE.match(line)
        if task:
            current = task.group(1)
            sections[current] = ([], set())
        elif line.startswith("- [") and current is not None:
            current = None  # a Human Gate line, not a Task
        if current is None:
            continue
        tests, criteria = sections[current]
        tests.extend(TEST_PATH.findall(line))
        listed = REQUIREMENTS_LINE.match(line)
        if listed:
            for ref in listed.group(1).split(","):
                ac = AC_REF.match(ref.strip())
                assert ac, (current, ref)
                criteria.add((int(ac.group(1)), int(ac.group(2))))
    return sections


# ---------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------


def test_expected_counts_match_the_requirements_document(spec: Tuple[str, str]) -> None:
    found = requirement_criteria(spec[0])
    assert {r: len(v) for r, v in found.items()} == EXPECTED_CRITERION_COUNTS
    for requirement, numbers in found.items():
        assert numbers == list(range(1, len(numbers) + 1)), requirement
    assert sum(EXPECTED_CRITERION_COUNTS.values()) == EXPECTED_TOTAL_CRITERIA


def test_table_covers_exactly_the_criteria(spec: Tuple[str, str]) -> None:
    rows = traceability_rows(spec[1])
    in_table = {(r, ac) for r, acs, _, _ in rows for ac in acs}
    expected = {(r, ac) for r, n in EXPECTED_CRITERION_COUNTS.items() for ac in range(1, n + 1)}
    assert sorted(expected - in_table) == [], "criteria missing from the table"
    assert sorted(in_table - expected) == [], "table names undefined criteria"


def test_table_uses_known_tasks_and_verification(spec: Tuple[str, str]) -> None:
    sections = task_sections(spec[1])
    for requirement, acs, tasks, letters in traceability_rows(spec[1]):
        for task in tasks:
            assert TASK_CELL.match(task), (requirement, acs, task)
            assert task in sections or task.startswith("H"), (requirement, acs, task)
        unknown = {t for t in letters if not (set(t) <= KNOWN_LETTERS or t in KNOWN_WORDS)}
        assert not unknown, (requirement, acs, unknown)


def test_table_agrees_with_each_tasks_requirements_line(spec: Tuple[str, str]) -> None:
    sections = task_sections(spec[1])
    missing = []
    for requirement, acs, tasks, _ in traceability_rows(spec[1]):
        for task in tasks:
            if task.startswith("H"):
                continue
            listed = sections[task][1]
            missing.extend((task, requirement, ac) for ac in acs if (requirement, ac) not in listed)
    assert missing == [], "table pairs absent from the Task's _Requirements_ line"


def test_every_named_test_file_exists(spec: Tuple[str, str]) -> None:
    named = {path for tests, _ in task_sections(spec[1]).values() for path in tests}
    assert named, "no test file is named"
    missing = sorted(p for p in named if not (REPO_ROOT / p).is_file())
    assert missing == [], "named test files that do not exist"


def test_every_tested_criterion_has_an_implemented_test(spec: Tuple[str, str]) -> None:
    sections = task_sections(spec[1])
    untested = []
    for requirement, acs, tasks, letters in traceability_rows(spec[1]):
        if not any(set(t) & TEST_LETTERS for t in letters if t not in KNOWN_WORDS):
            continue
        with_tests = [
            t
            for t in tasks
            if t in IMPLEMENTED_TASKS and any((REPO_ROOT / p).is_file() for p in sections[t][0])
        ]
        if not with_tests:
            untested.extend((requirement, ac) for ac in acs)
    unexpected = sorted(set(untested) - DEFERRED_CRITERIA)
    assert unexpected == [], "criteria without an implemented test"


def test_deferred_criteria_are_exactly_the_known_set(spec: Tuple[str, str]) -> None:
    by_criterion: Dict[Criterion, Set[str]] = {}
    for requirement, acs, tasks, _ in traceability_rows(spec[1]):
        for ac in acs:
            by_criterion.setdefault((requirement, ac), set()).update(tasks)
    deferred = {c for c, tasks in by_criterion.items() if not tasks & IMPLEMENTED_TASKS}
    assert deferred == DEFERRED_CRITERIA
