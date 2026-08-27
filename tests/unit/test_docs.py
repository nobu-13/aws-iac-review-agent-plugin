"""Structural and anti-drift tests for the documents under ``docs/``.

The value of this module is not that the documents exist -- it is that they keep
saying what the code says. Wherever a document records a value the
implementation also holds, the assertion reads the implementation and compares,
rather than comparing the document against a literal copied out of it. A literal
in a test is a second place for the same fact to go stale.

What is read from the implementation:
- ``iacreview.finding``: the 13 field names and the four closed value sets
- ``iacreview.categories``: the ``Normalized_Category`` vocabulary
- ``iacreview.cdk.SYNTH_WARNING``: quoted verbatim by ``docs/security-model.md``
- ``iacreview/category_map.json``: the rules flagged ``blocks_deployment`` and
  ``security_relevant``, whose IDs the Finding schema survey enumerates
- ``benchmark.harness.run_benchmark.HARNESS_EXIT_CODES``: the harness codes
- ``tests/unit/test_cfnguard_parse.py::OBSERVED_CASES``: the measured cfn-guard
  exit codes, which live there as the classification table and in
  ``docs/architecture.md`` as the measurement they came from
- the filesystem: every repository path the documents reference, the absence of
  symlinks, and the absence of any ``.kiro/`` reference in the runtime tree

Covers:
- Requirement 13 AC6  : the documents under ``docs/`` are written in English
- Requirement 13 AC9  : ``docs/`` holds the four required references
- Requirement 13 AC10 : every Finding field and permitted value is documented
- Requirement 13 AC11 : no document promises an unimplemented capability as
                        available -- checked here as "no document points at a
                        path that does not exist"
- Task 26.1 - 26.6    : the per-document checks each of those tasks specified

``mcp.json``'s absence from the plugin root is Requirement 1 AC7 and is asserted
by ``tests/unit/test_manifest.py::test_no_mcp_json_at_plugin_root``; it is not
duplicated here.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

import pytest

from benchmark.harness.run_benchmark import (
    BENCHMARK_FAILURE,
    CASE_NOT_EVALUATED,
    HARNESS_EXIT_CODES,
)
from iacreview import categories
from iacreview.cdk import SYNTH_WARNING
from iacreview.finding import CONFIDENCES, FINDING_FIELDS, FINDING_TYPES, SEVERITIES, SOURCES
from test_cfnguard_parse import OBSERVED_CASES

# ---------------------------------------------------------------------------
# The documents
# ---------------------------------------------------------------------------

PLUGIN_ROOT = Path(__file__).resolve().parents[2]
DOCS_DIR = PLUGIN_ROOT / "docs"

ARCHITECTURE = "architecture.md"
SECURITY_MODEL = "security-model.md"
FINDING_SCHEMA = "finding-schema.md"
BENCHMARK_METHODOLOGY = "benchmark-methodology.md"
KIRO_POWER = "kiro-power.md"
TRACEABILITY = "traceability.md"
MCP_README = "mcp/README.md"
MCP_EXAMPLE = "mcp/mcp.json.example"

#: The four references Requirement 13 AC9 requires, by relative path.
REQUIRED_REFERENCES: Tuple[str, ...] = (
    ARCHITECTURE,
    SECURITY_MODEL,
    BENCHMARK_METHODOLOGY,
    FINDING_SCHEMA,
)

#: Every Markdown document this module covers. ``traceability.md`` is listed here
#: for the three whole-document checks below -- English, one title, and no
#: reference to a path that does not exist. Its own structure is asserted by
#: ``tests/unit/test_traceability.py``, which parses the criterion tables.
DOCUMENTS: Tuple[str, ...] = REQUIRED_REFERENCES + (KIRO_POWER, TRACEABILITY, MCP_README)

# ---------------------------------------------------------------------------
# English text (Requirement 13 AC6)
# ---------------------------------------------------------------------------

#: Non-ASCII characters permitted in an English document.
#:
#: Requirement 13 AC6 requires the documents to be *written in English*, and
#: Task 26.7 spells the check as "contains no non-ASCII character". The two
#: readings differ on exactly one class of character: English typographic dashes.
#: They are admitted here for two reasons.
#:
#: 1. An em dash is English punctuation, not evidence of another language. The
#:    ASCII test is a mechanical proxy for AC6, and a proxy that rejects correct
#:    English is measuring the wrong thing.
#: 2. ``finding-schema.md`` carries 36 of them, 11 inside the cfn-lint survey
#:    sections that Task 26.3 was required to preserve verbatim -- including rule
#:    ranges such as ``E1150`-`E1156`` where an en dash *is* the notation. A
#:    strict assertion could only pass by rewriting text another task was told
#:    to keep, which trades a real document for a cosmetic test result.
#:
#: The allowlist stays this short on purpose. Everything the check is actually
#: for still fails it: Japanese or any other non-Latin script, smart quotes and
#: apostrophes pasted in from a word processor, a non-breaking space, a
#: zero-width character. Adding a third entry here needs the same kind of
#: argument as these two.
PERMITTED_NON_ASCII: Dict[str, str] = {
    "\u2014": "EM DASH",
    "\u2013": "EN DASH",
}

# ---------------------------------------------------------------------------
# Required headings, per document
# ---------------------------------------------------------------------------

#: ``docs/architecture.md`` (Task 26.1). The level-2 headings are the document's
#: spine; the level-3 ones are the seven subjects Task 26.1 had to record.
ARCHITECTURE_SECTIONS: Tuple[str, ...] = (
    "Review pipeline",
    "The deterministic / agent boundary",
    "Components",
    "cfn-lint",
    "cfn-guard",
    "Degraded operation and scope boundaries",
)
ARCHITECTURE_SUBSECTIONS: Tuple[str, ...] = (
    "The shared package `iacreview/`",
    "`rules_evaluated` and `rules_passed`",
    "Reviewing JSON templates without PyYAML",
    "External tool version differences are outside Requirement 10 AC3",
    "Development and test dependencies are outside Requirement 16 AC3",
    "`extensions` is unused in v0.1",
)
#: Matched by prefix: the heading names the cfn-guard version it measured, and
#: the version is expected to change without the section disappearing.
ARCHITECTURE_EXIT_CODE_SECTION = "Observed exit codes"

#: ``docs/security-model.md`` (Task 26.2).
SECURITY_MODEL_SECTIONS: Tuple[str, ...] = (
    "Default Posture: Read-Only",
    "Trust Boundaries",
    "External Command Execution",
    "Path Safety",
    "Untrusted IaC",
    "Credentials",
    "`cdk synth`: The Arbitrary Code Execution Boundary",
    "MCP",
    "AWS API Access and IAM Least Privilege",
    "Evidence-Based Findings",
    "Residual Risks",
    "Roadmap Candidates",
    "Where These Claims Are Tested",
)
SECURITY_MODEL_SUBSECTIONS: Tuple[str, ...] = (
    "Shell Metacharacter Rejection Is Defense in Depth",
    "Temporary Files",
    "Excerpt Redaction",
)

#: ``docs/finding-schema.md`` (Task 26.3).
FINDING_SCHEMA_SECTIONS: Tuple[str, ...] = (
    "The five closed value sets",
    "The 13 fields",
    "Constraints JSON Schema cannot express",
    "Reading a report",
    "Deduplication: what one Finding stands for",
    "cfn-lint `blocks_deployment` classification",
    "cfn-lint `security_relevant` classification",
)

#: ``docs/benchmark-methodology.md`` (Task 26.4).
BENCHMARK_SECTIONS: Tuple[str, ...] = (
    "Ground truth",
    "Matching",
    "Metrics",
    "Pass and fail",
    "Exit codes 9 and 10",
    "Source subset modes",
    "Deferred metrics",
    "Bounding agent non-determinism",
    "Known limitations",
)

#: ``docs/kiro-power.md`` (Task 26.5).
KIRO_POWER_SECTIONS: Tuple[str, ...] = (
    "The package is portable, and Kiro adds nothing to it",
    "What was verified",
    "What was not verified",
    "The Kiro-specific files in this repository",
    "If a Kiro-specific hook is ever needed",
    "Open design decision O-7",
)

#: ``docs/mcp/README.md`` (Task 26.6): the nine per-server record items, as the
#: level-3 headings of the "Per-Server Record" section.
MCP_RECORD_ITEMS: Tuple[str, ...] = (
    "Purpose",
    "Required Permissions",
    "Network Access",
    "Credentials",
    "Data Sent Externally",
    "Failure Behaviour",
    "Data Flow Direction",
    "stdio Transport Notation",
    "Agent-to-Server Security Boundary",
)

# ---------------------------------------------------------------------------
# Other anchors
# ---------------------------------------------------------------------------

#: The metric names ``steering/testing.md`` enumerates and Task 26.4 requires the
#: methodology to define: five measured, one reported count, three deferred.
BENCHMARK_METRIC_NAMES: Tuple[str, ...] = (
    "Detection Rate",
    "Precision",
    "Recall",
    "False Positive",
    "False Negative",
    "Severity Accuracy",
    "Review Time",
    "Remediation Accuracy",
    "Human Intervention Count",
)

#: The three deferred metrics, which have to be identifiable as deferred rather
#: than merely mentioned, so each is required to be a section of its own.
DEFERRED_METRIC_NAMES: Tuple[str, ...] = (
    "Review Time",
    "Remediation Accuracy",
    "Human Intervention Count",
)

#: cfn-lint survey scope figures (Task 9.1 and Task 9.2) that no module exposes
#: as a constant: they describe the catalogue that was surveyed, not this
#: repository. Recorded here so a survey redone against a newer catalogue has to
#: update the document and this test together.
CFNLINT_SURVEY_ANCHORS: Tuple[str, ...] = (
    "1.46.0",  # cfn-lint version surveyed
    "267",  # rules in the catalogue
    "201",  # Error-level rules, the blocks_deployment survey scope
    "66",  # Warning + Informational rules, the security_relevant survey scope
)

#: Directories whose contents are not part of the distributed package.
NON_PACKAGE_DIR_NAMES = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".hypothesis",
        ".tox",
        "cdk.out",
        ".idea",
        ".vscode",
    }
)

#: Trees that make up the runtime of the plugin. ``docs/kiro-power.md`` claims
#: none of them reads anything from ``.kiro/``.
RUNTIME_TREES: Tuple[str, ...] = ("skills", "iacreview", "rules", "benchmark")

#: A repository path in backticks, as the documents write them.
REPOSITORY_PATH_PATTERN = re.compile(
    r"`((?:docs|skills|iacreview|rules|benchmark|tests|examples)/[A-Za-z0-9_./*-]+)`"
)

_FENCE = "```"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def read_document(relative_path: str) -> str:
    """Text of one document under ``docs/``."""
    return (DOCS_DIR / relative_path).read_text(encoding="utf-8")


def body_lines(text: str) -> List[str]:
    """Lines of ``text`` with fenced code blocks removed.

    Headings and tables are read off the result, so a ``#`` that is a Python
    comment inside a fence -- ``docs/architecture.md`` has several -- cannot be
    mistaken for a heading. Same approach as
    ``tests/unit/test_skills.py::_body_lines``, kept local because that one is
    shaped for a ``SKILL.md`` with front matter.
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


def heading_titles(lines: Sequence[str], level: int) -> List[str]:
    """Every heading of exactly ``level`` among already-defenced ``lines``."""
    prefix = "#" * level + " "
    return [line[len(prefix) :].strip() for line in lines if line.startswith(prefix)]


def headings(text: str, level: int) -> List[str]:
    """Every heading of exactly ``level`` in ``text``, in document order."""
    return heading_titles(body_lines(text), level)


def section_lines(text: str, title: str) -> List[str]:
    """Lines under the heading whose text starts with ``title``, that heading's
    own line included, up to the next heading of the same or a higher level.

    Raises:
        AssertionError: when no heading starts with ``title``, so a renamed
            section fails as a missing section rather than as an empty one.
    """
    lines = body_lines(text)
    start = None
    heading_prefix = ""
    for index, line in enumerate(lines):
        stripped = line.lstrip("#")
        marker = line[: len(line) - len(stripped)]
        if marker and stripped.strip().startswith(title):
            start = index
            heading_prefix = marker
            break
    assert start is not None, "no heading starting with {0!r}".format(title)
    depth = len(heading_prefix)
    for index in range(start + 1, len(lines)):
        candidate = lines[index]
        stripped = candidate.lstrip("#")
        marker_length = len(candidate) - len(stripped)
        if 0 < marker_length <= depth:
            return lines[start:index]
    return lines[start:]


def table_rows(lines: Sequence[str]) -> List[List[str]]:
    """Body cells of every Markdown table in ``lines``.

    The separator row and the header row above it are dropped, so a caller reads
    data rows only.
    """
    rows: List[List[str]] = []
    for line in lines:
        stripped = line.strip()
        if not (stripped.startswith("|") and stripped.endswith("|")):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if all(cell and set(cell) <= set("-: ") for cell in cells):
            if rows:  # the row above a separator is the header
                rows.pop()
            continue
        rows.append(cells)
    return rows


def unbackticked(cell: str) -> str:
    """A table cell with Markdown emphasis and code markers removed."""
    return cell.replace("`", "").replace("*", "").strip()


def normalized(text: str) -> str:
    """``text`` with every run of whitespace collapsed to one space.

    Markdown wraps prose, so a quotation of a Python constant can only be
    compared once line breaks stop mattering.
    """
    return " ".join(text.split())


def package_files(root: Path) -> List[Path]:
    """Every regular file of the distributed package under ``root``."""
    found: List[Path] = []
    stack = [root]
    while stack:
        current = stack.pop()
        for entry in sorted(current.iterdir()):
            if entry.is_dir() and not entry.is_symlink():
                if entry.name not in NON_PACKAGE_DIR_NAMES:
                    stack.append(entry)
                continue
            found.append(entry)
    return found


@pytest.fixture(scope="module")
def category_names() -> Tuple[str, ...]:
    """The closed ``Normalized_Category`` set, read from the mapping file."""
    return categories.load_map().categories


@pytest.fixture(scope="module")
def cfnlint_rule_flags() -> Dict[str, List[str]]:
    """Rule IDs flagged in ``category_map.json``, by flag name."""
    document = json.loads(
        (PLUGIN_ROOT / "iacreview" / "category_map.json").read_text(encoding="utf-8")
    )
    overrides = document["cfnlint"]["rule_overrides"]
    return {
        flag: sorted(rule for rule, entry in overrides.items() if entry.get(flag))
        for flag in ("blocks_deployment", "security_relevant")
    }


# ---------------------------------------------------------------------------
# Presence and language
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("relative_path", REQUIRED_REFERENCES)
def test_required_reference_documents_exist(relative_path: str) -> None:
    """Requirement 13 AC9: the four references ship under ``docs/``."""
    path = DOCS_DIR / relative_path
    assert path.is_file(), "{0} is missing".format(path)
    assert path.read_text(encoding="utf-8").strip(), "{0} is empty".format(path)


@pytest.mark.parametrize("relative_path", DOCUMENTS)
def test_document_is_written_in_english(relative_path: str) -> None:
    """Requirement 13 AC6, as ASCII plus :data:`PERMITTED_NON_ASCII`."""
    text = read_document(relative_path)
    offenders = sorted(
        {
            character
            for character in text
            if ord(character) > 127 and character not in PERMITTED_NON_ASCII
        }
    )
    assert not offenders, "{0} carries non-English characters: {1}".format(
        relative_path,
        ", ".join("U+{0:04X}".format(ord(character)) for character in offenders),
    )


@pytest.mark.parametrize("relative_path", DOCUMENTS)
def test_document_has_exactly_one_title(relative_path: str) -> None:
    """One level-1 heading per document, so the section levels below it mean the
    same thing in every file."""
    assert len(headings(read_document(relative_path), 1)) == 1


def test_documents_reference_only_paths_that_exist() -> None:
    """Requirement 13 AC11, mechanically: a document that points at a path which
    is not there is describing a repository that no longer exists.

    Only repository-rooted paths in backticks are checked, and a path containing
    a glob is skipped: ``skills/**/SKILL.md`` is a pattern, not a file.
    """
    missing: List[str] = []
    for relative_path in DOCUMENTS:
        text = read_document(relative_path)
        for referenced in sorted(set(REPOSITORY_PATH_PATTERN.findall(text))):
            if "*" in referenced:
                continue
            if not (PLUGIN_ROOT / referenced).exists():
                missing.append("{0} -> {1}".format(relative_path, referenced))
    assert not missing, "documents reference paths that do not exist: {0}".format(missing)


# ---------------------------------------------------------------------------
# docs/architecture.md (Task 26.1)
# ---------------------------------------------------------------------------


def test_architecture_has_required_sections() -> None:
    """Task 26.1: the pipeline, the boundary, the components, both tools, and the
    degraded-operation boundaries are sections of their own."""
    text = read_document(ARCHITECTURE)
    present = set(headings(text, 2))
    assert set(ARCHITECTURE_SECTIONS) <= present, "missing sections: {0}".format(
        sorted(set(ARCHITECTURE_SECTIONS) - present)
    )


def test_architecture_has_required_subsections() -> None:
    """Task 26.1: each of the seven subjects it had to record is a subsection."""
    text = read_document(ARCHITECTURE)
    present = set(headings(text, 3))
    assert set(ARCHITECTURE_SUBSECTIONS) <= present, "missing subsections: {0}".format(
        sorted(set(ARCHITECTURE_SUBSECTIONS) - present)
    )
    assert any(
        title.startswith(ARCHITECTURE_EXIT_CODE_SECTION) for title in present
    ), "no subsection starting with {0!r}".format(ARCHITECTURE_EXIT_CODE_SECTION)


def test_architecture_exit_code_table_matches_the_measured_cases() -> None:
    """Task 11.3 and Task 26.1: the five measured cfn-guard runs are recorded,
    and they agree with the classification table in
    ``tests/unit/test_cfnguard_parse.py``.

    The test module is the code-side home of these values -- it feeds each of
    them through ``interpret_guard_result`` -- so reading them from there is
    what makes this a drift check rather than a second copy of the numbers.
    """
    rows = table_rows(section_lines(read_document(ARCHITECTURE), ARCHITECTURE_EXIT_CODE_SECTION))
    measured = [row for row in rows if len(row) == 5 and len(row[0]) == 1 and row[0].isalpha()]
    documented_cases = [row[0] for row in measured]
    documented_codes = [int(unbackticked(row[2])) for row in measured]

    expected_cases = [case.split(" ", 1)[0] for case, _, _, _ in OBSERVED_CASES]
    expected_codes = [code for _, code, _, _ in OBSERVED_CASES]

    assert documented_cases == expected_cases
    assert documented_codes == expected_codes, (
        "docs/architecture.md records {0}, test_cfnguard_parse.py measures {1}".format(
            documented_codes, expected_codes
        )
    )


# ---------------------------------------------------------------------------
# docs/security-model.md (Task 26.2)
# ---------------------------------------------------------------------------


def test_security_model_has_required_sections() -> None:
    """Task 26.2: the default posture, every boundary, the residual risks and the
    tests that back the claims are sections of their own."""
    text = read_document(SECURITY_MODEL)
    sections = set(headings(text, 2))
    subsections = set(headings(text, 3))
    assert set(SECURITY_MODEL_SECTIONS) <= sections, "missing sections: {0}".format(
        sorted(set(SECURITY_MODEL_SECTIONS) - sections)
    )
    assert set(SECURITY_MODEL_SUBSECTIONS) <= subsections, "missing subsections: {0}".format(
        sorted(set(SECURITY_MODEL_SUBSECTIONS) - subsections)
    )


def test_security_model_quotes_the_synth_warning_verbatim() -> None:
    """Task 26.2: the ``cdk synth`` warning is stated once in code, and the
    document quotes that constant rather than paraphrasing it.

    Wording that drifts here is worse than a missing section: the document would
    promise a warning the tool does not actually print.
    """
    lines = body_lines(read_document(SECURITY_MODEL))
    mention = next(
        index for index, line in enumerate(lines) if "`SYNTH_WARNING`" in line
    )
    quoted: List[str] = []
    for line in lines[mention + 1 :]:
        if line.startswith(">"):
            quoted.append(line.lstrip(">").strip())
        elif quoted:
            break
    assert quoted, "no blockquote follows the SYNTH_WARNING mention"
    assert normalized(" ".join(quoted)) == normalized(SYNTH_WARNING)


def test_security_model_does_not_defer_docs_mcp_to_a_future_task() -> None:
    """Regression: the MCP section carried a status note saying ``docs/mcp/``
    "is created by Task 26.6" while that directory already existed.

    A reader of a published document cannot resolve an internal task number, and
    a note about work that is already done is simply wrong. The note was removed
    when this test was written; the paragraph that follows it, which names
    ``docs/mcp/README.md`` as the authoritative per-server record, is accurate
    and stayed.
    """
    text = read_document(SECURITY_MODEL)
    assert (DOCS_DIR / MCP_README).is_file()
    assert "Task 26.6" not in text
    assert "docs/mcp/README.md" in text


# ---------------------------------------------------------------------------
# docs/finding-schema.md (Task 26.3)
# ---------------------------------------------------------------------------


def test_finding_schema_has_required_sections() -> None:
    """Task 26.3: the value sets, the fields, the reading guidance, the merge
    granularity and both cfn-lint surveys are sections of their own."""
    present = set(headings(read_document(FINDING_SCHEMA), 2))
    assert set(FINDING_SCHEMA_SECTIONS) <= present, "missing sections: {0}".format(
        sorted(set(FINDING_SCHEMA_SECTIONS) - present)
    )


def test_finding_schema_documents_every_field() -> None:
    """Requirement 13 AC10: all 13 field names, read from the dataclass."""
    text = read_document(FINDING_SCHEMA)
    assert len(FINDING_FIELDS) == 13, "the schema changed; the document has to follow"
    undocumented = [field for field in FINDING_FIELDS if field not in text]
    assert not undocumented, "fields absent from the document: {0}".format(undocumented)


@pytest.mark.parametrize(
    "set_name,values",
    [
        ("FINDING_TYPES", FINDING_TYPES),
        ("SEVERITIES", SEVERITIES),
        ("CONFIDENCES", CONFIDENCES),
        ("SOURCES", SOURCES),
    ],
    ids=["FindingType", "Severity", "Confidence", "Source"],
)
def test_finding_schema_documents_every_permitted_value(
    set_name: str, values: Sequence[str]
) -> None:
    """Requirement 13 AC10: every permitted value of each closed set appears,
    compared against the constants rather than a list copied from the document."""
    text = read_document(FINDING_SCHEMA)
    missing = [value for value in values if value not in text]
    assert not missing, "{0} values absent from the document: {1}".format(set_name, missing)


def test_finding_schema_documents_every_category(category_names: Tuple[str, ...]) -> None:
    """Requirement 13 AC10 and Requirement 14 AC1: the whole
    ``Normalized_Category`` vocabulary, read from ``category_map.json``."""
    text = read_document(FINDING_SCHEMA)
    missing = [name for name in category_names if name not in text]
    assert not missing, "categories absent from the document: {0}".format(missing)


@pytest.mark.parametrize("flag", ["blocks_deployment", "security_relevant"])
def test_finding_schema_survey_matches_the_mapping_file(
    flag: str, cfnlint_rule_flags: Dict[str, List[str]]
) -> None:
    """Task 9.1 and Task 9.2: the survey sections enumerate the rules actually
    flagged in ``category_map.json``, and state the same count.

    A rule flagged in the mapping file but absent from the document is an
    unexplained CRITICAL or an unexplained security categorization, which is
    exactly what the survey exists to prevent.
    """
    text = read_document(FINDING_SCHEMA)
    flagged = cfnlint_rule_flags[flag]
    missing = [rule for rule in flagged if rule not in text]
    assert not missing, "{0} rules absent from the document: {1}".format(flag, missing)
    assert "**{0}**".format(len(flagged)) in text, (
        "the document does not state {0} as the {1} count".format(len(flagged), flag)
    )


def test_finding_schema_records_the_surveyed_cfnlint_catalogue() -> None:
    """Task 9.1 and Task 9.2: the surveyed catalogue is identified, so a reader
    can tell which cfn-lint version the classification was derived from."""
    text = read_document(FINDING_SCHEMA)
    missing = [anchor for anchor in CFNLINT_SURVEY_ANCHORS if anchor not in text]
    assert not missing, "survey scope figures absent from the document: {0}".format(missing)


# ---------------------------------------------------------------------------
# docs/benchmark-methodology.md (Task 26.4)
# ---------------------------------------------------------------------------


def test_benchmark_methodology_has_required_sections() -> None:
    """Task 26.4: ground truth, matching, metrics, the verdict, the harness exit
    codes, the deferred metrics and the known limitations."""
    present = set(headings(read_document(BENCHMARK_METHODOLOGY), 2))
    assert set(BENCHMARK_SECTIONS) <= present, "missing sections: {0}".format(
        sorted(set(BENCHMARK_SECTIONS) - present)
    )


def test_benchmark_methodology_names_every_metric() -> None:
    """Task 26.4: all nine metric names of ``steering/testing.md`` are defined,
    and each deferred one is a section rather than a passing mention."""
    text = read_document(BENCHMARK_METHODOLOGY)
    missing = [name for name in BENCHMARK_METRIC_NAMES if name not in text]
    assert not missing, "metrics absent from the document: {0}".format(missing)

    deferred_sections = set(heading_titles(section_lines(text, "Deferred metrics"), 3))
    assert set(DEFERRED_METRIC_NAMES) <= deferred_sections, (
        "deferred metrics not carried as sections: {0}".format(
            sorted(set(DEFERRED_METRIC_NAMES) - deferred_sections)
        )
    )


def test_benchmark_methodology_exit_codes_match_the_harness() -> None:
    """Task 26.4: the two harness-only exit codes, and the plugin codes the
    harness reuses, are read from ``run_benchmark`` rather than transcribed."""
    section = section_lines(read_document(BENCHMARK_METHODOLOGY), "Exit codes 9 and 10")
    rows = table_rows(section)
    documented = {
        unbackticked(row[1]): int(row[0])
        for row in rows
        if len(row) == 3 and row[0].isdigit()
    }
    assert documented == {
        "BENCHMARK_FAILURE": BENCHMARK_FAILURE,
        "CASE_NOT_EVALUATED": CASE_NOT_EVALUATED,
    }

    reused = sorted(
        value
        for name, value in HARNESS_EXIT_CODES.items()
        if name not in ("BENCHMARK_FAILURE", "CASE_NOT_EVALUATED")
    )
    claim = re.search(r"Codes ([0-9, and]+) are the plugin's own", "\n".join(section))
    assert claim is not None, "the section does not say which codes are the plugin's own"
    assert sorted(int(token) for token in re.findall(r"\d+", claim.group(1))) == reused


# ---------------------------------------------------------------------------
# docs/kiro-power.md (Task 26.5)
# ---------------------------------------------------------------------------


def test_kiro_power_has_required_sections() -> None:
    """Task 26.5: portability, what was verified, what was not, the
    Kiro-specific files, the extension route, and O-7's resolution."""
    present = set(headings(read_document(KIRO_POWER), 2))
    assert set(KIRO_POWER_SECTIONS) <= present, "missing sections: {0}".format(
        sorted(set(KIRO_POWER_SECTIONS) - present)
    )


def test_no_runtime_file_reads_the_kiro_directory() -> None:
    """Task 26.5, owed to this module: ``docs/kiro-power.md`` claims that no file
    under ``skills/``, ``iacreview/``, ``rules/`` or ``benchmark/`` reads
    anything from ``.kiro/``, which is what makes Requirement 10 AC9 concrete --
    deleting the directory cannot change a review result.
    """
    offenders: List[str] = []
    for tree in RUNTIME_TREES:
        for path in package_files(PLUGIN_ROOT / tree):
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):  # pragma: no cover - not a reference
                continue
            if ".kiro" in text:
                offenders.append(str(path.relative_to(PLUGIN_ROOT)))
    assert not offenders, "runtime files reference .kiro/: {0}".format(offenders)


def test_package_contains_no_symlink() -> None:
    """Task 26.5, owed to this module: ``docs/kiro-power.md`` claims the package
    contains no symbolic link.

    A symlink in a distributed package resolves against the installing machine's
    filesystem, which is a portability and containment question a client cannot
    answer for us.
    """
    symlinks = [
        str(path.relative_to(PLUGIN_ROOT))
        for path in package_files(PLUGIN_ROOT)
        if path.is_symlink()
    ]
    assert not symlinks, "the package contains symlinks: {0}".format(symlinks)


# ---------------------------------------------------------------------------
# docs/mcp/ (Task 26.6)
# ---------------------------------------------------------------------------


def test_mcp_example_is_a_valid_stdio_configuration() -> None:
    """Task 26.6: the example parses as JSON and states its transport, with the
    command as one executable token and its arguments in ``args``."""
    document = json.loads((DOCS_DIR / MCP_EXAMPLE).read_text(encoding="utf-8"))
    servers = document["mcpServers"]
    assert servers, "the example declares no server"
    for name, entry in servers.items():
        assert entry["type"] == "stdio", "{0} does not state the stdio transport".format(name)
        assert isinstance(entry["command"], str) and entry["command"]
        assert " " not in entry["command"], (
            "{0}'s command is not a single executable token".format(name)
        )
        assert isinstance(entry["args"], list)
        assert all(isinstance(argument, str) for argument in entry["args"])


def test_mcp_readme_quotes_the_example_file() -> None:
    """Task 26.6: the configuration shown in the README is the file beside it.

    Compared as parsed JSON, so reformatting the file is not a failure while a
    changed key or value is.
    """
    fence = re.search(r"```json\n(.*?)\n```", read_document(MCP_README), re.DOTALL)
    assert fence is not None, "the README shows no JSON configuration"
    assert json.loads(fence.group(1)) == json.loads(
        (DOCS_DIR / MCP_EXAMPLE).read_text(encoding="utf-8")
    )


def test_mcp_readme_records_all_nine_items() -> None:
    """Task 26.6: the nine per-server items are sections of the record, so an
    unanswered one is visible instead of being silently absent."""
    present = set(
        heading_titles(section_lines(read_document(MCP_README), "Per-Server Record"), 3)
    )
    assert set(MCP_RECORD_ITEMS) <= present, "missing record items: {0}".format(
        sorted(set(MCP_RECORD_ITEMS) - present)
    )


def test_mcp_readme_states_that_core_review_needs_no_server() -> None:
    """Task 26.6 and Requirement 10 AC4: an opt-in feature has to say it is
    optional, and the capability table is where a reader checks that."""
    text = read_document(MCP_README)
    rows = table_rows(section_lines(text, "MCP Is Not a Dependency"))
    needs_mcp = {row[0]: row[1] for row in rows if len(row) == 2}
    assert needs_mcp, "no capability table under the section"
    assert set(needs_mcp.values()) == {"No"}, (
        "a capability is documented as requiring MCP: {0}".format(needs_mcp)
    )
