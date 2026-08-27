"""Structural and anti-drift tests for the documents at the repository root.

``tests/unit/test_docs.py`` covers ``docs/``. This module covers the files a
reader meets before they open ``docs/`` at all: ``README.md``, ``LICENSE``,
``NOTICE``, and -- as later tasks add them -- ``CONTRIBUTING.md``,
``CHANGELOG.md`` and ``README.ja.md``.

The same rule applies here as there: where a document records a value the
implementation also holds, the assertion reads the implementation and compares.
The license is the clearest case. ``plugin.json`` declares an SPDX identifier
and ``LICENSE`` carries a license text, and those are two statements of one
fact. A test that hard-coded ``"Apache-2.0"`` on both sides would pass while the
two files disagreed, so the identifier is read from the manifest and used to
select which text ``LICENSE`` is required to be.

Covers:
- Requirement 1 AC5   : ``license`` is declared in ``plugin.json`` -- asserted as
                        a field there by ``tests/unit/test_manifest.py``, and
                        asserted here to be the license actually shipped
- Requirement 13 AC3  : ``LICENSE`` holds the full text of an OSI-approved
                        license
- Task 27.2           : ``NOTICE`` names the project, the copyright and the
                        third-party attributions

Structure for later tasks
-------------------------

Tasks 27.1, 27.3, 27.4 and 27.5 add cases to this module. Two conventions keep
it navigable as it grows:

- the repository root is :data:`REPO_ROOT`, resolved from ``__file__``. No test
  here takes an absolute path from anywhere else.
- one assertion per test function, named for what it asserts rather than for the
  file it reads, so a failure names the broken claim.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, Tuple

import pytest

# tests/unit/test_root_docs.py -> tests/unit -> tests -> repository root
REPO_ROOT: Path = Path(__file__).resolve().parents[2]

LICENSE_PATH: Path = REPO_ROOT / "LICENSE"
NOTICE_PATH: Path = REPO_ROOT / "NOTICE"
README_PATH: Path = REPO_ROOT / "README.md"
MANIFEST_PATH: Path = REPO_ROOT / "plugin.json"

#: The project name, as ``plugin.json`` spells it. ``NOTICE`` has to name the
#: same project the manifest names.
PROJECT_NAME = "aws-iac-review-agent-plugin"

# ---------------------------------------------------------------------------
# What identifies a license text
# ---------------------------------------------------------------------------

#: Section headings and structural markers that, taken together, identify a text
#: as the full Apache License 2.0 rather than a summary, a link, or a truncated
#: copy.
#:
#: Chosen so that every numbered section of the license contributes at least one
#: entry, plus the two structural markers that only the complete file has: the
#: terms-and-conditions banner it opens with and the ``APPENDIX`` boilerplate it
#: closes with. A file that satisfies all of these cannot be a fragment.
#:
#: Task 27.2 named ``Grant of Patent License`` specifically. It is the section
#: that distinguishes Apache-2.0 from MIT and the first of the design's five
#: reasons for choosing Apache-2.0, so a copy missing it would be the wrong
#: license under the right filename.
APACHE_2_0_MARKERS: Tuple[str, ...] = (
    "Apache License",
    "Version 2.0, January 2004",
    "TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION",
    "1. Definitions.",
    "2. Grant of Copyright License.",
    "3. Grant of Patent License.",
    "4. Redistribution.",
    "5. Submission of Contributions.",
    "6. Trademarks.",
    "7. Disclaimer of Warranty.",
    "8. Limitation of Liability.",
    "9. Accepting Warranty or Additional Liability.",
    "END OF TERMS AND CONDITIONS",
    "APPENDIX: How to apply the Apache License to your work.",
)

#: The identifying markers of each license this repository knows how to verify,
#: by SPDX identifier.
#:
#: A mapping rather than a single constant because the license identifier is read
#: from ``plugin.json``. Design's License Recommendation records Apache-2.0 as a
#: recommendation awaiting maintainer confirmation (requirements.md Open
#: Question 2), with MIT as the documented alternative. If that decision is
#: revisited, the manifest changes and this table is where the second entry goes;
#: until then, an identifier with no entry here fails as an unverifiable license
#: rather than passing unchecked.
LICENSE_MARKERS: Dict[str, Tuple[str, ...]] = {
    "Apache-2.0": APACHE_2_0_MARKERS,
}

#: A copyright line: the word, a four-digit year, and a holder. Matched rather
#: than compared to a literal so that the year and the holder can change without
#: this test needing an edit, while a ``NOTICE`` that forgot one still fails.
COPYRIGHT_PATTERN = re.compile(r"^Copyright\s+(\d{4})(?:-\d{4})?\s+(\S.*)$", re.MULTILINE)

#: The blockquote note the README uses to record a gap. Task 27.2 closed the one
#: in the License section, and a status note is exactly the kind of text that
#: outlives the gap it described.
STATUS_NOTE_PATTERN = re.compile(r"^>\s*\*\*Status\.\*\*(?P<body>.*)$", re.MULTILINE)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def declared_license() -> str:
    """The SPDX identifier ``plugin.json`` declares.

    Read here rather than imported from ``tests/unit/test_manifest.py`` so that
    this module's failures are about the root documents; that module owns the
    assertion that the field is present and well-formed (Requirement 1 AC5).
    """
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    identifier = manifest.get("license")
    assert isinstance(identifier, str) and identifier, (
        "plugin.json must declare a non-empty 'license' identifier; "
        "found {0!r}".format(identifier)
    )
    return identifier


@pytest.fixture(scope="module")
def license_text() -> str:
    """The text of ``LICENSE``."""
    assert LICENSE_PATH.is_file(), "Requirement 13 AC3: LICENSE is missing"
    return LICENSE_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def notice_text() -> str:
    """The text of ``NOTICE``."""
    assert NOTICE_PATH.is_file(), "Task 27.2: NOTICE is missing"
    return NOTICE_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def readme_text() -> str:
    """The text of ``README.md``."""
    assert README_PATH.is_file(), "Requirement 13 AC1: README.md is missing"
    return README_PATH.read_text(encoding="utf-8")


def readme_section(text: str, title: str) -> str:
    """The body of the level-2 README section titled ``title``.

    Raises:
        AssertionError: when no such heading exists, so a renamed section fails
            as a missing section rather than as an empty one.
    """
    heading = "## {0}".format(title)
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.strip() == heading:
            for end in range(index + 1, len(lines)):
                if lines[end].startswith("## "):
                    return "\n".join(lines[index + 1 : end])
            return "\n".join(lines[index + 1 :])
    raise AssertionError("README.md has no level-2 section {0!r}".format(title))


# ---------------------------------------------------------------------------
# LICENSE (Requirement 13 AC3, Requirement 1 AC5)
# ---------------------------------------------------------------------------


def test_license_file_exists() -> None:
    """Requirement 13 AC3: the license ships as a file at the root.

    Separate from the content tests so that a missing file reports as a missing
    file, rather than as fourteen missing section headings.
    """
    assert LICENSE_PATH.is_file(), "Requirement 13 AC3 requires a LICENSE file at the root"


def test_declared_license_is_one_this_repository_can_verify(declared_license: str) -> None:
    """The identifier in ``plugin.json`` is one :data:`LICENSE_MARKERS` covers.

    Without this, changing the manifest to an identifier the table does not know
    would silently skip the verification below instead of failing.
    """
    assert declared_license in LICENSE_MARKERS, (
        "plugin.json declares license {0!r}, which this module cannot verify. "
        "Add its identifying markers to LICENSE_MARKERS.".format(declared_license)
    )


def test_license_text_matches_the_declared_identifier(
    declared_license: str, license_text: str
) -> None:
    """Requirement 13 AC3 and Requirement 1 AC5: ``LICENSE`` is the license
    ``plugin.json`` declares, in full.

    The markers are checked against the identifier read from the manifest, so
    the two files cannot drift apart: replacing ``LICENSE`` without updating
    ``plugin.json`` fails here, and so does the reverse.
    """
    missing = [
        marker for marker in LICENSE_MARKERS[declared_license] if marker not in license_text
    ]
    assert not missing, (
        "LICENSE does not contain the full text of {0}. Missing: {1}".format(
            declared_license, missing
        )
    )


def test_license_grants_a_patent_license(license_text: str) -> None:
    """Task 27.2, named explicitly: the patent grant is present.

    Called out on its own because it is the clause the design's License
    Recommendation chose Apache-2.0 for. A ``LICENSE`` that lost this section
    would still look like Apache-2.0 to a casual reader.
    """
    assert "3. Grant of Patent License." in license_text
    assert "patent license to make, have made" in license_text


def test_license_is_not_a_stub(license_text: str) -> None:
    """The file holds a license text, not a pointer to one.

    A one-line ``LICENSE`` reading "Apache-2.0, see apache.org" satisfies a
    naive substring check and fails Requirement 13 AC3, which asks for the full
    text. The real file is about 11 KB over roughly 200 lines.
    """
    lines = license_text.splitlines()
    assert len(lines) > 150, "LICENSE has only {0} lines; expected the full text".format(
        len(lines)
    )
    assert len(license_text) > 10000, "LICENSE is {0} bytes; expected the full text".format(
        len(license_text)
    )


def test_license_is_plain_ascii(license_text: str) -> None:
    """Requirement 13 AC6: ``LICENSE`` is English text.

    The canonical Apache-2.0 file is pure ASCII, so unlike the documents under
    ``docs/`` this one needs no dash allowlist. A non-ASCII character here means
    the text was retyped or passed through a word processor, which for a legal
    document is a defect regardless of which character appeared.
    """
    offenders = sorted({character for character in license_text if ord(character) > 127})
    assert not offenders, "LICENSE contains non-ASCII characters: {0}".format(
        [hex(ord(character)) for character in offenders]
    )


def test_license_body_carries_no_placeholder_substitution(license_text: str) -> None:
    """The bracketed fields of the ``APPENDIX`` boilerplate are left as they are.

    ``Copyright [yyyy] [name of copyright owner]`` belongs to the appendix's
    instructions for *applying* the license to a work; filling it in edits the
    license text. This project's own copyright line lives in ``NOTICE``.
    """
    assert "Copyright [yyyy] [name of copyright owner]" in license_text, (
        "the APPENDIX boilerplate should be verbatim, with its bracketed fields intact"
    )


# ---------------------------------------------------------------------------
# NOTICE (Task 27.2)
# ---------------------------------------------------------------------------


def test_notice_file_exists() -> None:
    """Task 27.2: ``NOTICE`` ships at the root.

    Apache-2.0 Section 4(d) gives a ``NOTICE`` file a defined role in
    redistribution, and the design's License Recommendation lists it as one of
    the two files Apache-2.0 requires this project to provide.
    """
    assert NOTICE_PATH.is_file(), "Task 27.2 requires a NOTICE file at the root"


def test_notice_names_the_project(notice_text: str) -> None:
    """Task 27.2: the project name, and the one ``plugin.json`` declares.

    The name is compared against the manifest's rather than a literal, because a
    ``NOTICE`` naming a differently-named project is the failure worth catching.
    """
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    assert manifest["name"] == PROJECT_NAME, (
        "plugin.json name changed to {0!r}; update PROJECT_NAME".format(manifest["name"])
    )
    first_line = notice_text.splitlines()[0].strip()
    assert first_line == PROJECT_NAME, (
        "NOTICE should open with the project name; found {0!r}".format(first_line)
    )


def test_notice_carries_a_copyright_line(notice_text: str) -> None:
    """Task 27.2: a copyright with a year and a holder.

    Matched by shape, so the year can advance and the holder can change without
    an edit here, while an omitted year or holder still fails.
    """
    match = COPYRIGHT_PATTERN.search(notice_text)
    assert match is not None, (
        "NOTICE has no line of the form 'Copyright <year> <holder>'"
    )
    year, holder = match.group(1), match.group(2).strip()
    assert 2024 <= int(year) <= 2100, "implausible copyright year {0!r}".format(year)
    assert len(holder) > 3, "copyright holder {0!r} is too short to be one".format(holder)


def test_notice_attributes_the_declared_runtime_dependency(notice_text: str) -> None:
    """Task 27.2: the run-time dependency of ``pyproject.toml`` is attributed.

    The dependency list is read from ``pyproject.toml`` rather than listed here,
    so adding a run-time dependency without attributing it fails. Requirement 16
    AC3 keeps that list at one entry; this test does not assume it stays that
    way.
    """
    dependency_names = read_runtime_dependency_names()
    assert dependency_names, "pyproject.toml declares no run-time dependency to check"
    lowered = notice_text.lower()
    missing = [name for name in dependency_names if name.lower() not in lowered]
    assert not missing, "NOTICE does not attribute run-time dependencies: {0}".format(missing)


@pytest.mark.parametrize(
    "component",
    ["cfn-lint", "cfn-guard", "CDK"],
    ids=["cfn-lint", "cfn-guard", "cdk-cli"],
)
def test_notice_attributes_each_external_tool(notice_text: str, component: str) -> None:
    """Task 27.2: the three external tools a review may invoke are recorded.

    They are not redistributed, so no license obliges this. They are listed
    because a reader of ``NOTICE`` is asking what software a review run touches,
    and a tool invoked as a subprocess touches it just as much as an imported
    module does.
    """
    assert component in notice_text, "NOTICE does not mention {0}".format(component)


def test_notice_states_that_nothing_is_bundled(notice_text: str) -> None:
    """Task 27.2: the attribution says which components are redistributed.

    None are, and that is the load-bearing fact: it is what makes the
    third-party section informational rather than an obligation this project has
    to discharge. A ``NOTICE`` that merely listed the components would leave a
    reader unable to tell the difference.
    """
    lowered = notice_text.lower()
    assert "bundled" in lowered or "vendored" in lowered, (
        "NOTICE should state whether third-party components are bundled"
    )
    disclaimers = ("not bundled", "bundled, vendored", "no third-party code")
    assert any(phrase in lowered for phrase in disclaimers), (
        "NOTICE should state that no third-party code is redistributed"
    )


def test_notice_points_at_the_license_file(notice_text: str) -> None:
    """Task 27.2: ``NOTICE`` names ``LICENSE`` rather than restating its terms.

    Apache-2.0 Section 4(d) is explicit that a ``NOTICE`` file does not modify
    the license. Referring to ``LICENSE`` keeps the terms in one place.
    """
    assert "LICENSE" in notice_text


def test_notice_contains_no_absolute_host_path(notice_text: str) -> None:
    """steering/security.md: no local filesystem path from the machine that
    produced the file.

    The licenses in ``NOTICE`` were read from installed package metadata, and a
    path such as ``/Users/<name>/Library/Python/...`` is the kind of detail that
    travels with a copy-paste and discloses the author's environment.
    """
    leaks = [
        line
        for line in notice_text.splitlines()
        if "/Users/" in line or "/home/" in line or "site-packages" in line
    ]
    assert not leaks, "NOTICE contains host-specific paths: {0}".format(leaks)


# ---------------------------------------------------------------------------
# README, where it records the state of these two files
# ---------------------------------------------------------------------------


def test_readme_license_section_does_not_claim_the_files_are_missing(
    readme_text: str,
) -> None:
    """Regression, the same shape as
    ``test_docs.py::test_security_model_does_not_defer_docs_mcp_to_a_future_task``.

    The License section carried a status note saying ``LICENSE`` and ``NOTICE``
    were "not added yet". Both now exist. A status note describing a gap that has
    closed is worse than no note: a reader trusts it and concludes the project
    ships unlicensed.
    """
    section = readme_section(readme_text, "License")
    for match in STATUS_NOTE_PATTERN.finditer(section):
        body = match.group("body").lower()
        assert "not added yet" not in body and "not yet" not in body, (
            "the README License section still says LICENSE/NOTICE are absent: "
            "{0!r}".format(match.group(0))
        )


def test_readme_license_section_names_both_files(readme_text: str) -> None:
    """Requirement 13 AC1: the License section tells a reader where the terms are.

    Both files exist, so the section that a reader checks for the license should
    name both rather than only the SPDX identifier.
    """
    section = readme_section(readme_text, "License")
    for filename in ("LICENSE", "NOTICE"):
        assert filename in section, (
            "the README License section does not mention {0}".format(filename)
        )


def test_readme_license_section_agrees_with_the_manifest(
    readme_text: str, declared_license: str
) -> None:
    """The identifier in prose is the identifier in ``plugin.json``."""
    section = readme_section(readme_text, "License")
    assert declared_license in section, (
        "the README License section does not name {0!r}, which plugin.json "
        "declares".format(declared_license)
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def read_runtime_dependency_names() -> Tuple[str, ...]:
    """Distribution names of the ``[project] dependencies`` of ``pyproject.toml``.

    Parsed with a small regular expression rather than a TOML library:
    ``tomllib`` arrived in Python 3.11 and this repository supports 3.9, and
    ``tomli`` is not a dependency this test justifies adding (steering/tech.md).
    The parse handles only the one-line array form the file actually uses, and
    asserts rather than guesses when it does not find it.
    """
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r"^dependencies\s*=\s*\[(?P<items>[^\]]*)\]", text, re.MULTILINE)
    assert match is not None, (
        "could not find a single-line 'dependencies = [...]' array in pyproject.toml"
    )
    names = []
    for item in match.group("items").split(","):
        stripped = item.strip().strip("\"'")
        if not stripped:
            continue
        names.append(re.split(r"[<>=!~\[;\s]", stripped, 1)[0])
    return tuple(names)


# ---------------------------------------------------------------------------
# CONTRIBUTING.md (Task 27.3)
# ---------------------------------------------------------------------------
#
# Requirement 13 AC4 names seven sections by their content rather than by a
# heading string, so the constant below fixes the headings this repository uses
# for them and the parametrized test names the criterion. Beyond the seven,
# CONTRIBUTING.md carries rules that other requirements place in "the contributor
# documentation" -- ground-truth authoring order (11 AC14, AC15), a benchmark
# template per new rule (11 AC16), a regression test per fixed defect (12 AC10)
# and per security-relevant change (12 AC12), and the dependency procedure
# (16 AC4). Those are the assertions after the heading ones: a heading can be
# present while the rule it was supposed to carry is not.

CONTRIBUTING_PATH: Path = REPO_ROOT / "CONTRIBUTING.md"

#: The seven sections Requirement 13 AC4 requires, as this repository titles
#: them, paired with the criterion's own wording so a failure says what is
#: missing rather than only which string was not found.
CONTRIBUTING_REQUIRED_SECTIONS: Tuple[Tuple[str, str], ...] = (
    ("Development environment setup", "development environment setup with prerequisite tool versions"),
    ("Coding standards", "coding standards"),
    ("Testing procedures", "testing procedures with the commands to run tests"),
    ("Guard rule contribution guide", "Guard_Rule contribution guide with directory structure and naming conventions"),
    ("Skill contribution guide", "Skill contribution guide"),
    ("Security issue handling", "security issue handling process"),
    ("Pull request process", "pull request process"),
)

#: The five classes steering/testing.md and design's "テスト失敗時の方針" require a
#: failure to be sorted into before anything is changed.
FAILURE_CLASSES: Tuple[str, ...] = (
    "Implementation Bug",
    "Test Bug",
    "Missing Requirement",
    "Agent nondeterminism",
    "Tool version difference",
)

#: The five questions steering/tech.md asks of a proposed dependency, reduced to
#: the phrase each one turns on. Matched by phrase rather than by sentence so
#: that the questions can be worded naturally.
DEPENDENCY_QUESTION_PHRASES: Tuple[str, ...] = (
    "standard functionality",
    "necessary",
    "maintained",
    "security risk",
    "portability",
)

#: Paths named in ``CONTRIBUTING.md`` that are deliberately absent from a clean
#: checkout. ``.hypothesis/`` is the local example database, listed in
#: ``.gitignore``; the document mentions it precisely to say it is not committed.
UNCOMMITTED_PATHS: Tuple[str, ...] = (".hypothesis/",)

#: A fenced code block, so that path extraction reads inline code spans only.
#: A command line inside a fence contains flags and arguments that are not paths.
FENCED_BLOCK_PATTERN = re.compile(r"^```.*?^```", re.MULTILINE | re.DOTALL)

#: An inline code span.
INLINE_CODE_PATTERN = re.compile(r"`([^`\n]+)`")

#: What counts as a repository path worth checking: no spaces, no angle-bracket
#: placeholder, and either a directory separator or a known file extension.
PATH_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_.\-/]+$")
PATH_EXTENSIONS = (".md", ".py", ".json", ".toml", ".yaml", ".yml", ".guard")


@pytest.fixture(scope="module")
def contributing_text() -> str:
    """The text of ``CONTRIBUTING.md``."""
    assert CONTRIBUTING_PATH.is_file(), "Requirement 13 AC4: CONTRIBUTING.md is missing"
    return CONTRIBUTING_PATH.read_text(encoding="utf-8")


def contributing_section(text: str, title: str, level: int = 2) -> str:
    """The body of the section of ``CONTRIBUTING.md`` titled ``title``.

    Separate from :func:`readme_section` rather than shared with it: the failure
    message names the file, and this one takes a heading level so that a
    subsection such as ``### Proposing a dependency`` can be isolated from the
    section that contains it.

    Raises:
        AssertionError: when no such heading exists.
    """
    heading = "{0} {1}".format("#" * level, title)
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.strip() == heading:
            in_fence = False
            for end in range(index + 1, len(lines)):
                current = lines[end]
                if current.startswith("```"):
                    # A shell comment inside a fenced block starts with '#' and
                    # is not a heading. Without this the section would end at the
                    # first commented command line.
                    in_fence = not in_fence
                    continue
                if in_fence or not current.startswith("#"):
                    continue
                depth = len(current) - len(current.lstrip("#"))
                if depth <= level and current[depth : depth + 1] == " ":
                    return "\n".join(lines[index + 1 : end])
            return "\n".join(lines[index + 1 :])
    raise AssertionError(
        "CONTRIBUTING.md has no level-{0} section {1!r}".format(level, title)
    )


def flowed(text: str) -> str:
    """``text`` with every run of whitespace collapsed to one space.

    Every phrase assertion below runs against this. The document is hard-wrapped,
    so a phrase such as "do not edit an existing rule file" is split across a line
    break in the source and would not be found by a plain substring search. The
    alternative -- wording each rule to fit on one line -- would let the layout
    dictate the prose.
    """
    return " ".join(text.split())


def test_contributing_file_exists() -> None:
    """Requirement 13 AC4: ``CONTRIBUTING.md`` ships at the root.

    Separate from the section tests so a missing file reports once rather than as
    seven missing headings.
    """
    assert CONTRIBUTING_PATH.is_file(), "Requirement 13 AC4 requires a CONTRIBUTING.md"


@pytest.mark.parametrize(
    ("heading", "criterion_wording"),
    CONTRIBUTING_REQUIRED_SECTIONS,
    ids=[heading for heading, _ in CONTRIBUTING_REQUIRED_SECTIONS],
)
def test_contributing_has_required_section(
    contributing_text: str, heading: str, criterion_wording: str
) -> None:
    """Requirement 13 AC4: each of the seven required sections is present.

    Asserted through :func:`contributing_section`, which fails on a missing
    heading, so a renamed section reports as missing rather than as empty.
    """
    body = contributing_section(contributing_text, heading)
    assert body.strip(), (
        "Requirement 13 AC4 requires a section covering {0!r}; "
        "CONTRIBUTING.md has the heading {1!r} but it is empty".format(
            criterion_wording, heading
        )
    )


def test_contributing_is_plain_ascii(contributing_text: str) -> None:
    """Requirement 13 AC6: ``CONTRIBUTING.md`` is written in English.

    Same check the shipped ``SKILL.md`` documents get. ASCII is not the same
    thing as English, but a non-ASCII character in this file is in practice a
    typographic dash or quote pasted from elsewhere, and those are what make a
    document awkward to diff and to grep.
    """
    offenders = sorted({character for character in contributing_text if ord(character) > 127})
    assert not offenders, "CONTRIBUTING.md contains non-ASCII characters: {0}".format(
        [hex(ord(character)) for character in offenders]
    )


def test_setup_section_states_the_prerequisite_tool_versions(
    contributing_text: str,
) -> None:
    """Requirement 13 AC4: the setup section carries the prerequisite versions,
    and the ones :mod:`iacreview.toolcheck` actually enforces.

    The minimum versions are read from ``TOOL_REQUIREMENTS`` rather than listed
    here, because a contributor who installs the version this document names and
    then hits a ``ToolVersionError`` has been misled by the document. Raising the
    floor in code now fails here until the table is updated.
    """
    from iacreview.toolcheck import TOOL_REQUIREMENTS

    section = contributing_section(contributing_text, "Development environment setup")
    missing = [
        "{0} {1}".format(requirement.name, requirement.min_version)
        for requirement in TOOL_REQUIREMENTS.values()
        if requirement.name not in section or requirement.min_version not in section
    ]
    assert not missing, (
        "the setup section does not state the enforced minimum version of: {0}".format(
            missing
        )
    )


def test_testing_section_names_the_command_that_runs_the_tests(
    contributing_text: str,
) -> None:
    """Requirement 13 AC4: "with the commands to run tests", not a description of
    them.
    """
    section = contributing_section(contributing_text, "Testing procedures")
    assert "python3 -m pytest" in section


def test_coverage_command_measures_what_pyproject_declares(
    contributing_text: str,
) -> None:
    """The documented coverage command covers the sources ``pyproject.toml`` sets.

    The coverage gate is only meaningful over the whole measured surface. Adding a
    package to ``[tool.coverage.run] source`` without adding it to the documented
    command would leave contributors measuring a subset and reporting a number
    that continuous integration does not reproduce.
    """
    section = contributing_section(contributing_text, "Testing procedures")
    missing = [
        source
        for source in read_coverage_sources()
        if "--cov={0}".format(source) not in section
    ]
    assert not missing, (
        "the documented coverage command omits sources declared in "
        "pyproject.toml: {0}".format(missing)
    )


@pytest.mark.parametrize("failure_class", FAILURE_CLASSES)
def test_testing_section_lists_each_failure_class(
    contributing_text: str, failure_class: str
) -> None:
    """steering/testing.md and design's "テスト失敗時の方針": a failing test is
    classified before anything is changed.

    Parametrized so that dropping one class from the table names which one. The
    five are not interchangeable: agent nondeterminism and a tool version
    difference in particular are the two that a contributor is most likely to
    resolve by weakening an assertion.
    """
    section = contributing_section(contributing_text, "Testing procedures")
    assert failure_class in section, (
        "the failure triage table does not list {0!r}".format(failure_class)
    )


def test_testing_section_forbids_weakening_a_requirement(
    contributing_text: str,
) -> None:
    """steering/testing.md: a requirement is not weakened to make a test pass.

    The rule the triage table exists to serve. Without it the table is a list of
    excuses rather than a procedure.
    """
    section = flowed(contributing_section(contributing_text, "Testing procedures"))
    lowered = section.lower()
    assert "weaken a requirement" in lowered or "weakening a requirement" in lowered, (
        "the testing section does not state that a requirement is never weakened "
        "to make a test pass"
    )


def test_testing_section_pins_counterexamples_into_the_regression_suite(
    contributing_text: str,
) -> None:
    """Task 24.7, owed to this task: the counterexample workflow is written down.

    A property test that has found a defect leaves its evidence in a place that
    does not survive -- the printed output of one run, and a ``.hypothesis/``
    database that is not committed. The document has to name both halves: the
    regression case that pins the one input, and the property that keeps looking
    for the next.
    """
    section = flowed(contributing_section(contributing_text, "Testing procedures"))
    assert "hypothesis" in section.lower()
    assert "tests/regression/" in section, (
        "the testing section does not say where a counterexample is pinned"
    )
    assert "Keep the property test" in section, (
        "the testing section does not say that the property test is kept as well "
        "as the regression case"
    )


def test_testing_section_requires_a_regression_test_for_a_security_change(
    contributing_text: str,
) -> None:
    """Requirement 12 AC12: a security-relevant change carries a regression test.

    Stated in the testing section, where a contributor decides what to write, as
    well as in the security section, where they arrive from a report.
    """
    section = flowed(contributing_section(contributing_text, "Testing procedures"))
    assert "security-relevant change" in section
    assert "regression test" in section


def test_security_section_repeats_the_regression_test_obligation(
    contributing_text: str,
) -> None:
    """Requirement 12 AC12, from the other entry point.

    The two audiences differ. Someone reading "Security issue handling" is
    holding a vulnerability, not planning a change, and this is the sentence that
    tells them a fix is not complete without a test.
    """
    section = contributing_section(contributing_text, "Security issue handling")
    assert "regression test" in section, (
        "the security section does not state the Requirement 12 AC12 obligation"
    )


def test_security_section_requires_private_reporting(contributing_text: str) -> None:
    """Requirement 13 AC4: the security issue handling process.

    An unfixed vulnerability disclosed in a public issue is disclosed to everyone
    who reads issues, including the people it is a vulnerability against. The
    document has to say so rather than only naming a channel.
    """
    section = flowed(contributing_section(contributing_text, "Security issue handling"))
    lowered = section.lower()
    assert "privately" in lowered
    assert "do not open a public issue" in lowered, (
        "the security section does not tell a reporter to keep an unfixed "
        "vulnerability out of public issues"
    )


def test_security_section_forbids_credentials_anywhere(contributing_text: str) -> None:
    """steering/security.md: no credential in the repository, and none in a report.

    Enumerated rather than summarized, because "no secrets" reads as being about
    source code, and the places this project is most likely to leak one are a
    benchmark template and an issue attachment.
    """
    section = flowed(contributing_section(contributing_text, "Security issue handling")).lower()
    lowered = section
    for place in ("tests", "examples", "benchmark", "issues", "pull requests"):
        assert place in lowered, (
            "the credentials rule does not cover {0!r}".format(place)
        )


def test_guard_guide_states_the_four_steps(contributing_text: str) -> None:
    """Design, cfn-guard Integration: the four steps for adding a rule.

    The first step is the one that needs stating: an existing rule name appears in
    findings, in its ``_meta.json`` entry and in benchmark ground truth, so
    editing what it matches changes the meaning of results already recorded
    against it.
    """
    section = flowed(contributing_section(contributing_text, "Guard rule contribution guide"))
    lowered = section.lower()
    assert "do not edit an existing rule" in lowered, "step 1 (new file, not an edit)"
    assert "exactly one entry" in lowered and "_meta.json" in section, "step 2 (sidecar)"
    assert "benchmark case" in lowered, "step 3 (a case that makes it fire)"
    assert "test_guard_rules.py" in section, "step 4 (the coverage test)"


def test_guard_guide_matches_the_shipped_rule_layout(contributing_text: str) -> None:
    """Requirement 13 AC4: "directory structure and naming conventions", and the
    ones that are actually shipped.

    The category directories are read from ``rules/`` rather than listed here, so
    a new category that the guide does not mention fails, and so does a guide
    describing a directory that no longer exists.
    """
    section = contributing_section(contributing_text, "Guard rule contribution guide")
    categories = sorted(
        path.name for path in (REPO_ROOT / "rules").iterdir() if path.is_dir()
    )
    assert categories, "rules/ has no category directories"
    missing = [category for category in categories if category not in section]
    assert not missing, (
        "the Guard rule guide does not mention category directories: {0}".format(missing)
    )


def test_guard_guide_states_the_file_naming_convention(contributing_text: str) -> None:
    """Requirement 13 AC4: the naming convention, as
    ``tests/unit/test_guard_rules.py`` enforces it.

    Lower snake case, one rule per file, and the rule name equal to the file stem.
    The last is the one with consequences: the stem is the join key for the
    sidecar and for the rule id carried in Evidence.
    """
    section = flowed(contributing_section(contributing_text, "Guard rule contribution guide"))
    assert "<rule_name>.guard" in section
    assert "snake case" in section.lower()
    assert "file stem" in section.lower() or "file name" in section.lower()


def test_ground_truth_is_authored_before_any_review(contributing_text: str) -> None:
    """Requirement 11 AC14: ground truth comes from the template's intended
    defects, written before a review is run against it.
    """
    section = flowed(contributing_section(contributing_text, "Testing procedures"))
    lowered = section.lower()
    assert "before any review is run" in lowered
    assert "deliberately placed" in lowered or "intended defect" in lowered


def test_deriving_ground_truth_from_review_output_is_prohibited(
    contributing_text: str,
) -> None:
    """Requirement 11 AC15: the prohibition, stated as one.

    Separate from AC14 because they fail differently. A contributor can honour
    "write it first" and still, on a disagreement, edit the expectation to match
    what the review printed. That is the same defect arriving later.
    """
    section = flowed(contributing_section(contributing_text, "Testing procedures"))
    lowered = section.lower()
    assert "prohibited" in lowered
    assert "review output" in lowered or "observed review output" in lowered


def test_new_rule_requires_a_benchmark_template(contributing_text: str) -> None:
    """Requirement 11 AC16: new Guard rule or new review logic, at least one
    benchmark template that exercises it.

    Asserted in the testing section, which is where the obligation is stated for
    both kinds of addition; the Guard guide repeats it as its step 3.
    """
    section = flowed(contributing_section(contributing_text, "Testing procedures"))
    assert "review logic" in section
    assert "at least one benchmark" in section.lower()


def test_skill_guide_lists_the_required_skill_md_sections(
    contributing_text: str,
) -> None:
    """Requirement 13 AC4: the Skill contribution guide, agreeing with the
    structure ``tests/unit/test_skills.py`` enforces.

    The section list is imported from that module rather than restated, so the
    guide cannot drift from the check a new Skill has to pass.
    """
    from tests.unit.test_skills import REQUIRED_SECTIONS

    section = contributing_section(contributing_text, "Skill contribution guide")
    missing = [title for title in REQUIRED_SECTIONS if title not in section]
    assert not missing, (
        "the Skill guide does not name the required SKILL.md sections: {0}".format(
            missing
        )
    )


def test_skill_guide_states_the_front_matter_requirement(
    contributing_text: str,
) -> None:
    """The Skill guide names what the front matter has to carry.

    ``name`` equal to the directory name is the one a new Skill gets wrong, and it
    is the one that makes the Skill undiscoverable rather than merely
    inconsistent.
    """
    section = flowed(contributing_section(contributing_text, "Skill contribution guide"))
    assert "front matter" in section.lower()
    assert "directory name" in section


def test_pull_request_section_names_the_checks_to_run(contributing_text: str) -> None:
    """Requirement 13 AC4: the pull request process.

    Both gates, because they fail independently: the suite catches a broken
    change, and the benchmark catches a change that keeps the suite green while
    losing a detection.
    """
    section = contributing_section(contributing_text, "Pull request process")
    assert "python3 -m pytest" in section
    assert "run_benchmark.py" in section


def test_dependency_proposal_answers_the_five_questions(
    contributing_text: str,
) -> None:
    """Requirement 16 AC4 and steering/tech.md: a pull request adding a dependency
    answers the five questions.

    Matched on the phrase each question turns on rather than on its wording, so
    the questions can be phrased naturally while a dropped one still fails.
    """
    section = flowed(
        contributing_section(contributing_text, "Proposing a dependency", level=3)
    )
    lowered = section.lower()
    missing = [phrase for phrase in DEPENDENCY_QUESTION_PHRASES if phrase not in lowered]
    assert not missing, (
        "the dependency procedure does not ask about: {0}".format(missing)
    )


def test_dev_dependencies_are_recorded_as_outside_the_runtime_budget(
    contributing_text: str,
) -> None:
    """Requirement 16 AC4, and the interpretation design asks both
    ``docs/architecture.md`` and this file to carry.

    Requirement 16 AC3 constrains the run-time dependencies of the deterministic
    components. Without this sentence a contributor reads the one-dependency
    budget as covering ``pytest`` and concludes the test suite is in violation.
    """
    section = flowed(
        contributing_section(contributing_text, "Proposing a dependency", level=3)
    )
    assert "16 AC4" in section or "AC4" in section, (
        "the dependency procedure does not cite the criterion that exempts dev "
        "and test dependencies"
    )
    lowered = section.lower()
    assert "not" in lowered and "subject to that constraint" in lowered, (
        "the dependency procedure does not state that dev and test dependencies "
        "are outside the run-time constraint"
    )


def test_lint_tools_are_recommended_rather_than_required(
    contributing_text: str,
) -> None:
    """Design, "採用しない依存": ``ruff`` and ``mypy`` are recommended, not
    required, and not dependencies of the plugin.

    The distinction is what keeps a contribution from being blocked on a tool the
    project does not depend on.
    """
    section = flowed(contributing_section(contributing_text, "Coding standards"))
    assert "ruff" in section and "mypy" in section
    assert "recommended, not required" in section.lower(), (
        "the coding standards do not state that ruff and mypy are optional"
    )


def test_contributions_are_licensed_under_the_declared_license(
    contributing_text: str, declared_license: str
) -> None:
    """Design, License Recommendation: CONTRIBUTING.md states that a contribution
    is licensed under the project license.

    Compared against ``plugin.json`` rather than a literal, for the same reason
    the ``LICENSE`` assertions are: one fact, three files, and a disagreement
    between them is the failure worth catching.
    """
    assert declared_license in contributing_text, (
        "CONTRIBUTING.md does not state that contributions are licensed under "
        "{0!r}, which plugin.json declares".format(declared_license)
    )


def test_contributing_names_only_paths_that_exist(contributing_text: str) -> None:
    """Every repository path in an inline code span resolves.

    The same guard ``tests/unit/test_docs.py`` applies to ``docs/``. This document
    is a set of instructions, and an instruction naming a moved file wastes the
    time of exactly the reader who was trying to follow it.

    Fenced blocks are excluded: they hold command lines and directory sketches,
    whose tokens are flags and placeholders rather than paths.
    """
    prose = FENCED_BLOCK_PATTERN.sub("", contributing_text)
    missing = sorted(
        {
            token
            for token in INLINE_CODE_PATTERN.findall(prose)
            if is_repository_path_token(token) and not (REPO_ROOT / token).exists()
        }
    )
    assert not missing, "CONTRIBUTING.md names paths that do not exist: {0}".format(
        missing
    )


def test_contributing_contains_no_absolute_host_path(contributing_text: str) -> None:
    """steering/security.md: no path from the machine that wrote the file.

    The setup section is the likely place for one, since it is written while
    installing tools, and a ``pip install --user`` script directory is exactly the
    kind of value that gets pasted in as if it were universal.
    """
    leaks = [
        line
        for line in contributing_text.splitlines()
        if "/Users/" in line or "/home/" in line or "site-packages" in line
    ]
    assert not leaks, "CONTRIBUTING.md contains host-specific paths: {0}".format(leaks)


def test_readme_contributing_section_points_at_the_file(readme_text: str) -> None:
    """Requirement 13 AC1: the README Contributing section sends a reader to
    ``CONTRIBUTING.md`` rather than restating it.

    The conventions lived in the README while the file did not exist. Two copies
    of a convention is one copy that goes stale.
    """
    section = readme_section(readme_text, "Contributing")
    assert "CONTRIBUTING.md" in section


def test_readme_contributing_section_does_not_claim_the_file_is_missing(
    readme_text: str,
) -> None:
    """Regression, the same shape as
    ``test_readme_license_section_does_not_claim_the_files_are_missing``.

    The Contributing section carried a status note saying ``CONTRIBUTING.md`` was
    not written yet, with the conventions inlined behind that caveat. The file
    exists now. A note saying otherwise sends a reader looking for rules that are
    in front of them.
    """
    section = readme_section(readme_text, "Contributing")
    for match in STATUS_NOTE_PATTERN.finditer(section):
        body = match.group("body").lower()
        assert "not written yet" not in body and "not yet" not in body, (
            "the README Contributing section still says CONTRIBUTING.md is "
            "absent: {0!r}".format(match.group(0))
        )


def is_repository_path_token(token: str) -> bool:
    """Whether ``token`` from an inline code span is a repository path to check.

    A path is a token that carries a directory separator and whose first
    component names something at the repository root. Both conditions are needed.
    Without the separator the filter would catch every bare filename the document
    discusses as a convention rather than as a location -- ``SKILL.md``,
    ``_meta.json``, ``.guard`` -- none of which is a path to anywhere. Without the
    root check it would catch a fragment such as ``unit/`` written to name a
    subdirectory in context.

    Also excluded: angle-bracket placeholders (``rules/<category>/``), tokens with
    a space or a shell character, and the deliberately uncommitted paths in
    :data:`UNCOMMITTED_PATHS`.
    """
    if token in UNCOMMITTED_PATHS:
        return False
    if not PATH_TOKEN_PATTERN.match(token) or "/" not in token:
        return False
    first_component = token.split("/", 1)[0]
    return bool(first_component) and (REPO_ROOT / first_component).exists()


def read_coverage_sources() -> Tuple[str, ...]:
    """The ``[tool.coverage.run] source`` entries of ``pyproject.toml``.

    Parsed the same way :func:`read_runtime_dependency_names` parses its array,
    and for the same reason: ``tomllib`` is Python 3.11 and this repository
    supports 3.9.
    """
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r"^source\s*=\s*\[(?P<items>[^\]]*)\]", text, re.MULTILINE)
    assert match is not None, (
        "could not find a single-line 'source = [...]' array in pyproject.toml"
    )
    sources = tuple(
        item.strip().strip("\"'") for item in match.group("items").split(",") if item.strip()
    )
    assert sources, "pyproject.toml declares no coverage sources"
    return sources


# ---------------------------------------------------------------------------
# CHANGELOG.md (Task 27.4)
# ---------------------------------------------------------------------------
#
# Requirement 13 AC5 asks for three things at once: Keep a Changelog format, the
# six change-type headings, and a link to a version tag on every entry. Two of
# the three are easy to satisfy in appearance and miss in substance, so the
# assertions below are shaped against the weaker reading:
#
# - "the six headings are used" is asserted as *only* those six are used. A
#   changelog that adds a seventh heading of its own -- "Notes", "Internal",
#   "Improvements" -- still contains all six, and a reader who groups by change
#   type has no idea where the seventh belongs.
# - "each entry links to a version tag" is asserted against a target built from
#   the manifest's ``repository`` field, not against a URL written here. The
#   manifest still carries an ``<org>`` placeholder in that field, which is a
#   known gap; the point of deriving the target is that this test says nothing
#   about who the org is, and keeps saying nothing once it is filled in.
#
# The version itself is read from ``plugin.json`` for the same reason the license
# is: a release entry and the manifest are two statements of one fact.

CHANGELOG_PATH: Path = REPO_ROOT / "CHANGELOG.md"

#: The six change types of Keep a Changelog, and the only headings this file may
#: use to group the changes of a release.
KEEP_A_CHANGELOG_CHANGE_TYPES: Tuple[str, ...] = (
    "Added",
    "Changed",
    "Deprecated",
    "Removed",
    "Fixed",
    "Security",
)

#: A release heading: ``## [0.1.0] - 2026-08-27``, or ``## [Unreleased]``. The
#: date is optional in the pattern so that a missing one fails in the test that
#: is about dates rather than by the heading going unrecognised.
RELEASE_HEADING_PATTERN = re.compile(
    r"^##\s+\[(?P<label>[^\]]+)\](?:\s*-\s*(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2}))?\s*$",
    re.MULTILINE,
)

#: A level-3 heading, which in this file is always a change type.
CHANGE_TYPE_HEADING_PATTERN = re.compile(r"^###\s+(?P<title>.+?)\s*$", re.MULTILINE)

#: A Markdown link reference definition: ``[0.1.0]: https://...``.
LINK_DEFINITION_PATTERN = re.compile(
    r"^\[(?P<label>[^\]]+)\]:\s*(?P<target>\S+)\s*$", re.MULTILINE
)

#: A semantic version, which is what ``plugin.json`` declares and what a release
#: label has to be to name a version tag.
SEMVER_PATTERN = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?$")

#: The label of the section for changes that have no release yet. Excluded from
#: the tests that are about released versions.
UNRELEASED_LABEL = "Unreleased"

#: The five kinds of change steering/documentation.md and Task 27.4 require this
#: file to state that it records, reduced to the phrase each turns on. Matched
#: case-insensitively against the flowed text so the prose can be worded
#: naturally rather than as a list of keywords.
RECORDED_CHANGE_KINDS: Tuple[str, ...] = (
    "breaking change",
    "finding schema",
    "skill",
    "dependency",
    "security fix",
)

#: Capabilities requirements.md lists as out of scope for v0.1. None may appear in
#: the ``Added`` section of the first release: Requirement 13 AC11 forbids
#: describing an unimplemented capability as available, and an ``Added`` bullet is
#: the most direct way to do it.
NON_GOAL_PHRASES: Tuple[str, ...] = (
    "terraform",
    "pulumi",
    "web ui",
    "finops",
    "runtime security",
    "auto-remediation",
    "automatic remediation",
    "automatically deploy",
)


@pytest.fixture(scope="module")
def changelog_text() -> str:
    """The text of ``CHANGELOG.md``."""
    assert CHANGELOG_PATH.is_file(), "Requirement 13 AC5: CHANGELOG.md is missing"
    return CHANGELOG_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def declared_version() -> str:
    """The version ``plugin.json`` declares.

    Read here for the same reason :func:`declared_license` is: the changelog and
    the manifest state one fact, and a test that hard-coded ``"0.1.0"`` would
    pass while the two disagreed. ``tests/unit/test_manifest.py`` owns the
    assertion that the field is present and is a semantic version; this fixture
    only refuses to hand on something unusable.
    """
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    version = manifest.get("version")
    assert isinstance(version, str) and SEMVER_PATTERN.match(version), (
        "plugin.json must declare a semantic version; found {0!r}".format(version)
    )
    return version


@pytest.fixture(scope="module")
def declared_repository() -> str:
    """The repository URL ``plugin.json`` declares, without a trailing slash.

    The value currently contains an ``<org>`` placeholder. That is deliberate and
    is recorded as an open gap: nothing in this repository knows the account the
    project will be published under. Reading the field rather than naming a URL
    means these tests carry no guess about it, and keep working when it is
    replaced.
    """
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    repository = manifest.get("repository")
    assert isinstance(repository, str) and repository, (
        "plugin.json must declare a non-empty 'repository'; found {0!r}".format(repository)
    )
    return repository.rstrip("/")


def release_labels(text: str) -> Tuple[str, ...]:
    """Every release label of the changelog, in document order.

    Includes ``Unreleased``: it is a section of the same kind, and the tests that
    are only about released versions filter it out by name.
    """
    return tuple(match.group("label") for match in RELEASE_HEADING_PATTERN.finditer(text))


def link_definitions(text: str) -> Dict[str, str]:
    """The link reference definitions of the changelog, by label."""
    return {
        match.group("label"): match.group("target")
        for match in LINK_DEFINITION_PATTERN.finditer(text)
    }


def release_body(text: str, label: str) -> str:
    """The body of the release entry labelled ``label``.

    Ends at the next level-1 or level-2 heading, or at the first link reference
    definition block, so the footer of link targets is not read as part of the
    last release.

    Raises:
        AssertionError: when no such release heading exists.
    """
    lines = text.splitlines()
    start = None
    for index, line in enumerate(lines):
        match = RELEASE_HEADING_PATTERN.match(line)
        if match is not None and match.group("label") == label:
            start = index
            break
    assert start is not None, "CHANGELOG.md has no release entry for {0!r}".format(label)
    for end in range(start + 1, len(lines)):
        current = lines[end]
        if current.startswith("## ") or current.startswith("# "):
            return "\n".join(lines[start + 1 : end])
        if LINK_DEFINITION_PATTERN.match(current):
            return "\n".join(lines[start + 1 : end])
    return "\n".join(lines[start + 1 :])


def test_changelog_file_exists() -> None:
    """Requirement 13 AC5: ``CHANGELOG.md`` ships at the root.

    Separate from the content tests so that a missing file reports once rather
    than as a dozen unmet claims about its structure.
    """
    assert CHANGELOG_PATH.is_file(), "Requirement 13 AC5 requires a CHANGELOG.md at the root"


def test_changelog_is_plain_ascii(changelog_text: str) -> None:
    """Requirement 13 AC6: ``CHANGELOG.md`` is English text.

    Held to ASCII rather than to an allowlist of typographic dashes, the same way
    the other root documents are: a non-ASCII character here comes from a paste
    rather than from the writing.
    """
    offenders = sorted({character for character in changelog_text if ord(character) > 127})
    assert not offenders, "CHANGELOG.md contains non-ASCII characters: {0}".format(
        [hex(ord(character)) for character in offenders]
    )


def test_changelog_names_the_format_it_follows(changelog_text: str) -> None:
    """Requirement 13 AC5: the file says it follows Keep a Changelog.

    The format is a promise to the reader about how to read the file. Stating it
    is what makes the six headings below mean what the reader expects rather than
    being six headings that happen to have those names.
    """
    assert "Keep a Changelog" in changelog_text, (
        "CHANGELOG.md does not name the format it follows"
    )


def test_change_type_headings_are_only_the_six_allowed(changelog_text: str) -> None:
    """Requirement 13 AC5: the six Keep a Changelog change types are the *only*
    headings used to group changes.

    Asserted as a subset check rather than as six presence checks. A seventh
    heading -- "Notes", "Internal", "Improvements" -- leaves all six present while
    breaking the one thing the format buys a reader: that every change in a
    release is filed under a known change type.
    """
    used = {match.group("title") for match in CHANGE_TYPE_HEADING_PATTERN.finditer(changelog_text)}
    unexpected = sorted(used - set(KEEP_A_CHANGELOG_CHANGE_TYPES))
    assert not unexpected, (
        "CHANGELOG.md groups changes under headings outside the Keep a Changelog "
        "set {0}: {1}".format(list(KEEP_A_CHANGELOG_CHANGE_TYPES), unexpected)
    )


def test_every_change_type_heading_sits_inside_a_release_entry(changelog_text: str) -> None:
    """A change type heading appears under a release, not in the preamble.

    Without this, ``### Added`` in the introduction would satisfy the subset check
    above while belonging to no version, which is the same as an unversioned
    change.
    """
    first_release = RELEASE_HEADING_PATTERN.search(changelog_text)
    assert first_release is not None, "CHANGELOG.md has no release entry at all"
    stray = [
        match.group("title")
        for match in CHANGE_TYPE_HEADING_PATTERN.finditer(changelog_text)
        if match.start() < first_release.start()
    ]
    assert not stray, (
        "CHANGELOG.md uses change type headings before its first release entry: "
        "{0}".format(stray)
    )


def test_no_change_type_section_is_left_empty(changelog_text: str) -> None:
    """Keep a Changelog: an empty change type is omitted rather than kept.

    This is what makes the single ``Added`` section of the first release correct
    rather than incomplete. It also catches the opposite defect: a heading added
    in anticipation of a change that was never written under it.
    """
    lines = changelog_text.splitlines()
    empty = []
    for index, line in enumerate(lines):
        heading = CHANGE_TYPE_HEADING_PATTERN.match(line)
        if heading is None:
            continue
        body = []
        for end in range(index + 1, len(lines)):
            if lines[end].startswith("#") or LINK_DEFINITION_PATTERN.match(lines[end]):
                break
            body.append(lines[end])
        if not " ".join(body).strip():
            empty.append(heading.group("title"))
    assert not empty, "CHANGELOG.md has change type headings with nothing under them: {0}".format(
        empty
    )


def test_a_release_entry_exists_for_the_declared_version(
    changelog_text: str, declared_version: str
) -> None:
    """Task 27.4 completion condition: the entry for the shipped version exists.

    The version comes from ``plugin.json``, so shipping a new version without
    writing its entry fails here rather than being noticed by a user reading a
    changelog that stops one release short.
    """
    labels = release_labels(changelog_text)
    assert declared_version in labels, (
        "plugin.json declares version {0!r}, which has no entry in CHANGELOG.md. "
        "Entries found: {1}".format(declared_version, list(labels))
    )


def test_every_release_label_is_a_version_or_the_unreleased_section(
    changelog_text: str,
) -> None:
    """Requirement 13 AC5: an entry names a version, so it can link to a tag.

    ``Unreleased`` is the one exception the format defines, and it is excluded by
    name rather than by pattern so that a label such as ``Next`` or ``0.2`` fails.
    """
    malformed = [
        label
        for label in release_labels(changelog_text)
        if label != UNRELEASED_LABEL and not SEMVER_PATTERN.match(label)
    ]
    assert not malformed, (
        "CHANGELOG.md has release labels that are neither a semantic version nor "
        "{0!r}: {1}".format(UNRELEASED_LABEL, malformed)
    )


def test_every_release_entry_has_a_link(changelog_text: str) -> None:
    """Requirement 13 AC5: every entry links, via a link reference definition.

    The headings are written as ``## [0.1.0]``, which renders as plain text unless
    a definition for the label exists. So the completion condition -- the entry
    has a link -- is exactly the question of whether every label is defined.
    """
    defined = link_definitions(changelog_text)
    undefined = [label for label in release_labels(changelog_text) if label not in defined]
    assert not undefined, (
        "CHANGELOG.md has release entries whose link reference is not defined: "
        "{0}".format(undefined)
    )


def test_release_link_targets_the_version_tag_in_the_declared_repository(
    changelog_text: str, declared_version: str, declared_repository: str
) -> None:
    """Requirement 13 AC5: the link is to *the version tag*, not to anywhere.

    The expected target is built from the manifest's ``repository`` and the
    manifest's ``version``, so this test asserts no URL of its own: it asserts
    that the changelog and the manifest agree on where the release lives. The
    ``v`` prefix is this project's tag convention, stated in the changelog
    preamble alongside the link.
    """
    target = link_definitions(changelog_text).get(declared_version)
    expected = "{0}/releases/tag/v{1}".format(declared_repository, declared_version)
    assert target == expected, (
        "the {0} link in CHANGELOG.md is {1!r}; expected {2!r}, built from the "
        "'repository' and 'version' fields of plugin.json".format(
            declared_version, target, expected
        )
    )


def test_every_released_entry_carries_an_iso_date(changelog_text: str) -> None:
    """Keep a Changelog: a released entry is dated ``YYYY-MM-DD``.

    Matched by shape rather than against a literal date, so the date of a future
    release is not this test's business. ``Unreleased`` is exempt: it has no date
    because it has no release.
    """
    undated = [
        match.group("label")
        for match in RELEASE_HEADING_PATTERN.finditer(changelog_text)
        if match.group("label") != UNRELEASED_LABEL and match.group("date") is None
    ]
    assert not undated, (
        "CHANGELOG.md has released entries without an ISO-8601 date: {0}".format(undated)
    )


def test_changelog_states_the_five_kinds_of_change_it_records(
    changelog_text: str,
) -> None:
    """Task 27.4 and steering/documentation.md: the five recorded kinds are named.

    A changelog that only lists what changed leaves a contributor guessing what is
    worth an entry. These five are the ones that can break a working caller, so
    the file states them rather than leaving the policy in the contributor guide.
    """
    text = flowed(changelog_text).lower()
    missing = [phrase for phrase in RECORDED_CHANGE_KINDS if phrase not in text]
    assert not missing, (
        "CHANGELOG.md does not state that it records: {0}".format(missing)
    )


def test_changelog_records_changes_to_the_category_vocabulary(
    changelog_text: str,
) -> None:
    """Design, Normalized Category Vocabulary: the mapping file is versioned, and a
    change to it is user-visible.

    Every Finding names a ``Normalized_Category`` from the closed set in
    ``iacreview/category_map.json``, so adding or removing one changes what a
    caller reads out of a report. That makes the mapping file's own
    ``schema_version`` something the changelog has to speak about, not an internal
    detail.
    """
    text = flowed(changelog_text)
    assert "iacreview/category_map.json" in text and "schema_version" in text, (
        "CHANGELOG.md does not say that changes to the versioned category mapping "
        "file are recorded"
    )


def test_changelog_quotes_the_category_map_schema_version(changelog_text: str) -> None:
    """The version the changelog attributes to the mapping file is the one the file
    declares.

    Read from ``iacreview/category_map.json`` rather than written here: the
    changelog quoting a stale ``schema_version`` is the drift worth catching, and
    it is invisible to every other assertion.
    """
    mapping = json.loads((REPO_ROOT / "iacreview" / "category_map.json").read_text(encoding="utf-8"))
    schema_version = mapping.get("schema_version")
    assert isinstance(schema_version, str) and schema_version, (
        "iacreview/category_map.json declares no schema_version"
    )
    assert schema_version in changelog_text, (
        "CHANGELOG.md does not mention the mapping file's schema_version {0!r}".format(
            schema_version
        )
    )


def test_changelog_quotes_the_report_schema_version(changelog_text: str) -> None:
    """The report ``schema_version`` the first release claims is the one the code
    emits.

    Imported rather than restated for the same reason the license identifier is
    read from the manifest. ``iacreview.report.SCHEMA_VERSION`` is the single
    source of the value, and a changelog naming a different one is a document that
    describes a different release.
    """
    from iacreview import report

    assert report.SCHEMA_VERSION in changelog_text, (
        "CHANGELOG.md does not mention the report schema_version {0!r} that "
        "iacreview.report emits".format(report.SCHEMA_VERSION)
    )


def test_first_release_claims_no_capability_that_is_out_of_scope(
    changelog_text: str, declared_version: str
) -> None:
    """Requirement 13 AC11: an ``Added`` bullet describes something that ships.

    The v0.1 non-goals -- Terraform, Pulumi, automatic remediation, deployment, a
    web UI, runtime security analysis, FinOps -- are the phrases most likely to
    appear in a release summary written from the design rather than from the
    repository. Checked against the ``Added`` body alone, because the surrounding
    prose legitimately says these are *not* done.
    """
    body = release_body(changelog_text, declared_version)
    added = ""
    lines = body.splitlines()
    for index, line in enumerate(lines):
        heading = CHANGE_TYPE_HEADING_PATTERN.match(line)
        if heading is not None and heading.group("title") == "Added":
            for end in range(index + 1, len(lines)):
                if lines[end].startswith("#"):
                    added = "\n".join(lines[index + 1 : end])
                    break
            else:
                added = "\n".join(lines[index + 1 :])
            break
    assert added.strip(), "the {0} entry has no Added section".format(declared_version)
    claimed = [phrase for phrase in NON_GOAL_PHRASES if phrase in flowed(added).lower()]
    assert not claimed, (
        "the {0} Added section describes out-of-scope capabilities as shipped: "
        "{1}".format(declared_version, claimed)
    )


def test_changelog_names_only_paths_that_exist(changelog_text: str) -> None:
    """Every repository path in an inline code span resolves.

    The same guard applied to ``docs/`` and to ``CONTRIBUTING.md``. A release entry
    is read long after it was written, and a path that has since moved makes the
    entry unverifiable by exactly the reader trying to confirm what a release
    contained.
    """
    prose = FENCED_BLOCK_PATTERN.sub("", changelog_text)
    missing = sorted(
        {
            token
            for token in INLINE_CODE_PATTERN.findall(prose)
            if is_repository_path_token(token) and not (REPO_ROOT / token).exists()
        }
    )
    assert not missing, "CHANGELOG.md names paths that do not exist: {0}".format(missing)


def test_changelog_contains_no_absolute_host_path(changelog_text: str) -> None:
    """steering/security.md: no path from the machine that wrote the file."""
    leaks = [
        line
        for line in changelog_text.splitlines()
        if "/Users/" in line or "/home/" in line or "site-packages" in line
    ]
    assert not leaks, "CHANGELOG.md contains host-specific paths: {0}".format(leaks)


# ---------------------------------------------------------------------------
# README.md structure (Task 27.1)
# ---------------------------------------------------------------------------
#
# Requirement 13 AC1 names seventeen level-2 sections and names them in an order.
# Task 27.1 asks for both, and for the nine limitations Requirement 13 AC2 and the
# task itself require the "Known Limitations" section to carry. The three
# assertions below are shaped so that each failure says something different:
#
# - presence, parametrized, so a dropped section is named;
# - the exact sequence, so a reordered or *added* section fails. A README that
#   gains an eighteenth level-2 heading still contains all seventeen, and the
#   order AC1 lists is the reading order a newcomer is promised;
# - the nine limitations, parametrized, matched on the phrase each turns on
#   rather than on a sentence, so the prose can be rewritten while a limitation
#   that quietly disappeared still fails.
#
# The nine are not interchangeable. Six of them exist because a reader would
# otherwise draw a false conclusion from a clean report -- no sandbox, a rejected
# filename, conservative CRITICAL, the Guard rules' resource-type reach, the
# resource-based-policy list, tool version drift -- and steering/documentation.md
# is explicit that those are recorded rather than downplayed.

#: The seventeen level-2 sections Requirement 13 AC1 requires, in the order the
#: criterion lists them. Order is part of the requirement, so this is a sequence
#: and it is compared as one.
README_REQUIRED_SECTIONS: Tuple[str, ...] = (
    "What is aws-iac-review-agent-plugin",
    "Why this project exists",
    "Architecture",
    "Supported IaC",
    "Requirements",
    "Installation",
    "Using as a Kiro Power",
    "Usage",
    "Review Categories",
    "Examples",
    "Benchmark",
    "Validation",
    "Security Considerations",
    "Known Limitations",
    "Roadmap",
    "Contributing",
    "License",
)

#: The nine limitations Task 27.1 requires "Known Limitations" to list, each as a
#: label and the phrases that have to be present for the limitation to have been
#: stated. Matched case-insensitively against the flowed section, because the
#: file is hard-wrapped and a phrase such as "no sandboxing for `cdk synth`" is
#: split across a line break in the source.
#:
#: More than one phrase per entry where the heading alone would not settle it: a
#: bold lead-in can survive while the consequence it existed to state is edited
#: away, and the consequence is the part a reader needs.
KNOWN_LIMITATION_CLAIMS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    (
        "features out of scope for v0.1",
        (
            "v0.1 does not cover",
            "terraform",
            "pulumi",
            "runtime security",
            "finops",
            "web ui",
            "automatic remediation",
            "non-goals for this version",
        ),
    ),
    (
        "cdk synth has no sandbox",
        ("no sandboxing for `cdk synth`", "your full user privileges"),
    ),
    (
        "Agent Review output is not deterministic",
        ("agent review output is not deterministic", "on a second run"),
    ),
    (
        "Windows is not supported",
        ("windows is not supported", "macos and linux only"),
    ),
    (
        "a filename containing $ is rejected",
        ("a filename containing `$` is rejected", "shell metacharacter"),
    ),
    (
        "CRITICAL is assigned conservatively",
        (
            "the `critical` severity is assigned conservatively",
            "reported as `high` rather than `critical`",
        ),
    ),
    (
        "the bundled Guard rules reach only the resource types they target",
        (
            "only inspect the resource types they name",
            "produces no cfn-guard finding",
        ),
    ),
    (
        "resource-based policy coverage is a fixed list",
        ("resource-based policy coverage is a fixed list", "not yet covered"),
    ),
    (
        "external tool version differences change results",
        (
            "external tool version differences change results",
            "`tools[].version`",
        ),
    ),
)


def readme_level_2_headings(text: str) -> Tuple[str, ...]:
    """The level-2 heading titles of a README, in document order.

    Used for both READMEs, so that the Japanese supplement is compared against
    the English original's structure rather than against a count written here.
    """
    return tuple(
        line.strip()[len("## ") :].strip()
        for line in text.splitlines()
        if line.startswith("## ")
    )


@pytest.mark.parametrize("title", README_REQUIRED_SECTIONS)
def test_readme_has_required_section(readme_text: str, title: str) -> None:
    """Requirement 13 AC1: each of the seventeen sections is present, and has a
    body.

    Asserted through :func:`readme_section`, which fails on a missing heading, so
    a renamed section reports as missing rather than as empty.
    """
    assert readme_section(readme_text, title).strip(), (
        "Requirement 13 AC1 requires a level-2 section {0!r} with content".format(title)
    )


def test_readme_level_2_headings_are_exactly_the_required_sequence(
    readme_text: str,
) -> None:
    """Requirement 13 AC1: those seventeen sections, in that order, and no others.

    Compared as a sequence rather than as a set for two reasons. The order is
    what the criterion states, and it is the reading order the document promises:
    a newcomer meets "what is this" before "how do I install it". And an
    eighteenth section of someone's own invention passes every presence check
    above while moving a claim out of the section a reader looks for it in.
    """
    assert readme_level_2_headings(readme_text) == README_REQUIRED_SECTIONS


def test_readme_is_plain_ascii(readme_text: str) -> None:
    """Requirement 13 AC6: ``README.md`` is written in English.

    The same mechanical proxy the other root documents get, and here it carries a
    second job. Requirement 13 AC8 permits a Japanese supplement *alongside* the
    English original and forbids it replacing the original, so the thing to pin is
    that Japanese prose arrives in ``README.ja.md`` rather than in this file. The
    document is ASCII today -- it writes its em dashes as ``--`` deliberately, and
    says so where it transcribes a passage from ``docs/finding-schema.md`` -- so
    this assertion costs it nothing.
    """
    offenders = sorted({character for character in readme_text if ord(character) > 127})
    assert not offenders, "README.md contains non-ASCII characters: {0}".format(
        [hex(ord(character)) for character in offenders]
    )


@pytest.mark.parametrize(
    ("label", "phrases"),
    KNOWN_LIMITATION_CLAIMS,
    ids=[label for label, _ in KNOWN_LIMITATION_CLAIMS],
)
def test_known_limitations_records_each_required_limitation(
    readme_text: str, label: str, phrases: Tuple[str, ...]
) -> None:
    """Requirement 13 AC2 and Task 27.1: the nine limitations are stated.

    Scoped to the "Known Limitations" section rather than to the whole file. Most
    of these nine are discussed elsewhere in the README as well -- the sandbox in
    Security Considerations, the non-goals in Roadmap -- and a reader who opens
    Known Limitations to find out what this plugin does not do is entitled to find
    them there.
    """
    section = flowed(readme_section(readme_text, "Known Limitations")).lower()
    missing = [phrase for phrase in phrases if phrase not in section]
    assert not missing, (
        "the README Known Limitations section does not record {0!r}; missing "
        "phrases: {1}".format(label, missing)
    )


# ---------------------------------------------------------------------------
# README.ja.md (Task 27.5, Requirement 13 AC8)
# ---------------------------------------------------------------------------
#
# The Japanese supplement is the one deliverable of Task 27 that design treats as
# deferrable, so every case below skips when the file is absent rather than
# failing. Absence is a permitted state; a supplement that exists and does not
# correspond to the English original is not.
#
# What Requirement 13 AC8 actually constrains is the relationship between two
# files, not the contents of one: an identifying suffix, and no replacement of the
# English original. So the assertions are relational. The section count and the
# section order are read out of ``README.md`` rather than restated here, which is
# the same rule the license assertions follow -- one fact, two files, and the
# disagreement between them is what is worth catching. If Requirement 13 AC1 ever
# gains an eighteenth section, the test above is the one that fails, and these
# keep measuring correspondence rather than a stale count of seventeen.

README_JA_PATH: Path = REPO_ROOT / "README.ja.md"

#: Each English section paired with the Japanese title this repository gives it.
#: Fixed here for the same reason :data:`CONTRIBUTING_REQUIRED_SECTIONS` fixes
#: its headings: the requirement names the sections by their content, and the
#: titles are this repository's rendering of them. Ordered by the English
#: sequence, so the expected Japanese sequence is derived from it rather than
#: written twice.
README_JA_SECTION_TITLES: Tuple[Tuple[str, str], ...] = (
    ("What is aws-iac-review-agent-plugin", "aws-iac-review-agent-plugin \u3068\u306f"),
    ("Why this project exists", "\u306a\u305c\u3053\u306e Project \u304c\u5fc5\u8981\u304b"),
    ("Architecture", "Architecture"),
    ("Supported IaC", "\u5bfe\u5fdc IaC"),
    ("Requirements", "Requirements"),
    ("Installation", "Installation"),
    ("Using as a Kiro Power", "Kiro Power \u3068\u3057\u3066\u306e\u5229\u7528"),
    ("Usage", "Usage"),
    ("Review Categories", "Review Categories"),
    ("Examples", "Examples"),
    ("Benchmark", "Benchmark"),
    ("Validation", "Validation"),
    ("Security Considerations", "Security \u4e0a\u306e\u8003\u616e\u4e8b\u9805"),
    ("Known Limitations", "Known Limitations"),
    ("Roadmap", "Roadmap"),
    ("Contributing", "Contributing"),
    ("License", "License"),
)

#: What the supplement has to say about its own standing, written as escapes so
#: that this module stays readable in a terminal that does not render Japanese.
#: ``\u6b63\u5178`` is "authoritative text"; ``\u7f6e\u304d\u63db\u3048\u306a\u3044``
#: is "does not replace". Both halves of Requirement 13 AC8 are claims the
#: document makes to its reader, so the document is where they are checked.
README_JA_STANDING_PHRASES: Tuple[str, ...] = (
    "README.md",
    "\u6b63\u5178",
    "\u82f1\u8a9e\u7248",
    "\u7f6e\u304d\u63db\u3048\u306a\u3044",
)


@pytest.fixture(scope="module")
def readme_ja_text() -> str:
    """The text of ``README.ja.md``, or a skip when it is not there.

    Requirement 13 AC8 is a ``WHERE`` criterion: it constrains a Japanese
    supplement if one is provided, and provides for none otherwise. Task 27.5 is
    marked deferrable for the same reason. A hard failure here would make an
    optional document mandatory by way of its test.
    """
    if not README_JA_PATH.is_file():
        pytest.skip(
            "README.ja.md is not present; Requirement 13 AC8 constrains the "
            "Japanese supplement only where one is provided"
        )
    return README_JA_PATH.read_text(encoding="utf-8")


def test_readme_ja_does_not_replace_the_english_readme(readme_ja_text: str) -> None:
    """Requirement 13 AC8: the supplement is added, and the original stays.

    The completion condition of Task 27.5, stated as one assertion. The failure it
    exists for is a translation committed *over* ``README.md``, which leaves a
    repository whose front page no longer reads for the community the project is
    published to.
    """
    assert README_PATH.is_file(), (
        "README.ja.md exists but README.md does not; Requirement 13 AC8 forbids "
        "the supplement replacing the English original"
    )


def test_readme_ja_is_where_the_japanese_prose_lives(readme_ja_text: str) -> None:
    """Requirement 13 AC8: the identifying suffix identifies something.

    Paired with ``test_readme_is_plain_ascii``, this is the pair of assertions
    that gives the ``.ja`` suffix its meaning: the Japanese text is in the file
    whose name says so, and the English file has none. A supplement that had been
    started and left as an English copy would satisfy every structural assertion
    below and satisfy nothing a Japanese reader opened it for.
    """
    assert any(ord(character) > 127 for character in readme_ja_text), (
        "README.ja.md carries no non-ASCII character, so it is not the Japanese "
        "supplement its name claims"
    )


def test_readme_ja_has_one_section_per_english_section(
    readme_ja_text: str, readme_text: str
) -> None:
    """Task 27.5 completion condition: the section structure corresponds.

    Counted against ``README.md`` rather than against the literal seventeen, so
    that a section added to the English original is reported here as a section
    the supplement is missing, rather than both files passing a count that is no
    longer what Requirement 13 AC1 asks for.
    """
    english = readme_level_2_headings(readme_text)
    japanese = readme_level_2_headings(readme_ja_text)
    assert len(japanese) == len(english), (
        "README.md has {0} level-2 sections and README.ja.md has {1}; the "
        "supplement should correspond section for section. README.ja.md: "
        "{2}".format(len(english), len(japanese), list(japanese))
    )


def test_readme_ja_sections_follow_the_english_order(readme_ja_text: str) -> None:
    """Task 27.5: the sections correspond *in order*, not merely in number.

    The expected sequence is built from :data:`README_JA_SECTION_TITLES`, which is
    ordered by the English sequence, so a supplement that renamed or reordered a
    section fails and names which one. A count alone would pass a document whose
    Roadmap had been folded into Known Limitations and a section invented to make
    the total come out right.
    """
    expected = tuple(japanese for _, japanese in README_JA_SECTION_TITLES)
    assert readme_level_2_headings(readme_ja_text) == expected


def test_no_readme_ja_section_is_left_empty(readme_ja_text: str) -> None:
    """Task 27.5: "corresponds to the English section structure", with content.

    Seventeen headings and nothing under them corresponds to the structure and to
    none of the substance. Checked here rather than by comparing lengths with the
    English section, which would turn every editorial decision about how much
    detail to translate into a test failure.
    """
    headings = readme_level_2_headings(readme_ja_text)
    empty = [
        title
        for title in headings
        if not readme_section(readme_ja_text, title).strip()
    ]
    assert not empty, "README.ja.md has level-2 sections with nothing under them: {0}".format(
        empty
    )


def test_readme_links_to_the_japanese_supplement(
    readme_ja_text: str, readme_text: str
) -> None:
    """Task 27.5: ``README.md`` links to the supplement.

    Half of the reciprocal link, and the half that has a reader on the other end.
    A Japanese reader who never learns the supplement exists is in the position
    the supplement was written to improve.
    """
    assert "README.ja.md" in readme_text, (
        "README.md does not link to README.ja.md"
    )


def test_readme_ja_links_back_to_the_english_readme(readme_ja_text: str) -> None:
    """Task 27.5: the other half of the reciprocal link.

    Asserted as a Markdown link target rather than as a mention, because the
    supplement names ``README.md`` in prose as well and a mention is not a way
    back.
    """
    assert "(README.md)" in readme_ja_text, (
        "README.ja.md does not link back to README.md"
    )


def test_readme_ja_states_that_the_english_readme_is_authoritative(
    readme_ja_text: str,
) -> None:
    """Requirement 13 AC8: the supplement says what it is.

    Two documents describing one system will drift, and when they do a reader has
    to know which one settles it. Saying so in the supplement is what keeps a
    stale translation from being read as a correction to the original.
    """
    missing = [phrase for phrase in README_JA_STANDING_PHRASES if phrase not in readme_ja_text]
    assert not missing, (
        "README.ja.md does not state that README.md is the authoritative "
        "document that it supplements rather than replaces; missing: {0}".format(missing)
    )


def test_readme_ja_names_only_paths_that_exist(readme_ja_text: str) -> None:
    """Every repository path in an inline code span resolves.

    The same guard ``docs/``, ``CONTRIBUTING.md`` and ``CHANGELOG.md`` get. A
    supplement is the document most likely to hold a stale path, because it is
    written once from the original and then not re-read every time a file moves.
    """
    prose = FENCED_BLOCK_PATTERN.sub("", readme_ja_text)
    missing = sorted(
        {
            token
            for token in INLINE_CODE_PATTERN.findall(prose)
            if is_repository_path_token(token) and not (REPO_ROOT / token).exists()
        }
    )
    assert not missing, "README.ja.md names paths that do not exist: {0}".format(missing)


def test_readme_ja_contains_no_absolute_host_path(readme_ja_text: str) -> None:
    """steering/security.md: no path from the machine that wrote the file."""
    leaks = [
        line
        for line in readme_ja_text.splitlines()
        if "/Users/" in line or "/home/" in line or "site-packages" in line
    ]
    assert not leaks, "README.ja.md contains host-specific paths: {0}".format(leaks)
