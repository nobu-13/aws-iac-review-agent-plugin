"""Structural checks on every ``SKILL.md`` under ``skills/``.

A Skill's ``SKILL.md`` is the only thing a host agent reads before deciding to
invoke the Skill, so its structure is an interface rather than documentation.
This module holds the five Skills to that interface:

- Requirement 1 AC4   : a Skill directory with no ``SKILL.md``, or one whose
                        ``SKILL.md`` has no top-level heading, is skipped without
                        disabling its valid siblings
- Requirement 2 AC11  : front matter declares ``name`` and ``description``, and
                        the description states both the capability offered and the
                        conditions for selecting the Skill
- Requirement 2 AC12  : ``name`` equals the name of the containing directory
- Requirement 2 AC13  : the six required sections are present, in one order
- Requirement 13 AC7  : the file is written in English, asserted as ASCII-only
- Requirement 15 AC2  : ``## Dependencies`` names each external runtime
                        dependency and states that it is not bundled
- Requirement 16 AC8  : every documented exit code is one
                        :mod:`iacreview.exitcodes` defines, and each Skill
                        documents the codes it can actually return
- design.md [Correction] C-10 : the cross-Skill stdout key contract

Two things are deliberately *not* asserted here.

The ``sys.path`` prologue of each entry point is
``tests/unit/test_bootstrap.py``'s job: it compares every script against
:data:`iacreview.bootstrap.REQUIRED_BOOTSTRAP_LINES` and against the
``parents[3]`` depth assumption. This module only checks that the entry point a
``SKILL.md`` tells the user to run exists, which is the half no other test covers.

The actual bytes on stdout are the per-Skill integration tests' job
(``tests/integration/test_skill_*.py`` assert the real key set of a real run
against :data:`iacreview.report.REPORT_KEYS`). This module checks that every
``SKILL.md`` *documents* the same contract those tests enforce, so documentation
and behaviour cannot drift apart silently.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Tuple

import pytest
import yaml

from iacreview import exitcodes
from iacreview.report import REPORT_KEYS

# ---------------------------------------------------------------------------
# The contract, as data
# ---------------------------------------------------------------------------

#: Every Skill the plugin ships (Requirement 2 AC1-AC5), in sorted order.
#: Written out literally rather than derived from the filesystem: a Skill
#: silently disappearing from ``skills/`` is exactly what this list catches.
SKILL_NAMES: Tuple[str, ...] = (
    "cfn-guard-review",
    "cfn-lint-review",
    "cloudformation-review",
    "iac-review",
    "iam-review",
)

#: The sections Requirement 2 AC13 requires, spelled as the five Skills spell
#: them and in the order all five use. Order is asserted as well as presence: a
#: reader comparing two Skills should not have to hunt for the same section in
#: two places.
REQUIRED_SECTIONS: Tuple[str, ...] = (
    "Purpose",
    "When to use this skill",
    "Input",
    "Output",
    "Limitations",
    "Dependencies",
)

#: Front matter fields Requirement 2 AC11 requires.
REQUIRED_FRONT_MATTER_FIELDS: Tuple[str, ...] = ("name", "description")

#: Lower bound on the length of ``description``, in characters. An approximation
#: of Requirement 2 AC11's "states both the capability and the selection
#: conditions": the shortest of the five descriptions is over 700 characters, so
#: this fails only a description that stopped stating one of the two halves.
MIN_DESCRIPTION_LENGTH = 200

#: Phrases approximating the two halves of Requirement 2 AC11. The positive
#: phrase carries the selection condition; the negative one is design.md's
#: addition, because five Skills cover adjacent ground and each description must
#: also say when *not* to pick it.
DESCRIPTION_SELECTION_PHRASE = "Use this skill when"
DESCRIPTION_REJECTION_PHRASE = "Do not use this skill"

#: Skills that launch an external tool, and the tool names their
#: ``## Dependencies`` section must name (Requirement 15 AC2).
EXTERNAL_TOOL_SKILLS: Dict[str, Tuple[str, ...]] = {
    "cfn-lint-review": ("cfn-lint",),
    "cfn-guard-review": ("cfn-guard",),
    "iac-review": ("cfn-lint", "cfn-guard", "CDK"),
}

#: Skills that launch nothing.
TOOL_FREE_SKILLS: Tuple[str, ...] = tuple(
    sorted(set(SKILL_NAMES) - set(EXTERNAL_TOOL_SKILLS))
)

#: Wordings accepted for "stdout carries this JSON document and nothing more"
#: (Requirement 16 AC10, and the first clause of design.md C-10). Two spellings,
#: differing only in the comma, because the Skills use both.
STDOUT_ONLY_PHRASES: Tuple[str, ...] = (
    "stdout and nothing else",
    "stdout, and nothing else",
)

#: Wordings accepted for "this tool is not part of the plugin package"
#: (Requirement 15 AC2). Two spellings, because the Skills use both.
NOT_BUNDLED_PHRASES: Tuple[str, ...] = (
    "not included in the plugin package",
    "not bundled",
)

#: Exit codes every Skill can return whatever it does: success, internal error,
#: argument validation, unreadable input, unparsable input, a path outside the
#: workspace, nothing reviewable. None of them depends on an external tool.
UNIVERSAL_EXIT_CODES: FrozenSet[int] = frozenset(
    {
        exitcodes.OK,
        exitcodes.UNEXPECTED,
        exitcodes.INVALID_ARGUMENTS,
        exitcodes.INPUT_NOT_FOUND,
        exitcodes.PARSE_FAILURE,
        exitcodes.PATH_VIOLATION,
        exitcodes.NO_REVIEWABLE_TEMPLATE,
    }
)

#: Top-level stdout keys each ``SKILL.md`` must declare (design.md
#: [Correction] C-10). Derived from :data:`iacreview.report.REPORT_KEYS` rather
#: than written out, so changing the envelope forces the documentation to change
#: with it.
#:
#: ``cfn-guard-review`` is the one Skill permitted a key beside the envelope:
#: Requirement 5 AC4 obliges a clean run to state how many rules it evaluated,
#: which makes that count part of the *result* rather than a diagnostic, and
#: Requirement 16 AC10 puts results on stdout. Every other counter in the plugin
#: is a diagnostic and belongs on stderr.
#:
#: ``cloudformation-review`` maps to the empty set: its stdout is a facts
#: document, not a Review_Report, so it declares no envelope. Its own key table
#: lives in its ``## Output`` section.
STDOUT_KEY_CONTRACT: Dict[str, FrozenSet[str]] = {
    "cfn-lint-review": frozenset(REPORT_KEYS),
    "cfn-guard-review": frozenset(REPORT_KEYS) | {"stats"},
    "iam-review": frozenset(REPORT_KEYS),
    "iac-review": frozenset(REPORT_KEYS),
    "cloudformation-review": frozenset(),
}

#: The one key a Skill may add beside the envelope, and the only Skill that may.
COUNTERS_KEY = "stats"
COUNTERS_KEY_OWNER = "cfn-guard-review"

#: The acceptance criterion that permits :data:`COUNTERS_KEY`, as the owning
#: document must cite it.
COUNTERS_KEY_JUSTIFICATION = "Requirement 5 AC4"

#: Entry points each ``SKILL.md`` tells the user to run, relative to the Skill
#: directory. Only the invocations the document advertises; the depth and
#: prologue of every script are ``tests/unit/test_bootstrap.py``'s concern.
ADVERTISED_ENTRY_POINTS: Dict[str, Tuple[str, ...]] = {
    "cfn-lint-review": ("scripts/run_cfn_lint.py",),
    "cfn-guard-review": ("scripts/run_cfn_guard.py",),
    "iam-review": ("scripts/extract_policies.py", "scripts/run_iam_scan.py"),
    "cloudformation-review": ("scripts/extract_facts.py",),
    "iac-review": ("scripts/run_iac_review.py",),
}

#: Reasons :func:`discover_skills` skips a directory (Requirement 1 AC4).
SKIP_NO_SKILL_MD = "no SKILL.md"
SKIP_NO_TOP_LEVEL_HEADING = "no top-level heading"

SKILL_FILE_NAME = "SKILL.md"

_FENCE = "```"
_FRONT_MATTER_DELIMITER = "---"
_TOP_LEVEL_HEADING = "# "
_SECTION_HEADING = "## "
_CODE_SPAN = re.compile(r"`([^`]+)`")
#: The declaration sentence of the stdout key contract, up to its first period.
#: The enumeration holds no period, so ``[^.]*`` stops exactly at the end of it.
_STDOUT_KEYS_SENTENCE = re.compile(r"Top-level stdout keys[^.]*\.")
#: An exit code as the Skills document one: the leading cell of a table row, or a
#: bare number in a code span for the Skill that documents them in prose.
_TABLE_ROW_NUMBER = re.compile(r"(?m)^\|\s*(\d+)\s*\|")
_INLINE_CODE_NUMBER = re.compile(r"`(\d+)`")


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SkillDoc:
    """One ``SKILL.md`` that passed discovery.

    Attributes:
        name: The Skill directory name.
        path: Absolute path to the ``SKILL.md``.
        text: Its full contents, front matter included.
    """

    name: str
    path: Path
    text: str


@dataclass(frozen=True)
class SkippedSkill:
    """One directory discovery declined to treat as a Skill.

    Attributes:
        name: The directory name.
        reason: :data:`SKIP_NO_SKILL_MD` or :data:`SKIP_NO_TOP_LEVEL_HEADING`.
    """

    name: str
    reason: str


def _front_matter_bounds(text: str) -> Optional[Tuple[int, int]]:
    """Character offsets of the front matter block's content, or ``None``.

    ``None`` covers both "no opening delimiter" and "opening delimiter never
    closed"; neither is a front matter a caller can read.
    """
    opening = _FRONT_MATTER_DELIMITER + "\n"
    if not text.startswith(opening):
        return None
    closing = text.find("\n" + opening, len(_FRONT_MATTER_DELIMITER))
    if closing == -1:
        return None
    return len(opening), closing + 1


def strip_front_matter(text: str) -> str:
    """Return ``text`` without its YAML front matter block.

    Args:
        text: Full ``SKILL.md`` contents.

    Returns:
        The Markdown body, or ``text`` unchanged when it carries no readable
        front matter -- so a document without one is still scanned for headings
        rather than treated as empty.
    """
    bounds = _front_matter_bounds(text)
    if bounds is None:
        return text
    return text[bounds[1] + len(_FRONT_MATTER_DELIMITER) + 1 :]


def parse_front_matter(text: str) -> Optional[Dict[str, object]]:
    """Parse the YAML front matter of ``text``.

    Args:
        text: Full ``SKILL.md`` contents.

    Returns:
        The parsed mapping, or ``None`` when there is no readable front matter
        block or its content is not a mapping. ``None`` rather than an exception:
        the caller decides whether that is a failure or a reason to skip.
    """
    bounds = _front_matter_bounds(text)
    if bounds is None:
        return None
    loaded = yaml.safe_load(text[bounds[0] : bounds[1]])
    return loaded if isinstance(loaded, dict) else None


def _body_lines(text: str) -> List[str]:
    """Body lines of ``text`` with fenced code blocks removed.

    Headings are found on the result, so a ``#`` that is a shell comment or a
    Markdown example inside a fence cannot be mistaken for a heading.
    """
    lines: List[str] = []
    inside_fence = False
    for line in strip_front_matter(text).splitlines():
        if line.startswith(_FENCE):
            inside_fence = not inside_fence
            continue
        if not inside_fence:
            lines.append(line)
    return lines


def top_level_headings(text: str) -> List[str]:
    """Every ``# `` heading of ``text``, in document order.

    ``"## Purpose"`` does not match: its second character is ``#`` rather than a
    space, so the prefix test distinguishes the two heading levels on its own.
    """
    return [
        line[len(_TOP_LEVEL_HEADING) :].strip()
        for line in _body_lines(text)
        if line.startswith(_TOP_LEVEL_HEADING)
    ]


def section_titles(text: str) -> List[str]:
    """Every ``## `` heading of ``text``, in document order. ``###`` is not one."""
    return [
        line[len(_SECTION_HEADING) :].strip()
        for line in _body_lines(text)
        if line.startswith(_SECTION_HEADING)
    ]


def section_body(text: str, title: str) -> str:
    """Return the text under the ``## <title>`` heading, subsections included.

    Args:
        text: Full ``SKILL.md`` contents.
        title: Section title without the ``## `` prefix.

    Returns:
        Everything from the line after the heading up to the next ``## `` heading
        or the end of the document, the empty string when the section is absent.
        Fenced blocks are kept -- a section body is read for content, and a
        ``##`` inside a fence does not end it.
    """
    heading = _SECTION_HEADING + title
    collected: List[str] = []
    capturing = False
    inside_fence = False
    for line in strip_front_matter(text).splitlines():
        if line.startswith(_FENCE):
            inside_fence = not inside_fence
        elif not inside_fence and line.startswith(_SECTION_HEADING):
            if line.strip() == heading:
                capturing = True
                continue
            if capturing:
                break
        if capturing:
            collected.append(line)
    return "\n".join(collected)


def flatten(text: str) -> str:
    """Collapse every run of whitespace in ``text`` to one space.

    Phrase assertions run on the result. Without it, a phrase would have to be
    matched across the line break the 80-column wrapping happens to have put in
    the middle of it, which would make a reflow of a paragraph fail a test.
    """
    return " ".join(text.split())


def declared_stdout_keys(text: str) -> FrozenSet[str]:
    """Top-level stdout keys the document declares (design.md C-10).

    Args:
        text: Full ``SKILL.md`` contents.

    Returns:
        The key names of the "Top-level stdout keys" declaration, or the empty
        set when the document makes no such declaration -- the correct answer for
        a Skill whose stdout is not a Review_Report. The whole document is
        searched rather than one section: the declaration belongs wherever the
        Skill documents its script's stdout, which for an agent-reasoning Skill is
        not ``## Output`` (see
        :func:`test_document_states_that_stdout_carries_json_only`).
    """
    match = _STDOUT_KEYS_SENTENCE.search(flatten(text))
    if match is None:
        return frozenset()
    return frozenset(_CODE_SPAN.findall(match.group(0)))


def documented_exit_codes(text: str) -> FrozenSet[int]:
    """Exit codes the ``## Output`` section tells the caller it can return.

    Args:
        text: Full ``SKILL.md`` contents.

    Returns:
        Every number presented as an exit code, read from exit code table rows
        and from inline code spans holding a bare number. Both forms are needed:
        four Skills use a table and ``cloudformation-review`` uses a sentence.
        Only ``## Output`` is scanned, because that is where all five document
        their codes and other sections hold numbered tables of their own.
    """
    output = section_body(text, "Output")
    numbers = _TABLE_ROW_NUMBER.findall(output) + _INLINE_CODE_NUMBER.findall(output)
    return frozenset(int(value) for value in numbers)


def discover_skills(
    skills_root: Path,
) -> Tuple[Tuple[SkillDoc, ...], Tuple[SkippedSkill, ...]]:
    """Load every valid Skill under ``skills_root``, skipping the invalid ones.

    Implements the discovery Requirement 1 AC4 describes: a directory with no
    ``SKILL.md``, or a ``SKILL.md`` with no top-level heading, is skipped and its
    siblings are unaffected. Nothing is raised for a broken directory, because
    raising is the behaviour AC4 forbids.

    Args:
        skills_root: The ``skills/`` directory to scan.

    Returns:
        ``(valid, skipped)``, both sorted by directory name so the result does
        not depend on filesystem order.
    """
    valid: List[SkillDoc] = []
    skipped: List[SkippedSkill] = []
    for directory in sorted(path for path in skills_root.iterdir() if path.is_dir()):
        skill_md = directory / SKILL_FILE_NAME
        if not skill_md.is_file():
            skipped.append(SkippedSkill(directory.name, SKIP_NO_SKILL_MD))
            continue
        text = skill_md.read_text(encoding="utf-8")
        if not top_level_headings(text):
            skipped.append(SkippedSkill(directory.name, SKIP_NO_TOP_LEVEL_HEADING))
            continue
        valid.append(SkillDoc(name=directory.name, path=skill_md, text=text))
    return tuple(valid), tuple(skipped)


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def skills_root(plugin_root: Path) -> Path:
    """The plugin's own ``skills/`` directory."""
    return plugin_root / "skills"


@pytest.fixture(scope="module")
def skill_docs(skills_root: Path) -> Dict[str, SkillDoc]:
    """Every valid ``SKILL.md`` of the plugin, keyed by Skill name."""
    valid, _ = discover_skills(skills_root)
    return {doc.name: doc for doc in valid}


@pytest.fixture
def skill(request: pytest.FixtureRequest, skill_docs: Dict[str, SkillDoc]) -> SkillDoc:
    """The ``SkillDoc`` of the Skill named by the test's indirect parameter.

    Parametrized as ``@pytest.mark.parametrize("skill", ..., indirect=True)``, so
    a test declares which Skills it applies to and receives the document itself.
    """
    name = request.param
    assert name in skill_docs, "{0} was not discovered as a valid Skill".format(name)
    return skill_docs[name]


def _write_skill_md(directory: Path, body: str, *, name: str = "stub") -> None:
    """Write a ``SKILL.md`` with valid front matter and the given body."""
    directory.mkdir(parents=True, exist_ok=True)
    (directory / SKILL_FILE_NAME).write_text(
        "---\nname: {0}\ndescription: stub\n---\n\n{1}".format(name, body),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Discovery (Requirement 1 AC4)
# ---------------------------------------------------------------------------


def test_every_expected_skill_is_discovered(skill_docs: Dict[str, SkillDoc]) -> None:
    assert tuple(sorted(skill_docs)) == SKILL_NAMES


def test_no_skill_directory_of_the_plugin_is_skipped(skills_root: Path) -> None:
    _, skipped = discover_skills(skills_root)
    assert skipped == ()


def test_a_broken_sibling_does_not_disable_the_real_skills(
    tmp_path: Path, skill_docs: Dict[str, SkillDoc]
) -> None:
    """Requirement 1 AC4, checked against the real documents.

    The five real ``SKILL.md`` files are copied next to two broken directories
    rather than broken in place: ``skills/`` is shared with the rest of the suite
    and with whatever else runs in the workspace, so nothing here writes into it.
    """
    root = tmp_path / "skills"
    for name, doc in skill_docs.items():
        target = root / name
        target.mkdir(parents=True)
        (target / SKILL_FILE_NAME).write_text(doc.text, encoding="utf-8")
    (root / "no-skill-md").mkdir()
    _write_skill_md(root / "no-heading", "Body without any heading.\n")

    valid, skipped = discover_skills(root)

    assert tuple(doc.name for doc in valid) == SKILL_NAMES
    assert skipped == (
        SkippedSkill("no-heading", SKIP_NO_TOP_LEVEL_HEADING),
        SkippedSkill("no-skill-md", SKIP_NO_SKILL_MD),
    )


def test_a_directory_without_a_skill_md_is_skipped(tmp_path: Path) -> None:
    root = tmp_path / "skills"
    (root / "empty").mkdir(parents=True)
    valid, skipped = discover_skills(root)
    assert valid == ()
    assert skipped == (SkippedSkill("empty", SKIP_NO_SKILL_MD),)


def test_a_document_with_only_section_headings_is_skipped(tmp_path: Path) -> None:
    """A document whose highest heading is ``##`` has no top-level heading."""
    root = tmp_path / "skills"
    _write_skill_md(root / "sections-only", "## Purpose\n\nText.\n")
    valid, skipped = discover_skills(root)
    assert valid == ()
    assert skipped == (SkippedSkill("sections-only", SKIP_NO_TOP_LEVEL_HEADING),)


def test_a_heading_inside_a_code_fence_is_not_a_top_level_heading(
    tmp_path: Path,
) -> None:
    """A fenced Markdown example must not stand in for the real heading."""
    root = tmp_path / "skills"
    _write_skill_md(root / "fenced-heading", "```markdown\n# Not a heading\n```\n")
    valid, skipped = discover_skills(root)
    assert valid == ()
    assert skipped == (SkippedSkill("fenced-heading", SKIP_NO_TOP_LEVEL_HEADING),)


def test_a_valid_stub_is_discovered(tmp_path: Path) -> None:
    """The negative cases above fail for the stated reason, not by construction."""
    root = tmp_path / "skills"
    _write_skill_md(root / "stub", "# Stub\n")
    valid, skipped = discover_skills(root)
    assert tuple(doc.name for doc in valid) == ("stub",)
    assert skipped == ()


# ---------------------------------------------------------------------------
# Front matter (Requirement 2 AC11, AC12)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("skill", SKILL_NAMES, indirect=True)
def test_front_matter_declares_the_required_fields(skill: SkillDoc) -> None:
    front_matter = parse_front_matter(skill.text)
    assert front_matter is not None, "front matter is missing or unterminated"
    for field in REQUIRED_FRONT_MATTER_FIELDS:
        value = front_matter.get(field)
        assert isinstance(value, str) and value.strip(), (
            "{0} must be a non-empty string".format(field)
        )


@pytest.mark.parametrize("skill", SKILL_NAMES, indirect=True)
def test_front_matter_name_matches_the_directory(skill: SkillDoc) -> None:
    front_matter = parse_front_matter(skill.text)
    assert front_matter is not None
    assert front_matter["name"] == skill.path.parent.name


@pytest.mark.parametrize("skill", SKILL_NAMES, indirect=True)
def test_description_states_capability_and_selection_conditions(
    skill: SkillDoc,
) -> None:
    front_matter = parse_front_matter(skill.text)
    assert front_matter is not None
    description = " ".join(str(front_matter["description"]).split())
    assert len(description) >= MIN_DESCRIPTION_LENGTH
    assert DESCRIPTION_SELECTION_PHRASE in description
    assert DESCRIPTION_REJECTION_PHRASE in description


@pytest.mark.parametrize("skill", SKILL_NAMES, indirect=True)
def test_description_names_the_sibling_skill_it_defers_to(
    skill: SkillDoc, skill_docs: Dict[str, SkillDoc]
) -> None:
    """The rejection half must point somewhere, not merely say "not here".

    Five Skills cover adjacent ground, so a description that declines a request
    without naming the Skill that handles it leaves the host agent nowhere to go.
    """
    front_matter = parse_front_matter(skill.text)
    assert front_matter is not None
    description = str(front_matter["description"])
    referenced = {
        other for other in skill_docs if other != skill.name and other in description
    }
    assert referenced, "no sibling Skill is named as the alternative"


# ---------------------------------------------------------------------------
# Body structure (Requirement 1 AC4, Requirement 2 AC13, Requirement 13 AC7)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("skill", SKILL_NAMES, indirect=True)
def test_exactly_one_top_level_heading(skill: SkillDoc) -> None:
    assert len(top_level_headings(skill.text)) == 1


@pytest.mark.parametrize("skill", SKILL_NAMES, indirect=True)
def test_required_sections_are_present_in_one_order(skill: SkillDoc) -> None:
    assert tuple(section_titles(skill.text)) == REQUIRED_SECTIONS


@pytest.mark.parametrize("skill", SKILL_NAMES, indirect=True)
@pytest.mark.parametrize("title", REQUIRED_SECTIONS)
def test_required_section_is_not_empty(skill: SkillDoc, title: str) -> None:
    assert section_body(skill.text, title).strip()


@pytest.mark.parametrize("skill", SKILL_NAMES, indirect=True)
def test_document_is_ascii_only(skill: SkillDoc) -> None:
    """Requirement 13 AC7, approximated: English prose needs no non-ASCII.

    The five documents are ASCII today, and the check is what keeps a
    Japanese-language edit out of the English original -- Requirement 13 AC8 asks
    for a ``.ja.md`` suffix instead.
    """
    offenders = sorted({character for character in skill.text if ord(character) > 127})
    assert offenders == [], "non-ASCII characters: {0}".format(offenders)


# ---------------------------------------------------------------------------
# Dependencies (Requirement 15 AC2)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("skill", SKILL_NAMES, indirect=True)
def test_dependencies_section_names_python(skill: SkillDoc) -> None:
    assert "Python" in flatten(section_body(skill.text, "Dependencies"))


@pytest.mark.parametrize("skill", sorted(EXTERNAL_TOOL_SKILLS), indirect=True)
def test_dependencies_declare_the_external_runtime_dependency(
    skill: SkillDoc,
) -> None:
    section = section_body(skill.text, "Dependencies")
    lowered = flatten(section).lower()
    assert "external runtime dependency" in lowered
    assert any(phrase in lowered for phrase in NOT_BUNDLED_PHRASES)
    for tool in EXTERNAL_TOOL_SKILLS[skill.name]:
        assert tool in section, "{0} is not named as a dependency".format(tool)


@pytest.mark.parametrize("skill", TOOL_FREE_SKILLS, indirect=True)
def test_dependencies_of_a_tool_free_skill_say_so(skill: SkillDoc) -> None:
    """A Skill that launches nothing must say that rather than stay silent.

    Silence reads as "the document forgot", and a reader then cannot tell whether
    cfn-lint has to be installed for this Skill to work.
    """
    assert "no external" in flatten(section_body(skill.text, "Dependencies")).lower()


# ---------------------------------------------------------------------------
# Exit codes (Requirement 16 AC8)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("skill", SKILL_NAMES, indirect=True)
def test_documented_exit_codes_are_defined_in_the_exit_code_table(
    skill: SkillDoc,
) -> None:
    documented = documented_exit_codes(skill.text)
    defined = frozenset(exitcodes.EXIT_CODES.values())
    assert documented <= defined, "codes outside exitcodes.py: {0}".format(
        sorted(documented - defined)
    )


@pytest.mark.parametrize("skill", SKILL_NAMES, indirect=True)
def test_universal_exit_codes_are_documented(skill: SkillDoc) -> None:
    missing = UNIVERSAL_EXIT_CODES - documented_exit_codes(skill.text)
    assert missing == frozenset(), "missing exit codes: {0}".format(sorted(missing))


@pytest.mark.parametrize("skill", sorted(EXTERNAL_TOOL_SKILLS), indirect=True)
def test_a_tool_launching_skill_documents_the_tool_failure_codes(
    skill: SkillDoc,
) -> None:
    documented = documented_exit_codes(skill.text)
    assert exitcodes.TOOL_UNAVAILABLE in documented
    assert exitcodes.TOOL_EXECUTION_FAILURE in documented


@pytest.mark.parametrize("skill", TOOL_FREE_SKILLS, indirect=True)
def test_a_tool_free_skill_documents_no_tool_execution_failure(
    skill: SkillDoc,
) -> None:
    """No external process means exit 6 cannot happen, so it is not advertised.

    Exit 5 stays reachable for both tool-free Skills: it also covers a PyYAML
    that is missing or too old.
    """
    assert exitcodes.TOOL_EXECUTION_FAILURE not in documented_exit_codes(skill.text)


# ---------------------------------------------------------------------------
# The stdout key contract (design.md [Correction] C-10)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("skill", SKILL_NAMES, indirect=True)
def test_document_states_that_stdout_carries_json_only(skill: SkillDoc) -> None:
    """Requirement 16 AC10, and the first clause of design.md C-10.

    The whole document is searched rather than ``## Output``. Four Skills state it
    there, but ``cloudformation-review``'s ``## Output`` documents the *agent's*
    output -- the findings file the reasoning produces -- while its script's
    stdout is the facts document the agent reads, and therefore belongs under
    ``## Input``. Both placements are honest, so the assertion is about the
    document rather than about a section.
    """
    flattened = flatten(skill.text)
    assert any(phrase in flattened for phrase in STDOUT_ONLY_PHRASES)
    assert "stderr" in flattened


@pytest.mark.parametrize("skill", SKILL_NAMES, indirect=True)
def test_declared_stdout_keys_match_the_contract(skill: SkillDoc) -> None:
    assert declared_stdout_keys(skill.text) == STDOUT_KEY_CONTRACT[skill.name]


def test_only_one_skill_declares_a_key_beside_the_envelope(
    skill_docs: Dict[str, SkillDoc]
) -> None:
    owners = {
        name
        for name, doc in skill_docs.items()
        if COUNTERS_KEY in declared_stdout_keys(doc.text)
    }
    assert owners == {COUNTERS_KEY_OWNER}


def test_the_counters_key_owner_cites_the_criterion_that_permits_it(
    skill_docs: Dict[str, SkillDoc]
) -> None:
    """The exception carries its justification where the key is documented."""
    section = flatten(section_body(skill_docs[COUNTERS_KEY_OWNER].text, "Output"))
    assert COUNTERS_KEY_JUSTIFICATION in section


@pytest.mark.parametrize("skill", SKILL_NAMES, indirect=True)
def test_no_skill_declares_a_stdout_key_outside_the_contract(
    skill: SkillDoc,
) -> None:
    permitted = frozenset(REPORT_KEYS) | {COUNTERS_KEY}
    extra = declared_stdout_keys(skill.text) - permitted
    assert extra == frozenset(), "keys outside the contract: {0}".format(sorted(extra))


def test_the_contract_covers_every_skill() -> None:
    """The contract map cannot silently stop covering a Skill."""
    assert tuple(sorted(STDOUT_KEY_CONTRACT)) == SKILL_NAMES


# ---------------------------------------------------------------------------
# Advertised entry points
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("skill", SKILL_NAMES, indirect=True)
def test_advertised_entry_points_exist_and_are_named(skill: SkillDoc) -> None:
    """Every script the document tells the user to run is really there.

    The prologue of each script and the ``parents[3]`` depth assumption are
    asserted in ``tests/unit/test_bootstrap.py``; this only pairs the documents
    with the files.
    """
    skill_dir = skill.path.parent
    for relative in ADVERTISED_ENTRY_POINTS[skill.name]:
        assert (skill_dir / relative).is_file(), "{0} is missing".format(relative)
        assert Path(relative).name in skill.text, (
            "{0} is not named in SKILL.md".format(relative)
        )


@pytest.mark.parametrize("skill", SKILL_NAMES, indirect=True)
def test_no_entry_point_goes_unadvertised(skill: SkillDoc) -> None:
    """A script nobody is told to run is either dead code or missing docs."""
    scripts_dir = skill.path.parent / "scripts"
    present = tuple(
        sorted(
            "scripts/{0}".format(path.name)
            for path in scripts_dir.glob("*.py")
            if not path.name.startswith("_")
        )
    )
    assert present == ADVERTISED_ENTRY_POINTS[skill.name]
