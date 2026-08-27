"""Malformed input at the entry-point boundary: every Skill fails safely.

steering/security.md treats every input Template as untrusted content and
requires that a malformed one never produces arbitrary code execution, a leaked
secret, disclosed environment information, or a read of an unrelated file.
Requirement 12 AC8 states the observable half of that: malformed YAML or JSON --
invalid syntax, a truncated file, binary content -- must come back as a
*structured error carrying the parse error type and its location*, with no
unhandled exception.

This module asserts that contract where a user meets it: at the process
boundary, for every entry point, over an enumerated list of concrete bad inputs.
Each case is run as a subprocess, because what is being asserted is a property
of the process rather than of a function -- the exit code, the two streams, and
the absence of a traceback are only observable there.

The matrix
----------

============================  ==========================  ====
Input                         ``error_class``             Exit
============================  ==========================  ====
malformed YAML                ``parse_failure``              4
malformed JSON                ``parse_failure``              4
truncated document            ``parse_failure``              4
invalid UTF-8 (binary)        ``parse_failure``              4
empty file                    ``parse_failure``              4
TAB in YAML indentation       ``parse_failure``              4
non-allowlisted YAML tag      ``parse_failure``              4
``!!python/object`` tag       ``parse_failure``              4
UTF-8 BOM before JSON         ``parse_failure``              4
2000-deep nesting             ``parse_failure``              4
parses, no ``Resources``      ``no_reviewable_template``     8
parses, empty ``Resources``   ``no_reviewable_template``     8
a directory as ``--target``   ``input_not_found``            3
``;`` in the file name        ``invalid_arguments``          2
============================  ==========================  ====

The first twelve rows are design.md's failure mode matrix for "YAML / JSON parse
failure", "binary / truncated 入力" and "``Resources`` mapping 無し", and they run
against all six entry points. The last two are the neighbouring rows -- a failure
detected before any file was read -- and they are here because a user reaches
them by the same mistake, not because this module owns argument validation.

Two entry points print no report at all on failure, by their own documented
contract (``extract_facts.py``, ``extract_policies.py``: a partially populated
facts file would be indistinguishable from a Template that genuinely has fewer
facts). For them the assertion is that stdout stays *empty*; for the other four
it is that stdout is a valid Review_Report whose ``errors[]`` describes the
failure. Both are the same claim about the boundary: stdout is either the answer
or nothing, never a fragment.

Where the parse position lives
------------------------------

``errors[]`` entries carry exactly :data:`iacreview.errors.STRUCTURED_ERROR_KEYS`,
and ``error_type`` / ``line`` / ``column`` are deliberately not among them: the
key set is a fixed output contract that consumers index without existence
checks, so widening it for one exception class would change the shape of every
other error. The three values are therefore rendered into the ``message``
(:data:`iacreview.template.PARSE_POSITION_FORMAT`), which is where a report
consumer and a human both read them. :func:`parsed_position` is the reader for
that, and it is what makes Requirement 3 AC6 checkable from outside the process.

Requirement 16 AC11 is asserted on every row
--------------------------------------------

No absolute host path may appear in stdout, so every case checks the workspace
root and the interpreter path against the whole stdout rather than against one
field. This is not decoration: ``TemplateParseError`` used to be built from the
absolute path :func:`iacreview.pathguard.resolve_within` returns, so a parse
failure put the host's directory layout into ``errors[].message`` for every
standalone Skill. ``tests/regression/test_sec_no_host_path_in_errors.py`` pins
that defect; this module keeps the whole matrix honest.

Existing coverage this module does not repeat
---------------------------------------------

``tests/unit/test_template.py`` / ``tests/unit/test_yamlcfn.py``
    The same inputs as unit cases: which exception, which ``error_type``, which
    line and column. This module asserts what a *process* does with them.
``tests/property/test_prop_template.py`` (Property 17, Property 21)
    Safe failure over arbitrary byte strings and "Template content is never
    executed", as universally quantified claims. The value here is the opposite:
    named, enumerated inputs and the exact exit code and report shape each one
    produces, which a quantified property deliberately does not pin down.
``tests/integration/test_tool_unavailable.py``
    The tool-failure matrix. No case here depends on a real external tool.
``tests/integration/test_skill_*.py``
    One malformed target per Skill, as part of that Skill's own contract. This
    module is the other axis: every input against every entry point.

Out of scope, deliberately
--------------------------

**Resource exhaustion.** A YAML alias bomb (``billion laughs``) is an
availability attack, not a safe-failure question: PyYAML expands aliases eagerly,
so a small file can exhaust memory, and no requirement in v0.1 sets an input
size or expansion budget to test against. Asserting anything here would need
memory and CPU limits that are not portable across the platforms this plugin
supports, and a test that merely *hopes* the process dies quickly would be worse
than none. An input size or alias-expansion budget is a requirement this plugin
does not yet have; it belongs in the Roadmap, not in an assertion invented here.

The deep-nesting case *is* included, because it is bounded work with a
deterministic outcome, and because it is the reason
:func:`iacreview.template.parse_template_text` catches broadly rather than
catching only the parser's declared error type: a ``RecursionError`` would
otherwise escape as a traceback.

Tools
-----

``PATH`` is replaced with the fakes in ``tests/fakebin/`` for every run, so no
case depends on whether cfn-lint or cfn-guard is installed on the machine. That
is not a shortcut around the tool-unavailable matrix: a *missing* tool would add
a second ``errors[]`` entry to some of these reports, and this module needs the
malformed input to be the only thing wrong in order to assert that it is
reported exactly once.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    FrozenSet,
    List,
    NamedTuple,
    Optional,
    Sequence,
    Tuple,
)

import pytest

from iacreview import exitcodes
from iacreview.report import REPORT_KEYS
from iacreview.template import EMPTY_DOCUMENT_ERROR_TYPE

#: Generous: every run here is a Python start-up plus a parse that fails. A run
#: that takes longer than this has hung, which is itself the failure to report.
TIMEOUT_S = 60

#: Directory the fixture Templates are copied from.
INVALID_FIXTURES = Path("tests") / "fixtures" / "invalid"

#: The one accepted input in this module; see
#: :func:`test_a_bom_before_a_yaml_template_is_accepted`.
BOM_YAML_FIXTURE = Path("tests") / "fixtures" / "valid" / "bom_prefixed.yaml"

#: Nesting depth of the generated deep-nesting case. Past CPython's default
#: recursion limit, so the decoder gives up, and small enough that the file is a
#: few kilobytes and the parse attempt is instant.
NESTING_DEPTH = 2000

#: A file name carrying a shell metacharacter (Requirement 12 AC11). The file is
#: never created: the name is rejected during argument validation, before
#: anything is opened, which is the property being asserted.
DANGEROUS_TARGET_NAME = "report.yaml; rm -rf /"

#: How :data:`iacreview.template.PARSE_POSITION_FORMAT` reads once rendered.
#: Matching it is how a subprocess-level test recovers the three values
#: Requirement 3 AC6 asks for, which are on the exception instance and not in the
#: StructuredError key set.
PARSE_POSITION = re.compile(
    r"(?P<error_type>[A-Za-z_][\w.]*) at line (?P<line>\d+), column (?P<column>\d+)"
)


class Position(NamedTuple):
    """The parse error type and location recovered from an ``errors[]`` message."""

    error_type: str
    line: int
    column: int


def parsed_position(message: str) -> Optional[Position]:
    """Recover the parse position from a StructuredError ``message``.

    Args:
        message: An ``errors[]`` entry's message.

    Returns:
        The :class:`Position` it names, or ``None`` when it names none -- which is
        itself an assertable outcome, since a ``no_reviewable_template`` entry
        must *not* carry one: the document parsed.
    """
    match = PARSE_POSITION.search(message)
    if match is None:
        return None
    return Position(
        error_type=match.group("error_type"),
        line=int(match.group("line")),
        column=int(match.group("column")),
    )


# ---------------------------------------------------------------------------
# The inputs
# ---------------------------------------------------------------------------


def copied(relative: Path) -> Callable[[Path, Path], str]:
    """Return a placer that copies a committed fixture into the workspace.

    The fixture keeps its own file name, so the report names a file a reader can
    look up, and it is copied rather than referenced in place because every
    ``--target`` must resolve inside the workspace root the entry point runs in.
    """

    def place(workspace: Path, plugin_root: Path) -> str:
        destination = workspace / relative.name
        destination.write_bytes((plugin_root / relative).read_bytes())
        return relative.name

    return place


def deeply_nested(workspace: Path, plugin_root: Path) -> str:
    """Write a JSON document nested past the interpreter's recursion limit."""
    name = "deeply_nested.json"
    (workspace / name).write_text(
        "[" * NESTING_DEPTH + "]" * NESTING_DEPTH, encoding="utf-8"
    )
    return name


class Case(NamedTuple):
    """One malformed input and the outcome every entry point must produce.

    Attributes:
        id: pytest parameter id, also the human name of the case.
        place: Writes the input into a workspace and returns the ``--target``
            value, always workspace-relative. Takes the workspace and the plugin
            root, so a case may either copy a committed fixture or generate its
            input.
        exit_code: The documented exit code from :mod:`iacreview.exitcodes`.
        error_class: The ``error_class`` the report must carry, for the entry
            points that print one.
        error_type: Expected ``error_type`` in the rendered position, or ``None``
            when the case carries no position at all. A trailing ``.`` means
            "starts with": the precise PyYAML class for a given syntax error is
            a detail of its scanner (``ScannerError`` versus ``ParserError``)
            rather than something this plugin defines, so only the namespace is
            pinned.
    """

    id: str
    place: Callable[[Path, Path], str]
    exit_code: int
    error_class: str
    error_type: Optional[str]


#: Every input that fails to parse. Ten shapes rather than the three
#: Requirement 12 AC8 names, because each reaches a different branch: a scanner
#: error, a parser error, a decoder error, a decode failure, the empty-document
#: guard, the tag allowlist, ``SafeLoader``'s tag refusal, and the broad
#: ``except`` that keeps a ``RecursionError`` from escaping.
PARSE_FAILURE_CASES: Tuple[Case, ...] = (
    Case(
        "malformed-yaml",
        copied(INVALID_FIXTURES / "malformed_syntax.yaml"),
        exitcodes.PARSE_FAILURE,
        "parse_failure",
        "yaml.",
    ),
    Case(
        "malformed-json",
        copied(INVALID_FIXTURES / "malformed_syntax.json"),
        exitcodes.PARSE_FAILURE,
        "parse_failure",
        "json.decoder.JSONDecodeError",
    ),
    Case(
        "truncated",
        copied(INVALID_FIXTURES / "truncated.yaml"),
        exitcodes.PARSE_FAILURE,
        "parse_failure",
        "yaml.",
    ),
    Case(
        "invalid-utf8",
        copied(INVALID_FIXTURES / "binary_content.yaml"),
        exitcodes.PARSE_FAILURE,
        "parse_failure",
        "UnicodeDecodeError",
    ),
    Case(
        "empty-file",
        copied(INVALID_FIXTURES / "empty_file.yaml"),
        exitcodes.PARSE_FAILURE,
        "parse_failure",
        EMPTY_DOCUMENT_ERROR_TYPE,
    ),
    Case(
        "yaml-tab",
        copied(INVALID_FIXTURES / "tab_indentation.yaml"),
        exitcodes.PARSE_FAILURE,
        "parse_failure",
        "yaml.scanner.ScannerError",
    ),
    Case(
        "unsupported-yaml-tag",
        copied(INVALID_FIXTURES / "unsupported_yaml_tag.yaml"),
        exitcodes.PARSE_FAILURE,
        "parse_failure",
        "yaml.",
    ),
    Case(
        "python-object-tag",
        copied(INVALID_FIXTURES / "python_object_tag.yaml"),
        exitcodes.PARSE_FAILURE,
        "parse_failure",
        "yaml.",
    ),
    Case(
        "bom-before-json",
        copied(INVALID_FIXTURES / "bom_prefixed.json"),
        exitcodes.PARSE_FAILURE,
        "parse_failure",
        "json.decoder.JSONDecodeError",
    ),
    Case(
        "deeply-nested",
        deeply_nested,
        exitcodes.PARSE_FAILURE,
        "parse_failure",
        "RecursionError",
    ),
)

#: Inputs that parse and are still not reviewable (Requirement 3 AC5). Separate
#: from the parse failures because the distinction is the point: exit 8 rather
#: than 4, and no parse position, because there was no parse error to locate.
NOT_REVIEWABLE_CASES: Tuple[Case, ...] = (
    Case(
        "no-resources",
        copied(INVALID_FIXTURES / "no_resources.yaml"),
        exitcodes.NO_REVIEWABLE_TEMPLATE,
        "no_reviewable_template",
        None,
    ),
    Case(
        "empty-resources",
        copied(INVALID_FIXTURES / "empty_resources.json"),
        exitcodes.NO_REVIEWABLE_TEMPLATE,
        "no_reviewable_template",
        None,
    ),
)

#: Every input a file can be, for the cases that assert the boundary contract
#: regardless of which failure it was.
FILE_CASES: Tuple[Case, ...] = PARSE_FAILURE_CASES + NOT_REVIEWABLE_CASES


def as_params(cases: Sequence[Case]) -> List[Any]:
    """Render ``cases`` as pytest parameters carrying their own ids."""
    return [pytest.param(case, id=case.id) for case in cases]


# ---------------------------------------------------------------------------
# The entry points
# ---------------------------------------------------------------------------


class EntryPoint(NamedTuple):
    """One Skill entry point and how it reports a failure.

    Attributes:
        id: pytest parameter id.
        script: Path to the script, relative to the plugin root.
        prints_report: Whether stdout carries a partial Review_Report when the
            input is unusable. ``False`` for the two facts-extraction scripts,
            which document an empty stdout on every non-zero exit.
        extra_stdout_keys: Keys this entry point adds beside the Review_Report
            envelope. Only ``cfn-guard-review`` has one -- the ``stats`` object
            Requirement 5 AC4 obliges it to return -- and it is named here rather
            than tolerated globally, so a second entry point growing a key of its
            own fails this module.
    """

    id: str
    script: Path
    prints_report: bool
    extra_stdout_keys: FrozenSet[str] = frozenset()


ENTRY_POINTS: Tuple[EntryPoint, ...] = (
    EntryPoint(
        "cfn-lint-review",
        Path("skills") / "cfn-lint-review" / "scripts" / "run_cfn_lint.py",
        True,
    ),
    EntryPoint(
        "cfn-guard-review",
        Path("skills") / "cfn-guard-review" / "scripts" / "run_cfn_guard.py",
        True,
        frozenset({"stats"}),
    ),
    EntryPoint(
        "iam-review-scan",
        Path("skills") / "iam-review" / "scripts" / "run_iam_scan.py",
        True,
    ),
    EntryPoint(
        "iac-review",
        Path("skills") / "iac-review" / "scripts" / "run_iac_review.py",
        True,
    ),
    EntryPoint(
        "cloudformation-review",
        Path("skills") / "cloudformation-review" / "scripts" / "extract_facts.py",
        False,
    ),
    EntryPoint(
        "iam-review-policies",
        Path("skills") / "iam-review" / "scripts" / "extract_policies.py",
        False,
    ),
)

#: The four entry points whose stdout is a Review_Report.
REPORTING_ENTRY_POINTS: Tuple[EntryPoint, ...] = tuple(
    entry for entry in ENTRY_POINTS if entry.prints_report
)

#: The two whose stdout stays empty on failure.
SILENT_ENTRY_POINTS: Tuple[EntryPoint, ...] = tuple(
    entry for entry in ENTRY_POINTS if not entry.prints_report
)

ALL_ENTRY_POINTS = [pytest.param(entry, id=entry.id) for entry in ENTRY_POINTS]
REPORTING = [pytest.param(entry, id=entry.id) for entry in REPORTING_ENTRY_POINTS]
SILENT = [pytest.param(entry, id=entry.id) for entry in SILENT_ENTRY_POINTS]


# ---------------------------------------------------------------------------
# Running an entry point
# ---------------------------------------------------------------------------


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """An empty workspace root, which is also the process working directory.

    Every entry point derives its containment root from the working directory,
    so a ``--target`` inside here is legal and one outside is exit 7. A fresh
    directory per test keeps one case's input out of another's directory scan --
    ``iac-review`` accepts a directory and would otherwise review the leftovers.
    """
    root = tmp_path / "workspace"
    root.mkdir()
    return root


@pytest.fixture
def fake_tool_path(fakebin_dir: Path) -> str:
    """``PATH`` resolving cfn-lint and cfn-guard to the fakes, and nothing else.

    Replaced rather than extended, so a real tool installed on the machine cannot
    answer instead and make the outcome depend on the host. The interpreter's own
    directory is included because both fakes are Python scripts with a
    ``#!/usr/bin/env python3`` shebang: without it, ``env`` cannot find an
    interpreter and the fake exits 127 before running a line.
    """
    entries = (
        fakebin_dir,
        fakebin_dir / "cfn-guard-configured",
        Path(sys.executable).parent,
    )
    return os.pathsep.join(str(entry) for entry in entries)


class Run(NamedTuple):
    """What one entry-point process produced.

    Attributes:
        exit_code: The process exit status.
        stdout: Raw stdout, asserted on as a whole for the host-path checks.
        stderr: Raw stderr, where a traceback would appear.
        report: Parsed stdout, or ``None`` when stdout was empty.
    """

    exit_code: int
    stdout: str
    stderr: str
    report: Optional[Dict[str, Any]]


def run_entry_point(
    entry: EntryPoint,
    target: str,
    *,
    plugin_root: Path,
    workspace: Path,
    path: str,
) -> Run:
    """Run ``entry`` against ``target`` from ``workspace`` and collect the result.

    Args:
        entry: The entry point to run.
        target: The ``--target`` value, workspace-relative.
        plugin_root: Where the scripts live. Passed absolutely, because the
            working directory is the workspace and not the plugin root -- which
            is also the arrangement a host agent uses.
        workspace: Working directory, and therefore the containment root.
        path: ``PATH`` for the child.

    Returns:
        A :class:`Run`. stdout is parsed as JSON only when it is non-empty; a
        non-empty stdout that does not parse fails the test here rather than
        somewhere further along, since "stdout is JSON or nothing"
        (Requirement 16 AC10) is part of what every case asserts.
    """
    env = dict(os.environ)
    env["PATH"] = path
    completed = subprocess.run(
        [sys.executable, str(plugin_root / entry.script), "--target", target],
        cwd=str(workspace),
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=TIMEOUT_S,
    )

    report: Optional[Dict[str, Any]] = None
    if completed.stdout:
        try:
            report = json.loads(completed.stdout)
        except ValueError as exc:  # pragma: no cover - only on a failing case
            raise AssertionError(
                "{0}: stdout is not valid JSON ({1}); stderr was:\n{2}".format(
                    entry.id, exc, completed.stderr
                )
            )
    return Run(completed.returncode, completed.stdout, completed.stderr, report)


def assert_no_traceback(run: Run, entry: EntryPoint) -> None:
    """Assert no unhandled exception escaped (Requirement 12 AC7, AC8).

    Two independent signals, because either alone can be fooled:
    :func:`iacreview.bootstrap.run_entry_point` prints the trace on stderr *and*
    returns :data:`iacreview.exitcodes.UNEXPECTED`, so a run showing neither
    handled its failure deliberately.
    """
    assert "Traceback" not in run.stderr, "{0}:\n{1}".format(entry.id, run.stderr)
    assert run.exit_code != exitcodes.UNEXPECTED, run.stderr


def assert_no_host_path(run: Run, workspace: Path) -> None:
    """Assert stdout carries no absolute host path (Requirement 16 AC11).

    The whole of stdout is searched rather than one field: the guarantee is about
    the bytes a consumer receives, and a leak that moved from ``message`` to
    ``remediation`` would be no better.
    """
    for absolute in (str(workspace), str(workspace.parent), sys.executable):
        assert absolute not in run.stdout, run.stdout


def only_error(run: Run) -> Dict[str, Any]:
    """Return the single ``errors[]`` entry of a report, failing if there is not one.

    Exactly one, because exactly one thing was wrong: the input. A second entry
    would mean something else failed too -- an unavailable tool, say -- and the
    case would no longer be about malformed input.
    """
    assert run.report is not None
    errors = run.report["errors"]
    assert len(errors) == 1, errors
    return errors[0]


# ---------------------------------------------------------------------------
# (a) + (b): a documented exit code, and no traceback, for every entry point
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case", as_params(FILE_CASES))
@pytest.mark.parametrize("entry", ALL_ENTRY_POINTS)
def test_every_entry_point_fails_with_a_documented_exit_code(
    entry: EntryPoint,
    case: Case,
    plugin_root: Path,
    workspace: Path,
    fake_tool_path: str,
) -> None:
    """The whole boundary contract, for twelve inputs against six entry points.

    Four claims per cell:

    (a) no unhandled exception -- no ``Traceback`` on stderr, and not the
        catch-all exit 1;
    (b) the exit code design.md's failure mode matrix assigns to the input: 4 for
        an unparsable document, 8 for one that parses without ``Resources``;
    (c) stdout is a valid Review_Report or empty, per the entry point's own
        documented contract -- never a fragment;
    (d) no absolute host path in stdout (Requirement 16 AC11).

    (c) and (d) are asserted here rather than in cases of their own so that they
    cannot fall behind the matrix: an input added to :data:`FILE_CASES` or an
    entry point added to :data:`ENTRY_POINTS` is checked for both automatically.
    """
    target = case.place(workspace, plugin_root)

    run = run_entry_point(
        entry,
        target,
        plugin_root=plugin_root,
        workspace=workspace,
        path=fake_tool_path,
    )

    assert_no_traceback(run, entry)
    assert run.exit_code == case.exit_code, run.stderr
    if entry.prints_report:
        assert run.report is not None, "expected a partial report on stdout"
        assert set(run.report) == set(REPORT_KEYS) | entry.extra_stdout_keys
        assert run.report["findings"] == []
    else:
        assert run.stdout == "", run.stdout
    assert_no_host_path(run, workspace)


# ---------------------------------------------------------------------------
# (c): errors[] carries the error class and the parse position
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case", as_params(PARSE_FAILURE_CASES))
@pytest.mark.parametrize("entry", REPORTING)
def test_a_parse_failure_reports_its_error_class_type_line_and_column(
    entry: EntryPoint,
    case: Case,
    plugin_root: Path,
    workspace: Path,
    fake_tool_path: str,
) -> None:
    """Requirement 12 AC8 and Requirement 3 AC6, read off stdout.

    The structured error is one entry, classed ``parse_failure``, and its message
    names the parse error type together with the line and the column. The type is
    matched by namespace for the YAML cases and exactly for the rest; see
    :attr:`Case.error_type`.

    The message also names the file, as the report names it: workspace-relative,
    which is what makes the same input produce the same bytes on another machine.
    """
    target = case.place(workspace, plugin_root)

    run = run_entry_point(
        entry,
        target,
        plugin_root=plugin_root,
        workspace=workspace,
        path=fake_tool_path,
    )

    error = only_error(run)
    assert error["error_class"] == case.error_class
    assert error["remediation"], "a parse failure must say what to do next"

    message = str(error["message"])
    assert target in message
    position = parsed_position(message)
    assert position is not None, message
    expected_type = case.error_type
    assert expected_type is not None, "a parse failure case must expect a type"
    if expected_type.endswith("."):
        assert position.error_type.startswith(expected_type), message
    else:
        assert position.error_type == expected_type, message
    assert position.line >= 1 and position.column >= 1, message


@pytest.mark.parametrize("case", as_params(NOT_REVIEWABLE_CASES))
@pytest.mark.parametrize("entry", REPORTING)
def test_a_file_that_parses_but_is_not_reviewable_names_the_file_and_no_position(
    entry: EntryPoint,
    case: Case,
    plugin_root: Path,
    workspace: Path,
    fake_tool_path: str,
) -> None:
    """Requirement 3 AC5: the report says which file was not reviewable.

    And it carries no parse position, which is the observable difference from the
    previous case: nothing failed to parse, so there is no location to point at.
    Reporting one would send a user looking for a syntax error that is not there.
    """
    target = case.place(workspace, plugin_root)

    run = run_entry_point(
        entry,
        target,
        plugin_root=plugin_root,
        workspace=workspace,
        path=fake_tool_path,
    )

    error = only_error(run)
    assert error["error_class"] == "no_reviewable_template"
    message = str(error["message"])
    assert target in message
    assert parsed_position(message) is None, message


# ---------------------------------------------------------------------------
# The neighbouring rows: a directory, and a hostile file name
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("entry", ALL_ENTRY_POINTS)
def test_a_directory_where_a_template_is_expected_is_input_not_found(
    entry: EntryPoint,
    plugin_root: Path,
    workspace: Path,
    fake_tool_path: str,
) -> None:
    """A directory is read as unreadable input, not as a parse failure.

    Exit 3 with an empty stdout, which is the row design.md's matrix assigns to
    "入力ファイルが読めない": the file was never a document, so there is nothing
    for a report to say about its contents.

    ``iac-review`` is the exception and is excluded from the assertion below: a
    directory is a legal target for it, and an empty one means nothing reviewable
    was found -- exit 8 with a report that says so.
    """
    (workspace / "templates").mkdir()

    run = run_entry_point(
        entry,
        "templates",
        plugin_root=plugin_root,
        workspace=workspace,
        path=fake_tool_path,
    )

    assert_no_traceback(run, entry)
    if entry.id == "iac-review":
        assert run.exit_code == exitcodes.NO_REVIEWABLE_TEMPLATE
        assert only_error(run)["error_class"] == "no_reviewable_template"
    else:
        assert run.exit_code == exitcodes.INPUT_NOT_FOUND, run.stderr
        assert run.stdout == "", run.stdout
    assert_no_host_path(run, workspace)


@pytest.mark.parametrize("entry", ALL_ENTRY_POINTS)
def test_a_target_name_holding_a_shell_metacharacter_is_rejected(
    entry: EntryPoint,
    plugin_root: Path,
    workspace: Path,
    fake_tool_path: str,
) -> None:
    """Requirement 9 AC4 at the boundary: rejected, and rejected first.

    Exit 2 with an empty stdout for every entry point, and the file is never
    created -- the name is refused during argument validation, before anything is
    opened, so no ``rm`` fragment of it can reach a log, a Finding, or a
    subprocess argument list.

    ``tests/regression/test_sec_shell_metacharacters.py`` (Task 24.7) owns the
    detail of *which* characters and the ``UnsafeArgumentError`` itself. What is
    asserted here is only that every entry point stops at the boundary.
    """
    run = run_entry_point(
        entry,
        DANGEROUS_TARGET_NAME,
        plugin_root=plugin_root,
        workspace=workspace,
        path=fake_tool_path,
    )

    assert_no_traceback(run, entry)
    assert run.exit_code == exitcodes.INVALID_ARGUMENTS, run.stderr
    assert run.stdout == "", run.stdout
    assert list(workspace.iterdir()) == [], "nothing may be created or removed"


# ---------------------------------------------------------------------------
# The counterpart: a malformed-looking input that is in fact fine
# ---------------------------------------------------------------------------


def test_a_bom_before_a_yaml_template_is_accepted(
    plugin_root: Path, workspace: Path, fake_tool_path: str
) -> None:
    """The same byte prefix that fails as JSON succeeds as YAML.

    Worth pinning as its own case because it is the boundary of this module: the
    matrix above must fail on bad input without failing on merely *unusual*
    input, and a byte-order mark is what an editor or a PowerShell redirection
    adds without being asked. PyYAML treats a leading BOM as encoding metadata,
    so the Template reviews normally; ``json.loads`` refuses it outright, which
    is the ``bom-before-json`` row.

    That asymmetry is the parsers', not the plugin's. Accepting a BOM before a
    JSON Template would mean decoding as ``utf-8-sig``, which no requirement asks
    for; it is recorded here as a candidate rather than assumed.

    Run through ``extract_policies.py`` because it needs no external tool, so
    what the case proves is about the input and nothing else.
    """
    target = copied(BOM_YAML_FIXTURE)(workspace, plugin_root)

    run = run_entry_point(
        EntryPoint(
            "iam-review-policies",
            Path("skills") / "iam-review" / "scripts" / "extract_policies.py",
            False,
        ),
        target,
        plugin_root=plugin_root,
        workspace=workspace,
        path=fake_tool_path,
    )

    assert run.exit_code == exitcodes.OK, run.stderr
    assert run.report is not None
    assert run.report["policy_sites"] == []
