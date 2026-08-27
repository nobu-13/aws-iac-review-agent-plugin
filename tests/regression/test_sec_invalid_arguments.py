"""Regression: an unusable argument vector is refused before any work starts.

Requirement guarded
-------------------

Requirement 16 AC7 (argv is validated before anything else runs), AC8 (exit 2 for
an invalid invocation) and AC10 (stdout carries JSON and nothing else).
Requirement 12 AC11 names ``invalid command arguments`` as one of the six security
cases the regression suite must carry; this file is that case.

Why an argument error is a security case at all
-----------------------------------------------

Because of what the *wrong* behaviour would be. Three of the cases below are
mistakes whose plausible mishandling is silent rather than loud:

:func:`test_an_empty_target_is_refused`
    An empty or blank ``--target`` resolves to the containment root itself. Left
    unchecked, "no path given" silently becomes "review the entire workspace" --
    the plugin walking a tree the user never named. :mod:`iacreview.pathguard`
    rejects it explicitly for that reason, and this pins it.
:func:`test_an_abbreviated_flag_is_not_guessed`
    ``argparse`` matches unique option prefixes by default, so ``--rules`` would
    silently mean ``--rules-dir`` today and change meaning the day a second option
    shares that prefix. ``allow_abbrev=False`` in
    :func:`iacreview.bootstrap.new_parser` turns that into exit 2. A flag whose
    meaning depends on which other flags exist is not a flag anyone can review.
:func:`test_help_goes_to_stderr_and_leaves_stdout_empty`
    ``argparse`` prints ``--help`` on stdout. Here stdout is a machine-readable
    channel, so a consumer piping it into a JSON parser would receive usage text.
    :class:`iacreview.bootstrap.EntryPointParser` overrides the one hook argparse
    funnels all output through; that override is small, easy to lose, and its loss
    would not fail any test that only checks exit codes.

The ordinary cases -- an unknown flag, a missing required option -- are here too,
because Requirement 12 AC11 asks for them by name and because they are what fixes
the exit code at 2 rather than at 1.

Cross-references, not repeated here
-----------------------------------

``tests/property/test_prop_security.py`` (Property 20)
    The quantified claim, over all six entry points: for *any* invalid argument
    vector the exit code is a documented non-zero value, and no subprocess is
    spawned and no file is created or modified -- observed with ``subprocess.run``
    and the filesystem both under watch, not inferred. That is why the cases here
    do not each re-observe the absence of side effects; they pin the named
    examples and the exact exit code.
``tests/unit/test_bootstrap.py``
    ``argparse``'s exits mapped onto the exit code table, and the parser's
    stream discipline, as unit cases.
``tests/regression/test_sec_shell_metacharacters.py``
    The other argument value that yields exit 2, and the one case here whose
    absent side effect *is* asserted directly, because a shell would have left
    evidence.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from iacreview import exitcodes

from skillrun import IAM_SKILL, make_workspace, run_skill


def test_an_unknown_flag_is_refused(tmp_path: Path) -> None:
    """The plainest invalid invocation: exit 2, usage on stderr, stdout empty."""
    workspace = make_workspace(tmp_path)

    run = run_skill(
        IAM_SKILL, ["--target", "app.yaml", "--no-such-flag"], cwd=workspace
    )

    run.assert_no_traceback()
    assert run.exit_code == exitcodes.INVALID_ARGUMENTS
    assert run.stdout == ""
    assert "usage:" in run.stderr


def test_a_missing_required_target_is_refused(tmp_path: Path) -> None:
    """No ``--target`` at all. Exit 2 rather than a review of the whole directory."""
    workspace = make_workspace(tmp_path)

    run = run_skill(IAM_SKILL, [], cwd=workspace)

    run.assert_no_traceback()
    assert run.exit_code == exitcodes.INVALID_ARGUMENTS
    assert run.stdout == ""
    assert "--target" in run.stderr


@pytest.mark.parametrize("value", ["", "   ", "\t"], ids=["empty", "spaces", "tab"])
def test_an_empty_target_is_refused(value: str, tmp_path: Path) -> None:
    """A blank ``--target`` must not silently mean "the workspace root".

    All three spellings are blank after ``strip()``, which is the test
    :mod:`iacreview.pathguard` applies. Parametrized because the interesting
    failure is not the empty string -- which is easy to remember -- but the
    whitespace that looks like a value and resolves to the same place.
    """
    workspace = make_workspace(tmp_path)

    run = run_skill(IAM_SKILL, ["--target", value], cwd=workspace)

    run.assert_no_traceback()
    assert run.exit_code == exitcodes.INVALID_ARGUMENTS
    assert run.stdout == ""
    assert "invalid_arguments" in run.stderr


def test_an_abbreviated_flag_is_not_guessed(tmp_path: Path) -> None:
    """``--targ`` is an unknown flag, not a shorter way to write ``--target``.

    ``argparse`` would accept it by default. Pinned as a rejection because the
    default behaviour makes a script's meaning depend on which *other* options
    happen to exist, which is not a property anyone reviewing a command line can
    check.
    """
    workspace = make_workspace(tmp_path)

    run = run_skill(IAM_SKILL, ["--targ", "app.yaml"], cwd=workspace)

    run.assert_no_traceback()
    assert run.exit_code == exitcodes.INVALID_ARGUMENTS
    assert run.stdout == ""


def test_help_goes_to_stderr_and_leaves_stdout_empty(tmp_path: Path) -> None:
    """``--help`` is a *valid* invocation, and still must not write to stdout.

    Exit 0 with an empty stdout and the usage text on stderr. Requirement 16 AC10
    makes stdout the machine-readable channel unconditionally, so help text there
    would corrupt the output of a caller that pipes it -- the one failure mode a
    human running the command by hand would never notice.
    """
    workspace = make_workspace(tmp_path)

    run = run_skill(IAM_SKILL, ["--help"], cwd=workspace)

    run.assert_no_traceback()
    assert run.exit_code == exitcodes.OK
    assert run.stdout == ""
    assert "--target" in run.stderr
