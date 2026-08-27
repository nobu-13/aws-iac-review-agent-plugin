"""Regression: a filename carrying a shell metacharacter is refused, not run.

Requirement guarded
-------------------

Requirement 9 AC4: commands for cfn-lint, cfn-guard and ``cdk synth`` are built
as argv arrays with no shell interpolation, *and* execution is refused with an
error when an input value contains one of ``;``, ``|``, ``&``, ``$``, a backtick,
``>`` or ``<``. Requirement 12 AC11 names ``filenames containing shell
metacharacters`` as one of the six security cases the regression suite must carry.

This file was owed. Task 23.9 looked for it, found it absent, and cross-referenced
``tests/unit/test_pathguard.py`` and ``tests/unit/test_proc.py`` instead; this is
the case that discharge was deferred to.

What is actually being defended
-------------------------------

The primary control is not the character check. It is ``shell=False`` plus an
argv array in :mod:`iacreview.proc`, and under that control no shell ever exists
to interpret a ``;``, so a file genuinely named ``report.yaml; rm -rf /`` would be
analyzed rather than executed. :func:`iacreview.pathguard.assert_no_shell_metacharacters`
is defense in depth: it keeps a hostile filename out of logs, Findings and report
messages, and it fails early rather than at the moment a subprocess is spawned.

Two consequences of that, both pinned below, because both are the kind of thing a
later change could quietly invert:

*Rejected, never sanitized.* Rewriting a path string to strip a ``;`` would
silently redirect the read to a *different file* -- a worse failure than an
explicit error, and one nobody would notice (design.md, "shell metacharacter
拒否の位置づけ"). :func:`test_a_metacharacter_name_is_refused_not_rewritten`
asserts the error rather than a repaired path.

*The set is exactly seven characters.* A quote, a space or an apostrophe is
perfectly ordinary in a filename and is not a shell escape under ``shell=False``.
:func:`test_a_filename_with_quotes_and_spaces_is_accepted` is here so that the
check cannot drift into "reject anything unusual", which would make normal
workspaces unreviewable in the name of security.

Cross-references, not repeated here
-----------------------------------

``tests/property/test_prop_pathguard.py`` (Property 19)
    The quantified form of both halves: every string containing one of the seven
    raises, every string containing none does not, and every argv the plugin
    builds reaches ``subprocess`` as a list with ``shell=False``. That property
    also greps the shipped source for a second route to a shell.
``tests/property/test_prop_security.py`` (Property 20)
    For any invalid argv, no subprocess is spawned and no file is created or
    modified, observed rather than inferred.
``tests/unit/test_pathguard.py``
    The unit matrix, including the deliberate asymmetry that plugin-owned paths
    are *not* metacharacter-checked (Requirement 15 AC3): the plugin's own install
    directory may legitimately contain one of these characters, and that value
    does not come from user input.
``tests/integration/test_malformed_input.py``
    Runs one metacharacter target against all six entry points as the neighbouring
    row of its matrix. This file is the security case in its own right: the
    per-character set, the absent side effect, and the accepted counter-case.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from iacreview import exitcodes, pathguard
from iacreview.errors import UnsafeArgumentError

from skillrun import IAM_SKILL, make_workspace, run_skill

#: The name from the task description and from design.md. Kept verbatim because
#: it is what a reader of either document will search for.
DANGEROUS_NAME = "report.yaml; rm -rf /"

#: A filename whose suffix would run a command if any shell saw it. The command
#: is a harmless ``touch`` so that its *absence* is what the test observes; a
#: destructive payload could not be asserted about safely.
INJECTION_TARGET = "app.yaml; touch pwned"

#: The file :data:`INJECTION_TARGET` would create if a shell interpreted it.
INJECTION_WITNESS = "pwned"


def test_the_documented_dangerous_filename_is_refused(tmp_path: Path) -> None:
    """``report.yaml; rm -rf /`` -> ``UnsafeArgumentError`` and exit 2.

    The error class is ``invalid_arguments`` rather than one of its own: the
    argument was unusable, which is the same answer an unknown flag gets, and
    Requirement 16 AC8's table has one code for that.
    """
    workspace = make_workspace(tmp_path)

    with pytest.raises(UnsafeArgumentError) as caught:
        pathguard.resolve_within(DANGEROUS_NAME, workspace)

    assert caught.value.error_class == "invalid_arguments"
    assert caught.value.exit_code == exitcodes.INVALID_ARGUMENTS


@pytest.mark.parametrize("char", sorted(pathguard.SHELL_METACHARACTERS))
def test_each_metacharacter_of_the_set_is_refused_on_its_own(
    char: str, tmp_path: Path
) -> None:
    """All seven characters Requirement 9 AC4 enumerates, one per case.

    Parametrized over :data:`iacreview.pathguard.SHELL_METACHARACTERS` rather than
    over a literal list, so a character removed from the set fails this test
    instead of silently reducing what is checked.
    """
    workspace = make_workspace(tmp_path)

    with pytest.raises(UnsafeArgumentError) as caught:
        pathguard.resolve_within("app{0}.yaml".format(char), workspace)

    assert char in caught.value.message
    assert caught.value.remediation


def test_a_metacharacter_name_is_refused_not_rewritten(tmp_path: Path) -> None:
    """A file that really is named with a ``;`` is refused rather than repaired.

    The file exists and is a valid Template, so nothing here is a missing-file
    error: the two candidate wrong behaviours are silently reading it (dropping
    the defense-in-depth layer) and silently reading ``app.yaml`` instead (having
    stripped the suffix). The error class distinguishes all three outcomes --
    ``invalid_arguments`` rather than ``input_not_found`` or a returned path.
    """
    workspace = make_workspace(tmp_path)
    hostile = workspace / "app.yaml; rm -rf tmp"
    hostile.write_text("Resources:\n  A:\n    Type: AWS::S3::Bucket\n", encoding="utf-8")

    with pytest.raises(UnsafeArgumentError):
        pathguard.resolve_within(hostile.name, workspace)

    # Refusal is not deletion either: the plugin is read-only (Requirement 9 AC3).
    assert hostile.is_file()


def test_a_filename_with_quotes_and_spaces_is_accepted(tmp_path: Path) -> None:
    """The counter-case: the set is seven characters, not "anything unusual".

    Spaces, apostrophes and double quotes are ordinary in filenames and carry no
    meaning under ``shell=False``. Rejecting them would be a security theatre
    change that makes real workspaces unreviewable, so it is pinned as a failure.
    """
    workspace = make_workspace(tmp_path)
    awkward = workspace / "my app's \"main\" template.yaml"
    awkward.write_text("Resources:\n  A:\n    Type: AWS::S3::Bucket\n", encoding="utf-8")

    assert pathguard.resolve_within(awkward.name, workspace) == awkward.resolve()


def test_an_injection_target_exits_two_and_runs_no_command(tmp_path: Path) -> None:
    """The regression proper: the injected command did not happen.

    ``--target 'app.yaml; touch pwned'`` is the shape of the attack. Three claims,
    and the second is the one that would catch a real regression: the witness file
    does not exist, so no shell evaluated the argument -- asserted about the
    filesystem rather than inferred from the exit code, because a future entry
    point could exit 2 *after* having spawned something.

    stdout is empty because the rejection happens in the ``validate`` slot, before
    any Template is read, so there is no partial report to describe.
    """
    workspace = make_workspace(tmp_path)

    run = run_skill(IAM_SKILL, ["--target", INJECTION_TARGET], cwd=workspace)

    run.assert_no_traceback()
    assert not (workspace / INJECTION_WITNESS).exists()
    assert run.exit_code == exitcodes.INVALID_ARGUMENTS
    assert run.stdout == ""
    assert "invalid_arguments" in run.stderr
