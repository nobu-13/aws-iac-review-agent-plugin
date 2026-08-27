"""Regression: a path that escapes the workspace root is refused.

Requirement guarded
-------------------

Requirement 9 AC5: a resolved path must stay inside the workspace root, a path
containing ``..`` that resolves outside it must be rejected, and the error must
say that the path was the problem. Requirement 12 AC11 names ``path traversal
input`` as one of the six security cases the regression suite must carry; this
file is that case.

Why these examples are pinned
-----------------------------

No defect is being reproduced here. What is pinned is the *shape* of the control,
because the two cheap implementations of "reject traversal" both look correct and
both are wrong, and either could be reintroduced by someone simplifying
:mod:`iacreview.pathguard`:

``".." in candidate``
    Misses :func:`test_a_symlink_pointing_outside_the_root_is_refused`, whose
    candidate contains no ``..`` at all.
``str(resolved).startswith(str(root))``
    Accepts :func:`test_a_sibling_root_sharing_the_prefix_is_refused`, where
    ``.../workspace-evil`` starts with ``.../workspace``.

Both of those are here next to the plain ``../../etc/passwd`` a reader expects,
and so is the *accepted* case
(:func:`test_a_dot_dot_that_stays_inside_the_root_is_accepted`) -- without it,
"reject anything containing ``..``" would pass every other case in this file
while making a legitimate relative path unreviewable.

:func:`iacreview.pathguard.resolve_within` compares path *components* with
:meth:`pathlib.Path.relative_to` after normalizing both sides, which is what
makes all four outcomes fall out of one rule instead of four checks.

Cross-references, not repeated here
-----------------------------------

``tests/property/test_prop_pathguard.py`` (Property 18)
    The universally quantified form: for any candidate and any root, resolution
    either raises ``PathContainmentError`` or returns a path inside the resolved
    root, symlinks included, checked against an independent oracle. That is the
    claim; the cases below are the named examples of it a reader can point at.
``tests/regression/test_sec_symlink_loop.py``
    The counterexample Property 18 actually found -- a symlink *cycle*, which is
    a different failure from a symlink that escapes. Its last case already pins
    that a cycle elsewhere in the workspace does not mask a containment
    violation, so that combination is not repeated here.
``tests/unit/test_pathguard.py``
    The full unit matrix for ``resolve_within`` and ``resolve_plugin_owned``,
    including the wording of the errors.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from iacreview import exitcodes, pathguard
from iacreview.errors import PathContainmentError

from skillrun import IAM_SKILL, make_workspace, run_skill

#: The traversal string every discussion of this control starts with. Six levels,
#: which is enough to leave ``tmp_path`` on any platform the suite runs on -- a
#: shallower one could resolve to a path that is still inside the root and would
#: then test nothing.
CLASSIC_TRAVERSAL = "../../../../../../etc/passwd"


def test_the_classic_traversal_string_is_refused(tmp_path: Path) -> None:
    """``../../etc/passwd``, the case Requirement 9 AC5 describes literally."""
    workspace = make_workspace(tmp_path)

    with pytest.raises(PathContainmentError) as caught:
        pathguard.resolve_within(CLASSIC_TRAVERSAL, workspace)

    assert caught.value.error_class == "path_violation"
    assert caught.value.exit_code == exitcodes.PATH_VIOLATION


def test_a_single_step_out_of_the_root_is_refused(tmp_path: Path) -> None:
    """One ``..`` is enough, and the target exists -- so this is not "not found".

    The file is real and readable. Containment is checked before existence in
    ``resolve_within``, which is what keeps the two apart: a path outside the root
    is a violation whether or not anything is there, and answering "no such file"
    for a file that does exist would tell a caller which paths exist.
    """
    workspace = make_workspace(tmp_path)
    (tmp_path / "secret.yaml").write_text("Resources: {}\n", encoding="utf-8")

    with pytest.raises(PathContainmentError):
        pathguard.resolve_within("../secret.yaml", workspace)


def test_a_symlink_pointing_outside_the_root_is_refused(tmp_path: Path) -> None:
    """The candidate contains no ``..``: a substring check would let this through.

    Symlinks are resolved before the comparison, so a link *inside* the workspace
    pointing outside it is an escape and is reported as one. This is the case that
    makes component comparison necessary rather than merely tidy.
    """
    workspace = make_workspace(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.yaml").write_text("Resources: {}\n", encoding="utf-8")
    (workspace / "innocent.yaml").symlink_to(outside / "secret.yaml")

    with pytest.raises(PathContainmentError):
        pathguard.resolve_within("innocent.yaml", workspace)


def test_a_sibling_root_sharing_the_prefix_is_refused(tmp_path: Path) -> None:
    """``workspace-evil`` is not inside ``workspace``, though its path starts with it.

    An absolute candidate, so no normalization step removes anything: the only
    thing between this path and a read is the containment comparison itself.
    """
    workspace = make_workspace(tmp_path)
    sibling = tmp_path / "workspace-evil"
    sibling.mkdir()
    (sibling / "app.yaml").write_text("Resources: {}\n", encoding="utf-8")

    with pytest.raises(PathContainmentError):
        pathguard.resolve_within(str(sibling / "app.yaml"), workspace)


def test_a_dot_dot_that_stays_inside_the_root_is_accepted(tmp_path: Path) -> None:
    """The counter-case, present so the control cannot degrade into a blocklist.

    ``sub/../app.yaml`` contains ``..`` and resolves inside the root, so it names
    a reviewable Template. A rule that rejected every ``..`` would pass every
    other case in this file and break this one.
    """
    workspace = make_workspace(tmp_path)
    (workspace / "sub").mkdir()

    resolved = pathguard.resolve_within("sub/../app.yaml", workspace)

    assert resolved == (workspace / "app.yaml").resolve()


def test_a_traversing_target_exits_seven_with_an_empty_stdout(tmp_path: Path) -> None:
    """The contract as a user meets it, at the process boundary.

    Three claims, and the third is the one worth stating: stdout is *empty*. The
    failure is detected in the entry point's ``validate`` slot, before any file is
    read, so there is no partial report to print and printing an empty one would
    claim a review happened (design.md, Failure mode matrix). The diagnostic goes
    to stderr, which is where the refused absolute path may legitimately appear.
    """
    workspace = make_workspace(tmp_path)

    run = run_skill(IAM_SKILL, ["--target", CLASSIC_TRAVERSAL], cwd=workspace)

    run.assert_no_traceback()
    assert run.exit_code == exitcodes.PATH_VIOLATION
    assert run.stdout == ""
    assert "path_violation" in run.stderr
