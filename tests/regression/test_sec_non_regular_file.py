"""Regression: a non-regular file, or one swapped after the check, is refused.

Requirements guarded
--------------------

Requirement 17 AC6: if the file opened for reading is not a regular file (a
FIFO, a device, or a directory), the plugin refuses to read it and reports a
distinct, documented failure. Requirement 17 AC5: the containment check and the
read happen against the same file object, so a symlink or path substituted
between the check and the read cannot cause a file outside the workspace root to
be read (time-of-check to time-of-use safety). Requirement 17 AC9: the failure
is reported through the structured-error mechanism using a documented error
class, and the message names no absolute host path.

Why these examples are pinned
-----------------------------

The read used to be ``path.read_bytes()`` on a path that
:func:`iacreview.pathguard.resolve_within` had validated *earlier*, as a separate
operation. That left two gaps a hostile input could drive through, and both are
easy to reintroduce by anyone who "simplifies" the reader back to a plain path
read:

*A non-regular file.* A directory or a FIFO passed as the template used to fail
    (or hang) incidentally, not by a check. :func:`test_a_directory_target_is_refused`
    and :func:`test_a_fifo_target_is_refused` pin that the refusal is explicit
    and reports ``path_violation``.

*The check/read window.* The fd-based reader opens the path once with
    ``O_NOFOLLOW`` and then proves, via ``os.fstat`` on that one descriptor,
    that it holds a regular file whose inode still matches the resolved path.
    The identity comparison is the control that closes the window; its unit-level
    rejection of a mismatch is pinned in ``tests/unit/test_template.py``, and the
    non-regular-file refusal is pinned here at the process boundary a user meets.

Cross-references, not repeated here
-----------------------------------

``tests/unit/test_template.py``
    The fd-path unit matrix: a normal regular file still loads, the size check
    runs on the fstat before any byte is read, a FIFO is refused, and an inode
    mismatch between the fstat and the resolved-path stat is refused.
``tests/regression/test_sec_path_traversal.py``
    The containment (path-escape) cases. This file is the file-*type* and
    file-*identity* companion to those.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from iacreview import exitcodes
from iacreview.errors import PathContainmentError

from skillrun import IAM_SKILL, make_workspace, run_skill


def test_a_directory_target_is_refused(tmp_path: Path) -> None:
    """A directory inside the workspace is not a regular file (AC6).

    It resolves and is contained, so containment alone lets it through; the
    ``S_ISREG`` check on the opened descriptor is what refuses it, as a
    ``path_violation``. The message names no absolute host path (AC9).
    """
    from iacreview import template

    workspace = make_workspace(tmp_path)
    a_directory = workspace / "subdir"
    a_directory.mkdir()

    with pytest.raises(PathContainmentError) as caught:
        template.load_template(a_directory)

    assert caught.value.error_class == "path_violation"
    assert str(a_directory) not in caught.value.message


def test_a_fifo_target_is_refused(tmp_path: Path) -> None:
    """A FIFO passed as the template is refused, and does not hang the read (AC6).

    ``O_NONBLOCK`` on the open keeps a writer-less FIFO from blocking, so the
    refusal is prompt rather than a hang, and the ``S_ISREG`` check reports it as
    a ``path_violation``.
    """
    if not hasattr(os, "mkfifo"):
        pytest.skip("os.mkfifo is not available on this platform")

    from iacreview import template

    workspace = make_workspace(tmp_path)
    fifo = workspace / "pipe.yaml"
    os.mkfifo(fifo)

    with pytest.raises(PathContainmentError) as caught:
        template.load_template(fifo)

    assert caught.value.error_class == "path_violation"
    assert str(workspace) not in caught.value.message


def test_a_fifo_target_exits_seven_with_an_empty_stdout(tmp_path: Path) -> None:
    """The contract at the process boundary: a path violation, empty stdout.

    The refusal is a ``path_violation``, which the failure mode matrix maps to
    exit 7, and no partial report is printed -- printing an empty one would claim
    a review happened (design.md, Failure mode matrix). The diagnostic naming the
    refused file goes to stderr.
    """
    if not hasattr(os, "mkfifo"):
        pytest.skip("os.mkfifo is not available on this platform")

    workspace = make_workspace(tmp_path)
    os.mkfifo(workspace / "pipe.yaml")

    run = run_skill(IAM_SKILL, ["--target", "pipe.yaml"], cwd=workspace)

    run.assert_no_traceback()
    assert run.exit_code == exitcodes.PATH_VIOLATION
    assert run.stdout == ""
    assert "path_violation" in run.stderr
