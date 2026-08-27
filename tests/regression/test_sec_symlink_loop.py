"""Regression: a symlink cycle in the workspace must fail as a plugin error.

Found by
--------

``tests/property/test_prop_pathguard.py::test_path_resolution_stays_inside_the_root``
(Property 18), whose candidate space includes a path that traverses a symbolic
link. Requirement 12 AC11 asks the regression suite to carry the security cases,
and steering/testing.md asks a property's counterexample to be pinned as a plain
example; this file is both.

The defect
----------

:func:`iacreview.pathguard.resolve_within` normalizes a candidate with
:meth:`pathlib.Path.resolve` and caught ``(OSError, ValueError)`` around it. On
CPython 3.9 through 3.12, ``Path.resolve`` walks the path itself and, on
detecting a cycle, raises ``RuntimeError("Symlink loop from ...")`` rather than
letting the kernel report ``ELOOP`` as an ``OSError``. ``RuntimeError`` is
neither ``OSError`` nor ``ValueError``, so it escaped:

    RuntimeError: Symlink loop from '/workspace/loop_a'

Both resolution sites were affected -- the candidate, and the containment root,
which ``_resolve_root`` resolves with ``strict=True``.

Why it mattered
---------------

The security steering rule treats every input path as untrusted, and a workspace
holding a symlink cycle is ordinary content: a broken checkout produces one, and
so does a repository authored to produce one. Containment itself never failed --
no path escaped the root, because nothing resolved at all -- so this was not a
containment bypass. What failed was the failure: an entry point died with a
traceback on stderr and an undefined exit status instead of the documented error
class and exit code every other bad path gets (Requirement 16 AC7, AC8), which
also breaks the "no unhandled exception on untrusted input" contract
:mod:`iacreview.pathguard` states in its own module docstring.

The fix
-------

``RuntimeError`` joined the caught tuple at both sites. A cycle now produces the
same error class an ``ELOOP`` ``OSError`` already produced: ``invalid_arguments``
for a candidate that cannot be normalized, ``input_not_found`` for a root that
cannot be. Catching it rather than testing the Python version also keeps the
behaviour identical on 3.13, where the non-strict call stopped raising.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from iacreview import pathguard
from iacreview.errors import (
    InputNotFoundError,
    InvalidArgumentsError,
    PathContainmentError,
)

TEMPLATE_BODY = "Resources:\n  A:\n    Type: AWS::S3::Bucket\n"


def _workspace(tmp_path: Path) -> Path:
    """A workspace root holding one real Template."""
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "app.yaml").write_text(TEMPLATE_BODY, encoding="utf-8")
    return root


def test_two_link_cycle_named_directly_is_an_invalid_argument(tmp_path: Path) -> None:
    """The original counterexample: ``loop_a -> loop_b -> loop_a``."""
    root = _workspace(tmp_path)
    (root / "loop_a").symlink_to(root / "loop_b")
    (root / "loop_b").symlink_to(root / "loop_a")

    with pytest.raises(InvalidArgumentsError) as excinfo:
        pathguard.resolve_within("loop_a", root)

    assert excinfo.value.error_class == "invalid_arguments"


def test_three_link_cycle_is_an_invalid_argument(tmp_path: Path) -> None:
    """Cycle length is not what the fix keys on."""
    root = _workspace(tmp_path)
    (root / "ring_a").symlink_to(root / "ring_b")
    (root / "ring_b").symlink_to(root / "ring_c")
    (root / "ring_c").symlink_to(root / "ring_a")

    with pytest.raises(InvalidArgumentsError):
        pathguard.resolve_within("ring_a", root)


def test_cycle_in_a_traversed_directory_is_an_invalid_argument(
    tmp_path: Path,
) -> None:
    """The cycle is in a middle component, not the one the candidate names."""
    root = _workspace(tmp_path)
    (root / "dir_a").symlink_to(root / "dir_b", target_is_directory=True)
    (root / "dir_b").symlink_to(root / "dir_a", target_is_directory=True)

    with pytest.raises(InvalidArgumentsError):
        pathguard.resolve_within("dir_a/app.yaml", root)


def test_cycle_as_the_containment_root_is_a_missing_root(tmp_path: Path) -> None:
    """The second affected site: the root itself cannot be resolved.

    ``_resolve_root`` uses ``strict=True``, which raises the same
    ``RuntimeError`` for a cycle. A root that cannot be resolved is unusable, so
    the outcome is the one a nonexistent root already produced.
    """
    (tmp_path / "root_a").symlink_to(tmp_path / "root_b", target_is_directory=True)
    (tmp_path / "root_b").symlink_to(tmp_path / "root_a", target_is_directory=True)

    with pytest.raises(InputNotFoundError) as excinfo:
        pathguard.resolve_within("app.yaml", tmp_path / "root_a")

    assert excinfo.value.error_class == "input_not_found"


def test_a_cycle_does_not_mask_a_containment_violation(tmp_path: Path) -> None:
    """Present so the fix cannot be mistaken for "cycles are harmless".

    A candidate that escapes the root is still a containment violation when a
    cycle happens to exist elsewhere in the workspace: the cycle is not on the
    resolution path, so it is not consulted.
    """
    root = _workspace(tmp_path)
    (root / "loop_a").symlink_to(root / "loop_b")
    (root / "loop_b").symlink_to(root / "loop_a")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.yaml").write_text(TEMPLATE_BODY, encoding="utf-8")

    with pytest.raises(PathContainmentError):
        pathguard.resolve_within("../outside/secret.yaml", root)
