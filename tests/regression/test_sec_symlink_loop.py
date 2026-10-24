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
CPython 3.9 through 3.12, ``Path.resolve`` detects a cycle itself (3.9.0 through
3.9.22 by walking the path, 3.9.23 and later and 3.10 through 3.12 through
``os.path.realpath``) and raises ``RuntimeError("Symlink loop from ...")`` rather than
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
cannot be.

Catching the exception was not enough on CPython 3.13, where the non-strict call
stopped detecting cycles and returns the path unresolved: a candidate cycle then
reached the existence check and was reported as ``input_not_found`` (exit 3)
instead of ``invalid_arguments`` (exit 2). :mod:`iacreview.pathguard` therefore
detects the cycle itself when the OS reports ``ELOOP`` -- with the walk 3.9.0
through 3.9.22 perform, iteratively, and the same message -- so every version
gives the same class. (3.9.23 and later, and 3.10 through 3.12, detect it
through ``os.path.realpath`` and name the unresolved remainder too; that wording
is pinned per version below.) ``ELOOP`` alone does not decide it,
because the OS also reports it for a long chain that is not a cycle.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Tuple

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


def test_a_self_loop_is_an_invalid_argument(tmp_path: Path) -> None:
    """The shortest cycle: one link pointing at itself."""
    root = _workspace(tmp_path)
    (root / "self").symlink_to(root / "self")

    with pytest.raises(InvalidArgumentsError):
        pathguard.resolve_within("self", root)


def test_a_cycle_in_a_traversed_directory_with_a_missing_leaf_is_an_invalid_argument(
    tmp_path: Path,
) -> None:
    """The leaf does not exist, but the cycle is reached first."""
    root = _workspace(tmp_path)
    (root / "dir_a").symlink_to(root / "dir_b", target_is_directory=True)
    (root / "dir_b").symlink_to(root / "dir_a", target_is_directory=True)

    with pytest.raises(InvalidArgumentsError):
        pathguard.resolve_within("dir_a/missing.yaml", root)


@pytest.mark.parametrize("links", [39, 45])
def test_a_long_non_cyclic_chain_still_resolves(tmp_path: Path, links: int) -> None:
    """``ELOOP`` without a cycle: the OS limit is reached, the chain still ends.

    39 links exceed macOS's limit (32) but not Linux's (40); 45 exceed both. The
    explicit cycle check must not turn either into an error, because neither is
    one for ``Path.resolve`` on any version.
    """
    root = _workspace(tmp_path)
    (root / "chain0").symlink_to("app.yaml")
    for index in range(1, links):
        (root / "chain{0}".format(index)).symlink_to("chain{0}".format(index - 1))

    resolved = pathguard.resolve_within("chain{0}".format(links - 1), root)

    assert resolved == (root / "app.yaml").resolve()


def _resolve_names_the_whole_path(version: Tuple[int, ...]) -> bool:
    """Whether ``Path.resolve`` on ``version`` names the whole unresolved path.

    CPython 3.10 through 3.12, and 3.9.23 and later, resolve through
    ``os.path.realpath`` and report the path whose ``stat`` failed, which keeps
    the components after the cycle (``dir_a/app.yaml``). 3.9.23 took that
    implementation in as a backport (bpo-43757 / bpo-25264, shipped with the
    gh-135034 tarfile fix; see the 3.9.23 changelog and cpython#136755). The
    walk of 3.9.0 through 3.9.22, and the plugin's explicit check on 3.13 and
    later, name the link that closes the cycle (``dir_a``). The two coincide
    when the cycle is the last component.
    """
    if (3, 9, 23) <= version[:3] < (3, 10):
        return True
    return (3, 10) <= version[:2] < (3, 13)


#: The naming of the interpreter running the suite.
RESOLVE_NAMES_THE_WHOLE_PATH = _resolve_names_the_whole_path(
    tuple(sys.version_info[:3])
)


@pytest.mark.parametrize(
    ("version", "whole_path"),
    [
        ((3, 9, 6), False),
        ((3, 9, 22), False),
        ((3, 9, 23), True),
        ((3, 9, 25), True),
        ((3, 10, 0), True),
        ((3, 12, 9), True),
        ((3, 13, 0), False),
        ((3, 14, 0), False),
    ],
)
def test_resolve_naming_follows_the_cpython_release_that_changed_it(
    version: Tuple[int, int, int], whole_path: bool
) -> None:
    """Both sides of every boundary, so neither naming can go unexercised."""
    assert _resolve_names_the_whole_path(version) is whole_path


@pytest.mark.parametrize(
    ("candidate", "link", "whole_path"),
    [
        ("loop_a", "loop_a", "loop_a"),
        ("ring_a", "ring_a", "ring_a"),
        ("self", "self", "self"),
        ("dir_a/app.yaml", "dir_a", "dir_a/app.yaml"),
    ],
)
def test_the_cycle_message_names_where_the_cycle_was_met(
    tmp_path: Path, candidate: str, link: str, whole_path: str
) -> None:
    """The exact message, with each version's naming fixed as a literal.

    3.9 and 3.10-3.12 phrase it through CPython, 3.13 through the plugin, which
    follows 3.9.0-3.9.22. Every version agrees on the class and on the text for
    a cycle named directly.
    """
    root = _workspace(tmp_path)
    (root / "loop_a").symlink_to(root / "loop_b")
    (root / "loop_b").symlink_to(root / "loop_a")
    (root / "ring_a").symlink_to(root / "ring_b")
    (root / "ring_b").symlink_to(root / "ring_c")
    (root / "ring_c").symlink_to(root / "ring_a")
    (root / "self").symlink_to(root / "self")
    (root / "dir_a").symlink_to(root / "dir_b", target_is_directory=True)
    (root / "dir_b").symlink_to(root / "dir_a", target_is_directory=True)

    with pytest.raises(InvalidArgumentsError) as excinfo:
        pathguard.resolve_within(candidate, root)

    named = whole_path if RESOLVE_NAMES_THE_WHOLE_PATH else link
    assert excinfo.value.message == (
        "path cannot be normalized: {0!r} (Symlink loop from {1!r})".format(
            candidate, str(root.resolve() / named)
        )
    )


def test_a_cycle_outside_the_root_is_an_invalid_argument(tmp_path: Path) -> None:
    """As on 3.9, a cycle on the resolution path is reported before containment.

    The candidate escapes the root, but it cannot be normalized at all, and that
    is the outcome every version reports for it.
    """
    root = _workspace(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "loop").symlink_to(outside / "loop_back")
    (outside / "loop_back").symlink_to(outside / "loop")

    with pytest.raises(InvalidArgumentsError):
        pathguard.resolve_within("../outside/loop", root)
