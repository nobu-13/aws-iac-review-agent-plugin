"""Path containment and rejection of unsafe user-supplied argument values.

Every path that reaches an argv array or an ``open()`` call must first pass
through this module. Two independent controls live here and they answer
different questions:

:func:`assert_no_shell_metacharacters`
    Defense-in-depth only. The primary protection against shell injection is
    ``shell=False`` plus argv arrays in :mod:`iacreview.proc`; no shell ever
    interprets these characters. Rejecting them early keeps hostile filenames
    such as ``report.yaml; rm -rf /`` out of logs and Findings, and gives
    Requirement 12 AC11 a concrete assertion target. Values are **rejected**,
    never sanitized: rewriting a path string can silently redirect access to a
    different file, which is a worse failure than an explicit error
    (design.md, "shell metacharacter 拒否の位置づけ").

:func:`resolve_within` / :func:`resolve_plugin_owned`
    Containment. Both normalize with :meth:`pathlib.Path.resolve` first and
    only then compare against the root with :meth:`pathlib.Path.relative_to`.
    Checking for the substring ``..`` is deliberately *not* done: it misses
    escapes through symlinks that contain no ``..`` at all, and a string
    ``startswith`` prefix test would wrongly accept ``/workspace-evil`` for
    root ``/workspace``. ``relative_to`` compares path components, so that
    mistake cannot happen (design.md, "Path containment").

The two functions differ in which root they use and in whether the
metacharacter check applies. User input is contained to the workspace root and
is metacharacter-checked. Plugin-owned resources (``rules/``,
``category_map.json``) are contained to the plugin root and are **not**
metacharacter-checked, because the plugin may legitimately be installed under a
directory whose name contains one of those characters and the path in that case
does not originate from user input.

Containment is not a sandbox. It constrains path resolution inside this
process; it does not constrain what cfn-lint, cfn-guard, or ``cdk synth`` can
reach once started. A TOCTOU window also remains between ``resolve()`` and the
subsequent read. Both residual risks are documented in
``docs/security-model.md``.

:func:`secure_temp_file`
    The single way this plugin creates a temporary file, with mode ``0600`` and
    deletion on every exit path the process can still observe
    (Requirement 9 AC6). See the section comment below for the cleanup model.
"""

from __future__ import annotations

import atexit
import contextlib
import os
import signal
import tempfile
from contextlib import contextmanager
from pathlib import Path
from types import FrameType
from typing import Any, Dict, FrozenSet, Iterator, Optional, Set, Tuple

from iacreview.errors import (
    InputNotFoundError,
    InvalidArgumentsError,
    MappingFileError,
    PathContainmentError,
    UnsafeArgumentError,
)

__all__ = [
    "SHELL_METACHARACTERS",
    "PLUGIN_MANIFEST_NAME",
    "TEMP_FILE_MODE",
    "CLEANUP_SIGNAL_NAMES",
    "assert_no_shell_metacharacters",
    "resolve_within",
    "resolve_plugin_owned",
    "plugin_root",
    "secure_temp_file",
    "install_temp_file_cleanup",
    "cleanup_temp_files",
    "registered_temp_files",
]

#: Characters rejected in user-supplied argument values (Requirement 9 AC4).
SHELL_METACHARACTERS: FrozenSet[str] = frozenset({";", "|", "&", "$", "`", ">", "<"})

#: Manifest file whose presence identifies the plugin root (Requirement 1 AC1).
PLUGIN_MANIFEST_NAME = "plugin.json"


def _metacharacter_list() -> str:
    """Return the rejected characters as a stable, space-separated string."""
    return " ".join(sorted(SHELL_METACHARACTERS))


# ---------------------------------------------------------------------------
# Unsafe argument rejection
# ---------------------------------------------------------------------------


def assert_no_shell_metacharacters(value: str) -> None:
    """Reject ``value`` if it contains any shell metacharacter.

    Args:
        value: A user-supplied argument value, typically a path string.

    Raises:
        UnsafeArgumentError: If any of :data:`SHELL_METACHARACTERS` occurs in
            ``value``. The message names the offending characters and the value
            so the user can rename the file.
    """
    found = sorted(char for char in SHELL_METACHARACTERS if char in value)
    if found:
        raise UnsafeArgumentError(
            "value contains shell metacharacter(s) {0}: {1!r}".format(
                " ".join(found), value
            ),
            remediation=(
                "Rename or quote-free the path so it contains none of: "
                + _metacharacter_list()
            ),
        )


# ---------------------------------------------------------------------------
# Path containment
# ---------------------------------------------------------------------------


def _resolve_root(root: Path) -> Path:
    """Normalize a containment root, which must already exist.

    ``strict=True`` is required here: an unresolvable root would make the
    subsequent :meth:`Path.relative_to` comparison meaningless. On macOS this
    step also expands the ``/tmp`` and ``/var`` symlinks, so a root and a
    target given in different forms still compare correctly.

    ``RuntimeError`` is caught alongside ``OSError`` for the reason given in
    :func:`_resolve_under_root`: a root reached through a symlink cycle is
    unusable, and "the root cannot be resolved" is the same outcome whether the
    OS reported ``ELOOP`` or :mod:`pathlib` detected the cycle itself.

    Raises:
        InputNotFoundError: If ``root`` does not exist or cannot be resolved.
    """
    try:
        return root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise InputNotFoundError(
            "containment root does not exist: {0}".format(root)
        ) from exc


def _resolve_under_root(candidate: str, root: Path) -> Path:
    """Resolve ``candidate`` and verify it stays inside ``root``.

    Existence of the *target* is not checked; callers decide which error class
    a missing target deserves. Containment is verified before existence so that
    a path outside the root is always reported as a containment violation, even
    when it happens to be missing as well.

    Raises:
        InvalidArgumentsError: If ``candidate`` is empty or cannot be
            normalized (for example an embedded NUL byte).
        InputNotFoundError: If ``root`` does not exist.
        PathContainmentError: If the resolved path is outside ``root``.
    """
    # An empty or blank string would resolve to the root itself, which silently
    # turns "no path given" into "the whole workspace". Reject it explicitly.
    if not candidate.strip():
        raise InvalidArgumentsError("path must be a non-empty string")

    root_real = _resolve_root(root)

    target = Path(candidate)
    if not target.is_absolute():
        target = root_real / target

    try:
        # strict=False: a not-yet-existing path still normalizes. Existence is
        # a separate concern handled by the caller.
        target_real = target.resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        # Untrusted input must fail cleanly rather than surface an OS-level
        # traceback (for example ValueError for an embedded NUL byte).
        #
        # ``RuntimeError`` is in the tuple for symlink cycles. On CPython 3.9
        # through 3.12, ``Path.resolve`` detects a cycle itself and raises
        # ``RuntimeError("Symlink loop from ...")`` instead of letting the OS
        # return ``ELOOP`` as an ``OSError``; 3.13 stopped raising for the
        # non-strict case. Catching it keeps a workspace that contains a cycle --
        # untrusted content, like every other input path -- from reaching the
        # caller as a traceback instead of a documented error class, on every
        # version. The class is the same one an ``ELOOP`` ``OSError`` already
        # produced here, so the two spellings of one OS condition now agree
        # (Requirement 16 AC7, AC8).
        raise InvalidArgumentsError(
            "path cannot be normalized: {0!r} ({1})".format(candidate, exc)
        ) from exc

    try:
        target_real.relative_to(root_real)
    except ValueError:
        raise PathContainmentError(
            "path resolves outside the containment root: {0!r} -> {1} "
            "(root: {2})".format(candidate, target_real, root_real),
            remediation=(
                "Provide a path inside {0}. Symbolic links are followed, so a "
                "link inside the root that points outside it is also "
                "rejected.".format(root_real)
            ),
        ) from None

    return target_real


def resolve_within(candidate: str, root: Path) -> Path:
    """Validate a user-supplied path and resolve it inside ``root``.

    Args:
        candidate: Relative or absolute path string from user input. Relative
            paths are interpreted against ``root``.
        root: Containment root, normally the workspace root.

    Returns:
        The resolved absolute path, guaranteed to be inside ``root`` and to
        exist at the moment of the check.

    Raises:
        UnsafeArgumentError: ``candidate`` contains a shell metacharacter.
        InvalidArgumentsError: ``candidate`` is empty or cannot be normalized.
        PathContainmentError: The resolved path is outside ``root``, whether
            reached via ``..``, an absolute path, or a symlink.
        InputNotFoundError: ``root`` or the resolved target does not exist.
    """
    assert_no_shell_metacharacters(candidate)
    resolved = _resolve_under_root(candidate, root)
    if not resolved.exists():
        raise InputNotFoundError(
            "input path does not exist: {0!r} (resolved: {1})".format(
                candidate, resolved
            )
        )
    return resolved


def resolve_plugin_owned(relative: str) -> Path:
    """Resolve a plugin-owned resource path inside the plugin root.

    Used for the plugin's own configuration and rule sets (``rules/``,
    ``category_map.json``). The shell metacharacter check is intentionally not
    applied: the value does not come from user input, and the plugin's install
    directory may legitimately contain one of those characters
    (Requirement 15 AC3).

    Args:
        relative: Path relative to the plugin root. An absolute path is
            accepted only if it already resolves inside the plugin root.

    Returns:
        The resolved absolute path inside the plugin root.

    Raises:
        MappingFileError: The plugin root cannot be verified, or the resource
            is missing. Either way the installation is broken rather than the
            user's input being wrong.
        InvalidArgumentsError: ``relative`` is empty or cannot be normalized.
        PathContainmentError: The resolved path is outside the plugin root.
    """
    root = plugin_root()
    resolved = _resolve_under_root(relative, root)
    if not resolved.exists():
        raise MappingFileError(
            "plugin-owned resource is missing: {0!r} (expected at {1})".format(
                relative, resolved
            ),
            remediation=(
                "Reinstall the plugin; its bundled resources are incomplete."
            ),
        )
    return resolved


# ---------------------------------------------------------------------------
# Plugin root
# ---------------------------------------------------------------------------


def plugin_root() -> Path:
    """Return the verified plugin root directory.

    The root is derived from this file's location
    (``<root>/iacreview/pathguard.py``) and then confirmed by the presence of
    ``plugin.json``. The confirmation matters because the derivation depends on
    the depth of this module inside the package: if ``iacreview/`` is ever
    moved, the manifest check fails loudly instead of silently containing paths
    to the wrong directory (design.md, Directory Structure).

    Raises:
        MappingFileError: ``plugin.json`` is not present at the derived root.
    """
    root = Path(__file__).resolve().parents[1]
    manifest = root / PLUGIN_MANIFEST_NAME
    if not manifest.is_file():
        raise MappingFileError(
            "plugin root verification failed: {0} not found at {1}".format(
                PLUGIN_MANIFEST_NAME, root
            ),
            remediation=(
                "Reinstall the plugin so that {0} sits one directory above "
                "iacreview/.".format(PLUGIN_MANIFEST_NAME)
            ),
        )
    return root


# ---------------------------------------------------------------------------
# Temporary files (Requirement 9 AC6)
# ---------------------------------------------------------------------------
#
# Requirement 9 AC6 asks for two things: mode 0600 in the system-designated
# temporary directory, and removal after use "including on abnormal termination
# via a best-effort cleanup mechanism". They are handled by two different
# mechanisms because one cannot cover both cases:
#
#   normal return / exception  -> the ``finally`` block in secure_temp_file
#   SIGTERM / SIGINT / sys.exit -> the module-level registry below
#   SIGKILL / hard crash        -> not coverable; left to the OS temp sweeper
#
# The registry holds every temp file currently inside a live ``with`` block. The
# ``finally`` block removes the file and deregisters it, so on a normal path the
# registry is empty again and the atexit hook has nothing to do.
#
# Signal-handler safety: the registry is only ever mutated with ``set.add`` and
# ``set.discard`` and only ever read through ``list()``. No lock is taken. A
# lock would be the usual choice for thread safety, but a signal handler runs on
# the main thread and would deadlock if it interrupted that same thread while it
# held the lock. Atomic set operations avoid the deadlock, at the cost of the
# theoretical case of a signal arriving between ``mkstemp`` and ``add`` -- a
# window the ``finally`` block cannot help with either.


#: Permission bits every temporary file this plugin creates must carry.
TEMP_FILE_MODE = 0o600

#: Signals whose default disposition terminates the process and which can still
#: be caught. ``SIGKILL`` is deliberately absent: it cannot be handled, and
#: pretending otherwise would be misleading. Looked up by name via ``getattr``
#: so the module stays importable on platforms lacking one of them.
CLEANUP_SIGNAL_NAMES: Tuple[str, ...] = ("SIGTERM", "SIGINT")

#: Temp files created by :func:`secure_temp_file` that are not yet removed.
_TEMP_FILE_REGISTRY: Set[Path] = set()

#: Guard making :func:`install_temp_file_cleanup` idempotent.
_CLEANUP_INSTALLED = False

#: Handlers displaced by :func:`install_temp_file_cleanup`, keyed by signal
#: number, so :func:`_handle_termination_signal` can chain to them.
_PREVIOUS_SIGNAL_HANDLERS: Dict[int, Any] = {}


def registered_temp_files() -> FrozenSet[Path]:
    """Return the temp files currently awaiting cleanup.

    Exposed for tests and for diagnostics. The result is a snapshot; it does not
    track later registrations.
    """
    return frozenset(_TEMP_FILE_REGISTRY)


def _remove_temp_file(path: Path) -> None:
    """Delete ``path`` and deregister it, ignoring an already-gone file.

    ``OSError`` is suppressed because cleanup runs on paths that may already be
    unlinked (double cleanup, or removal by the caller). Cleanup that raises
    would mask the original exception in a ``finally`` block, or abort a signal
    handler before the remaining files are reached.
    """
    _TEMP_FILE_REGISTRY.discard(path)
    with contextlib.suppress(OSError):
        path.unlink()


def cleanup_temp_files() -> None:
    """Remove every registered temporary file.

    Safe to call repeatedly and safe to call with an empty registry, which is
    what the ``atexit`` hook normally sees.
    """
    for path in list(_TEMP_FILE_REGISTRY):
        _remove_temp_file(path)


def _handle_termination_signal(signum: int, frame: Optional[FrameType]) -> None:
    """Clean up registered temp files, then honour the displaced handler.

    Chaining matters: this module may be imported into a host process (an Agent
    runtime, a test session) that already installed its own SIGTERM or SIGINT
    handler. Replacing that handler outright would change the host's shutdown
    behaviour as a side effect of a path helper being imported.

    The three dispositions are handled distinctly:

    ``SIG_DFL``
        Restore the default and re-send the signal to this process, so the exit
        status reports death by signal rather than a plain ``exit(0)``.
    ``SIG_IGN`` or no Python-level handler
        Return, leaving the process running. Cleanup has already happened, and
        a temp file will be created again if the work continues.
    a callable
        Delegate to it. The default SIGINT handler is such a callable and
        raises ``KeyboardInterrupt``, so normal Ctrl-C behaviour survives.
    """
    cleanup_temp_files()

    previous = _PREVIOUS_SIGNAL_HANDLERS.get(signum, signal.SIG_DFL)

    if callable(previous):
        previous(signum, frame)
        return

    if previous == signal.SIG_DFL:
        # Restore every handler we installed before re-raising, so the second
        # delivery is not intercepted again.
        _restore_signal_handlers()
        os.kill(os.getpid(), signum)


def _restore_signal_handlers() -> None:
    """Reinstate the handlers displaced by :func:`install_temp_file_cleanup`."""
    global _CLEANUP_INSTALLED
    for signum, previous in list(_PREVIOUS_SIGNAL_HANDLERS.items()):
        with contextlib.suppress(OSError, ValueError):
            signal.signal(signum, previous)
    _PREVIOUS_SIGNAL_HANDLERS.clear()
    _CLEANUP_INSTALLED = False


def install_temp_file_cleanup() -> None:
    """Install the ``atexit`` hook and the termination signal handlers.

    design.md places this call in ``main()``. It is additionally invoked from
    :func:`secure_temp_file` on first use, which makes the guarantee hold for
    any caller -- a Skill entry point that forgets the call, or an embedding
    host that has no ``main()`` of ours at all. The assumption behind the lazy
    call is that installation is only observable once a temp file exists: before
    that the registry is empty and both the hook and the handlers are no-ops
    beyond chaining. Deferring also keeps import of this module free of process
    -wide side effects, which matters because :mod:`iacreview.pathguard` is
    imported by every entry point, including ones that never create a temp file.

    Idempotent. ``signal.signal`` only works on the main thread; on any other
    thread the ``ValueError`` is swallowed and the ``atexit`` hook is left as
    the sole mechanism, since failing here would be a worse outcome than a
    narrower cleanup guarantee.
    """
    global _CLEANUP_INSTALLED
    if _CLEANUP_INSTALLED:
        return
    # Set first: a failure below must not leave a half-installed state that a
    # later call would duplicate.
    _CLEANUP_INSTALLED = True

    atexit.register(cleanup_temp_files)

    for name in CLEANUP_SIGNAL_NAMES:
        signum = getattr(signal, name, None)
        if signum is None:
            continue
        try:
            previous = signal.getsignal(signum)
            signal.signal(signum, _handle_termination_signal)
        except (OSError, ValueError):
            # Not the main thread, or the platform refuses this signal.
            continue
        _PREVIOUS_SIGNAL_HANDLERS[signum] = previous


def _validate_temp_suffix(suffix: str) -> None:
    """Reject a suffix that could move the file out of the temp directory.

    ``suffix`` is plugin-supplied rather than user input, so this is not the
    Requirement 9 AC4 check. It guards a narrower mistake: ``mkstemp`` appends
    the suffix to a generated name, so a separator in it would place the file in
    a subdirectory of the temp directory or fail outright, and the containment
    reasoning above no longer applies.

    Raises:
        InvalidArgumentsError: If ``suffix`` contains a path separator or a NUL.
    """
    forbidden = {"/", os.sep, "\0"}
    if os.altsep:
        forbidden.add(os.altsep)
    found = sorted(char for char in forbidden if char in suffix)
    if found:
        raise InvalidArgumentsError(
            "temp file suffix must not contain a path separator: {0!r}".format(suffix)
        )


@contextmanager
def secure_temp_file(suffix: str) -> Iterator[Path]:
    """Yield a private temporary file path, removed when the block exits.

    ``tempfile.mkstemp`` creates the file in the system-designated temporary
    directory (honouring ``TMPDIR``) with an unpredictable name, ``O_EXCL``, and
    mode ``0600``. The unpredictable name plus ``O_EXCL`` is what defeats
    symlink attacks on a world-writable ``/tmp``; the explicit
    :func:`os.chmod` that follows is a re-confirmation of the mode, not the
    control itself, which is why applying it by path rather than by descriptor
    is acceptable here.

    The file is created empty and immediately closed. Callers open it by path,
    which suits handing the path to an external tool -- the reason a temp file
    would be needed at all.

    Args:
        suffix: Filename suffix, normally an extension such as ``".json"``.

    Yields:
        Absolute path to an existing empty file with mode ``0600``.

    Raises:
        InvalidArgumentsError: ``suffix`` contains a path separator.
        OSError: The temporary directory is unwritable or unavailable.
    """
    _validate_temp_suffix(suffix)
    install_temp_file_cleanup()

    fd, name = tempfile.mkstemp(suffix=suffix)
    path = Path(name)
    # Registered before the mode is confirmed: from this point the file exists,
    # so an abnormal termination must find it in the registry.
    _TEMP_FILE_REGISTRY.add(path)
    try:
        os.close(fd)
        os.chmod(path, TEMP_FILE_MODE)
        yield path
    finally:
        _remove_temp_file(path)
