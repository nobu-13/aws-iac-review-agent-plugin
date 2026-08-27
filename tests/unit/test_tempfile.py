"""``secure_temp_file`` mode and cleanup on every reachable exit path.

The four cases required by the task are covered: (a) mode ``0600`` at creation,
(b) removal after the ``with`` block, (c) removal when the block raises, and
(d) removal on SIGTERM through the module-level registry, exercised in a real
child process. A fifth case covers interpreter exit while a block is still open,
which is the path the ``atexit`` hook exists for.

Signal handling and the registry are process-global state. The
``isolated_cleanup_state`` fixture saves and restores that state, including the
module's private globals, so an in-process signal test cannot leak a handler
into the rest of the session. Reaching into the private names is deliberate:
there is no public uninstall, because production code has no reason to uninstall
cleanup, and inventing one just for tests would widen the API for no benefit.
"""

from __future__ import annotations

import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Iterator, List

import pytest

from iacreview import pathguard
from iacreview.errors import InvalidArgumentsError

# tests/unit/test_tempfile.py -> tests/unit -> tests -> plugin root
PLUGIN_ROOT = Path(__file__).resolve().parents[2]

#: POSIX permission bits are meaningful only on POSIX; on Windows ``os.chmod``
#: cannot express 0600 and signal delivery differs.
posix_only = pytest.mark.skipif(
    os.name != "posix", reason="POSIX permission bits and signal semantics required"
)


@pytest.fixture()
def isolated_cleanup_state() -> Iterator[None]:
    """Restore signal handlers and the cleanup registry around a test."""
    original_handlers = {}
    for name in pathguard.CLEANUP_SIGNAL_NAMES:
        signum = getattr(signal, name, None)
        if signum is not None:
            original_handlers[signum] = signal.getsignal(signum)

    saved_registry = set(pathguard._TEMP_FILE_REGISTRY)
    saved_installed = pathguard._CLEANUP_INSTALLED
    saved_previous = dict(pathguard._PREVIOUS_SIGNAL_HANDLERS)

    # Force a fresh install inside the test regardless of what ran before.
    pathguard._CLEANUP_INSTALLED = False
    pathguard._PREVIOUS_SIGNAL_HANDLERS.clear()
    try:
        yield
    finally:
        for signum, handler in original_handlers.items():
            signal.signal(signum, handler)
        pathguard._TEMP_FILE_REGISTRY.clear()
        pathguard._TEMP_FILE_REGISTRY.update(saved_registry)
        pathguard._CLEANUP_INSTALLED = saved_installed
        pathguard._PREVIOUS_SIGNAL_HANDLERS.clear()
        pathguard._PREVIOUS_SIGNAL_HANDLERS.update(saved_previous)


def _run_child(script: str, *, terminate: bool) -> "subprocess.Popen[str]":
    """Start a child that prints a temp file path, then stop it.

    With ``terminate=True`` the child blocks after printing, so the parent can
    confirm the file exists before sending the signal. With ``terminate=False``
    the child exits on its own and may already have cleaned up by the time the
    parent reads the path, so no pre-check is possible there.
    """
    env = dict(os.environ)
    env["PYTHONPATH"] = str(PLUGIN_ROOT)
    # Line-buffered stdout in the child is not enough on its own; the child
    # scripts flush explicitly.
    process = subprocess.Popen(
        [sys.executable, "-c", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
    )
    try:
        line = process.stdout.readline() if process.stdout else ""
        assert line.strip(), "child did not report a temp file path"
        path = Path(line.strip())

        if terminate:
            assert path.exists(), "child temp file missing before termination"
            process.send_signal(signal.SIGTERM)
        process.wait(timeout=15)
    except BaseException:
        process.kill()
        process.wait(timeout=15)
        raise

    process.reported_path = path  # type: ignore[attr-defined]
    return process


# --- (a) mode 0600 at creation ----------------------------------------------


@posix_only
def test_temp_file_is_created_with_mode_0600() -> None:
    with pathguard.secure_temp_file(".json") as path:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(path.stat().st_mode) == pathguard.TEMP_FILE_MODE


def test_temp_file_lives_in_the_system_temp_directory() -> None:
    """Requirement 9 AC6 asks for the system-designated temporary directory."""
    temp_root = Path(tempfile.gettempdir()).resolve()

    with pathguard.secure_temp_file(".json") as path:
        assert path.resolve().parent == temp_root
        assert path.name.endswith(".json")


def test_temp_file_is_created_empty_and_writable_by_the_owner() -> None:
    with pathguard.secure_temp_file(".txt") as path:
        assert path.is_file()
        assert path.stat().st_size == 0

        path.write_text("payload", encoding="utf-8")
        assert path.read_text(encoding="utf-8") == "payload"


# --- (b) removal after a normal exit ----------------------------------------


def test_temp_file_is_removed_after_the_block() -> None:
    with pathguard.secure_temp_file(".json") as path:
        assert path.exists()

    assert not path.exists()
    assert path not in pathguard.registered_temp_files()


def test_temp_file_is_registered_only_while_the_block_is_open() -> None:
    with pathguard.secure_temp_file(".json") as path:
        assert path in pathguard.registered_temp_files()

    assert path not in pathguard.registered_temp_files()


def test_caller_deleting_the_file_early_does_not_raise() -> None:
    """Cleanup is idempotent; a consumed temp file may already be gone."""
    with pathguard.secure_temp_file(".json") as path:
        path.unlink()

    assert not path.exists()


# --- (c) removal when the block raises --------------------------------------


def test_temp_file_is_removed_when_the_block_raises() -> None:
    captured: List[Path] = []

    with pytest.raises(RuntimeError, match="boom"):
        with pathguard.secure_temp_file(".json") as path:
            captured.append(path)
            raise RuntimeError("boom")

    assert captured
    assert not captured[0].exists()
    assert captured[0] not in pathguard.registered_temp_files()


# --- (d) removal on SIGTERM via the registry --------------------------------


CHILD_SIGTERM = """
import sys, time
from iacreview import pathguard

with pathguard.secure_temp_file(".json") as path:
    print(path)
    sys.stdout.flush()
    time.sleep(30)
"""


@posix_only
def test_temp_file_is_removed_when_the_process_receives_sigterm() -> None:
    """The ``finally`` block never runs here; the registry does the work."""
    process = _run_child(CHILD_SIGTERM, terminate=True)
    path: Path = process.reported_path  # type: ignore[attr-defined]

    assert not path.exists(), "temp file survived SIGTERM"
    # Default SIGTERM disposition is preserved: the handler re-raises after
    # cleanup, so the child reports death by signal rather than exit status 0.
    assert process.returncode == -signal.SIGTERM


CHILD_EXIT_WHILE_OPEN = """
import sys
from iacreview import pathguard

cm = pathguard.secure_temp_file(".json")
path = cm.__enter__()
print(path)
sys.stdout.flush()
sys.exit(0)
"""


def test_temp_file_does_not_survive_interpreter_exit_inside_an_open_block() -> None:
    """Covers the path the ``atexit`` hook exists for."""
    process = _run_child(CHILD_EXIT_WHILE_OPEN, terminate=False)
    path: Path = process.reported_path  # type: ignore[attr-defined]

    assert process.returncode == 0
    assert not path.exists(), "temp file survived interpreter exit"


# --- signal handler chaining and installation -------------------------------


@posix_only
def test_signal_handler_chains_to_a_pre_existing_handler(
    isolated_cleanup_state: None,
) -> None:
    """A host's own SIGTERM handler must still run after cleanup."""
    received: List[int] = []

    def host_handler(signum: int, frame: object) -> None:
        received.append(signum)

    signal.signal(signal.SIGTERM, host_handler)

    with pathguard.secure_temp_file(".json") as path:
        os.kill(os.getpid(), signal.SIGTERM)
        # Python runs the handler between bytecodes; give it a moment.
        deadline = time.monotonic() + 5.0
        while not received and time.monotonic() < deadline:
            time.sleep(0.01)

        assert received == [signal.SIGTERM], "pre-existing handler was not called"
        assert not path.exists(), "registry did not clean up on SIGTERM"

    assert signal.getsignal(signal.SIGTERM) is pathguard._handle_termination_signal


@posix_only
def test_install_is_idempotent_and_records_one_previous_handler(
    isolated_cleanup_state: None,
) -> None:
    def host_handler(signum: int, frame: object) -> None:  # pragma: no cover
        raise AssertionError("must not run in this test")

    signal.signal(signal.SIGTERM, host_handler)

    pathguard.install_temp_file_cleanup()
    pathguard.install_temp_file_cleanup()

    # A second install must not record our own handler as the "previous" one,
    # which would make the chain call itself forever.
    assert pathguard._PREVIOUS_SIGNAL_HANDLERS[signal.SIGTERM] is host_handler


def test_cleanup_temp_files_is_safe_with_an_empty_registry() -> None:
    pathguard.cleanup_temp_files()

    assert pathguard.registered_temp_files() == frozenset()


# --- suffix validation ------------------------------------------------------


@pytest.mark.parametrize("suffix", ["/etc/passwd", "sub/dir.json", "bad\0.json"])
def test_suffix_containing_a_separator_or_nul_is_rejected(suffix: str) -> None:
    with pytest.raises(InvalidArgumentsError):
        with pathguard.secure_temp_file(suffix):
            pytest.fail("context manager must not be entered")


def test_empty_suffix_is_accepted() -> None:
    with pathguard.secure_temp_file("") as path:
        assert path.is_file()
