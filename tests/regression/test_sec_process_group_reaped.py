"""Regression: a timed-out tool takes its descendants down with it.

Requirement guarded
-------------------

Requirement 17 AC7: when an external tool invocation exceeds its timeout, the
plugin terminates the tool together with any child processes it started, so that
no descendant of the timed-out tool survives the review. The v0.8.0 design (R-9)
implements this by starting the child as a new session leader
(``start_new_session=True``) and signalling the whole process group on timeout.

Why this belongs in a security regression suite
-----------------------------------------------

The dangerous failure is a leak, not a crash. Before R-9, ``proc.run`` used
``subprocess.run(timeout=...)``, which kills only the direct child; a tool that
forked a helper -- ``cdk synth`` spawning ``node``, say -- could leave that
helper running after the review reported a clean timeout and exited. A review of
untrusted Infrastructure as Code that quietly seeds orphaned processes is exactly
the outcome Requirement 17 is meant to foreclose, so the guarantee is pinned at
the process boundary rather than argued from the code.

Technique
---------

``tests/fakebin/cfn-lint-grandchild/cfn-lint`` backgrounds a ``sleep`` -- the
grandchild -- inside the group ``proc.run`` creates, records that sleep's PID to
the path handed to it as ``--grandchild-pidfile`` (through argv, because
``proc.run`` strips every environment variable outside its allowlist), then hangs
on a sleep of its own so a one-second timeout fires. After
:func:`iacreview.proc.run` raises
:class:`~iacreview.errors.ToolTimeoutError`, the grandchild PID must stop being a
live process.

Liveness is checked with ``os.kill(pid, 0)``, which sends no signal and raises
:class:`ProcessLookupError` once the process is gone -- portable across macOS and
Linux, unlike anything that parses ``ps`` output. The check is polled briefly
rather than asserted once, because ``SIGKILL`` delivery and reaping are not
instantaneous and a single read would be flaky; a surviving grandchild never
disappears, so the poll converts "reaped" into a fast pass and "leaked" into a
bounded wait before failure.
"""

from __future__ import annotations

import errno
import os
import time
from pathlib import Path

import pytest

from iacreview import proc
from iacreview.errors import ToolTimeoutError

#: The fake tool's timeout. One second is long enough for the shell to reach the
#: point where it has written the grandchild PID and started its own blocking
#: sleep, and short enough to keep the test fast.
_TOOL_TIMEOUT_S = 1

#: Upper bound on how long the grandchild may take to disappear after the
#: timeout. Generous relative to the SIGTERM grace period so a loaded CI host
#: does not flake, but finite so a genuine leak fails rather than hangs.
_REAP_DEADLINE_S = 5.0


def _is_alive(pid: int) -> bool:
    """Return whether ``pid`` names a live process, portably.

    ``os.kill(pid, 0)`` delivers no signal; it only performs the existence and
    permission checks. ``ProcessLookupError`` means the process is gone.
    ``PermissionError`` (EPERM) means it exists but is owned by another user,
    which for a process this test started cannot happen, but is treated as alive
    so a spurious pass is impossible.
    """
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError as exc:  # pragma: no cover - defensive
        if exc.errno == errno.ESRCH:
            return False
        raise
    return True


def test_timed_out_tool_reaps_its_grandchild(
    fakebin_dir: Path, tmp_path: Path
) -> None:
    """Requirement 17 AC7: no descendant of the timed-out tool survives."""
    pidfile = tmp_path / "grandchild.pid"
    fake_tool = fakebin_dir / "cfn-lint-grandchild" / "cfn-lint"

    # The pidfile path is passed through argv, not the environment: proc.run's
    # _minimal_env allowlist would strip any variable this test tried to set.
    with pytest.raises(ToolTimeoutError) as excinfo:
        proc.run(
            [str(fake_tool), "--grandchild-pidfile", str(pidfile)],
            timeout_s=_TOOL_TIMEOUT_S,
        )

    assert excinfo.value.error_class == "tool_timeout"

    # The fake writes the PID before blocking, so by the time the timeout fired
    # and run() returned, the file exists and holds the grandchild's PID.
    assert pidfile.exists(), "the fake tool never recorded its grandchild PID"
    grandchild_pid = int(pidfile.read_text(encoding="utf-8").strip())

    deadline = time.monotonic() + _REAP_DEADLINE_S
    while _is_alive(grandchild_pid) and time.monotonic() < deadline:
        time.sleep(0.05)

    if _is_alive(grandchild_pid):
        # Clean up the leak we are about to fail on, so a failing run does not
        # strand a `sleep 999` on the developer's machine.
        try:
            os.kill(grandchild_pid, 9)
        except OSError:
            pass
        pytest.fail(
            "grandchild process {0} survived the tool timeout".format(
                grandchild_pid
            )
        )
