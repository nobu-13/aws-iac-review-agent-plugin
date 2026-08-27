"""Properties 20, 22, 23 and 29: the four security claims stated as absences.

Every property in this file says that something does **not** happen -- no process
starts, no file survives, no more than five lines are copied, no credential
reaches the report -- and an absence is the easiest thing to assert vacuously. So
each test here pairs its absence with a *positive control* in the same example:
something that must be observed, in the same window, by the same mechanism. A
mechanism that stopped observing anything would fail the control rather than pass
the property.

What the example tests already own, and this module does not repeat
--------------------------------------------------------------------

``tests/unit/test_tempfile.py``
    ``secure_temp_file`` one case at a time: mode ``0600``, the system temp
    directory, removal after the block, removal when the block raises, removal on
    SIGTERM through the registry (in a real child process), interpreter exit
    inside an open block, signal-handler chaining, and the rejected suffixes.

``tests/unit/test_proc.py``
    The wrapper's own boundary: argv validation, the environment allowlist, closed
    stdin, a non-zero status returned rather than raised, and an absolute
    ``argv[0]`` reported by its bare name.

``tests/unit/test_finding.py``
    ``redaction_trigger`` / ``redact_finding`` per trigger and per non-trigger,
    including the deliberate non-detections (a key merely *named* ``password``).

``tests/regression/test_sec_no_host_path_in_errors.py``
    Six pinned cases in which a message must not carry an absolute host path --
    the sibling concern to Property 29's "must not carry a credential".

``tests/regression/test_sec_symlink_loop.py``
    The counterexample Property 18 found, pinned as plain examples.

``tests/property/test_prop_pathguard.py``
    Properties 18 and 19. Two of its results are *used* here rather than
    re-derived: its AST scan establishes that :mod:`iacreview.proc` is the single
    funnel through which the shipped code can start a process, and its
    ``_captured_subprocess_run`` explains why a ``monkeypatch`` fixture cannot be
    combined with ``@given`` -- a function-scoped fixture is set up once per test,
    not once per example, and Hypothesis rejects the combination. Every context
    manager below is written by hand for that reason.

``tests/property/test_prop_template.py``
    Property 17 (arbitrary input bytes fail safely) and Property 21 (a Template's
    YAML tags are never executed). Property 20 is the argv-side counterpart:
    those two are about content that reaches a parser, this one is about content
    that never should reach anything.

How "no subprocess and no file created or modified" is observed
--------------------------------------------------------------

Property 20 quantifies over a *negative* about the whole process, so it is
observed rather than inferred, in two layers that fail for different reasons:

**interception**, for the whole filesystem and every process start.
    :func:`_observed` replaces, for the duration of one ``main()`` call:
    ``builtins.open``, ``io.open`` and ``os.open`` (recording a call only when the
    mode or the flags request writing); the twelve :mod:`os` functions that mutate
    a directory entry without opening anything (:data:`_MUTATING_OS_FUNCTIONS`);
    ``subprocess.run``, ``subprocess.Popen``, and the :mod:`os` process starters
    (:data:`_PROCESS_STARTING_OS_FUNCTIONS`). All three ``open`` spellings are
    needed and none is redundant: :meth:`pathlib.Path.write_text` reaches
    ``io.open``, which is a *different attribute lookup* from ``builtins.open``
    even though it is the same function object, and :func:`tempfile.mkstemp` goes
    to ``os.open`` without passing either. The probe below caught exactly that.

**a before/after snapshot** of the workspace tree.
    Name, file type, permission bits, size and mtime in nanoseconds for every
    entry under the workspace, compared as a whole. This is the layer that does
    not depend on the interception being complete: a write from a C extension, or
    through an ``open`` spelling not listed above, still moves an mtime.

Neither layer alone would carry the claim. The snapshot cannot see a write to
``/tmp`` or to the plugin directory; the interception cannot see a write that
bypasses the Python-level names it replaced. Together they cover the statement,
and :func:`_probe_the_observer` -- run on every example -- shows that they are both
still working by writing one file and starting one process inside an observed
window and requiring all three signals to fire.

The alternative was to assert the absence from the *outside*: run each entry point
as a child under ``strace``/``dtrace`` and read the syscalls. That observes more,
but it needs a privileged tracer that is unavailable on a stock macOS and differs
per platform, and it would make a security property untestable on a contributor's
machine. Interception plus snapshot is weaker in principle and checkable
everywhere, and the probe is what keeps "weaker" from becoming "silent".

No external tool is needed anywhere in this file. cfn-lint, cfn-guard and the CDK
CLI may all be absent: ``subprocess.run`` is replaced before any invocation could
reach it, and the two places an invocation is arranged at all -- the observer's own
probe and Property 23's timeout branch -- use :data:`sys.executable` as ``argv[0]``
so that the ``PATH`` lookup succeeds without installing anything.

Non-vacuity, per property
-------------------------

=============  ==============================================================
Property 20    the probe (one write, one launch, one snapshot difference, all
               three observed) plus stderr non-empty and stdout empty on every
               rejected invocation, which is what shows ``main()`` ran and
               rejected the argv deliberately rather than dying before it.
Property 22    the path exists, and its mode is read, *inside* the block; a
               helper that yielded a non-existent path would fail there rather
               than satisfy "no longer exists" for free.
Property 23    ``stderr_texts()`` spans fewer, exactly and more lines than the
               bound, and the test requires the drawn text's own line count to
               decide which side of the bound it is on, so a generator that
               stopped producing long texts would stop satisfying the
               assertion that the cap actually truncated something.
Property 29    a fourth Evidence entry at a location that triggers nothing must
               reach the report **verbatim**. Redacting everything would satisfy
               the property and fail this control.
=============  ==============================================================
"""

from __future__ import annotations

import builtins
import copy
import importlib.util
import io
import json
import os
import re
import stat
import subprocess
import sys
import types
from contextlib import contextmanager
from pathlib import Path
from typing import (
    Any,
    Dict,
    FrozenSet,
    Iterator,
    List,
    NamedTuple,
    Optional,
    Sequence,
    Tuple,
)

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

import strategies as S
from iacreview import exitcodes, pathguard, proc
from iacreview.errors import (
    ERROR_CLASS_HIERARCHY,
    STDERR_HEAD_MAX_LINES,
    STRUCTURED_ERROR_KEYS,
    ToolTimeoutError,
)
from iacreview.finding import (
    AGENT_SOURCE,
    CREDENTIAL_RULE_IDS,
    FINDING_TYPES,
    REDACTED_EXCERPT,
    VALIDITY_TYPE,
    Finding,
    RedactionTrigger,
    noecho_parameter_names,
    redaction_trigger,
    to_dict,
)

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

#: Every Skill entry point, relative to the plugin root. Property 20 is stated
#: over "the entry point", and the plugin ships six of them, so all six are
#: checked on every example rather than one being taken as representative -- they
#: do not share an argument parser, and one of them
#: (``cloudformation-review``) passes no ``validate`` callable to
#: :func:`iacreview.bootstrap.run_entry_point` at all, relying instead on
#: ``pathguard.resolve_within`` being the first statement of its ``run``. That is
#: precisely the arrangement this property is able to break.
ENTRY_POINTS: Tuple[str, ...] = (
    "skills/cfn-lint-review/scripts/run_cfn_lint.py",
    "skills/cfn-guard-review/scripts/run_cfn_guard.py",
    "skills/cloudformation-review/scripts/extract_facts.py",
    "skills/iam-review/scripts/run_iam_scan.py",
    "skills/iam-review/scripts/extract_policies.py",
    "skills/iac-review/scripts/run_iac_review.py",
)

#: Exit codes the plugin documents, minus success. Property 20's "documented
#: non-zero exit code drawn from the defined set", read off
#: :mod:`iacreview.exitcodes` rather than restated, so a new code is admitted
#: here the moment it is documented there.
DEFINED_NONZERO_EXIT_CODES: FrozenSet[int] = frozenset(
    set(exitcodes.EXIT_CODES.values()) - {exitcodes.OK}
)

#: Name of the Template placed in the workspace. It exists so that a snapshot
#: comparison can detect a *modification* and not only a creation, and so that an
#: argv naming it is rejected for its own reason rather than for the file being
#: absent.
TEMPLATE_NAME = "app.yaml"

#: Body of that Template: the smallest reviewable document
#: (:func:`iacreview.template.is_reviewable` needs a non-empty ``Resources``).
TEMPLATE_BODY = "Resources:\n  A:\n    Type: AWS::S3::Bucket\n"

#: File the observer's own probe writes. Removed after each probe, so the
#: workspace baseline is a function of the test rather than of the example order.
PROBE_NAME = "_observer_probe.txt"


# ---------------------------------------------------------------------------
# Property 20: observing the absence of a side effect
# ---------------------------------------------------------------------------

#: ``open`` modes that request the ability to write. ``"+"`` is included because
#: ``"r+"`` opens an existing file for update, which modifies it.
_WRITE_MODE_CHARACTERS: FrozenSet[str] = frozenset("wxa+")

#: ``os.open`` flags that request the ability to write or to create. ``O_EXCL``
#: is meaningless without ``O_CREAT`` but is listed so the mask reads as "any
#: intent other than read".
_WRITE_FLAGS: int = (
    os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND | os.O_EXCL
)

#: :mod:`os` functions that change a directory entry or an inode without opening
#: anything, so no ``open`` interception would see them. ``makedirs`` and
#: ``removedirs`` are absent because they are pure Python wrappers around
#: ``mkdir`` and ``rmdir``, which are here.
_MUTATING_OS_FUNCTIONS: Tuple[str, ...] = (
    "mkdir",
    "rmdir",
    "rename",
    "replace",
    "remove",
    "unlink",
    "symlink",
    "link",
    "chmod",
    "chown",
    "truncate",
    "utime",
)

#: :mod:`os` functions that start a process without :mod:`subprocess`. The same
#: list ``tests/property/test_prop_pathguard.py`` scans the shipped sources for
#: statically; replaced here so that a call *through a variable*, which no AST
#: scan can see, is still observed at run time.
_PROCESS_STARTING_OS_FUNCTIONS: Tuple[str, ...] = (
    "system",
    "popen",
    "posix_spawn",
    "posix_spawnp",
    "execv",
    "execve",
    "execvp",
    "execvpe",
    "spawnv",
    "spawnve",
    "spawnvp",
    "fork",
    "forkpty",
)

#: Snapshot entry: file type, permission bits, size, and mtime in nanoseconds.
#: ``lstat`` rather than ``stat``, so a symlink is described by the link and not
#: by whatever it points at.
_Stat = Tuple[int, int, int, int]


class Observation(NamedTuple):
    """What one observed ``main()`` call did, besides returning an exit code.

    Attributes:
        exit_code: What ``main()`` returned.
        stdout: Everything written to :data:`sys.stdout` during the call.
        stderr: Everything written to :data:`sys.stderr` during the call.
        writes: One description per intercepted write attempt, anywhere on the
            filesystem. Empty is the expected value for every invalid argv.
        launches: One description per intercepted process start, likewise.
        tree_changes: Workspace entries whose snapshot differs, as
            ``relative path -> (before, after)`` with ``None`` for absent.
    """

    exit_code: int
    stdout: str
    stderr: str
    writes: List[str]
    launches: List[str]
    tree_changes: Dict[str, Tuple[Optional[_Stat], Optional[_Stat]]]


class _Recorder:
    """Mutable collector the replaced functions append to.

    ``stdout`` and ``stderr`` are filled in when :func:`_observed` exits, since
    that is where the captured streams are drained.
    """

    def __init__(self) -> None:
        self.writes: List[str] = []
        self.launches: List[str] = []
        self.stdout: str = ""
        self.stderr: str = ""


def _snapshot(root: Path) -> Dict[str, _Stat]:
    """Describe every entry under ``root`` well enough to notice a change.

    Returns:
        ``relative path -> (file type, permission bits, size, mtime_ns)``. mtime
        in nanoseconds because a rewrite with identical content changes nothing
        else, and second-resolution mtimes would miss it.
    """
    entries: Dict[str, _Stat] = {}
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        entries[path.relative_to(root).as_posix()] = (
            stat.S_IFMT(info.st_mode),
            stat.S_IMODE(info.st_mode),
            info.st_size,
            info.st_mtime_ns,
        )
    return entries


def _tree_difference(
    before: Dict[str, _Stat], after: Dict[str, _Stat]
) -> Dict[str, Tuple[Optional[_Stat], Optional[_Stat]]]:
    """Entries that were added, removed, or changed between two snapshots."""
    return {
        name: (before.get(name), after.get(name))
        for name in sorted(set(before) | set(after))
        if before.get(name) != after.get(name)
    }


@contextmanager
def _observed(workspace: Path) -> Iterator[_Recorder]:
    """Run a block with writes and process starts intercepted, from ``workspace``.

    Also swaps :data:`sys.stdout` and :data:`sys.stderr` for in-memory streams and
    changes the working directory, because every entry point derives its
    containment root from :func:`pathlib.Path.cwd` and writes its report to
    ``sys.stdout``.

    Written as a context manager rather than with the ``monkeypatch`` fixture for
    the reason ``tests/property/test_prop_pathguard.py`` records: a function-scoped
    fixture is set up once per test, and this has to happen once per example.

    ``subprocess.run`` records and returns a benign
    :class:`subprocess.CompletedProcess` -- letting the caller continue, so that a
    *later* file write is observed too rather than being masked by an exception.
    Every other process starter records and then raises: those are reachable only
    by bypassing :mod:`iacreview.proc`, and continuing from one would mean
    continuing from a violation.

    Yields:
        The recorder. Its lists are complete only after the block exits, since
        that is where the streams are drained.
    """
    recorder = _Recorder()
    originals: List[Tuple[Any, str, Any]] = []

    def replace(target: Any, name: str, value: Any) -> None:
        originals.append((target, name, getattr(target, name)))
        setattr(target, name, value)

    def make_opener(original: Any, label: str) -> Any:
        def opener(file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
            requested = kwargs.get("mode", mode)
            if isinstance(requested, str) and (
                set(requested) & _WRITE_MODE_CHARACTERS
            ):
                recorder.writes.append(
                    "{0}({1!r}, mode={2!r})".format(label, file, requested)
                )
            return original(file, mode, *args, **kwargs)

        return opener

    def make_os_opener(original: Any) -> Any:
        def os_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> Any:
            if flags & _WRITE_FLAGS:
                recorder.writes.append(
                    "os.open({0!r}, flags={1:#o})".format(path, flags)
                )
            return original(path, flags, *args, **kwargs)

        return os_open

    def make_mutator(original: Any, label: str) -> Any:
        def mutator(*args: Any, **kwargs: Any) -> Any:
            recorder.writes.append("{0}({1})".format(label, _first_argument(args)))
            return original(*args, **kwargs)

        return mutator

    def subprocess_run(*args: Any, **kwargs: Any) -> Any:
        argv: Any = args[0] if args else kwargs.get("args")
        recorder.launches.append("subprocess.run({0!r})".format(argv))
        return subprocess.CompletedProcess(
            args=argv, returncode=0, stdout="", stderr=""
        )

    def make_blocker(label: str) -> Any:
        def blocker(*args: Any, **kwargs: Any) -> Any:
            recorder.launches.append(
                "{0}({1})".format(label, _first_argument(args))
            )
            raise AssertionError(
                "{0} bypasses iacreview.proc and must not be reached".format(label)
            )

        return blocker

    # All three spellings: they are three attribute lookups, and the shipped code
    # reaches the filesystem through each of them (see the module docstring).
    replace(builtins, "open", make_opener(builtins.open, "open"))
    replace(io, "open", make_opener(io.open, "io.open"))
    replace(os, "open", make_os_opener(os.open))
    for name in _MUTATING_OS_FUNCTIONS:
        if hasattr(os, name):
            replace(os, name, make_mutator(getattr(os, name), "os." + name))
    replace(subprocess, "run", subprocess_run)
    replace(subprocess, "Popen", make_blocker("subprocess.Popen"))
    for name in _PROCESS_STARTING_OS_FUNCTIONS:
        if hasattr(os, name):
            replace(os, name, make_blocker("os." + name))

    out, err = io.StringIO(), io.StringIO()
    saved_stdout, saved_stderr = sys.stdout, sys.stderr
    saved_cwd = os.getcwd()
    sys.stdout, sys.stderr = out, err
    # os.chdir is not in the intercepted set: it changes no directory entry.
    os.chdir(str(workspace))
    try:
        yield recorder
    finally:
        os.chdir(saved_cwd)
        sys.stdout, sys.stderr = saved_stdout, saved_stderr
        for target, name, value in reversed(originals):
            setattr(target, name, value)
        recorder.stdout = out.getvalue()
        recorder.stderr = err.getvalue()


def _first_argument(args: Sequence[Any]) -> str:
    """Render the first positional argument of an intercepted call, or nothing."""
    return repr(args[0]) if args else ""


def _run_entry_point(
    module: types.ModuleType, argv: Sequence[str], workspace: Path
) -> Observation:
    """Call ``module.main(argv)`` inside an observed window from ``workspace``.

    Args:
        module: An entry point module loaded by :func:`entry_points`.
        argv: Arguments after the program name.
        workspace: Working directory, and the tree the snapshot covers.

    Returns:
        The :class:`Observation`. ``main()`` is called rather than the script
        being spawned, which is what makes the interception possible at all: a
        child process would have its own :mod:`subprocess` and its own
        ``builtins``.
    """
    before = _snapshot(workspace)
    with _observed(workspace) as recorder:
        exit_code = module.main(list(argv))
    return Observation(
        exit_code=exit_code,
        stdout=recorder.stdout,
        stderr=recorder.stderr,
        writes=list(recorder.writes),
        launches=list(recorder.launches),
        tree_changes=_tree_difference(before, _snapshot(workspace)),
    )


def _probe_the_observer(workspace: Path) -> None:
    """Assert that the observer can still see a write, a launch and a change.

    The positive control for Property 20. Inside one observed window this writes
    a file with :meth:`pathlib.Path.write_text` (which reaches ``io.open``, the
    spelling ``builtins.open`` alone would miss) and calls
    :func:`iacreview.proc.run`, the funnel every Source uses. All three signals
    must fire; if any of them stops firing, "nothing was observed" stops meaning
    "nothing happened".

    No child process is started: ``subprocess.run`` is already replaced inside the
    window, so ``argv[0]`` only has to resolve, and :data:`sys.executable` does
    that without ``PATH`` and without any external tool.

    Raises:
        AssertionError: One of the three mechanisms observed nothing.
    """
    probe = workspace / PROBE_NAME
    before = _snapshot(workspace)
    try:
        with _observed(workspace) as recorder:
            probe.write_text("probe", encoding="utf-8")
            proc.run([sys.executable, "-c", "pass"], timeout_s=30)
        changes = _tree_difference(before, _snapshot(workspace))
        assert recorder.writes, "the write interception observed nothing"
        assert recorder.launches, "the process interception observed nothing"
        assert PROBE_NAME in changes, "the workspace snapshot observed no change"
    finally:
        if probe.exists():
            probe.unlink()


def _requests_help(argv: Sequence[str]) -> bool:
    """Whether ``argv`` asks for ``--help``, which is a *valid* argument vector.

    ``argparse`` prints usage and exits 0 for a help request, so such a vector is
    outside Property 20's quantifier rather than a counterexample to it. Tokens
    beginning ``-h`` are covered as well: ``argparse`` clusters short options, so
    ``-hx`` fires the help action before it reaches the unknown one.
    :func:`strategies.invalid_argument_vectors` draws one branch from arbitrary
    text, which is the only way such a token can appear here.
    """
    return any(token == "--help" or token.startswith("-h") for token in argv)


@pytest.fixture(scope="module")
def entry_points(plugin_root: Path) -> Dict[str, types.ModuleType]:
    """The six entry point scripts, imported once, keyed by relative path.

    They live under ``skills/`` and are meant to be run as files, so they are
    loaded by location rather than by package path -- the same approach
    ``tests/integration/test_tool_unavailable.py`` uses. Module-scoped: executing
    a module body once per example would import the world a hundred times, and a
    function-scoped fixture cannot be combined with ``@given`` anyway.
    """
    modules: Dict[str, types.ModuleType] = {}
    for relative in ENTRY_POINTS:
        name = "prop_security_{0}".format(Path(relative).stem)
        spec = importlib.util.spec_from_file_location(
            name, plugin_root / relative
        )
        assert spec is not None and spec.loader is not None, relative
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        modules[relative] = module
    return modules


@pytest.fixture(scope="module")
def workspace(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A workspace holding one reviewable Template, shared by every example.

    Module-scoped for the reason above. Sharing is safe because no example is
    allowed to change it: that is the property.
    """
    root = tmp_path_factory.mktemp("security")
    (root / TEMPLATE_NAME).write_text(TEMPLATE_BODY, encoding="utf-8")
    return root


# Feature: aws-iac-review-agent-plugin, Property 20: *For any* invalid argument vector, the entry point exits with a documented non-zero exit code drawn from the defined set, and no subprocess is spawned and no file is created or modified.
@settings(max_examples=100, deadline=None)
@given(argv=S.invalid_argument_vectors())
def test_an_invalid_argv_exits_without_starting_a_process_or_writing_a_file(
    entry_points: Dict[str, types.ModuleType],
    workspace: Path,
    argv: List[str],
) -> None:
    """**Validates: Requirements 16.7, 16.8**

    Each example runs the drawn vector against all six entry points. They share
    :func:`iacreview.bootstrap.run_entry_point` but not their parsers, and one of
    them supplies no ``validate`` callable at all, so "the entry point" in the
    property statement means all of them.

    Four assertions per invocation. The exit code is non-zero *and* documented,
    which is one assertion and not two: a plausible failure here is an
    undocumented status such as ``argparse``'s own 2 leaking through unmapped, or
    a ``SystemExit`` reaching the caller. ``launches`` and ``writes`` empty is the
    interception layer, ``tree_changes`` empty is the snapshot layer, and the
    stderr/stdout pair is the non-vacuity check: a rejected invocation must have
    said why on stderr and must have produced no report.

    ``deadline=None``: an example walks a directory tree twelve times and calls
    six ``main()`` functions, so its wall-clock time is a property of the
    filesystem, not of the code under test.
    """
    # A help request is a valid argument vector, so it is not a counterexample.
    assume(not _requests_help(argv))

    # The positive control, run first so that a broken observer fails before any
    # absence is asserted on its output.
    _probe_the_observer(workspace)

    for relative, module in entry_points.items():
        observation = _run_entry_point(module, argv, workspace)
        context = (relative, argv, observation.exit_code)

        assert observation.exit_code in DEFINED_NONZERO_EXIT_CODES, context
        assert observation.launches == [], context + (observation.launches,)
        assert observation.writes == [], context + (observation.writes,)
        assert observation.tree_changes == {}, context + (observation.tree_changes,)
        # Non-vacuity: the rejection was deliberate and nothing was produced.
        assert observation.stderr, context
        assert observation.stdout == "", context + (observation.stdout,)


# ---------------------------------------------------------------------------
# Property 22: temporary file safety
# ---------------------------------------------------------------------------

class _BlockFailed(Exception):
    """Deliberate failure raised inside a ``secure_temp_file`` block.

    A dedicated class, so that catching it cannot swallow a real failure raised by
    the helper itself.
    """


# Feature: aws-iac-review-agent-plugin, Property 22: *For any* suffix, the temporary file helper yields a path whose permission mode is `0600`, and after the context exits — whether normally or by exception — that path no longer exists.
@settings(max_examples=100, deadline=None)
@given(suffix=S.temp_file_suffixes(), raise_inside=st.booleans())
def test_a_temporary_file_is_private_and_does_not_outlive_its_block(
    suffix: str, raise_inside: bool
) -> None:
    """**Validates: Requirements 9.6**

    Both exit paths are drawn rather than written as two tests, because the
    property is one statement about both and the assertions after the block are
    identical: the same path, the same non-existence, from a block that returned
    and from a block that raised.

    Three things are checked inside the block, and each is a premise the
    after-assertion needs. The path exists -- otherwise "no longer exists" is
    satisfied by a helper that created nothing. Its mode is exactly
    :data:`iacreview.pathguard.TEMP_FILE_MODE`, read from the filesystem rather
    than from ``mkstemp``'s promise. And it is registered, which is the mechanism
    that removes it on ``SIGTERM``; a file that were absent from the registry
    would still pass the after-assertion here while leaking on abnormal
    termination (``tests/unit/test_tempfile.py`` pins that case in a real child
    process).

    The mode assertion is POSIX-conditional: ``0600`` is not expressible on
    Windows, where ``os.chmod`` cannot clear the group and other bits. The rest of
    the property is platform-independent and is asserted everywhere.

    ``deadline=None``: every example creates and removes a file in the system
    temporary directory.
    """
    created: List[Path] = []

    def enter_and_exit() -> None:
        with pathguard.secure_temp_file(suffix) as path:
            created.append(path)
            assert path.is_file(), suffix
            assert path.name.endswith(suffix), (path.name, suffix)
            if os.name == "posix":
                mode = stat.S_IMODE(path.stat().st_mode)
                assert mode == pathguard.TEMP_FILE_MODE, (oct(mode), suffix)
            assert path in pathguard.registered_temp_files(), suffix
            if raise_inside:
                raise _BlockFailed(suffix)

    if raise_inside:
        with pytest.raises(_BlockFailed):
            enter_and_exit()
    else:
        enter_and_exit()

    assert len(created) == 1, suffix
    path = created[0]
    assert not path.exists(), (str(path), raise_inside)
    assert path not in pathguard.registered_temp_files(), (str(path), raise_inside)


# ---------------------------------------------------------------------------
# Property 23: bounded stderr transcription
# ---------------------------------------------------------------------------

#: Every sequence :meth:`str.splitlines` treats as a line boundary, in the order
#: a regex has to try them (``\r\n`` before ``\r``). Written out so that the
#: oracle below shares no code with the implementation: ``iacreview.errors``
#: calls ``splitlines``, and an oracle that also called it would agree with the
#: implementation by construction rather than by being right.
_LINE_BOUNDARIES: Tuple[str, ...] = (
    "\r\n",
    "\n",
    "\r",
    "\v",
    "\f",
    "\x1c",
    "\x1d",
    "\x1e",
    "\x85",
    "\u2028",
    "\u2029",
)

_LINE_BOUNDARY = re.compile("|".join(re.escape(sep) for sep in _LINE_BOUNDARIES))
_TRAILING_BOUNDARY = re.compile("(?:{0})$".format(_LINE_BOUNDARY.pattern))


def _lines_of(text: str) -> List[str]:
    """Split ``text`` into lines, independently of :meth:`str.splitlines`.

    The oracle for Property 23's "line ``i`` of the input text". A boundary at the
    very end terminates the last line rather than starting an empty one, which is
    the one place a naive ``split`` disagrees with what a reader means by "line".

    Args:
        text: External tool stderr, as captured.

    Returns:
        The lines, without their terminators. Empty for empty input.
    """
    if not text:
        return []
    parts = _LINE_BOUNDARY.split(text)
    if _TRAILING_BOUNDARY.search(text):
        parts = parts[:-1]
    return parts


@contextmanager
def _timing_out_subprocess(stderr_text: str) -> Iterator[None]:
    """Make the next ``subprocess.run`` behave as a tool that timed out.

    The realistic way stderr reaches a StructuredError: :func:`iacreview.proc.run`
    catches :class:`subprocess.TimeoutExpired`, reads its partial ``stderr``, and
    raises :class:`~iacreview.errors.ToolTimeoutError` carrying it. Simulated at
    the ``subprocess`` boundary rather than by constructing the exception
    ourselves, so that the transcription is exercised through the same call chain
    a real cfn-lint timeout takes -- and with no external tool installed and no
    test that has to wait for a real timeout.
    """
    original = subprocess.run

    def timing_out(*args: Any, **kwargs: Any) -> Any:
        argv: Any = args[0] if args else kwargs.get("args")
        raise subprocess.TimeoutExpired(
            cmd=argv, timeout=kwargs.get("timeout", 1), stderr=stderr_text
        )

    subprocess.run = timing_out  # type: ignore[assignment]
    try:
        yield
    finally:
        subprocess.run = original  # type: ignore[assignment]


# Feature: aws-iac-review-agent-plugin, Property 23: *For any* stderr text produced by an external tool, the `stderr_head` field of the resulting structured error contains at most 5 elements, and element `i` equals line `i` of the input text.
@settings(max_examples=100, deadline=None)
@given(text=S.stderr_texts(), error_class=st.sampled_from(ERROR_CLASS_HIERARCHY))
def test_stderr_transcription_is_capped_and_copies_the_leading_lines(
    text: str, error_class: type
) -> None:
    """**Validates: Requirements 15.7**

    Two paths to the same field, and both are checked on every example.

    The *direct* path draws one of the thirteen declared exception classes and
    constructs it with the text. The cap lives in the base class, so every class
    inherits it -- and asserting that over the whole
    :data:`iacreview.errors.ERROR_CLASS_HIERARCHY` is what would catch a subclass
    that overrode ``__init__`` and copied stderr itself, which
    :class:`~iacreview.errors.TemplateParseError` already does for its position
    fields.

    The *funnel* path runs :func:`iacreview.proc.run` against a
    ``subprocess.run`` that raises :class:`subprocess.TimeoutExpired` carrying the
    same text, which is how a real tool's stderr arrives. Its ``stderr_head`` must
    equal the direct path's: a wrapper that re-wrapped, joined or re-split the
    output on its way through would differ here while the direct path stayed
    correct.

    The bound is asserted twice over, once as a length and once as an equality
    against the independently computed prefix, and the final assertion requires
    the cap to have *done* something whenever the input has more lines than the
    bound. That last one is what keeps the property from being satisfied by a
    field that is always empty.

    ``deadline=None``: the funnel path resolves ``argv[0]`` on ``PATH``, which is
    a filesystem operation whose timing says nothing about this code.
    """
    expected = _lines_of(text)

    direct = error_class("a tool failed", stderr=text).to_structured_error()
    assert set(direct) == set(STRUCTURED_ERROR_KEYS), error_class.__name__
    head = direct["stderr_head"]

    assert isinstance(head, list), (error_class.__name__, head)
    assert len(head) <= STDERR_HEAD_MAX_LINES, (error_class.__name__, head)
    assert head == expected[:STDERR_HEAD_MAX_LINES], (error_class.__name__, text)

    with _timing_out_subprocess(text):
        with pytest.raises(ToolTimeoutError) as caught:
            proc.run([sys.executable, "-c", "pass"], timeout_s=1)
    from_funnel = caught.value.to_structured_error(source="cfn-lint")
    assert from_funnel["stderr_head"] == head, (from_funnel["stderr_head"], head)

    # Non-vacuity of the cap: when the tool said more than the bound allows, the
    # transcription is exactly the bound and strictly shorter than the input.
    if len(expected) > STDERR_HEAD_MAX_LINES:
        assert len(head) == STDERR_HEAD_MAX_LINES, head
        assert len(head) < len(expected), (head, expected)


# ---------------------------------------------------------------------------
# Property 29: credential values never reach Evidence
# ---------------------------------------------------------------------------

#: The orchestrator, whose report is the one a consumer reads. Property 29 is
#: stated over "the resulting Review_Report", so it is asserted on the whole
#: report of the entry point that assembles one from every Source.
ORCHESTRATOR = "skills/iac-review/scripts/run_iac_review.py"

#: Source selection for Property 29's review. The IAM Source reads the Template
#: in process and starts nothing, so the example needs neither cfn-lint nor
#: cfn-guard installed. The Source does not have to *find* anything: the Excerpts
#: under test come from the agent findings file, which is the only intake that
#: produces an ``Excerpt`` in v0.1 (the deterministic Sources set it to ``None``,
#: which is why a report of theirs alone would satisfy this property vacuously).
IAM_SOURCE_ARGUMENTS: Tuple[str, ...] = ("--sources", "iam-review")

#: Name of the agent findings file inside the workspace.
AGENT_FINDINGS_NAME = "agent-findings.json"

#: Excerpt of the control entry: Template text from a location that triggers no
#: redaction, holding neither the credential nor the ``NoEcho`` Parameter's name.
#: It must survive into the report verbatim.
CONTROL_EXCERPT = "Type: AWS::SecretsManager::Secret"

#: ``Resource`` of each generated entry. Distinct per entry and non-null, so no
#: two share a deduplication key (Requirement 14 AC5) and the four entries reach
#: the report as four Findings -- which lets the counts below be exact instead of
#: lower bounds.
ENTRY_RESOURCES: Tuple[Optional[str], ...] = ("A", "B", "C", None)


def _agent_entry(
    base: Dict[str, Any],
    *,
    resource: Optional[str],
    template_path: Optional[List[Any]],
    excerpt: str,
    rule_id: Optional[str],
) -> Dict[str, Any]:
    """Rewrite a Finding payload into one agent findings entry.

    Only the fields this property is about are set; everything else is whatever
    :func:`strategies.findings` drew, so the entry is a generated Finding rather
    than a hand-written one.

    Args:
        base: A Finding payload from :func:`iacreview.finding.to_dict`.
        resource: ``Resource`` value, drawn from :data:`ENTRY_RESOURCES`.
        template_path: ``Location.TemplatePath``, which is one of the two ways a
            ``NoEcho`` Parameter's location is recognized.
        excerpt: The single ``Evidence[].Excerpt``.
        rule_id: The single ``Evidence[].RuleId``, or ``None``.

    Returns:
        A new payload; ``base`` is not modified.
    """
    entry = copy.deepcopy(base)
    entry["Source"] = [AGENT_SOURCE]
    entry["Resource"] = resource
    entry["Location"]["File"] = TEMPLATE_NAME
    entry["Location"]["TemplatePath"] = template_path
    # Exactly one Evidence entry, so the counts asserted below are exact.
    entry["Evidence"] = [
        {
            "Source": AGENT_SOURCE,
            "Detail": "The agent quoted this location.",
            "RuleId": rule_id,
            "Excerpt": excerpt,
        }
    ]
    return entry


def _credential_entries(
    base: Dict[str, Any], parameter: str, secret: str, credential_rule: str
) -> List[Dict[str, Any]]:
    """The four entries of the agent findings file: three triggers and a control.

    The three triggering shapes are the ones design.md's O-11 defines, and they
    are deliberately different from each other so that no single implementation
    shortcut covers all three:

    1. ``TemplatePath`` addressing the ``NoEcho`` Parameter's ``Default``, with an
       Excerpt that does **not** name the Parameter -- the case where the
       credential *is* the quoted text.
    2. An Excerpt naming the Parameter, at a resource property that has no
       special path -- the case where only the text betrays the reference.
    3. A ``RuleId`` from :data:`iacreview.finding.CREDENTIAL_RULE_IDS`, with
       neither the path nor the name to go on.

    The fourth entry triggers nothing and must reach the report unchanged. Without
    it, a redaction that replaced every Excerpt would satisfy Property 29.
    """
    return [
        _agent_entry(
            base,
            resource=ENTRY_RESOURCES[0],
            template_path=["Parameters", parameter, "Default"],
            excerpt="Default: {0}".format(secret),
            rule_id=None,
        ),
        _agent_entry(
            base,
            resource=ENTRY_RESOURCES[1],
            template_path=["Resources", "A", "Properties", "SecretString"],
            excerpt="SecretString: !Ref {0}  # {1}".format(parameter, secret),
            rule_id=None,
        ),
        _agent_entry(
            base,
            resource=ENTRY_RESOURCES[2],
            template_path=["Resources", "A", "Properties", "SecretString"],
            excerpt=secret,
            rule_id=credential_rule,
        ),
        _agent_entry(
            base,
            resource=ENTRY_RESOURCES[3],
            template_path=["Resources", "A", "Type"],
            excerpt=CONTROL_EXCERPT,
            rule_id=None,
        ),
    ]


def _excerpts_of(report: Dict[str, Any]) -> List[str]:
    """Every ``Evidence[].Excerpt`` in ``report``, including the ``None`` ones."""
    return [
        entry["Excerpt"]
        for finding in report["findings"]
        for entry in finding["Evidence"]
    ]


# Feature: aws-iac-review-agent-plugin, Property 29: *For any* Template containing a value at a redaction-triggering location (a parameter declared `NoEcho`, or a location flagged by a credential-detection rule), no `Evidence[].Excerpt` in the resulting Review_Report contains that value.
@settings(max_examples=100, deadline=None)
@given(
    template=S.credential_templates(),
    base=S.findings(),
    finding_type=st.sampled_from(
        tuple(name for name in FINDING_TYPES if name != VALIDITY_TYPE)
    ),
    credential_rule=st.sampled_from(tuple(sorted(CREDENTIAL_RULE_IDS))),
)
def test_a_credential_value_reaches_no_excerpt_in_the_report(
    entry_points: Dict[str, types.ModuleType],
    workspace: Path,
    template: Tuple[Dict[str, Any], str],
    base: Finding,
    finding_type: str,
    credential_rule: str,
) -> None:
    """**Validates: Requirements 9.2**

    The whole pipeline, end to end, because the property is about what leaves it.
    The Template carries the secret twice -- as the ``NoEcho`` Parameter's
    ``Default`` and inside a resource property -- and the agent findings file
    quotes it at three redaction-triggering locations plus one that triggers
    nothing.

    The leak is looked for in the **whole report**, not only in the field the
    property names. A credential that moved from ``Excerpt`` into ``Detail`` or
    into ``Recommendation`` would satisfy the letter of the property and be no
    less of a leak, so the serialized report is searched as text and the Excerpts
    are then checked individually to localize a failure.

    Two premises are asserted before the absence, and both are load-bearing:
    every one of the three shapes really is a redaction-triggering location
    according to :func:`iacreview.finding.redaction_trigger`, and ``errors[]`` is
    empty, meaning all four entries were *accepted* rather than dropped for a
    schema violation. A dropped entry would remove the Excerpt from the report and
    make the absence trivial.

    ``FindingType`` excludes ``Validity``: Requirement 7 AC6 requires a
    ``Validity`` ``CRITICAL`` Finding to carry a deployment-blocking ``RuleId``,
    which contradicts the credential-detection ``RuleId`` shape 3 needs. That
    interaction is Property 8's subject, and forcing the two together here would
    only test the schema validator.

    ``deadline=None``: every example writes two files and runs a review.
    """
    document, secret = template
    noecho = noecho_parameter_names(document)
    # The strategy's contract; asserted rather than assumed, since every trigger
    # below depends on it.
    assert noecho, document
    parameter = sorted(noecho)[0]

    payload = to_dict(base)
    payload["FindingType"] = finding_type
    entries = _credential_entries(payload, parameter, secret, credential_rule)

    for index, entry in enumerate(entries[:3]):
        evidence = entry["Evidence"][0]
        trigger = redaction_trigger(
            excerpt=evidence["Excerpt"],
            rule_id=evidence["RuleId"],
            template_path=entry["Location"]["TemplatePath"],
            noecho_parameters=noecho,
        )
        assert trigger is not RedactionTrigger.NONE, (index, evidence)
    control_evidence = entries[3]["Evidence"][0]
    assert (
        redaction_trigger(
            excerpt=control_evidence["Excerpt"],
            rule_id=control_evidence["RuleId"],
            template_path=entries[3]["Location"]["TemplatePath"],
            noecho_parameters=noecho,
        )
        is RedactionTrigger.NONE
    ), control_evidence

    (workspace / TEMPLATE_NAME).write_text(S.dump_yaml(document), encoding="utf-8")
    (workspace / AGENT_FINDINGS_NAME).write_text(
        json.dumps({"findings": entries}, sort_keys=True), encoding="utf-8"
    )
    try:
        observation = _run_entry_point(
            entry_points[ORCHESTRATOR],
            [
                "--target",
                TEMPLATE_NAME,
                "--agent-findings",
                AGENT_FINDINGS_NAME,
                *IAM_SOURCE_ARGUMENTS,
            ],
            workspace,
        )
    finally:
        # The workspace is shared by every example of every test in this module,
        # and Property 20 asserts it is unchanged. Restore it.
        (workspace / AGENT_FINDINGS_NAME).unlink()
        (workspace / TEMPLATE_NAME).write_text(TEMPLATE_BODY, encoding="utf-8")

    assert observation.exit_code == exitcodes.OK, observation.stderr
    assert observation.stdout, observation.stderr
    report = json.loads(observation.stdout)

    # Premise: nothing was dropped, so every Excerpt below really is in play.
    assert report["errors"] == [], report["errors"]
    assert len(report["findings"]) == len(entries), report["findings"]

    excerpts = _excerpts_of(report)
    assert len(excerpts) == len(entries), excerpts

    # The property, first over the whole report and then per Excerpt.
    assert secret not in observation.stdout, (
        "the credential value reached the report"
    )
    for excerpt in excerpts:
        assert excerpt is None or secret not in excerpt, excerpt

    # Non-vacuity: three Excerpts were withheld and the fourth was not.
    assert excerpts.count(REDACTED_EXCERPT) == 3, excerpts
    assert excerpts.count(CONTROL_EXCERPT) == 1, excerpts
