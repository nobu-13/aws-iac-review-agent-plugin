"""CDK project detection, template discovery, and the gated ``cdk synth`` call.

Requirement 8 splits into two halves that this module keeps strictly apart.

**Detection and discovery are always safe.** :func:`detect_cdk_project`,
:func:`find_synthesized_templates`, :func:`find_templates` and
:func:`partition_templates` only read directory entries. They start no process,
so no code path through them can execute project code (Requirement 8 AC3).
Discovery is what makes a CDK project reviewable at all: a synthesized
``cdk.out/*.template.json`` is an ordinary CloudFormation Template and goes
through the same pipeline as a hand-written one (AC1, AC9).

**Synthesis is gated.** :func:`synth_if_confirmed` is the only function here
that can start a process, and it does so only when ``confirmed`` is ``True``.
With ``confirmed=False`` there is no reachable call to :mod:`iacreview.proc`,
:mod:`shutil` or :mod:`subprocess`; the function returns whatever was already
synthesized (AC5). That structural absence, not a runtime check, is what
Property 25 asserts.

Why the gate is a boolean parameter rather than a prompt: Requirement 16 AC9
forbids reading a prompt from stdin, so "explicit user confirmation" (AC4) is
expressed as the ``--confirm-cdk-synth`` flag that the host Agent adds *after*
showing the user :data:`SYNTH_WARNING`. This module states the warning on stderr
on both paths -- confirmed and not -- so that the risk is on the record even
when a caller passes the flag without having shown it.

``cdk synth`` executes the project's TypeScript or Python code, and with it the
lifecycle scripts of every dependency the project installs. Nothing in this
plugin sandboxes that (AC11): :func:`iacreview.proc.run` withholds AWS
credentials from the child and nothing more. Once started, the synth process has
the full authority of the invoking user.

Two deliberate limitations in discovery, both narrowing the surface rather than
guessing:

``cdk.out`` is the only output directory consulted
    ``cdk.json`` may set an ``output`` key, and honouring it would mean reading
    an untrusted config file to decide which directory to trust. design.md fixes
    the name as a constant instead, in the same list that
    :data:`EXCLUDED_DIRECTORY_NAMES` is drawn from. A project using a custom
    output directory is reviewed by pointing ``--target`` at that directory.

nested cloud assemblies are not traversed
    Only ``cdk.out/*.template.json`` is enumerated, not
    ``cdk.out/assembly-*/*.template.json``. A nested assembly belongs to a stage
    whose templates are also written at the top level for the stacks that are
    directly synthesizable, and recursing would report the same stack twice.

Directory traversal is deterministic by construction (Requirement 10 AC3):
:func:`os.walk` yields entries in filesystem order, which differs between
machines, so the collected list is sorted by path string before it is returned
and never consumed in walk order.
"""

from __future__ import annotations

import os
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import FrozenSet, Iterator, List, Optional, Tuple, Union

from iacreview import proc
from iacreview.errors import (
    InputNotFoundError,
    InvalidArgumentsError,
    ToolExecutionError,
    ToolTimeoutError,
)
from iacreview.toolcheck import CDK, require_known_tool

__all__ = [
    "CDK_CONFIG_FILENAME",
    "CDK_OUTPUT_DIRECTORY_NAME",
    "SYNTHESIZED_TEMPLATE_SUFFIX",
    "TEMPLATE_SUFFIXES",
    "EXCLUDED_DIRECTORY_NAMES",
    "SYNTH_TIMEOUT_S",
    "SYNTH_SUBCOMMAND",
    "SYNTH_WARNING",
    "SYNTH_NOT_CONFIRMED_NOTICE",
    "NO_FALLBACK_REMEDIATION",
    "CdkDetection",
    "detect_cdk_project",
    "find_synthesized_templates",
    "find_templates",
    "partition_templates",
    "build_synth_argv",
    "synth_if_confirmed",
]

#: File whose presence identifies a CDK project (Requirement 8 AC2).
CDK_CONFIG_FILENAME = "cdk.json"

#: CDK's default cloud assembly directory. See the module docstring for why the
#: ``output`` key of ``cdk.json`` is not consulted.
CDK_OUTPUT_DIRECTORY_NAME = "cdk.out"

#: Suffix of a synthesized Template inside the cloud assembly. Matched
#: case-insensitively, like :data:`TEMPLATE_SUFFIXES`.
SYNTHESIZED_TEMPLATE_SUFFIX = ".template.json"

#: Filename suffixes collected by :func:`find_templates` (design.md, Review Flow
#: and Orchestration). ``.template.json`` is already covered by ``.json``; it is
#: listed because design.md lists it, and because the list doubles as the
#: documentation of what a directory scan considers a candidate Template.
#:
#: Matching is case-insensitive so that a file named ``Template.YAML`` is found
#: on a case-sensitive filesystem too. Without that, the same directory tree
#: would produce different reports on Linux and on macOS.
TEMPLATE_SUFFIXES: Tuple[str, ...] = (
    ".yaml",
    ".yml",
    ".json",
    ".template",
    ".template.json",
)

#: Directory names never descended into by :func:`find_templates`.
#:
#: ``cdk.out`` is excluded because its Templates are reported as their own group
#: (Requirement 8 AC10) via :func:`find_synthesized_templates`; including them
#: here would merge the two groups and review each synthesized Template twice.
#: The other three hold no reviewable Template but plenty of JSON, and walking
#: ``node_modules`` in particular turns a scan of a small project into a scan of
#: tens of thousands of files.
EXCLUDED_DIRECTORY_NAMES: FrozenSet[str] = frozenset(
    {
        CDK_OUTPUT_DIRECTORY_NAME,
        "node_modules",
        ".git",
        ".venv",
    }
)

#: Wall-clock limit for one ``cdk synth`` (Requirement 8 AC6). Larger than the
#: 60 seconds the static analyzers get, because synthesis compiles and runs the
#: project: a TypeScript app with a cold ``ts-node`` start regularly needs tens
#: of seconds.
SYNTH_TIMEOUT_S = 120

#: The single subcommand this module ever invokes. No user-supplied value is
#: appended to it, so the ``argv`` array is fully plugin-controlled.
SYNTH_SUBCOMMAND = "synth"

#: The warning Requirement 8 AC4 requires before ``cdk synth`` may run. Stated
#: once here so the Skill documentation, the host Agent's prompt, and the stderr
#: diagnostic cannot describe the risk differently.
SYNTH_WARNING = (
    "cdk synth executes this project's own code and the lifecycle scripts of "
    "its dependencies. This plugin provides no sandboxing for that execution: "
    "the synth process runs with your full user privileges. Review CDK source "
    "you do not trust only after inspecting it."
)

#: Stated alongside :data:`SYNTH_WARNING` when the confirmation is absent, so
#: that "nothing was reviewed" is never silent (Requirement 8 AC5).
SYNTH_NOT_CONFIRMED_NOTICE = (
    "cdk synth was not run because it was not explicitly confirmed; only "
    "already-synthesized templates under {0}/ are reviewed.".format(
        CDK_OUTPUT_DIRECTORY_NAME
    )
)

#: Attached to a failed synth. Requirement 8 AC7 forbids falling back to any
#: alternative execution mode, so the remediation is an instruction to the user
#: rather than a second strategy the plugin could try.
NO_FALLBACK_REMEDIATION = (
    "Run `cdk synth` yourself, fix the reported error, then re-run the review "
    "against the generated {0}/ directory. No alternative synthesis mode is "
    "attempted.".format(CDK_OUTPUT_DIRECTORY_NAME)
)


def _warn(message: str) -> None:
    """Emit a diagnostic on stderr.

    stdout carries the report and must stay byte-identical between runs
    (Requirement 16 AC11), so no diagnostic goes there.
    """
    print("warning: {0}".format(message), file=sys.stderr)


# ---------------------------------------------------------------------------
# Directory validation and containment
# ---------------------------------------------------------------------------


def _validated_directory(directory: Union[str, Path]) -> Path:
    """Normalize ``directory`` and confirm it is an existing directory.

    Containment of the caller's ``--target`` inside the workspace root is
    :func:`iacreview.pathguard.resolve_within`'s job and has already happened by
    the time an orchestrator calls into this module; repeating it here would
    require this module to know the workspace root, which design.md's API for
    :func:`detect_cdk_project` does not carry. What is checked here is only what
    every function below depends on: a resolved, existing directory to compare
    discovered entries against.

    Returns:
        The resolved absolute directory.

    Raises:
        InvalidArgumentsError: ``directory`` is blank, cannot be normalized, or
            names a file rather than a directory.
        InputNotFoundError: ``directory`` does not exist.
    """
    text = str(directory)
    if not text.strip():
        raise InvalidArgumentsError("directory must be a non-empty path")

    try:
        # strict=False and an explicit existence check below: a missing
        # directory should report as input_not_found, not as an OS error.
        resolved = Path(text).resolve(strict=False)
    except (OSError, ValueError) as exc:
        raise InvalidArgumentsError(
            "directory path cannot be normalized: {0!r} ({1})".format(text, exc)
        ) from exc

    if not resolved.exists():
        raise InputNotFoundError(
            "directory does not exist: {0!r} (resolved: {1})".format(text, resolved)
        )
    if not resolved.is_dir():
        raise InvalidArgumentsError(
            "expected a directory, got a file: {0}".format(resolved)
        )
    return resolved


def _is_contained(candidate: Path, resolved_root: Path) -> bool:
    """Report whether ``candidate`` still resolves inside ``resolved_root``.

    A discovered entry is inside the scanned tree by construction, but a symlink
    inside it may point anywhere. :func:`os.walk` is called with
    ``followlinks=False``, which stops *directory* symlinks from being descended
    but says nothing about a symlinked *file*. Skipping such an entry keeps a
    link named ``stack.yaml`` from pulling an arbitrary file into the review,
    and keeps discovery consistent with the containment
    :func:`iacreview.pathguard.resolve_within` would later apply.

    Args:
        candidate: Path to test. Resolved here, so symlinks are followed.
        resolved_root: Root to compare against, already ``resolve``\\ d.
    """
    try:
        candidate.resolve(strict=False).relative_to(resolved_root)
    except (OSError, ValueError):
        return False
    return True


def _has_template_suffix(filename: str) -> bool:
    """Report whether ``filename`` ends with one of :data:`TEMPLATE_SUFFIXES`."""
    lowered = filename.lower()
    return any(lowered.endswith(suffix) for suffix in TEMPLATE_SUFFIXES)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def find_templates(directory: Union[str, Path]) -> List[Path]:
    """Collect candidate Templates under ``directory``, recursively.

    "Candidate" means the filename matches :data:`TEMPLATE_SUFFIXES`. Whether a
    file really is a reviewable Template is decided by
    :func:`iacreview.template.load_template`, which parses it; deciding that
    here would mean parsing every file twice.

    Args:
        directory: Root of the scan.

    Returns:
        Absolute paths, sorted ascending by path string. The sort is what makes
        a report reproducible across machines (Requirement 10 AC3): filesystem
        order is not.

        :data:`EXCLUDED_DIRECTORY_NAMES` are not descended into at any depth, so
        a synthesized Template under ``cdk.out`` never appears here; use
        :func:`find_synthesized_templates` for those.

    Raises:
        InvalidArgumentsError: ``directory`` is blank or names a file.
        InputNotFoundError: ``directory`` does not exist.
    """
    root = _validated_directory(directory)

    found: List[Path] = []
    for current, dirnames, filenames in os.walk(root, followlinks=False):
        # In-place assignment is how os.walk is told not to descend. Sorting at
        # the same time makes the traversal itself deterministic, which matters
        # for anything that observes it (a --verbose trace, a profiler) even
        # though the returned list is sorted again below.
        dirnames[:] = sorted(
            name for name in dirnames if name not in EXCLUDED_DIRECTORY_NAMES
        )
        current_path = Path(current)
        for filename in sorted(filenames):
            if not _has_template_suffix(filename):
                continue
            candidate = current_path / filename
            if not _is_contained(candidate, root):
                continue
            found.append(candidate)

    return sorted(found, key=str)


def find_synthesized_templates(directory: Union[str, Path]) -> List[Path]:
    """List the synthesized Templates of the cloud assembly under ``directory``.

    Args:
        directory: The CDK project directory, *not* the ``cdk.out`` directory
            itself.

    Returns:
        Absolute paths of ``cdk.out/*.template.json``, sorted ascending by path
        string. Empty when ``cdk.out`` is absent, is not a directory, or holds
        no Template -- all three mean the same thing to a caller: nothing has
        been synthesized yet (Requirement 8 AC5).

    Raises:
        InvalidArgumentsError: ``directory`` is blank or names a file.
        InputNotFoundError: ``directory`` does not exist.
    """
    root = _validated_directory(directory)
    output_directory = root / CDK_OUTPUT_DIRECTORY_NAME
    if not output_directory.is_dir():
        return []

    found: List[Path] = []
    for entry in output_directory.iterdir():
        if not entry.name.lower().endswith(SYNTHESIZED_TEMPLATE_SUFFIX):
            continue
        if not entry.is_file():
            continue
        if not _is_contained(entry, root):
            continue
        found.append(entry)

    return sorted(found, key=str)


@dataclass(frozen=True)
class CdkDetection:
    """What was found in one directory, with respect to CDK.

    Attributes:
        directory: The resolved directory that was inspected.
        config_file: Path to ``cdk.json``, or ``None`` when the directory is not
            a CDK project. Carried as a path rather than as a bare boolean
            because Requirement 8 AC2 asks for the detection to be *reported*,
            and the report names the evidence.
        output_directory: Path to ``cdk.out``, or ``None`` when it does not
            exist. Independent of ``config_file``: a directory holding only a
            copied-out cloud assembly has one without the other, and its
            Templates are still reviewable (AC1).
        synthesized_templates: ``cdk.out/*.template.json``, sorted ascending. A
            tuple, so a caller cannot mutate a detection it received.
    """

    directory: Path
    config_file: Optional[Path]
    output_directory: Optional[Path]
    synthesized_templates: Tuple[Path, ...]

    @property
    def is_cdk_project(self) -> bool:
        """Whether ``cdk.json`` is present (Requirement 8 AC2)."""
        return self.config_file is not None

    @property
    def has_synthesized_templates(self) -> bool:
        """Whether anything under ``cdk.out`` is reviewable right now."""
        return bool(self.synthesized_templates)


def detect_cdk_project(directory: Union[str, Path]) -> CdkDetection:
    """Inspect ``directory`` for a CDK project and its synthesized Templates.

    Reads directory entries only. No process is started on any path through this
    function, which is what Requirement 8 AC3 requires of every review flow that
    the user has not explicitly confirmed.

    The cloud assembly is enumerated whether or not ``cdk.json`` is present,
    because Requirement 8 AC1 accepts a synthesized Template as ordinary input:
    a directory containing only ``cdk.out`` (a copied artifact, or a project
    whose source lives elsewhere) is still reviewable.

    Args:
        directory: Directory to inspect.

    Returns:
        A :class:`CdkDetection`.

    Raises:
        InvalidArgumentsError: ``directory`` is blank or names a file.
        InputNotFoundError: ``directory`` does not exist.
    """
    root = _validated_directory(directory)

    config = root / CDK_CONFIG_FILENAME
    output_directory = root / CDK_OUTPUT_DIRECTORY_NAME
    return CdkDetection(
        directory=root,
        config_file=config if config.is_file() else None,
        output_directory=output_directory if output_directory.is_dir() else None,
        synthesized_templates=tuple(find_synthesized_templates(root)),
    )


def partition_templates(
    directory: Union[str, Path],
) -> Tuple[List[Path], List[Path]]:
    """Split ``directory`` into the two Template groups, in review order.

    Requirement 8 AC10 requires standalone Templates to be reviewed *first* and
    the two groups to be reported separately when both are present. The return
    order encodes the first half; the caller keeps the two lists apart in
    ``target.files`` and ``target.cdk.synthesized_templates`` for the second.

    Args:
        directory: Directory to scan.

    Returns:
        ``(standalone, synthesized)``. The lists are disjoint:
        :data:`EXCLUDED_DIRECTORY_NAMES` keeps ``cdk.out`` out of the first.

    Raises:
        InvalidArgumentsError: ``directory`` is blank or names a file.
        InputNotFoundError: ``directory`` does not exist.
    """
    root = _validated_directory(directory)
    return find_templates(root), find_synthesized_templates(root)


# ---------------------------------------------------------------------------
# The gated synth
# ---------------------------------------------------------------------------


def build_synth_argv(executable: str = CDK) -> List[str]:
    """Build the ``cdk synth`` command line.

    Every element is a literal owned by this module: no user-supplied value is
    appended, so there is nothing here for
    :func:`iacreview.pathguard.assert_no_shell_metacharacters` to check and no
    string concatenation to review (Requirement 16 AC6).

    Args:
        executable: What to place in ``argv[0]``. Defaults to the bare name for
            readability in tests; :func:`synth_if_confirmed` passes
            :attr:`~iacreview.toolcheck.ToolInfo.path` so the binary whose
            version was verified is the binary that runs.

    Returns:
        A fresh list, safe for the caller to keep or log.
    """
    return [executable, SYNTH_SUBCOMMAND]


@contextmanager
def _working_directory(directory: Path) -> Iterator[None]:
    """Run the block with the process working directory set to ``directory``.

    The CDK CLI locates ``cdk.json`` relative to its own working directory and
    has no flag naming the project directory, so synthesizing a project that is
    not the current directory requires this. :func:`iacreview.proc.run`
    deliberately inherits the working directory and exposes no ``cwd``
    parameter, so the change is made here, in the one function of the one module
    that needs it, rather than widening the process wrapper's contract.

    The change is process-global while the block runs, and therefore not
    thread-safe. That is acceptable because the plugin's entry points are
    single-threaded and because ``cdk synth`` is the only external tool that
    needs it; every other tool receives absolute paths in its ``argv``. The
    working directory is restored on every exit path, including an exception.
    """
    previous = Path.cwd()
    os.chdir(directory)
    try:
        yield
    finally:
        os.chdir(previous)


def synth_if_confirmed(
    directory: Union[str, Path], confirmed: bool
) -> List[Path]:
    """Return reviewable Templates, running ``cdk synth`` only if confirmed.

    ``confirmed=False`` takes a path through this function on which
    :mod:`iacreview.proc` is never reached: the warning goes to stderr and the
    already-synthesized Templates are returned (Requirement 8 AC3, AC5). An
    empty list then means "nothing is reviewable yet", which the caller reports
    as ``no_reviewable_template``.

    ``confirmed=True`` states the warning as well -- a caller that passed the
    flag without showing it to the user still leaves a record -- then verifies
    the CDK CLI, runs ``cdk synth`` with the project directory as the working
    directory, and enumerates the resulting cloud assembly.

    Args:
        directory: The CDK project directory.
        confirmed: The user's explicit confirmation, supplied as
            ``--confirm-cdk-synth``. Requirement 16 AC9 forbids obtaining it by
            prompting on stdin.

    Returns:
        Absolute paths of the synthesized Templates, sorted ascending. Empty
        when nothing has been synthesized and nothing was allowed to run.

    Raises:
        InvalidArgumentsError: ``directory`` is blank, names a file, or -- with
            ``confirmed=True`` -- holds no ``cdk.json``. Synthesizing a
            directory that is not a CDK project would execute code for no
            possible benefit, so it is refused rather than attempted.
        InputNotFoundError: ``directory`` does not exist.
        ToolUnavailableError: The CDK CLI is absent from ``PATH``. Its
            remediation carries the official installation documentation URL
            (Requirement 8 AC8).
        ToolVersionError: The CDK CLI is older than the supported minimum.
        ToolTimeoutError: ``cdk synth`` exceeded :data:`SYNTH_TIMEOUT_S`.
        ToolExecutionError: ``cdk synth`` exited non-zero, or the CLI became
            unusable after the version check.

        The last three carry the first
        :data:`~iacreview.errors.STDERR_HEAD_MAX_LINES` lines of the captured
        stderr (Requirement 8 AC6, AC7) and are raised rather than swallowed:
        Requirement 8 AC7 forbids continuing into any alternative execution
        mode, and returning the previous contents of ``cdk.out`` after a failed
        synth would review a stale Template as though it were the current one.
    """
    root = _validated_directory(directory)
    detection = detect_cdk_project(root)

    if not confirmed:
        # No process is started here, and none can be: this branch returns
        # before any reference to proc, shutil, or subprocess is evaluated
        # (Requirement 8 AC3, Property 25).
        if detection.is_cdk_project:
            _warn(SYNTH_WARNING)
            _warn(SYNTH_NOT_CONFIRMED_NOTICE)
        return list(detection.synthesized_templates)

    if not detection.is_cdk_project:
        raise InvalidArgumentsError(
            "cdk synth was confirmed but {0} is not a CDK project: no {1} "
            "found".format(root, CDK_CONFIG_FILENAME),
            remediation=(
                "Point the review at the directory containing {0}, or drop the "
                "synthesis confirmation to review already-synthesized "
                "templates only.".format(CDK_CONFIG_FILENAME)
            ),
        )

    _warn(SYNTH_WARNING)

    # Raises ToolUnavailableError with the CDK documentation URL in its
    # remediation when cdk is absent (Requirement 8 AC8), and ToolVersionError
    # when it is too old. Neither is caught: with no CLI there is nothing to
    # synthesize, and AC7's "no fallback" applies to a failure to obtain a
    # template just as much as to a failed run.
    tool = require_known_tool(CDK)

    try:
        with _working_directory(root):
            completed = proc.run(
                build_synth_argv(executable=tool.path), timeout_s=SYNTH_TIMEOUT_S
            )
    except ToolTimeoutError as exc:
        # Re-raised with the bare tool name in place of the absolute path
        # proc.run reports, so the StructuredError this becomes holds no host
        # path (Requirement 16 AC11), and with the no-fallback statement.
        raise ToolTimeoutError(
            "cdk synth exceeded its {0}s timeout and was terminated".format(
                SYNTH_TIMEOUT_S
            ),
            tool=CDK,
            stderr="\n".join(exc.stderr_head),
            remediation=NO_FALLBACK_REMEDIATION,
        ) from exc

    if completed.exit_code != 0:
        raise ToolExecutionError(
            "cdk synth failed with exit code {0}".format(completed.exit_code),
            tool=CDK,
            tool_exit_code=completed.exit_code,
            stderr=completed.stderr,
            remediation=NO_FALLBACK_REMEDIATION,
        )

    return find_synthesized_templates(root)
