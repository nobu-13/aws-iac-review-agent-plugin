"""``sys.path`` bootstrap and the shared ``main()`` wrapper for entry points.

The plugin ships as a directory and is never ``pip install``-ed
(design.md, Directory Structure). A Skill entry point at
``skills/<skill>/scripts/<script>.py`` therefore cannot import ``iacreview``
until the plugin root is on ``sys.path``. This module holds both halves of that
contract: the path derivation rules, and the ``main()`` wrapper every entry
point delegates to so that exit codes, stream discipline and error handling are
implemented exactly once (Requirement 2 AC16).

Why four lines are duplicated in every entry point
--------------------------------------------------

design.md records the tension explicitly: the bootstrap boilerplate cannot
itself be imported from a shared module, because importing that module is the
very thing the boilerplate makes possible. The resolution is to keep the
duplicated part as small and as fixed as possible -- it is not shared *logic*,
it is a fixed prologue -- and to verify the assumption it encodes immediately
afterwards with :func:`require_plugin_root`.

Every entry point script therefore begins with literally this, before any other
import (see :data:`ENTRY_POINT_BOOTSTRAP`)::

    import sys
    from pathlib import Path

    # scripts/ -> skill dir -> skills/ -> plugin root
    _PLUGIN_ROOT = Path(__file__).resolve().parents[3]
    if str(_PLUGIN_ROOT) not in sys.path:
        sys.path.insert(0, str(_PLUGIN_ROOT))

    from iacreview import bootstrap  # noqa: E402

    bootstrap.require_plugin_root(__file__)

``parents[3]`` is a relative-depth assumption: it is correct only while entry
points live exactly three directories below the plugin root. Two guards cover a
broken assumption, and they cover different halves of it:

``tests/unit/test_bootstrap.py``
    Asserts the depth for every entry point path, so moving a script fails a
    test. This is the primary guard, because a wrong depth usually makes
    ``iacreview`` unimportable and the script then dies on its own ``import``
    line, before any code of ours can explain why.

:func:`require_plugin_root`
    Catches the cases the import survives: the derived directory has no
    ``plugin.json`` (an incomplete copy of the plugin), or another copy of
    ``iacreview`` was already importable from elsewhere and the script would
    silently mix two installations.

``Path(__file__).resolve()`` (rather than ``absolute()``) resolves symlinks
first, which matches the "filesystem-resolved plugin root" that Agent
Plugins 1.0.0 defines and that :func:`iacreview.pathguard.plugin_root` uses.

Entry point conventions enforced by :func:`run_entry_point`
----------------------------------------------------------

===============================  ==========================================
Requirement 16 AC7               argv is validated before anything else runs
Requirement 16 AC8               only documented exit codes are returned
Requirement 16 AC9               stdin is never read, and never waited on
Requirement 16 AC10              JSON on stdout, diagnostics on stderr
Requirement 16 AC11              stdout encoding and newline are pinned
===============================  ==========================================

``--verbose`` widens stderr diagnostics only. It is deliberately not passed to
anything that shapes the report, so stdout is byte-identical with and without
it (Requirement 16 AC11).
"""

from __future__ import annotations

import argparse
import dataclasses
import sys
import traceback
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Sequence, TextIO, Tuple, Union

from iacreview import exitcodes, pathguard
from iacreview.errors import IacReviewError, MappingFileError
from iacreview.pathguard import PLUGIN_MANIFEST_NAME
from iacreview.report import configure_stdout, dump

__all__ = [
    "SCRIPT_DEPTH_TO_PLUGIN_ROOT",
    "ENTRY_POINT_BOOTSTRAP",
    "REQUIRED_BOOTSTRAP_LINES",
    "derive_plugin_root",
    "ensure_plugin_root_on_sys_path",
    "verify_plugin_root",
    "require_plugin_root",
    "EntryPointParser",
    "new_parser",
    "EntryPointOutcome",
    "run_entry_point",
    "diagnostic",
    "verbose_diagnostic",
]

#: Number of directory levels between an entry point script and the plugin root:
#: ``scripts/`` -> ``<skill>/`` -> ``skills/`` -> plugin root. Entry points spell
#: the same number literally as ``parents[3]``; this constant is what the tests
#: and :func:`derive_plugin_root` agree on, so a layout change fails loudly in
#: one place.
SCRIPT_DEPTH_TO_PLUGIN_ROOT = 3

#: The exact prologue every entry point script must contain, verbatim. Kept here
#: so the required text has a single authoritative copy that tests compare
#: against, even though the text itself cannot be executed from here.
ENTRY_POINT_BOOTSTRAP = """\
import sys
from pathlib import Path

# scripts/ -> skill dir -> skills/ -> plugin root
_PLUGIN_ROOT = Path(__file__).resolve().parents[3]
if str(_PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_ROOT))
"""

#: The two lines of :data:`ENTRY_POINT_BOOTSTRAP` that carry meaning rather than
#: form. Tests assert on these instead of on the whole snippet, so that a
#: comment reworded or a blank line moved does not fail a test, while a changed
#: depth or a dropped ``sys.path`` insertion does.
REQUIRED_BOOTSTRAP_LINES: Tuple[str, ...] = (
    "_PLUGIN_ROOT = Path(__file__).resolve().parents[{0}]".format(
        SCRIPT_DEPTH_TO_PLUGIN_ROOT
    ),
    "sys.path.insert(0, str(_PLUGIN_ROOT))",
)


# ---------------------------------------------------------------------------
# Path bootstrap
# ---------------------------------------------------------------------------


def derive_plugin_root(script: Union[str, Path]) -> Path:
    """Derive the plugin root from the location of an entry point script.

    This is the callable form of the ``parents[3]`` line in the boilerplate. It
    performs no verification; use :func:`verify_plugin_root` for that.

    Args:
        script: Path to an entry point script, normally ``__file__``. The path
            need not exist: the derivation is purely lexical after symlink
            resolution, which lets tests check the depth assumption for a script
            that has not been written yet.

    Returns:
        The resolved absolute directory ``SCRIPT_DEPTH_TO_PLUGIN_ROOT`` levels
        above ``script``.

    Raises:
        MappingFileError: ``script`` sits fewer than
            ``SCRIPT_DEPTH_TO_PLUGIN_ROOT`` levels below the filesystem root, so
            no such ancestor exists. That means the plugin layout is wrong
            rather than the caller's input, hence the installation-level error.
    """
    resolved = Path(script).resolve()
    try:
        return resolved.parents[SCRIPT_DEPTH_TO_PLUGIN_ROOT]
    except IndexError:
        raise MappingFileError(
            "cannot derive the plugin root from {0}: fewer than {1} parent "
            "directories exist".format(resolved, SCRIPT_DEPTH_TO_PLUGIN_ROOT),
            remediation=(
                "Entry point scripts must live at "
                "skills/<skill>/scripts/<script>.py inside the plugin root."
            ),
        ) from None


def ensure_plugin_root_on_sys_path(script: Union[str, Path]) -> Path:
    """Derive the plugin root from ``script`` and put it on ``sys.path``.

    Equivalent to the boilerplate prologue, for callers that can already import
    :mod:`iacreview` (the test suite, the benchmark harness, an embedding host).
    Idempotent: the root is inserted only when absent, so repeated calls do not
    grow ``sys.path``.

    Args:
        script: Path to an entry point script, normally ``__file__``.

    Returns:
        The derived plugin root, unverified. Callers that depend on the root
        being genuine should follow with :func:`verify_plugin_root`.

    Raises:
        MappingFileError: The root cannot be derived (see
            :func:`derive_plugin_root`).
    """
    root = derive_plugin_root(script)
    text = str(root)
    if text not in sys.path:
        # Front of the path, as the boilerplate does: the plugin's own modules
        # must win over a same-named module elsewhere on the host's path.
        sys.path.insert(0, text)
    return root


def verify_plugin_root(script: Union[str, Path]) -> Path:
    """Confirm the root derived from ``script`` is the real plugin root.

    Two independent things are checked, because they fail for different reasons:

    1. ``plugin.json`` exists at the derived root (Requirement 1 AC1). This is
       what catches a script moved to a different depth, or a plugin directory
       that was copied incompletely.
    2. The derived root equals :func:`iacreview.pathguard.plugin_root`, the root
       derived independently from the location of the imported ``iacreview``
       package. A mismatch means the script is bootstrapping one installation
       while importing the shared code of another -- for instance because an
       older copy of the plugin was already on ``sys.path``. Path containment
       would then be checked against a different root than the one the script
       belongs to, so this is refused rather than warned about.

    Args:
        script: Path to an entry point script, normally ``__file__``.

    Returns:
        The verified plugin root.

    Raises:
        MappingFileError: Either check failed. The message names the derived
            root, so the reader can see which directory was inspected.
    """
    derived = derive_plugin_root(script)
    manifest = derived / PLUGIN_MANIFEST_NAME
    if not manifest.is_file():
        raise MappingFileError(
            "plugin root verification failed for {0}: {1} not found at "
            "{2}".format(Path(script), PLUGIN_MANIFEST_NAME, derived),
            remediation=(
                "Run the script from its place in the plugin directory: "
                "skills/<skill>/scripts/<script>.py, with {0} at the plugin "
                "root.".format(PLUGIN_MANIFEST_NAME)
            ),
        )

    package_root = pathguard.plugin_root()
    if derived != package_root:
        raise MappingFileError(
            "plugin root mismatch: the script at {0} derives {1}, but the "
            "imported iacreview package lives under {2}".format(
                Path(script), derived, package_root
            ),
            remediation=(
                "Remove the other copy of the plugin from PYTHONPATH so that "
                "the script and the shared package come from one installation."
            ),
        )
    return derived


def require_plugin_root(
    script: Union[str, Path], *, stderr: Optional[TextIO] = None
) -> Path:
    """Verify the plugin root, or exit with a clear message and no traceback.

    This is what entry points call immediately after the boilerplate. It runs at
    import time, before :func:`run_entry_point` exists to catch anything, so it
    handles its own reporting: a missing manifest is a deployment problem whose
    stack trace tells the reader nothing, so the message alone is printed and
    the process exits :data:`~iacreview.exitcodes.UNEXPECTED`.

    Args:
        script: Path to the entry point script, normally ``__file__``.
        stderr: Stream for the diagnostic. Defaults to :data:`sys.stderr`.

    Returns:
        The verified plugin root.

    Raises:
        SystemExit: Verification failed. The status is
            :data:`~iacreview.exitcodes.UNEXPECTED` (1), matching the
            "broken installation" row of design.md's failure matrix.
    """
    try:
        return verify_plugin_root(script)
    except MappingFileError as exc:
        diagnostic(str(exc), stream=stderr)
        if exc.remediation:
            diagnostic(exc.remediation, stream=stderr)
        raise SystemExit(exitcodes.UNEXPECTED)


# ---------------------------------------------------------------------------
# Diagnostics (stderr only)
# ---------------------------------------------------------------------------


def diagnostic(message: str, *, stream: Optional[TextIO] = None) -> None:
    """Write one human-readable diagnostic line to stderr.

    The single place entry points emit non-JSON text, which is what keeps
    Requirement 16 AC10 checkable: stdout carries JSON and nothing else.

    Args:
        message: Text to write. A newline is appended.
        stream: Destination. Defaults to :data:`sys.stderr`, read at call time
            so a caller that replaced it is honored.
    """
    target = sys.stderr if stream is None else stream
    target.write(message + "\n")


def verbose_diagnostic(
    message: str, *, verbose: bool, stream: Optional[TextIO] = None
) -> None:
    """Write a diagnostic only when ``--verbose`` was given.

    Args:
        message: Text to write when ``verbose`` is true.
        verbose: The parsed ``--verbose`` flag.
        stream: Destination. Defaults to :data:`sys.stderr`.
    """
    if verbose:
        diagnostic(message, stream=stream)


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


class EntryPointParser(argparse.ArgumentParser):
    """``ArgumentParser`` that sends usage, help and errors to stderr.

    ``argparse`` prints ``--help`` on stdout. For a normal CLI that is correct,
    but here stdout is a machine-readable channel (Requirement 16 AC10) and a
    consumer piping it into a JSON parser should never receive usage text.
    Routing every parser message to stderr keeps that channel clean without
    giving up ``--help``.

    ``_print_message`` is the one hook ``argparse`` funnels all of its output
    through; overriding it covers help, usage and errors together. Its
    ``file`` argument is ignored on purpose -- the point is that the caller's
    choice of stdout is overridden.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        #: Set before ``super().__init__``: the base constructor can emit
        #: messages, and the attribute must already exist by then.
        self.diagnostic_stream: Optional[TextIO] = None
        super().__init__(*args, **kwargs)

    def _print_message(  # type: ignore[override]
        self, message: str, file: Optional[TextIO] = None
    ) -> None:
        if not message:
            return
        target = (
            sys.stderr if self.diagnostic_stream is None else self.diagnostic_stream
        )
        target.write(message)


def new_parser(prog: str, description: str) -> EntryPointParser:
    """Build the parser every entry point starts from.

    Args:
        prog: Program name shown in usage, normally the script's filename.
        description: One-line summary of what the script produces.

    Returns:
        A parser with ``--verbose`` already declared.

    Note:
        ``allow_abbrev=False`` disables ``argparse``'s prefix matching. With it
        enabled, ``--rules`` would silently mean ``--rules-dir`` today and break
        the day a second option shares that prefix; an unknown flag should be
        rejected (exit 2), not guessed.
    """
    parser = EntryPointParser(
        prog=prog,
        description=description,
        allow_abbrev=False,
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help=(
            "Emit additional diagnostics on stderr. Does not change stdout."
        ),
    )
    return parser


def _parse_argv(
    parser: argparse.ArgumentParser,
    argv: Sequence[str],
    stderr: TextIO,
) -> Union[argparse.Namespace, int]:
    """Parse ``argv``, translating ``argparse``'s exits into exit codes.

    Returns:
        The parsed namespace, or an exit code when the process should stop here:
        :data:`~iacreview.exitcodes.OK` after ``--help``,
        :data:`~iacreview.exitcodes.INVALID_ARGUMENTS` for a missing argument or
        an unknown flag (Requirement 16 AC7).
    """
    if isinstance(parser, EntryPointParser):
        parser.diagnostic_stream = stderr
    try:
        return parser.parse_args(list(argv))
    except SystemExit as exc:
        # argparse exits 0 for --help and 2 for a usage error. Any other status
        # is mapped to INVALID_ARGUMENTS as well: it still came out of argument
        # parsing, and the documented code for that is 2.
        if exc.code in (None, 0):
            return exitcodes.OK
        return exitcodes.INVALID_ARGUMENTS


# ---------------------------------------------------------------------------
# main() wrapper
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class EntryPointOutcome:
    """What an entry point produced: a JSON payload and an exit status.

    Attributes:
        report: The object to serialize on stdout, or ``None`` to write nothing.
            Usually a Review_Report from :func:`iacreview.report.build_report`,
            but the facts-extraction scripts pass their own JSON object.
        exit_code: Process exit status. A non-zero status together with a
            ``report`` is the normal shape for "the tool was unavailable, here
            is the partial report" (design.md, Failure mode matrix).
    """

    report: Optional[Dict[str, Any]] = None
    exit_code: int = exitcodes.OK

    def __post_init__(self) -> None:
        """Reject an exit code outside the documented table.

        Requirement 16 AC8 makes the exit code table part of the contract, so an
        entry point inventing a status is a bug that should surface here rather
        than reach the caller as an undocumented number.

        Raises:
            ValueError: ``exit_code`` is not one of
                :data:`iacreview.exitcodes.EXIT_CODES`.
        """
        if self.exit_code not in set(exitcodes.EXIT_CODES.values()):
            raise ValueError(
                "exit_code {0!r} is not a documented exit code: {1}".format(
                    self.exit_code, sorted(set(exitcodes.EXIT_CODES.values()))
                )
            )


#: What an entry point's ``run`` callable may return: an explicit outcome, a
#: bare JSON object (exit 0), or ``None`` (exit 0, no stdout).
RunResult = Union["EntryPointOutcome", Dict[str, Any], None]


def _as_outcome(value: RunResult) -> EntryPointOutcome:
    """Normalize a ``run`` return value into an :class:`EntryPointOutcome`.

    Raises:
        TypeError: ``value`` is none of the accepted forms. Surfaces through the
            wrapper as exit 1, since it is a bug in the entry point.
    """
    if isinstance(value, EntryPointOutcome):
        return value
    if value is None:
        return EntryPointOutcome()
    if isinstance(value, dict):
        return EntryPointOutcome(report=value)
    raise TypeError(
        "entry point run() must return an EntryPointOutcome, a dict, or None; "
        "got {0}".format(type(value).__name__)
    )


def _write_json(stream: TextIO, payload: Dict[str, Any]) -> None:
    """Serialize ``payload`` onto ``stream`` and flush it.

    Flushing matters because the wrapper returns an exit code instead of calling
    ``sys.exit``; a caller could exit through a path that skips interpreter
    shutdown, and a truncated report is worse than a loud failure.
    """
    stream.write(dump(payload))
    stream.flush()


def _report_error(
    exc: IacReviewError,
    *,
    stdout: TextIO,
    stderr: TextIO,
    partial_report: Optional[Callable[[IacReviewError], Optional[Dict[str, Any]]]],
) -> None:
    """Describe ``exc`` on stderr and, if offered, print a partial report.

    The ``error_class`` prefix is included because it is the same string that
    appears in the report's ``errors[]`` entries, which lets a reader connect a
    stderr line to a report entry.

    ``partial_report`` exists because whether a partial report is possible
    depends on how far the entry point got: design.md's failure matrix expects
    ``errors[]`` on stdout for a parse failure or an unavailable tool, and an
    empty stdout for a path violation detected before any target was read. The
    wrapper cannot know which case it is in, so the entry point supplies the
    payload -- or nothing, and stdout stays empty.
    """
    diagnostic("error: {0}: {1}".format(exc.error_class, exc.message), stream=stderr)
    if exc.remediation:
        diagnostic(exc.remediation, stream=stderr)
    for line in exc.stderr_head:
        diagnostic("  {0}".format(line), stream=stderr)

    if partial_report is None:
        return
    payload = partial_report(exc)
    if payload is not None:
        _write_json(stdout, payload)


def run_entry_point(
    *,
    parser: argparse.ArgumentParser,
    run: Callable[[argparse.Namespace], RunResult],
    argv: Optional[Sequence[str]] = None,
    validate: Optional[Callable[[argparse.Namespace], None]] = None,
    partial_report: Optional[
        Callable[[IacReviewError], Optional[Dict[str, Any]]]
    ] = None,
    stdout: Optional[TextIO] = None,
    stderr: Optional[TextIO] = None,
) -> int:
    """Run an entry point under the shared conventions and return an exit code.

    The order of steps is part of the contract:

    1. ``argv`` is parsed and validated. Nothing else happens first, so an
       invalid invocation cannot spawn a process or touch a file
       (Requirement 16 AC7).
    2. ``validate`` runs, for checks ``argparse`` cannot express (path
       containment, mutually dependent options).
    3. Temp file cleanup handlers are installed (Requirement 9 AC6) and stdout's
       encoding is pinned (Requirement 16 AC11).
    4. ``run`` does the work and returns the payload.
    5. The payload is serialized to stdout. It is the only thing ever written
       there.

    stdin is never read, at any step. Neither is it consulted to decide
    anything, so the script behaves identically whether it is attached to a
    terminal, a pipe, or nothing (Requirement 16 AC9).

    Args:
        parser: Parser from :func:`new_parser`, with the script's own options
            added.
        run: Callable receiving the parsed namespace and returning an
            :class:`EntryPointOutcome`, a JSON object, or ``None``.
        argv: Argument list without the program name. Defaults to
            ``sys.argv[1:]``.
        validate: Optional extra argument validation, run before any work.
            Raises :class:`~iacreview.errors.IacReviewError` to reject.
        partial_report: Optional builder invoked when an
            :class:`~iacreview.errors.IacReviewError` is caught, returning a
            payload to print or ``None`` to leave stdout empty.
        stdout: JSON destination. Defaults to :data:`sys.stdout`.
        stderr: Diagnostics destination. Defaults to :data:`sys.stderr`.

    Returns:
        A documented exit code from :mod:`iacreview.exitcodes`: the failing
        exception's ``exit_code`` for an expected failure,
        :data:`~iacreview.exitcodes.UNEXPECTED` for anything else. The value is
        returned rather than raised so that tests can call this in-process, and
        so a caller keeps the choice of how to terminate.
    """
    out = sys.stdout if stdout is None else stdout
    err = sys.stderr if stderr is None else stderr
    arguments = sys.argv[1:] if argv is None else argv

    try:
        # Pins encoding and newline only; writes nothing, so this is safe to do
        # before argument validation.
        configure_stdout(out)

        parsed = _parse_argv(parser, arguments, err)
        if isinstance(parsed, int):
            return parsed
        args = parsed

        if validate is not None:
            validate(args)

        pathguard.install_temp_file_cleanup()

        outcome = _as_outcome(run(args))
        if outcome.report is not None:
            _write_json(out, outcome.report)
        return outcome.exit_code
    except IacReviewError as exc:
        _report_error(exc, stdout=out, stderr=err, partial_report=partial_report)
        return exc.exit_code
    except Exception:  # noqa: BLE001 - the wrapper is the last line of defense
        # Requirement 12 AC7: no unhandled exception escapes an entry point. The
        # trace goes to stderr because it is a diagnostic, and stdout stays
        # empty because no valid report exists for a state we do not understand.
        traceback.print_exc(file=err)
        diagnostic(
            "unexpected internal error; please report this with the trace "
            "above.",
            stream=err,
        )
        return exitcodes.UNEXPECTED
