#!/usr/bin/env python3
"""Benchmark runner: review every case, compare with Ground_Truth, print the numbers.

``metrics.py`` owns the arithmetic and touches nothing outside its two argument
lists. This module owns everything else: it discovers the cases, runs the real
review over each one, hands the two documents to :mod:`metrics`, serializes the
result on stdout and turns the verdict into a process exit code.

It is a contributor tool, not a Skill. Nothing in ``plugin.json`` advertises it,
no ``SKILL.md`` mentions it, and a host Agent has no reason to call it.

Why this script is not a Skill entry point, and what that changes
----------------------------------------------------------------

Exactly two things.

**The plugin root is two levels up, not three.** The five Skill entry points live
at ``skills/<skill>/scripts/<script>.py`` and derive the root with
``parents[3]``; :data:`iacreview.bootstrap.SCRIPT_DEPTH_TO_PLUGIN_ROOT` is that
3, and ``tests/unit/test_bootstrap.py`` holds every Skill entry point to it. This
file sits at ``benchmark/harness/run_benchmark.py``, so its root is
``parents[2]``. Reusing ``bootstrap.derive_plugin_root`` or
``bootstrap.require_plugin_root`` here would silently derive
``<plugin root>/..`` -- the directory the plugin was unpacked into -- and the
manifest check would then fail with a message about a broken installation for a
perfectly good one. The depth is therefore stated locally as
:data:`PLUGIN_ROOT_DEPTH`, and :func:`verify_plugin_root` performs the same two
checks ``bootstrap`` performs (``plugin.json`` present, and the derived root
equal to the root the imported ``iacreview`` package comes from) by delegating
the first to :func:`iacreview.pathguard.plugin_root`. Everything else about the
entry point contract -- argument validation before any work, JSON on stdout,
diagnostics on stderr, no stdin, no unhandled exception --  is
:func:`iacreview.bootstrap.run_entry_point`, unchanged and shared.

**The exit code table has one entry the plugin's table does not.** "A
deterministic expectation was missed" is not one of the documented plugin failure
classes, and :data:`iacreview.exitcodes.EXIT_CODES` is closed on purpose:
``tests/unit/test_exitcodes.py`` pins it to nine values that are part of the
Plugin's contract with host Agents. A benchmark regression is not a plugin
failure, so it gets a code outside that table (:data:`BENCHMARK_FAILURE`) rather
than borrowing ``UNEXPECTED``, which would make CI unable to tell a missed
expectation from a crash. See :data:`HARNESS_EXIT_CODES`.

How a case is reviewed
----------------------

By running ``skills/iac-review/scripts/run_iac_review.py`` as a subprocess,
through :func:`iacreview.proc.run`: one argv array, no shell, no inherited AWS
credentials. Two reasons, and neither is about convenience.

*The pipeline is not reimplemented.* The orchestrator decides which Sources run,
in what order, how their failures are recorded and how equivalent Findings merge.
A benchmark that assembled its own pipeline from :mod:`iacreview.cfnlint`,
:mod:`iacreview.cfnguard` and :mod:`iacreview.iam` would measure *that* pipeline,
and would keep passing while the one users actually run broke. What is measured
here is the documented entry point with a documented ``--sources`` value.

*One bad case cannot end the run.* Benchmark templates are untrusted input by
design, and a case that crashes the review, hangs, or is malformed is recorded as
one unevaluated case (:data:`CASE_REASONS`) while the remaining cases are still
measured. A process boundary makes that true by construction rather than by
catching the right exceptions.

Two ways to measure one Source (Requirement 11 AC10, AC11)
----------------------------------------------------------

A single-Source mode can be measured two ways, and the point of ``--filter-only``
is that they must agree.

*By default*, the mode is applied twice: the review is started with
``--sources <that Source>``, so the other Sources never run, and its report is
then filtered to the Source as well (:func:`metrics.filter_by_source`). What is
measured is the Source *in isolation* -- the pipeline as a user would run it with
that one Source enabled.

*With ``--filter-only``*, the mode is applied once, to the result: the review runs
with every Source enabled, exactly as ``combined`` does, and only the filter
selects the Source. What is measured is the Source's *contribution to a full
review*. One review per case serves every mode, which is what the flag is for: a
sweep over the four modes costs four reviews per case by default and one with it.

Requirement 11 AC10 is what makes the two equal: a Finding keeps every Source that
reached it, so filtering a combined report to one Source recovers that Source's
Findings. ``tests/integration/test_benchmark_harness.py`` measures the equality
over the real cases rather than assuming it -- if the two ever disagree, one of
them is wrong about what the Source contributes, and that is a finding about the
pipeline, not about the harness.

The paths differ in one way that matters, and it is not in the numbers. When an
external tool is absent, the default path fails the review outright (the
orchestrator exits 5 with no Source able to run) and the case is recorded
unevaluated; ``--filter-only`` gets a successful combined report from which that
Source is simply missing, so its measurement would read as a regression.
:meth:`Benchmark._warn_absent_tool` says so on stderr for that case.
``--filter-only`` has no effect on ``combined``, whose review already enables
every Source; it is accepted there rather than refused, so a sweep over the modes
needs no special case, and ``--verbose`` says it changed nothing.

Determinism (Requirement 16 AC11)
---------------------------------

stdout is a function of the case files, the ``--mode`` value and the
``--filter-only`` value alone. It carries
no timing, no absolute path, no tool version, no ``errors[]`` text from the
review, and no case count that depends on which tools happen to be installed:
counts and percentages, case IDs, template file names, and status strings.
Percentages arrive from :mod:`metrics` already formatted as strings.

Review Time is deliberately absent, and is not measured at all here.
``metrics.DEFERRED_METRICS`` records why: it is environment-dependent, so it
cannot enter output that must be byte-identical between runs, and implementing it
means a second output channel rather than a field. What the review reports about
its own execution -- an unavailable tool, a Source that failed -- is
environment-dependent for the same reason and goes to stderr, where the reader
who needs it is looking.

Aggregate numbers
-----------------

The ``metrics`` and ``categories`` objects at the top level are computed over
every case at once, with each item's resource prefixed by its case ID
(:func:`namespaced`). Without the prefix, two cases that happen to use the same
logical ID in the same category would cross-match, and a case's missed
expectation could be silently satisfied by another case's Finding. With it, the
aggregate is exactly the sum of the per-case counts, and no metric definition is
restated here: the ratios stay in :func:`metrics.compute`.

Exit codes
----------

======  =========================================================
0       Every category PASS or INFO, and every discovered case was
        evaluated
1       Unexpected exception, or a broken plugin installation
2       Missing or unknown argument, or a path containing a shell
        metacharacter
3       ``--cases`` or ``--agent-findings`` does not exist
7       A path resolves outside the workspace root
9       At least one category is FAIL: a ``deterministic``
        expectation was missed (Requirement 11 AC7)
10      Every measured category passed, but at least one case could
        not be evaluated, so the benchmark is incomplete
======  =========================================================

9 wins over 10 when both apply: a measured regression is the more specific fact.
"""

import sys
from pathlib import Path

# harness/ -> benchmark/ -> plugin root. One level shallower than a Skill entry
# point; see the module docstring on why bootstrap's parents[3] is not used.
_PLUGIN_ROOT = Path(__file__).resolve().parents[2]
if str(_PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_ROOT))

import argparse  # noqa: E402
import dataclasses  # noqa: E402
import json  # noqa: E402
import time  # noqa: E402
from types import MappingProxyType  # noqa: E402
from typing import (  # noqa: E402
    Any,
    Dict,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Union,
)

from benchmark.harness import metrics  # noqa: E402
from iacreview import (  # noqa: E402
    agentin,
    bootstrap,
    cfnguard,
    cfnlint,
    exitcodes,
    iam,
    pathguard,
    proc,
    report,
    toolcheck,
)
from iacreview.errors import (  # noqa: E402
    IacReviewError,
    InputNotFoundError,
    InvalidArgumentsError,
    MappingFileError,
)

__all__ = [
    "PLUGIN_ROOT_DEPTH",
    "BENCHMARK_FAILURE",
    "CASE_NOT_EVALUATED",
    "HARNESS_EXIT_CODES",
    "SCHEMA_VERSION",
    "GROUND_TRUTH_FILENAME",
    "ORCHESTRATOR",
    "REVIEW_TIMEOUT_S",
    "MALFORMED_GROUND_TRUTH",
    "MISSING_TEMPLATE",
    "UNSAFE_CASE_PATH",
    "REVIEW_FAILED",
    "CASE_REASONS",
    "SUMMARY_KEYS",
    "CASE_KEYS",
    "COMBINED",
    "AGENT_ONLY",
    "HUMAN_REVIEW",
    "MODES",
    "MODE_NAMES",
    "DEFAULT_MODE",
    "TOOL_BY_SOURCE",
    "Mode",
    "review_mode",
    "CaseError",
    "derive_plugin_root",
    "verify_plugin_root",
    "build_parser",
    "workspace_root",
    "discover_cases",
    "load_ground_truth",
    "expectations_of",
    "template_path",
    "review",
    "namespaced",
    "case_status",
    "Benchmark",
    "main",
]

#: Directory levels between this script and the plugin root:
#: ``harness/`` -> ``benchmark/`` -> plugin root. Deliberately *not*
#: :data:`iacreview.bootstrap.SCRIPT_DEPTH_TO_PLUGIN_ROOT`, which is 3 and
#: belongs to the Skill entry points.
PLUGIN_ROOT_DEPTH = 2


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------

#: A category is ``FAIL``: a ``deterministic`` expectation was not detected
#: (Requirement 11 AC7). Outside :data:`iacreview.exitcodes.EXIT_CODES` on
#: purpose -- see the module docstring.
BENCHMARK_FAILURE = 9

#: Nothing measured failed, but at least one case could not be evaluated, so the
#: run does not cover the cases it was asked to cover. Distinct from
#: :data:`BENCHMARK_FAILURE` because the two ask for different responses: a
#: regression is a change in the review, an unevaluated case is usually a broken
#: case file or a missing tool.
CASE_NOT_EVALUATED = 10

#: Every status this script can exit with, name to value. The first six are the
#: plugin's own codes, reached through
#: :func:`iacreview.bootstrap.run_entry_point`; the last two are this script's.
HARNESS_EXIT_CODES: Mapping[str, int] = MappingProxyType(
    {
        "OK": exitcodes.OK,
        "UNEXPECTED": exitcodes.UNEXPECTED,
        "INVALID_ARGUMENTS": exitcodes.INVALID_ARGUMENTS,
        "INPUT_NOT_FOUND": exitcodes.INPUT_NOT_FOUND,
        "PATH_VIOLATION": exitcodes.PATH_VIOLATION,
        "BENCHMARK_FAILURE": BENCHMARK_FAILURE,
        "CASE_NOT_EVALUATED": CASE_NOT_EVALUATED,
    }
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Program name in usage text, written out rather than derived from ``sys.argv``.
SCRIPT_NAME = "run_benchmark.py"

#: ``--help`` summary.
DESCRIPTION = (
    "Review every benchmark case, compare the result with its ground truth, and "
    "print detection rate, precision, recall, false positives and severity "
    "accuracy as one JSON document on stdout."
)

#: Version of the summary document this script prints. Independent of the
#: Review_Report's ``schema_version`` and of the Ground_Truth format's: this is
#: the shape of *this* output, and it is the only version-like value in it.
SCHEMA_VERSION = "1.0.0"

#: The Ground_Truth file, in every case directory. A directory without one is not
#: a case (see :func:`discover_cases`).
GROUND_TRUTH_FILENAME = "ground_truth.json"

#: The entry point a case is reviewed with, relative to the plugin root. Resolved
#: through :func:`iacreview.pathguard.resolve_plugin_owned`, so a missing
#: orchestrator is reported as a broken installation rather than as a failure of
#: every case.
ORCHESTRATOR = "skills/iac-review/scripts/run_iac_review.py"

#: Wall-clock limit for reviewing one case, in seconds. Generous: a review starts
#: cfn-lint and cfn-guard, and a slow CI machine reviewing a large template is
#: not a failure. A case that exceeds it is one unevaluated case, not a dead run.
REVIEW_TIMEOUT_S = 300

#: ``--sources`` spelling for the IAM Source. The canonical name
#: (``iam.SOURCE_NAME``) contains a space; the orchestrator accepts this alias
#: for exactly that reason, and it is what a reader can retype from the
#: ``--verbose`` diagnostics. The canonical name is what
#: :attr:`Mode.source` filters on, so the alias never reaches :mod:`metrics`.
IAM_SOURCE_CLI_ALIAS = "iam-review"


# ---------------------------------------------------------------------------
# Why a case was not evaluated
# ---------------------------------------------------------------------------
#
# One short, closed vocabulary rather than a message. A message would carry the
# host's paths and the installed tools' wording into stdout, which Requirement 16
# AC11 keeps out of it; the message itself goes to stderr, where it is useful and
# where nothing depends on it being stable.

#: ``ground_truth.json`` is unreadable, is not JSON, is not an object, or its
#: ``template`` field is not a plain file name inside the case directory.
MALFORMED_GROUND_TRUTH = "malformed_ground_truth"

#: ``ground_truth.json`` is well formed, but the template it names is not there,
#: or is not a file.
MISSING_TEMPLATE = "missing_template"

#: The case directory does not resolve inside the ``--cases`` tree, or its name
#: carries a shell metacharacter. A symlinked case directory pointing elsewhere is
#: the case this catches: no check on the ``template`` field can see it, because
#: the escape happens one level above the file the field names.
UNSAFE_CASE_PATH = "unsafe_case_path"

#: The review did not produce a report: a non-zero exit status, a timeout, output
#: that is not a Review_Report, or an unavailable tool that left no Source able to
#: run.
REVIEW_FAILED = "review_failed"

#: The closed set, in the order a case meets them.
CASE_REASONS: Tuple[str, ...] = (
    UNSAFE_CASE_PATH,
    MALFORMED_GROUND_TRUTH,
    MISSING_TEMPLATE,
    REVIEW_FAILED,
)


# ---------------------------------------------------------------------------
# Output shape
# ---------------------------------------------------------------------------

#: Top-level keys of the summary, in the order :meth:`Benchmark.summary` inserts
#: them. Serialization sorts keys (:func:`iacreview.report.dump`), so this tuple
#: documents the schema rather than the byte order.
#:
#: ``metrics`` and ``categories`` are the aggregate over every evaluated case;
#: ``status`` is the aggregate verdict; ``errors`` lists the cases that were not
#: evaluated. Every key is present in every run, including one where no case was
#: evaluated at all, so a consumer never has to test for a key's existence.
#: ``filter_only`` records which of the two paths of the module docstring produced
#: the numbers. It describes how the measurement was obtained rather than what was
#: measured -- the same reason ``agent_findings_supplied`` is here -- and it is
#: needed for the same reason: a stored summary of a single-Source mode cannot be
#: read without it, because the filtered path can report an empty measurement for
#: an absent tool where the default path would have reported an unevaluated case.
#: It comes from the command line, so it does not weaken Requirement 16 AC11: one
#: invocation still prints the same bytes every time.
SUMMARY_KEYS: Tuple[str, ...] = (
    "schema_version",
    "mode",
    "sources_evaluated",
    "filter_only",
    "agent_findings_supplied",
    "cases",
    "metrics",
    "categories",
    "diagnostics",
    "status",
    "errors",
)

#: Keys of one entry of ``cases``. Fixed for an evaluated and an unevaluated case
#: alike: an unevaluated one carries ``evaluated: false``, a ``reason`` from
#: :data:`CASE_REASONS`, ``metrics: null``, ``diagnostics: null``, ``status:
#: null`` and no categories. ``diagnostics`` (Requirement 19 AC3) is the
#: per-case diagnostic block :func:`metrics.compute_diagnostics` returns; it
#: never bears on ``status``, and its values are :data:`metrics.NOT_APPLICABLE`
#: for a case that declares no diagnostic expectation (AC6).
CASE_KEYS: Tuple[str, ...] = (
    "case_id",
    "template",
    "evaluated",
    "reason",
    "metrics",
    "categories",
    "diagnostics",
    "status",
)


# ---------------------------------------------------------------------------
# --mode (Requirement 11 AC10, AC11)
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Mode:
    """One ``--mode`` value: which Sources run, and what the comparison keeps.

    The mode name to Source name mapping lives here rather than in
    :mod:`metrics`, which knows nothing about this plugin's Source vocabulary and
    takes the Source to filter on as an argument.

    Attributes:
        name: The ``--mode`` value.
        source: The Source name to filter both documents to
            (:func:`metrics.filter_by_source`), or ``None`` for ``combined``,
            which filters nothing. This is the canonical name, as
            ``Finding.Source`` and ground truth's ``detected_by`` spell it.
        cli_sources: ``--sources`` values passed to the orchestrator, so the mode
            also *disables* the other Sources at review time rather than only
            filtering their output afterwards. Empty for ``combined``: the
            orchestrator's own default is all three Sources, and restating it
            here would be a second copy of that default. ``--filter-only`` clears
            this and keeps :attr:`source`, which is the whole of that flag; see
            :func:`review_mode` and the module docstring.
        sources_evaluated: Source names the mode measures, for the summary. Fixed
            per mode, so the key does not describe the host's installed tools.
        expectation_field: Which ground-truth array supplies this mode's
            expectations. ``expected_findings`` for the deterministic and
            combined modes; the reserved ``expected_findings_agent_only`` for
            ``agent-only`` and ``expected_findings_human_review`` for
            ``human-review`` (Requirement 19 AC1). The reserved arrays are the
            AC12 extension point: they exist so this can be added without a
            schema-version bump, and every v0.1 case leaves them empty.
        thresholded: Whether a missed ``deterministic`` expectation in this mode
            is a FAIL. True for the modes that measure the pipeline against what
            it is expected to produce; false for ``human-review``, whose
            expectations name findings only a human reviewer is expected to
            reach, so holding the pipeline to them would fail every run
            (Requirement 19 AC1 records the mode without changing the pass/fail
            contract).
    """

    name: str
    source: Optional[str]
    cli_sources: Tuple[str, ...]
    sources_evaluated: Tuple[str, ...]
    expectation_field: str = "expected_findings"
    thresholded: bool = True


#: Every deterministic Source, in the orchestrator's collection order.
ALL_SOURCES: Tuple[str, ...] = (
    cfnlint.SOURCE_NAME,
    cfnguard.SOURCE_NAME,
    iam.SOURCE_NAME,
)

#: The mode that measures the pipeline as a user runs it.
COMBINED = "combined"

#: The mode measuring only the Agent Review Source (Requirement 19 AC1). Agent
#: Findings are enabled by supplying ``--agent-findings``, not by a ``--sources``
#: value -- the orchestrator has no ``--sources`` spelling for the Agent Source
#: on purpose -- so :attr:`Mode.cli_sources` is empty and the mode filters both
#: documents to :data:`agentin.SOURCE_NAME`. Its expectations come from the
#: reserved ``expected_findings_agent_only`` array, empty in every v0.1 case.
AGENT_ONLY = "agent-only"

#: The mode recording the expectations only a human reviewer is expected to reach
#: (Requirement 19 AC1). Informational: its expectations name findings the
#: pipeline is not expected to produce, so it is never held to a threshold
#: (:attr:`Mode.thresholded` is false) and cannot make the run FAIL. Its
#: expectations come from the reserved ``expected_findings_human_review`` array,
#: empty in every v0.1 case.
HUMAN_REVIEW = "human-review"

#: The benchmark modes. Requirement 11 AC11 asks for at least ``cfn-lint only``,
#: ``cfn-guard only`` and ``combined``; ``iam-only`` is the third deterministic
#: Source. Requirement 19 AC1 adds ``agent-only`` and ``human-review``, which
#: read the reserved ground-truth arrays rather than ``expected_findings``.
MODES: Mapping[str, Mode] = MappingProxyType(
    {
        COMBINED: Mode(
            name=COMBINED,
            source=None,
            cli_sources=(),
            sources_evaluated=ALL_SOURCES,
        ),
        "cfn-lint-only": Mode(
            name="cfn-lint-only",
            source=cfnlint.SOURCE_NAME,
            cli_sources=(cfnlint.SOURCE_NAME,),
            sources_evaluated=(cfnlint.SOURCE_NAME,),
        ),
        "cfn-guard-only": Mode(
            name="cfn-guard-only",
            source=cfnguard.SOURCE_NAME,
            cli_sources=(cfnguard.SOURCE_NAME,),
            sources_evaluated=(cfnguard.SOURCE_NAME,),
        ),
        "iam-only": Mode(
            name="iam-only",
            source=iam.SOURCE_NAME,
            cli_sources=(IAM_SOURCE_CLI_ALIAS,),
            sources_evaluated=(iam.SOURCE_NAME,),
        ),
        AGENT_ONLY: Mode(
            name=AGENT_ONLY,
            source=agentin.SOURCE_NAME,
            # No --sources: the Agent Source is enabled by --agent-findings, and
            # the orchestrator has no --sources spelling for it. cli_sources
            # stays empty so the review runs every Source and the filter keeps
            # only the Agent Findings.
            cli_sources=(),
            sources_evaluated=(agentin.SOURCE_NAME,),
            expectation_field="expected_findings_agent_only",
        ),
        HUMAN_REVIEW: Mode(
            name=HUMAN_REVIEW,
            # Not filtered to a Source: the expectations name findings no Source
            # is expected to produce. combined's None keeps every Finding, and
            # the reserved array supplies the expectations.
            source=None,
            cli_sources=(),
            sources_evaluated=ALL_SOURCES,
            expectation_field="expected_findings_human_review",
            thresholded=False,
        ),
    }
)

#: ``--mode`` choices, sorted so ``--help`` is stable.
MODE_NAMES: Tuple[str, ...] = tuple(sorted(MODES))

#: Mode used when ``--mode`` is absent.
DEFAULT_MODE = COMBINED

#: The external executable a Source needs, for the Sources that need one. Written
#: out rather than derived from the Source name: the two happen to be spelled the
#: same today (:data:`iacreview.toolcheck.CFN_LINT` *is*
#: ``cfnlint.SOURCE_NAME``), and a mapping that relied on that would break
#: silently the day one of them is renamed. Read only to explain an empty
#: ``--filter-only`` measurement (:meth:`Benchmark._warn_absent_tool`); the IAM
#: Source is absent because it needs no tool.
TOOL_BY_SOURCE: Mapping[str, str] = MappingProxyType(
    {
        cfnlint.SOURCE_NAME: toolcheck.CFN_LINT,
        cfnguard.SOURCE_NAME: toolcheck.CFN_GUARD,
    }
)


def review_mode(mode: Mode, filter_only: bool) -> Mode:
    """The mode the review is *run* with, which is not always the mode measured.

    The one place ``--filter-only`` acts. Everything downstream -- the filter, the
    metrics, the summary -- reads the mode as selected, so the flag cannot change
    what is compared, only how the report being compared was obtained.

    Args:
        mode: The mode ``--mode`` selected.
        filter_only: The ``--filter-only`` value.

    Returns:
        ``mode`` unchanged when ``filter_only`` is false, so the review runs with
        that Source alone. Otherwise a copy with :attr:`Mode.cli_sources` cleared
        and :attr:`Mode.source` kept, so the review enables every Source and the
        filter alone narrows the result. For ``combined`` the two are already
        equal, and the copy is the same mode by value.
    """
    if not filter_only:
        return mode
    return dataclasses.replace(mode, cli_sources=())


# ---------------------------------------------------------------------------
# Plugin root
# ---------------------------------------------------------------------------


def derive_plugin_root(script: Union[str, Path]) -> Path:
    """Derive the plugin root from a harness script's location.

    The callable form of the ``parents[2]`` line at the top of this file.

    Args:
        script: Path to a script under ``benchmark/harness/``, normally
            ``__file__``. Need not exist: the derivation is lexical after symlink
            resolution.

    Returns:
        The resolved directory :data:`PLUGIN_ROOT_DEPTH` levels above ``script``.

    Raises:
        MappingFileError: ``script`` has fewer than :data:`PLUGIN_ROOT_DEPTH`
            parent directories, so the layout is wrong rather than the input.
    """
    resolved = Path(script).resolve()
    try:
        return resolved.parents[PLUGIN_ROOT_DEPTH]
    except IndexError:
        raise MappingFileError(
            "cannot derive the plugin root from {0}: fewer than {1} parent "
            "directories exist".format(resolved, PLUGIN_ROOT_DEPTH),
            remediation=(
                "The benchmark harness must stay at "
                "benchmark/harness/<script>.py inside the plugin root."
            ),
        ) from None


def verify_plugin_root(script: Union[str, Path]) -> Path:
    """Confirm the root derived from ``script`` is the real plugin root.

    The same two checks :func:`iacreview.bootstrap.verify_plugin_root` performs
    for a Skill entry point, at this script's depth: ``plugin.json`` exists at the
    root (delegated to :func:`iacreview.pathguard.plugin_root`, which derives it
    independently from the imported package's own location), and that root is the
    one this file derived. A mismatch means the harness is bootstrapping one
    installation while importing another's shared code.

    Args:
        script: Path to this script, normally ``__file__``.

    Returns:
        The verified plugin root.

    Raises:
        MappingFileError: Either check failed.
    """
    derived = derive_plugin_root(script)
    package_root = pathguard.plugin_root()
    if derived != package_root:
        raise MappingFileError(
            "plugin root mismatch: the harness at {0} derives {1}, but the "
            "imported iacreview package lives under {2}".format(
                Path(script), derived, package_root
            ),
            remediation=(
                "Remove the other copy of the plugin from PYTHONPATH so that "
                "the harness and the shared package come from one installation."
            ),
        )
    return derived


def _require_plugin_root() -> None:
    """Verify the plugin root at import time, or exit with a plain message.

    Runs before :func:`iacreview.bootstrap.run_entry_point` exists to catch
    anything, so it reports for itself. A broken installation's traceback tells
    the reader nothing the message does not.
    """
    try:
        verify_plugin_root(__file__)
    except MappingFileError as exc:
        bootstrap.diagnostic(str(exc))
        if exc.remediation:
            bootstrap.diagnostic(exc.remediation)
        raise SystemExit(exitcodes.UNEXPECTED)


_require_plugin_root()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> bootstrap.EntryPointParser:
    """Build this script's argument parser.

    Returns:
        A parser accepting ``--cases`` (required), ``--mode``,
        ``--agent-findings`` and the shared ``--verbose``.
    """
    parser = bootstrap.new_parser(SCRIPT_NAME, DESCRIPTION)
    parser.add_argument(
        "--cases",
        required=True,
        metavar="DIR",
        help=(
            "Directory of case directories, normally benchmark/cases. Every "
            "subdirectory holding a {0} is one case; the rest are ignored. "
            "Resolved inside the workspace root.".format(GROUND_TRUTH_FILENAME)
        ),
    )
    parser.add_argument(
        "--mode",
        choices=list(MODE_NAMES),
        default=DEFAULT_MODE,
        help=(
            "Which Sources to measure. A single-Source mode compares only the "
            "expectations attributed to it, and by default also runs only that "
            "Source; see --filter-only. Default: {0}.".format(DEFAULT_MODE)
        ),
    )
    parser.add_argument(
        "--filter-only",
        action="store_true",
        help=(
            "Run the review once with every Source enabled and select the "
            "mode's Source by filtering the result, instead of also disabling "
            "the other Sources at review time. Both measure the same thing, so "
            "this is one review per case for a sweep over several modes rather "
            "than one per mode. No effect on {0}, which enables every Source "
            "either way.".format(COMBINED)
        ),
    )
    parser.add_argument(
        "--agent-findings",
        metavar="DIR",
        help=(
            "Directory of fixed agent finding fixtures, one <case_id>.json per "
            "case. Agent findings are never generated during a run, so the "
            "harness stays deterministic; a case with no fixture is reviewed "
            "without agent findings."
        ),
    )
    parser.add_argument(
        "--agent-runs",
        type=int,
        default=1,
        metavar="N",
        help=(
            "Review each case N times so the Agent Source's variation across "
            "runs can be reported as a diagnostic on stderr (Requirement 19 "
            "AC4). The deterministic Sources are evaluated exactly once whatever "
            "N is: only the agent-only mode repeats, and the summary is computed "
            "from the first run. Default: 1."
        ),
    )
    return parser


def workspace_root() -> Path:
    """Containment root for every path this script resolves.

    Returns:
        The resolved current working directory, which is also the root the
        orchestrator subprocess will use and the root the review's paths are
        relative to. Resolved so it compares equal to the roots
        :mod:`iacreview.pathguard` derives internally.
    """
    return Path.cwd().resolve()


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------


class CaseError(Exception):
    """One case cannot be evaluated; the others still can.

    Attributes:
        reason: One of :data:`CASE_REASONS`, and the only part of this that
            reaches stdout. The message goes to stderr.
    """

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


def discover_cases(cases_dir: Path) -> List[str]:
    """Return the case directory names under ``cases_dir``, sorted.

    Discovered from the filesystem rather than from any list, so a case added by
    a contributor is measured without editing this file.

    Args:
        cases_dir: The ``--cases`` directory, already contained and existing.

    Returns:
        Directory names holding a :data:`GROUND_TRUTH_FILENAME`, ascending by
        name -- which is also the order the aggregate consumes them in, so the
        output does not depend on the order the filesystem lists entries.

        A subdirectory without a ground truth file is not a case and is skipped:
        the directory may legitimately hold shared fixtures or a partially
        created case, and refusing to run at all would make every other case
        unmeasurable. ``--verbose`` names what was skipped.
    """
    names = [
        entry.name
        for entry in cases_dir.iterdir()
        if entry.is_dir() and (entry / GROUND_TRUTH_FILENAME).is_file()
    ]
    return sorted(names)


def load_ground_truth(path: Path) -> Dict[str, Any]:
    """Read and parse one ``ground_truth.json``.

    Args:
        path: The file, inside a case directory.

    Returns:
        The parsed document. Its fields are validated by
        ``benchmark/ground_truth.schema.json`` in
        ``tests/unit/test_ground_truth.py``, not here: the harness checks only
        what it must read to run, so that a schema violation is reported by the
        test that exists to report it rather than as an unevaluated case.

    Raises:
        CaseError: The file cannot be read or decoded, is not valid JSON, or is
            not a JSON object.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CaseError(
            MALFORMED_GROUND_TRUTH, "cannot read {0}: {1}".format(path.name, exc)
        ) from exc
    except UnicodeDecodeError as exc:
        raise CaseError(
            MALFORMED_GROUND_TRUTH,
            "{0} is not UTF-8 text: {1}".format(path.name, exc),
        ) from exc

    try:
        document = json.loads(text)
    except ValueError as exc:
        raise CaseError(
            MALFORMED_GROUND_TRUTH, "{0} is not valid JSON: {1}".format(path.name, exc)
        ) from exc

    if not isinstance(document, dict):
        raise CaseError(
            MALFORMED_GROUND_TRUTH,
            "{0} must hold a JSON object, got {1}".format(
                path.name, type(document).__name__
            ),
        )
    return document


def expectations_of(
    document: Mapping[str, Any], field: str = "expected_findings"
) -> List[Dict[str, Any]]:
    """Return the expectations to evaluate, in ground truth's own order.

    ``field`` names which ground-truth array to read. The combined and
    deterministic modes read ``expected_findings``; ``agent-only`` and
    ``human-review`` read the reserved ``expected_findings_agent_only`` and
    ``expected_findings_human_review`` arrays (Requirement 19 AC1, the AC12
    extension point). The reserved arrays are empty in every v0.1 case, so those
    modes measure nothing there rather than measuring the wrong thing: reading
    ``expected_findings`` for an agent-only run would evaluate the deterministic
    expectations against a review filtered to the Agent Source, reporting them
    all as missed.

    Args:
        document: One parsed ``ground_truth.json``.
        field: The expectation array to read. One of ``expected_findings``,
            ``expected_findings_agent_only``, ``expected_findings_human_review``.

    Returns:
        A new list of the entries.

    Raises:
        CaseError: ``field`` is absent, is not an array, or holds something other
            than objects. An expectation set that cannot be read is not an empty
            one -- that would report a perfect score for a broken case. The
            reserved arrays are ``required`` by the schema, so their absence is a
            malformed case rather than a mode that does not apply.
    """
    entries = document.get(field)
    if not isinstance(entries, list):
        raise CaseError(
            MALFORMED_GROUND_TRUTH,
            "{0} must be an array, got {1}".format(field, type(entries).__name__),
        )
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise CaseError(
                MALFORMED_GROUND_TRUTH,
                "{0}[{1}] must be an object, got {2}".format(
                    field, index, type(entry).__name__
                ),
            )
    return list(entries)


def template_path(case_dir: Path, document: Mapping[str, Any]) -> Path:
    """Resolve the template one case names, inside that case's directory.

    Args:
        case_dir: The case directory, already contained in the workspace.
        document: The parsed ground truth, whose ``template`` field names the
            file.

    Returns:
        The resolved absolute path to the template.

    Raises:
        CaseError: ``template`` is not a plain file name, escapes ``case_dir``,
            contains a shell metacharacter, or does not exist. The field is
            untrusted input like the template it names, so it is validated as a
            bare file name *and* contained against the case directory: the first
            check rejects ``../`` before any filesystem access, the second
            catches a symlink pointing out of the case directory, which no name
            check can see.
    """
    name = document.get("template")
    if not isinstance(name, str) or not name:
        raise CaseError(
            MALFORMED_GROUND_TRUTH,
            "template must be a non-empty file name, got {0!r}".format(name),
        )
    if name != Path(name).name or name in (".", ".."):
        raise CaseError(
            MALFORMED_GROUND_TRUTH,
            "template must be a file name with no path separator, got "
            "{0!r}".format(name),
        )

    try:
        resolved = pathguard.resolve_within(name, case_dir)
    except InputNotFoundError as exc:
        raise CaseError(MISSING_TEMPLATE, str(exc)) from exc
    except IacReviewError as exc:
        raise CaseError(MALFORMED_GROUND_TRUTH, str(exc)) from exc

    if not resolved.is_file():
        raise CaseError(
            MISSING_TEMPLATE,
            "template {0!r} is not a file".format(name),
        )
    return resolved


# ---------------------------------------------------------------------------
# The review
# ---------------------------------------------------------------------------


def review(
    orchestrator: Path,
    target: str,
    mode: Mode,
    agent_findings: Optional[str],
    *,
    verbose: bool,
) -> Dict[str, Any]:
    """Review one case with the ``iac-review`` orchestrator and parse its report.

    Args:
        orchestrator: Absolute path to ``run_iac_review.py``.
        target: The template, as a workspace-relative path. Relative so that the
            report names the file the way this summary does and no host path
            enters either.
        mode: The mode, whose :attr:`Mode.cli_sources` become ``--sources``.
        agent_findings: A fixture file for this case, or ``None``.
        verbose: Whether to echo the review's stderr.

    Returns:
        The parsed Review_Report.

    Raises:
        CaseError: The review exited non-zero, timed out, could not be started,
            or printed something that is not a Review_Report. All four mean the
            same thing for the benchmark: this case was not measured. A review
            that *completed* while reporting failures in ``errors[]`` -- an
            absent cfn-lint, for instance -- is not an error here: it returns 0,
            its report is real, and the missing Findings show up as missed
            expectations. ``--verbose`` shows the entries.
    """
    argv = [sys.executable, str(orchestrator), "--target", target]
    for source in mode.cli_sources:
        argv.extend(["--sources", source])
    if agent_findings is not None:
        argv.extend(["--agent-findings", agent_findings])

    try:
        # Argument array, no shell, no inherited AWS credentials
        # (Requirement 16 AC6, Requirement 9 AC2).
        result = proc.run(argv, REVIEW_TIMEOUT_S)
    except IacReviewError as exc:
        raise CaseError(
            REVIEW_FAILED, "{0}: {1}".format(exc.error_class, exc.message)
        ) from exc

    if verbose and result.stderr:
        for line in result.stderr.rstrip("\n").split("\n"):
            bootstrap.diagnostic("  review: {0}".format(line))

    if result.exit_code != exitcodes.OK:
        raise CaseError(
            REVIEW_FAILED,
            "the review exited {0}; first lines of its stderr:\n{1}".format(
                result.exit_code, _stderr_head(result.stderr)
            ),
        )

    try:
        document = json.loads(result.stdout)
    except ValueError as exc:
        raise CaseError(
            REVIEW_FAILED, "the review printed no parsable report: {0}".format(exc)
        ) from exc

    if not isinstance(document, dict) or not set(report.REPORT_KEYS) <= set(document):
        raise CaseError(
            REVIEW_FAILED,
            "the review printed something other than a Review_Report",
        )
    if not isinstance(document.get("findings"), list):
        raise CaseError(REVIEW_FAILED, "the report's findings are not an array")
    return document


def _stderr_head(text: str, limit: int = 5) -> str:
    """First ``limit`` lines of a failed review's stderr, for a diagnostic.

    Bounded for the same reason :class:`iacreview.errors.IacReviewError` bounds
    its own: a tool that failed can produce a great deal of output, and the first
    few lines are where the cause is.
    """
    lines = [line for line in text.split("\n") if line.strip()]
    return "\n".join("    {0}".format(line) for line in lines[:limit])


def _findings_of(document: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """The report's Findings, keeping only the objects among them."""
    return [entry for entry in document["findings"] if isinstance(entry, dict)]


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

#: Separator between a case ID and a resource logical ID in an aggregate match
#: key. ``::`` cannot occur in either half -- a logical ID is alphanumeric and a
#: case ID is ``case-NNN-slug`` -- so no two cases can produce one key.
CASE_SEPARATOR = "::"


def namespaced(item: metrics.Item, case_id: str) -> Dict[str, Any]:
    """Return a copy of ``item`` whose resource is prefixed with ``case_id``.

    What makes the aggregate honest. ``metrics`` compares on resource, finding
    type and category, and two cases may legitimately use the same logical ID for
    the same kind of problem; pooling them unprefixed would let one case's Finding
    satisfy another case's expectation. Prefixing keeps the pooled numbers equal
    to the sum of the per-case numbers.

    Args:
        item: One expectation or one Finding.
        case_id: The case it came from.

    Returns:
        A new dict. The resource is rewritten under whichever spelling the item
        already uses, so an expectation stays snake_case and a Finding keeps the
        report's spelling. An item carrying neither is returned unchanged, and
        :mod:`metrics` reports it as the malformed input it is.
    """
    for name in metrics.FIELD_ALIASES["resource"]:
        if name in item:
            copy = dict(item)
            value = item[name]
            copy[name] = "{0}{1}{2}".format(
                case_id, CASE_SEPARATOR, "" if value is None else value
            )
            return copy
    return dict(item)


def case_status(per_category: Mapping[str, Mapping[str, Any]]) -> str:
    """Return one PASS / FAIL / INFO verdict for a whole case or a whole run.

    :func:`metrics.category_status` decides a single category; a case spans
    several. The rule is applied once to their pooled ``deterministic`` counts
    rather than restated, so a case is ``PASS`` exactly when every deterministic
    expectation in it was detected, ``FAIL`` when one was missed
    (Requirement 11 AC7), and ``INFO`` when it holds no deterministic expectation
    to hold to a threshold (Requirement 11 AC8).

    Args:
        per_category: :func:`metrics.compute_by_category`'s result.

    Returns:
        One of :data:`metrics.STATUS_PASS`, :data:`metrics.STATUS_FAIL`,
        :data:`metrics.STATUS_INFO`. ``FAIL`` for exactly the inputs
        :func:`metrics.has_failure` is true for.
    """
    expected = sum(
        int(entry["deterministic_expected_count"]) for entry in per_category.values()
    )
    matched = sum(
        int(entry["deterministic_matched_count"]) for entry in per_category.values()
    )
    return metrics.category_status(
        metrics.percentage(matched, expected), expected > 0
    )


# ---------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------


class Benchmark:
    """State of one benchmark run.

    A short-lived object rather than module state, so a test may call
    :func:`main` twice in one process without the second run inheriting the
    first one's numbers.

    Attributes:
        root: The workspace root (:func:`workspace_root`).
        cases_dir: Contained, existing ``--cases`` directory.
        mode: The selected :class:`Mode`. Always the mode *measured*; the mode a
            case is *reviewed* with is :func:`review_mode` of it and
            :attr:`filter_only`.
        filter_only: The ``--filter-only`` value.
        agent_dir: Contained ``--agent-findings`` directory, or ``None``.
        orchestrator: Absolute path to the entry point a case is reviewed with.
        entries: One summary entry per discovered case, in case ID order.
        errors: ``{"case_id", "reason"}`` for each case that was not evaluated,
            in the same order.
        pooled_expected: Every evaluated case's expectations, namespaced.
        pooled_actual: Every evaluated case's Findings, namespaced.
        completed: Whether :meth:`run` finished. Read by :func:`main` so that a
            run which never happened -- ``--help``, a rejected argument -- cannot
            be given a benchmark verdict.
    """

    def __init__(self) -> None:
        self.root: Path = workspace_root()
        self.cases_dir: Optional[Path] = None
        self.mode: Mode = MODES[DEFAULT_MODE]
        self.filter_only: bool = False
        self.agent_dir: Optional[Path] = None
        self.agent_runs: int = 1
        self.orchestrator: Optional[Path] = None
        self.entries: List[Dict[str, Any]] = []
        self.errors: List[Dict[str, str]] = []
        self.pooled_expected: List[Dict[str, Any]] = []
        self.pooled_actual: List[Dict[str, Any]] = []
        self.completed: bool = False

    # -- argument validation ------------------------------------------------

    def validate(self, args: argparse.Namespace) -> None:
        """Resolve and contain every path before any work begins.

        Runs in :func:`iacreview.bootstrap.run_entry_point`'s ``validate`` slot,
        which is before the first file read and the first subprocess
        (Requirement 16 AC7).

        Args:
            args: The parsed namespace.

        Raises:
            UnsafeArgumentError: A path contains a shell metacharacter (exit 2).
            InvalidArgumentsError: A path is empty, cannot be normalized, or is
                not a directory (exit 2).
            InputNotFoundError: A path does not exist (exit 3).
            PathContainmentError: A path resolves outside the workspace (exit 7).
            MappingFileError: The orchestrator is missing from this installation
                (exit 1).
        """
        cases_dir = pathguard.resolve_within(args.cases, self.root)
        if not cases_dir.is_dir():
            raise InvalidArgumentsError(
                "--cases must be a directory of case directories: {0!r}".format(
                    args.cases
                ),
                remediation="Pass the directory holding the case directories, "
                "normally benchmark/cases.",
            )
        self.cases_dir = cases_dir
        self.mode = MODES[args.mode]
        self.filter_only = bool(args.filter_only)

        # argparse's type=int has already rejected a non-integer; a value below 1
        # is a caller asking for zero reviews, which measures nothing.
        if args.agent_runs < 1:
            raise InvalidArgumentsError(
                "--agent-runs must be at least 1, got {0}".format(args.agent_runs),
                remediation="Pass --agent-runs 1 or greater; the default is 1.",
            )
        self.agent_runs = int(args.agent_runs)

        if args.agent_findings:
            agent_dir = pathguard.resolve_within(args.agent_findings, self.root)
            if not agent_dir.is_dir():
                raise InvalidArgumentsError(
                    "--agent-findings must be a directory of <case_id>.json "
                    "fixtures: {0!r}".format(args.agent_findings)
                )
            self.agent_dir = agent_dir

        # Plugin-owned, so a missing orchestrator is a broken installation
        # (exit 1) reported once, rather than a review failure per case.
        self.orchestrator = pathguard.resolve_plugin_owned(ORCHESTRATOR)

    # -- per case -----------------------------------------------------------

    def _relative_to_root(self, path: Path) -> str:
        """Render ``path`` as the workspace-relative string the review is given.

        Both the case directory and the template are contained in the workspace
        root by :meth:`validate` and :func:`template_path`, so the relative form
        always exists and no absolute path is ever passed to the review or put in
        the summary.
        """
        return str(path.relative_to(self.root))

    def _case_directory(self, case_id: str) -> Path:
        """Resolve one case directory, contained in the ``--cases`` tree.

        Args:
            case_id: A directory name from :func:`discover_cases`.

        Returns:
            The resolved absolute directory.

        Raises:
            CaseError: The directory resolves outside ``--cases`` -- a symlink
                pointing away from the benchmark tree -- or its name carries a
                shell metacharacter. Recorded against the case rather than
                aborting: one suspicious directory does not make the other cases
                unmeasurable.
        """
        assert self.cases_dir is not None
        try:
            return pathguard.resolve_within(case_id, self.cases_dir)
        except IacReviewError as exc:
            raise CaseError(
                UNSAFE_CASE_PATH, "{0}: {1}".format(exc.error_class, exc.message)
            ) from exc

    def _agent_findings_for(self, case_id: str) -> Optional[str]:
        """Return this case's agent finding fixture, as a relative path.

        Args:
            case_id: The case directory name, which is also the fixture's stem.

        Returns:
            ``<--agent-findings>/<case_id>.json`` when that file exists, else
            ``None``. A case with no fixture is reviewed without agent findings:
            the reserved expectation arrays are not evaluated in v0.1, so a
            missing fixture narrows what is measured rather than breaking it.
        """
        if self.agent_dir is None:
            return None
        try:
            resolved = pathguard.resolve_within(
                "{0}.json".format(case_id), self.agent_dir
            )
        except InputNotFoundError:
            return None
        return self._relative_to_root(resolved)

    def _evaluate(self, case_id: str, *, verbose: bool) -> Dict[str, Any]:
        """Review one case and measure it.

        Args:
            case_id: The case directory name, used as the case ID rather than the
                ``case_id`` field: the directory is what was discovered, and a
                document claiming a different ID would attribute results to the
                wrong case. ``tests/unit/test_ground_truth.py`` asserts the two
                agree.
            verbose: Whether to emit per-case diagnostics.

        Returns:
            One entry with exactly the keys of :data:`CASE_KEYS`.

        Note:
            Never raises. A :class:`CaseError` becomes an unevaluated entry plus
            one :attr:`errors` record, and the run continues with the next case.
        """
        # validate() ran first (run_entry_point guarantees the order), so both are
        # set; asserted rather than re-derived so a future caller that skips
        # validation fails here instead of reviewing an unchecked path.
        assert self.cases_dir is not None and self.orchestrator is not None
        template_name: Optional[str] = None
        document: Mapping[str, Any] = {}

        try:
            case_dir = self._case_directory(case_id)
            document = load_ground_truth(case_dir / GROUND_TRUTH_FILENAME)
            expected_all = expectations_of(document, self.mode.expectation_field)
            template = template_path(case_dir, document)
            template_name = template.name
            report_document = self._review_timed(
                case_id,
                self._relative_to_root(template),
                self._agent_findings_for(case_id),
                verbose=verbose,
            )
        except CaseError as exc:
            bootstrap.diagnostic(
                "warning: {0}: {1}: {2}".format(case_id, exc.reason, exc)
            )
            self.errors.append({"case_id": case_id, "reason": exc.reason})
            return self._unevaluated_entry(case_id, template_name, exc.reason)

        for entry in report_document["errors"]:
            # Environment-dependent, so stderr and not stdout: which tools are
            # installed is not part of what the benchmark measures, but a reader
            # looking at a low detection rate needs to see it.
            if not isinstance(entry, dict):
                continue
            bootstrap.diagnostic(
                "warning: {0}: the review reported {1}: {2}".format(
                    case_id,
                    entry.get("error_class"),
                    entry.get("message"),
                )
            )
        self._warn_absent_tool(case_id, report_document)

        expected = metrics.filter_by_source(expected_all, self.mode.source)
        actual = metrics.filter_by_source(
            _findings_of(report_document), self.mode.source
        )

        try:
            measured = metrics.compute(expected, actual)
            per_category = metrics.compute_by_category(expected, actual)
        except metrics.MetricsInputError as exc:
            # A field the comparison needs is absent. On the expectation side the
            # schema forbids it, and on the Finding side the report schema does,
            # so this is a malformed case or a defective report rather than a
            # measurement.
            bootstrap.diagnostic(
                "warning: {0}: {1}: {2}".format(case_id, MALFORMED_GROUND_TRUTH, exc)
            )
            self.errors.append(
                {"case_id": case_id, "reason": MALFORMED_GROUND_TRUTH}
            )
            return self._unevaluated_entry(
                case_id, template_name, MALFORMED_GROUND_TRUTH
            )

        diagnostics = metrics.compute_diagnostics(expected, actual, document)

        # An unthresholded mode (human-review) is only ever measured, never held
        # to a threshold, so its expectations are kept out of the pool that
        # decides the run's verdict. Pooling them would let a human-review
        # expectation the pipeline cannot reach make the aggregate FAIL, which
        # Requirement 19 AC1 forbids. Its per-case metrics are still reported.
        if self.mode.thresholded:
            self.pooled_expected.extend(namespaced(item, case_id) for item in expected)
            self.pooled_actual.extend(namespaced(item, case_id) for item in actual)
            status = case_status(per_category)
        else:
            status = metrics.STATUS_INFO

        bootstrap.verbose_diagnostic(
            "{0}: expected {1}, matched {2}, false positives {3}: {4}".format(
                case_id,
                measured["expected_count"],
                measured["matched_count"],
                measured["false_positive_count"],
                status,
            ),
            verbose=verbose,
        )
        return {
            "case_id": case_id,
            "template": template_name,
            "evaluated": True,
            "reason": None,
            "metrics": measured,
            "categories": per_category,
            "diagnostics": diagnostics,
            "status": status,
        }

    def _warn_absent_tool(self, case_id: str, document: Mapping[str, Any]) -> None:
        """Say when a ``--filter-only`` measurement is empty for want of a tool.

        The one place the two paths of the module docstring are not
        interchangeable. Without ``--filter-only``, an absent cfn-lint or
        cfn-guard leaves its single-Source review with no Source able to run, so
        the orchestrator fails and the case is recorded unevaluated -- visible,
        and attributed to the environment. With ``--filter-only`` the combined
        review succeeds on the Sources that *are* installed, and filtering it to
        the absent one yields nothing, which is indistinguishable from a review
        that stopped detecting anything: exit
        :data:`BENCHMARK_FAILURE`, reported as a regression.

        Args:
            case_id: The case being measured.
            document: Its Review_Report, whose ``tools`` array carries one
                ``available`` flag per external tool the review looked for.

        Note:
            stderr, not stdout, and not an :attr:`errors` entry: which tools the
            host installed is environment-dependent, and Requirement 16 AC11
            keeps that out of the summary. Nothing about the measurement changes
            -- the numbers are what they are, and the reader is told how to read
            them.
        """
        if not self.filter_only or self.mode.source is None:
            return
        executable = TOOL_BY_SOURCE.get(self.mode.source)
        if executable is None:
            return
        entries = document.get("tools")
        if not isinstance(entries, list):
            return
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            if entry.get("name") == executable and entry.get("available") is False:
                bootstrap.diagnostic(
                    "warning: {0}: --filter-only measured {1} from a review in "
                    "which {2} was unavailable, so this case has nothing to "
                    "detect with; the missed expectations are an absent tool, "
                    "not a regression".format(case_id, self.mode.source, executable)
                )
                return

    @staticmethod
    def _unevaluated_entry(
        case_id: str, template: Optional[str], reason: str
    ) -> Dict[str, Any]:
        """One case entry for a case that was not measured."""
        return {
            "case_id": case_id,
            "template": template,
            "evaluated": False,
            "reason": reason,
            "metrics": None,
            "categories": {},
            "diagnostics": None,
            "status": None,
        }

    def _review_timed(
        self,
        case_id: str,
        target: str,
        agent_findings: Optional[str],
        *,
        verbose: bool,
    ) -> Dict[str, Any]:
        """Review one case, measuring Review Time and reporting it on stderr.

        Review Time is a diagnostic (Requirement 19 AC2) that must not enter the
        byte-identical summary: it is wall-clock, so two runs would differ in it
        (Requirement 16 AC11). It goes to stderr, the second channel design.md's
        Determinism Design reserves for environment-dependent metadata, and never
        to stdout. When ``--agent-runs`` is greater than one, the review runs that
        many times and the variation across runs is reported too (Requirement 19
        AC4); the report used for measurement is the first run's, so the
        deterministic Sources are evaluated exactly once against a single report
        whatever the repeat count.

        Args:
            case_id: The case, for the diagnostic line.
            target: Workspace-relative template path.
            agent_findings: The case's fixture, or ``None``.
            verbose: Whether to echo the review's stderr.

        Returns:
            The first run's parsed Review_Report -- the one the metrics are
            computed from.

        Raises:
            CaseError: The first review did not produce a report. Repeat runs
                that fail are noted on stderr and do not abort the case: the
                measurement already has its report.
        """
        reviewed_mode = review_mode(self.mode, self.filter_only)
        elapsed: List[float] = []

        start = time.monotonic()
        first = review(
            self.orchestrator, target, reviewed_mode, agent_findings, verbose=verbose
        )
        elapsed.append(time.monotonic() - start)

        # Requirement 19 AC4: repeat runs characterise Agent variation. Only when
        # the mode measures the Agent Source and a fixture is present is there
        # anything that could vary; a deterministic mode's repeats would be
        # identical by construction, so they are skipped rather than timed.
        repeats = self.agent_runs - 1
        if repeats > 0 and self.mode.source == agentin.SOURCE_NAME:
            for _ in range(repeats):
                try:
                    start = time.monotonic()
                    review(
                        self.orchestrator,
                        target,
                        reviewed_mode,
                        agent_findings,
                        verbose=verbose,
                    )
                    elapsed.append(time.monotonic() - start)
                except CaseError as exc:
                    bootstrap.diagnostic(
                        "warning: {0}: repeat agent run did not complete: "
                        "{1}".format(case_id, exc)
                    )

        self._report_timing(case_id, elapsed, verbose=verbose)
        return first

    @staticmethod
    def _report_timing(
        case_id: str, elapsed: Sequence[float], *, verbose: bool
    ) -> None:
        """Report Review Time on stderr, never on stdout (Requirement 19 AC2).

        Args:
            case_id: The case measured.
            elapsed: One wall-clock duration per completed review, in seconds.
            verbose: Whether to emit the line; timing is a verbose-only
                diagnostic, since a non-verbose run's stderr is reserved for
                warnings.
        """
        if not elapsed:
            return
        if len(elapsed) == 1:
            bootstrap.verbose_diagnostic(
                "{0}: review time {1:.3f}s".format(case_id, elapsed[0]),
                verbose=verbose,
            )
            return
        bootstrap.verbose_diagnostic(
            "{0}: review time over {1} runs min {2:.3f}s max {3:.3f}s "
            "mean {4:.3f}s".format(
                case_id,
                len(elapsed),
                min(elapsed),
                max(elapsed),
                sum(elapsed) / len(elapsed),
            ),
            verbose=verbose,
        )

    # -- output -------------------------------------------------------------

    def summary(self) -> Dict[str, Any]:
        """Assemble the document printed on stdout.

        Returns:
            A dict with exactly the keys of :data:`SUMMARY_KEYS`. ``metrics`` and
            ``categories`` are measured over every evaluated case at once, on the
            namespaced items :func:`namespaced` produced.
        """
        per_category = metrics.compute_by_category(
            self.pooled_expected, self.pooled_actual
        )
        return {
            "schema_version": SCHEMA_VERSION,
            "mode": self.mode.name,
            "sources_evaluated": list(self.mode.sources_evaluated),
            "filter_only": self.filter_only,
            "agent_findings_supplied": self.agent_dir is not None,
            "cases": list(self.entries),
            "metrics": metrics.compute(self.pooled_expected, self.pooled_actual),
            "categories": per_category,
            "diagnostics": self._aggregate_diagnostics(),
            "status": case_status(per_category),
            "errors": list(self.errors),
        }

    def _aggregate_diagnostics(self) -> Dict[str, Any]:
        """Roll the per-case diagnostic blocks up into one (Requirement 19 AC3).

        Diagnostics never bear on the run's verdict, so this is reporting rather
        than arithmetic the pass/fail rule reads. A key is :data:`aggregated
        <metrics.NOT_APPLICABLE>` unless at least one evaluated case declared it:
        Human Intervention Count sums the declared counts, and Remediation
        Accuracy is the *unweighted* mean of the declared per-case rates -- a
        case declaring one remediation and a case declaring ten weigh equally,
        not a pool of the underlying cleared/declared counts
        (``docs/benchmark-methodology.md`` states why). When no case declared a
        diagnostic, it stays :data:`metrics.NOT_APPLICABLE` (AC6), so the block's
        shape is the same whatever the cases measured.

        Returns:
            A dict with exactly the keys of :data:`metrics.DIAGNOSTIC_KEYS`.
        """
        blocks = [
            entry["diagnostics"]
            for entry in self.entries
            if entry.get("evaluated") and isinstance(entry.get("diagnostics"), dict)
        ]

        intervention_counts = [
            block["human_intervention_count"]
            for block in blocks
            if isinstance(block["human_intervention_count"], int)
            and not isinstance(block["human_intervention_count"], bool)
        ]
        if intervention_counts:
            human_intervention: Any = sum(intervention_counts)
        else:
            human_intervention = metrics.NOT_APPLICABLE

        # Average the declared per-case rates. Parsed back from the one-decimal
        # strings compute_diagnostics produced, then re-formatted, so the
        # aggregate is a percentage string like the per-case values and stays
        # byte-stable.
        rates = [
            float(block["remediation_accuracy"])
            for block in blocks
            if block["remediation_accuracy"] != metrics.NOT_APPLICABLE
        ]
        if rates:
            remediation_accuracy: Any = metrics.format_percentage(
                sum(rates) / len(rates)
            )
        else:
            remediation_accuracy = metrics.NOT_APPLICABLE

        return {
            "remediation_accuracy": remediation_accuracy,
            "human_intervention_count": human_intervention,
        }

    def exit_code(self) -> int:
        """The benchmark's own verdict, as a process status.

        Returns:
            :data:`BENCHMARK_FAILURE` when any category is ``FAIL``
            (Requirement 11 AC7), which is :func:`metrics.has_failure` and
            nothing else: the threshold rule lives there, and this reads it.
            :data:`CASE_NOT_EVALUATED` when nothing measured failed but a case
            could not be measured, so the run is incomplete rather than clean.
            :data:`iacreview.exitcodes.OK` otherwise.
        """
        per_category = metrics.compute_by_category(
            self.pooled_expected, self.pooled_actual
        )
        if metrics.has_failure(per_category):
            return BENCHMARK_FAILURE
        if self.errors:
            return CASE_NOT_EVALUATED
        return exitcodes.OK

    # -- the run ------------------------------------------------------------

    def run(self, args: argparse.Namespace) -> bootstrap.EntryPointOutcome:
        """Review and measure every discovered case.

        Args:
            args: Parsed arguments. Only ``--verbose`` is read here; the rest was
                consumed by :meth:`validate`.

        Returns:
            The summary, with :data:`iacreview.exitcodes.OK`. The benchmark's own
            verdict is *not* returned here: :class:`EntryPointOutcome` accepts
            only the plugin's documented exit codes, and
            :data:`BENCHMARK_FAILURE` is deliberately outside them.
            :func:`main` applies it after the wrapper has returned.
        """
        assert self.cases_dir is not None
        verbose = args.verbose

        case_ids = discover_cases(self.cases_dir)
        if verbose:
            skipped = sorted(
                entry.name
                for entry in self.cases_dir.iterdir()
                if entry.is_dir() and entry.name not in case_ids
            )
            for name in skipped:
                bootstrap.diagnostic(
                    "{0}: no {1}; not a case".format(name, GROUND_TRUTH_FILENAME)
                )
        bootstrap.verbose_diagnostic(
            "{0} case(s), mode {1}, reviewed with {2}".format(
                len(case_ids),
                self.mode.name,
                ", ".join(review_mode(self.mode, self.filter_only).cli_sources)
                or "every Source",
            ),
            verbose=verbose,
        )
        if self.filter_only and self.mode.source is None:
            # Accepted rather than refused: combined enables every Source on both
            # paths, so the flag is redundant here and not wrong. Refusing it
            # would make a sweep over the modes special-case one of them, which
            # is the sweep the flag exists for.
            bootstrap.verbose_diagnostic(
                "--filter-only changes nothing for mode {0}: its review already "
                "enables every Source".format(self.mode.name),
                verbose=verbose,
            )

        for case_id in case_ids:
            self.entries.append(self._evaluate(case_id, verbose=verbose))

        self.completed = True
        return bootstrap.EntryPointOutcome(
            report=self.summary(), exit_code=exitcodes.OK
        )


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the benchmark and return its exit code.

    Args:
        argv: Arguments without the program name. ``None`` reads
            ``sys.argv[1:]``.

    Returns:
        One of :data:`HARNESS_EXIT_CODES`. The shared wrapper's code when the run
        did not complete -- an argument was rejected, a path escaped the
        workspace, ``--help`` was asked for -- and otherwise the benchmark's own
        verdict from :meth:`Benchmark.exit_code`.
    """
    benchmark = Benchmark()
    code = bootstrap.run_entry_point(
        parser=build_parser(),
        run=benchmark.run,
        argv=argv,
        validate=benchmark.validate,
    )
    if code != exitcodes.OK or not benchmark.completed:
        return code
    return benchmark.exit_code()


if __name__ == "__main__":
    sys.exit(main())
