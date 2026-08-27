#!/usr/bin/env python3
"""Layer 1 of the ``iam-review`` Skill: deterministic IAM findings as a report.

One of the two entry points of this Skill, and the deterministic one. It reviews
each Template named with ``--target`` through :func:`iacreview.iam.run_and_normalize`
and prints a Review_Report on stdout. Every Finding it emits carries
``Confidence: "Confirmed"`` (Requirement 7 AC9): the fifteen detectors match
enumerated action names, values and structures, so a match is an observation
rather than an estimate.

Layer 2 -- the contextual reasoning the host Agent performs -- is not run here.
Its input comes from the sibling ``extract_policies.py``, and its output is
merged by ``iac-review``. Keeping the two in separate scripts is what lets a
client take the deterministic answer alone, with no Agent involved
(Requirement 2 AC8).

The script is deliberately thin. Path containment, Template loading, policy
location, detection, deduplication and report assembly all live in
:mod:`iacreview`, shared with the ``iac-review`` orchestrator, so running this
Skill standalone and running it as part of a full review cannot produce
different Findings for the same Template (Requirement 2 AC16).

Streams
-------

stdout
    The Review_Report JSON, and nothing else (Requirement 16 AC10). Byte-stable
    for a given input, with or without ``--verbose`` (Requirement 16 AC11).
stderr
    Diagnostics. Requirement 6 AC12's informational message for a Template with
    no IAM lands here unconditionally -- it is a statement about the review, not
    a Finding, and the report envelope has no field for it.

Exit codes
----------

===  =====================================================================
0    The review ran. Zero findings is a successful review, not a failure.
2    Argument validation failed: no ``--target``, unknown flag, or a shell
     metacharacter in a path.
3    A ``--target`` path does not exist or cannot be read.
4    A Template could not be parsed as YAML or JSON. stdout carries a report
     whose ``errors[]`` describes the failure.
7    A ``--target`` path resolves outside the workspace root. stdout is empty.
8    A Template holds no non-empty ``Resources`` mapping, so there was nothing
     to review. stdout carries a report with ``errors[]``.
1    Unexpected internal error; the trace is on stderr.
===  =====================================================================

Exit codes 5 and 6 cannot occur: this Skill runs no external tool.
"""

import sys
from pathlib import Path

# scripts/ -> skill dir -> skills/ -> plugin root
_PLUGIN_ROOT = Path(__file__).resolve().parents[3]
if str(_PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_ROOT))

from iacreview import bootstrap  # noqa: E402

bootstrap.require_plugin_root(__file__)

import argparse  # noqa: E402
from typing import Any, Dict, List, Optional, Sequence  # noqa: E402

from iacreview import dedup, exitcodes, iam, pathguard, report  # noqa: E402
from iacreview.errors import IacReviewError  # noqa: E402
from iacreview.source import SourceResult, workspace_relative  # noqa: E402

#: The one Source this script speaks for.
SOURCE_NAME = iam.SOURCE_NAME

#: Shown in ``--help``.
DESCRIPTION = (
    "Review the IAM policies of one or more CloudFormation templates with the "
    "plugin's deterministic detectors and print a normalized review report on "
    "stdout. Every finding carries Confidence 'Confirmed'."
)

#: Error classes whose report is still worth printing. For these the review
#: reached a Template and has something to say about *why* it produced nothing,
#: which design.md's failure-mode matrix asks to appear in ``errors[]`` rather
#: than only on stderr. Every other failure (a path outside the workspace, a
#: missing file, bad argv) happened before a Template was read, and design.md
#: leaves stdout empty for those.
REPORTED_ERROR_CLASSES = ("parse_failure", "no_reviewable_template")


def build_parser() -> bootstrap.EntryPointParser:
    """Build the argument parser.

    Returns:
        A parser accepting ``--target`` (required, repeatable) and ``--verbose``.

    Note:
        ``--target`` takes a Template file, never a directory: discovering
        Templates in a tree, and telling a CDK output directory from ordinary
        input, belongs to the ``iac-review`` Skill (Requirement 8). Naming files
        explicitly keeps this Skill's output a function of its arguments.
    """
    parser = bootstrap.new_parser(Path(__file__).name, DESCRIPTION)
    parser.add_argument(
        "--target",
        action="append",
        metavar="PATH",
        required=True,
        help=(
            "Path to a CloudFormation template file, relative to the current "
            "working directory. Repeat the option to review several templates "
            "in one report."
        ),
    )
    return parser


def workspace_root() -> Path:
    """Containment root for every ``--target``, and the root report paths are relative to.

    Returns:
        The current working directory. The caller's directory is the workspace
        the way Agent Plugins 1.0.0 uses the term: the plugin's own directory is
        where its code lives, not where the reviewed Templates live, so
        containment is checked against the invoking workspace and a Template
        outside it is refused (Requirement 9 AC4).
    """
    return Path.cwd()


def validate(args: argparse.Namespace) -> None:
    """Resolve every ``--target`` before any file is opened.

    Runs as :func:`iacreview.bootstrap.run_entry_point`'s ``validate`` hook, so
    an unusable path is rejected before the first Template is read
    (Requirement 16 AC7). The resolved paths are attached to ``args`` rather than
    resolved a second time in :func:`run`, so containment is checked exactly
    once per target and the check cannot be skipped by a later code path.

    Args:
        args: Parsed arguments. Gains a ``resolved_targets`` attribute holding
            one absolute path per ``--target``, in the order given.

    Raises:
        UnsafeArgumentError: A target contains a shell metacharacter (exit 2).
        InvalidArgumentsError: A target is empty or cannot be normalized (exit 2).
        InputNotFoundError: A target does not exist (exit 3).
        PathContainmentError: A target resolves outside the workspace (exit 7).
    """
    root = workspace_root()
    args.resolved_targets = [
        pathguard.resolve_within(target, root) for target in args.target
    ]


def _relative(path: Path, root: Path) -> str:
    """Render ``path`` as the workspace-relative path a report may carry.

    ``resolve_within`` has already established containment, so the relative form
    exists; ``.name`` covers only the degenerate case of the root itself.
    """
    return workspace_relative(str(path), root) or path.name


def _review_one(
    resolved: Path, root: Path, *, verbose: bool
) -> SourceResult:
    """Review one Template and report what was examined on stderr.

    Args:
        resolved: Absolute, already-contained path to the Template.
        root: Workspace root, which ``Location.File`` values are relative to.
        verbose: The ``--verbose`` flag, gating the counter diagnostics only.

    Returns:
        The Source's result, Findings not yet deduplicated.
    """
    result = iam.run_and_normalize(resolved, workspace_root=root)
    relative = _relative(resolved, root)

    message = result.stats.get("informational_message")
    if message:
        # Requirement 6 AC12 asks for an informational message alongside the
        # zero findings. Not gated on --verbose: it is the answer, not a
        # diagnostic. Not on stdout: the report envelope has no field for it and
        # stdout is the machine-readable channel.
        bootstrap.diagnostic("{0}: {1}".format(relative, message))

    bootstrap.verbose_diagnostic(
        "{0}: {1} policy sites, {2} statements, {3} detectors, "
        "{4} unresolvable locations, {5} findings".format(
            relative,
            result.stats.get("policy_sites"),
            result.stats.get("statements_analysed"),
            result.stats.get("detectors_evaluated"),
            result.stats.get("unresolvable_locations"),
            len(result.findings),
        ),
        verbose=verbose,
    )
    return result


def _exit_code(results: Sequence[SourceResult]) -> int:
    """Exit status for a run that completed.

    Returns:
        :data:`iacreview.exitcodes.OK`, unless a result carried a non-fatal
        error -- then the status of the first such result. This Source runs no
        external tool and documents ``errors`` as always empty, so the branch is
        not reachable today; it exists because dropping a recorded error while
        still reporting exit 0 would be the one failure mode a reader of the
        report could not detect.
    """
    for result in results:
        status = result.exit_status()
        if status != exitcodes.OK:
            return status
    return exitcodes.OK


def run(args: argparse.Namespace) -> bootstrap.EntryPointOutcome:
    """Review every target and assemble one report.

    Findings are deduplicated per Template, then numbered across the whole
    report. Per-Template is the right granularity because equivalence is matched
    on resource logical ID and Category (Requirement 14 AC5), and two Templates
    may legitimately use the same logical ID for unrelated resources; merging
    across files would attribute one Template's Evidence to another's resource.

    Deduplication runs even though there is a single Source. design.md's Layer 1
    table says so explicitly: several detectors matching one Role all produce
    Category ``IAM`` Findings on that Role, and the merged entry keeps every
    detector's Evidence, so the report answers "why is this CRITICAL" with all
    of the reasons rather than repeating the resource once per rule.

    Args:
        args: Parsed arguments, carrying ``resolved_targets`` from
            :func:`validate`.

    Returns:
        The report and its exit code.
    """
    root = workspace_root()
    results: List[SourceResult] = []
    findings: List[Any] = []
    files: List[str] = []

    for resolved in args.resolved_targets:
        result = _review_one(resolved, root, verbose=args.verbose)
        results.append(result)
        findings.extend(dedup.deduplicate(result.findings))
        files.append(_relative(resolved, root))

    payload = report.build_report(
        findings,
        [error for result in results for error in result.errors],
        report.ReportMeta(
            files=files,
            sources_enabled=[SOURCE_NAME],
            # No ``tools`` entry: this Skill invokes no external executable, so
            # there is no availability or version to report.
            tools=(),
        ),
    )
    return bootstrap.EntryPointOutcome(report=payload, exit_code=_exit_code(results))


def partial_report(exc: IacReviewError) -> Optional[Dict[str, Any]]:
    """Report to print when the review failed, or ``None`` to keep stdout empty.

    Args:
        exc: The failure :func:`iacreview.bootstrap.run_entry_point` caught.

    Returns:
        A report carrying the failure in ``errors[]`` for the classes of
        :data:`REPORTED_ERROR_CLASSES`, otherwise ``None``. ``target.files`` is
        empty in that report: no Template was reviewed, and listing the one that
        failed to parse under ``files`` would claim otherwise.
    """
    if exc.error_class not in REPORTED_ERROR_CLASSES:
        return None
    return report.build_report(
        [],
        [exc.to_structured_error(SOURCE_NAME)],
        report.ReportMeta(sources_enabled=[SOURCE_NAME]),
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point.

    Args:
        argv: Arguments without the program name. Defaults to ``sys.argv[1:]``.

    Returns:
        A documented exit code from :mod:`iacreview.exitcodes`.
    """
    return bootstrap.run_entry_point(
        parser=build_parser(),
        run=run,
        argv=argv,
        validate=validate,
        partial_report=partial_report,
    )


if __name__ == "__main__":
    sys.exit(main())
