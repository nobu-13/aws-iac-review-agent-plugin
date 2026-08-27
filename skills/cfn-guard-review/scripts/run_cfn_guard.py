#!/usr/bin/env python3
"""Entry point of the ``cfn-guard-review`` Skill.

Runs cfn-guard against one or more CloudFormation Templates with the bundled
Guard rules, plus any rule directory the caller adds with ``--rules-dir``, and
writes one Review_Report on stdout (Requirement 2 AC3, Requirement 5).

The script is deliberately thin: every decision it could make wrongly is made in
:mod:`iacreview`. It resolves paths (:mod:`iacreview.pathguard`), rejects input
that is not a reviewable Template (:mod:`iacreview.template`), delegates the run
and the normalization to :func:`iacreview.cfnguard.run_and_normalize`, merges
equivalent Findings (:func:`iacreview.dedup.deduplicate`) and serializes the
report (:mod:`iacreview.report`). Requirement 2 AC16 is the reason: the
orchestrating ``iac-review`` Skill calls the same functions, so neither Skill may
own a copy of this logic.

``--rules-dir`` is repeatable and *additive*
--------------------------------------------

The bundled ``rules/`` tree is always evaluated, so the Skill works with no
configuration (Requirement 10 AC1); each ``--rules-dir`` adds to it rather than
replacing it (design.md O-10). Two invocations that name the same directories in
a different order produce byte-identical stdout, because
:func:`iacreview.cfnguard.resolve_rules_dirs` sorts the command line and
:func:`iacreview.cfnguard.sort_results` sorts the Findings by rule name. Every
value goes through :func:`iacreview.pathguard.resolve_within`, so a directory
outside the workspace is refused with exit 7 before cfn-guard is started
(Requirement 15 AC3).

Why stdout carries a ``stats`` object next to the report
-------------------------------------------------------

Requirement 5 AC4 asks a clean run to report *how many rules were evaluated*,
and the Review_Report envelope has no ``stats`` section (see the module
docstring of :mod:`iacreview.report`). The counters therefore sit in a top-level
``stats`` key that this Skill adds outside the envelope, keyed by the reviewed
Template's workspace-relative path -- a run may cover several Templates, and one
flat set of counters would have to either pick one Template or sum numbers that
do not add up. The aggregated report of ``iac-review`` does not carry the key,
which is why the counters are described here rather than in the shared schema.

**This is the only entry point that adds a key beside the envelope**, and
Requirement 5 AC4 is the only reason it may (design.md [Correction] C-10). The
criterion asks the Skill to *return a result* stating the count, and
Requirement 16 AC10 assigns results to stdout and diagnostics to stderr, so the
count cannot be demoted to a stderr diagnostic without leaving AC4 half
satisfied: ``summary.passed_all_checks`` would carry the "all rules passed" half
on stdout while the count it is qualified by went to a different channel, only
under ``--verbose``. Every other counter in the plugin has no such criterion
behind it and is therefore a diagnostic on stderr.
``tests/unit/test_skills.py`` enforces the contract across all five ``SKILL.md``
files.

Exit codes follow design.md's failure mode matrix; ``SKILL.md`` lists them.
"""

from __future__ import annotations

import sys
from pathlib import Path

# scripts/ -> skill dir -> skills/ -> plugin root
_PLUGIN_ROOT = Path(__file__).resolve().parents[3]
if str(_PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_ROOT))

from iacreview import bootstrap  # noqa: E402

bootstrap.require_plugin_root(__file__)

import argparse  # noqa: E402
from typing import Any, Dict, FrozenSet, List, Optional, Tuple  # noqa: E402

from iacreview import cfnguard, exitcodes, pathguard, template  # noqa: E402
from iacreview.dedup import deduplicate  # noqa: E402
from iacreview.errors import IacReviewError  # noqa: E402
from iacreview.finding import Finding  # noqa: E402
from iacreview.report import ReportMeta, ToolStatus, build_report  # noqa: E402
from iacreview.source import SourceResult, StructuredError, workspace_relative  # noqa: E402
from iacreview.toolcheck import (  # noqa: E402
    CFN_GUARD,
    UNKNOWN_VERSION,
    ToolInfo,
    require_known_tool,
)

#: Shown by ``--help``.
DESCRIPTION = (
    "Validate CloudFormation templates against the bundled cfn-guard policy "
    "rules and write a normalized review report on stdout."
)

#: Top-level stdout key holding the per-Template rule counters of
#: Requirement 5 AC4. Outside the Review_Report envelope; see the module
#: docstring.
STATS_KEY = "stats"

#: Input failures whose report *is* the answer, so the run continues and stdout
#: carries a partial report naming them (design.md, Failure mode matrix; the
#: ``## Output`` table of ``SKILL.md``). Both are statements about a target that
#: was named and read: it did not parse, or it held nothing reviewable, and with
#: several targets the others are still worth reviewing.
#:
#: Anything else -- a target that turned out to be unreadable, for instance a
#: directory -- is re-raised instead. ``SKILL.md`` documents an empty stdout for
#: exit 3, and a report describing a file the Skill never read would contradict
#: it as well as the failure matrix.
PARTIAL_REPORT_ERROR_CLASSES: FrozenSet[str] = frozenset(
    {"parse_failure", "no_reviewable_template"}
)


def build_parser() -> bootstrap.EntryPointParser:
    """Build the argument parser.

    Returns:
        A parser accepting ``--target`` (required, repeatable), ``--rules-dir``
        (optional, repeatable) and the shared ``--verbose``.
    """
    parser = bootstrap.new_parser(Path(__file__).name, DESCRIPTION)
    parser.add_argument(
        "--target",
        action="append",
        required=True,
        metavar="PATH",
        help=(
            "CloudFormation template to review. Repeat to review several "
            "templates in one report."
        ),
    )
    parser.add_argument(
        "--rules-dir",
        action="append",
        metavar="PATH",
        help=(
            "Additional directory of .guard rules to evaluate, in addition to "
            "the rules bundled with the plugin. Repeatable; the order of the "
            "options does not affect the output. Must be inside the workspace."
        ),
    )
    return parser


def validate(args: argparse.Namespace) -> None:
    """Resolve and contain every path before anything else runs.

    Runs before the temp file handlers, before the Template is read and before
    cfn-guard is started, so a path outside the workspace cannot reach any of
    them (Requirement 15 AC3, Requirement 16 AC7). The resolved values are
    stored back on ``args`` so that :func:`run` does not resolve them twice and
    cannot resolve them differently.

    Args:
        args: The parsed namespace. Gains ``workspace_root`` (a
            :class:`~pathlib.Path`), ``targets`` (resolved Template paths) and
            ``rules_roots`` (the rule directories this run evaluates, bundled
            set first).

    Raises:
        UnsafeArgumentError: A value contains a shell metacharacter (exit 2).
        InvalidArgumentsError: A value is empty or cannot be normalized (exit 2).
        InputNotFoundError: A value names something that does not exist (exit 3).
        PathContainmentError: A value resolves outside the workspace (exit 7).
        MappingFileError: The bundled ``rules/`` tree is missing (exit 1).
    """
    # Resolved, so that the root compares equal to the roots pathguard derives
    # internally. Without it, a workspace reached through a symlinked temporary
    # directory could not be stripped from the paths the report displays.
    root = Path.cwd().resolve()
    args.workspace_root = root
    args.targets = [pathguard.resolve_within(value, root) for value in args.target]
    args.rules_roots = cfnguard.resolve_rules_dirs(args.rules_dir, root)


def display_path(path: Path, root: Path) -> str:
    """Render ``path`` the way the report names it: relative to ``root``.

    Args:
        path: An absolute path inside ``root``.
        root: The workspace root.

    Returns:
        The workspace-relative, ``/``-separated path. Falls back to the file name
        if the path cannot be expressed relative to the root, which
        :func:`iacreview.pathguard.resolve_within` has already made unreachable
        for a target it accepted.
    """
    return workspace_relative(str(path), root) or path.name


def exit_code_for(result: SourceResult) -> int:
    """Exit code one Template's :class:`SourceResult` justifies.

    :meth:`iacreview.source.SourceResult.exit_status` maps a failure class to its
    code, with one case it cannot decide on its own: a category whose
    ``_meta.json`` is unusable is reported as ``parse_failure`` while the review
    keeps going with fallback classification, and design.md's failure mode matrix
    keeps that case at exit 0. The two are told apart by whether cfn-guard's own
    output was usable -- ``rules_evaluated`` is filled in only after it was
    parsed -- so a result that carries a rule count has no failure left that
    stopped the review.

    Args:
        result: One Template's result.

    Returns:
        A documented exit code from :mod:`iacreview.exitcodes`.
    """
    if not result.errors:
        return exitcodes.OK
    if result.stats.get("rules_evaluated") is not None:
        return exitcodes.OK
    return result.exit_status()


def _tool_status(tool: Optional[ToolInfo]) -> ToolStatus:
    """Render the cfn-guard version check as the report's ``tools`` entry.

    Args:
        tool: The verified tool, or ``None`` when the check failed.

    Returns:
        A :class:`~iacreview.report.ToolStatus`. The version is ``None`` for an
        unparsable banner as well as for an absent tool, because
        :data:`~iacreview.toolcheck.UNKNOWN_VERSION` is a sentinel and not a
        version a consumer could compare.
    """
    if tool is None:
        return ToolStatus(name=CFN_GUARD, available=False, version=None)
    version = None if tool.version == UNKNOWN_VERSION else tool.version
    return ToolStatus(name=CFN_GUARD, available=True, version=version)


def _load_reviewable(
    targets: List[Path], failures: List[Tuple[StructuredError, int]]
) -> List[Path]:
    """Keep the targets that are reviewable Templates, reporting the others.

    Parsing is checked here rather than left to cfn-guard so that a malformed or
    non-Template file is reported with the parse position (Requirement 3 AC6) or
    as "not reviewable" (Requirement 3 AC5) instead of as a tool failure.

    The resolved absolute path is what gets opened.
    :func:`iacreview.template.load_template` renders it workspace-relative in
    every message it builds, so the ``errors[]`` entries these failures become
    carry no absolute host path (Requirement 16 AC11) without this Skill having
    to arrange it.

    Args:
        targets: Resolved Template paths.
        failures: Accumulator; each rejected target appends one StructuredError
            with the exit code it justifies (4 for a parse failure, 8 for a file
            with no ``Resources`` mapping).

    Returns:
        The subset of ``targets`` that parsed and holds resources, in input
        order.

    Raises:
        IacReviewError: A target failed for a reason outside
            :data:`PARTIAL_REPORT_ERROR_CLASSES` -- it became unreadable, or it
            is a directory. Raised rather than recorded so that stdout stays
            empty, which is what ``SKILL.md`` documents for those exit codes.
    """
    reviewable: List[Path] = []
    for path in targets:
        try:
            template.load_template(path)
        except IacReviewError as exc:
            if exc.error_class not in PARTIAL_REPORT_ERROR_CLASSES:
                raise
            # source=None: the failure is the input's, not cfn-guard's.
            failures.append((exc.to_structured_error(), exc.exit_code))
            continue
        reviewable.append(path)
    return reviewable


def _verify_tool(
    failures: List[Tuple[StructuredError, int]]
) -> Optional[ToolInfo]:
    """Resolve cfn-guard once for the whole run.

    Verified here rather than per Template so that ``--version`` runs once no
    matter how many Templates were named, and so that an absent tool is reported
    as one error rather than one per Template (Requirement 5 AC5).

    Args:
        failures: Accumulator; an unavailable or too-old tool appends one
            StructuredError with exit code 5.

    Returns:
        The verified tool, or ``None`` when it cannot be used.
    """
    try:
        return require_known_tool(CFN_GUARD)
    except IacReviewError as exc:
        failures.append((exc.to_structured_error(cfnguard.SOURCE_NAME), exc.exit_code))
        return None


def run(args: argparse.Namespace) -> bootstrap.EntryPointOutcome:
    """Review every target and build the report.

    Args:
        args: The namespace :func:`validate` prepared.

    Returns:
        The report and the exit code of the first failure encountered, or
        :data:`~iacreview.exitcodes.OK` when nothing failed. A failure still
        produces a report: the failure matrix asks for ``errors[]`` on stdout for
        an unavailable tool, a parse failure and a file that is not reviewable.
    """
    root = args.workspace_root
    failures: List[Tuple[StructuredError, int]] = []
    reviewable = _load_reviewable(args.targets, failures)
    tool = _verify_tool(failures)

    findings: List[Finding] = []
    stats: Dict[str, Any] = {}
    metadata = (
        cfnguard.load_rule_metadata(args.rules_roots) if tool is not None else None
    )

    for path in reviewable if tool is not None else []:
        bootstrap.verbose_diagnostic(
            "cfn-guard: reviewing {0}".format(display_path(path, root)),
            verbose=args.verbose,
        )
        # The user-supplied directories are passed on as given, not as the
        # resolved list: run_and_normalize prepends the bundled rules itself, and
        # handing that absolute path back to it would have it contained against
        # the workspace root, which the plugin need not live inside.
        result = cfnguard.run_and_normalize(
            path,
            args.rules_dir,
            tool,
            workspace_root=args.workspace_root,
            metadata=metadata,
        )
        findings.extend(result.findings)
        code = exit_code_for(result)
        for error in result.errors:
            failures.append((error, code))
        stats[display_path(path, root)] = result.stats

    files = [display_path(path, root) for path in args.targets]
    report = build_report(
        deduplicate(findings),
        [error for error, _ in failures],
        ReportMeta(
            files=files,
            sources_enabled=[cfnguard.SOURCE_NAME],
            tools=[_tool_status(tool)],
        ),
    )
    report[STATS_KEY] = stats

    # The first failure decides: the earlier accumulators hold the input and tool
    # problems that prevented work, so a later degraded-category exit 0 cannot
    # mask them.
    exit_code = next(
        (code for _, code in failures if code != exitcodes.OK), exitcodes.OK
    )
    return bootstrap.EntryPointOutcome(report=report, exit_code=exit_code)


def main(argv: Optional[List[str]] = None) -> int:
    """Run the Skill and return its exit code.

    Args:
        argv: Argument list without the program name. ``None`` reads
            ``sys.argv[1:]``.

    Returns:
        A documented exit code from :mod:`iacreview.exitcodes`.
    """
    return bootstrap.run_entry_point(
        parser=build_parser(),
        run=run,
        argv=argv,
        validate=validate,
    )


if __name__ == "__main__":
    raise SystemExit(main())
