#!/usr/bin/env python3
"""Entry point of the ``cfn-lint-review`` Skill.

Runs cfn-lint against one or more CloudFormation Templates and prints a
Review_Report on stdout. Deliberately thin: every decision it could get wrong
already lives in a shared module (Requirement 2 AC16), so this file only
sequences them.

    --target  ->  pathguard.resolve_within   (containment, argument safety)
              ->  template.load_template     (parse, reviewability)
              ->  cfnlint.run_and_normalize  (run the tool, build Findings)
              ->  report.build_report        (order, number, validate)
              ->  report.dump                (serialize)

Everything below the CLI is either a call into that chain or the bookkeeping the
chain cannot do for itself: which Templates were reviewed, which errors were
collected, and which exit code the collection amounts to.

Why the tool is verified once, here
-----------------------------------

:func:`iacreview.cfnlint.run_and_normalize` verifies cfn-lint itself when no
:class:`~iacreview.toolcheck.ToolInfo` is passed. Letting it do that per Template
would run ``cfn-lint --version`` once per Template and, worse, append the same
``tool_unavailable`` error once per Template. So the check happens once and the
result is passed down -- which is also what makes the report's ``tools`` array
answerable (Requirement 15 AC4).

Exit codes
----------

======  =========================================================
0       Every Template was reviewed. Zero Findings included: a
        clean Template is a successful review (Requirement 4 AC13)
2       Missing or unknown argument, or a path containing a shell
        metacharacter
3       A ``--target`` does not exist or cannot be read
4       A ``--target`` could not be parsed as YAML or JSON
5       cfn-lint is absent from PATH, or older than 1.0.0
        (Requirement 4 AC10)
6       cfn-lint crashed, timed out, or printed output that did
        not match the expected structure (Requirement 4 AC12)
7       A ``--target`` resolves outside the workspace root
8       A ``--target`` holds no reviewable ``Resources`` mapping
1       Anything else, including a corrupt bundled category map
======  =========================================================

The codes come from :mod:`iacreview.exitcodes`; none is spelled numerically here.
A non-zero code from 4, 5, 6 or 8 still prints a report, because the errors are
the report's content in those cases (design.md, Failure mode matrix). 2, 3 and 7
leave stdout empty: they are rejected before any Template was read, so there is
nothing to report about.
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
from typing import Any, Dict, FrozenSet, List, Optional, Sequence  # noqa: E402

from iacreview import cfnlint, exitcodes, pathguard, report, template  # noqa: E402
from iacreview.errors import IacReviewError  # noqa: E402
from iacreview.finding import Finding  # noqa: E402
from iacreview.source import SourceResult, StructuredError, workspace_relative  # noqa: E402
from iacreview.toolcheck import CFN_LINT, ToolInfo, require_known_tool  # noqa: E402

#: Program name in usage text. Written out rather than derived from
#: ``sys.argv[0]``, so usage does not change with how the script was invoked.
SCRIPT_NAME = "run_cfn_lint.py"

#: ``--help`` summary. One sentence, naming the output format, because an agent
#: reading ``--help`` needs to know it gets JSON before it runs anything.
DESCRIPTION = (
    "Run cfn-lint against one or more CloudFormation templates and print a "
    "Review_Report JSON document on stdout."
)

#: Failures whose report *is* the answer, so stdout carries a partial report
#: rather than staying empty (design.md, Failure mode matrix). Both are
#: statements about a Template that was named and read: it did not parse, or it
#: held nothing reviewable. Every other failure class means the review never
#: started, and a report would describe work that did not happen.
PARTIAL_REPORT_ERROR_CLASSES: FrozenSet[str] = frozenset(
    {"parse_failure", "no_reviewable_template"}
)


def build_parser() -> bootstrap.EntryPointParser:
    """Build this script's argument parser.

    Returns:
        A parser accepting ``--target`` one or more times, plus the
        ``--verbose`` flag :func:`iacreview.bootstrap.new_parser` adds.

    Note:
        ``--target`` is ``action="append"`` with ``required=True``: repeating it
        reviews several Templates in one report, and omitting it is exit 2. A
        positional list would have been shorter, but a filename beginning with
        ``-`` would then need ``--`` to be readable, and an agent constructing
        the command line is more likely to get an explicit option right.
    """
    parser = bootstrap.new_parser(SCRIPT_NAME, DESCRIPTION)
    parser.add_argument(
        "--target",
        action="append",
        required=True,
        metavar="PATH",
        help=(
            "CloudFormation template to review, relative to the workspace root "
            "or absolute inside it. Repeat to review several templates in one "
            "report."
        ),
    )
    return parser


class CfnLintReview:
    """State of one invocation: what was reviewed, and what went wrong.

    A short-lived object rather than module globals, so that a test can run
    :func:`main` twice in one process without the second run inheriting the
    first one's findings.

    Attributes:
        workspace_root: Containment root for every ``--target`` and the root
            report paths are relative to. The current working directory, which
            is the workspace root for every entry point of this plugin.
        targets: Contained, existing absolute paths, filled by :meth:`validate`.
        findings: Normalized Findings collected so far, unordered and unnumbered
            (:func:`iacreview.report.build_report` does both).
        errors: StructuredErrors collected so far, in the order they occurred.
        files: The same targets as workspace-relative strings, for the report's
            ``target.files``. Filled by :meth:`validate`, so the report names the
            input set even when the review of it did not get far -- a report
            saying "cfn-lint is missing" is more use naming the template it was
            asked about than not.
        tool: The verified cfn-lint, or ``None`` when it was unavailable.
        work_started: Whether :meth:`run` was entered. Decides whether a failure
            can produce a partial report at all.
    """

    def __init__(self) -> None:
        self.workspace_root: Path = Path.cwd()
        self.targets: List[Path] = []
        self.findings: List[Finding] = []
        self.errors: List[StructuredError] = []
        self.files: List[str] = []
        self.tool: Optional[ToolInfo] = None
        self.work_started: bool = False

    # -- argument validation ------------------------------------------------

    def validate(self, args: argparse.Namespace) -> None:
        """Contain every ``--target`` before any work begins.

        Runs inside :func:`iacreview.bootstrap.run_entry_point`'s ``validate``
        slot, which is before the first subprocess and before the first file
        read. That ordering is the point: a path outside the workspace, or one
        carrying a shell metacharacter, is refused while refusing it still costs
        nothing (Requirement 16 AC7).

        Raises:
            UnsafeArgumentError: A target contains a shell metacharacter.
            InvalidArgumentsError: A target is empty or cannot be normalized.
            PathContainmentError: A target resolves outside the workspace root.
            InputNotFoundError: A target does not exist.
        """
        self.targets = [
            pathguard.resolve_within(value, self.workspace_root)
            for value in args.target
        ]
        self.files = [self._relative(target) for target in self.targets]

    # -- the review ---------------------------------------------------------

    def run(self, args: argparse.Namespace) -> bootstrap.EntryPointOutcome:
        """Review every target and return the report with its exit code.

        Args:
            args: Parsed arguments. Only ``--verbose`` is read here; the targets
                were consumed by :meth:`validate`.

        Returns:
            The Review_Report and the exit code it amounts to: the first non-OK
            status any step produced, so a run whose second Template hit a tool
            crash exits 6 while still reporting the first Template's Findings.

        Raises:
            TemplateParseError: A target could not be parsed. Propagated so the
                wrapper can report it, with the Findings collected so far
                attached by :meth:`partial_report`.
            NotReviewableError: A target held no ``Resources`` mapping.
        """
        self.work_started = True
        status = self._verify_tool(verbose=args.verbose)

        # No tool, no review. Continuing would let run_and_normalize verify
        # cfn-lint again per Template and append the same tool_unavailable error
        # once more each time, turning one problem into N.
        if status == exitcodes.OK:
            for target in self.targets:
                outcome = self._review_one(target, verbose=args.verbose)
                if status == exitcodes.OK:
                    status = outcome

        return bootstrap.EntryPointOutcome(report=self._report(), exit_code=status)

    def _verify_tool(self, *, verbose: bool) -> int:
        """Resolve and version-check cfn-lint once for the whole run.

        Returns:
            :data:`iacreview.exitcodes.OK`, or
            :data:`iacreview.exitcodes.TOOL_UNAVAILABLE` when cfn-lint is absent
            or too old. The error is recorded in :attr:`errors` and a single line
            goes to stderr; nothing is raised, because the report still has
            something to say -- namely which tool was missing and how to install
            it (Requirement 4 AC10).
        """
        try:
            self.tool = require_known_tool(CFN_LINT)
        except IacReviewError as exc:
            self.errors.append(exc.to_structured_error(source=cfnlint.SOURCE_NAME))
            bootstrap.diagnostic(
                "warning: {0}: {1}".format(exc.error_class, exc.message)
            )
            if exc.remediation:
                bootstrap.diagnostic(exc.remediation)
            return exc.exit_code

        bootstrap.verbose_diagnostic(
            "cfn-lint {0} at {1}".format(self.tool.version, self.tool.path),
            verbose=verbose,
        )
        return exitcodes.OK

    def _review_one(self, target: Path, *, verbose: bool) -> int:
        """Load one Template, lint it, and absorb the result.

        The Template is loaded before cfn-lint runs even though cfn-lint would
        also reject an unparsable file. Two reasons: the plugin's own parse error
        carries the line and column Requirement 3 AC6 asks for, and a file that
        is not a Template at all should not become a tool invocation.

        Returns:
            The exit status this Template's result implies -- OK when no error
            was recorded, otherwise the code its first error maps to
            (:meth:`iacreview.source.SourceResult.exit_status`).
        """
        loaded = template.load_template(target)
        result = cfnlint.run_and_normalize(
            loaded.path,
            self.tool,
            workspace_root=self.workspace_root,
        )
        self.findings.extend(result.findings)
        self.errors.extend(result.errors)
        self._log_stats(loaded.path, result, verbose=verbose)
        return result.exit_status()

    def _log_stats(
        self, path: Path, result: SourceResult, *, verbose: bool
    ) -> None:
        """Report one Template's counters on stderr under ``--verbose``.

        Counters live on stderr, not in the report. The Review_Report's key set
        is fixed (:data:`iacreview.report.REPORT_KEYS`) so that one Skill's
        output can be read by the same consumer as another's, and stdout has to
        stay byte-identical between runs (Requirement 16 AC11) -- which a
        counters section would survive, but a schema change would not.
        """
        if not verbose:
            return
        rendered = ", ".join(
            "{0}={1}".format(key, result.stats.get(key))
            for key in cfnlint.STATS_KEYS
        )
        bootstrap.diagnostic("{0}: {1}".format(self._relative(path), rendered))

    # -- output -------------------------------------------------------------

    def _relative(self, path: Path) -> str:
        """Render ``path`` as the workspace-relative string a report may carry.

        The fallback to ``path.name`` covers the one case
        :func:`iacreview.source.workspace_relative` declines: the workspace root
        itself, which cannot be expressed relative to itself. A target that
        escaped the workspace never reaches here -- :meth:`validate` refused it.
        """
        return workspace_relative(str(path), self.workspace_root) or path.name

    def _report(self) -> Dict[str, Any]:
        """Assemble the Review_Report from the state collected so far."""
        return report.build_report(
            self.findings,
            self.errors,
            report.ReportMeta(
                files=self.files,
                sources_enabled=(cfnlint.SOURCE_NAME,),
                tools=(
                    report.ToolStatus(
                        name=CFN_LINT,
                        available=self.tool is not None,
                        version=None if self.tool is None else self.tool.version,
                    ),
                ),
            ),
        )

    def partial_report(self, exc: IacReviewError) -> Optional[Dict[str, Any]]:
        """Build the report that accompanies a failure, or decline to.

        Args:
            exc: The failure :func:`iacreview.bootstrap.run_entry_point` caught.

        Returns:
            A Review_Report carrying ``exc`` in ``errors[]`` alongside whatever
            was collected before it, or ``None`` to leave stdout empty.

        Note:
            ``source`` is ``None`` on the recorded error: a Template that would
            not parse failed in :func:`iacreview.template.load_template`, before
            any Source saw it, and attributing it to cfn-lint would suggest the
            tool reported something it never ran on.
        """
        if not self.work_started:
            return None
        if exc.error_class not in PARTIAL_REPORT_ERROR_CLASSES:
            return None
        self.errors.append(exc.to_structured_error())
        return self._report()


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the Skill and return its exit code.

    Args:
        argv: Arguments without the program name. ``None`` reads
            ``sys.argv[1:]``.

    Returns:
        A documented exit code from :mod:`iacreview.exitcodes`. Returned rather
        than raised, so tests can call this in-process.
    """
    review = CfnLintReview()
    return bootstrap.run_entry_point(
        parser=build_parser(),
        run=review.run,
        argv=argv,
        validate=review.validate,
        partial_report=review.partial_report,
    )


if __name__ == "__main__":
    sys.exit(main())
