"""cfn-lint contribution measurement series (Requirement 19 AC5).

This is a measurement series, not a ground-truth harness. It reviews the
templates under ``templates/`` with the cfn-lint Source alone and reports how
many findings cfn-lint contributed, pinned to the installed cfn-lint version.
The number is *informational*: it is never turned into a PASS or FAIL, and the
exit status reflects only whether the measurement could be taken, not what it
found.

Why this is kept apart from ``benchmark/cases/``
------------------------------------------------

The ground-truth cases have a pass/fail contract that must not depend on the
installed cfn-lint rule catalogue (Requirement 19 AC5). cfn-lint gains rules
between releases, so thresholding its raw finding count would make one machine
disagree with another. That count is still worth tracking, so it is measured
here, reported with the cfn-lint version it was produced against, and never fed
into a threshold.

Determinism
-----------

stdout is a function of the templates and the installed cfn-lint version alone.
The version *is* in the output, because it is the one environment value the
series exists to measure; everything else that varies by host -- wall-clock
time, absolute paths, process identifiers -- is kept out, the same contract the
ground-truth harness holds (Requirement 16 AC11). Findings are counted by
severity and the counts are sorted, so two runs against one cfn-lint version
print the same bytes.
"""

from __future__ import annotations

import sys
from pathlib import Path

# run_contribution.py -> cfn-lint-contribution/ -> benchmark/ -> plugin root.
# Two levels, like the ground-truth harness and unlike a Skill entry point.
_PLUGIN_ROOT = Path(__file__).resolve().parents[2]
if str(_PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_ROOT))

import argparse  # noqa: E402
from typing import Any, Dict, List, Optional, Sequence, Tuple  # noqa: E402

from iacreview import (  # noqa: E402
    bootstrap,
    cfnlint,
    exitcodes,
    pathguard,
    template as template_mod,
    toolcheck,
)
from iacreview.errors import (  # noqa: E402
    IacReviewError,
    InvalidArgumentsError,
    ToolUnavailableError,
    ToolVersionError,
)
from iacreview.finding import SEVERITIES  # noqa: E402

__all__ = [
    "SCRIPT_NAME",
    "DESCRIPTION",
    "SCHEMA_VERSION",
    "TEMPLATE_SUFFIXES",
    "SUMMARY_KEYS",
    "TEMPLATE_KEYS",
    "build_parser",
    "workspace_root",
    "discover_templates",
    "empty_severity_counts",
    "count_by_severity",
    "Contribution",
    "main",
]

#: Program name in usage text.
SCRIPT_NAME = "run_contribution.py"

#: ``--help`` summary.
DESCRIPTION = (
    "Measure how many findings cfn-lint contributes to a review across the "
    "series templates, pinned to the installed cfn-lint version, and print the "
    "counts as one JSON document on stdout. Informational only: never a "
    "pass/fail verdict."
)

#: Version of this series' output document. Independent of every other
#: schema_version in the repository.
SCHEMA_VERSION = "1.0.0"

#: Template file extensions the series reviews, matched case-insensitively.
TEMPLATE_SUFFIXES: Tuple[str, ...] = (".yaml", ".yml", ".json", ".template")

#: Top-level keys of the series output, in insertion order. ``cfn_lint_version``
#: is the pinned version the counts were produced against (Requirement 19 AC5);
#: it is the one environment-dependent value that belongs in the output, because
#: it is what the series measures against. ``total_findings`` and
#: ``by_severity`` are the aggregate contribution; ``templates`` is the per-file
#: breakdown; ``errors`` lists templates cfn-lint could not measure.
SUMMARY_KEYS: Tuple[str, ...] = (
    "schema_version",
    "cfn_lint_version",
    "template_count",
    "total_findings",
    "by_severity",
    "templates",
    "errors",
)

#: Keys of one entry of ``templates``.
TEMPLATE_KEYS: Tuple[str, ...] = (
    "template",
    "finding_count",
    "by_severity",
)


def build_parser() -> bootstrap.EntryPointParser:
    """Build this script's argument parser.

    Returns:
        A parser accepting ``--templates`` (required) and the shared
        ``--verbose``.
    """
    parser = bootstrap.new_parser(SCRIPT_NAME, DESCRIPTION)
    parser.add_argument(
        "--templates",
        required=True,
        metavar="DIR",
        help=(
            "Directory of series templates to review with cfn-lint. Normally "
            "benchmark/cfn-lint-contribution/templates."
        ),
    )
    return parser


def workspace_root() -> Path:
    """Containment root for every path this script resolves."""
    return Path.cwd().resolve()


def empty_severity_counts() -> Dict[str, int]:
    """A zeroed count per Severity, in the schema's severity order.

    A fixed key set (:data:`iacreview.finding.SEVERITIES`) so the ``by_severity``
    block is the same shape whether or not a given severity was seen, which keeps
    the output byte-stable (Requirement 16 AC11).
    """
    return {severity: 0 for severity in SEVERITIES}


def count_by_severity(findings: Sequence[Any]) -> Dict[str, int]:
    """Count ``findings`` by their ``Severity``.

    Args:
        findings: The Findings one template's cfn-lint review produced.

    Returns:
        A count per Severity, all severities present. A Finding whose severity is
        outside :data:`iacreview.finding.SEVERITIES` is ignored rather than
        counted under a new key: the Finding schema closes the set, so this
        cannot happen for a valid Finding, and tolerating it keeps the key set
        fixed.
    """
    counts = empty_severity_counts()
    for finding in findings:
        severity = getattr(finding, "Severity", None)
        if severity in counts:
            counts[severity] += 1
    return counts


def discover_templates(directory: Path) -> List[Path]:
    """Return the series templates under ``directory``, in sorted order.

    Args:
        directory: The contained ``--templates`` directory.

    Returns:
        Every regular file whose suffix is in :data:`TEMPLATE_SUFFIXES`, sorted
        by name so the output order does not depend on the filesystem's.
    """
    found = [
        entry
        for entry in directory.iterdir()
        if entry.is_file() and entry.suffix.lower() in TEMPLATE_SUFFIXES
    ]
    return sorted(found, key=lambda path: path.name)


class Contribution:
    """State of one contribution measurement run.

    A short-lived object rather than module state, so a test may call
    :func:`main` twice in one process without the second run inheriting the
    first's counts.
    """

    def __init__(self) -> None:
        self.root: Path = workspace_root()
        self.templates_dir: Optional[Path] = None
        self.tool: Optional[toolcheck.ToolInfo] = None
        self.entries: List[Dict[str, Any]] = []
        self.errors: List[Dict[str, Any]] = []

    def validate(self, args: argparse.Namespace) -> None:
        """Contain the templates directory and verify cfn-lint, before any review.

        cfn-lint is verified once here rather than per template, so its
        ``--version`` runs once and the pinned version is known before the first
        review. Its absence fails the whole series: the measurement cannot be
        taken, and reporting a zero contribution would be indistinguishable from
        a cfn-lint that found nothing (Requirement 19 AC5, the same reason the
        ground-truth harness records an absent tool rather than a clean run).

        Raises:
            InvalidArgumentsError: ``--templates`` is not a directory.
            ToolUnavailableError: cfn-lint is absent from PATH (exit 5).
            ToolVersionError: cfn-lint is older than the minimum (exit 5).
            PathContainmentError: ``--templates`` resolves outside the workspace.
        """
        templates_dir = pathguard.resolve_within(args.templates, self.root)
        if not templates_dir.is_dir():
            raise InvalidArgumentsError(
                "--templates must be a directory of series templates: "
                "{0!r}".format(args.templates),
                remediation="Pass the directory holding the series templates, "
                "normally benchmark/cfn-lint-contribution/templates.",
            )
        self.templates_dir = templates_dir
        # Verified up front so the pinned version is known and a single
        # --version call serves every template.
        self.tool = toolcheck.require_known_tool(toolcheck.CFN_LINT)

    def _relative(self, path: Path) -> str:
        """Render ``path`` as a workspace-relative string for the output."""
        return str(path.relative_to(self.root))

    def _measure(self, path: Path, *, verbose: bool) -> Optional[Dict[str, Any]]:
        """Review one template with cfn-lint and count its findings.

        Args:
            path: The template, contained in ``--templates``.
            verbose: Whether to echo the count on stderr.

        Returns:
            One entry with the keys of :data:`TEMPLATE_KEYS`, or ``None`` when the
            template could not be measured (a parse failure or a cfn-lint error),
            in which case an entry is appended to :attr:`errors` instead. The run
            continues either way: one unmeasurable template does not end the
            series.
        """
        relative = self._relative(path)
        try:
            template_mod.load_template(path)
        except IacReviewError as exc:
            self.errors.append(
                {"template": relative, "error_class": exc.error_class}
            )
            bootstrap.diagnostic(
                "warning: {0}: {1}: {2}".format(relative, exc.error_class, exc.message)
            )
            return None

        result = cfnlint.run_and_normalize(
            path, self.tool, workspace_root=self.root
        )
        if result.errors:
            for error in result.errors:
                self.errors.append(
                    {
                        "template": relative,
                        "error_class": error.get("error_class"),
                    }
                )
                bootstrap.diagnostic(
                    "warning: {0}: cfn-lint reported {1}".format(
                        relative, error.get("error_class")
                    )
                )
            return None

        by_severity = count_by_severity(result.findings)
        bootstrap.verbose_diagnostic(
            "{0}: {1} finding(s)".format(relative, len(result.findings)),
            verbose=verbose,
        )
        return {
            "template": relative,
            "finding_count": len(result.findings),
            "by_severity": by_severity,
        }

    def summary(self) -> Dict[str, Any]:
        """Assemble the document printed on stdout.

        Returns:
            A dict with exactly the keys of :data:`SUMMARY_KEYS`. The pinned
            cfn-lint version is recorded so a later run can distinguish a
            rule-catalogue change from a template change.
        """
        total_by_severity = empty_severity_counts()
        total = 0
        for entry in self.entries:
            total += entry["finding_count"]
            for severity, count in entry["by_severity"].items():
                total_by_severity[severity] += count

        version = self.tool.version if self.tool is not None else toolcheck.UNKNOWN_VERSION
        return {
            "schema_version": SCHEMA_VERSION,
            "cfn_lint_version": version,
            "template_count": len(self.entries),
            "total_findings": total,
            "by_severity": total_by_severity,
            "templates": list(self.entries),
            "errors": list(self.errors),
        }

    def run(self, args: argparse.Namespace) -> bootstrap.EntryPointOutcome:
        """Review and measure every series template.

        Returns:
            The summary with :data:`iacreview.exitcodes.OK`. The series never
            fails on what it finds; a template it could not measure is recorded
            in ``errors`` and does not change the exit status, because the count
            is informational (Requirement 19 AC5).
        """
        assert self.templates_dir is not None
        verbose = args.verbose

        for path in discover_templates(self.templates_dir):
            entry = self._measure(path, verbose=verbose)
            if entry is not None:
                self.entries.append(entry)

        return bootstrap.EntryPointOutcome(
            report=self.summary(), exit_code=exitcodes.OK
        )


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the contribution series and return its exit code.

    Args:
        argv: Arguments without the program name. ``None`` reads
            ``sys.argv[1:]``.

    Returns:
        :data:`iacreview.exitcodes.OK` on a successful measurement,
        :data:`~iacreview.exitcodes.TOOL_UNAVAILABLE` when cfn-lint is absent or
        too old, or the shared wrapper's code for a rejected argument. The series
        never returns a benchmark-style failure code: what it found is
        informational.
    """
    series = Contribution()
    return bootstrap.run_entry_point(
        parser=build_parser(),
        run=series.run,
        argv=argv,
        validate=series.validate,
    )


if __name__ == "__main__":
    sys.exit(main())
