#!/usr/bin/env python3
"""Entry point of the ``iac-review`` Skill: every Source, one Review_Report.

Runs the three deterministic Sources over every reviewable Template reachable
from ``--target``, folds in the agent Findings a host agent produced, merges
equivalent Findings and writes one Review_Report on stdout (Requirement 2 AC5).

The orchestration is deliberately *loose*: this script does not run the other
Skills' scripts and does not read their ``SKILL.md``. It calls the same shared
modules they call -- :mod:`iacreview.cfnlint`, :mod:`iacreview.cfnguard`,
:mod:`iacreview.iam` -- so the dependency direction is always Skill -> shared
module and never Skill -> Skill (Requirement 2 AC10, AC16). A Skill invoked on
its own therefore produces the same Findings for the same Template as this one
does, and a bug fixed in a Source is fixed for both.

The Source loop
---------------

:data:`SOURCE_ORDER_FOR_COLLECTION` fixes the order at ``cfn-lint`` ->
``cfn-guard`` -> ``IAM Review``, matching the Evidence concatenation order of
Requirement 14 AC11, and :meth:`IacReview.collect` is design.md's ``collect()``
loop: both an expected failure (:class:`~iacreview.errors.IacReviewError`) and an
unexpected exception become one ``errors[]`` entry, and the loop continues with
the remaining Sources (Requirement 2 AC10). One Source failing costs its
Findings and nothing else.

Three decisions this file settles, all about what stdout is
-----------------------------------------------------------

**stdout is exactly the Review_Report envelope.** The seven keys of
:data:`iacreview.report.REPORT_KEYS`, nothing beside them. That matters more here
than for a single-Source Skill: this report is what a consumer reads when it does
not know which Sources ran.

*The settled cross-Skill contract* (design.md [Correction] C-10). stdout is one
JSON document; the envelope is the same seven keys in every Skill; and a counter
reaches stdout only where an acceptance criterion makes it part of the *result*
rather than a diagnostic. One criterion does -- Requirement 5 AC4, which obliges a
clean cfn-guard run to state how many rules it evaluated -- so ``run_cfn_guard.py``
adds a top-level ``stats`` object beside its envelope and no other entry point
does. Every counter this script produces is a diagnostic: they go to stderr under
``--verbose``, keyed by Template and Source, and a report produced here has no
``stats`` key even when cfn-guard ran. An aggregating Skill could not carry one
honestly anyway -- the key set of a multi-Source counters object would depend on
which Sources ran, which is exactly what stdout must not do.
``tests/unit/test_skills.py`` holds the contract to every ``SKILL.md``, and the
per-Skill integration tests hold it to the actual bytes.

**The IAM informational message goes to stderr.** Requirement 6 AC12 asks a
Template with no IAM at all to yield zero findings *with an informational
message*. It is not a Finding (a Finding names a resource, and there is none to
name), it is not an ``errors[]`` entry (``error_class`` is a closed set of
failure classes and this is not a failure), and the envelope has no field for it.
The remaining channel is stderr, which is also where the standalone
``run_iam_scan.py`` puts it -- so the message reads the same whichever way the
Source was invoked. It is not gated on ``--verbose``: it is an answer, not a
diagnostic.

**No host path is introduced into stdout.** Requirement 16 AC11 makes stdout a
function of the input alone, and two shapes of message would otherwise carry the
running machine's directory layout into ``errors[]``: a message built from a path
this script passed in, and the text of an exception nobody here wrote. Both are
handled at the source. Templates are opened through their workspace-relative
path, so a parse failure reports the file the way the report names it, and an
undeclared exception is recorded by type with its message and traceback sent to
stderr (see :func:`unexpected_error`). Existing leaks elsewhere in the pipeline
are not widened here.

CDK
---

``cdk`` is never started unless ``--confirm-cdk-synth`` was given. The gate is
:func:`iacreview.cdk.synth_if_confirmed`, which structurally cannot reach
:mod:`iacreview.proc` on the unconfirmed path; this script passes ``confirmed``
through to it and holds no second copy of the decision (Requirement 8 AC3). When
a CDK project is reviewed without the flag, the run continues with whatever is
already under ``cdk.out`` and an ``invalid_arguments`` entry records that
synthesis was skipped (Requirement 8 AC5) -- with exit code 0, because a skipped
synthesis is a warning about coverage rather than a failed review.

Exit codes
----------

======  =========================================================
0       At least one Template was reviewed by at least one Source.
        Zero Findings included; so is a run in which one Source was
        unavailable (Requirement 4 AC12, Requirement 5 AC6)
2       Missing or unknown argument, or a path containing a shell
        metacharacter
3       A ``--target``, ``--rules-dir`` or ``--agent-findings`` path
        does not exist or cannot be read
4       Every candidate Template failed to parse
5       Every enabled Source was unavailable, or the CDK CLI was
        absent after ``--confirm-cdk-synth``
6       Every enabled Source failed while running, or ``cdk synth``
        failed
7       A path resolves outside the workspace root
8       Nothing reviewable was found under ``--target``
1       Anything else, including a corrupt bundled category map
======  =========================================================

A failure of *some* Sources, or of *some* Templates, is reported in ``errors[]``
with exit 0: the report then says what was reviewed and what was not, which is
the distinction a non-zero exit would erase.
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
import dataclasses  # noqa: E402
import functools  # noqa: E402
import traceback  # noqa: E402
from typing import (  # noqa: E402
    Any,
    Callable,
    Dict,
    FrozenSet,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
)

from iacreview import (  # noqa: E402
    agentin,
    cdk,
    cfnguard,
    cfnlint,
    dedup,
    exitcodes,
    iam,
    netgraph,
    pathguard,
    report,
    secrets,
    template,
)
from iacreview.errors import (  # noqa: E402
    IacReviewError,
    InvalidArgumentsError,
    NotReviewableError,
)
from iacreview.finding import (  # noqa: E402
    AGENT_SOURCE,
    Finding,
    noecho_parameter_names,
    sorted_sources,
)
from iacreview.source import (  # noqa: E402
    SOURCE_ERROR_EXIT_CODES,
    SourceResult,
    StructuredError,
    workspace_relative,
)
from iacreview.toolcheck import (  # noqa: E402
    CFN_GUARD,
    CFN_LINT,
    UNKNOWN_VERSION,
    ToolInfo,
    require_known_tool,
)

#: Program name in usage text. Written out rather than derived from
#: ``sys.argv[0]``, so usage does not change with how the script was invoked.
SCRIPT_NAME = "run_iac_review.py"

#: ``--help`` summary.
DESCRIPTION = (
    "Review CloudFormation templates with every available source -- cfn-lint, "
    "cfn-guard and the deterministic IAM detectors -- and print one merged "
    "Review_Report JSON document on stdout."
)

#: Source execution order (design.md, Review Flow and Orchestration). Fixed at
#: the order Requirement 14 AC11 gives Evidence concatenation, so collection
#: order and merge order agree and ``dedup`` has nothing to reorder.
SOURCE_ORDER_FOR_COLLECTION: Tuple[str, ...] = (
    cfnlint.SOURCE_NAME,
    cfnguard.SOURCE_NAME,
    iam.SOURCE_NAME,
    netgraph.SOURCE_NAME,
    secrets.SOURCE_NAME,
)

#: Accepted ``--sources`` spellings, mapped to the Source name the report uses.
#: ``iam-review`` is offered because the canonical name contains a space, which a
#: caller assembling a command line has to quote; both spellings mean the same
#: Source. :data:`AGENT_SOURCE` is deliberately absent: agent Findings are
#: enabled by supplying a file, not by naming a Source.
SOURCE_ALIASES: Mapping[str, str] = {
    cfnlint.SOURCE_NAME: cfnlint.SOURCE_NAME,
    cfnguard.SOURCE_NAME: cfnguard.SOURCE_NAME,
    iam.SOURCE_NAME: iam.SOURCE_NAME,
    "iam-review": iam.SOURCE_NAME,
    netgraph.SOURCE_NAME: netgraph.SOURCE_NAME,
    "network-review": netgraph.SOURCE_NAME,
    secrets.SOURCE_NAME: secrets.SOURCE_NAME,
    "secret-review": secrets.SOURCE_NAME,
}

#: Failures whose report *is* the answer, so stdout carries a partial report
#: rather than staying empty (design.md, Failure mode matrix). Each is a
#: statement the report can make: nothing was reviewable, a Template did not
#: parse, or an external tool could not be used. Argument, path and input
#: failures are rejected before any Template is read, and a report about them
#: would describe work that did not happen.
PARTIAL_REPORT_ERROR_CLASSES: FrozenSet[str] = frozenset(
    {
        "parse_failure",
        "no_reviewable_template",
        "tool_unavailable",
        "tool_version",
        "tool_execution",
        "tool_timeout",
    }
)

#: Attached to the ``errors[]`` entry recorded when a CDK project is reviewed
#: without ``--confirm-cdk-synth``.
SYNTH_NOT_CONFIRMED_REMEDIATION = (
    "Show the user the synthesis warning, then re-run with --confirm-cdk-synth "
    "if they accept it. Alternatively run `cdk synth` yourself and review the "
    "generated {0}/ directory.".format(cdk.CDK_OUTPUT_DIRECTORY_NAME)
)

#: Attached to the ``errors[]`` entry recorded for an exception no Source
#: declared. The trace is on stderr rather than in the report; see
#: :func:`unexpected_error`.
UNEXPECTED_REMEDIATION = (
    "This is a defect in the plugin. The traceback is on stderr; please report "
    "it with the template that triggered it."
)


# ---------------------------------------------------------------------------
# Source specifications
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class SourceSpec:
    """One Source of the collection loop (design.md's ``SOURCES`` entries).

    Attributes:
        name: The Source name, as ``Finding.Source`` and ``sources_enabled``
            spell it.
        call: The Source, already bound to everything that is fixed for the whole
            run -- the verified tool, the rule metadata, the workspace root --
            so the loop passes only the Template. Binding once is what keeps
            ``--version`` and the rule sidecars from being re-read per Template.

    design.md's ``SourceSpec`` also carries ``required``, set to ``False`` for all
    three Sources. It is omitted here rather than carried unused: with no Source
    marked required there is no code path that would read it, and a field that is
    always ``False`` invites a reader to believe some Source is mandatory.
    """

    name: str
    call: Callable[[Path], SourceResult]


def source_ran(result: SourceResult) -> bool:
    """Whether ``result`` shows the Source completed, rather than gave up.

    The distinction decides the process exit code and nothing else: a Source that
    ran contributes to "something was reviewed", so the run exits 0 and its
    ``errors[]`` entries describe what it could not do (design.md: exit 5 or 6 is
    for the case where *every* Source failed).

    Args:
        result: One Source's result for one Template.

    Returns:
        ``True`` when the Source reported no failure, produced Findings despite
        one, or -- for cfn-guard -- filled in the rule counters. The counters are
        written only after cfn-guard's own output was parsed, so a result
        carrying them completed the run and merely degraded one rule category's
        classification (design.md: "rule 実行そのものは継続する"), which the
        failure matrix keeps at exit 0.
    """
    if not result.errors or result.findings:
        return True
    return result.stats.get("rules_evaluated") is not None


def unexpected_error(source: str, exc: BaseException) -> StructuredError:
    """Render an exception no Source declared as an ``errors[]`` entry.

    Args:
        source: Source that raised.
        exc: The exception.

    Returns:
        A StructuredError with ``error_class: "unexpected"``.

    Note:
        The message names the exception *type* and not its text. An arbitrary
        exception message is not content this plugin authored: it routinely
        carries an absolute host path (a failed ``open`` names the file it
        tried), and Requirement 16 AC11 keeps host paths out of stdout. The full
        message and the traceback go to stderr, where an absolute path is
        expected and useful.
    """
    return IacReviewError(
        "{0} failed with an unexpected {1}; see stderr for the traceback".format(
            source, type(exc).__name__
        ),
        remediation=UNEXPECTED_REMEDIATION,
    ).to_structured_error(source)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> bootstrap.EntryPointParser:
    """Build this script's argument parser.

    Returns:
        A parser accepting ``--target`` (required, repeatable), ``--sources``,
        ``--rules-dir``, ``--agent-findings``, ``--confirm-cdk-synth`` and the
        shared ``--verbose``.
    """
    parser = bootstrap.new_parser(SCRIPT_NAME, DESCRIPTION)
    parser.add_argument(
        "--target",
        action="append",
        required=True,
        metavar="PATH",
        help=(
            "CloudFormation template file, or a directory to scan for them. "
            "Repeat to review several targets in one report. Paths are "
            "resolved inside the workspace root."
        ),
    )
    parser.add_argument(
        "--sources",
        action="append",
        metavar="SOURCE",
        choices=sorted(SOURCE_ALIASES),
        help=(
            "Restrict the review to a subset of the deterministic sources. "
            "Repeat to enable several. Default: all of them. Agent findings are "
            "enabled by --agent-findings instead."
        ),
    )
    parser.add_argument(
        "--rules-dir",
        action="append",
        metavar="PATH",
        help=(
            "Additional directory of .guard rules for the cfn-guard source, in "
            "addition to the rules bundled with the plugin. Repeatable; the "
            "order of the options does not affect the output."
        ),
    )
    parser.add_argument(
        "--agent-findings",
        metavar="PATH",
        help=(
            "JSON file of findings produced by agent reasoning, to merge into "
            "the report. Findings that fail validation are dropped and recorded "
            "in errors[]."
        ),
    )
    parser.add_argument(
        "--confirm-cdk-synth",
        action="store_true",
        help=(
            "Permit `cdk synth` to run for a CDK project given as --target. "
            "Without this flag no cdk process is started, and only "
            "already-synthesized templates are reviewed. cdk synth executes the "
            "project's own code and its dependencies' lifecycle scripts, "
            "unsandboxed."
        ),
    )
    return parser


def workspace_root() -> Path:
    """Containment root for every path, and the root report paths are relative to.

    Returns:
        The resolved current working directory. The caller's directory is the
        workspace the way Agent Plugins 1.0.0 uses the term: the plugin's own
        directory holds its code, not the Templates under review.

        Resolved rather than taken as-is, so it compares equal to the roots
        :mod:`iacreview.pathguard` and :mod:`iacreview.cdk` derive internally. A
        workspace reached through a symlinked directory (``/tmp`` on macOS)
        could otherwise not be stripped from the paths the report displays.
    """
    return Path.cwd().resolve()


def enabled_sources(values: Optional[Sequence[str]]) -> List[str]:
    """Resolve ``--sources`` into the Source names to run.

    Args:
        values: The ``--sources`` values, or ``None`` when the option was absent.

    Returns:
        The Source names, de-duplicated and in
        :data:`iacreview.finding.SOURCE_ORDER` order. All three deterministic
        Sources when ``values`` is empty or ``None``: a review with nothing
        enabled is never what a caller meant, and ``argparse`` cannot express
        "this option defaults to everything".
    """
    if not values:
        return list(SOURCE_ORDER_FOR_COLLECTION)
    return sorted_sources({SOURCE_ALIASES[value] for value in values})


# ---------------------------------------------------------------------------
# The review
# ---------------------------------------------------------------------------


class IacReview:
    """State of one orchestrated run.

    A short-lived object rather than module globals, so a test may call
    :func:`main` twice in one process without the second run inheriting the
    first one's Findings.

    Attributes:
        root: The workspace root (:func:`workspace_root`).
        targets: Contained, existing absolute paths from ``--target``.
        enabled: Source names this run may use.
        rules_dirs: ``--rules-dir`` values, as given. Passed on unresolved,
            because :func:`iacreview.cfnguard.run_and_normalize` contains them
            itself against the workspace root.
        rules_roots: The same directories resolved, plus the bundled ``rules/``
            tree. Held so that containment is checked during validation, before
            any tool runs.
        agent_findings: Resolved ``--agent-findings`` path, or ``None``.
        confirm_cdk_synth: The ``--confirm-cdk-synth`` flag.
        tools: Verified external tools by executable name; ``None`` for one that
            could not be used.
        specs: The Sources that will actually be called, in collection order.
        succeeded: Sources that completed at least one Template. Decides,
            together with :attr:`reviewed`, whether the run exits 0.
        failures: ``(StructuredError, exit_code)`` in the order recorded. The
            exit code is what that failure would justify on its own; whether it
            is used depends on how much else succeeded.
        buckets: Findings by Template path. Deduplication is per Template
            (Requirement 14 AC5 matches on logical ID, and two Templates may
            reuse one logical ID for unrelated resources).
        standalone_files: Candidate Templates named directly or found outside
            ``cdk.out``.
        synthesized_files: Candidate Templates found under ``cdk.out``
            (Requirement 8 AC10).
        reviewed: The candidates that parsed and were handed to the Sources. The
            report's ``target`` arrays are built from these rather than from the
            candidate lists: a directory scan reaches files that were never
            Templates, and listing one under ``target.files`` would claim it was
            reviewed. Each is instead named in ``errors[]`` (Requirement 3 AC5).
        cdk_detected: Whether any target directory held a ``cdk.json``.
        noecho: ``NoEcho`` Parameter names seen across the reviewed Templates,
            used to redact agent-supplied Evidence.
        work_started: Whether :meth:`run` was entered, which decides whether a
            failure can produce a partial report at all.
    """

    def __init__(self) -> None:
        self.root: Path = workspace_root()
        self.targets: List[Path] = []
        self.enabled: List[str] = list(SOURCE_ORDER_FOR_COLLECTION)
        self.rules_dirs: Optional[List[str]] = None
        self.rules_roots: List[Path] = []
        self.agent_findings: Optional[Path] = None
        self.confirm_cdk_synth: bool = False
        self.tools: Dict[str, Optional[ToolInfo]] = {}
        self.specs: List[SourceSpec] = []
        self.succeeded: Set[str] = set()
        self.failures: List[Tuple[StructuredError, int]] = []
        self.buckets: Dict[str, List[Finding]] = {}
        self.standalone_files: List[str] = []
        self.synthesized_files: List[str] = []
        self.reviewed: List[str] = []
        self.cdk_detected: bool = False
        self.noecho: Set[str] = set()
        self.work_started: bool = False

    # -- argument validation ------------------------------------------------

    def validate(self, args: argparse.Namespace) -> None:
        """Resolve and contain every path before any work begins.

        Runs in :func:`iacreview.bootstrap.run_entry_point`'s ``validate`` slot,
        which is before the first file read and the first subprocess. A path
        outside the workspace, or one carrying a shell metacharacter, is refused
        while refusing it still costs nothing (Requirement 16 AC7).

        Args:
            args: The parsed namespace.

        Raises:
            UnsafeArgumentError: A path contains a shell metacharacter (exit 2).
            InvalidArgumentsError: A path is empty or cannot be normalized
                (exit 2).
            InputNotFoundError: A path does not exist (exit 3).
            PathContainmentError: A path resolves outside the workspace (exit 7).
            MappingFileError: The bundled ``rules/`` tree is missing (exit 1).
        """
        self.targets = [
            pathguard.resolve_within(value, self.root) for value in args.target
        ]
        self.enabled = enabled_sources(args.sources)
        self.rules_dirs = args.rules_dir
        # Resolved here purely so that a rule directory outside the workspace is
        # exit 7 before cfn-guard starts; the unresolved values are what the
        # Source receives.
        self.rules_roots = cfnguard.resolve_rules_dirs(args.rules_dir, self.root)
        self.agent_findings = (
            pathguard.resolve_within(args.agent_findings, self.root)
            if args.agent_findings
            else None
        )
        self.confirm_cdk_synth = bool(args.confirm_cdk_synth)

    # -- discovery ----------------------------------------------------------

    def _relative(self, path: Path) -> str:
        """Render ``path`` as the workspace-relative string a report may carry.

        The fallback to ``path.name`` covers the one case
        :func:`iacreview.source.workspace_relative` declines: the workspace root
        itself, which cannot be expressed relative to itself. A path outside the
        workspace never reaches here -- :meth:`validate` and
        :mod:`iacreview.cdk` both refuse one.
        """
        return workspace_relative(str(path), self.root) or path.name

    def _record(self, error: StructuredError, exit_code: int) -> None:
        """Add one ``errors[]`` entry and the exit code it would justify."""
        self.failures.append((error, exit_code))

    def _discover(self, *, verbose: bool) -> Tuple[List[Path], List[Path]]:
        """Find the Templates to review, split into the two groups.

        Requirement 8 AC10 wants standalone and synthesized Templates reported
        separately, so the split is made here and carried all the way to
        ``target.files`` / ``target.cdk.synthesized_templates``.

        Returns:
            ``(standalone, synthesized)``, both absolute and sorted ascending.

        Raises:
            ToolUnavailableError: ``--confirm-cdk-synth`` was given and the CDK
                CLI is absent (Requirement 8 AC8).
            ToolExecutionError: ``cdk synth`` exited non-zero.
            ToolTimeoutError: ``cdk synth`` exceeded its timeout.

                The last three are raised rather than recorded because
                Requirement 8 AC7 forbids continuing into any alternative
                execution mode; a report built from the previous contents of
                ``cdk.out`` would review a stale Template as a current one.
        """
        standalone: List[Path] = []
        synthesized: List[Path] = []

        for target in self.targets:
            if not target.is_dir():
                standalone.append(target)
                continue

            detection = cdk.detect_cdk_project(target)
            self.cdk_detected = self.cdk_detected or detection.is_cdk_project
            found, _ = cdk.partition_templates(target)
            standalone.extend(found)

            if detection.is_cdk_project and not self.confirm_cdk_synth:
                # Requirement 8 AC4, AC5: the run continues with whatever is
                # already synthesized, and the report records that synthesis was
                # skipped. Exit code OK: nothing failed, coverage is narrower.
                self._record(
                    InvalidArgumentsError(
                        "{0} {1}".format(
                            cdk.SYNTH_NOT_CONFIRMED_NOTICE, cdk.SYNTH_WARNING
                        ),
                        remediation=SYNTH_NOT_CONFIRMED_REMEDIATION,
                    ).to_structured_error(),
                    exitcodes.OK,
                )
            elif self.confirm_cdk_synth and not detection.is_cdk_project:
                bootstrap.verbose_diagnostic(
                    "--confirm-cdk-synth has no effect for {0}: no {1}".format(
                        self._relative(target), cdk.CDK_CONFIG_FILENAME
                    ),
                    verbose=verbose,
                )

            # One call, whichever way the gate went: synth_if_confirmed returns
            # the already-synthesized templates when it is not confirmed, and
            # cannot reach a process on that path (Requirement 8 AC3).
            synthesized.extend(
                cdk.synth_if_confirmed(
                    target, self.confirm_cdk_synth and detection.is_cdk_project
                )
            )

        return sorted(set(standalone), key=str), sorted(set(synthesized), key=str)

    # -- the Source loop ----------------------------------------------------

    def _verify_tools(self, *, verbose: bool) -> None:
        """Resolve and version-check each enabled Source's tool once.

        Once per run, not once per Template: otherwise ``--version`` would run
        per Template and an absent tool would append the same
        ``tool_unavailable`` entry once per Template, turning one problem into N.
        A Source whose tool cannot be used is left out of :attr:`specs`, so it is
        never called and counts as failed for the exit code.
        """
        checks = (
            (CFN_LINT, cfnlint.SOURCE_NAME),
            (CFN_GUARD, cfnguard.SOURCE_NAME),
        )
        for executable, source in checks:
            if source not in self.enabled:
                continue
            try:
                tool = require_known_tool(executable)
            except IacReviewError as exc:
                self.tools[executable] = None
                self._record(exc.to_structured_error(source), exc.exit_code)
                bootstrap.diagnostic(
                    "warning: {0}: {1}".format(exc.error_class, exc.message)
                )
                if exc.remediation:
                    bootstrap.diagnostic(exc.remediation)
                continue
            self.tools[executable] = tool
            bootstrap.verbose_diagnostic(
                "{0} {1} at {2}".format(executable, tool.version, tool.path),
                verbose=verbose,
            )

    def _build_specs(self) -> None:
        """Bind each usable Source to everything fixed for the whole run.

        design.md's ``SOURCES`` list, with the per-run arguments applied: the
        verified tool, the rule metadata, the workspace root. What is left is one
        parameter, the Template, which is what the loop varies.
        """
        specs: List[SourceSpec] = []

        lint_tool = self.tools.get(CFN_LINT)
        if cfnlint.SOURCE_NAME in self.enabled and lint_tool is not None:
            specs.append(
                SourceSpec(
                    cfnlint.SOURCE_NAME,
                    functools.partial(
                        cfnlint.run_and_normalize,
                        tool=lint_tool,
                        workspace_root=self.root,
                    ),
                )
            )

        guard_tool = self.tools.get(CFN_GUARD)
        if cfnguard.SOURCE_NAME in self.enabled and guard_tool is not None:
            # Loaded once: the sidecars describe the rule set, not the Template,
            # and a malformed one should be reported once rather than per file.
            metadata = cfnguard.load_rule_metadata(self.rules_roots)
            specs.append(
                SourceSpec(
                    cfnguard.SOURCE_NAME,
                    functools.partial(
                        cfnguard.run_and_normalize,
                        rules_dirs=self.rules_dirs,
                        tool=guard_tool,
                        workspace_root=self.root,
                        metadata=metadata,
                    ),
                )
            )

        if iam.SOURCE_NAME in self.enabled:
            specs.append(
                SourceSpec(
                    iam.SOURCE_NAME,
                    functools.partial(iam.run_and_normalize, workspace_root=self.root),
                )
            )

        if netgraph.SOURCE_NAME in self.enabled:
            specs.append(
                SourceSpec(
                    netgraph.SOURCE_NAME,
                    functools.partial(
                        netgraph.run_and_normalize, workspace_root=self.root
                    ),
                )
            )

        if secrets.SOURCE_NAME in self.enabled:
            specs.append(
                SourceSpec(
                    secrets.SOURCE_NAME,
                    functools.partial(
                        secrets.run_and_normalize, workspace_root=self.root
                    ),
                )
            )

        # Sorted rather than trusted in append order, so the fixed Source order
        # survives an edit that reorders the blocks above.
        order = {name: index for index, name in enumerate(SOURCE_ORDER_FOR_COLLECTION)}
        self.specs = sorted(specs, key=lambda spec: order[spec.name])

    def collect(
        self, path: Path, loaded: template.LoadedTemplate, *, verbose: bool
    ) -> List[Finding]:
        """Run every Source over one Template (design.md's ``collect()``).

        Args:
            path: The Template, as a workspace-relative path. Relative so that
                any message a Source builds from it names the file the way the
                report does, rather than embedding an absolute host path
                (Requirement 16 AC11).
            loaded: The already-parsed Template, handed to the IAM Source so the
                file is parsed once per Template rather than once per Source.
            verbose: The ``--verbose`` flag, gating counter diagnostics only.

        Returns:
            The Findings every Source produced for this Template, in Source
            order, not yet deduplicated.

        Note:
            Neither an expected failure nor an unexpected exception leaves this
            method: both become one ``errors[]`` entry and the loop moves on to
            the next Source (Requirement 2 AC10). A Source that returns
            successfully while reporting a failure -- an unavailable tool, an
            unreadable rule sidecar -- has its errors merged in the same way.
        """
        findings: List[Finding] = []

        for spec in self.specs:
            call = spec.call
            if spec.name in (iam.SOURCE_NAME, netgraph.SOURCE_NAME, secrets.SOURCE_NAME):
                # The only Source that reads the Template itself rather than
                # handing the path to a subprocess, so it is the only one that
                # can reuse the parse. Bound here rather than in _build_specs
                # because the parsed Template changes per Template while
                # everything else a spec carries does not.
                call = functools.partial(call, loaded=loaded)

            try:
                result = call(path)
            except IacReviewError as exc:
                self._record(
                    exc.to_structured_error(spec.name),
                    SOURCE_ERROR_EXIT_CODES.get(exc.error_class, exc.exit_code),
                )
                bootstrap.diagnostic(
                    "warning: {0}: {1}: {2}".format(
                        spec.name, exc.error_class, exc.message
                    )
                )
                continue
            except Exception as exc:  # noqa: BLE001 - AC10: never stop the loop
                self._record(unexpected_error(spec.name, exc), exitcodes.UNEXPECTED)
                traceback.print_exc(file=sys.stderr)
                continue

            findings.extend(result.findings)
            for error in result.errors:
                self._record(
                    error,
                    SOURCE_ERROR_EXIT_CODES.get(
                        str(error.get("error_class")), exitcodes.UNEXPECTED
                    ),
                )
            if source_ran(result):
                self.succeeded.add(spec.name)
            self._log_result(path, result, verbose=verbose)

        return findings

    def _log_result(
        self, path: Path, result: SourceResult, *, verbose: bool
    ) -> None:
        """Report one Source's counters, and the IAM message, on stderr.

        The counters are gated on ``--verbose``; the informational message of
        Requirement 6 AC12 is not, because it is the answer for a Template with
        no IAM rather than a diagnostic. Neither reaches stdout: see the module
        docstring on why the envelope carries no ``stats``.
        """
        message = result.stats.get("informational_message")
        if message:
            bootstrap.diagnostic("{0}: {1}".format(path, message))

        if not result.stats:
            return
        rendered = ", ".join(
            "{0}={1}".format(key, result.stats[key]) for key in sorted(result.stats)
        )
        bootstrap.verbose_diagnostic(
            "{0}: {1}: {2}".format(path, result.source, rendered), verbose=verbose
        )

    # -- agent findings -----------------------------------------------------

    def _load_agent_findings(self) -> List[Finding]:
        """Load ``--agent-findings``, outside the Source loop.

        design.md keeps the intake out of the loop because agent output is not a
        Source that runs per Template: it is one file describing any number of
        Templates, and it is validated once.

        Returns:
            The Findings that passed validation, or an empty list. A Finding that
            failed validation is dropped with one ``errors[]`` entry; a file that
            could not be read or parsed at all is one ``errors[]`` entry and the
            review continues without agent Findings (design.md, Failure mode
            matrix). Neither is a non-zero exit: the deterministic review is
            unaffected by what the agent supplied.

        Note:
            An exception the intake does not declare is handled the same way
            :meth:`collect` handles one -- recorded by type and stepped over --
            rather than left to propagate. In the orchestrated run this intake is
            where the ``cloudformation-review`` Skill's output arrives, so a
            defect here is a failing sub-skill, and Requirement 2 AC10 asks for
            an ``errors[]`` entry and a continued review rather than for the loss
            of the whole report. Property 24 is what found the asymmetry: without
            this branch, an undeclared exception here reached
            :func:`iacreview.bootstrap.run_entry_point` and the run ended with
            exit 1 and an empty stdout, discarding every deterministic Finding
            already collected.
        """
        if self.agent_findings is None:
            return []
        try:
            findings, errors = agentin.load_agent_findings(
                self.agent_findings, noecho_parameters=sorted(self.noecho)
            )
        except IacReviewError as exc:
            self._record(exc.to_structured_error(AGENT_SOURCE), exitcodes.OK)
            bootstrap.diagnostic(
                "warning: {0}: {1}".format(exc.error_class, exc.message)
            )
            return []
        except Exception as exc:  # noqa: BLE001 - AC10: never lose the report
            self._record(unexpected_error(AGENT_SOURCE, exc), exitcodes.OK)
            traceback.print_exc(file=sys.stderr)
            return []

        for error in errors:
            self._record(error, exitcodes.OK)
        if errors:
            bootstrap.diagnostic(
                "warning: {0} agent finding(s) were dropped as invalid".format(
                    len(errors)
                )
            )
        return findings

    # -- output -------------------------------------------------------------

    def _report(self) -> Dict[str, Any]:
        """Assemble the Review_Report from the state collected so far."""
        findings: List[Finding] = []
        for key in sorted(self.buckets):
            findings.extend(dedup.deduplicate(self.buckets[key]))

        sources = list(self.enabled)
        if self.agent_findings is not None:
            sources.append(AGENT_SOURCE)

        reviewed = set(self.reviewed)
        return report.build_report(
            findings,
            [error for error, _ in self.failures],
            report.ReportMeta(
                files=[f for f in self.standalone_files if f in reviewed],
                sources_enabled=sources,
                tools=self._tool_statuses(),
                cdk_detected=self.cdk_detected,
                synthesized_templates=[
                    f for f in self.synthesized_files if f in reviewed
                ],
            ),
        )

    def _tool_statuses(self) -> List[report.ToolStatus]:
        """Render the version checks as the report's ``tools`` array.

        One entry per external tool this run had a Source for, so a disabled
        Source contributes none. The version is ``None`` for an unparsable banner
        as well as for an absent tool: :data:`~iacreview.toolcheck.UNKNOWN_VERSION`
        is a sentinel, not a version a consumer could compare.
        """
        statuses: List[report.ToolStatus] = []
        for executable in (CFN_LINT, CFN_GUARD):
            if executable not in self.tools:
                continue
            tool = self.tools[executable]
            version = None
            if tool is not None and tool.version != UNKNOWN_VERSION:
                version = tool.version
            statuses.append(
                report.ToolStatus(
                    name=executable, available=tool is not None, version=version
                )
            )
        return statuses

    def exit_code(self) -> int:
        """Exit status for a run that produced a report.

        Returns:
            :data:`~iacreview.exitcodes.OK` when at least one Template was
            reviewed by at least one Source: the report then describes real work,
            and the failures it also describes are in ``errors[]`` where a reader
            can see exactly what was missed (design.md: "個別 Source の失敗は
            errors[] に記録され exit 0 を維持する").

            Otherwise the code the *first* recorded failure justifies. The first
            one is the failure that stopped the review; a later, milder one
            cannot mask it.
        """
        first = next(
            (code for _, code in self.failures if code != exitcodes.OK), exitcodes.OK
        )
        if self.reviewed and self.succeeded:
            return exitcodes.OK
        return first

    def partial_report(self, exc: IacReviewError) -> Optional[Dict[str, Any]]:
        """Build the report that accompanies a failure, or decline to.

        Args:
            exc: The failure :func:`iacreview.bootstrap.run_entry_point` caught.

        Returns:
            A Review_Report carrying ``exc`` in ``errors[]`` alongside everything
            collected before it, or ``None`` to leave stdout empty. ``None``
            whenever the failure happened before :meth:`run` was entered, or its
            class is not one the report can describe
            (:data:`PARTIAL_REPORT_ERROR_CLASSES`).
        """
        if not self.work_started:
            return None
        if exc.error_class not in PARTIAL_REPORT_ERROR_CLASSES:
            return None
        self._record(exc.to_structured_error(), exc.exit_code)
        return self._report()

    # -- the run ------------------------------------------------------------

    def run(self, args: argparse.Namespace) -> bootstrap.EntryPointOutcome:
        """Review every reachable Template and return the report.

        The order is the one design.md's flow diagram fixes: discover, then
        review standalone Templates, then review synthesized ones
        (Requirement 8 AC10), then take in agent Findings, then merge per
        Template, then assemble.

        Args:
            args: Parsed arguments. Only ``--verbose`` is read here; everything
                else was consumed by :meth:`validate`.

        Returns:
            The report and its exit code.

        Raises:
            NotReviewableError: No candidate Template was found under any
                ``--target`` (exit 8, Requirement 3 AC5, Requirement 8 AC5).
            ToolUnavailableError: The CDK CLI was absent after
                ``--confirm-cdk-synth`` (exit 5).
            ToolExecutionError: ``cdk synth`` failed (exit 6).
            ToolTimeoutError: ``cdk synth`` timed out (exit 6).
        """
        self.work_started = True
        verbose = args.verbose

        standalone, synthesized = self._discover(verbose=verbose)
        synthesized_set = set(synthesized)
        # A file named directly *and* found under cdk.out belongs to the
        # synthesized group: that is where it came from, and the two arrays must
        # stay disjoint for summary.by_template_group to add up.
        self.standalone_files = [
            self._relative(path) for path in standalone if path not in synthesized_set
        ]
        self.synthesized_files = [self._relative(path) for path in synthesized]

        candidates = self.standalone_files + self.synthesized_files
        if not candidates:
            raise NotReviewableError(
                "no reviewable CloudFormation template was found under: "
                "{0}".format(", ".join(self._relative(t) for t in self.targets)),
                remediation=(
                    "Point --target at a template file, or at a directory "
                    "containing one. For a CDK project, synthesize it first or "
                    "pass --confirm-cdk-synth."
                ),
            )

        self._verify_tools(verbose=verbose)
        self._build_specs()

        for file in candidates:
            path = Path(file)
            try:
                loaded = template.load_template(path)
            except IacReviewError as exc:
                # A file that does not parse, or holds no Resources, is reported
                # and skipped. With several candidates that is the only sensible
                # behaviour -- a directory scan reaches JSON that was never a
                # Template -- and design.md's failure matrix says so explicitly:
                # errors[] when some Templates are affected, the failure's own
                # exit code when all of them are.
                self._record(exc.to_structured_error(), exc.exit_code)
                bootstrap.diagnostic(
                    "warning: {0}: {1}".format(exc.error_class, exc.message)
                )
                continue

            self.noecho.update(noecho_parameter_names(loaded.doc))
            self.reviewed.append(file)
            self.buckets.setdefault(file, []).extend(
                self.collect(path, loaded, verbose=verbose)
            )

        for f in self._load_agent_findings():
            # Bucketed by the file the agent named, so an agent Finding merges
            # with the deterministic Findings of the same Template and with
            # nothing else. A file no Source reviewed still gets its own bucket:
            # the Finding is reported, and merges only with its own kind.
            self.buckets.setdefault(f.Location.File, []).append(f)

        bootstrap.verbose_diagnostic(
            "reviewed {0} of {1} candidate template(s) with {2} source(s)".format(
                len(self.reviewed), len(candidates), len(self.specs)
            ),
            verbose=verbose,
        )
        return bootstrap.EntryPointOutcome(
            report=self._report(), exit_code=self.exit_code()
        )


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the Skill and return its exit code.

    Args:
        argv: Arguments without the program name. ``None`` reads
            ``sys.argv[1:]``.

    Returns:
        A documented exit code from :mod:`iacreview.exitcodes`. Returned rather
        than raised, so tests can call this in-process.
    """
    review = IacReview()
    return bootstrap.run_entry_point(
        parser=build_parser(),
        run=review.run,
        argv=argv,
        validate=review.validate,
        partial_report=review.partial_report,
    )


if __name__ == "__main__":
    sys.exit(main())
