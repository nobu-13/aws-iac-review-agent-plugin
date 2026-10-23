"""Command line of the v1.1 Delta_Tool (Design 8, 10-4, 10-5).

Run from the workspace root with the Plugin root on the import path::

    PYTHONPATH=<plugin_root> python3 -m iacreview.deltacli \\
        --base-template base.yaml --head-template head.yaml \\
        --base-report base.json --head-report head.json \\
        --declare reports_unmodified ...

The workspace root is the current directory. Every path must resolve inside it.

Declared Template path (H-M1-1 approved, Design 8-2, 9-4)
    With both pairs, ``--reviewed-template-path PATH`` declares the one
    workspace-relative path at which both Reports reviewed the Template (two
    checkouts of one repository). It is a declaration, not a verification: the
    file is not read, and the value is recorded as ``declared_not_verified``.
    It only replaces the path the correspondence check compares with each
    Report's ``target``; report integrity, Comparable, the required
    declarations and the limits are unchanged.

Arguments are checked before any input is read
    A pair given on one side only, no pair at all, ``--declare`` without a
    Report_Pair, ``--declare reports_match_templates`` without a
    Template_Pair, a declaration Code outside the closed set (including
    ``all``), a path option or ``--format`` given twice, an empty path, and a path with a shell
    metacharacter or a NUL character all exit 2 with no Delta_Report. So does
    ``--reviewed-template-path`` without both pairs, given twice, empty, with a
    NUL or shell metacharacter, absolute, with a drive or ``..``, or leaving
    the workspace through an existing symlink; a path that does not exist is
    accepted.
    ``argparse``'s own messages, which can repeat argument text, are not
    shown; a fixed message and the usage line are.

Processing order
    Base Template, Head Template, Semantic Diff, Base Report, Head Report,
    Report checks, correspondence, Finding Delta, Delta_Report. Both inputs of a
    pair are always read, so one unanalyzable side or comparison never hides
    the other: the other comparison is written in full. The exit code is the
    code of the first failure in the order Base Template, Head Template,
    Template comparison, Base Report, Head Report, output; 0 when every
    requested comparison is analyzed, whatever it observed.

Channels
    stdout carries the Delta_Report and nothing else, serialized like
    ``report.dump`` (with C1 and bidirectional controls as JSON ``\\uXXXX``
    escapes, ``deltareport.dump``) on a stream set up by
    ``report.configure_stdout``. stderr
    carries messages built from failure Codes, sides, input kinds, integer
    positions, schema field paths and limit values only, with C0 / C1 control
    characters and bidirectional controls replaced by ``\\u{XXXX}`` and
    ``errors.redact_stderr_line`` applied. No comparison summary is written to
    stderr. An unexpected exception is reported by its type name only, with no
    traceback, and exits 1.

Nothing else is read or written
    Behaviour depends on the arguments and the input files only: no
    environment variable, configuration file or stdin is read, and no file is
    written. The Plugin's own data (the category map and the bundled Guard
    rule names) is read as v1.0 reads it.
"""

from __future__ import annotations

import argparse
import io
import sys
from pathlib import Path
from typing import Any, FrozenSet, List, Optional, Sequence, TextIO, Tuple, Union

from iacreview import bootstrap, delta, deltaio, deltareport, deltaschema, exitcodes, pathguard, report, reportcheck, semdiff
from iacreview.deltaio import Failure, ParsedTemplate
from iacreview.deltareport import DeltaRequest, FailureRecord, ReportInput, TemplateInput
from iacreview.errors import IacReviewError, InputNotFoundError, redact_stderr_line
from iacreview.reportcheck import CheckedReport, ReportRejection

__all__ = ["PROG", "build_parser", "sanitize_stderr", "main"]

#: Program name shown in usage.
PROG = "python3 -m iacreview.deltacli"

_DESCRIPTION = (
    "Compare a Base and a Head CloudFormation Template (Semantic Diff) and/or a "
    "Base and a Head Review_Report (Finding Delta). Writes a Delta_Report JSON "
    "to stdout. Read-only: starts no process and writes no file."
)

#: Code points replaced on stderr besides C0 / C1 controls and DEL: the
#: bidirectional embedding, override and isolate controls, and the marks.
_BIDI_CONTROLS: FrozenSet[int] = frozenset(
    list(range(0x202A, 0x202F)) + list(range(0x2066, 0x206A)) + [0x200E, 0x200F, 0x061C]
)

_PATH_OPTIONS: Tuple[str, ...] = ("base_template", "head_template", "base_report", "head_report")

_DECLARED_PATH_OPTION = "--reviewed-template-path"


# ---------------------------------------------------------------------------
# stderr
# ---------------------------------------------------------------------------


def sanitize_stderr(line: str) -> str:
    """Replace control and bidirectional characters, then redact host values."""
    parts: List[str] = []
    for char in line:
        code = ord(char)
        if code < 0x20 or 0x7F <= code <= 0x9F or code in _BIDI_CONTROLS:
            parts.append("\\u{{{0:04X}}}".format(code))
        else:
            parts.append(char)
    return redact_stderr_line("".join(parts))


def _diagnose(stream: TextIO, text: str) -> None:
    for line in text.splitlines():
        stream.write(sanitize_stderr(line) + "\n")


# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------


class _Once(argparse.Action):
    """Store a value, refusing a second occurrence of the option."""

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Any,
        option_string: Optional[str] = None,
    ) -> None:
        if getattr(namespace, self.dest, None) is not None:
            parser.error("{0} given more than once".format(option_string))
        setattr(namespace, self.dest, values)


def build_parser() -> bootstrap.EntryPointParser:
    """The Delta_Tool parser, built on ``bootstrap.new_parser``."""
    parser = bootstrap.new_parser(PROG, _DESCRIPTION)
    for option, help_text in (
        ("--base-template", "Base (before) Template file."),
        ("--head-template", "Head (after) Template file."),
        ("--base-report", "Base Review_Report JSON produced by run_iac_review.py."),
        ("--head-report", "Head Review_Report JSON produced by run_iac_review.py."),
    ):
        parser.add_argument(option, action=_Once, default=None, metavar="PATH", help=help_text)
    parser.add_argument(
        "--declare",
        action="append",
        default=[],
        choices=deltaschema.DECLARATION_CODES,
        metavar="CODE",
        help=(
            "Declare one input assumption the tool cannot check; repeatable, one "
            "Code each: {0}. A declaration is recorded, not verified.".format(
                ", ".join(deltaschema.DECLARATION_CODES)
            )
        ),
    )
    parser.add_argument(
        _DECLARED_PATH_OPTION,
        action=_Once,
        default=None,
        dest="reviewed_template_path",
        metavar="PATH",
        help=(
            "With both pairs: the workspace-relative path at which both Reports "
            "reviewed the Template, compared with each Report's target instead of "
            "the Template paths. A declaration, recorded as declared_not_verified: "
            "not verified, and the file is not read."
        ),
    )
    parser.add_argument(
        "--format",
        action=_Once,
        default=None,
        choices=("json",),
        help="Output format. Only json (the default).",
    )
    parser.add_argument(
        "--plain-identifiers",
        action="store_true",
        help=(
            "Write identifiers (Logical IDs, entry names, path keys, Resource Types) "
            "in plain form. Values and free text are never written."
        ),
    )
    return parser


def _parse(argv: Sequence[str], stderr: TextIO) -> Union[argparse.Namespace, int]:
    """Parse ``argv``; argparse's messages are captured and not shown."""
    parser = build_parser()
    captured = io.StringIO()
    parser.diagnostic_stream = captured
    try:
        return parser.parse_args(list(argv))
    except SystemExit as exc:
        if exc.code in (None, 0):
            # --help: the text is built from this module only.
            _diagnose(stderr, captured.getvalue())
            return exitcodes.OK
        _reject(stderr, "the arguments were not accepted", parser)
        return exitcodes.INVALID_ARGUMENTS


def _reject(stderr: TextIO, reason: str, parser: Optional[argparse.ArgumentParser] = None) -> None:
    _diagnose(stderr, "deltacli: invalid_arguments: {0}".format(reason))
    usage = (parser or build_parser()).format_usage()
    _diagnose(stderr, usage)


def _argument_problem(args: argparse.Namespace) -> Optional[str]:
    """Why the parsed arguments cannot run, before any input is read."""
    templates = (args.base_template, args.head_template)
    reports = (args.base_report, args.head_report)
    if (templates[0] is None) != (templates[1] is None):
        return "a Template_Pair needs --base-template and --head-template"
    if (reports[0] is None) != (reports[1] is None):
        return "a Report_Pair needs --base-report and --head-report"
    if templates[0] is None and reports[0] is None:
        return "give a Template_Pair, a Report_Pair, or both"
    if args.declare and reports[0] is None:
        return "--declare needs a Report_Pair"
    if "reports_match_templates" in args.declare and templates[0] is None:
        return "--declare reports_match_templates needs a Template_Pair"
    if args.reviewed_template_path is not None and (templates[0] is None or reports[0] is None):
        return "{0} needs a Template_Pair and a Report_Pair".format(_DECLARED_PATH_OPTION)
    for name in _PATH_OPTIONS + ("reviewed_template_path",):
        value = getattr(args, name)
        if value is None:
            continue
        if not value or "\x00" in value:
            return "a path argument is empty or contains a NUL character"
        try:
            pathguard.assert_no_shell_metacharacters(value)
        except IacReviewError:
            return "a path argument contains a shell metacharacter"
    return None


def _declared_path(value: str, root: Path) -> Optional[str]:
    """The normalized ``--reviewed-template-path``, or ``None`` when refused.

    The value is normalized like a Report path (``report.normalize_output_path``
    refuses an absolute path, a drive and ``..``) and must not leave ``root``
    through an existing path element, a symlink included. It need not exist:
    the Reports may come from another checkout. Nothing is read.
    """
    try:
        normalized = report.normalize_output_path(value)
    except IacReviewError:
        return None
    try:
        pathguard.resolve_within(normalized, root)
    except InputNotFoundError:
        return normalized
    except (IacReviewError, OSError, ValueError):
        return None
    return normalized


# ---------------------------------------------------------------------------
# Processing
# ---------------------------------------------------------------------------


def _workspace_path(arg: str, root: Path) -> Optional[str]:
    """The ``/``-separated workspace-relative path of ``arg``, if it resolves."""
    try:
        resolved = pathguard.resolve_within(arg, root)
        return report.normalize_output_path(resolved.relative_to(root).as_posix())
    except (IacReviewError, OSError, ValueError):
        return None


_TemplateResult = Union[ParsedTemplate, Failure]


def _read_templates(
    args: argparse.Namespace, root: Path, failures: List[FailureRecord]
) -> Tuple[Tuple[TemplateInput, TemplateInput], Tuple[_TemplateResult, _TemplateResult]]:
    inputs: List[TemplateInput] = []
    results: List[_TemplateResult] = []
    for side, arg in (("base", args.base_template), ("head", args.head_template)):
        result = deltaio.read_template(arg, root, side)
        if isinstance(result, Failure):
            failures.append(FailureRecord(result))
            inputs.append(TemplateInput(_workspace_path(arg, root), None))
        else:
            inputs.append(TemplateInput(_workspace_path(arg, root), result))
        results.append(result)
    return (inputs[0], inputs[1]), (results[0], results[1])


def _read_reports(
    args: argparse.Namespace, root: Path, failures: List[FailureRecord]
) -> Tuple[ReportInput, ReportInput]:
    inputs: List[ReportInput] = []
    for side, arg in (("base", args.base_report), ("head", args.head_report)):
        path = _workspace_path(arg, root)
        loaded = deltaio.read_report(arg, root, side)
        if isinstance(loaded, Failure):
            failures.append(FailureRecord(loaded))
            inputs.append(ReportInput(path, None, None))
            continue
        checked = reportcheck.check_report(loaded.obj, side)
        if isinstance(checked, ReportRejection):
            failures.append(FailureRecord(checked.failure, checked.field))
            inputs.append(ReportInput(path, loaded.sha256, None))
        else:
            inputs.append(ReportInput(path, loaded.sha256, checked))
    return inputs[0], inputs[1]


def _request(args: argparse.Namespace, root: Path, declared_path: Optional[str] = None) -> DeltaRequest:
    """The DeltaRequest; ``declared_path`` is the checked ``--reviewed-template-path``."""
    failures: List[FailureRecord] = []
    declarations = frozenset(args.declare)

    templates: Optional[Tuple[TemplateInput, TemplateInput]] = None
    template_results: Optional[Tuple[_TemplateResult, _TemplateResult]] = None
    diff_result: Optional[semdiff.SemanticDiffResult] = None
    if args.base_template is not None:
        templates, template_results = _read_templates(args, root, failures)
        base_t, head_t = template_results
        if isinstance(base_t, ParsedTemplate) and isinstance(head_t, ParsedTemplate):
            compared = semdiff.diff(base_t, head_t)
            if isinstance(compared, Failure):
                failures.append(FailureRecord(compared))
                # The Templates were not compared: correspondence is unknown.
                template_results = (compared, compared)
            else:
                diff_result = compared

    reports: Optional[Tuple[ReportInput, ReportInput]] = None
    delta_result: Optional[delta.FindingDeltaResult] = None
    guard_rule_names: FrozenSet[str] = frozenset()
    if args.base_report is not None:
        guard_rule_names = deltaio.load_guard_rule_names()
        reports = _read_reports(args, root, failures)
        base_r, head_r = reports[0].checked, reports[1].checked
        if isinstance(base_r, CheckedReport) and isinstance(head_r, CheckedReport):
            if templates is None or template_results is None:
                correspondence = reportcheck.correspondence(None, None, base_r, head_r, None)
            else:
                if declared_path is not None:
                    # Design 9-4: the declared path is the comparison path of both sides.
                    paths = (declared_path, declared_path)
                else:
                    paths = (templates[0].path or "", templates[1].path or "")
                correspondence = reportcheck.correspondence(
                    template_results[0], template_results[1], base_r, head_r, paths
                )
            delta_result = delta.match_and_classify(
                base_r,
                head_r,
                declarations=declarations,
                correspondence=correspondence,
                rename_hints=frozenset() if diff_result is None else diff_result.rename_hints,
            )

    return DeltaRequest(
        templates=templates,
        reports=reports,
        semantic_diff=diff_result,
        finding_delta=delta_result,
        failures=tuple(failures),
        declarations=declarations,
        guard_rule_names=guard_rule_names,
        reviewed_template_path=declared_path,
    )


def _main(argv: Sequence[str], stdout: TextIO, stderr: TextIO) -> int:
    parsed = _parse(argv, stderr)
    if isinstance(parsed, int):
        return parsed
    problem = _argument_problem(parsed)
    if problem is not None:
        _reject(stderr, problem)
        return exitcodes.INVALID_ARGUMENTS

    root = Path.cwd().resolve()
    declared_path: Optional[str] = None
    if parsed.reviewed_template_path is not None:
        declared_path = _declared_path(parsed.reviewed_template_path, root)
        if declared_path is None:
            _reject(stderr, "{0} must be a workspace-relative path that stays inside the workspace".format(_DECLARED_PATH_OPTION))
            return exitcodes.INVALID_ARGUMENTS
    request = _request(parsed, root, declared_path)
    mode = "plain" if parsed.plain_identifiers else "anonymized"
    rendered = deltareport.render_delta_report(request, mode)
    report.configure_stdout(stdout)
    stdout.write(rendered.text)
    stdout.flush()
    for record in rendered.failures:
        _diagnose(stderr, "deltacli: " + deltareport.failure_message(record))
    return rendered.exit_code


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    stdout: Optional[TextIO] = None,
    stderr: Optional[TextIO] = None,
) -> int:
    """Run the Delta_Tool. Returns the exit code.

    Args:
        argv: Arguments without the program name; ``sys.argv[1:]`` by default.
        stdout: Delta_Report destination; ``sys.stdout`` by default.
        stderr: Diagnostics destination; ``sys.stderr`` by default.
    """
    out = sys.stdout if stdout is None else stdout
    err = sys.stderr if stderr is None else stderr
    try:
        return _main(sys.argv[1:] if argv is None else argv, out, err)
    except (Exception, KeyboardInterrupt) as exc:  # noqa: BLE001 - outermost handler, no traceback
        _diagnose(err, "deltacli: unexpected: {0}".format(type(exc).__name__))
        return exitcodes.UNEXPECTED


if __name__ == "__main__":
    sys.exit(main())
