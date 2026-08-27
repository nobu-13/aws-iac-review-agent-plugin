"""Path bootstrap and shared ``main()`` wrapper checks.

Three groups, matching the three things ``iacreview/bootstrap.py`` promises:

(a) the ``parents[3]`` depth assumption holds for every Skill entry point, so
    moving a script to another depth fails a test instead of failing at run time;
(b) the verification function reports a missing ``plugin.json`` clearly;
(c) the ``main()`` wrapper maps every :class:`IacReviewError` onto its documented
    exit code, keeps stdout to JSON only, and never reads stdin.

The depth assertions in group (a) deliberately do not require the script files to
exist: the assumption is a property of where a script is *placed*, and asserting
it works for a path alone. The prologue assertion does require existence, since
there is nothing to read otherwise, and all six entry points are now written.
"""

from __future__ import annotations

import argparse
import io
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from iacreview import bootstrap, exitcodes
from iacreview.errors import (
    ERROR_CLASS_HIERARCHY,
    IacReviewError,
    InputNotFoundError,
    InvalidArgumentsError,
    MappingFileError,
    ToolUnavailableError,
)

# Entry point scripts of the five Skills, as design.md's Directory Structure
# lists them. Written out literally: if a script is added, moved or renamed, this
# list must be updated, and the depth assertions below then re-check the move.
ENTRY_POINT_SCRIPTS = [
    "skills/cfn-lint-review/scripts/run_cfn_lint.py",
    "skills/cfn-guard-review/scripts/run_cfn_guard.py",
    "skills/iam-review/scripts/run_iam_scan.py",
    "skills/iam-review/scripts/extract_policies.py",
    "skills/cloudformation-review/scripts/extract_facts.py",
    "skills/iac-review/scripts/run_iac_review.py",
]

SKILL_NAMES = {
    "cfn-lint-review",
    "cfn-guard-review",
    "iam-review",
    "cloudformation-review",
    "iac-review",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fake_plugin_tree(root: Path, *, with_manifest: bool) -> Path:
    """Create ``<root>/skills/demo/scripts/demo.py`` and return the script path.

    Used instead of moving the repository's own ``plugin.json`` aside: a test
    that renames a file at the plugin root would break every other test running
    in the same session.
    """
    scripts = root / "skills" / "demo" / "scripts"
    scripts.mkdir(parents=True)
    script = scripts / "demo.py"
    script.write_text("", encoding="utf-8")
    if with_manifest:
        (root / "plugin.json").write_text("{}", encoding="utf-8")
    return script


class _RefusingStdin(io.StringIO):
    """A stdin stand-in that fails the test if anything reads from it."""

    def read(self, *args: Any, **kwargs: Any) -> str:
        raise AssertionError("entry point read from stdin")

    def readline(self, *args: Any, **kwargs: Any) -> str:  # type: ignore[override]
        raise AssertionError("entry point read from stdin")

    def readlines(self, *args: Any, **kwargs: Any) -> List[str]:  # type: ignore[override]
        raise AssertionError("entry point read from stdin")


def _parser(*, require_target: bool = False) -> bootstrap.EntryPointParser:
    parser = bootstrap.new_parser("demo.py", "demo entry point")
    if require_target:
        parser.add_argument("--target", action="append", required=True)
    return parser


# ---------------------------------------------------------------------------
# (a) Plugin root derivation for the five Skills' entry points
# ---------------------------------------------------------------------------


def test_script_depth_constant_matches_the_documented_layout() -> None:
    # scripts/ -> <skill>/ -> skills/ -> plugin root
    assert bootstrap.SCRIPT_DEPTH_TO_PLUGIN_ROOT == 3


@pytest.mark.parametrize("relative", ENTRY_POINT_SCRIPTS)
def test_entry_point_derives_the_real_plugin_root(
    plugin_root: Path, relative: str
) -> None:
    assert bootstrap.derive_plugin_root(plugin_root / relative) == plugin_root


@pytest.mark.parametrize("relative", ENTRY_POINT_SCRIPTS)
def test_entry_point_sits_exactly_three_levels_below_the_root(relative: str) -> None:
    parts = Path(relative).parts
    assert parts[0] == "skills"
    assert parts[2] == "scripts"
    assert len(parts) == bootstrap.SCRIPT_DEPTH_TO_PLUGIN_ROOT + 1


def test_every_skill_has_at_least_one_entry_point_listed() -> None:
    covered = {Path(relative).parts[1] for relative in ENTRY_POINT_SCRIPTS}
    assert covered == SKILL_NAMES


@pytest.mark.parametrize("relative", ENTRY_POINT_SCRIPTS)
def test_entry_point_contains_the_required_bootstrap_lines(
    plugin_root: Path, relative: str
) -> None:
    # All six entry points exist, so the prologue is asserted unconditionally:
    # a script that loses the sys.path insertion, or moves to another depth,
    # fails here rather than at run time in someone else's workspace.
    script = plugin_root / relative
    assert script.is_file(), "{0} is missing".format(relative)
    text = script.read_text(encoding="utf-8")
    for line in bootstrap.REQUIRED_BOOTSTRAP_LINES:
        assert line in text


def test_documented_snippet_contains_the_required_lines() -> None:
    for line in bootstrap.REQUIRED_BOOTSTRAP_LINES:
        assert line in bootstrap.ENTRY_POINT_BOOTSTRAP


def test_a_script_at_another_depth_derives_a_different_root(tmp_path: Path) -> None:
    # This is the failure the depth assumption is exposed to: one directory level
    # dropped between skills/ and the script.
    too_shallow = tmp_path / "skills" / "demo" / "demo.py"
    correct = tmp_path / "skills" / "demo" / "scripts" / "demo.py"

    assert bootstrap.derive_plugin_root(correct) == tmp_path.resolve()
    assert bootstrap.derive_plugin_root(too_shallow) != tmp_path.resolve()


def test_derive_rejects_a_path_without_enough_parents() -> None:
    with pytest.raises(MappingFileError) as excinfo:
        bootstrap.derive_plugin_root(Path("/demo.py"))
    assert "plugin root" in str(excinfo.value)


def test_derive_resolves_symlinks_to_the_real_root(tmp_path: Path) -> None:
    real = tmp_path / "real"
    script = _fake_plugin_tree(real, with_manifest=True)
    link = tmp_path / "link.py"
    try:
        link.symlink_to(script)
    except (OSError, NotImplementedError):  # pragma: no cover - platform dependent
        pytest.skip("symlinks are not available on this platform")

    # The link sits directly under tmp_path; only symlink resolution can lead
    # back to the real tree three levels below.
    assert bootstrap.derive_plugin_root(link) == real.resolve()


def test_ensure_plugin_root_on_sys_path_is_idempotent(
    plugin_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sys

    monkeypatch.setattr(sys, "path", ["/somewhere/else"])
    script = plugin_root / ENTRY_POINT_SCRIPTS[0]

    first = bootstrap.ensure_plugin_root_on_sys_path(script)
    after_first = list(sys.path)
    second = bootstrap.ensure_plugin_root_on_sys_path(script)

    assert first == second == plugin_root
    assert sys.path[0] == str(plugin_root)
    assert sys.path == after_first


def test_verify_accepts_this_installation(plugin_root: Path) -> None:
    script = plugin_root / ENTRY_POINT_SCRIPTS[0]
    assert bootstrap.verify_plugin_root(script) == plugin_root


# ---------------------------------------------------------------------------
# (b) Verification when plugin.json is absent
# ---------------------------------------------------------------------------


def test_verify_reports_a_missing_manifest(tmp_path: Path) -> None:
    script = _fake_plugin_tree(tmp_path, with_manifest=False)

    with pytest.raises(MappingFileError) as excinfo:
        bootstrap.verify_plugin_root(script)

    message = str(excinfo.value)
    assert "plugin.json" in message
    # The inspected directory is named, so the reader can see where it looked.
    assert str(tmp_path.resolve()) in message
    assert excinfo.value.remediation


def test_missing_manifest_reports_as_unexpected_exit_code(tmp_path: Path) -> None:
    script = _fake_plugin_tree(tmp_path, with_manifest=False)
    with pytest.raises(MappingFileError) as excinfo:
        bootstrap.verify_plugin_root(script)
    # A broken installation, not bad user input (design.md, failure matrix).
    assert excinfo.value.exit_code == exitcodes.UNEXPECTED
    assert excinfo.value.error_class == "unexpected"


def test_verify_rejects_a_root_that_disagrees_with_the_imported_package(
    tmp_path: Path, plugin_root: Path
) -> None:
    script = _fake_plugin_tree(tmp_path, with_manifest=True)

    with pytest.raises(MappingFileError) as excinfo:
        bootstrap.verify_plugin_root(script)

    message = str(excinfo.value)
    assert "mismatch" in message
    assert str(plugin_root) in message


def test_require_plugin_root_exits_with_a_message_and_no_traceback(
    tmp_path: Path,
) -> None:
    script = _fake_plugin_tree(tmp_path, with_manifest=False)
    stderr = io.StringIO()

    with pytest.raises(SystemExit) as excinfo:
        bootstrap.require_plugin_root(script, stderr=stderr)

    assert excinfo.value.code == exitcodes.UNEXPECTED
    text = stderr.getvalue()
    assert "plugin.json" in text
    assert "Traceback" not in text


def test_require_plugin_root_returns_the_root_when_valid(plugin_root: Path) -> None:
    stderr = io.StringIO()
    script = plugin_root / ENTRY_POINT_SCRIPTS[0]
    assert bootstrap.require_plugin_root(script, stderr=stderr) == plugin_root
    assert stderr.getvalue() == ""


# ---------------------------------------------------------------------------
# (c) The main() wrapper
# ---------------------------------------------------------------------------


CONCRETE_ERRORS = [cls for cls in ERROR_CLASS_HIERARCHY]


@pytest.mark.parametrize(
    "error_class", CONCRETE_ERRORS, ids=[cls.__name__ for cls in CONCRETE_ERRORS]
)
def test_wrapper_maps_iac_review_error_to_its_exit_code(error_class: type) -> None:
    stdout, stderr = io.StringIO(), io.StringIO()

    def run(args: argparse.Namespace) -> None:
        raise error_class("boom")

    code = bootstrap.run_entry_point(
        parser=_parser(),
        run=run,
        argv=[],
        stdout=stdout,
        stderr=stderr,
    )

    assert code == error_class.exit_code
    # No report could be built, so stdout stays empty and the diagnostic names
    # the error class that appears in a report's errors[] entries.
    assert stdout.getvalue() == ""
    assert error_class.error_class in stderr.getvalue()
    assert "boom" in stderr.getvalue()


def test_wrapper_maps_validation_failure_before_running(tmp_path: Path) -> None:
    stdout, stderr = io.StringIO(), io.StringIO()
    calls: List[str] = []

    def validate(args: argparse.Namespace) -> None:
        calls.append("validate")
        raise InputNotFoundError("no such target")

    def run(args: argparse.Namespace) -> None:
        calls.append("run")

    code = bootstrap.run_entry_point(
        parser=_parser(),
        run=run,
        validate=validate,
        argv=[],
        stdout=stdout,
        stderr=stderr,
    )

    assert code == exitcodes.INPUT_NOT_FOUND
    assert calls == ["validate"]
    assert stdout.getvalue() == ""


def test_wrapper_writes_the_report_as_json_on_stdout() -> None:
    stdout, stderr = io.StringIO(), io.StringIO()

    code = bootstrap.run_entry_point(
        parser=_parser(),
        run=lambda args: {"findings": [], "schema_version": "1.0.0"},
        argv=[],
        stdout=stdout,
        stderr=stderr,
    )

    assert code == exitcodes.OK
    assert stdout.getvalue() == (
        '{\n  "findings": [],\n  "schema_version": "1.0.0"\n}\n'
    )
    assert stderr.getvalue() == ""


def test_wrapper_writes_nothing_when_run_returns_none() -> None:
    stdout = io.StringIO()
    code = bootstrap.run_entry_point(
        parser=_parser(),
        run=lambda args: None,
        argv=[],
        stdout=stdout,
        stderr=io.StringIO(),
    )
    assert code == exitcodes.OK
    assert stdout.getvalue() == ""


def test_wrapper_honours_a_non_zero_outcome_with_a_report() -> None:
    stdout = io.StringIO()
    outcome = bootstrap.EntryPointOutcome(
        report={"errors": [{"error_class": "tool_unavailable"}]},
        exit_code=exitcodes.TOOL_UNAVAILABLE,
    )

    code = bootstrap.run_entry_point(
        parser=_parser(),
        run=lambda args: outcome,
        argv=[],
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert code == exitcodes.TOOL_UNAVAILABLE
    assert "tool_unavailable" in stdout.getvalue()


def test_outcome_rejects_an_undocumented_exit_code() -> None:
    with pytest.raises(ValueError):
        bootstrap.EntryPointOutcome(exit_code=42)


def test_wrapper_prints_a_partial_report_when_the_entry_point_offers_one() -> None:
    stdout, stderr = io.StringIO(), io.StringIO()
    seen: List[IacReviewError] = []

    def partial_report(exc: IacReviewError) -> Optional[Dict[str, Any]]:
        seen.append(exc)
        return {"errors": [exc.to_structured_error("cfn-lint")]}

    def run(args: argparse.Namespace) -> None:
        raise ToolUnavailableError("cfn-lint not found", tool="cfn-lint")

    code = bootstrap.run_entry_point(
        parser=_parser(),
        run=run,
        partial_report=partial_report,
        argv=[],
        stdout=stdout,
        stderr=stderr,
    )

    assert code == exitcodes.TOOL_UNAVAILABLE
    assert len(seen) == 1
    assert '"error_class": "tool_unavailable"' in stdout.getvalue()


def test_wrapper_leaves_stdout_empty_when_partial_report_declines() -> None:
    stdout = io.StringIO()
    code = bootstrap.run_entry_point(
        parser=_parser(),
        run=lambda args: (_ for _ in ()).throw(InvalidArgumentsError("bad")),
        partial_report=lambda exc: None,
        argv=[],
        stdout=stdout,
        stderr=io.StringIO(),
    )
    assert code == exitcodes.INVALID_ARGUMENTS
    assert stdout.getvalue() == ""


def test_wrapper_maps_an_unexpected_exception_to_exit_one() -> None:
    stdout, stderr = io.StringIO(), io.StringIO()

    def run(args: argparse.Namespace) -> None:
        raise RuntimeError("not anticipated")

    code = bootstrap.run_entry_point(
        parser=_parser(),
        run=run,
        argv=[],
        stdout=stdout,
        stderr=stderr,
    )

    assert code == exitcodes.UNEXPECTED
    assert stdout.getvalue() == ""
    text = stderr.getvalue()
    assert "Traceback" in text
    assert "not anticipated" in text


def test_wrapper_treats_a_wrong_run_return_type_as_a_bug() -> None:
    stdout, stderr = io.StringIO(), io.StringIO()
    code = bootstrap.run_entry_point(
        parser=_parser(),
        run=lambda args: "not a report",  # type: ignore[return-value]
        argv=[],
        stdout=stdout,
        stderr=stderr,
    )
    assert code == exitcodes.UNEXPECTED
    assert stdout.getvalue() == ""


def test_missing_required_argument_exits_two_with_empty_stdout() -> None:
    stdout, stderr = io.StringIO(), io.StringIO()

    code = bootstrap.run_entry_point(
        parser=_parser(require_target=True),
        run=lambda args: {"unreachable": True},
        argv=[],
        stdout=stdout,
        stderr=stderr,
    )

    assert code == exitcodes.INVALID_ARGUMENTS
    assert stdout.getvalue() == ""
    assert "usage" in stderr.getvalue()
    assert "--target" in stderr.getvalue()


def test_unknown_flag_exits_two_without_running() -> None:
    stdout, stderr = io.StringIO(), io.StringIO()
    calls: List[str] = []

    code = bootstrap.run_entry_point(
        parser=_parser(),
        run=lambda args: calls.append("run"),
        argv=["--nope"],
        stdout=stdout,
        stderr=stderr,
    )

    assert code == exitcodes.INVALID_ARGUMENTS
    assert calls == []
    assert stdout.getvalue() == ""


def test_abbreviated_flag_is_rejected_rather_than_guessed() -> None:
    parser = _parser()
    parser.add_argument("--rules-dir", action="append")
    stdout, stderr = io.StringIO(), io.StringIO()

    code = bootstrap.run_entry_point(
        parser=parser,
        run=lambda args: None,
        argv=["--rules", "rules"],
        stdout=stdout,
        stderr=stderr,
    )

    assert code == exitcodes.INVALID_ARGUMENTS
    assert stdout.getvalue() == ""


def test_parser_routes_messages_to_the_given_stream() -> None:
    parser = _parser()
    stream = io.StringIO()
    parser.diagnostic_stream = stream

    parser.print_help()
    assert "usage" in stream.getvalue()

    # argparse calls the same hook with an empty message; it must stay a no-op
    # rather than write a stray newline into the diagnostics.
    before = stream.getvalue()
    parser._print_message("")
    assert stream.getvalue() == before


def test_help_exits_zero_and_keeps_stdout_free_of_usage_text() -> None:
    stdout, stderr = io.StringIO(), io.StringIO()

    code = bootstrap.run_entry_point(
        parser=_parser(),
        run=lambda args: {"unreachable": True},
        argv=["--help"],
        stdout=stdout,
        stderr=stderr,
    )

    assert code == exitcodes.OK
    # Requirement 16 AC10: stdout is the machine-readable channel, so even help
    # text goes to stderr.
    assert stdout.getvalue() == ""
    assert "usage" in stderr.getvalue()


def test_verbose_does_not_change_stdout() -> None:
    # A run() written the way the convention requires: --verbose reaches the
    # diagnostics and nothing else. The payload is a function of the input only.
    def run(args: argparse.Namespace) -> Dict[str, Any]:
        bootstrap.verbose_diagnostic(
            "loaded 1 template", verbose=args.verbose, stream=captured_stderr
        )
        return {"findings": [], "summary": {"total": 0}}

    outputs = []
    for argv in ([], ["--verbose"]):
        stdout = io.StringIO()
        captured_stderr = io.StringIO()
        code = bootstrap.run_entry_point(
            parser=_parser(),
            run=run,
            argv=argv,
            stdout=stdout,
            stderr=captured_stderr,
        )
        assert code == exitcodes.OK
        outputs.append((stdout.getvalue(), captured_stderr.getvalue()))

    quiet_stdout, quiet_stderr = outputs[0]
    verbose_stdout, verbose_stderr = outputs[1]

    assert quiet_stdout == verbose_stdout
    assert quiet_stdout != ""
    assert quiet_stderr == ""
    assert "loaded 1 template" in verbose_stderr


def test_wrapper_never_reads_stdin(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    monkeypatch.setattr(sys, "stdin", _RefusingStdin("input that must be ignored"))
    stdout = io.StringIO()

    code = bootstrap.run_entry_point(
        parser=_parser(),
        run=lambda args: {"findings": []},
        argv=[],
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert code == exitcodes.OK
    assert stdout.getvalue() == '{\n  "findings": []\n}\n'


def test_wrapper_defaults_argv_to_sys_argv(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    monkeypatch.setattr(sys, "argv", ["demo.py", "--verbose"])
    seen: List[bool] = []

    code = bootstrap.run_entry_point(
        parser=_parser(),
        run=lambda args: seen.append(args.verbose),
        argv=None,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )

    assert code == exitcodes.OK
    assert seen == [True]


def test_wrapper_defaults_streams_to_sys_streams(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = bootstrap.run_entry_point(
        parser=_parser(),
        run=lambda args: {"findings": []},
        argv=[],
    )
    captured = capsys.readouterr()

    assert code == exitcodes.OK
    assert captured.out == '{\n  "findings": []\n}\n'
    assert captured.err == ""


def test_wrapper_installs_temp_file_cleanup_after_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    order: List[str] = []
    monkeypatch.setattr(
        bootstrap.pathguard,
        "install_temp_file_cleanup",
        lambda: order.append("cleanup"),
    )

    def validate(args: argparse.Namespace) -> None:
        order.append("validate")

    bootstrap.run_entry_point(
        parser=_parser(),
        run=lambda args: order.append("run"),
        validate=validate,
        argv=[],
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )

    assert order == ["validate", "cleanup", "run"]


def test_diagnostic_writes_to_stderr_by_default(
    capsys: pytest.CaptureFixture[str],
) -> None:
    bootstrap.diagnostic("a warning")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "a warning\n"


def test_verbose_diagnostic_is_silent_when_not_verbose() -> None:
    stream = io.StringIO()
    bootstrap.verbose_diagnostic("hidden", verbose=False, stream=stream)
    bootstrap.verbose_diagnostic("shown", verbose=True, stream=stream)
    assert stream.getvalue() == "shown\n"


def test_error_diagnostic_includes_remediation_and_stderr_head() -> None:
    stderr = io.StringIO()

    def run(args: argparse.Namespace) -> None:
        raise ToolUnavailableError(
            "cfn-lint not found on PATH",
            tool="cfn-lint",
            remediation="pip install cfn-lint",
            stderr="line one\nline two",
        )

    bootstrap.run_entry_point(
        parser=_parser(),
        run=run,
        argv=[],
        stdout=io.StringIO(),
        stderr=stderr,
    )

    text = stderr.getvalue()
    assert "pip install cfn-lint" in text
    assert "line one" in text
    assert "line two" in text
