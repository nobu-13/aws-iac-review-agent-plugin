"""Integration tests for the ``cfn-lint-review`` Skill.

Every test here runs ``skills/cfn-lint-review/scripts/run_cfn_lint.py`` as a
subprocess. Calling ``main()`` in-process would be faster, but it would not
exercise what the Skill actually promises: that the script is independently
runnable (Requirement 2 AC6), that its ``sys.path`` bootstrap works from a fresh
interpreter, and that stdout carries JSON and nothing else (Requirement 16 AC10).
Those are properties of the process, not of the function.

The three cases tasks.md requires are, in order:
:func:`test_stdout_is_a_valid_report_whose_findings_pass_schema_validation`,
:func:`test_missing_target_exits_with_invalid_arguments_and_empty_stdout`, and
:func:`test_absent_cfn_lint_exits_tool_unavailable`. The rest cover the flags the
first case depends on and the two "nothing to report" outcomes that are easy to
get wrong.

cfn-lint itself is faked (``tests/fakebin/cfn-lint``) for every test that asserts
on Findings. Real cfn-lint's results depend on its version and on the AWS
resource specification it bundles, so an assertion on them would break on an
upstream release rather than on a change to this plugin. One test does use the
real tool when it happens to be installed, as a smoke test of the whole chain;
it is skipped otherwise.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import pytest

from iacreview import exitcodes
from iacreview.cfnlint import SOURCE_NAME
from iacreview.finding import from_dict, validate
from iacreview.report import REPORT_KEYS, SCHEMA_VERSION

SCRIPT = Path("skills") / "cfn-lint-review" / "scripts" / "run_cfn_lint.py"

# A template that exists in the repository and parses. Which template it is does
# not matter for the faked cases: the fake ignores its input and prints the
# configured payload.
TEMPLATE = Path("tests") / "fixtures" / "valid" / "minimal_compliant_template.yaml"

TIMEOUT_S = 60


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _results(template_file: str) -> List[Dict[str, Any]]:
    """One cfn-lint result per level, all attributed to ``template_file``.

    Three levels rather than one, because the level is what drives the
    FindingType and Severity mapping of Requirement 4 AC3-AC7; a payload with
    only Errors would leave two thirds of that mapping unexercised end to end.
    """
    return [
        {
            "Filename": template_file,
            "Level": "Error",
            "Location": {
                "Start": {"LineNumber": 14, "ColumnNumber": 3},
                "Path": ["Resources", "DataBucket", "Properties", "BucketName"],
            },
            "Message": "Property BucketName should be of type String",
            "Rule": {
                "Id": "E3002",
                "ShortDescription": "Resource properties are invalid",
                "Description": "Making sure resource properties are configured",
                "Source": "https://example.invalid/rules#E3002",
            },
        },
        {
            "Filename": template_file,
            "Level": "Warning",
            "Location": {
                "Start": {"LineNumber": 13, "ColumnNumber": 3},
                "Path": ["Resources", "DataBucket"],
            },
            "Message": "Specifying an explicit name prevents replacement updates",
            "Rule": {
                "Id": "W3011",
                "ShortDescription": "Check DeletionPolicy on resources",
                "Description": "Ensure resources have a DeletionPolicy",
                "Source": "https://example.invalid/rules#W3011",
            },
        },
        {
            "Filename": template_file,
            "Level": "Informational",
            "Location": {
                "Start": {"LineNumber": 13, "ColumnNumber": 3},
                "Path": ["Resources", "DataBucket"],
            },
            "Message": "Consider adding a DeletionPolicy to this stateful resource",
            "Rule": {
                "Id": "I3013",
                "ShortDescription": "Check stateful resources have a DeletionPolicy",
                "Description": "The default action when replacing is to delete",
                "Source": "https://example.invalid/rules#I3013",
            },
        },
    ]


#: Configuration file the fake cfn-lint reads, and the argv log it writes,
#: both inside the directory handed to the script as ``TMPDIR``. Named here
#: rather than inlined so a rename of either side fails in one place.
FAKE_CONFIG = "fake-cfn-lint.json"
FAKE_ARGV_LOG = "fake-cfn-lint-argv.json"


def _configure_fake(tmp_path: Path, **config: Any) -> Dict[str, str]:
    """Write the fake tool's configuration and return the env that reveals it.

    The configuration travels in a file rather than in environment variables
    because :mod:`iacreview.proc` passes children an environment allowlist, so
    that AWS credentials cannot reach a static analyzer. ``TMPDIR`` is on that
    allowlist; ``FAKE_CFN_LINT_*`` would be dropped and never arrive.
    """
    (tmp_path / FAKE_CONFIG).write_text(json.dumps(config), encoding="utf-8")
    return {"TMPDIR": str(tmp_path)}


def _fake_tool_path(fakebin_dir: Path) -> List[Path]:
    """``PATH`` entries that resolve ``cfn-lint`` to the fake and nothing else.

    The interpreter's own directory is included because the fake is a Python
    script with a ``#!/usr/bin/env python3`` shebang: with a ``PATH`` holding only
    ``fakebin``, ``env`` cannot find ``python3`` and the fake exits 127 before
    running a line. ``fakebin`` comes first, so a real cfn-lint installed
    alongside the interpreter is still shadowed.
    """
    return [fakebin_dir, Path(sys.executable).parent]


def _run(
    plugin_root: Path,
    arguments: Sequence[str],
    *,
    path_entries: Optional[Sequence[Path]] = None,
    env_extra: Optional[Dict[str, str]] = None,
) -> "subprocess.CompletedProcess[str]":
    """Run the Skill script from the workspace root.

    Args:
        plugin_root: Workspace root, and the process's working directory. The
            script derives its containment root from the cwd, so running from
            here is what makes a repository-relative ``--target`` legal.
        arguments: Arguments after the script path.
        path_entries: Directories forming ``PATH``. ``None`` inherits the
            caller's. An empty sequence yields an empty ``PATH``, which is how
            the "tool not installed" case is produced without uninstalling
            anything.
        env_extra: Extra environment variables, for configuring the fake tool.

    Returns:
        The completed process, with text stdout and stderr.
    """
    env = dict(os.environ)
    if path_entries is not None:
        env["PATH"] = os.pathsep.join(str(entry) for entry in path_entries)
    if env_extra:
        env.update(env_extra)

    return subprocess.run(
        [sys.executable, str(SCRIPT), *arguments],
        cwd=str(plugin_root),
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=TIMEOUT_S,
    )


def _report(completed: "subprocess.CompletedProcess[str]") -> Dict[str, Any]:
    """Parse the process's stdout as a Review_Report, failing the test if it is not one."""
    try:
        payload = json.loads(completed.stdout)
    except ValueError as exc:  # pragma: no cover - only on a failing assertion
        raise AssertionError(
            "stdout is not valid JSON ({0}); stderr was:\n{1}".format(
                exc, completed.stderr
            )
        )
    assert isinstance(payload, dict)
    assert tuple(sorted(payload)) == tuple(sorted(REPORT_KEYS))
    assert payload["schema_version"] == SCHEMA_VERSION
    return payload


# ---------------------------------------------------------------------------
# (a) A report whose Findings satisfy the Finding schema
# ---------------------------------------------------------------------------


def test_stdout_is_a_valid_report_whose_findings_pass_schema_validation(
    plugin_root: Path, fakebin_dir: Path, tmp_path: Path
) -> None:
    env_extra = _configure_fake(
        tmp_path, results_text=json.dumps(_results(TEMPLATE.as_posix()))
    )

    completed = _run(
        plugin_root,
        ["--target", TEMPLATE.as_posix()],
        path_entries=_fake_tool_path(fakebin_dir),
        env_extra=env_extra,
    )

    # Findings exist, so this is a successful review, not a failed one.
    assert completed.returncode == exitcodes.OK, completed.stderr
    report = _report(completed)

    assert report["errors"] == []
    assert report["sources_enabled"] == [SOURCE_NAME]
    assert report["target"]["files"] == [TEMPLATE.as_posix()]
    assert report["tools"] == [
        {"name": "cfn-lint", "available": True, "version": "1.22.0"}
    ]

    # from_dict is the round trip: it rejects a payload the schema does not
    # describe, and validate then rejects a described payload with an illegal
    # value. Both have to pass for a consumer to be able to read the report.
    assert len(report["findings"]) == len(_results(TEMPLATE.as_posix()))
    for payload in report["findings"]:
        validate(from_dict(payload))

    ids = [f["ID"] for f in report["findings"]]
    assert ids == list(range(1, len(ids) + 1))
    # Source is a list: a Finding merged from several Sources names all of them.
    # Only one Source ran here, so every list holds exactly cfn-lint.
    assert all(f["Source"] == [SOURCE_NAME] for f in report["findings"])
    assert report["summary"]["total"] == len(ids)
    assert report["summary"]["passed_all_checks"] is False


def test_report_maps_each_cfn_lint_level_onto_its_finding_type(
    plugin_root: Path, fakebin_dir: Path, tmp_path: Path
) -> None:
    """Requirement 4 AC3, AC6, AC7, end to end through the script."""
    env_extra = _configure_fake(
        tmp_path, results_text=json.dumps(_results(TEMPLATE.as_posix()))
    )

    completed = _run(
        plugin_root,
        ["--target", TEMPLATE.as_posix()],
        path_entries=_fake_tool_path(fakebin_dir),
        env_extra=env_extra,
    )

    report = _report(completed)
    by_rule = {
        f["Evidence"][0]["RuleId"]: (f["FindingType"], f["Severity"])
        for f in report["findings"]
    }
    assert by_rule["W3011"] == ("BestPractice", "MEDIUM")
    assert by_rule["I3013"] == ("Informational", "LOW")
    # E3002 is an Error, so HIGH unless the mapping file marks it security
    # relevant or deployment blocking; either way it is not MEDIUM or LOW.
    assert by_rule["E3002"][1] in {"HIGH", "CRITICAL"}


# ---------------------------------------------------------------------------
# (b) A missing --target
# ---------------------------------------------------------------------------


def test_missing_target_exits_with_invalid_arguments_and_empty_stdout(
    plugin_root: Path, fakebin_dir: Path
) -> None:
    completed = _run(plugin_root, [], path_entries=_fake_tool_path(fakebin_dir))

    assert completed.returncode == exitcodes.INVALID_ARGUMENTS
    # Empty, not "empty apart from usage text": argparse prints usage on stdout
    # by default, and EntryPointParser exists to prevent exactly that.
    assert completed.stdout == ""
    assert "--target" in completed.stderr


def test_unknown_flag_exits_with_invalid_arguments_and_empty_stdout(
    plugin_root: Path, fakebin_dir: Path
) -> None:
    completed = _run(
        plugin_root,
        ["--target", TEMPLATE.as_posix(), "--rules-dir", "rules"],
        path_entries=_fake_tool_path(fakebin_dir),
    )

    assert completed.returncode == exitcodes.INVALID_ARGUMENTS
    assert completed.stdout == ""


# ---------------------------------------------------------------------------
# (c) cfn-lint absent from PATH
# ---------------------------------------------------------------------------


def test_absent_cfn_lint_exits_tool_unavailable(plugin_root: Path) -> None:
    completed = _run(
        plugin_root, ["--target", TEMPLATE.as_posix()], path_entries=[]
    )

    assert completed.returncode == exitcodes.TOOL_UNAVAILABLE

    # The report is still printed: which tool was missing and how to install it
    # is the answer to the request (Requirement 4 AC10), not a lack of one.
    report = _report(completed)
    assert report["findings"] == []
    assert len(report["errors"]) == 1
    error = report["errors"][0]
    assert error["error_class"] == "tool_unavailable"
    assert error["tool"] == "cfn-lint"
    assert error["required_min_version"] == "1.0.0"
    assert "pip install cfn-lint" in "{0} {1}".format(
        error["message"], error["remediation"]
    )
    assert report["tools"] == [
        {"name": "cfn-lint", "available": False, "version": None}
    ]


# ---------------------------------------------------------------------------
# The invocation the mapping above depends on
# ---------------------------------------------------------------------------


def test_cfn_lint_is_invoked_with_json_output_and_informational_rules(
    plugin_root: Path, fakebin_dir: Path, tmp_path: Path
) -> None:
    """Requirement 4 AC1 (``-f json``) and AC8 (``-c I``).

    Asserted on the command line the script actually built, not on
    ``build_argv``: a unit test of the latter cannot catch an entry point that
    calls the tool by another route.
    """
    completed = _run(
        plugin_root,
        ["--target", TEMPLATE.as_posix()],
        path_entries=_fake_tool_path(fakebin_dir),
        env_extra=_configure_fake(tmp_path, log_argv=True),
    )
    assert completed.returncode == exitcodes.OK, completed.stderr

    # The log holds the last invocation, which is the review; the --version
    # probe came first.
    argv_log = tmp_path / FAKE_ARGV_LOG
    arguments = json.loads(argv_log.read_text(encoding="utf-8"))
    assert arguments[:5] == ["-f", "json", "-c", "I", "--"]
    assert arguments[5].endswith(TEMPLATE.name)


def test_verbose_changes_stderr_but_not_stdout(
    plugin_root: Path, fakebin_dir: Path, tmp_path: Path
) -> None:
    """Requirement 16 AC11: ``--verbose`` widens diagnostics only."""
    env_extra = _configure_fake(
        tmp_path, results_text=json.dumps(_results(TEMPLATE.as_posix()))
    )
    arguments = ["--target", TEMPLATE.as_posix()]

    quiet = _run(
        plugin_root, arguments, path_entries=_fake_tool_path(fakebin_dir), env_extra=env_extra
    )
    loud = _run(
        plugin_root,
        [*arguments, "--verbose"],
        path_entries=_fake_tool_path(fakebin_dir),
        env_extra=env_extra,
    )

    assert quiet.returncode == loud.returncode == exitcodes.OK
    assert quiet.stdout == loud.stdout
    assert len(loud.stderr) > len(quiet.stderr)
    # The counters cfn-lint can honestly report go to stderr, not into the
    # report: rules_triggered is derivable from what fired, rules_evaluated is
    # not (see SKILL.md, Limitations).
    assert "rules_triggered=3" in loud.stderr
    assert "rules_triggered" not in quiet.stdout


# ---------------------------------------------------------------------------
# Nothing to report, and nothing reviewable
# ---------------------------------------------------------------------------


def test_clean_template_reports_an_empty_finding_list_and_exits_zero(
    plugin_root: Path, fakebin_dir: Path
) -> None:
    """Requirement 4 AC13: zero violations is a successful review."""
    completed = _run(
        plugin_root,
        ["--target", TEMPLATE.as_posix()],
        path_entries=_fake_tool_path(fakebin_dir),
    )

    assert completed.returncode == exitcodes.OK, completed.stderr
    report = _report(completed)
    assert report["findings"] == []
    assert report["errors"] == []
    assert report["sources_enabled"] == [SOURCE_NAME]
    assert report["summary"]["total"] == 0
    assert report["summary"]["passed_all_checks"] is True


def test_template_without_resources_exits_no_reviewable_template(
    plugin_root: Path, fakebin_dir: Path
) -> None:
    target = Path("tests") / "fixtures" / "invalid" / "no_resources.yaml"

    completed = _run(
        plugin_root,
        ["--target", target.as_posix()],
        path_entries=_fake_tool_path(fakebin_dir),
    )

    assert completed.returncode == exitcodes.NO_REVIEWABLE_TEMPLATE
    report = _report(completed)
    assert report["findings"] == []
    assert [e["error_class"] for e in report["errors"]] == [
        "no_reviewable_template"
    ]
    assert target.name in report["errors"][0]["message"]


def test_unparsable_template_exits_parse_failure_with_a_partial_report(
    plugin_root: Path, fakebin_dir: Path
) -> None:
    target = Path("tests") / "fixtures" / "invalid" / "malformed_syntax.yaml"

    completed = _run(
        plugin_root,
        ["--target", target.as_posix()],
        path_entries=_fake_tool_path(fakebin_dir),
    )

    assert completed.returncode == exitcodes.PARSE_FAILURE
    report = _report(completed)
    assert [e["error_class"] for e in report["errors"]] == ["parse_failure"]


def test_target_outside_the_workspace_exits_path_violation_with_empty_stdout(
    plugin_root: Path, fakebin_dir: Path, tmp_path: Path
) -> None:
    """Requirement 9 AC5 / Requirement 15 AC3, refused before anything is read."""
    outside = tmp_path / "template.yaml"
    shutil.copyfile(plugin_root / TEMPLATE, outside)

    completed = _run(
        plugin_root, ["--target", str(outside)], path_entries=_fake_tool_path(fakebin_dir)
    )

    assert completed.returncode == exitcodes.PATH_VIOLATION
    # No report: the refusal happened before any template was read, so there is
    # nothing a report could describe (design.md, Failure mode matrix).
    assert completed.stdout == ""


def test_target_with_a_shell_metacharacter_is_rejected(
    plugin_root: Path, fakebin_dir: Path
) -> None:
    completed = _run(
        plugin_root,
        ["--target", "{0}; rm -rf /".format(TEMPLATE.as_posix())],
        path_entries=_fake_tool_path(fakebin_dir),
    )

    assert completed.returncode == exitcodes.INVALID_ARGUMENTS
    assert completed.stdout == ""


def test_crashing_cfn_lint_exits_tool_execution_failure(
    plugin_root: Path, fakebin_dir: Path, tmp_path: Path
) -> None:
    """Requirement 4 AC12: exit 1 is a crash, not a finding count."""
    completed = _run(
        plugin_root,
        ["--target", TEMPLATE.as_posix()],
        path_entries=_fake_tool_path(fakebin_dir),
        env_extra=_configure_fake(
            tmp_path,
            exit_code=1,
            results_text="",
            stderr="Traceback (most recent call last):\nRuntimeError: boom\n",
        ),
    )

    assert completed.returncode == exitcodes.TOOL_EXECUTION_FAILURE
    report = _report(completed)
    assert [e["error_class"] for e in report["errors"]] == ["tool_execution"]
    error = report["errors"][0]
    assert error["tool"] == "cfn-lint"
    assert error["exit_code"] == 1
    # Bounded quotation of the tool's stderr (Requirement 15 AC7).
    assert 0 < len(error["stderr_head"]) <= 5


# ---------------------------------------------------------------------------
# Real cfn-lint, when it is installed
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    shutil.which("cfn-lint") is None, reason="cfn-lint is not installed"
)
def test_real_cfn_lint_produces_a_valid_report(plugin_root: Path) -> None:
    """The task's completion condition, against the real tool.

    Asserts on the report's shape and on schema validity of whatever Findings
    the installed version produces -- never on which rules fired, which is the
    tool's business and changes between releases.
    """
    completed = _run(plugin_root, ["--target", TEMPLATE.as_posix()])

    assert completed.returncode == exitcodes.OK, completed.stderr
    report = _report(completed)
    assert report["errors"] == []
    assert report["target"]["files"] == [TEMPLATE.as_posix()]
    for payload in report["findings"]:
        validate(from_dict(payload))
