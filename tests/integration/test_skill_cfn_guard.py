"""Integration checks for the ``cfn-guard-review`` Skill entry point.

The script is exercised the way a host agent runs it: as a subprocess, with a
working directory that is the workspace root, reading only argv and writing JSON
on stdout. Nothing is imported from it, so the ``sys.path`` bootstrap, the
argument validation and the exit codes are all covered as they will actually
behave.

Four cases, matching the completion condition of Task 18.3:

(a) A default run against a real template produces a valid Review_Report whose
    Findings all satisfy the Finding schema, and reports the number of rules it
    evaluated (Requirement 5 AC4).
(b) Two ``--rules-dir`` options given in either order produce byte-identical
    stdout (design.md O-10, Requirement 10 AC3).
(c) A ``--rules-dir`` outside the workspace is refused with exit 7 and an empty
    stdout (Requirement 15 AC3).
(d) cfn-guard absent from ``PATH`` is reported with exit 5 and a report carrying
    ``errors[]`` (Requirement 5 AC5).

Cases (a) and (b) need the real cfn-guard and are skipped when it is not
installed: what they check is the behaviour of the tool's own output, which a
fake cannot stand in for. Cases (c) and (d) never reach the tool, so they always
run.
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
from iacreview.finding import from_dict
from iacreview.report import REPORT_KEYS

#: The entry point under test, relative to the plugin root.
SCRIPT = "skills/cfn-guard-review/scripts/run_cfn_guard.py"

#: A template the bundled rules have something to say about.
VIOLATING_TEMPLATE = "tests/fixtures/tool_output/cfnguard_violations_input.yaml"

#: A template that satisfies the bundled rules.
COMPLIANT_TEMPLATE = "tests/fixtures/valid/minimal_compliant_template.yaml"

#: Extra stdout key this Skill adds beside the Review_Report envelope.
STATS_KEY = "stats"

requires_cfn_guard = pytest.mark.skipif(
    shutil.which("cfn-guard") is None,
    reason="cfn-guard is not installed; the end-to-end run cannot be made here",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def run_skill(
    plugin_root: Path,
    argv: Sequence[str],
    *,
    cwd: Optional[Path] = None,
    path_env: Optional[str] = None,
) -> subprocess.CompletedProcess:
    """Run the entry point as a subprocess and return the completed process.

    Args:
        plugin_root: The plugin root, used to locate the script.
        argv: Arguments after the script name.
        cwd: Working directory, which is the workspace root the script contains
            paths within. Defaults to the plugin root.
        path_env: Replacement for ``PATH`` in the child environment. Used to hide
            cfn-guard; ``None`` inherits the caller's ``PATH``.

    Returns:
        The completed process, with text-decoded stdout and stderr.
    """
    env = dict(os.environ)
    if path_env is not None:
        env["PATH"] = path_env
    return subprocess.run(
        [sys.executable, str(plugin_root / SCRIPT), *argv],
        cwd=str(plugin_root if cwd is None else cwd),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=180,
    )


def write_template(directory: Path) -> Path:
    """Write a template that violates two bundled rules, and return its path."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "template.yaml"
    path.write_text(
        "Resources:\n"
        "  PlainBucket:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Properties:\n"
        "      BucketName: plain-bucket\n",
        encoding="utf-8",
    )
    return path


def write_rule_dir(directory: Path, rule_name: str, property_name: str) -> Path:
    """Write a one-rule category directory with its ``_meta.json`` sidecar."""
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "{0}.guard".format(rule_name)).write_text(
        "let buckets = Resources.*[ Type == 'AWS::S3::Bucket' ]\n"
        "\n"
        "rule {rule} when %buckets !empty {{\n"
        "  %buckets.Properties.{prop} exists\n"
        "    << The {prop} property is required by a local policy. "
        "Add it to the bucket. >>\n"
        "}}\n".format(rule=rule_name, prop=property_name),
        encoding="utf-8",
    )
    (directory / "_meta.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "category": directory.name,
                "normalized_category": "Tagging",
                "default": {"finding_type": "BestPractice", "severity": "LOW"},
                "rules": {rule_name: {"severity": "LOW"}},
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return directory


def load_report(completed: subprocess.CompletedProcess) -> Dict[str, Any]:
    """Parse the process stdout as JSON, failing the test with its stderr."""
    assert completed.stdout, "stdout was empty; stderr was: {0}".format(
        completed.stderr
    )
    return json.loads(completed.stdout)


def error_classes(report: Dict[str, Any]) -> List[str]:
    return [str(entry["error_class"]) for entry in report["errors"]]


# ---------------------------------------------------------------------------
# (a) A default run produces a valid report
# ---------------------------------------------------------------------------


@requires_cfn_guard
def test_default_run_produces_a_valid_review_report(plugin_root: Path) -> None:
    completed = run_skill(plugin_root, ["--target", VIOLATING_TEMPLATE])
    report = load_report(completed)

    assert completed.returncode == exitcodes.OK
    # Findings are not a failure, and the report is the only thing on stdout.
    assert sorted(report) == sorted(REPORT_KEYS + (STATS_KEY,))
    assert report["sources_enabled"] == ["cfn-guard"]
    assert report["target"]["files"] == [VIOLATING_TEMPLATE]
    assert report["errors"] == []

    # Every Finding satisfies the schema it claims to follow: from_dict validates.
    findings = report["findings"]
    assert findings
    for entry in findings:
        from_dict(entry)
    assert [entry["ID"] for entry in findings] == list(range(1, len(findings) + 1))
    # Source is a list: a merged Finding can name several. Here there is one.
    assert {name for entry in findings for name in entry["Source"]} == {"cfn-guard"}
    assert report["summary"]["total"] == len(findings)
    assert report["summary"]["passed_all_checks"] is False
    # Requirement 16 AC11: nothing environment-dependent on stdout.
    assert str(plugin_root) not in completed.stdout


@requires_cfn_guard
def test_a_compliant_template_reports_the_rules_it_evaluated(
    plugin_root: Path,
) -> None:
    """Requirement 5 AC4: all rules passed, with the count of rules evaluated."""
    completed = run_skill(plugin_root, ["--target", COMPLIANT_TEMPLATE])
    report = load_report(completed)

    assert completed.returncode == exitcodes.OK
    assert report["findings"] == []
    assert report["errors"] == []
    assert report["summary"]["passed_all_checks"] is True

    stats = report[STATS_KEY][COMPLIANT_TEMPLATE]
    assert stats["rules_evaluated"] >= 1
    assert stats["rules_passed"] >= 1
    assert stats["violations_parsed"] == 0
    assert report["tools"] == [
        {"name": "cfn-guard", "available": True, "version": stats["tool_version"]}
    ]


@requires_cfn_guard
def test_verbose_does_not_change_stdout(plugin_root: Path) -> None:
    quiet = run_skill(plugin_root, ["--target", COMPLIANT_TEMPLATE])
    verbose = run_skill(plugin_root, ["--target", COMPLIANT_TEMPLATE, "--verbose"])

    assert quiet.stdout == verbose.stdout
    assert quiet.stderr == ""
    # --verbose widens stderr only (Requirement 16 AC11).
    assert COMPLIANT_TEMPLATE in verbose.stderr


# ---------------------------------------------------------------------------
# (b) --rules-dir order does not affect the output
# ---------------------------------------------------------------------------


@requires_cfn_guard
def test_two_rules_dirs_in_either_order_produce_identical_stdout(
    plugin_root: Path, tmp_path: Path
) -> None:
    """design.md O-10: the order of ``--rules-dir`` is not part of the input.

    The two rule names sort in the opposite order to their directories, so output
    that followed the command line would come out reordered.
    """
    workspace = tmp_path / "workspace"
    template = write_template(workspace / "templates")
    write_rule_dir(workspace / "policies" / "aaa", "zzz_local_rule", "Tags")
    write_rule_dir(
        workspace / "policies" / "zzz", "aaa_local_rule", "VersioningConfiguration"
    )

    relative_template = str(template.relative_to(workspace))
    forward = run_skill(
        plugin_root,
        [
            "--target",
            relative_template,
            "--rules-dir",
            "policies/aaa",
            "--rules-dir",
            "policies/zzz",
        ],
        cwd=workspace,
    )
    backward = run_skill(
        plugin_root,
        [
            "--target",
            relative_template,
            "--rules-dir",
            "policies/zzz",
            "--rules-dir",
            "policies/aaa",
        ],
        cwd=workspace,
    )

    assert forward.returncode == backward.returncode == exitcodes.OK
    assert forward.stdout == backward.stdout

    report = json.loads(forward.stdout)
    # Both added rules fired, so the comparison covers rules whose order could
    # have differed, not an empty findings list.
    # Every Evidence entry, not just the first: Findings of one category on one
    # resource are merged, so both local rules can end up on the same Finding.
    rule_ids = [
        evidence["RuleId"]
        for entry in report["findings"]
        for evidence in entry["Evidence"]
    ]
    assert "aaa_local_rule" in rule_ids
    assert "zzz_local_rule" in rule_ids
    # The bundled rules are evaluated as well: --rules-dir adds, it does not
    # replace (Requirement 10 AC1).
    assert "s3_bucket_encryption" in rule_ids


# ---------------------------------------------------------------------------
# (c) A rule directory outside the workspace is refused
# ---------------------------------------------------------------------------


def test_rules_dir_outside_the_workspace_exits_seven(
    plugin_root: Path, tmp_path: Path
) -> None:
    workspace = tmp_path / "workspace"
    template = write_template(workspace / "templates")
    outside = write_rule_dir(tmp_path / "outside", "local_rule", "Tags")

    completed = run_skill(
        plugin_root,
        [
            "--target",
            str(template.relative_to(workspace)),
            "--rules-dir",
            str(outside),
        ],
        cwd=workspace,
    )

    assert completed.returncode == exitcodes.PATH_VIOLATION
    # Refused before anything ran, so there is no partial report to print.
    assert completed.stdout == ""
    assert str(outside) in completed.stderr


def test_rules_dir_escaping_through_parent_segments_exits_seven(
    plugin_root: Path, tmp_path: Path
) -> None:
    workspace = tmp_path / "workspace"
    template = write_template(workspace / "templates")
    write_rule_dir(tmp_path / "outside", "local_rule", "Tags")

    completed = run_skill(
        plugin_root,
        [
            "--target",
            str(template.relative_to(workspace)),
            "--rules-dir",
            "../outside",
        ],
        cwd=workspace,
    )

    assert completed.returncode == exitcodes.PATH_VIOLATION
    assert completed.stdout == ""


def test_unparsable_target_exits_four_with_a_partial_report(plugin_root: Path) -> None:
    """The failure matrix asks for ``errors[]`` on stdout, not an empty stdout."""
    completed = run_skill(
        plugin_root, ["--target", "tests/fixtures/invalid/malformed_syntax.yaml"]
    )
    report = load_report(completed)

    assert completed.returncode == exitcodes.PARSE_FAILURE
    assert error_classes(report) == ["parse_failure"]
    assert report["findings"] == []
    # Requirement 16 AC11: the message names the file as the report does, so no
    # host-specific path reaches stdout.
    assert str(plugin_root) not in completed.stdout


def test_a_file_without_resources_exits_eight(plugin_root: Path) -> None:
    completed = run_skill(
        plugin_root, ["--target", "tests/fixtures/invalid/no_resources.yaml"]
    )
    report = load_report(completed)

    assert completed.returncode == exitcodes.NO_REVIEWABLE_TEMPLATE
    assert error_classes(report) == ["no_reviewable_template"]
    assert "tests/fixtures/invalid/no_resources.yaml" in str(
        report["errors"][0]["message"]
    )


def test_missing_target_exits_two_with_empty_stdout(plugin_root: Path) -> None:
    completed = run_skill(plugin_root, [])

    assert completed.returncode == exitcodes.INVALID_ARGUMENTS
    assert completed.stdout == ""
    assert "--target" in completed.stderr


# ---------------------------------------------------------------------------
# (d) cfn-guard absent from PATH
# ---------------------------------------------------------------------------


def test_absent_cfn_guard_exits_five_and_reports_it(
    plugin_root: Path, tmp_path: Path
) -> None:
    """Requirement 5 AC5: name the tool, point at its docs, do not crash."""
    empty_bin = tmp_path / "bin"
    empty_bin.mkdir()

    completed = run_skill(
        plugin_root,
        ["--target", COMPLIANT_TEMPLATE],
        path_env=str(empty_bin),
    )
    report = load_report(completed)

    assert completed.returncode == exitcodes.TOOL_UNAVAILABLE
    assert error_classes(report) == ["tool_unavailable"]

    error = report["errors"][0]
    assert error["source"] == "cfn-guard"
    assert error["tool"] == "cfn-guard"
    assert error["required_min_version"] == "3.0.0"
    assert "cloudformation-guard" in str(error["remediation"])

    # The report is still well formed: the tool is listed as unavailable, no
    # findings are claimed, and no rule count is invented.
    assert report["findings"] == []
    assert report["tools"] == [
        {"name": "cfn-guard", "available": False, "version": None}
    ]
    assert report[STATS_KEY] == {}
    assert report["summary"]["passed_all_checks"] is True
