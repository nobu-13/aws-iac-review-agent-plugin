"""Integration checks for the ``iac-review`` Skill entry point.

The orchestrator is exercised the way a host agent runs it: as a subprocess, from
a working directory that is the workspace root, reading only argv and writing one
JSON document on stdout. Nothing is imported from the script for those cases, so
the ``sys.path`` bootstrap, the argument validation and the exit codes are all
covered as they will actually behave.

Six cases, matching the completion condition of Task 18.6:

(a) Every enabled Source succeeds: the report is a valid Review_Report whose
    Findings all satisfy the Finding schema and whose IDs run from 1
    (Requirement 7 AC1, Requirement 2 AC5).
(b) One Source fails: its failure is one ``errors[]`` entry, the other Sources'
    Findings are still in the report, and the exit code is 0
    (Requirement 2 AC10).
(c) Every Source fails: the exit code is non-zero, because nothing was reviewed
    by anything (design.md, Exit code).
(d) A directory target separates standalone from synthesized Templates
    (Requirement 8 AC10).
(e) Without ``--confirm-cdk-synth`` no ``cdk`` process is started
    (Requirement 8 AC3, Property 25).
(f) ``--agent-findings`` are merged and the whole report is numbered
    sequentially.

cfn-lint is faked (``tests/fakebin/cfn-lint``) wherever a test asserts on its
results or drives it into a failure: real cfn-lint's findings depend on its
version and on the AWS resource specification it bundles, so asserting on them
would break on an upstream release rather than on a change here. cfn-guard is
used for real where a test needs a second Source that produces Findings, and
those tests skip when it is not installed. The IAM Source needs no tool and is
therefore what the tool-independent cases rely on.

Case (e) is the one test that calls ``main()`` in-process. It has to: the
assertion is that :func:`iacreview.proc.run` never receives a ``cdk`` command
line, which is only observable from inside the process that would have made the
call. It is complemented by an out-of-process assertion that nothing was
synthesized.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import types
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import pytest

from iacreview import exitcodes, proc
from iacreview.finding import from_dict
from iacreview.report import REPORT_KEYS, SCHEMA_VERSION

#: The entry point under test, relative to the plugin root.
SCRIPT = Path("skills") / "iac-review" / "scripts" / "run_iac_review.py"

#: Configuration file the fake cfn-lint reads, inside the directory handed to the
#: script as ``TMPDIR`` (see ``tests/fakebin/cfn-lint``).
FAKE_CONFIG = "fake-cfn-lint.json"

#: A template in the repository whose IAM policies the deterministic detectors
#: report on. Used where a test needs Findings without needing any tool.
IAM_TEMPLATE = "tests/fixtures/security/iam_dangerous_policies.yaml"

TIMEOUT_S = 180

requires_cfn_guard = pytest.mark.skipif(
    shutil.which("cfn-guard") is None,
    reason="cfn-guard is not installed; this case needs a second real source",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def run_skill(
    plugin_root: Path,
    arguments: Sequence[str],
    *,
    cwd: Optional[Path] = None,
    path_entries: Optional[Sequence[Path]] = None,
    env_extra: Optional[Dict[str, str]] = None,
) -> "subprocess.CompletedProcess[str]":
    """Run the entry point as a subprocess and return the completed process.

    Args:
        plugin_root: The plugin root, used to locate the script.
        arguments: Arguments after the script path.
        cwd: Working directory, which is the workspace root the script contains
            paths within. Defaults to the plugin root.
        path_entries: Directories forming ``PATH``. ``None`` inherits the
            caller's; an empty sequence produces the "no tool installed"
            environment without uninstalling anything.
        env_extra: Extra environment variables, for configuring the fake tool.

    Returns:
        The completed process, with text-decoded stdout and stderr.
    """
    env = dict(os.environ)
    if path_entries is not None:
        env["PATH"] = os.pathsep.join(str(entry) for entry in path_entries)
    if env_extra:
        env.update(env_extra)

    return subprocess.run(
        [sys.executable, str(plugin_root / SCRIPT), *arguments],
        cwd=str(plugin_root if cwd is None else cwd),
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=TIMEOUT_S,
    )


def load_report(completed: "subprocess.CompletedProcess[str]") -> Dict[str, Any]:
    """Parse the process stdout as JSON, failing the test with its stderr."""
    assert completed.stdout, "stdout was empty; stderr was: {0}".format(
        completed.stderr
    )
    return json.loads(completed.stdout)


def error_classes(report: Dict[str, Any]) -> List[str]:
    return [str(entry["error_class"]) for entry in report["errors"]]


def sources_of(report: Dict[str, Any]) -> List[str]:
    """Every Source named by any Finding, de-duplicated and sorted."""
    return sorted({name for f in report["findings"] for name in f["Source"]})


def fake_lint_path(fakebin_dir: Path, *, with_cfn_guard: bool = False) -> List[Path]:
    """``PATH`` entries resolving ``cfn-lint`` to the fake, and nothing else.

    The interpreter's directory is included because the fake is a Python script
    with a ``#!/usr/bin/env python3`` shebang: with a ``PATH`` holding only
    ``fakebin``, ``env`` cannot find ``python3``. ``fakebin`` comes first, so a
    real cfn-lint installed next to the interpreter is shadowed.
    """
    entries = [fakebin_dir, Path(sys.executable).parent]
    if with_cfn_guard:
        guard = shutil.which("cfn-guard")
        assert guard is not None, "requires_cfn_guard should have skipped this test"
        entries.append(Path(guard).parent)
    return entries


def configure_fake_lint(directory: Path, **config: Any) -> Dict[str, str]:
    """Write the fake cfn-lint configuration and return the env revealing it.

    The configuration travels in a file rather than in environment variables
    because :mod:`iacreview.proc` hands children an environment allowlist, so
    that AWS credentials cannot reach a static analyzer. ``TMPDIR`` is on that
    allowlist; an invented variable would be dropped and never arrive.
    """
    (directory / FAKE_CONFIG).write_text(json.dumps(config), encoding="utf-8")
    return {"TMPDIR": str(directory)}


def lint_results(template_file: str) -> List[Dict[str, Any]]:
    """One cfn-lint Warning result attributed to ``template_file``."""
    return [
        {
            "Filename": template_file,
            "Level": "Warning",
            "Location": {
                "Start": {"LineNumber": 3, "ColumnNumber": 5},
                "Path": ["Resources", "PlainBucket", "Properties", "BucketName"],
            },
            "Message": "Specifying an explicit name prevents replacement updates",
            "Rule": {
                "Id": "W3011",
                "ShortDescription": "Check DeletionPolicy on resources",
                "Description": "Ensure resources have a DeletionPolicy",
                "Source": "https://example.invalid/rules#W3011",
            },
        }
    ]


#: A template that gives each Source something to report: a bare bucket for the
#: cfn-guard rules, and a role granting everything for the IAM detectors.
MIXED_TEMPLATE = """\
Resources:
  PlainBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: plain-bucket
  AdminRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: ec2.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: Everything
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action: "*"
                Resource: "*"
"""

#: A minimal reviewable template, for cases that only need a file to exist.
SIMPLE_TEMPLATE = '{"Resources": {"Queue": {"Type": "AWS::SQS::Queue"}}}\n'


def make_workspace(tmp_path: Path, **files: str) -> Path:
    """Create a workspace directory holding ``files`` (path -> content)."""
    workspace = tmp_path / "workspace"
    for relative, content in files.items():
        path = workspace / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    workspace.mkdir(parents=True, exist_ok=True)
    return workspace


@pytest.fixture(scope="session")
def script_module(plugin_root: Path) -> types.ModuleType:
    """The entry point imported as a module, for the in-process case (e)."""
    spec = importlib.util.spec_from_file_location(
        "run_iac_review_under_test", plugin_root / SCRIPT
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# (a) Every enabled Source succeeds
# ---------------------------------------------------------------------------


@requires_cfn_guard
def test_all_sources_produce_one_valid_review_report(
    plugin_root: Path, fakebin_dir: Path, tmp_path: Path
) -> None:
    workspace = make_workspace(tmp_path, **{"template.yaml": MIXED_TEMPLATE})
    env = configure_fake_lint(
        tmp_path, results_text=json.dumps(lint_results("template.yaml"))
    )

    completed = run_skill(
        plugin_root,
        ["--target", "template.yaml"],
        cwd=workspace,
        path_entries=fake_lint_path(fakebin_dir, with_cfn_guard=True),
        env_extra=env,
    )
    report = load_report(completed)

    assert completed.returncode == exitcodes.OK
    # Requirement 16 AC10: stdout is the Review_Report envelope and nothing else.
    # Note that no ``stats`` key appears, unlike run_cfn_guard.py's stdout.
    assert sorted(report) == sorted(REPORT_KEYS)
    assert report["schema_version"] == SCHEMA_VERSION
    assert report["errors"] == []
    assert report["sources_enabled"] == ["cfn-lint", "cfn-guard", "IAM Review"]
    assert report["target"] == {
        "files": ["template.yaml"],
        "cdk": {"detected": False, "synthesized_templates": []},
    }

    findings = report["findings"]
    assert findings
    for entry in findings:
        from_dict(entry)
    assert [entry["ID"] for entry in findings] == list(range(1, len(findings) + 1))
    assert sources_of(report) == ["IAM Review", "cfn-guard", "cfn-lint"]
    assert report["summary"]["total"] == len(findings)
    assert report["summary"]["passed_all_checks"] is False
    assert report["summary"]["by_template_group"]["standalone"] == len(findings)
    # Requirement 16 AC11: nothing environment-dependent reaches stdout.
    assert str(workspace) not in completed.stdout
    assert str(plugin_root) not in completed.stdout


def test_stdout_is_the_report_envelope_with_no_stats_key(
    plugin_root: Path, tmp_path: Path
) -> None:
    """The orchestrator's contract: exactly the seven envelope keys.

    ``run_cfn_guard.py`` adds a top-level ``stats`` object to its own stdout
    (Requirement 5 AC4). This skill does not, and a consumer of this report may
    rely on that: see its SKILL.md, "Output".
    """
    workspace = make_workspace(tmp_path, **{"app.yaml": MIXED_TEMPLATE})

    completed = run_skill(
        plugin_root,
        ["--target", "app.yaml", "--sources", "iam-review", "--verbose"],
        cwd=workspace,
        path_entries=[],
    )
    report = load_report(completed)

    assert completed.returncode == exitcodes.OK
    assert sorted(report) == sorted(REPORT_KEYS)
    assert "stats" not in report
    # The counters live on stderr instead, keyed by template and source.
    assert "IAM Review" in completed.stderr


def test_the_two_spellings_of_the_iam_source_mean_one_source(
    plugin_root: Path, tmp_path: Path
) -> None:
    workspace = make_workspace(tmp_path, **{"app.yaml": MIXED_TEMPLATE})
    argv = ["--target", "app.yaml", "--sources"]

    hyphenated = run_skill(plugin_root, argv + ["iam-review"], cwd=workspace)
    canonical = run_skill(plugin_root, argv + ["IAM Review"], cwd=workspace)
    both = run_skill(
        plugin_root,
        argv + ["iam-review", "--sources", "IAM Review"],
        cwd=workspace,
    )

    assert hyphenated.stdout == canonical.stdout == both.stdout
    assert json.loads(hyphenated.stdout)["sources_enabled"] == ["IAM Review"]


def test_no_iam_message_is_written_to_stderr_not_stdout(
    plugin_root: Path, tmp_path: Path
) -> None:
    """Requirement 6 AC12, resolved for the orchestrated run.

    A template with no IAM yields zero findings plus an informational message.
    The message is a statement about the review, so it goes to stderr; stdout
    stays the envelope, which has no field for it.
    """
    workspace = make_workspace(tmp_path, **{"app.json": SIMPLE_TEMPLATE})

    completed = run_skill(
        plugin_root,
        ["--target", "app.json", "--sources", "iam-review"],
        cwd=workspace,
        path_entries=[],
    )
    report = load_report(completed)

    assert completed.returncode == exitcodes.OK
    assert report["findings"] == []
    assert report["errors"] == []
    assert report["summary"]["passed_all_checks"] is True
    # Not gated on --verbose: it is the answer, not a diagnostic.
    assert "No IAM-related resources" in completed.stderr
    assert "IAM-related" not in completed.stdout


def test_repeated_runs_produce_byte_identical_stdout(
    plugin_root: Path, tmp_path: Path
) -> None:
    """Requirement 16 AC11, and ``--verbose`` widens stderr only."""
    workspace = make_workspace(tmp_path, **{"template.yaml": MIXED_TEMPLATE})
    argv = ["--target", "template.yaml", "--sources", "iam-review"]

    first = run_skill(plugin_root, argv, cwd=workspace)
    second = run_skill(plugin_root, argv, cwd=workspace)
    verbose = run_skill(plugin_root, argv + ["--verbose"], cwd=workspace)

    assert first.returncode == exitcodes.OK
    assert first.stdout == second.stdout == verbose.stdout
    assert json.loads(first.stdout)["findings"]
    assert len(verbose.stderr) > len(first.stderr)


# ---------------------------------------------------------------------------
# (b) One Source fails, the rest of the review survives
# ---------------------------------------------------------------------------


def test_a_failing_source_is_one_error_and_does_not_stop_the_others(
    plugin_root: Path, fakebin_dir: Path, tmp_path: Path
) -> None:
    """Requirement 2 AC10, without depending on any real external tool.

    The fake cfn-lint exits 1, which design.md classifies as a crash rather than
    as findings (Requirement 4 AC12). The IAM Source needs no tool, so its
    Findings are what proves the loop continued.
    """
    workspace = make_workspace(tmp_path, **{"app.yaml": MIXED_TEMPLATE})
    env = configure_fake_lint(
        tmp_path, exit_code=1, results_text="", stderr="cfn-lint: internal error\n"
    )

    completed = run_skill(
        plugin_root,
        ["--target", "app.yaml", "--sources", "cfn-lint", "--sources", "iam-review"],
        cwd=workspace,
        path_entries=fake_lint_path(fakebin_dir),
        env_extra=env,
    )
    report = load_report(completed)

    # Exit 0: one Source failed, the review still happened.
    assert completed.returncode == exitcodes.OK
    assert error_classes(report) == ["tool_execution"]
    assert report["errors"][0]["source"] == "cfn-lint"
    assert report["errors"][0]["exit_code"] == 1
    assert report["errors"][0]["stderr_head"] == ["cfn-lint: internal error"]
    # Requirement 15 AC7: the transcription is bounded, never the whole stream.
    assert len(report["errors"][0]["stderr_head"]) <= 5

    assert sources_of(report) == ["IAM Review"]
    assert report["summary"]["total"] == len(report["findings"])
    assert report["summary"]["passed_all_checks"] is False
    for entry in report["findings"]:
        from_dict(entry)


@requires_cfn_guard
def test_a_failing_cfn_lint_keeps_cfn_guard_and_iam_findings(
    plugin_root: Path, fakebin_dir: Path, tmp_path: Path
) -> None:
    """The same property with all three Sources enabled, as Task 18.6 states it."""
    workspace = make_workspace(tmp_path, **{"app.yaml": MIXED_TEMPLATE})
    env = configure_fake_lint(tmp_path, exit_code=1, results_text="")

    completed = run_skill(
        plugin_root,
        ["--target", "app.yaml"],
        cwd=workspace,
        path_entries=fake_lint_path(fakebin_dir, with_cfn_guard=True),
        env_extra=env,
    )
    report = load_report(completed)

    assert completed.returncode == exitcodes.OK
    assert error_classes(report) == ["tool_execution"]
    assert sources_of(report) == ["IAM Review", "cfn-guard"]
    # The failed Source is still listed as enabled: what it was asked to do is a
    # different fact from what it managed to do.
    assert report["sources_enabled"] == ["cfn-lint", "cfn-guard", "IAM Review"]


def test_an_unparsable_template_among_several_is_reported_and_skipped(
    plugin_root: Path, tmp_path: Path
) -> None:
    """The failure matrix: ``errors[]`` when only some Templates are affected."""
    workspace = make_workspace(
        tmp_path,
        **{
            "good/app.yaml": MIXED_TEMPLATE,
            "bad/broken.yaml": "Resources:\n  Bucket:\n   - unbalanced: [\n",
        }
    )

    completed = run_skill(
        plugin_root, ["--target", ".", "--sources", "iam-review"], cwd=workspace
    )
    report = load_report(completed)

    assert completed.returncode == exitcodes.OK
    assert error_classes(report) == ["parse_failure"]
    assert report["target"]["files"] == ["good/app.yaml"]
    assert report["findings"]
    # Requirement 16 AC11: the message names the file the way the report does.
    assert "bad/broken.yaml" in str(report["errors"][0]["message"])
    assert str(workspace) not in completed.stdout


# ---------------------------------------------------------------------------
# (c) Every Source fails
# ---------------------------------------------------------------------------


def test_every_source_unavailable_exits_non_zero(
    plugin_root: Path, tmp_path: Path
) -> None:
    workspace = make_workspace(tmp_path, **{"app.yaml": MIXED_TEMPLATE})

    completed = run_skill(
        plugin_root,
        ["--target", "app.yaml", "--sources", "cfn-lint", "--sources", "cfn-guard"],
        cwd=workspace,
        path_entries=[Path(sys.executable).parent],
    )
    report = load_report(completed)

    # Nothing reviewed the template, so the run reports the failure class rather
    # than a clean review of nothing.
    assert completed.returncode == exitcodes.TOOL_UNAVAILABLE
    assert error_classes(report) == ["tool_unavailable", "tool_unavailable"]
    assert report["findings"] == []
    assert report["tools"] == [
        {"name": "cfn-guard", "available": False, "version": None},
        {"name": "cfn-lint", "available": False, "version": None},
    ]
    # passed_all_checks is about findings, not about errors; the errors array is
    # what tells a reader the review did not happen.
    assert report["summary"]["passed_all_checks"] is True


def test_one_available_source_among_unavailable_ones_exits_zero(
    plugin_root: Path, tmp_path: Path
) -> None:
    workspace = make_workspace(tmp_path, **{"app.yaml": MIXED_TEMPLATE})

    completed = run_skill(
        plugin_root,
        ["--target", "app.yaml"],
        cwd=workspace,
        path_entries=[Path(sys.executable).parent],
    )
    report = load_report(completed)

    assert completed.returncode == exitcodes.OK
    assert sources_of(report) == ["IAM Review"]
    assert len(report["errors"]) == 2


# ---------------------------------------------------------------------------
# (d) A directory target separates the two Template groups
# ---------------------------------------------------------------------------


def test_directory_target_separates_standalone_and_synthesized_templates(
    plugin_root: Path, tmp_path: Path
) -> None:
    """Requirement 8 AC2, AC9, AC10."""
    workspace = make_workspace(
        tmp_path,
        **{
            "templates/app.yaml": MIXED_TEMPLATE,
            "cdk.json": '{"app": "python3 app.py"}\n',
            "cdk.out/Stack.template.json": SIMPLE_TEMPLATE,
        }
    )

    completed = run_skill(
        plugin_root, ["--target", ".", "--sources", "iam-review"], cwd=workspace
    )
    report = load_report(completed)

    assert completed.returncode == exitcodes.OK
    assert report["target"]["files"] == ["templates/app.yaml"]
    assert report["target"]["cdk"] == {
        "detected": True,
        "synthesized_templates": ["cdk.out/Stack.template.json"],
    }
    # Both groups reviewed, and every Finding attributable to one of them.
    groups = report["summary"]["by_template_group"]
    assert groups["standalone"] == len(report["findings"])
    assert groups["synthesized"] == 0
    assert {f["Location"]["File"] for f in report["findings"]} == {
        "templates/app.yaml"
    }
    # cdk.json is a candidate by suffix and not a template; it is reported as
    # such (Requirement 3 AC5) rather than silently dropped or listed as
    # reviewed.
    assert "no_reviewable_template" in error_classes(report)
    assert "cdk.json" in str(
        [entry["message"] for entry in report["errors"]]
    )


def test_synthesized_findings_are_grouped_as_synthesized(
    plugin_root: Path, tmp_path: Path
) -> None:
    workspace = make_workspace(
        tmp_path,
        **{
            "cdk.json": '{"app": "python3 app.py"}\n',
            "cdk.out/Stack.template.json": json.dumps(
                {
                    "Resources": {
                        "AdminRole": {
                            "Type": "AWS::IAM::Role",
                            "Properties": {
                                "Policies": [
                                    {
                                        "PolicyName": "Everything",
                                        "PolicyDocument": {
                                            "Statement": [
                                                {
                                                    "Effect": "Allow",
                                                    "Action": "*",
                                                    "Resource": "*",
                                                }
                                            ]
                                        },
                                    }
                                ]
                            },
                        }
                    }
                }
            )
            + "\n",
        }
    )

    completed = run_skill(
        plugin_root, ["--target", ".", "--sources", "iam-review"], cwd=workspace
    )
    report = load_report(completed)

    assert completed.returncode == exitcodes.OK
    assert report["target"]["files"] == []
    assert report["target"]["cdk"]["synthesized_templates"] == [
        "cdk.out/Stack.template.json"
    ]
    assert report["findings"]
    groups = report["summary"]["by_template_group"]
    assert groups["synthesized"] == len(report["findings"])
    assert groups["standalone"] == 0


def test_a_directory_with_nothing_reviewable_exits_eight(
    plugin_root: Path, tmp_path: Path
) -> None:
    workspace = make_workspace(tmp_path, **{"notes/readme.txt": "nothing here\n"})

    completed = run_skill(
        plugin_root, ["--target", "."], cwd=workspace, path_entries=[]
    )
    report = load_report(completed)

    assert completed.returncode == exitcodes.NO_REVIEWABLE_TEMPLATE
    assert error_classes(report) == ["no_reviewable_template"]
    assert report["target"]["files"] == []
    assert report["findings"] == []


# ---------------------------------------------------------------------------
# (e) cdk synth is not invoked without confirmation
# ---------------------------------------------------------------------------


def test_no_cdk_process_is_started_without_confirmation(
    script_module: types.ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    """Requirement 8 AC3, Property 25, observed at the process boundary.

    In-process so that :func:`iacreview.proc.run` can be watched: it is the one
    function through which any external command reaches the operating system, so
    recording its arguments is the whole claim.
    """
    workspace = make_workspace(
        tmp_path,
        **{
            "cdk.json": '{"app": "python3 app.py"}\n',
            "app.py": "raise SystemExit('this must never run')\n",
        }
    )
    calls: List[List[str]] = []

    def record(argv: Sequence[str], **kwargs: Any) -> None:
        calls.append(list(argv))
        raise AssertionError("no external command should have been started")

    monkeypatch.setattr(proc, "run", record)
    monkeypatch.chdir(workspace)

    code = script_module.main(["--target", ".", "--sources", "iam-review"])
    captured = capsys.readouterr()

    assert calls == []
    # Nothing was synthesized, so nothing was reviewable (Requirement 8 AC5).
    assert code == exitcodes.NO_REVIEWABLE_TEMPLATE
    report = json.loads(captured.out)
    assert "no_reviewable_template" in error_classes(report)
    # The skipped synthesis is recorded rather than silent, and the warning the
    # host agent must show the user is in the message.
    assert "invalid_arguments" in error_classes(report)
    assert any(
        "no sandboxing" in str(entry["message"]) for entry in report["errors"]
    )
    assert report["target"]["cdk"]["detected"] is True


def test_already_synthesized_templates_are_reviewed_without_confirmation(
    plugin_root: Path, tmp_path: Path
) -> None:
    """Requirement 8 AC5: the run proceeds with what is already there."""
    workspace = make_workspace(
        tmp_path,
        **{
            "cdk.json": '{"app": "python3 app.py"}\n',
            "cdk.out/Stack.template.json": SIMPLE_TEMPLATE,
        }
    )

    completed = run_skill(
        plugin_root, ["--target", ".", "--sources", "iam-review"], cwd=workspace
    )
    report = load_report(completed)

    assert completed.returncode == exitcodes.OK
    assert report["target"]["cdk"]["synthesized_templates"] == [
        "cdk.out/Stack.template.json"
    ]
    assert "invalid_arguments" in error_classes(report)
    # The unconfirmed-synthesis notice does not make the run fail.
    assert "cdk synth" in completed.stderr


def test_confirming_synth_without_the_cdk_cli_exits_five(
    plugin_root: Path, tmp_path: Path
) -> None:
    """Requirement 8 AC8: name the CLI and point at its documentation."""
    workspace = make_workspace(
        tmp_path,
        **{
            "cdk.json": '{"app": "python3 app.py"}\n',
            "templates/app.yaml": MIXED_TEMPLATE,
        }
    )

    completed = run_skill(
        plugin_root,
        ["--target", ".", "--sources", "iam-review", "--confirm-cdk-synth"],
        cwd=workspace,
        path_entries=[Path(sys.executable).parent],
    )
    report = load_report(completed)

    assert completed.returncode == exitcodes.TOOL_UNAVAILABLE
    assert error_classes(report) == ["tool_unavailable"]
    assert report["errors"][0]["tool"] == "cdk"
    assert "aws.amazon.com" in str(report["errors"][0]["remediation"]) or "cdk" in str(
        report["errors"][0]["remediation"]
    )
    # Requirement 8 AC7: no fallback, so nothing was reviewed even though a
    # standalone template was present.
    assert report["findings"] == []


# ---------------------------------------------------------------------------
# (f) Agent findings are merged into a sequentially numbered report
# ---------------------------------------------------------------------------


def agent_findings_payload(template_file: str) -> Dict[str, Any]:
    """Two agent findings: one that merges with an IAM finding, one that does not."""
    return {
        "schema_version": "1.0.0",
        "findings": [
            {
                "Normalized_Category": "IAM",
                "FindingType": "Security",
                "Severity": "MEDIUM",
                "Confidence": "Contextual",
                "Source": ["Agent Review"],
                "Resource": "AdminRole",
                "Location": {
                    "File": template_file,
                    "Line": None,
                    "Column": None,
                    "TemplatePath": ["Resources", "AdminRole"],
                },
                "Finding": (
                    "This role may hold wider authority than the workload it "
                    "serves appears to need."
                ),
                "WhyItMatters": (
                    "Credentials obtained from a component using this role "
                    "could reach unrelated resources."
                ),
                "Evidence": [
                    {
                        "Source": "Agent Review",
                        "Detail": "The inline policy allows every action.",
                        "RuleId": None,
                        "Excerpt": 'Action: "*"\nResource: "*"',
                    }
                ],
                "Recommendation": "Narrow the policy to the actions performed.",
                "SuggestedRemediation": None,
            },
            {
                "Normalized_Category": "Availability",
                "FindingType": "BestPractice",
                "Severity": "LOW",
                "Confidence": "Likely",
                "Resource": None,
                "Location": {
                    "File": template_file,
                    "Line": None,
                    "Column": None,
                    "TemplatePath": [],
                },
                "Finding": (
                    "The template may place every resource in a single "
                    "Availability Zone."
                ),
                "WhyItMatters": (
                    "A single-zone deployment can become unavailable when that "
                    "zone degrades."
                ),
                "Evidence": [
                    {
                        "Detail": "No availability or subnet property appears.",
                        "Excerpt": "Resources:\n  PlainBucket:",
                    }
                ],
                "Recommendation": "Consider spreading resources across zones.",
            },
        ],
    }


def test_agent_findings_are_merged_and_the_report_is_numbered_sequentially(
    plugin_root: Path, tmp_path: Path
) -> None:
    workspace = make_workspace(
        tmp_path,
        **{
            "app.yaml": MIXED_TEMPLATE,
            "agent.json": json.dumps(agent_findings_payload("app.yaml")) + "\n",
        }
    )

    completed = run_skill(
        plugin_root,
        [
            "--target",
            "app.yaml",
            "--sources",
            "iam-review",
            "--agent-findings",
            "agent.json",
        ],
        cwd=workspace,
    )
    report = load_report(completed)

    assert completed.returncode == exitcodes.OK
    assert report["errors"] == []
    assert report["sources_enabled"] == ["IAM Review", "Agent Review"]

    findings = report["findings"]
    for entry in findings:
        from_dict(entry)
    assert [entry["ID"] for entry in findings] == list(range(1, len(findings) + 1))

    by_resource = {entry["Resource"]: entry for entry in findings}
    merged = by_resource["AdminRole"]
    # One resource, one category: the deterministic finding and the agent's are
    # one entry naming both Sources (Requirement 14 AC7, AC12).
    assert merged["Source"] == ["IAM Review", "Agent Review"]
    assert merged["Severity"] == "CRITICAL"
    # design.md C-8: a merged finding that includes agent reasoning cannot claim
    # Confirmed.
    assert merged["Confidence"] == "Likely"
    assert {evidence["Source"] for evidence in merged["Evidence"]} == {
        "IAM Review",
        "Agent Review",
    }

    # The finding with no resource stays on its own (Requirement 14 AC6).
    standalone = [entry for entry in findings if entry["Resource"] is None]
    assert len(standalone) == 1
    assert standalone[0]["Source"] == ["Agent Review"]
    assert report["summary"]["by_source"]["Agent Review"] == 2


def test_invalid_agent_findings_are_dropped_without_failing_the_review(
    plugin_root: Path, tmp_path: Path
) -> None:
    payload = agent_findings_payload("app.yaml")
    # Confidence outside the permitted values for agent output: the finding is
    # refused, the rest of the file loads.
    payload["findings"][1]["Severity"] = "EXTREME"
    workspace = make_workspace(
        tmp_path,
        **{
            "app.yaml": MIXED_TEMPLATE,
            "agent.json": json.dumps(payload) + "\n",
        }
    )

    completed = run_skill(
        plugin_root,
        [
            "--target",
            "app.yaml",
            "--sources",
            "iam-review",
            "--agent-findings",
            "agent.json",
        ],
        cwd=workspace,
    )
    report = load_report(completed)

    assert completed.returncode == exitcodes.OK
    assert error_classes(report) == ["schema_violation"]
    assert report["errors"][0]["source"] == "Agent Review"
    assert report["summary"]["by_source"]["Agent Review"] == 1


def test_an_unreadable_agent_findings_file_leaves_the_review_intact(
    plugin_root: Path, tmp_path: Path
) -> None:
    workspace = make_workspace(
        tmp_path,
        **{"app.yaml": MIXED_TEMPLATE, "agent.json": "not json at all\n"},
    )

    completed = run_skill(
        plugin_root,
        [
            "--target",
            "app.yaml",
            "--sources",
            "iam-review",
            "--agent-findings",
            "agent.json",
        ],
        cwd=workspace,
    )
    report = load_report(completed)

    # The deterministic review is unaffected by what the agent supplied.
    assert completed.returncode == exitcodes.OK
    assert error_classes(report) == ["schema_violation"]
    assert sources_of(report) == ["IAM Review"]


# ---------------------------------------------------------------------------
# Argument handling
# ---------------------------------------------------------------------------


def test_missing_target_exits_two_with_empty_stdout(plugin_root: Path) -> None:
    completed = run_skill(plugin_root, [])

    assert completed.returncode == exitcodes.INVALID_ARGUMENTS
    assert completed.stdout == ""
    assert "--target" in completed.stderr


def test_unknown_source_exits_two(plugin_root: Path) -> None:
    completed = run_skill(
        plugin_root, ["--target", IAM_TEMPLATE, "--sources", "cfn-nope"]
    )

    assert completed.returncode == exitcodes.INVALID_ARGUMENTS
    assert completed.stdout == ""


def test_a_target_outside_the_workspace_exits_seven(
    plugin_root: Path, tmp_path: Path
) -> None:
    workspace = make_workspace(tmp_path, **{"app.yaml": MIXED_TEMPLATE})
    outside = tmp_path / "outside.yaml"
    outside.write_text(MIXED_TEMPLATE, encoding="utf-8")

    completed = run_skill(
        plugin_root, ["--target", str(outside)], cwd=workspace, path_entries=[]
    )

    assert completed.returncode == exitcodes.PATH_VIOLATION
    # Refused before any template was read, so there is nothing to report about.
    assert completed.stdout == ""


def test_a_rules_dir_outside_the_workspace_exits_seven(
    plugin_root: Path, tmp_path: Path
) -> None:
    workspace = make_workspace(tmp_path, **{"app.yaml": MIXED_TEMPLATE})
    outside = tmp_path / "policies"
    outside.mkdir()

    completed = run_skill(
        plugin_root,
        ["--target", "app.yaml", "--rules-dir", str(outside)],
        cwd=workspace,
        path_entries=[],
    )

    assert completed.returncode == exitcodes.PATH_VIOLATION
    assert completed.stdout == ""


def test_a_missing_agent_findings_file_exits_three(
    plugin_root: Path, tmp_path: Path
) -> None:
    workspace = make_workspace(tmp_path, **{"app.yaml": MIXED_TEMPLATE})

    completed = run_skill(
        plugin_root,
        ["--target", "app.yaml", "--agent-findings", "absent.json"],
        cwd=workspace,
        path_entries=[],
    )

    assert completed.returncode == exitcodes.INPUT_NOT_FOUND
    assert completed.stdout == ""


def test_a_target_name_with_a_shell_metacharacter_exits_two(
    plugin_root: Path, tmp_path: Path
) -> None:
    workspace = make_workspace(tmp_path, **{"app.yaml": MIXED_TEMPLATE})

    completed = run_skill(
        plugin_root, ["--target", "app.yaml; echo hi"], cwd=workspace, path_entries=[]
    )

    assert completed.returncode == exitcodes.INVALID_ARGUMENTS
    assert completed.stdout == ""
