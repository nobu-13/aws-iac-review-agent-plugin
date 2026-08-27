"""The Tool Unavailable Test: three external tools, four situations, one contract.

steering/testing.md requires that cfn-lint, cfn-guard and the AWS CDK CLI each
fail *safely* when they are not usable. This module is where that requirement is
discharged, over the full matrix design.md's failure mode table describes:

=============  ====================  ======================  =====================
Situation      ``error_class``       Standalone Skill exit    Through ``iac-review``
=============  ====================  ======================  =====================
not installed  ``tool_unavailable``  5                       ``errors[]``, exit 0
below minimum  ``tool_version``      5                       ``errors[]``, exit 0
crash          ``tool_execution``    6                       ``errors[]``, exit 0
timeout        ``tool_timeout``      6                       ``errors[]``, exit 0
=============  ====================  ======================  =====================

The right-hand column has one documented exception, and it is the CDK CLI: a
confirmed ``cdk synth`` that cannot run leaves nothing to review, so
Requirement 8 AC7 forbids an alternative execution mode and the failure keeps its
own exit code even under the orchestrator. That contrast -- exit 0 for a failed
analyzer, exit 5 or 6 for a failed synth -- is asserted here rather than argued
about, because it is the one place where "record it and continue" does not apply.

What the exit-0 column really says is that it is not the *failure class* that
decides the exit code but whether any Source reviewed anything: the same faked
tool yields exit 0 when the IAM Source ran beside it and exit 5 or 6 when it was
the only Source enabled. Both halves are asserted for all eight analyzer
situations.

Requirements covered
--------------------

Requirement 12 AC7
    A structured error carrying the tool name and installation instructions, and
    no unhandled exception, for all three tools.
Requirement 4 AC10, AC12 / Requirement 5 AC5, AC6, AC7 / Requirement 8 AC8
    The per-tool remediation content: ``pip install cfn-lint``, the cfn-guard
    installation documentation, the CDK documentation URL.
Requirement 15 AC4, AC6
    Tool name plus minimum version for an absent tool; detected version, required
    version and upgrade command for one below the minimum.
Requirement 16 AC8, AC11
    A documented exit code per failure class, and no absolute host path anywhere
    in the output -- see the leak assertion in
    :func:`test_every_tool_situation_yields_one_structured_error`.
Requirement 10 AC5, design.md "JSON 入力のみの場合の縮退動作"
    PyYAML absent degrades rather than fails: the YAML Template is reported and
    skipped while the JSON Template is still reviewed.

Scope
-----

``tests/integration/test_fakebin_drives_sources.py`` proves each fake reaches the
branch it exists for; this module does not repeat that. It asserts the *contract*
instead: the same four situations for every tool, and the exit code each one
amounts to standalone versus orchestrated.

Left to Task 24.6: everything about the CDK CLI other than its exit codes and its
structured error -- the four project layouts, ``target.cdk.detected``, the
separation of standalone from synthesized Templates, the argv and timeout handed
to ``proc.run``, and the report content of a failed synth.

Not in scope, and recorded here so it is not lost: ``TemplateParseError.message``
carries the path it was given, and the standalone Skills pass
:func:`iacreview.pathguard.resolve_within`'s absolute result, so a parse failure
puts an absolute host path in ``errors[].message`` against Requirement 16 AC11.
That is a property of the malformed-input path, which Task 24.5
(``test_malformed_input.py``) owns; no assertion here depends on it.

Technique
---------

``PATH`` is replaced, never extended, and stated explicitly in every test: the
whole point of a fake is that it is the only thing resolvable, and an inherited
``PATH`` would let the real cfn-guard -- installed on many development machines
-- answer instead. :func:`use_fake` is imported from the module that introduced
it rather than reimplemented; it lives in a sibling test module, which pytest's
default import mode puts on ``sys.path`` before importing this file.

The entry points run in-process here, unlike in ``test_skill_*.py``. They have to:
the timeout situations are only reachable in reasonable time by shortening
``TIMEOUT_S`` inside the process that reads it, and a subprocess cannot be
monkeypatched. What in-process execution gives up is the guarantee that a
traceback never escapes, so every entry-point case also asserts that stderr holds
no ``Traceback`` and that the exit code is not the catch-all 1 -- which is what
:func:`iacreview.bootstrap.run_entry_point` would return if one had.
"""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import sys
import types
from pathlib import Path
from typing import Any, Callable, Dict, List, NamedTuple, Optional, Sequence, Tuple

import pytest

from iacreview import cdk, cfnguard, cfnlint, exitcodes
from iacreview.errors import IacReviewError
from iacreview.source import StructuredError
from iacreview.toolcheck import CDK, CFN_GUARD, CFN_LINT, TOOL_REQUIREMENTS

# The PATH-swapping helper introduced with the fakes themselves. Imported rather
# than copied so that a change to the fakebin layout is made in one place; the
# module is a sibling, and pytest's prepend import mode inserts this directory
# into sys.path before importing this file, which is what makes the plain module
# name resolvable.
from test_fakebin_drives_sources import use_fake

#: Short enough that four timeout situations do not dominate the suite's run
#: time, long enough that a fake answering immediately is not mistaken for one
#: that hung. The real budgets are 60 seconds per analyzer and 120 for
#: ``cdk synth``; shortening them changes no code path.
SHORT_TIMEOUT_S = 2

#: The three external tools steering/testing.md names.
TOOLS: Tuple[str, ...] = (CFN_LINT, CFN_GUARD, CDK)

#: ``fakebin`` scenario -> the ``error_class`` it must produce and the exit code a
#: standalone run of it must return (design.md, Failure mode マトリクス).
SITUATIONS: Dict[str, Tuple[str, int]] = {
    "missing": ("tool_unavailable", exitcodes.TOOL_UNAVAILABLE),
    "oldversion": ("tool_version", exitcodes.TOOL_UNAVAILABLE),
    "crash": ("tool_execution", exitcodes.TOOL_EXECUTION_FAILURE),
    "timeout": ("tool_timeout", exitcodes.TOOL_EXECUTION_FAILURE),
}

#: Every ``(tool, scenario)`` pair, as pytest parameters. One list so that no
#: test can silently cover eleven of the twelve.
ALL_SITUATIONS: List[Any] = [
    pytest.param(tool, scenario, id="{0}-{1}".format(tool, scenario))
    for tool in TOOLS
    for scenario in SITUATIONS
]

#: The two tools whose Sources record a failure and let the pipeline continue.
#: ``cdk`` is deliberately absent: it has no Skill of its own, and its failure is
#: not survivable (Requirement 8 AC7).
ANALYZERS: Tuple[str, ...] = (CFN_LINT, CFN_GUARD)

#: ``(tool, scenario)`` for the analyzers only, for the exit-code cases.
ANALYZER_SITUATIONS: List[Any] = [
    pytest.param(tool, scenario, id="{0}-{1}".format(tool, scenario))
    for tool in ANALYZERS
    for scenario in SITUATIONS
]

#: Entry point of each analyzer's standalone Skill, relative to the plugin root.
STANDALONE_SCRIPTS: Dict[str, str] = {
    CFN_LINT: "skills/cfn-lint-review/scripts/run_cfn_lint.py",
    CFN_GUARD: "skills/cfn-guard-review/scripts/run_cfn_guard.py",
}

#: The orchestrator.
ORCHESTRATOR_SCRIPT = "skills/iac-review/scripts/run_iac_review.py"

#: ``--sources`` value naming the Source each tool backs.
SOURCE_OF: Dict[str, str] = {
    CFN_LINT: cfnlint.SOURCE_NAME,
    CFN_GUARD: cfnguard.SOURCE_NAME,
}

#: A Template every Source has something to say about: a bare bucket for the
#: cfn-guard rules and a role granting everything for the IAM detectors. The IAM
#: Findings are what make "one Source still worked" observable.
TEMPLATE_TEXT = """\
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  DataBucket:
    Type: AWS::S3::Bucket
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

#: The same content as JSON, for the PyYAML degradation cases. Written by hand
#: rather than converted at run time, because converting it would need the parser
#: the test removes.
JSON_TEMPLATE_TEXT = json.dumps(
    {
        "Resources": {
            "AdminRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "ec2.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "Everything",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "*",
                                        "Resource": "*",
                                    }
                                ],
                            },
                        }
                    ],
                },
            }
        }
    },
    indent=2,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def short_timeouts(monkeypatch: pytest.MonkeyPatch) -> None:
    """Shorten every tool timeout for the whole module.

    Autouse because there is no test here that wants the real budgets, and a
    timeout situation reached with the default 60 or 120 seconds would look like
    a hung suite rather than like a passing test.
    """
    monkeypatch.setattr(cfnlint, "TIMEOUT_S", SHORT_TIMEOUT_S)
    monkeypatch.setattr(cfnguard, "TIMEOUT_S", SHORT_TIMEOUT_S)
    monkeypatch.setattr(cdk, "SYNTH_TIMEOUT_S", SHORT_TIMEOUT_S)


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """A workspace root holding one reviewable Template at ``app.yaml``."""
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "app.yaml").write_text(TEMPLATE_TEXT, encoding="utf-8")
    return root


@pytest.fixture(scope="session")
def entry_point(plugin_root: Path) -> Callable[[str], types.ModuleType]:
    """Return a loader for an entry-point script, importing each one once.

    The scripts are not importable by package path -- they live under ``skills/``
    and are meant to be run as files -- so they are loaded by location. Cached
    per session because executing a module body twice would install the
    ``sys.path`` bootstrap twice for no gain.
    """
    loaded: Dict[str, types.ModuleType] = {}

    def load(relative: str) -> types.ModuleType:
        if relative not in loaded:
            name = "entry_point_{0}".format(Path(relative).stem)
            spec = importlib.util.spec_from_file_location(
                name, plugin_root / relative
            )
            assert spec is not None and spec.loader is not None
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            loaded[relative] = module
        return loaded[relative]

    return load


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class Outcome(NamedTuple):
    """What one tool situation produced, whichever tool it was.

    Attributes:
        errors: The StructuredErrors recorded, in the order recorded.
        exit_code: The exit code a standalone run of that Source implies. For the
            two analyzers this is
            :meth:`iacreview.source.SourceResult.exit_status`; for ``cdk``, which
            raises rather than collecting, it is the exception's own
            ``exit_code``.
    """

    errors: List[StructuredError]
    exit_code: int


def situation_outcome(tool: str, workspace: Path) -> Outcome:
    """Drive ``tool`` over ``workspace`` and normalize what came back.

    Args:
        tool: One of :data:`TOOLS`. ``PATH`` must already point at the fake for
            the situation under test.
        workspace: A workspace holding ``app.yaml``. For ``cdk`` a ``cdk.json``
            is added, since :func:`iacreview.cdk.synth_if_confirmed` refuses a
            directory that is not a CDK project before it looks for the CLI.

    Returns:
        An :class:`Outcome`. Returning normally is itself part of what the caller
        asserts: only :class:`~iacreview.errors.IacReviewError` is caught here, so
        any other exception propagates and fails the test as the unhandled
        exception Requirement 12 AC7 forbids.
    """
    template = workspace / "app.yaml"
    if tool == CFN_LINT:
        result = cfnlint.run_and_normalize(template, workspace_root=workspace)
        return Outcome(result.errors, result.exit_status())
    if tool == CFN_GUARD:
        result = cfnguard.run_and_normalize(template, workspace_root=workspace)
        return Outcome(result.errors, result.exit_status())

    (workspace / "cdk.json").write_text('{"app": "fake"}', encoding="utf-8")
    try:
        cdk.synth_if_confirmed(workspace, confirmed=True)
    except IacReviewError as exc:
        return Outcome([exc.to_structured_error()], exc.exit_code)
    raise AssertionError("cdk synth was expected to fail but returned")


def only_situation_error(outcome: Outcome) -> StructuredError:
    """Return the single StructuredError of ``outcome``, failing if there is not one."""
    assert len(outcome.errors) == 1, outcome.errors
    return outcome.errors[0]


class EntryPointRun(NamedTuple):
    """The result of running an entry point in-process.

    Attributes:
        exit_code: What ``main()`` returned.
        report: The parsed Review_Report, or ``None`` when stdout was empty --
            which design.md's matrix expects for a failure detected before any
            Template was read.
        stdout: Raw stdout, for the assertions about what may not appear in it.
        stderr: Raw stderr, where diagnostics and any traceback would be.
    """

    exit_code: int
    report: Optional[Dict[str, Any]]
    stdout: str
    stderr: str


def run_entry_point(
    module: types.ModuleType,
    argv: Sequence[str],
    *,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> EntryPointRun:
    """Call an entry point's ``main()`` from ``workspace`` and collect its output.

    Args:
        module: An entry-point module from the :func:`entry_point` fixture.
        argv: Arguments after the script name.
        workspace: Working directory, which is the workspace root every entry
            point derives its containment root from.
        monkeypatch: Used for the directory change, so it is undone afterwards.
        capsys: Captures the two streams the entry point writes.

    Returns:
        An :class:`EntryPointRun`.
    """
    monkeypatch.chdir(workspace)
    exit_code = module.main(list(argv))
    captured = capsys.readouterr()
    report = json.loads(captured.out) if captured.out else None
    return EntryPointRun(exit_code, report, captured.out, captured.err)


def classes_of(report: Dict[str, Any]) -> List[str]:
    """Every ``error_class`` in ``report``, in report order."""
    return [str(entry["error_class"]) for entry in report["errors"]]


def assert_no_traceback(run: EntryPointRun) -> None:
    """Assert that no unhandled exception escaped the entry point.

    Two independent signals, because either alone can be fooled:
    :func:`iacreview.bootstrap.run_entry_point` prints the trace on stderr and
    returns :data:`iacreview.exitcodes.UNEXPECTED`, so a run that shows neither
    handled its failure deliberately (Requirement 12 AC7).
    """
    assert "Traceback" not in run.stderr, run.stderr
    assert run.exit_code != exitcodes.UNEXPECTED, run.stderr


# ---------------------------------------------------------------------------
# The matrix: 3 tools x 4 situations
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool,scenario", ALL_SITUATIONS)
def test_every_tool_situation_yields_one_structured_error(
    monkeypatch: pytest.MonkeyPatch,
    fakebin_dir: Path,
    workspace: Path,
    tool: str,
    scenario: str,
) -> None:
    """The whole contract of Requirement 12 AC7, twelve times.

    Four claims per situation:

    (a) no unhandled exception -- :func:`situation_outcome` catches only
        ``IacReviewError``, so anything else fails the test;
    (b) exactly one structured error, whose ``error_class``, ``tool`` and
        ``remediation`` are all populated;
    (c) the ``error_class`` is the one design.md's matrix assigns to the
        situation, and the exit code it maps to is 5 or 6 accordingly;
    (d) no absolute host path appears anywhere in the payload
        (Requirement 16 AC11).

    (d) is asserted here rather than in a case of its own so that it cannot fall
    behind the matrix: every situation added to :data:`SITUATIONS` is checked for
    the leak automatically. It is not a redundant assertion. ``argv[0]`` is the
    version-checked binary's absolute path
    (:attr:`iacreview.toolcheck.ToolInfo.path`), so the timeout and
    failed-to-start branches of :mod:`iacreview.proc` had that path in ``tool``
    and in ``message`` until it was reduced to the bare executable name.
    """
    expected_class, expected_exit = SITUATIONS[scenario]
    use_fake(monkeypatch, fakebin_dir, tool, scenario)

    outcome = situation_outcome(tool, workspace)

    error = only_situation_error(outcome)
    assert error["error_class"] == expected_class
    assert error["tool"] == tool
    assert error["remediation"], "every tool situation must say what to do next"
    assert outcome.exit_code == expected_exit

    payload = json.dumps(outcome.errors)
    for absolute in (str(fakebin_dir), str(workspace), os.fspath(sys.executable)):
        assert absolute not in payload, error


# ---------------------------------------------------------------------------
# Remediation content, per tool (Requirement 4 AC10, 5 AC5, 8 AC8, 15 AC4)
# ---------------------------------------------------------------------------


def test_absent_cfn_lint_remediation_names_the_pip_install_command(
    monkeypatch: pytest.MonkeyPatch, fakebin_dir: Path, workspace: Path
) -> None:
    """Requirement 4 AC10 names the command literally, so the test does too."""
    use_fake(monkeypatch, fakebin_dir, CFN_LINT, "missing")

    error = only_situation_error(situation_outcome(CFN_LINT, workspace))

    assert "pip install cfn-lint" in str(error["remediation"])
    # Requirement 15 AC4 asks for the minimum version alongside the command.
    assert error["required_min_version"] == TOOL_REQUIREMENTS[CFN_LINT].min_version


def test_absent_cfn_guard_remediation_references_its_installation_documentation(
    monkeypatch: pytest.MonkeyPatch, fakebin_dir: Path, workspace: Path
) -> None:
    """Requirement 5 AC5 asks for a documentation reference, not a command.

    cfn-guard has no single install command that works on every host -- Homebrew
    on macOS, ``cargo`` or the upstream script on Linux -- which is why the
    criterion is worded that way and why the URL is asserted from the table
    rather than as a literal: a URL that moves should be changed in one place.
    """
    use_fake(monkeypatch, fakebin_dir, CFN_GUARD, "missing")

    error = only_situation_error(situation_outcome(CFN_GUARD, workspace))
    remediation = str(error["remediation"])

    assert TOOL_REQUIREMENTS[CFN_GUARD].docs_url in remediation
    assert "cloudformation-guard" in remediation
    assert error["required_min_version"] == TOOL_REQUIREMENTS[CFN_GUARD].min_version


def test_absent_cdk_remediation_references_the_official_documentation(
    monkeypatch: pytest.MonkeyPatch, fakebin_dir: Path, workspace: Path
) -> None:
    """Requirement 8 AC8, on the one path that may ask for the CDK CLI at all."""
    use_fake(monkeypatch, fakebin_dir, CDK, "missing")

    error = only_situation_error(situation_outcome(CDK, workspace))
    remediation = str(error["remediation"])

    assert TOOL_REQUIREMENTS[CDK].docs_url in remediation
    assert "docs.aws.amazon.com/cdk" in remediation


# ---------------------------------------------------------------------------
# Version shortfall (Requirement 15 AC6)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool", TOOLS)
def test_a_tool_below_the_minimum_reports_detected_required_and_upgrade(
    monkeypatch: pytest.MonkeyPatch, fakebin_dir: Path, workspace: Path, tool: str
) -> None:
    """All three fields Requirement 15 AC6 enumerates, for all three tools.

    The detected version is asserted against the fake's banner and the required
    one against :data:`~iacreview.toolcheck.TOOL_REQUIREMENTS`, so the test fails
    if either side of the comparison drifts -- a fake updated past the minimum
    would otherwise make this case pass while testing nothing.
    """
    detected_versions = {CFN_LINT: "0.83.0", CFN_GUARD: "2.1.0", CDK: "1.99.0"}
    requirement = TOOL_REQUIREMENTS[tool]
    use_fake(monkeypatch, fakebin_dir, tool, "oldversion")

    error = only_situation_error(situation_outcome(tool, workspace))

    assert error["error_class"] == "tool_version"
    assert error["detected_version"] == detected_versions[tool]
    assert error["required_min_version"] == requirement.min_version
    assert requirement.upgrade_command in str(error["remediation"])


# ---------------------------------------------------------------------------
# Exit codes: a standalone Skill
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool,scenario", ANALYZER_SITUATIONS)
def test_a_standalone_skill_exits_five_or_six_and_still_prints_its_report(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
    entry_point: Callable[[str], types.ModuleType],
    fakebin_dir: Path,
    workspace: Path,
    tool: str,
    scenario: str,
) -> None:
    """design.md's "Exit code (単独 Skill)" column, for both analyzer Skills.

    The report is still printed with a non-zero exit code, and that is the point
    of the case: for these failures the ``errors[]`` array *is* the report's
    content, so a Skill that exited 5 with an empty stdout would leave the caller
    with a number and no way to know which tool was missing or how to install it.
    """
    expected_class, expected_exit = SITUATIONS[scenario]
    use_fake(monkeypatch, fakebin_dir, tool, scenario)
    module = entry_point(STANDALONE_SCRIPTS[tool])

    run = run_entry_point(
        module,
        ["--target", "app.yaml"],
        workspace=workspace,
        monkeypatch=monkeypatch,
        capsys=capsys,
    )

    assert_no_traceback(run)
    assert run.exit_code == expected_exit
    assert run.report is not None
    assert classes_of(run.report) == [expected_class]
    assert run.report["errors"][0]["tool"] == tool
    assert run.report["findings"] == []
    # The tool is reported as unusable rather than omitted, so a consumer can
    # tell "no findings" from "nothing looked" (Requirement 15 AC4).
    assert run.report["tools"][0]["name"] == tool
    assert str(workspace) not in run.stdout


# ---------------------------------------------------------------------------
# Exit codes: through iac-review
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool,scenario", ANALYZER_SITUATIONS)
def test_iac_review_records_the_failure_and_exits_zero_when_a_source_still_ran(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
    entry_point: Callable[[str], types.ModuleType],
    fakebin_dir: Path,
    workspace: Path,
    tool: str,
    scenario: str,
) -> None:
    """Requirement 2 AC10: one unusable tool does not stop the review.

    ``PATH`` holds a single fake directory, so the *other* analyzer is missing
    too and both failures are recorded. The IAM Source needs no external tool,
    which is what leaves something in ``findings`` and makes exit 0 a statement
    about work that was actually done rather than about a failure being ignored.
    """
    expected_class, _ = SITUATIONS[scenario]
    use_fake(monkeypatch, fakebin_dir, tool, scenario)
    module = entry_point(ORCHESTRATOR_SCRIPT)

    run = run_entry_point(
        module,
        ["--target", "app.yaml"],
        workspace=workspace,
        monkeypatch=monkeypatch,
        capsys=capsys,
    )

    assert_no_traceback(run)
    assert run.exit_code == exitcodes.OK
    assert run.report is not None
    assert expected_class in classes_of(run.report)
    assert run.report["findings"], "the IAM Source should still have reported"
    assert any(
        entry["tool"] == tool and entry["error_class"] == expected_class
        for entry in run.report["errors"]
    )


@pytest.mark.parametrize("tool,scenario", ANALYZER_SITUATIONS)
def test_iac_review_keeps_the_failure_exit_code_when_it_was_the_only_source(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
    entry_point: Callable[[str], types.ModuleType],
    fakebin_dir: Path,
    workspace: Path,
    tool: str,
    scenario: str,
) -> None:
    """The other half of the exit-code rule: it is not the failure class that decides.

    Same fake, same failure, same report entry as the previous case -- and a
    non-zero exit, because ``--sources`` left nothing else to review with. What
    the orchestrator's exit code answers is "did anything review anything", not
    "did anything fail" (design.md, Exit code).
    """
    _, expected_exit = SITUATIONS[scenario]
    use_fake(monkeypatch, fakebin_dir, tool, scenario)
    module = entry_point(ORCHESTRATOR_SCRIPT)

    run = run_entry_point(
        module,
        ["--target", "app.yaml", "--sources", SOURCE_OF[tool]],
        workspace=workspace,
        monkeypatch=monkeypatch,
        capsys=capsys,
    )

    assert_no_traceback(run)
    assert run.exit_code == expected_exit
    assert run.report is not None
    assert classes_of(run.report) == [SITUATIONS[scenario][0]]
    assert run.report["findings"] == []


@pytest.mark.parametrize("scenario", sorted(SITUATIONS))
def test_a_confirmed_cdk_synth_that_fails_keeps_its_own_exit_code(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
    entry_point: Callable[[str], types.ModuleType],
    fakebin_dir: Path,
    tmp_path: Path,
    scenario: str,
) -> None:
    """The documented exception to the exit-0 column (Requirement 8 AC7).

    A failed synth is not a Source failing beside others: with no Template there
    is nothing for any Source to review, and falling back to a stale ``cdk.out``
    would report a review of code that is no longer there. So the failure keeps
    the 5 or 6 it would have standalone, even under the orchestrator.

    Only the exit code and the absence of a traceback are asserted. What the
    report says about a failed synth -- the documentation URL, the first five
    stderr lines, the timeout handed to ``proc.run`` -- belongs to Task 24.6.
    """
    project = tmp_path / "project"
    project.mkdir()
    (project / "cdk.json").write_text('{"app": "fake"}', encoding="utf-8")
    _, expected_exit = SITUATIONS[scenario]
    use_fake(monkeypatch, fakebin_dir, CDK, scenario)
    module = entry_point(ORCHESTRATOR_SCRIPT)

    run = run_entry_point(
        module,
        ["--target", ".", "--confirm-cdk-synth"],
        workspace=project,
        monkeypatch=monkeypatch,
        capsys=capsys,
    )

    assert_no_traceback(run)
    assert run.exit_code == expected_exit
    # No template was obtained, so nothing was reviewed either way.
    assert run.report is None or run.report["findings"] == []


# ---------------------------------------------------------------------------
# A tool that is present but cannot be started
# ---------------------------------------------------------------------------


def test_an_executable_that_cannot_be_started_is_reported_without_its_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, workspace: Path
) -> None:
    """The fifth situation, which no fake in ``fakebin`` can produce.

    ``fakebin``'s scripts are all runnable; this one is on ``PATH`` with the
    execute bit set but names an interpreter that does not exist, so
    :func:`shutil.which` finds it and ``execve`` refuses it. That reaches
    :mod:`iacreview.proc`'s ``OSError`` branch, which is the third place an
    absolute path could enter the report: the operating system puts the offending
    filename into ``str(exc)``, so the message is built from the errno and its
    text instead (Requirement 16 AC11).

    Built here rather than added to ``fakebin`` because a committed file whose
    shebang must be invalid is a trap for the next reader, and because the path
    it must not leak has to be one this test knows.
    """
    unusable = tmp_path / "bin"
    unusable.mkdir()
    executable = unusable / CFN_LINT
    executable.write_text(
        "#!{0}/no-such-interpreter\n".format(tmp_path), encoding="utf-8"
    )
    executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", str(unusable))

    outcome = situation_outcome(CFN_LINT, workspace)

    error = only_situation_error(outcome)
    assert error["error_class"] == "tool_execution"
    assert error["tool"] == CFN_LINT
    assert outcome.exit_code == exitcodes.TOOL_EXECUTION_FAILURE
    assert str(tmp_path) not in json.dumps(outcome.errors)


# ---------------------------------------------------------------------------
# PyYAML absent: the degradation design.md specifies
# ---------------------------------------------------------------------------


@pytest.fixture
def without_pyyaml(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make ``import yaml`` fail for the duration of one test.

    A ``None`` entry in :data:`sys.modules` is the documented way to make an
    import raise ``ImportError`` without touching the filesystem, and
    ``monkeypatch`` restores the real entry afterwards. Uninstalling PyYAML would
    be the only alternative, and it would break the rest of the suite.

    This works because :mod:`iacreview.yamlcfn` imports PyYAML inside its
    functions rather than at module scope -- which is itself the mechanism the
    degradation depends on (design.md, "JSON 入力のみの場合の縮退動作").
    """
    monkeypatch.setitem(sys.modules, "yaml", None)


def test_without_pyyaml_the_yaml_template_fails_and_the_json_one_is_reviewed(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
    entry_point: Callable[[str], types.ModuleType],
    without_pyyaml: None,
    tmp_path: Path,
) -> None:
    """Requirement 10 AC5's shape applied to the one Python dependency.

    The degradation is per file, not per run: the YAML Template becomes one
    ``errors[]`` entry naming PyYAML and its install command, the JSON Template
    is reviewed normally, and the exit code stays 0 because something was
    reviewed. ``--sources iam-review`` isolates the case from ``PATH``: no
    external tool is involved in it at all.
    """
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "app.json").write_text(JSON_TEMPLATE_TEXT, encoding="utf-8")
    (workspace / "legacy.yaml").write_text(TEMPLATE_TEXT, encoding="utf-8")
    module = entry_point(ORCHESTRATOR_SCRIPT)

    run = run_entry_point(
        module,
        ["--target", ".", "--sources", "iam-review"],
        workspace=workspace,
        monkeypatch=monkeypatch,
        capsys=capsys,
    )

    assert_no_traceback(run)
    assert run.exit_code == exitcodes.OK
    assert run.report is not None
    assert run.report["target"]["files"] == ["app.json"]
    assert run.report["findings"], "the JSON template should still be reviewed"

    assert classes_of(run.report) == ["tool_unavailable"]
    error = run.report["errors"][0]
    assert error["tool"] == "PyYAML"
    assert "pip install" in str(error["remediation"])
    assert error["required_min_version"] == "6.0"


def test_without_pyyaml_a_yaml_only_workspace_reports_the_missing_dependency(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
    entry_point: Callable[[str], types.ModuleType],
    without_pyyaml: None,
    tmp_path: Path,
) -> None:
    """The degradation is not silence: with nothing else to review, the run fails.

    Same failure as the previous case, different exit code, for the same reason
    the analyzer cases give: exit 0 requires that something was reviewed. Without
    this case a report of zero Findings and one error could be mistaken for a
    clean Template.
    """
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "app.yaml").write_text(TEMPLATE_TEXT, encoding="utf-8")
    module = entry_point(ORCHESTRATOR_SCRIPT)

    run = run_entry_point(
        module,
        ["--target", ".", "--sources", "iam-review"],
        workspace=workspace,
        monkeypatch=monkeypatch,
        capsys=capsys,
    )

    assert_no_traceback(run)
    assert run.exit_code == exitcodes.TOOL_UNAVAILABLE
    assert run.report is not None
    assert run.report["target"]["files"] == []
    assert run.report["findings"] == []
    assert classes_of(run.report) == ["tool_unavailable"]
    assert run.report["errors"][0]["tool"] == "PyYAML"
