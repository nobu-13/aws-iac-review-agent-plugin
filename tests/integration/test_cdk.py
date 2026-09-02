"""The CDK flow of Requirement 8, driven through the ``iac-review`` orchestrator.

Four directory layouts, enumerated, and what the Review_Report says about each.
The layouts are the ones Task 24.6 lists, and between them they cover every
branch of design.md's CDK flowchart that does not need a CLI:

======================================  =========================  ============
layout                                  ``target.cdk.detected``    reviewable
======================================  =========================  ============
``cdk.json`` only                       ``True``                   nothing
``cdk.json`` + ``cdk.out``              ``True``                   synthesized
``cdk.json`` + standalone + ``cdk.out`` ``True``                   both groups
standalone only                         ``False``                  standalone
======================================  =========================  ============

On top of the matrix, the report content of a synthesis that was confirmed and
then failed: the documentation URL of an absent CLI (AC8), the first five lines
of a crash's stderr (AC6, AC7), the argv and timeout handed to
:func:`iacreview.proc.run`, and the absence of any fallback to a stale
``cdk.out`` (AC7).

The security boundary
---------------------

``cdk synth`` executes the project's own code and its dependencies' lifecycle
scripts, unsandboxed (AC11). The confirmation flag is therefore a security
control, not a convenience, and
:func:`test_no_cdk_process_is_started_for_any_layout_without_confirmation` is the
assertion that carries it: :func:`iacreview.proc.run` is the single function
through which any external command reaches the operating system, so a recorder
installed there observes the whole claim. Each layout also holds an ``app.py``
that raises on import, so a synthesis that somehow started would leave a mark
even if the recorder were bypassed.

Scope, and who owns what
------------------------

``tests/unit/test_cdk_detect.py``
    :mod:`iacreview.cdk` on its own -- detection, discovery, symlink
    containment, and ``synth_if_confirmed`` against a hand-written fake.

``tests/integration/test_fakebin_drives_sources.py``
    That each ``cdk`` fake in ``tests/fakebin`` reaches the branch it was
    written for, asserted directly against :mod:`iacreview.cdk`.

``tests/integration/test_tool_unavailable.py``
    The exit code and the one structured error of each of the four tool
    situations, for all three tools. It defers the *content* of a failed synth's
    report to this module by name.

``tests/integration/test_skill_iac_review.py``
    Three CDK cases inside the orchestrator's own six-case suite. This module
    does not repeat their single layout; it enumerates the other three and adds
    the report content.

``tests/property/test_prop_orchestration.py`` (Property 25)
    The same confirmation gate as a *quantified* property over generated
    layouts. This module's contribution is the enumerated matrix and the report
    content; the quantifier is theirs.

``PATH`` is stated explicitly in every test and never inherited. A real CDK CLI
on a contributor's machine would otherwise turn the confirmed cases into a real
synthesis of a fake project, and :data:`SHORT_TIMEOUT_S` keeps the one test that
actually elapses a timeout from waiting out the documented 120 seconds.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
import types
from pathlib import Path
from typing import Any, Dict, List, NamedTuple, Optional, Sequence

import pytest

from iacreview import cdk, exitcodes, proc
from iacreview.errors import STDERR_HEAD_MAX_LINES, ToolTimeoutError
from iacreview.toolcheck import CDK

#: The orchestrator, relative to the plugin root. The only entry point that
#: knows about CDK: the analyzer Skills take a Template, not a project.
ORCHESTRATOR_SCRIPT = "skills/iac-review/scripts/run_iac_review.py"

#: The Skill documentation that must carry the risk wording (Requirement 8 AC11).
ORCHESTRATOR_SKILL_DOC = "skills/iac-review/SKILL.md"

#: ``--sources`` value naming the one Source that needs no external tool. Used
#: everywhere here: these tests are about which Templates were discovered and
#: what the report says about them, and a Source whose tool may or may not be
#: installed would make that depend on the machine.
IAM_ONLY = ("--sources", "iam-review")

#: Synth timeout for the single test that lets one elapse. Long enough that a
#: fake answering at once is not mistaken for one that hung.
SHORT_TIMEOUT_S = 2

#: A ``cdk.json`` naming an app that would fail loudly if it ever ran.
CDK_CONFIG_TEXT = '{"app": "python3 app.py"}\n'

#: The tripwire that ``cdk.json`` names. Nothing in this plugin may execute it
#: without ``--confirm-cdk-synth``; if something did, the process would die
#: rather than quietly succeed.
TRIPWIRE_TEXT = "raise SystemExit('the CDK app must never be executed')\n"


def _iam_template_yaml(logical_id: str) -> str:
    """A YAML Template whose one role grants everything, as the IAM Source sees it.

    A wildcard action on a wildcard resource is what makes the deterministic IAM
    detectors produce a Finding, which is how "this Template was actually
    reviewed" becomes observable in the report rather than merely "this file was
    listed".
    """
    return """\
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  {0}:
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
""".format(
        logical_id
    )


def _iam_template_json(logical_id: str) -> str:
    """The same Template as JSON, for a synthesized cloud assembly.

    ``cdk synth`` writes JSON, and ``.template.json`` is what
    :func:`iacreview.cdk.find_synthesized_templates` collects, so a synthesized
    Template is spelled the way the real one would be.
    """
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                logical_id: {
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
            },
        },
        indent=1,
    )


#: Where a standalone Template sits in every layout that has one. Under a
#: subdirectory on purpose: the recursive scan has to reach it, and the path
#: sorts *after* ``cdk.out/...``, which is what makes review order distinguishable
#: from sort order in :func:`test_standalone_templates_are_reviewed_first`.
STANDALONE_FILE = "templates/standalone.yaml"

#: Where a pre-existing cloud assembly Template sits.
SYNTHESIZED_FILE = "cdk.out/AppStack.template.json"


# ---------------------------------------------------------------------------
# The four layouts
# ---------------------------------------------------------------------------


class Layout(NamedTuple):
    """One directory layout, with what the report must say about it.

    Attributes:
        files: Relative path -> content, written into the project directory.
        detected: Expected ``target.cdk.detected`` (Requirement 8 AC2).
        standalone: Expected ``target.files``, relative to the workspace root.
        synthesized: Expected ``target.cdk.synthesized_templates``.
        exit_code: Expected exit code of an unconfirmed run.
        synthesis: Expected ``target.cdk.synthesis`` for an unconfirmed run
            (Requirement 23 AC1): ``not_applicable`` for a non-CDK layout,
            ``skipped_unconfirmed`` for a CDK project reviewed without the flag.
    """

    files: Dict[str, str]
    detected: bool
    standalone: List[str]
    synthesized: List[str]
    exit_code: int
    synthesis: str


#: The layouts of Task 24.6, keyed by the name the parametrized test IDs use.
#:
#: Every expectation here is for a run *without* ``--confirm-cdk-synth``, which is
#: the only mode in which all four can be compared: with the flag, two of them
#: would need a CLI and one would be refused for not being a project.
LAYOUTS: Dict[str, Layout] = {
    "cdk-json-only": Layout(
        files={"cdk.json": CDK_CONFIG_TEXT, "app.py": TRIPWIRE_TEXT},
        detected=True,
        standalone=[],
        synthesized=[],
        # Requirement 8 AC5, second half: with nothing synthesized and no
        # confirmation, there is nothing reviewable at all.
        exit_code=exitcodes.NO_REVIEWABLE_TEMPLATE,
        synthesis="skipped_unconfirmed",
    ),
    "cdk-json-and-assembly": Layout(
        files={
            "cdk.json": CDK_CONFIG_TEXT,
            "app.py": TRIPWIRE_TEXT,
            SYNTHESIZED_FILE: _iam_template_json("SynthesizedRole"),
        },
        detected=True,
        standalone=[],
        synthesized=[SYNTHESIZED_FILE],
        # Requirement 8 AC5, first half: narrower coverage is not a failed
        # review, so the skipped synthesis costs an errors[] entry and not the
        # exit code.
        exit_code=exitcodes.OK,
        synthesis="skipped_unconfirmed",
    ),
    "cdk-json-standalone-and-assembly": Layout(
        files={
            "cdk.json": CDK_CONFIG_TEXT,
            "app.py": TRIPWIRE_TEXT,
            STANDALONE_FILE: _iam_template_yaml("StandaloneRole"),
            SYNTHESIZED_FILE: _iam_template_json("SynthesizedRole"),
        },
        detected=True,
        standalone=[STANDALONE_FILE],
        synthesized=[SYNTHESIZED_FILE],
        exit_code=exitcodes.OK,
        synthesis="skipped_unconfirmed",
    ),
    "standalone-only": Layout(
        files={STANDALONE_FILE: _iam_template_yaml("StandaloneRole")},
        detected=False,
        standalone=[STANDALONE_FILE],
        synthesized=[],
        exit_code=exitcodes.OK,
        synthesis="not_applicable",
    ),
}


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def orchestrator(plugin_root: Path) -> types.ModuleType:
    """The orchestrator imported as a module, for the in-process cases.

    In-process rather than as a subprocess because the two claims that matter
    most here -- that :func:`iacreview.proc.run` is never reached, and what
    argument list it receives when it is -- are only observable from inside the
    process that would make the call. The script is loaded by location: it lives
    under ``skills/`` and is not importable by package path.
    """
    spec = importlib.util.spec_from_file_location(
        "run_iac_review_cdk_under_test", plugin_root / ORCHESTRATOR_SCRIPT
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def empty_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Set ``PATH`` to one empty directory: no external tool is resolvable.

    The default for every test here that must not find a CDK CLI. Stated as a
    fixture rather than left to the caller so that no test in this module can
    inherit the developer's ``PATH`` by omission -- a real ``cdk`` would turn a
    gating test into a real synthesis.
    """
    directory = tmp_path / "empty-path"
    directory.mkdir()
    monkeypatch.setenv("PATH", str(directory))
    return directory


def make_project(root: Path, files: Dict[str, str]) -> Path:
    """Create ``root`` holding ``files`` (relative path -> content)."""
    root.mkdir(parents=True, exist_ok=True)
    for relative, content in sorted(files.items()):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def use_cdk_fake(
    monkeypatch: pytest.MonkeyPatch,
    fakebin_dir: Path,
    scenario: str,
    *,
    config: Optional[Dict[str, Any]] = None,
    config_dir: Optional[Path] = None,
) -> Path:
    """Point ``PATH`` at one ``cdk`` fake, and nothing else.

    The same technique as ``tests/integration/test_fakebin_drives_sources.py``'s
    ``use_fake``, narrowed to ``cdk``. Kept local rather than imported: a helper
    shared between two test modules couples them, and the shape here is a single
    tool with an optional configuration file.

    Args:
        monkeypatch: pytest's environment patcher.
        fakebin_dir: ``tests/fakebin``.
        scenario: ``missing``, ``crash``, ``oldversion``, ``timeout`` or
            ``configured``.
        config: Configuration for the ``configured`` fake, written to
            ``<config_dir>/fake-cdk.json``.
        config_dir: Directory handed to the fake as ``TMPDIR``. Required with
            ``config``, and kept *outside* the reviewed project: a stray
            ``fake-cdk.json`` inside it would be scanned as a candidate Template.

    Returns:
        The directory that now holds the resolvable ``cdk``.
    """
    directory = fakebin_dir / "cdk-{0}".format(scenario)
    entries = [str(directory)]
    if scenario == "configured":
        # The configured fake is a `#!/usr/bin/env python3` script, so `env` has
        # to be able to find an interpreter. The scenario fakes are POSIX sh with
        # an absolute interpreter path and need nothing but their own directory.
        entries.append(str(Path(sys.executable).parent))
    monkeypatch.setenv("PATH", os.pathsep.join(entries))

    if config is not None:
        assert config_dir is not None, "config requires a config_dir"
        config_dir.mkdir(parents=True, exist_ok=True)
        (config_dir / "fake-cdk.json").write_text(
            json.dumps(config), encoding="utf-8"
        )
        # TMPDIR is the channel because iacreview.proc hands children an
        # environment allowlist, so AWS credentials cannot reach an external
        # tool. An invented variable would be dropped and never arrive.
        monkeypatch.setenv("TMPDIR", str(config_dir))
    return directory


class Run(NamedTuple):
    """What one in-process orchestrator run produced.

    Attributes:
        exit_code: What ``main()`` returned.
        report: The parsed Review_Report, or ``None`` when stdout was empty.
        stdout: Raw stdout, for the assertions about what may not appear there.
        stderr: Raw stderr, where the diagnostics and any traceback would be.
    """

    exit_code: int
    report: Optional[Dict[str, Any]]
    stdout: str
    stderr: str


def run_review(
    orchestrator: types.ModuleType,
    argv: Sequence[str],
    *,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> Run:
    """Call the orchestrator's ``main()`` from ``workspace`` and collect its output."""
    monkeypatch.chdir(workspace)
    exit_code = orchestrator.main(list(argv))
    captured = capsys.readouterr()
    report = json.loads(captured.out) if captured.out else None
    return Run(exit_code, report, captured.out, captured.err)


def error_classes(report: Dict[str, Any]) -> List[str]:
    """Every ``error_class`` in ``report``, in report order."""
    return [str(entry["error_class"]) for entry in report["errors"]]


def error_of_class(report: Dict[str, Any], error_class: str) -> Dict[str, Any]:
    """Return the single ``errors[]`` entry of ``error_class``, failing otherwise."""
    matches = [
        entry for entry in report["errors"] if entry["error_class"] == error_class
    ]
    assert len(matches) == 1, report["errors"]
    return matches[0]


def assert_no_traceback(run: Run) -> None:
    """Assert no unhandled exception escaped the entry point.

    Two independent signals, because either alone can be fooled:
    :func:`iacreview.bootstrap.run_entry_point` prints the trace on stderr *and*
    returns :data:`iacreview.exitcodes.UNEXPECTED`.
    """
    assert "Traceback" not in run.stderr, run.stderr
    assert run.exit_code != exitcodes.UNEXPECTED, run.stderr


def forbid_processes(monkeypatch: pytest.MonkeyPatch) -> List[List[str]]:
    """Replace :func:`iacreview.proc.run` with a recorder that refuses to run.

    Returns:
        The list the recorder appends to. It stays empty for a run that started
        no external command, which is the whole content of the confirmation gate.

    Note:
        Patched on the :mod:`iacreview.proc` module itself, not on a name a
        caller imported, so every module that calls ``proc.run`` is covered. The
        recorder raises as well as records: were something to reach it, the test
        would fail at the call site with the argv in the traceback rather than at
        an assertion three screens later.
    """
    calls: List[List[str]] = []

    def record(argv: Sequence[str], *args: Any, **kwargs: Any) -> None:
        calls.append(list(argv))
        raise AssertionError(
            "no external command should have been started: {0!r}".format(list(argv))
        )

    monkeypatch.setattr(proc, "run", record)
    return calls


# ---------------------------------------------------------------------------
# (a) (b) (c) (h) The four layouts, without confirmation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("layout_name", sorted(LAYOUTS))
def test_each_layout_reports_its_detection_and_its_two_template_groups(
    orchestrator: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
    empty_path: Path,
    tmp_path: Path,
    layout_name: str,
) -> None:
    """Requirement 8 AC2, AC5, AC9, AC10 across the enumerated matrix.

    One assertion set, four layouts. ``target.cdk.detected`` states whether a
    ``cdk.json`` was found; ``target.files`` and
    ``target.cdk.synthesized_templates`` keep the two groups apart; and
    ``summary.by_template_group`` has to agree with both, which is what makes the
    separation more than a pair of labels.
    """
    layout = LAYOUTS[layout_name]
    workspace = make_project(tmp_path / "workspace", layout.files)

    run = run_review(
        orchestrator,
        ["--target", ".", *IAM_ONLY],
        workspace=workspace,
        monkeypatch=monkeypatch,
        capsys=capsys,
    )

    assert_no_traceback(run)
    assert run.exit_code == layout.exit_code
    assert run.report is not None
    target = run.report["target"]
    assert target["cdk"]["detected"] is layout.detected
    # Requirement 23 AC1/AC5: the synthesis outcome tells a skipped synthesis
    # apart from a non-CDK target, so an empty finding set is not read as clean.
    assert target["cdk"]["synthesis"] == layout.synthesis
    assert target["files"] == layout.standalone
    assert target["cdk"]["synthesized_templates"] == layout.synthesized

    # The two arrays are disjoint, so the group counts partition the Findings
    # rather than double-counting any of them.
    assert set(target["files"]).isdisjoint(target["cdk"]["synthesized_templates"])
    groups = run.report["summary"]["by_template_group"]
    assert groups["standalone"] + groups["synthesized"] == run.report["summary"][
        "total"
    ]
    # AC9: each group's Templates were put through the pipeline, not just listed.
    assert (groups["standalone"] > 0) is bool(layout.standalone)
    assert (groups["synthesized"] > 0) is bool(layout.synthesized)

    # Requirement 16 AC11: no host path reaches stdout, whichever layout it was.
    assert str(workspace) not in run.stdout


@pytest.mark.parametrize("layout_name", sorted(LAYOUTS))
def test_the_skipped_synthesis_is_recorded_for_a_project_and_only_for_a_project(
    orchestrator: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
    empty_path: Path,
    tmp_path: Path,
    layout_name: str,
) -> None:
    """Requirement 8 AC5: narrower coverage is stated, never silent.

    The ``invalid_arguments`` entry appears exactly for the three layouts holding
    a ``cdk.json`` and is absent from the fourth, where there was no synthesis to
    skip. Its message carries :data:`iacreview.cdk.SYNTH_WARNING` verbatim so a
    consumer reading only the report sees the same wording the host agent is
    meant to show the user (AC4, AC11).
    """
    layout = LAYOUTS[layout_name]
    workspace = make_project(tmp_path / "workspace", layout.files)

    run = run_review(
        orchestrator,
        ["--target", ".", *IAM_ONLY],
        workspace=workspace,
        monkeypatch=monkeypatch,
        capsys=capsys,
    )

    assert run.report is not None
    if not layout.detected:
        assert "invalid_arguments" not in error_classes(run.report)
        assert cdk.SYNTH_WARNING not in run.stderr
        return

    entry = error_of_class(run.report, "invalid_arguments")
    assert cdk.SYNTH_NOT_CONFIRMED_NOTICE in str(entry["message"])
    assert cdk.SYNTH_WARNING in str(entry["message"])
    assert "--confirm-cdk-synth" in str(entry["remediation"])
    # Stated on stderr too, by iacreview.cdk itself, so the risk is on the
    # record even for a caller that never reads the report.
    assert cdk.SYNTH_WARNING in run.stderr


def test_standalone_templates_are_reviewed_first(
    orchestrator: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
    empty_path: Path,
    tmp_path: Path,
) -> None:
    """Requirement 8 AC10's first half, in the mixed layout.

    Review *order* is not visible in the report -- Findings are emitted per
    Template in sorted path order -- so it is read from the per-Template
    diagnostics ``--verbose`` writes as each Source finishes. The standalone
    Template lives at ``templates/standalone.yaml``, which sorts *after*
    ``cdk.out/AppStack.template.json``: a run that reviewed in sorted order
    rather than in group order would fail this.
    """
    layout = LAYOUTS["cdk-json-standalone-and-assembly"]
    workspace = make_project(tmp_path / "workspace", layout.files)

    run = run_review(
        orchestrator,
        ["--target", ".", "--verbose", *IAM_ONLY],
        workspace=workspace,
        monkeypatch=monkeypatch,
        capsys=capsys,
    )

    assert run.exit_code == exitcodes.OK
    lines = [
        line
        for line in run.stderr.splitlines()
        if line.startswith((STANDALONE_FILE + ":", SYNTHESIZED_FILE + ":"))
    ]
    assert lines, run.stderr
    assert lines[0].startswith(STANDALONE_FILE + ":")
    assert any(line.startswith(SYNTHESIZED_FILE + ":") for line in lines)
    assert SYNTHESIZED_FILE < STANDALONE_FILE, (
        "the fixture no longer distinguishes review order from sort order"
    )


def test_a_synthesized_template_named_directly_stays_in_the_synthesized_group(
    orchestrator: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
    empty_path: Path,
    tmp_path: Path,
) -> None:
    """Requirement 8 AC10's second half, at the one point the split can blur.

    Naming ``cdk.out/AppStack.template.json`` as a ``--target`` in its own right
    puts it in the directory scan's group *and* in the cloud assembly's. It
    belongs to the second -- that is where it came from -- and the arrays must
    stay disjoint so ``summary.by_template_group`` still partitions the Findings.
    """
    layout = LAYOUTS["cdk-json-and-assembly"]
    workspace = make_project(tmp_path / "workspace", layout.files)

    run = run_review(
        orchestrator,
        ["--target", ".", "--target", SYNTHESIZED_FILE, *IAM_ONLY],
        workspace=workspace,
        monkeypatch=monkeypatch,
        capsys=capsys,
    )

    assert run.exit_code == exitcodes.OK
    assert run.report is not None
    target = run.report["target"]
    assert target["files"] == []
    assert target["cdk"]["synthesized_templates"] == [SYNTHESIZED_FILE]
    summary = run.report["summary"]
    assert summary["total"] > 0
    assert summary["by_template_group"]["synthesized"] == summary["total"]
    assert summary["by_template_group"]["standalone"] == 0


# ---------------------------------------------------------------------------
# (d) No cdk process without --confirm-cdk-synth
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("layout_name", sorted(LAYOUTS))
def test_no_cdk_process_is_started_for_any_layout_without_confirmation(
    orchestrator: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
    fakebin_dir: Path,
    tmp_path: Path,
    layout_name: str,
) -> None:
    """Requirement 8 AC3, across every layout, with a CLI that would have worked.

    The security assertion of this module. A working ``cdk`` is on ``PATH`` and
    configured to write a Template, so an empty recorder means *nothing was
    started*, not *nothing was available* -- which is the entire difference the
    confirmation gate makes.

    Three independent signals, because a gate that failed would want to be caught
    by more than one: no call reached :func:`iacreview.proc.run`, no ``cdk.out``
    appeared where the fake would have written one, and the tripwire the
    ``cdk.json`` names did not run.
    """
    layout = LAYOUTS[layout_name]
    workspace = make_project(tmp_path / "workspace", layout.files)
    use_cdk_fake(
        monkeypatch,
        fakebin_dir,
        "configured",
        config={},
        config_dir=tmp_path / "fakecfg",
    )
    calls = forbid_processes(monkeypatch)
    existing = set(layout.synthesized)

    run = run_review(
        orchestrator,
        ["--target", ".", *IAM_ONLY],
        workspace=workspace,
        monkeypatch=monkeypatch,
        capsys=capsys,
    )

    assert calls == []
    assert_no_traceback(run)
    assert run.exit_code == layout.exit_code
    assert run.report is not None
    # Nothing new under cdk.out: the fake's default template is named
    # FakeStack.template.json, and it is nowhere.
    assert run.report["target"]["cdk"]["synthesized_templates"] == sorted(existing)
    assert not (workspace / "cdk.out" / "FakeStack.template.json").exists()


def test_the_confirmation_flag_starts_nothing_when_the_target_is_not_a_project(
    orchestrator: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
    fakebin_dir: Path,
    tmp_path: Path,
) -> None:
    """The flag permits a synthesis; it does not request one.

    Requirement 8 AC2 makes ``cdk.json`` the thing that identifies a project, so
    a directory without one has no project code to run and the flag is inert. The
    review continues normally, and ``--verbose`` says the flag had no effect --
    which is the honest answer to a caller who passed it by habit.
    """
    layout = LAYOUTS["standalone-only"]
    workspace = make_project(tmp_path / "workspace", layout.files)
    use_cdk_fake(
        monkeypatch,
        fakebin_dir,
        "configured",
        config={},
        config_dir=tmp_path / "fakecfg",
    )
    calls = forbid_processes(monkeypatch)

    run = run_review(
        orchestrator,
        ["--target", ".", "--confirm-cdk-synth", "--verbose", *IAM_ONLY],
        workspace=workspace,
        monkeypatch=monkeypatch,
        capsys=capsys,
    )

    assert calls == []
    assert run.exit_code == exitcodes.OK
    assert run.report is not None
    assert run.report["target"]["files"] == [STANDALONE_FILE]
    assert run.report["target"]["cdk"]["detected"] is False
    assert "--confirm-cdk-synth has no effect" in run.stderr
    assert cdk.CDK_CONFIG_FILENAME in run.stderr


# ---------------------------------------------------------------------------
# (b) A confirmed synthesis, and where its output lands
# ---------------------------------------------------------------------------


def test_a_confirmed_synthesis_writes_into_the_project_and_is_reviewed(
    orchestrator: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
    fakebin_dir: Path,
    tmp_path: Path,
) -> None:
    """Requirement 8 AC1, AC6, AC9: the confirmed path, end to end, without Node.

    The project is a *subdirectory* of the workspace, and the fake writes
    ``cdk.out`` relative to its own working directory. So the Template landing
    under ``project/cdk.out`` rather than beside the workspace root is the
    evidence that :func:`iacreview.cdk.synth_if_confirmed` performed its
    ``chdir``: the CDK CLI has no flag naming the project directory, and a lost
    ``chdir`` would synthesize somewhere else in silence.

    The synthesized Template carries a wildcard IAM policy, so the Findings
    attributed to it prove it went through the pipeline and not merely into a
    list.
    """
    workspace = tmp_path / "workspace"
    project = make_project(
        workspace / "project",
        {"cdk.json": CDK_CONFIG_TEXT, "app.py": TRIPWIRE_TEXT},
    )
    use_cdk_fake(
        monkeypatch,
        fakebin_dir,
        "configured",
        config={
            "templates": {
                "AppStack.template.json": _iam_template_json("SynthesizedRole")
            }
        },
        config_dir=tmp_path / "fakecfg",
    )

    run = run_review(
        orchestrator,
        ["--target", "project", "--confirm-cdk-synth", *IAM_ONLY],
        workspace=workspace,
        monkeypatch=monkeypatch,
        capsys=capsys,
    )

    assert_no_traceback(run)
    assert run.exit_code == exitcodes.OK
    # The chdir, observed on the filesystem.
    assert (project / "cdk.out" / "AppStack.template.json").is_file()
    assert not (workspace / "cdk.out").exists()

    assert run.report is not None
    target = run.report["target"]
    assert target["cdk"]["detected"] is True
    # Requirement 23 AC1: synthesis ran on the confirmed path.
    assert target["cdk"]["synthesis"] == "ran"
    assert target["cdk"]["synthesized_templates"] == [
        "project/cdk.out/AppStack.template.json"
    ]
    assert target["files"] == []
    summary = run.report["summary"]
    assert summary["total"] > 0
    assert summary["by_template_group"]["synthesized"] == summary["total"]
    # AC4, AC11: the warning is stated even on the confirmed path.
    assert cdk.SYNTH_WARNING in run.stderr


# ---------------------------------------------------------------------------
# (e) Confirmed, with no CDK CLI
# ---------------------------------------------------------------------------


def test_an_absent_cdk_cli_is_reported_with_the_official_documentation_url(
    orchestrator: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
    fakebin_dir: Path,
    tmp_path: Path,
) -> None:
    """Requirement 8 AC8, plus AC7 applied to a synthesis that never started.

    The layout holds a standalone Template that would have been reviewable on its
    own, and the report contains no Finding: with no CLI there is no current
    Template for the project, and reporting a partial review as though it were
    the whole one is the fallback AC7 forbids.
    """
    layout = LAYOUTS["cdk-json-standalone-and-assembly"]
    workspace = make_project(tmp_path / "workspace", layout.files)
    use_cdk_fake(monkeypatch, fakebin_dir, "missing")

    run = run_review(
        orchestrator,
        ["--target", ".", "--confirm-cdk-synth", *IAM_ONLY],
        workspace=workspace,
        monkeypatch=monkeypatch,
        capsys=capsys,
    )

    assert_no_traceback(run)
    assert run.exit_code == exitcodes.TOOL_UNAVAILABLE
    assert run.report is not None
    assert error_classes(run.report) == ["tool_unavailable"]
    entry = run.report["errors"][0]
    assert entry["tool"] == CDK
    assert "docs.aws.amazon.com/cdk" in str(entry["remediation"])
    assert entry["required_min_version"] == "2.0.0"
    assert run.report["findings"] == []
    # Not even the pre-existing cloud assembly is offered as a substitute.
    assert run.report["target"]["cdk"]["synthesized_templates"] == []
    assert run.report["target"]["files"] == []


# ---------------------------------------------------------------------------
# (f) Confirmed, and the synthesis fails
# ---------------------------------------------------------------------------


def test_a_crashing_synthesis_reports_its_stderr_and_keeps_the_stale_assembly_out(
    orchestrator: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
    fakebin_dir: Path,
    tmp_path: Path,
) -> None:
    """Requirement 8 AC6, AC7 with ``fakebin/cdk-crash``.

    ``cdk.out`` is pre-populated, which is what gives the assertion teeth: a
    report built from it would describe a review of a Template that no longer
    corresponds to the project's source -- worse than reporting the failure. The
    file stays on disk (nothing here deletes anything) and stays out of the
    report.
    """
    layout = LAYOUTS["cdk-json-and-assembly"]
    workspace = make_project(tmp_path / "workspace", layout.files)
    stale = workspace / SYNTHESIZED_FILE
    use_cdk_fake(monkeypatch, fakebin_dir, "crash")

    run = run_review(
        orchestrator,
        ["--target", ".", "--confirm-cdk-synth", *IAM_ONLY],
        workspace=workspace,
        monkeypatch=monkeypatch,
        capsys=capsys,
    )

    assert_no_traceback(run)
    assert run.exit_code == exitcodes.TOOL_EXECUTION_FAILURE
    assert run.report is not None
    entry = error_of_class(run.report, "tool_execution")
    assert entry["tool"] == CDK
    assert entry["exit_code"] == 1
    # The fake's own two lines, reported in order. The first names an absolute
    # path (``/nonexistent``), which Task 34 redaction collapses to
    # ``<path>`` before it reaches the report (Requirement 16 AC11,
    # Requirement 18 AC2): the crash stderr is still reported, but the host
    # path in it is withheld. The non-path text of both lines survives verbatim,
    # which is what carries the intent that a crash's stderr is transcribed.
    assert entry["stderr_head"] == [
        "Error: Cannot find asset at <path>",
        "    at Object.synth (fake cdk)",
    ]
    assert entry["remediation"] == cdk.NO_FALLBACK_REMEDIATION
    # AC7: no alternative execution mode, and no stale template in its place.
    assert stale.is_file()
    assert run.report["target"]["cdk"]["synthesized_templates"] == []
    assert run.report["findings"] == []


def test_a_long_synthesis_error_is_truncated_to_five_stderr_lines(
    orchestrator: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
    fakebin_dir: Path,
    tmp_path: Path,
) -> None:
    """The bound on ``stderr_head``, which ``cdk-crash``'s two lines cannot show.

    A real failing synthesis writes a stack trace of tens of lines. The report
    carries the first :data:`~iacreview.errors.STDERR_HEAD_MAX_LINES` and stops,
    so an error message cannot grow the report without bound; the configurable
    fake is the only way to produce more lines than the bound on demand.
    """
    layout = LAYOUTS["cdk-json-only"]
    workspace = make_project(tmp_path / "workspace", layout.files)
    lines = ["synth line {0}".format(index) for index in range(1, 9)]
    use_cdk_fake(
        monkeypatch,
        fakebin_dir,
        "configured",
        config={"exit_code": 3, "stderr": "\n".join(lines) + "\n", "templates": {}},
        config_dir=tmp_path / "fakecfg",
    )

    run = run_review(
        orchestrator,
        ["--target", ".", "--confirm-cdk-synth", *IAM_ONLY],
        workspace=workspace,
        monkeypatch=monkeypatch,
        capsys=capsys,
    )

    assert_no_traceback(run)
    assert run.exit_code == exitcodes.TOOL_EXECUTION_FAILURE
    assert run.report is not None
    entry = error_of_class(run.report, "tool_execution")
    assert entry["exit_code"] == 3
    assert entry["stderr_head"] == lines[:STDERR_HEAD_MAX_LINES]
    assert len(entry["stderr_head"]) == 5


# ---------------------------------------------------------------------------
# (g) The timeout handed to proc.run
# ---------------------------------------------------------------------------


def test_the_synth_argv_and_the_120_second_timeout_reach_proc_run(
    orchestrator: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
    fakebin_dir: Path,
    tmp_path: Path,
) -> None:
    """Requirement 8 AC6, read off the call rather than off the clock.

    Elapsing the documented 120 seconds is not a test anyone would run, so the
    call itself is captured: the version check is delegated to the real fake, and
    the ``synth`` call is intercepted and answered with the timeout it would have
    produced. What is asserted is that the timeout ``iacreview.cdk`` documents is
    the timeout the process wrapper receives, and that the command line is the
    two plugin-owned literals with nothing appended (Requirement 9 AC4).
    """
    layout = LAYOUTS["cdk-json-only"]
    workspace = make_project(tmp_path / "workspace", layout.files)
    fake_dir = use_cdk_fake(monkeypatch, fakebin_dir, "timeout")
    real_run = proc.run
    recorded: List[Dict[str, Any]] = []

    def intercept_synth(argv: Sequence[str], timeout_s: int) -> Any:
        if cdk.SYNTH_SUBCOMMAND not in argv:
            # The --version call of the version gate, which must still happen:
            # a synth is not attempted against an unverified CLI.
            return real_run(list(argv), timeout_s=timeout_s)
        recorded.append({"argv": list(argv), "timeout_s": timeout_s})
        raise ToolTimeoutError(
            "{0} exceeded its {1}s timeout".format(argv[0], timeout_s),
            tool=str(argv[0]),
            stderr="synth stalled\nsecond line\n",
        )

    monkeypatch.setattr(proc, "run", intercept_synth)

    run = run_review(
        orchestrator,
        ["--target", ".", "--confirm-cdk-synth", *IAM_ONLY],
        workspace=workspace,
        monkeypatch=monkeypatch,
        capsys=capsys,
    )

    assert len(recorded) == 1, recorded
    call = recorded[0]
    assert call["timeout_s"] == 120
    assert call["timeout_s"] == cdk.SYNTH_TIMEOUT_S
    # Two elements, both literals owned by iacreview.cdk. argv[0] is the absolute
    # path of the binary whose version was just verified, so the CLI that ran is
    # the CLI that was checked.
    assert len(call["argv"]) == 2
    assert Path(call["argv"][0]) == fake_dir / CDK
    assert call["argv"][1] == cdk.SYNTH_SUBCOMMAND

    assert_no_traceback(run)
    assert run.exit_code == exitcodes.TOOL_EXECUTION_FAILURE
    assert run.report is not None
    entry = error_of_class(run.report, "tool_timeout")
    # The bare name, not the absolute path proc.run was handed: Requirement 16
    # AC11 keeps the host's directory layout out of stdout.
    assert entry["tool"] == CDK
    assert entry["stderr_head"] == ["synth stalled", "second line"]
    assert entry["remediation"] == cdk.NO_FALLBACK_REMEDIATION
    assert str(fake_dir) not in run.stdout


def test_a_hanging_synthesis_is_terminated_and_reported_without_a_fallback(
    orchestrator: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
    fakebin_dir: Path,
    tmp_path: Path,
) -> None:
    """The same outcome with the timeout actually elapsed, at two seconds.

    The captured-call test above proves the *documented* budget is the one handed
    over; this one proves the wrapper really does terminate the child and that
    the resulting report reaches the same place as a crash: no stale ``cdk.out``,
    no Findings. Only the shortened budget differs from a real 120-second wait.
    """
    layout = LAYOUTS["cdk-json-and-assembly"]
    workspace = make_project(tmp_path / "workspace", layout.files)
    stale = workspace / SYNTHESIZED_FILE
    use_cdk_fake(monkeypatch, fakebin_dir, "timeout")
    monkeypatch.setattr(cdk, "SYNTH_TIMEOUT_S", SHORT_TIMEOUT_S)

    run = run_review(
        orchestrator,
        ["--target", ".", "--confirm-cdk-synth", *IAM_ONLY],
        workspace=workspace,
        monkeypatch=monkeypatch,
        capsys=capsys,
    )

    assert_no_traceback(run)
    assert run.exit_code == exitcodes.TOOL_EXECUTION_FAILURE
    assert run.report is not None
    entry = error_of_class(run.report, "tool_timeout")
    assert entry["tool"] == CDK
    assert entry["remediation"] == cdk.NO_FALLBACK_REMEDIATION
    assert stale.is_file()
    assert run.report["target"]["cdk"]["synthesized_templates"] == []
    assert run.report["findings"] == []


# ---------------------------------------------------------------------------
# (h) Confirmed synthesis that produces nothing reviewable
# ---------------------------------------------------------------------------


def test_a_synthesis_that_succeeds_without_producing_a_template_is_not_reviewable(
    orchestrator: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
    fakebin_dir: Path,
    tmp_path: Path,
) -> None:
    """Exit 8 rather than 6: nothing failed, and nothing came out either.

    The counterpart of the unconfirmed ``cdk.json``-only layout. A CDK app whose
    stacks are all inside a stage, or one that produced only assets, synthesizes
    successfully and leaves no top-level ``*.template.json``. That is a coverage
    answer, not a tool failure, so it reads as ``no_reviewable_template``.
    """
    layout = LAYOUTS["cdk-json-only"]
    workspace = make_project(tmp_path / "workspace", layout.files)
    use_cdk_fake(
        monkeypatch,
        fakebin_dir,
        "configured",
        config={"templates": {}},
        config_dir=tmp_path / "fakecfg",
    )

    run = run_review(
        orchestrator,
        ["--target", ".", "--confirm-cdk-synth", *IAM_ONLY],
        workspace=workspace,
        monkeypatch=monkeypatch,
        capsys=capsys,
    )

    assert_no_traceback(run)
    assert run.exit_code == exitcodes.NO_REVIEWABLE_TEMPLATE
    assert run.report is not None
    assert "no_reviewable_template" in error_classes(run.report)
    assert run.report["target"]["cdk"]["detected"] is True
    assert run.report["target"]["cdk"]["synthesized_templates"] == []
    assert run.report["findings"] == []


# ---------------------------------------------------------------------------
# Requirement 8 AC11: one wording for the risk
# ---------------------------------------------------------------------------


def test_the_orchestrator_skill_documentation_quotes_the_synthesis_warning(
    plugin_root: Path,
) -> None:
    """Requirement 8 AC11, held to :data:`iacreview.cdk.SYNTH_WARNING`.

    The Skill documentation is what a host agent shows the user before adding
    ``--confirm-cdk-synth`` (AC4), so a documented wording that had drifted from
    the constant would mean the user consented to a description of the risk that
    the code does not make. ``tests/integration/test_examples.py`` holds the same
    constant to ``examples/cdk-synth-output/README.md``; this is the Skill's copy.

    Three things are normalized away before comparing, all of them Markdown
    rather than wording: blockquote markers, line wrapping, and the backticks
    SKILL.md puts around ``cdk synth`` to render it as inline code. Every word
    still has to match, so any drift in what the risk *says* fails this.
    """
    text = (plugin_root / ORCHESTRATOR_SKILL_DOC).read_text(encoding="utf-8")
    unquoted = " ".join(line.lstrip("> ") for line in text.splitlines())
    rendered = " ".join(unquoted.replace("`", "").split())
    assert " ".join(cdk.SYNTH_WARNING.split()) in rendered


def test_this_module_never_resolves_a_real_cdk_cli(
    empty_path: Path,
) -> None:
    """The premise every test here rests on, asserted rather than assumed.

    A ``cdk`` reachable on the inherited ``PATH`` would turn the gating tests
    into a real synthesis of a fake project -- which is exactly the arbitrary
    code execution the gate exists to prevent. The :func:`empty_path` fixture
    replaces ``PATH`` outright, so there is nothing to resolve; this states that
    the replacement works, independently of any fake being installed.
    """
    assert shutil.which(CDK) is None
    assert list(empty_path.iterdir()) == []
