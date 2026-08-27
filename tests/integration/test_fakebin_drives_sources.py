"""Each fake in ``tests/fakebin``, driven through the code path it exists to serve.

``tests/unit/test_fakebin.py`` checks the fakes in isolation: exit codes, banners,
permissions. That is not enough to trust them. A fake can be perfectly
well-behaved on its own and still fail to reach the branch it was written for --
by answering ``--version`` in a way that sends the Source down the
:data:`~iacreview.toolcheck.UNKNOWN_VERSION` path before the interesting code
runs, or by writing its payload somewhere the Source does not look. This module
closes that gap by asserting the *outcome each fake produces in the plugin*:

* ``<tool>-missing/``     -> ``tool_unavailable``
* ``<tool>-crash/``       -> ``tool_execution``
* ``<tool>-oldversion/``  -> ``tool_version``
* ``<tool>-timeout/``     -> ``tool_timeout``
* ``<tool>-configured/``  -> findings, a clean run, unusable output, or an
                             unreadable version banner, on demand

Together those are the tool-present-but-misbehaving half of the Tool Unavailable
Test that steering/testing.md requires for cfn-lint, cfn-guard and the AWS CDK,
and they satisfy Requirement 12 AC7 for all three tools: a structured error
carrying the tool name and installation instructions, and no unhandled exception.

Scope. This file proves the *fakes* work. The exhaustive 3-tools x 4-situations
matrix, the standalone-versus-orchestrated exit codes, and the eight CDK layout
cases belong to Tasks 24.3 and 24.6 and are not duplicated here.

``PATH`` is stated explicitly in every test and never inherited. The point of a
fake is that it is the only thing resolvable, and a test that let the real tool
through would assert something other than what it claims. The real cfn-guard is
installed on many development machines, so this matters in practice and not only
in principle.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from iacreview import cdk, cfnguard, cfnlint, toolcheck
from iacreview.errors import (
    ToolExecutionError,
    ToolTimeoutError,
    ToolUnavailableError,
    ToolVersionError,
)

# A Template that parses and holds a resource. Which resource does not matter:
# every fake ignores its input, and these tests assert on the Source's handling
# of the tool, not on any rule.
TEMPLATE_TEXT = """\
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  DataBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256
"""

#: Short enough that a timeout test finishes quickly, long enough that a fake
#: which answers immediately is not mistaken for one that hung.
SHORT_TIMEOUT_S = 2


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """A workspace root holding one reviewable Template at ``template.yaml``."""
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "template.yaml").write_text(TEMPLATE_TEXT, encoding="utf-8")
    return root


def use_fake(
    monkeypatch: pytest.MonkeyPatch,
    fakebin_dir: Path,
    tool: str,
    scenario: str,
    *,
    config: Optional[Dict[str, Any]] = None,
    config_dir: Optional[Path] = None,
) -> None:
    """Point ``PATH`` at one fake, and nothing else, for the duration of a test.

    Args:
        monkeypatch: pytest's environment patcher.
        fakebin_dir: ``tests/fakebin``.
        tool: ``"cfn-lint"``, ``"cfn-guard"`` or ``"cdk"``.
        scenario: A directory suffix -- ``missing``, ``crash``, ``oldversion``,
            ``timeout`` or ``configured``.
        config: Configuration for a ``configured`` fake. Written to
            ``<config_dir>/fake-<tool>.json``, which is where the fake looks.
        config_dir: Directory handed to the fake as ``TMPDIR``. Required
            whenever ``config`` is given.

    The interpreter's directory joins ``PATH`` only for the ``configured``
    fakes, which are ``#!/usr/bin/env python3`` scripts and would otherwise exit
    127 when ``env`` failed to find ``python3``. The scenario fakes are
    ``#!/bin/sh``, so their directory alone is enough -- which is what lets a
    ``missing`` test set ``PATH`` to a single empty directory and mean it.
    """
    if tool == "cfn-lint" and scenario == "configured":
        # cfn-lint's configurable fake predates the per-scenario layout and sits
        # at the top level of tests/fakebin; see tests/unit/test_fakebin.py.
        directory = fakebin_dir
    else:
        directory = fakebin_dir / "{0}-{1}".format(tool, scenario)

    entries: List[str] = [str(directory)]
    if scenario == "configured":
        entries.append(str(Path(sys.executable).parent))
    monkeypatch.setenv("PATH", os.pathsep.join(entries))

    if config is not None:
        assert config_dir is not None, "config requires a config_dir"
        filename = "fake-{0}.json".format(tool)
        (config_dir / filename).write_text(json.dumps(config), encoding="utf-8")
        # TMPDIR is the channel because iacreview.proc hands children an
        # environment allowlist so AWS credentials cannot reach a static
        # analyzer. An invented variable would be dropped and never arrive.
        monkeypatch.setenv("TMPDIR", str(config_dir))


def only_error(result: Any) -> Dict[str, Any]:
    """Return the single StructuredError on ``result``, failing if there is not one."""
    assert result.findings == []
    assert len(result.errors) == 1, result.errors
    return result.errors[0]


def cfnlint_results(template_file: str) -> str:
    """One cfn-lint Error result, as the fake's ``results_text`` payload."""
    return json.dumps(
        [
            {
                "Filename": template_file,
                "Level": "Error",
                "Location": {
                    "Start": {"LineNumber": 4, "ColumnNumber": 5},
                    "Path": ["Resources", "DataBucket", "Type"],
                },
                "Message": "Fake finding produced by the fake cfn-lint",
                "Rule": {
                    "Id": "E3002",
                    "ShortDescription": "Resource properties are invalid",
                    "Description": "Making sure resource properties are configured",
                    "Source": "https://example.invalid/rules#E3002",
                },
            }
        ]
    )


def guard_violation_records() -> str:
    """One cfn-guard record carrying one violated rule, as a JSON stream.

    ``s3_bucket_encryption`` is a real rule under ``rules/``, so the metadata
    sidecar lookup resolves and the resulting Finding carries a Severity that
    came from the rule set rather than from the hardcoded fallback.
    """
    return json.dumps(
        {
            "name": "template.yaml",
            "metadata": {},
            "status": "FAIL",
            "not_compliant": [
                {
                    "Rule": {
                        "name": "s3_bucket_encryption",
                        "metadata": {},
                        "messages": {"custom_message": None, "error_message": None},
                        "checks": [
                            {
                                "Clause": {
                                    "Unary": {
                                        "check": {
                                            "UnResolved": {
                                                "value": {
                                                    "traversed_to": {
                                                        "path": (
                                                            "/Resources/DataBucket"
                                                            "/Properties"
                                                        ),
                                                        "value": {},
                                                    },
                                                    "remaining_query": (
                                                        "BucketEncryption"
                                                    ),
                                                    "reason": "not found",
                                                },
                                                "comparison": ["Exists", False],
                                            }
                                        },
                                        "context": (
                                            " %s3_buckets[*].Properties"
                                            ".BucketEncryption EXISTS  "
                                        ),
                                        "messages": {
                                            "custom_message": (
                                                " Server side encryption is not "
                                                "configured on this bucket. "
                                            ),
                                            "error_message": (
                                                "Check was not compliant as "
                                                "property [BucketEncryption] is "
                                                "missing."
                                            ),
                                        },
                                    }
                                }
                            }
                        ],
                    }
                }
            ],
            "not_applicable": [],
            "compliant": [],
        }
    )


# ---------------------------------------------------------------------------
# cfn-lint
# ---------------------------------------------------------------------------


def test_cfn_lint_missing_is_reported_with_the_pip_install_command(
    monkeypatch: pytest.MonkeyPatch, fakebin_dir: Path, workspace: Path
) -> None:
    """Requirement 12 AC7 and Requirement 4 AC10, through the empty directory."""
    use_fake(monkeypatch, fakebin_dir, "cfn-lint", "missing")

    result = cfnlint.run_and_normalize(
        workspace / "template.yaml", workspace_root=workspace
    )

    error = only_error(result)
    assert error["error_class"] == "tool_unavailable"
    assert error["tool"] == "cfn-lint"
    assert "pip install cfn-lint" in error["remediation"]
    assert error["required_min_version"] == "1.0.0"


def test_cfn_lint_crash_is_reported_as_a_tool_execution_failure(
    monkeypatch: pytest.MonkeyPatch, fakebin_dir: Path, workspace: Path
) -> None:
    """Requirement 4 AC12: exit 1 is a crash, not a finding count.

    The fake answers ``--version`` with a supported version, so this asserts a
    failure during analysis rather than a version gate that happened to reject
    the tool first -- two different branches that produce two different
    ``error_class`` values.
    """
    use_fake(monkeypatch, fakebin_dir, "cfn-lint", "crash")

    result = cfnlint.run_and_normalize(
        workspace / "template.yaml", workspace_root=workspace
    )

    error = only_error(result)
    assert error["error_class"] == "tool_execution"
    assert error["tool"] == "cfn-lint"
    assert error["exit_code"] == 1
    assert 0 < len(error["stderr_head"]) <= 5
    assert result.stats["tool_version"] == "1.22.0"


def test_cfn_lint_below_the_minimum_version_is_reported_with_an_upgrade_command(
    monkeypatch: pytest.MonkeyPatch, fakebin_dir: Path, workspace: Path
) -> None:
    """Requirement 15 AC6: detected, required, and how to upgrade."""
    use_fake(monkeypatch, fakebin_dir, "cfn-lint", "oldversion")

    result = cfnlint.run_and_normalize(
        workspace / "template.yaml", workspace_root=workspace
    )

    error = only_error(result)
    assert error["error_class"] == "tool_version"
    assert error["detected_version"] == "0.83.0"
    assert error["required_min_version"] == "1.0.0"
    assert "pip install --upgrade cfn-lint" in error["remediation"]


def test_cfn_lint_that_hangs_is_reported_as_a_timeout(
    monkeypatch: pytest.MonkeyPatch, fakebin_dir: Path, workspace: Path
) -> None:
    """The Source's own timeout, shortened so the test does not wait 60 seconds.

    The fake answers ``--version`` at once and hangs only on the analysis, which
    is what keeps the 10-second version-check timeout out of this test.
    """
    use_fake(monkeypatch, fakebin_dir, "cfn-lint", "timeout")
    monkeypatch.setattr(cfnlint, "TIMEOUT_S", SHORT_TIMEOUT_S)

    result = cfnlint.run_and_normalize(
        workspace / "template.yaml", workspace_root=workspace
    )

    error = only_error(result)
    assert error["error_class"] == "tool_timeout"
    assert error["remediation"]
    # The bare name, although run_and_normalize passes ToolInfo.path as argv[0]
    # so the version-checked binary is the one that runs: iacreview.proc reports
    # the basename of argv[0], which keeps the resolved absolute path out of the
    # report (Requirement 16 AC11). tests/integration/test_tool_unavailable.py
    # asserts that property across all twelve tool situations.
    assert error["tool"] == "cfn-lint"


def test_the_configured_cfn_lint_produces_the_findings_it_was_given(
    monkeypatch: pytest.MonkeyPatch,
    fakebin_dir: Path,
    workspace: Path,
    tmp_path: Path,
) -> None:
    """The fake's whole reason for existing: a known payload, normalized."""
    use_fake(
        monkeypatch,
        fakebin_dir,
        "cfn-lint",
        "configured",
        config={"results_text": cfnlint_results("template.yaml")},
        config_dir=tmp_path,
    )

    result = cfnlint.run_and_normalize(
        workspace / "template.yaml", workspace_root=workspace
    )

    assert result.errors == []
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.Source == ["cfn-lint"]
    assert finding.Location.File == "template.yaml"
    assert finding.Resource == "DataBucket"
    assert "E3002" in {entry.RuleId for entry in finding.Evidence}


def test_the_configured_cfn_lint_can_produce_output_that_does_not_parse(
    monkeypatch: pytest.MonkeyPatch,
    fakebin_dir: Path,
    workspace: Path,
    tmp_path: Path,
) -> None:
    """A ``parse_failure`` needs stdout that is not the expected structure.

    Reachable only through a fake: real cfn-lint does not emit broken JSON on
    request. The payload is written verbatim by the fake for exactly this reason.
    """
    use_fake(
        monkeypatch,
        fakebin_dir,
        "cfn-lint",
        "configured",
        config={"results_text": '[{"Level": "Error", ', "exit_code": 2},
        config_dir=tmp_path,
    )

    result = cfnlint.run_and_normalize(
        workspace / "template.yaml", workspace_root=workspace
    )

    error = only_error(result)
    assert error["error_class"] == "parse_failure"
    assert error["tool"] == "cfn-lint"


def test_the_configured_cfn_lint_can_produce_an_unreadable_version_banner(
    monkeypatch: pytest.MonkeyPatch,
    fakebin_dir: Path,
    workspace: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture,
) -> None:
    """An unparsable banner warns and continues; it is not a failure.

    :mod:`iacreview.toolcheck` chooses this deliberately: refusing to run
    against a build whose banner format changed would be a worse outcome than
    running unverified. The warning goes to stderr, never to stdout, which must
    stay byte-stable.
    """
    use_fake(
        monkeypatch,
        fakebin_dir,
        "cfn-lint",
        "configured",
        config={"version_text": "cfn-lint, version unavailable\n"},
        config_dir=tmp_path,
    )

    result = cfnlint.run_and_normalize(
        workspace / "template.yaml", workspace_root=workspace
    )

    assert result.errors == []
    assert result.stats["tool_version"] == toolcheck.UNKNOWN_VERSION
    assert "could not parse a version" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# cfn-guard
# ---------------------------------------------------------------------------


def test_cfn_guard_missing_is_reported_with_its_installation_documentation(
    monkeypatch: pytest.MonkeyPatch, fakebin_dir: Path, workspace: Path
) -> None:
    """Requirement 12 AC7 and Requirement 5 AC5.

    cfn-guard has no single install command that works everywhere, which is why
    its remediation carries the upstream documentation URL as well.
    """
    use_fake(monkeypatch, fakebin_dir, "cfn-guard", "missing")

    result = cfnguard.run_and_normalize(
        workspace / "template.yaml", workspace_root=workspace
    )

    error = only_error(result)
    assert error["error_class"] == "tool_unavailable"
    assert error["tool"] == "cfn-guard"
    assert "cloudformation-guard" in error["remediation"]
    assert error["required_min_version"] == "3.0.0"


def test_cfn_guard_crash_is_reported_as_a_tool_execution_failure(
    monkeypatch: pytest.MonkeyPatch, fakebin_dir: Path, workspace: Path
) -> None:
    """Requirement 5 AC6, AC7: classified by empty stdout, not by the code 255.

    The fake reproduces what cfn-guard 3.2.1 was measured to do on failure --
    exit 255, nothing on stdout, the explanation on stderr -- and the Source
    classifies it as a tool error because stdout does not parse.
    """
    use_fake(monkeypatch, fakebin_dir, "cfn-guard", "crash")

    result = cfnguard.run_and_normalize(
        workspace / "template.yaml", workspace_root=workspace
    )

    error = only_error(result)
    assert error["error_class"] == "tool_execution"
    assert error["tool"] == "cfn-guard"
    assert error["exit_code"] == 255
    assert 0 < len(error["stderr_head"]) <= 5


def test_cfn_guard_below_the_minimum_version_is_reported_with_an_upgrade_command(
    monkeypatch: pytest.MonkeyPatch, fakebin_dir: Path, workspace: Path
) -> None:
    use_fake(monkeypatch, fakebin_dir, "cfn-guard", "oldversion")

    result = cfnguard.run_and_normalize(
        workspace / "template.yaml", workspace_root=workspace
    )

    error = only_error(result)
    assert error["error_class"] == "tool_version"
    assert error["detected_version"] == "2.1.0"
    assert error["required_min_version"] == "3.0.0"
    assert "cfn-guard" in error["remediation"]


def test_cfn_guard_that_hangs_is_reported_as_a_timeout(
    monkeypatch: pytest.MonkeyPatch, fakebin_dir: Path, workspace: Path
) -> None:
    use_fake(monkeypatch, fakebin_dir, "cfn-guard", "timeout")
    monkeypatch.setattr(cfnguard, "TIMEOUT_S", SHORT_TIMEOUT_S)

    result = cfnguard.run_and_normalize(
        workspace / "template.yaml", workspace_root=workspace
    )

    error = only_error(result)
    assert error["error_class"] == "tool_timeout"
    # The bare name, for the reason recorded on the cfn-lint timeout case above.
    assert error["tool"] == "cfn-guard"


def test_the_configured_cfn_guard_reports_a_clean_run_with_its_rule_counts(
    monkeypatch: pytest.MonkeyPatch,
    fakebin_dir: Path,
    workspace: Path,
    tmp_path: Path,
) -> None:
    """Requirement 5 AC4: zero violations is a successful review that says so."""
    use_fake(
        monkeypatch,
        fakebin_dir,
        "cfn-guard",
        "configured",
        config={},
        config_dir=tmp_path,
    )

    result = cfnguard.run_and_normalize(
        workspace / "template.yaml", workspace_root=workspace
    )

    assert result.errors == []
    assert result.findings == []
    assert result.stats["exit_code"] == 0
    assert result.stats["rules_evaluated"] == 1
    assert result.stats["rules_passed"] == 1


def test_the_configured_cfn_guard_produces_the_violation_it_was_given(
    monkeypatch: pytest.MonkeyPatch,
    fakebin_dir: Path,
    workspace: Path,
    tmp_path: Path,
) -> None:
    """Exit 19 plus a parsable payload is a rule violation.

    19 is the code the fake computes for a payload holding a violation, which is
    what cfn-guard 3.2.1 was measured to return. Nothing in the Source branches
    on it -- the next test is what pins that.
    """
    use_fake(
        monkeypatch,
        fakebin_dir,
        "cfn-guard",
        "configured",
        config={"results_text": guard_violation_records()},
        config_dir=tmp_path,
    )

    result = cfnguard.run_and_normalize(
        workspace / "template.yaml", workspace_root=workspace
    )

    assert result.errors == []
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.Source == ["cfn-guard"]
    assert finding.Resource == "DataBucket"
    assert "s3_bucket_encryption" in {entry.RuleId for entry in finding.Evidence}
    assert result.stats["exit_code"] == 19


@pytest.mark.parametrize("exit_code", [19, 255, 5])
def test_every_measured_cfn_guard_failure_code_classifies_the_same_way(
    monkeypatch: pytest.MonkeyPatch,
    fakebin_dir: Path,
    workspace: Path,
    tmp_path: Path,
    exit_code: int,
) -> None:
    """Requirement 5 AC7, asserted across the codes ``docs/architecture.md`` lists.

    The same empty stdout under three different non-zero codes must produce the
    same ``tool_execution``, with only the recorded number differing. That is the
    property the design rests on: a cfn-guard release that renumbers its failure
    codes changes nothing. Only the fake can produce this comparison, because
    talking the real tool into 19-with-empty-stdout is not possible.
    """
    use_fake(
        monkeypatch,
        fakebin_dir,
        "cfn-guard",
        "configured",
        config={"exit_code": exit_code, "results_text": "", "stderr": "failed\n"},
        config_dir=tmp_path,
    )

    result = cfnguard.run_and_normalize(
        workspace / "template.yaml", workspace_root=workspace
    )

    error = only_error(result)
    assert error["error_class"] == "tool_execution"
    assert error["exit_code"] == exit_code


def test_the_configured_cfn_guard_can_produce_output_that_does_not_parse(
    monkeypatch: pytest.MonkeyPatch,
    fakebin_dir: Path,
    workspace: Path,
    tmp_path: Path,
) -> None:
    """Well-formed JSON of the wrong shape, under a non-zero code.

    Distinct from the empty-stdout cases above: here stdout is JSON, so the
    payload reaches the structural checks and is rejected there.
    """
    use_fake(
        monkeypatch,
        fakebin_dir,
        "cfn-guard",
        "configured",
        config={"results_text": '{"not_compliant": "a string"}', "exit_code": 19},
        config_dir=tmp_path,
    )

    result = cfnguard.run_and_normalize(
        workspace / "template.yaml", workspace_root=workspace
    )

    error = only_error(result)
    assert error["error_class"] == "tool_execution"
    assert error["exit_code"] == 19


# ---------------------------------------------------------------------------
# cdk
# ---------------------------------------------------------------------------


@pytest.fixture
def cdk_project(tmp_path: Path) -> Path:
    """A directory that :func:`iacreview.cdk.detect_cdk_project` calls a project."""
    project = tmp_path / "project"
    project.mkdir()
    (project / "cdk.json").write_text('{"app": "fake"}', encoding="utf-8")
    return project


def test_cdk_missing_is_reported_with_the_official_documentation_url(
    monkeypatch: pytest.MonkeyPatch, fakebin_dir: Path, cdk_project: Path
) -> None:
    """Requirement 8 AC8. Raised, not collected: with no CLI there is nothing to synth."""
    use_fake(monkeypatch, fakebin_dir, "cdk", "missing")

    with pytest.raises(ToolUnavailableError) as caught:
        cdk.synth_if_confirmed(cdk_project, confirmed=True)

    assert caught.value.tool == "cdk"
    assert "docs.aws.amazon.com/cdk" in caught.value.remediation


def test_cdk_crash_is_reported_without_falling_back_to_a_stale_template(
    monkeypatch: pytest.MonkeyPatch, fakebin_dir: Path, cdk_project: Path
) -> None:
    """Requirement 8 AC7: no alternative execution mode, and no stale result.

    ``cdk.out`` is pre-populated so the assertion has teeth: a Source that
    swallowed the failure and enumerated the directory anyway would return a
    Template that does not correspond to the current source, which is a worse
    outcome than reporting the failure.
    """
    stale = cdk_project / "cdk.out"
    stale.mkdir()
    (stale / "Stale.template.json").write_text("{}", encoding="utf-8")
    use_fake(monkeypatch, fakebin_dir, "cdk", "crash")

    with pytest.raises(ToolExecutionError) as caught:
        cdk.synth_if_confirmed(cdk_project, confirmed=True)

    assert caught.value.tool == "cdk"
    assert caught.value.tool_exit_code == 1
    assert 0 < len(caught.value.stderr_head) <= 5


def test_cdk_below_the_minimum_version_is_refused_before_any_code_runs(
    monkeypatch: pytest.MonkeyPatch, fakebin_dir: Path, cdk_project: Path
) -> None:
    """A v1 CLI is rejected by the version gate.

    Worth its own case for ``cdk`` specifically: passing the gate here means
    executing the project's own code, so a gate that let an unsupported CLI
    through would run something the plugin had already decided not to run.
    """
    use_fake(monkeypatch, fakebin_dir, "cdk", "oldversion")

    with pytest.raises(ToolVersionError) as caught:
        cdk.synth_if_confirmed(cdk_project, confirmed=True)

    assert caught.value.detected_version == "1.99.0"
    assert caught.value.required_min_version == "2.0.0"


def test_cdk_that_hangs_is_reported_as_a_timeout_with_no_fallback(
    monkeypatch: pytest.MonkeyPatch, fakebin_dir: Path, cdk_project: Path
) -> None:
    """Requirement 8 AC6, with the synth timeout shortened for the test."""
    use_fake(monkeypatch, fakebin_dir, "cdk", "timeout")
    monkeypatch.setattr(cdk, "SYNTH_TIMEOUT_S", SHORT_TIMEOUT_S)

    with pytest.raises(ToolTimeoutError) as caught:
        cdk.synth_if_confirmed(cdk_project, confirmed=True)

    assert caught.value.tool == "cdk"
    assert cdk.NO_FALLBACK_REMEDIATION == caught.value.remediation


def test_the_configured_cdk_synthesizes_a_template_the_plugin_then_finds(
    monkeypatch: pytest.MonkeyPatch,
    fakebin_dir: Path,
    cdk_project: Path,
    tmp_path: Path,
) -> None:
    """The confirmed path end to end, without a Node toolchain.

    The fake writes into ``cdk.out`` relative to its working directory, which is
    what proves :func:`~iacreview.cdk.synth_if_confirmed` set that directory to
    the project: the CDK CLI has no flag naming the project, so a lost ``chdir``
    would silently synthesize somewhere else.
    """
    use_fake(
        monkeypatch,
        fakebin_dir,
        "cdk",
        "configured",
        config={},
        config_dir=tmp_path,
    )

    synthesized = cdk.synth_if_confirmed(cdk_project, confirmed=True)

    assert [path.name for path in synthesized] == ["FakeStack.template.json"]
    assert synthesized[0].parent == cdk_project / "cdk.out"
    payload = json.loads(synthesized[0].read_text(encoding="utf-8"))
    assert "Resources" in payload


def test_the_configured_cdk_is_not_started_without_the_confirmation_flag(
    monkeypatch: pytest.MonkeyPatch,
    fakebin_dir: Path,
    cdk_project: Path,
    tmp_path: Path,
) -> None:
    """Requirement 8 AC3, AC5, with a fake that *would* have produced something.

    The fake is on ``PATH`` and configured to write a Template, so the empty
    result is evidence that nothing ran rather than evidence that nothing was
    available. That distinction is the whole content of the confirmation gate.
    """
    use_fake(
        monkeypatch,
        fakebin_dir,
        "cdk",
        "configured",
        config={},
        config_dir=tmp_path,
    )

    synthesized = cdk.synth_if_confirmed(cdk_project, confirmed=False)

    assert synthesized == []
    assert not (cdk_project / "cdk.out").exists()


def test_the_configured_cdk_receives_exactly_the_synth_command(
    monkeypatch: pytest.MonkeyPatch,
    fakebin_dir: Path,
    cdk_project: Path,
    tmp_path: Path,
) -> None:
    """``log_argv`` pins the command line, which carries no user-supplied value.

    Every element of it is a literal owned by :mod:`iacreview.cdk`, so there is
    nothing here a filename could influence (Requirement 16 AC6).
    """
    use_fake(
        monkeypatch,
        fakebin_dir,
        "cdk",
        "configured",
        config={"log_argv": True},
        config_dir=tmp_path,
    )

    cdk.synth_if_confirmed(cdk_project, confirmed=True)

    logged = json.loads(
        (tmp_path / "fake-cdk-argv.json").read_text(encoding="utf-8")
    )
    assert logged == ["synth"]


# ---------------------------------------------------------------------------
# The fakes do not leak into each other, or into a real tool
# ---------------------------------------------------------------------------


def test_a_fake_for_one_tool_does_not_satisfy_another_tool(
    monkeypatch: pytest.MonkeyPatch, fakebin_dir: Path, workspace: Path
) -> None:
    """``PATH`` pointing at the cfn-lint fakes leaves cfn-guard unavailable.

    The real cfn-guard is installed on many development machines, so a test that
    inherited ``PATH`` while faking cfn-lint would quietly run the real one. This
    is the assertion that the ``PATH`` replacement is total.
    """
    use_fake(monkeypatch, fakebin_dir, "cfn-lint", "crash")

    result = cfnguard.run_and_normalize(
        workspace / "template.yaml", workspace_root=workspace
    )

    assert only_error(result)["error_class"] == "tool_unavailable"


def test_the_scenario_fakes_need_nothing_on_path_but_their_own_directory(
    monkeypatch: pytest.MonkeyPatch, fakebin_dir: Path, workspace: Path
) -> None:
    """The property that makes a single-directory ``PATH`` meaningful.

    A ``missing`` test sets ``PATH`` to one empty directory and concludes the tool
    is absent. That conclusion is only sound if a *present* fake would have been
    found with the same ``PATH`` shape -- otherwise every scenario would report
    "missing" and the suite would pass without testing anything. Asserted by
    reaching a non-``tool_unavailable`` outcome with ``PATH`` set to exactly one
    directory, which is what rules out an interpreter lookup leaking in.
    """
    monkeypatch.setenv("PATH", str(fakebin_dir / "cfn-lint-crash"))

    result = cfnlint.run_and_normalize(
        workspace / "template.yaml", workspace_root=workspace
    )

    assert only_error(result)["error_class"] == "tool_execution"
