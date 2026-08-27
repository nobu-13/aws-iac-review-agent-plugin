"""Sanity checks on the fake external tools under ``tests/fakebin``.

The fakes are how ``PATH`` gets swapped for a tool that is missing, crashing,
too old, hanging, or answering with output no parser accepts -- outcomes the real
cfn-lint, cfn-guard and CDK CLI cannot be talked into producing on demand, and
which Requirement 12 AC7 and AC11 require the suite to cover for all three tools.

This module tests the *fakes*, not the plugin. Nothing here imports a Source.
Each script is executed directly and its exit code and output are compared
against what the scenario claims to produce. The point is to keep a silently
broken fake from turning into a passing plugin test: a fake that exits 127
because its interpreter was not found, or one whose ``--version`` banner stopped
parsing, would make a tool-unavailable test pass for entirely the wrong reason.
``tests/integration/test_fakebin_drives_sources.py`` is the other half, and
checks that each fake drives the Source it stands in for into the intended
outcome.

Two structural properties are asserted here as well, because both are the kind of
thing that gets undone by accident:

executable bit
    ``PATH`` resolution ignores a file that is not executable, so a fake without
    the bit is indistinguishable from a missing tool -- which is another
    scenario in this same directory, and would therefore pass the wrong test.
    There is no VCS metadata to lean on in this checkout, so the mode is
    asserted rather than assumed.

no accidental shadowing
    ``tests/fakebin/`` itself is placed *first* on ``PATH`` by the existing
    integration tests that fake cfn-lint while using a real cfn-guard. A file
    named ``cfn-guard`` or ``cdk`` directly in that directory would shadow the
    real tool for all of them. The two configurable fakes therefore live one
    directory down, in ``cfn-guard-configured/`` and ``cdk-configured/``, and
    :func:`test_only_cfn_lint_is_faked_at_the_top_level_of_fakebin` pins that.
"""

from __future__ import annotations

import ast
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import pytest

from iacreview import toolcheck

TIMEOUT_S = 30

#: The three tools the plugin shells out to. Every one of them has a fake for
#: every scenario, so a gap in the coverage of one tool shows up as a collection
#: error rather than as a quietly missing case.
TOOLS = ("cfn-lint", "cfn-guard", "cdk")

#: Directory-name suffixes. ``missing`` has no script in it by definition; the
#: other four do.
MISSING = "missing"
CRASH = "crash"
OLDVERSION = "oldversion"
TIMEOUT = "timeout"
CONFIGURED = "configured"

SCENARIOS_WITH_SCRIPT = (CRASH, OLDVERSION, TIMEOUT, CONFIGURED)

#: ``(tool, scenario)`` pairs that must exist as a directory: the 12 tasks.md
#: enumerates, plus one ``-configured`` per tool -- except that cfn-lint's
#: configurable fake predates this layout and sits at the top level of
#: ``tests/fakebin`` (see the module docstring), so it has no directory of its
#: own. 14 in total.
DIRECTORIES = tuple(
    (tool, scenario)
    for tool in TOOLS
    for scenario in (MISSING, CRASH, OLDVERSION, TIMEOUT, CONFIGURED)
    if not (tool == "cfn-lint" and scenario == CONFIGURED)
)

#: ``(tool, scenario)`` pairs holding an executable named after the tool. All 12
#: of them, including the top-level cfn-lint fake, whose location differs but
#: which is held to the same standard.
SCRIPTS = tuple(
    (tool, scenario) for tool in TOOLS for scenario in SCENARIOS_WITH_SCRIPT
)

#: Version each fake reports for ``--version``, per scenario. The ``crash`` and
#: ``timeout`` fakes must report a *supported* version: they exist to test a
#: failure during analysis, which is only reachable once the version gate has
#: been passed.
EXPECTED_VERSIONS = {
    ("cfn-lint", CRASH): "1.22.0",
    ("cfn-lint", OLDVERSION): "0.83.0",
    ("cfn-lint", TIMEOUT): "1.22.0",
    ("cfn-lint", CONFIGURED): "1.22.0",
    ("cfn-guard", CRASH): "3.2.1",
    ("cfn-guard", OLDVERSION): "2.1.0",
    ("cfn-guard", TIMEOUT): "3.2.1",
    ("cfn-guard", CONFIGURED): "3.2.1",
    ("cdk", CRASH): "2.150.0",
    ("cdk", OLDVERSION): "1.99.0",
    ("cdk", TIMEOUT): "2.150.0",
    ("cdk", CONFIGURED): "2.150.0",
}

#: Configuration filename each configurable fake reads out of ``TMPDIR``, and
#: the argv log it writes there. One protocol, three tools.
CONFIG_FILENAMES = {
    "cfn-lint": ("fake-cfn-lint.json", "fake-cfn-lint-argv.json"),
    "cfn-guard": ("fake-cfn-guard.json", "fake-cfn-guard-argv.json"),
    "cdk": ("fake-cdk.json", "fake-cdk-argv.json"),
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def scenario_dir(fakebin_dir: Path, tool: str, scenario: str) -> Path:
    """Directory for one ``(tool, scenario)`` pair."""
    return fakebin_dir / "{0}-{1}".format(tool, scenario)


def script_path(fakebin_dir: Path, tool: str, scenario: str) -> Path:
    """The fake executable for one ``(tool, scenario)`` pair.

    cfn-lint's configurable fake is the one that lives at the top level; see the
    module docstring for why the others do not.
    """
    if tool == "cfn-lint" and scenario == CONFIGURED:
        return fakebin_dir / tool
    return scenario_dir(fakebin_dir, tool, scenario) / tool


def _run(
    executable: Path,
    arguments: Sequence[str],
    *,
    path_entries: Sequence[Path],
    cwd: Optional[Path] = None,
    env_extra: Optional[Dict[str, str]] = None,
    timeout_s: int = TIMEOUT_S,
) -> "subprocess.CompletedProcess[str]":
    """Execute a fake with an explicitly built ``PATH``.

    ``PATH`` is always stated by the caller and never inherited. A fake that
    found a real tool, or a real tool that found a fake, would make an assertion
    here describe something other than the file under test.
    """
    env = dict(os.environ)
    env["PATH"] = os.pathsep.join(str(entry) for entry in path_entries)
    if env_extra:
        env.update(env_extra)

    return subprocess.run(
        [str(executable), *arguments],
        cwd=None if cwd is None else str(cwd),
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=timeout_s,
    )


def _interpreter_dir() -> Path:
    """Directory holding the running interpreter.

    Needed on ``PATH`` for the configurable fakes, which are ``#!/usr/bin/env
    python3`` scripts: with a ``PATH`` that does not resolve ``python3``, ``env``
    exits 127 before a line of the fake runs.
    """
    return Path(sys.executable).parent


def _configure(directory: Path, tool: str, config: Dict[str, Any]) -> Dict[str, str]:
    """Write a configurable fake's config file and return the env revealing it."""
    filename = CONFIG_FILENAMES[tool][0]
    (directory / filename).write_text(json.dumps(config), encoding="utf-8")
    return {"TMPDIR": str(directory)}


# ---------------------------------------------------------------------------
# Layout, permissions, and the shadowing rule
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "scenario"), DIRECTORIES, ids=lambda value: str(value)
)
def test_every_scenario_directory_exists(
    fakebin_dir: Path, tool: str, scenario: str
) -> None:
    assert scenario_dir(fakebin_dir, tool, scenario).is_dir()


@pytest.mark.parametrize("tool", TOOLS)
def test_the_missing_directory_holds_no_executable_named_after_the_tool(
    fakebin_dir: Path, tool: str
) -> None:
    """The whole mechanism of the ``missing`` scenario, asserted directly.

    A placeholder file has to be present for the directory to survive a VCS that
    does not track empty directories, so "empty" is expressed as "holds nothing
    that ``PATH`` resolution would find" rather than as "holds no entries".
    """
    directory = scenario_dir(fakebin_dir, tool, MISSING)
    assert not (directory / tool).exists()
    assert shutil.which(tool, path=str(directory)) is None


@pytest.mark.parametrize(("tool", "scenario"), SCRIPTS, ids=lambda value: str(value))
def test_every_fake_is_executable_and_resolvable_on_path(
    fakebin_dir: Path, tool: str, scenario: str
) -> None:
    """``PATH`` resolution depends on the executable bit, so it is asserted.

    Without it the fake is indistinguishable from a missing tool, which is a
    different scenario in this same directory and would pass the wrong test.
    """
    script = script_path(fakebin_dir, tool, scenario)
    assert script.is_file()

    mode = script.stat().st_mode
    assert mode & stat.S_IXUSR, "{0} is not executable by its owner".format(script)
    assert os.access(str(script), os.X_OK)

    resolved = shutil.which(tool, path=str(script.parent))
    assert resolved is not None
    assert Path(resolved).resolve() == script.resolve()


def test_only_cfn_lint_is_faked_at_the_top_level_of_fakebin(
    fakebin_dir: Path,
) -> None:
    """A top-level ``cfn-guard`` or ``cdk`` would shadow the real tool.

    ``tests/fakebin`` goes *first* on ``PATH`` in the integration tests that fake
    cfn-lint while using a real cfn-guard, so anything else placed here wins
    that race for every one of them. The two configurable fakes live one
    directory down for that reason, and this test is what keeps the reason from
    being undone by someone adding the obvious file.
    """
    executables = sorted(
        entry.name
        for entry in fakebin_dir.iterdir()
        if entry.is_file() and os.access(str(entry), os.X_OK)
    )
    assert executables == ["cfn-lint"]


# ---------------------------------------------------------------------------
# The version banner: every fake must be parsable by toolcheck
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("tool", "scenario"), SCRIPTS, ids=lambda value: str(value))
def test_version_banner_parses_to_the_version_the_scenario_claims(
    fakebin_dir: Path, tool: str, scenario: str, tmp_path: Path
) -> None:
    """``--version`` must exit 0 and be readable by :func:`extract_version`.

    The version is what decides whether a scenario is reached at all: a banner
    that stopped parsing would send every fake down the
    :data:`~iacreview.toolcheck.UNKNOWN_VERSION` path and quietly disable the
    ``oldversion`` scenario entirely.
    """
    script = script_path(fakebin_dir, tool, scenario)
    completed = _run(
        script,
        ["--version"],
        path_entries=[script.parent, _interpreter_dir()],
        # An empty per-test TMPDIR, so a configurable fake reads no
        # configuration and its *default* banner is what gets asserted. Left to
        # the ambient TMPDIR this would depend on whatever another test wrote
        # into the system temp directory.
        env_extra={"TMPDIR": str(tmp_path)},
    )

    assert completed.returncode == 0, completed.stderr
    assert toolcheck.extract_version(completed.stdout) == EXPECTED_VERSIONS[
        (tool, scenario)
    ]


@pytest.mark.parametrize(("tool", "scenario"), SCRIPTS, ids=lambda value: str(value))
def test_the_version_scenario_agrees_with_the_minimum_version_table(
    fakebin_dir: Path, tool: str, scenario: str
) -> None:
    """``oldversion`` is below the table minimum; every other scenario is not.

    Self-consistency rather than behaviour: it is what keeps a bump of
    :data:`~iacreview.toolcheck.TOOL_REQUIREMENTS` from silently turning the
    ``crash`` and ``timeout`` fakes into version failures, which would still
    produce a structured error and so would still pass a carelessly written
    tool-unavailable test.
    """
    minimum = toolcheck.requirement_for(tool).min_version
    reported = EXPECTED_VERSIONS[(tool, scenario)]

    def as_tuple(version: str) -> tuple:
        return tuple(int(part) for part in version.split("."))

    if scenario == OLDVERSION:
        assert as_tuple(reported) < as_tuple(minimum)
    else:
        assert as_tuple(reported) >= as_tuple(minimum)


# ---------------------------------------------------------------------------
# The failure scenarios, executed directly
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool", TOOLS)
def test_the_crash_fake_exits_non_zero_with_stderr_and_empty_stdout(
    fakebin_dir: Path, tool: str
) -> None:
    """A crash is a non-zero exit with the explanation on stderr.

    Empty stdout is asserted for all three because it is what makes the failure
    unambiguous: for cfn-guard specifically, stdout that parses would be read as
    rule violations rather than as a tool error
    (:func:`iacreview.cfnguard.interpret_guard_result`).
    """
    script = script_path(fakebin_dir, tool, CRASH)
    completed = _run(script, ["--anything"], path_entries=[script.parent])

    assert completed.returncode != 0
    assert completed.stdout == ""
    assert completed.stderr.strip() != ""


@pytest.mark.parametrize("tool", TOOLS)
def test_the_oldversion_fake_refuses_to_do_any_work(
    fakebin_dir: Path, tool: str
) -> None:
    """Only ``--version`` succeeds; anything else is an error.

    The version gate is supposed to stop the plugin before it asks an
    unsupported tool to do anything. Exiting non-zero on every other path means
    a regression in that gate shows up as a failure rather than as a review that
    silently used a tool the plugin had rejected.
    """
    script = script_path(fakebin_dir, tool, OLDVERSION)
    completed = _run(script, ["--anything"], path_entries=[script.parent])

    assert completed.returncode != 0
    assert completed.stdout == ""


@pytest.mark.parametrize("tool", TOOLS)
def test_the_timeout_fake_answers_version_at_once_but_never_finishes(
    fakebin_dir: Path, tool: str
) -> None:
    """The banner is immediate; the work hangs until it is killed.

    Asserted as a real timeout of a real process, with a short limit. The
    ``--version`` half is what keeps the 10-second
    :data:`~iacreview.toolcheck.VERSION_CHECK_TIMEOUT_S` out of every test that
    uses this fake.
    """
    script = script_path(fakebin_dir, tool, TIMEOUT)

    banner = _run(script, ["--version"], path_entries=[script.parent], timeout_s=10)
    assert banner.returncode == 0

    with pytest.raises(subprocess.TimeoutExpired):
        _run(script, ["--anything"], path_entries=[script.parent], timeout_s=2)


@pytest.mark.parametrize("tool", TOOLS)
def test_the_timeout_fake_leaves_no_surviving_process_when_killed(
    fakebin_dir: Path, tool: str
) -> None:
    """``exec sleep`` is why the killed child is the sleep itself.

    :mod:`iacreview.proc` documents that grandchildren of the process it kills
    are not tracked. A fake that ran ``sleep 999`` as a child of ``/bin/sh``
    would therefore leak one surviving ``sleep`` per test that timed it out.
    Asserted by killing the process the way ``subprocess`` does and confirming
    the process group is gone.
    """
    script = script_path(fakebin_dir, tool, TIMEOUT)
    env = dict(os.environ)
    env["PATH"] = str(script.parent)

    process = subprocess.Popen(
        [str(script), "--anything"],
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    group = os.getpgid(process.pid)
    try:
        # Confirm it is genuinely hung before killing it. Without this the test
        # would also pass for a fake that exited immediately -- which is how the
        # first version of these scripts behaved: `exec sleep 999` could not
        # resolve `sleep` with PATH set to the scenario directory alone, so the
        # exec failed with 127 and the "hang" lasted milliseconds.
        with pytest.raises(subprocess.TimeoutExpired):
            process.wait(timeout=1)

        process.kill()
        process.communicate(timeout=10)
    finally:
        if process.poll() is None:  # pragma: no cover - only if the kill failed
            process.kill()
            process.wait(timeout=10)

    assert process.returncode is not None
    # The direct child is `sleep`, replaced into by `exec`, so killing the pid
    # kills the sleep. Had the shell stayed in place, the sleep would be a
    # grandchild in the same new session and this group would still hold it.
    with pytest.raises(ProcessLookupError):
        os.killpg(group, 0)


# ---------------------------------------------------------------------------
# The configurable fakes: one protocol, three tools
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool", TOOLS)
def test_a_configurable_fake_with_no_configuration_reports_its_default_version(
    fakebin_dir: Path, tool: str, tmp_path: Path
) -> None:
    """An absent config file is the default configuration, not an error."""
    script = script_path(fakebin_dir, tool, CONFIGURED)
    completed = _run(
        script,
        ["--version"],
        path_entries=[script.parent, _interpreter_dir()],
        env_extra={"TMPDIR": str(tmp_path)},
    )

    assert completed.returncode == 0, completed.stderr
    assert toolcheck.extract_version(completed.stdout) is not None


@pytest.mark.parametrize("tool", TOOLS)
def test_a_configurable_fake_can_produce_an_unparsable_version_banner(
    fakebin_dir: Path, tool: str, tmp_path: Path
) -> None:
    """``version_text`` reaches the :data:`UNKNOWN_VERSION` path.

    An empty banner is the case
    :func:`iacreview.toolcheck.require_tool` handles by warning on stderr and
    continuing, which is the one version outcome the ``oldversion`` fake cannot
    produce.
    """
    script = script_path(fakebin_dir, tool, CONFIGURED)
    env_extra = _configure(tmp_path, tool, {"version_text": ""})
    completed = _run(
        script,
        ["--version"],
        path_entries=[script.parent, _interpreter_dir()],
        env_extra=env_extra,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == ""
    assert toolcheck.extract_version(completed.stdout) is None


@pytest.mark.parametrize("tool", TOOLS)
def test_a_configurable_fake_honours_the_exit_code_and_stderr_it_is_given(
    fakebin_dir: Path, tool: str, tmp_path: Path
) -> None:
    script = script_path(fakebin_dir, tool, CONFIGURED)
    env_extra = _configure(
        tmp_path, tool, {"exit_code": 42, "stderr": "configured failure\n"}
    )
    completed = _run(
        script,
        ["--anything"],
        path_entries=[script.parent, _interpreter_dir()],
        cwd=tmp_path,
        env_extra=env_extra,
    )

    assert completed.returncode == 42
    assert completed.stderr == "configured failure\n"


@pytest.mark.parametrize("tool", TOOLS)
def test_a_configurable_fake_records_the_argv_it_was_given(
    fakebin_dir: Path, tool: str, tmp_path: Path
) -> None:
    """``log_argv`` is how a test asserts on the command line the plugin built."""
    script = script_path(fakebin_dir, tool, CONFIGURED)
    env_extra = _configure(tmp_path, tool, {"log_argv": True})
    completed = _run(
        script,
        ["--first", "second"],
        path_entries=[script.parent, _interpreter_dir()],
        cwd=tmp_path,
        env_extra=env_extra,
    )

    assert completed.returncode == 0, completed.stderr
    log = tmp_path / CONFIG_FILENAMES[tool][1]
    assert json.loads(log.read_text(encoding="utf-8")) == ["--first", "second"]


@pytest.mark.parametrize("tool", TOOLS)
def test_a_configurable_fake_without_tmpdir_falls_back_to_its_defaults(
    fakebin_dir: Path, tool: str, tmp_path: Path
) -> None:
    """No ``TMPDIR`` must not be a crash.

    :func:`iacreview.proc.run` copies ``TMPDIR`` only when the parent has one,
    so a fake that required it would fail on a host where it is unset -- for a
    reason having nothing to do with the test.
    """
    script = script_path(fakebin_dir, tool, CONFIGURED)
    env = dict(os.environ)
    env.pop("TMPDIR", None)
    env["PATH"] = os.pathsep.join(
        [str(script.parent), str(_interpreter_dir())]
    )

    completed = subprocess.run(
        [str(script), "--version"],
        cwd=str(tmp_path),
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=TIMEOUT_S,
    )

    assert completed.returncode == 0, completed.stderr
    assert toolcheck.extract_version(completed.stdout) is not None


def test_the_configurable_cfn_lint_computes_the_exit_bit_mask_per_level(
    fakebin_dir: Path, tmp_path: Path
) -> None:
    """cfn-lint's exit status is a bit mask, and the fake reproduces it.

    2 for an Error, 4 for a Warning, 8 for an Informational, OR-ed. A fake that
    always exited 0 would make ``decode_cfnlint_exit`` untestable end to end.
    """
    script = script_path(fakebin_dir, "cfn-lint", CONFIGURED)
    results = [{"Level": "Warning"}, {"Level": "Informational"}]
    env_extra = _configure(
        tmp_path, "cfn-lint", {"results_text": json.dumps(results)}
    )
    completed = _run(
        script,
        ["-f", "json"],
        path_entries=[script.parent, _interpreter_dir()],
        cwd=tmp_path,
        env_extra=env_extra,
    )

    assert completed.returncode == 4 | 8


def test_the_configurable_cfn_guard_pairs_violations_with_the_measured_exit_code(
    fakebin_dir: Path, tmp_path: Path
) -> None:
    """19 for violations, 0 for a clean run (docs/architecture.md, cases a, b)."""
    script = script_path(fakebin_dir, "cfn-guard", CONFIGURED)
    path_entries = [script.parent, _interpreter_dir()]

    clean = _run(
        script,
        ["validate"],
        path_entries=path_entries,
        cwd=tmp_path,
        env_extra=_configure(tmp_path, "cfn-guard", {}),
    )
    assert clean.returncode == 0, clean.stderr

    violating = json.dumps(
        {
            "name": "t.yaml",
            "status": "FAIL",
            "not_compliant": [{"Rule": {"name": "r", "checks": []}}],
            "not_applicable": [],
            "compliant": [],
        }
    )
    dirty = _run(
        script,
        ["validate"],
        path_entries=path_entries,
        cwd=tmp_path,
        env_extra=_configure(
            tmp_path, "cfn-guard", {"results_text": violating}
        ),
    )
    assert dirty.returncode == 19


@pytest.mark.parametrize("exit_code", [0, 19, 255, 5])
def test_the_configurable_cfn_guard_can_produce_every_measured_exit_code(
    fakebin_dir: Path, tmp_path: Path, exit_code: int
) -> None:
    """The four distinct codes in ``docs/architecture.md``'s table.

    255 appears twice there (an unparsable template, and a rules directory that
    does not exist); both pair it with empty stdout, so one parametrization
    covers the pair. Being able to reach all of them is what lets a test assert
    that :func:`iacreview.cfnguard.interpret_guard_result` classifies on stdout
    and not on the number.
    """
    script = script_path(fakebin_dir, "cfn-guard", CONFIGURED)
    env_extra = _configure(
        tmp_path, "cfn-guard", {"exit_code": exit_code, "results_text": ""}
    )
    completed = _run(
        script,
        ["validate"],
        path_entries=[script.parent, _interpreter_dir()],
        cwd=tmp_path,
        env_extra=env_extra,
    )

    assert completed.returncode == exit_code
    assert completed.stdout == ""


def test_the_configurable_cdk_writes_its_templates_into_cdk_out(
    fakebin_dir: Path, tmp_path: Path
) -> None:
    """The only output of ``cdk synth`` the plugin reads is the files it leaves."""
    script = script_path(fakebin_dir, "cdk", CONFIGURED)
    project = tmp_path / "project"
    project.mkdir()

    completed = _run(
        script,
        ["synth"],
        path_entries=[script.parent, _interpreter_dir()],
        cwd=project,
        env_extra=_configure(tmp_path, "cdk", {}),
    )

    assert completed.returncode == 0, completed.stderr
    written = sorted(path.name for path in (project / "cdk.out").iterdir())
    assert written == ["FakeStack.template.json"]
    payload = json.loads(
        (project / "cdk.out" / "FakeStack.template.json").read_text(
            encoding="utf-8"
        )
    )
    assert list(payload["Resources"]) == ["FakeStackBucket"]


def test_the_configurable_cdk_writes_nothing_for_an_empty_template_mapping(
    fakebin_dir: Path, tmp_path: Path
) -> None:
    """"Synth succeeded but produced nothing reviewable" is a distinct outcome.

    ``cdk.out`` is deliberately not created either, because
    :func:`iacreview.cdk.detect_cdk_project` reports its existence separately
    from the templates in it.
    """
    script = script_path(fakebin_dir, "cdk", CONFIGURED)
    project = tmp_path / "project"
    project.mkdir()

    completed = _run(
        script,
        ["synth"],
        path_entries=[script.parent, _interpreter_dir()],
        cwd=project,
        env_extra=_configure(tmp_path, "cdk", {"templates": {}}),
    )

    assert completed.returncode == 0, completed.stderr
    assert not (project / "cdk.out").exists()


@pytest.mark.parametrize(
    "name",
    [
        "../escaped.template.json",
        "nested/stack.template.json",
        "/absolute.template.json",
        "stack.json",
        ".hidden.template.json",
    ],
)
def test_the_configurable_cdk_refuses_a_template_name_that_is_not_a_plain_filename(
    fakebin_dir: Path, tmp_path: Path, name: str
) -> None:
    """A fake is held to the same path rules as the plugin.

    steering/security.md's path requirements apply to everything in this
    repository. A fake that could be talked into writing outside its own
    directory would be a worse hazard than the tool it stands in for, because
    tests hand it inputs nobody reviews. The name is refused rather than
    sanitized, so a test cannot believe it wrote one file while another was
    created.
    """
    script = script_path(fakebin_dir, "cdk", CONFIGURED)
    project = tmp_path / "project"
    project.mkdir()

    completed = _run(
        script,
        ["synth"],
        path_entries=[script.parent, _interpreter_dir()],
        cwd=project,
        env_extra=_configure(tmp_path, "cdk", {"templates": {name: "{}"}}),
    )

    assert completed.returncode != 0
    assert "fake cdk" in completed.stderr
    assert not (project / "cdk.out" / Path(name).name).exists()
    assert not (tmp_path / "escaped.template.json").exists()


# ---------------------------------------------------------------------------
# Cross-checks over the whole directory
# ---------------------------------------------------------------------------


def test_no_fake_reads_or_forwards_an_aws_credential(fakebin_dir: Path) -> None:
    """No fake may touch a credential variable, even to echo it.

    :func:`iacreview.proc.run` already withholds credentials from children, so
    this cannot currently be reached -- which is exactly why it is worth pinning:
    a fake that read ``AWS_SECRET_ACCESS_KEY`` would be a plausible-looking way
    to weaken that guarantee's test coverage from the other side, and would leave
    a credential in captured output where steering/security.md forbids one.
    """
    forbidden = (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_PROFILE",
    )
    for path in sorted(fakebin_dir.rglob("*")):
        if not path.is_file() or path.name == ".gitkeep":
            continue
        text = path.read_text(encoding="utf-8")
        for name in forbidden:
            assert name not in text, "{0} mentions {1}".format(path, name)


def test_no_shell_fake_substitutes_or_evaluates_a_command(
    fakebin_dir: Path,
) -> None:
    """The shell fakes compare their arguments; they never execute them.

    steering/security.md forbids building a command out of user input. A fake
    receives paths the plugin assembled from a ``--target`` the user chose, so
    the rule applies here as much as to the plugin: a fake that ran ``eval`` on
    an argument would execute a filename a test had constructed, which is the
    exact hazard ``tests/regression/test_sec_shell_metacharacters.py`` exists to
    rule out.

    ``exec`` is permitted and used: it is the builtin that replaces the process
    with ``sleep``, with a fixed argument list rather than an evaluated string.
    """
    forbidden = ("eval", "$(", "`", "system")
    for tool, scenario in SCRIPTS:
        if scenario == CONFIGURED:
            continue
        script = script_path(fakebin_dir, tool, scenario)
        # Comments are dropped first. Every one of these scripts explains in
        # prose that it never evaluates its arguments, and the word "evaluated"
        # contains "eval": scanning the commentary would report the explanation
        # as the violation.
        code = "\n".join(
            line
            for line in script.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        )
        for token in forbidden:
            assert token not in code, "{0} contains {1!r}".format(script, token)


#: Everything the configurable fakes are allowed to import. Small on purpose:
#: with no ``subprocess`` and no ``shlex``, a fake has no way to run a command
#: however its arguments are written.
ALLOWED_IMPORTS = frozenset({"json", "os", "sys", "time"})

#: Calls that would give a fake a way to execute something despite the import
#: allowlist, since ``os`` is on it.
FORBIDDEN_CALLS = frozenset(
    {
        "eval",
        "exec",
        "compile",
        "__import__",
        "os.system",
        "os.popen",
        "os.execv",
        "os.execvp",
        "os.spawnv",
    }
)


def _called_names(tree: "ast.AST") -> List[str]:
    """Dotted names of every call in ``tree``, as written in the source."""
    names: List[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            try:
                names.append(ast.unparse(node.func))
            except AttributeError:  # pragma: no cover - ast.unparse is 3.9+
                pass
    return names


@pytest.mark.parametrize("tool", TOOLS)
def test_a_configurable_fake_cannot_start_a_process(
    fakebin_dir: Path, tool: str
) -> None:
    """The Python fakes must have no way to run anything.

    Asserted by parsing the file rather than by searching it for suspicious
    words: these fakes document themselves at length, and a text search over
    prose reports the documentation instead of the code. steering/security.md's
    rule against executing user input applies to a fake as much as to the
    plugin, and a fake is the easiest place for such a call to go unnoticed.
    """
    script = script_path(fakebin_dir, tool, CONFIGURED)
    tree = ast.parse(script.read_text(encoding="utf-8"), filename=str(script))

    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported <= ALLOWED_IMPORTS, "{0} imports {1}".format(
        script, sorted(imported - ALLOWED_IMPORTS)
    )

    called = set(_called_names(tree))
    assert not called & FORBIDDEN_CALLS, "{0} calls {1}".format(
        script, sorted(called & FORBIDDEN_CALLS)
    )


def test_every_shell_fake_names_an_absolute_interpreter(fakebin_dir: Path) -> None:
    """Why the scenario fakes are ``/bin/sh`` and the configurable ones are not.

    A scenario fake is used with ``PATH`` pointing at its directory *only*, so
    its interpreter must be reachable without ``PATH``: ``#!/bin/sh`` is, and
    ``#!/usr/bin/env python3`` is not -- ``env`` would be found by absolute path
    and then fail to find ``python3``, exiting 127 before a line ran. The
    configurable fakes need to parse JSON, so they are Python and their callers
    put the interpreter's directory on ``PATH`` as well.
    """
    for tool, scenario in SCRIPTS:
        script = script_path(fakebin_dir, tool, scenario)
        shebang = script.read_text(encoding="utf-8").splitlines()[0]
        if scenario == CONFIGURED:
            assert shebang == "#!/usr/bin/env python3", script
        else:
            assert shebang == "#!/bin/sh", script


@pytest.mark.parametrize(("tool", "scenario"), SCRIPTS, ids=lambda value: str(value))
def test_every_fake_explains_itself_at_the_top(
    fakebin_dir: Path, tool: str, scenario: str
) -> None:
    """Each fake states what it imitates and why, before any code.

    Fifteen directories of look-alike scripts are unreadable otherwise, and a
    contributor reaching for the wrong scenario is how a tool-unavailable test
    ends up asserting the wrong outcome with no sign that anything is wrong.
    """
    script = script_path(fakebin_dir, tool, scenario)
    text = script.read_text(encoding="utf-8")

    if scenario == CONFIGURED:
        docstring = ast.get_docstring(ast.parse(text, filename=str(script)))
        assert docstring, "{0} has no module docstring".format(script)
        assert len(docstring.splitlines()) >= 5, script
        return

    # Comment block immediately after the shebang, up to the first blank or code
    # line. Contiguity is the point: a comment further down does not tell a
    # reader opening the file what they are looking at.
    comments: List[str] = []
    for line in text.splitlines()[1:]:
        if not line.startswith("#"):
            break
        comments.append(line)
    assert len(comments) >= 5, "{0} has only {1} leading comment lines".format(
        script, len(comments)
    )
