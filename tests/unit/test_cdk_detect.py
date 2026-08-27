"""Unit tests for :mod:`iacreview.cdk`.

Directory layouts are built in ``tmp_path`` rather than committed as fixtures:
the properties under test are about *which entries exist* and *in what order
they come back*, and an on-disk fixture cannot express the negative cases (a
symlink escaping the scan root, a ``node_modules`` tree large enough to matter)
without adding files that every other test collection would then have to ignore.

The confirmation gate (Requirement 8 AC3, AC5) is asserted by making every route
to a subprocess raise: :func:`iacreview.proc.run`, :func:`shutil.which` and
:func:`subprocess.run` are all replaced with a function that fails the test.
Asserting that no process starts, rather than that ``cdk`` was not found, is what
makes the test meaningful on a machine where the CDK CLI is installed.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path
from typing import Any, Callable, List, NoReturn, Tuple

import pytest

from iacreview import cdk, proc
from iacreview.errors import (
    InputNotFoundError,
    InvalidArgumentsError,
    ToolExecutionError,
    ToolTimeoutError,
    ToolUnavailableError,
)
from iacreview.proc import ProcResult
from iacreview.toolcheck import CDK, TOOL_REQUIREMENTS, ToolInfo

SYNTHESIZED_TEMPLATE = '{"Resources": {"Bucket": {"Type": "AWS::S3::Bucket"}}}\n'
STANDALONE_TEMPLATE = "Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n"


def _write(path: Path, text: str) -> Path:
    """Create ``path`` and its parents, then write ``text``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _relative(paths: List[Path], root: Path) -> List[str]:
    """Render discovered paths as ``/``-separated paths relative to ``root``."""
    return [str(path.relative_to(root)).replace(os.sep, "/") for path in paths]


@pytest.fixture
def no_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make any attempt to start a process fail the test.

    Covers all three layers a synth could reach: the plugin's own wrapper, the
    ``PATH`` lookup that precedes it, and :mod:`subprocess` underneath both.
    """

    def boom(*args: Any, **kwargs: Any) -> NoReturn:
        raise AssertionError(
            "a subprocess was started: args={0!r} kwargs={1!r}".format(args, kwargs)
        )

    # cdk.proc is this same module object; patching it once covers both names.
    monkeypatch.setattr(proc, "run", boom)
    monkeypatch.setattr("shutil.which", boom)
    monkeypatch.setattr(subprocess, "run", boom)


@pytest.fixture
def empty_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Replace ``PATH`` with an empty directory, hiding any installed tool."""
    bindir = tmp_path / "empty-bin"
    bindir.mkdir()
    monkeypatch.setenv("PATH", str(bindir))
    return bindir


@pytest.fixture
def fake_cdk(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Callable[..., Path]:
    """Install a fake ``cdk`` as the only executable on ``PATH``.

    The script answers ``--version`` with a supported version and, for any other
    invocation, runs ``body`` in its working directory. That is what lets one
    test assert both the synth result and the fact that synthesis happened in the
    project directory rather than in the process's own.
    """
    bindir = tmp_path / "bin"
    bindir.mkdir()
    # Prepended rather than replacing PATH: the script body needs the system
    # utilities, and bindir coming first means an installed cdk cannot win.
    monkeypatch.setenv(
        "PATH", str(bindir) + os.pathsep + os.environ.get("PATH", os.defpath)
    )

    def install(body: str, *, version: str = "2.1006.0 (build 1e9d8b1)") -> Path:
        script = bindir / CDK
        script.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = "--version" ]; then\n'
            "  printf '%s\\n' \"{version}\"\n"
            "  exit 0\n"
            "fi\n"
            "{body}\n".format(version=version, body=body),
            encoding="utf-8",
        )
        script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)
        return script

    return install


def _cdk_project(root: Path) -> Path:
    """Create a minimal CDK project directory (``cdk.json`` only)."""
    _write(root / cdk.CDK_CONFIG_FILENAME, '{"app": "python3 app.py"}\n')
    return root


# ---------------------------------------------------------------------------
# (a) detection with and without cdk.json (Requirement 8 AC2)
# ---------------------------------------------------------------------------


def test_cdk_json_present_is_detected(tmp_path: Path, no_subprocess: None) -> None:
    config = _cdk_project(tmp_path) / cdk.CDK_CONFIG_FILENAME

    detection = cdk.detect_cdk_project(tmp_path)

    assert detection.is_cdk_project is True
    assert detection.config_file == config
    assert detection.directory == tmp_path.resolve()


def test_cdk_json_absent_is_not_detected(
    tmp_path: Path, no_subprocess: None
) -> None:
    _write(tmp_path / "template.yaml", STANDALONE_TEMPLATE)

    detection = cdk.detect_cdk_project(tmp_path)

    assert detection.is_cdk_project is False
    assert detection.config_file is None
    assert detection.output_directory is None
    assert detection.synthesized_templates == ()


def test_cdk_json_directory_is_not_a_project(
    tmp_path: Path, no_subprocess: None
) -> None:
    """``cdk.json`` must be a file; a directory of that name is not evidence."""
    (tmp_path / cdk.CDK_CONFIG_FILENAME).mkdir()

    assert cdk.detect_cdk_project(tmp_path).is_cdk_project is False


def test_missing_directory_reports_input_not_found(tmp_path: Path) -> None:
    with pytest.raises(InputNotFoundError):
        cdk.detect_cdk_project(tmp_path / "absent")


def test_file_target_reports_invalid_arguments(tmp_path: Path) -> None:
    target = _write(tmp_path / "template.yaml", STANDALONE_TEMPLATE)

    with pytest.raises(InvalidArgumentsError):
        cdk.detect_cdk_project(target)


@pytest.mark.parametrize("blank", ["", "   ", "\t\n"])
def test_blank_directory_reports_invalid_arguments(blank: str) -> None:
    with pytest.raises(InvalidArgumentsError):
        cdk.detect_cdk_project(blank)


def test_unnormalizable_directory_reports_invalid_arguments() -> None:
    """An embedded NUL must fail cleanly, not surface an OS-level error."""
    with pytest.raises(InvalidArgumentsError):
        cdk.find_templates("project\0dir")


# ---------------------------------------------------------------------------
# (b) enumeration of cdk.out templates (Requirement 8 AC1, AC2)
# ---------------------------------------------------------------------------


def test_synthesized_templates_are_enumerated(
    tmp_path: Path, no_subprocess: None
) -> None:
    _cdk_project(tmp_path)
    out = tmp_path / cdk.CDK_OUTPUT_DIRECTORY_NAME
    _write(out / "AppStack.template.json", SYNTHESIZED_TEMPLATE)
    _write(out / "DbStack.template.json", SYNTHESIZED_TEMPLATE)
    # Cloud assembly bookkeeping, not a template.
    _write(out / "manifest.json", "{}\n")
    _write(out / "tree.json", "{}\n")

    detection = cdk.detect_cdk_project(tmp_path)

    assert detection.output_directory == out
    assert detection.has_synthesized_templates is True
    assert _relative(list(detection.synthesized_templates), tmp_path) == [
        "cdk.out/AppStack.template.json",
        "cdk.out/DbStack.template.json",
    ]


def test_synthesized_templates_without_cdk_json(
    tmp_path: Path, no_subprocess: None
) -> None:
    """A copied cloud assembly is reviewable even without the project source."""
    _write(
        tmp_path / cdk.CDK_OUTPUT_DIRECTORY_NAME / "AppStack.template.json",
        SYNTHESIZED_TEMPLATE,
    )

    templates = cdk.find_synthesized_templates(tmp_path)

    assert _relative(templates, tmp_path) == ["cdk.out/AppStack.template.json"]
    assert cdk.detect_cdk_project(tmp_path).is_cdk_project is False


def test_absent_cdk_out_yields_no_synthesized_templates(
    tmp_path: Path, no_subprocess: None
) -> None:
    _cdk_project(tmp_path)

    assert cdk.find_synthesized_templates(tmp_path) == []


def test_directory_named_like_a_template_is_not_enumerated(
    tmp_path: Path, no_subprocess: None
) -> None:
    out = tmp_path / cdk.CDK_OUTPUT_DIRECTORY_NAME
    (out / "Weird.template.json").mkdir(parents=True)
    _write(out / "AppStack.template.json", SYNTHESIZED_TEMPLATE)

    assert _relative(cdk.find_synthesized_templates(tmp_path), tmp_path) == [
        "cdk.out/AppStack.template.json"
    ]


def test_synthesized_symlink_escaping_the_root_is_skipped(
    tmp_path: Path, no_subprocess: None
) -> None:
    outside = _write(tmp_path / "outside" / "Foreign.template.json", "{}\n")
    project = tmp_path / "project"
    out = project / cdk.CDK_OUTPUT_DIRECTORY_NAME
    _write(out / "AppStack.template.json", SYNTHESIZED_TEMPLATE)
    (out / "Linked.template.json").symlink_to(outside)

    assert _relative(cdk.find_synthesized_templates(project), project) == [
        "cdk.out/AppStack.template.json"
    ]


def test_nested_assembly_templates_are_not_enumerated(
    tmp_path: Path, no_subprocess: None
) -> None:
    """Only ``cdk.out/*.template.json``; a nested stage assembly is skipped."""
    out = tmp_path / cdk.CDK_OUTPUT_DIRECTORY_NAME
    _write(out / "AppStack.template.json", SYNTHESIZED_TEMPLATE)
    _write(out / "assembly-Stage" / "StageStack.template.json", SYNTHESIZED_TEMPLATE)

    assert _relative(cdk.find_synthesized_templates(tmp_path), tmp_path) == [
        "cdk.out/AppStack.template.json"
    ]


# ---------------------------------------------------------------------------
# (c) excluded directories are never descended
# ---------------------------------------------------------------------------


def test_excluded_directories_are_not_scanned(
    tmp_path: Path, no_subprocess: None
) -> None:
    _write(tmp_path / "template.yaml", STANDALONE_TEMPLATE)
    _write(tmp_path / "nested" / "stack.json", SYNTHESIZED_TEMPLATE)
    for excluded in sorted(cdk.EXCLUDED_DIRECTORY_NAMES):
        _write(tmp_path / excluded / "buried.yaml", STANDALONE_TEMPLATE)
        _write(tmp_path / excluded / "deep" / "buried.json", SYNTHESIZED_TEMPLATE)
        _write(tmp_path / "nested" / excluded / "buried.yml", STANDALONE_TEMPLATE)

    found = _relative(cdk.find_templates(tmp_path), tmp_path)

    assert found == ["nested/stack.json", "template.yaml"]


def test_cdk_out_is_excluded_from_the_standalone_group(
    tmp_path: Path, no_subprocess: None
) -> None:
    """Requirement 8 AC10: the two groups are disjoint."""
    _cdk_project(tmp_path)
    _write(tmp_path / "extra.yaml", STANDALONE_TEMPLATE)
    _write(
        tmp_path / cdk.CDK_OUTPUT_DIRECTORY_NAME / "AppStack.template.json",
        SYNTHESIZED_TEMPLATE,
    )

    standalone, synthesized = cdk.partition_templates(tmp_path)

    # ``cdk.json`` matches the ``.json`` suffix and is therefore a candidate.
    # The scan does not decide reviewability -- parsing does -- so no filename
    # denylist is applied here beyond the excluded directories.
    assert _relative(standalone, tmp_path) == ["cdk.json", "extra.yaml"]
    assert _relative(synthesized, tmp_path) == ["cdk.out/AppStack.template.json"]
    assert set(standalone).isdisjoint(synthesized)


def test_symlinked_file_escaping_the_root_is_skipped(
    tmp_path: Path, no_subprocess: None
) -> None:
    outside = _write(tmp_path / "outside" / "secret.yaml", STANDALONE_TEMPLATE)
    scan_root = tmp_path / "project"
    _write(scan_root / "template.yaml", STANDALONE_TEMPLATE)
    (scan_root / "linked.yaml").symlink_to(outside)

    assert _relative(cdk.find_templates(scan_root), scan_root) == ["template.yaml"]


def test_symlinked_directory_is_not_followed(
    tmp_path: Path, no_subprocess: None
) -> None:
    _write(tmp_path / "outside" / "secret.yaml", STANDALONE_TEMPLATE)
    scan_root = tmp_path / "project"
    scan_root.mkdir()
    (scan_root / "linked").symlink_to(tmp_path / "outside", target_is_directory=True)

    assert cdk.find_templates(scan_root) == []


# ---------------------------------------------------------------------------
# (d) discovery order is ascending by path (Requirement 10 AC3)
# ---------------------------------------------------------------------------


def test_scan_result_is_sorted_ascending_by_path(
    tmp_path: Path, no_subprocess: None
) -> None:
    for relative in (
        "z.yaml",
        "a.yml",
        "m/z.json",
        "m/a.template",
        "b/c/d.template.json",
        "b/a.yaml",
    ):
        _write(tmp_path / relative, STANDALONE_TEMPLATE)
    # A name matching no listed suffix is not a candidate.
    _write(tmp_path / "app.py", "print('hi')\n")

    found = cdk.find_templates(tmp_path)

    assert _relative(found, tmp_path) == [
        "a.yml",
        "b/a.yaml",
        "b/c/d.template.json",
        "m/a.template",
        "m/z.json",
        "z.yaml",
    ]
    assert found == sorted(found, key=str)


def test_scan_order_is_independent_of_creation_order(
    tmp_path: Path, no_subprocess: None
) -> None:
    forward = tmp_path / "forward"
    reverse = tmp_path / "reverse"
    names = ("alpha.yaml", "beta.json", "gamma.template", "delta.yml")
    for name in names:
        _write(forward / name, STANDALONE_TEMPLATE)
    for name in reversed(names):
        _write(reverse / name, STANDALONE_TEMPLATE)

    assert _relative(cdk.find_templates(forward), forward) == _relative(
        cdk.find_templates(reverse), reverse
    )


def test_uppercase_suffix_is_collected(tmp_path: Path, no_subprocess: None) -> None:
    _write(tmp_path / "Template.YAML", STANDALONE_TEMPLATE)

    assert _relative(cdk.find_templates(tmp_path), tmp_path) == ["Template.YAML"]


def test_synthesized_templates_are_sorted_ascending(
    tmp_path: Path, no_subprocess: None
) -> None:
    out = tmp_path / cdk.CDK_OUTPUT_DIRECTORY_NAME
    for name in ("zeta.template.json", "alpha.template.json", "mu.template.json"):
        _write(out / name, SYNTHESIZED_TEMPLATE)

    found = cdk.find_synthesized_templates(tmp_path)

    assert _relative(found, tmp_path) == [
        "cdk.out/alpha.template.json",
        "cdk.out/mu.template.json",
        "cdk.out/zeta.template.json",
    ]


# ---------------------------------------------------------------------------
# (e) confirmed=False starts no process (Requirement 8 AC3, AC5, Property 25)
# ---------------------------------------------------------------------------


def _layout_no_cdk(root: Path) -> None:
    _write(root / "template.yaml", STANDALONE_TEMPLATE)


def _layout_cdk_json_only(root: Path) -> None:
    _cdk_project(root)


def _layout_cdk_out_only(root: Path) -> None:
    _write(
        root / cdk.CDK_OUTPUT_DIRECTORY_NAME / "AppStack.template.json",
        SYNTHESIZED_TEMPLATE,
    )


def _layout_cdk_json_and_out(root: Path) -> None:
    _cdk_project(root)
    _layout_cdk_out_only(root)


def _layout_empty(root: Path) -> None:
    return None


LAYOUTS: Tuple[Tuple[str, Callable[[Path], None], List[str]], ...] = (
    ("empty", _layout_empty, []),
    ("no-cdk", _layout_no_cdk, []),
    ("cdk.json only", _layout_cdk_json_only, []),
    ("cdk.out only", _layout_cdk_out_only, ["cdk.out/AppStack.template.json"]),
    (
        "cdk.json and cdk.out",
        _layout_cdk_json_and_out,
        ["cdk.out/AppStack.template.json"],
    ),
)


@pytest.mark.parametrize(
    "layout, expected",
    [(layout, expected) for _name, layout, expected in LAYOUTS],
    ids=[name for name, _layout, _expected in LAYOUTS],
)
def test_unconfirmed_synth_starts_no_process(
    tmp_path: Path,
    no_subprocess: None,
    layout: Callable[[Path], None],
    expected: List[str],
) -> None:
    layout(tmp_path)

    templates = cdk.synth_if_confirmed(tmp_path, confirmed=False)

    assert _relative(templates, tmp_path) == expected


def test_unconfirmed_synth_warns_on_a_cdk_project(
    tmp_path: Path,
    no_subprocess: None,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _cdk_project(tmp_path)

    assert cdk.synth_if_confirmed(tmp_path, confirmed=False) == []

    captured = capsys.readouterr()
    assert captured.out == ""
    assert cdk.SYNTH_WARNING in captured.err
    assert cdk.SYNTH_NOT_CONFIRMED_NOTICE in captured.err


def test_detection_and_discovery_start_no_process(
    tmp_path: Path, no_subprocess: None
) -> None:
    _layout_cdk_json_and_out(tmp_path)

    cdk.detect_cdk_project(tmp_path)
    cdk.find_synthesized_templates(tmp_path)
    cdk.find_templates(tmp_path)
    cdk.partition_templates(tmp_path)


# ---------------------------------------------------------------------------
# (f) confirmed=True without the CDK CLI (Requirement 8 AC8)
# ---------------------------------------------------------------------------


def test_confirmed_synth_without_cdk_reports_docs_url(
    tmp_path: Path, empty_path: Path
) -> None:
    _cdk_project(tmp_path)

    with pytest.raises(ToolUnavailableError) as excinfo:
        cdk.synth_if_confirmed(tmp_path, confirmed=True)

    error = excinfo.value
    docs_url = TOOL_REQUIREMENTS[CDK].docs_url
    assert error.tool == CDK
    assert docs_url in (error.remediation or "")
    assert error.required_min_version == TOOL_REQUIREMENTS[CDK].min_version
    assert error.to_structured_error("cdk")["error_class"] == "tool_unavailable"


def test_confirmed_synth_on_a_non_cdk_directory_is_refused(
    tmp_path: Path, no_subprocess: None
) -> None:
    """No cdk.json means no reason to execute project code."""
    _write(tmp_path / "template.yaml", STANDALONE_TEMPLATE)

    with pytest.raises(InvalidArgumentsError):
        cdk.synth_if_confirmed(tmp_path, confirmed=True)


# ---------------------------------------------------------------------------
# Confirmed synth: success, failure, timeout (Requirement 8 AC6, AC7)
# ---------------------------------------------------------------------------


def test_confirmed_synth_runs_in_the_project_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fake_cdk: Callable[..., Path],
) -> None:
    project = tmp_path / "project"
    _cdk_project(project)
    fake_cdk(
        "mkdir -p cdk.out\n"
        "printf '%s' '{\"Resources\":{}}' > cdk.out/AppStack.template.json\n"
        "exit 0\n"
    )
    # The process runs elsewhere: only a working directory change can make the
    # fake cdk write into the project.
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    templates = cdk.synth_if_confirmed(project, confirmed=True)

    assert _relative(templates, project) == ["cdk.out/AppStack.template.json"]
    assert Path.cwd() == elsewhere.resolve()
    assert list(elsewhere.iterdir()) == []


def test_confirmed_synth_non_zero_exit_reports_stderr_and_does_not_fall_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = _cdk_project(tmp_path)
    stale = _write(
        project / cdk.CDK_OUTPUT_DIRECTORY_NAME / "Stale.template.json",
        SYNTHESIZED_TEMPLATE,
    )
    stderr = "\n".join("line {0}".format(index) for index in range(1, 9))
    monkeypatch.setattr(
        cdk, "require_known_tool", lambda name: ToolInfo(name, "/fake/cdk", "2.1.0")
    )
    monkeypatch.setattr(
        cdk.proc,
        "run",
        lambda argv, timeout_s: ProcResult(
            exit_code=1, stdout="", stderr=stderr
        ),
    )

    with pytest.raises(ToolExecutionError) as excinfo:
        cdk.synth_if_confirmed(project, confirmed=True)

    error = excinfo.value
    assert error.tool == CDK
    assert error.tool_exit_code == 1
    assert error.stderr_head == ["line {0}".format(index) for index in range(1, 6)]
    assert cdk.CDK_OUTPUT_DIRECTORY_NAME in (error.remediation or "")
    # AC7: the previously synthesized template is not returned as a fallback.
    assert stale.is_file()


def test_confirmed_synth_timeout_reports_no_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = _cdk_project(tmp_path)
    recorded: List[int] = []

    def timing_out(argv: List[str], timeout_s: int) -> ProcResult:
        recorded.append(timeout_s)
        raise ToolTimeoutError(
            "/fake/cdk exceeded its {0}s timeout".format(timeout_s),
            tool="/fake/cdk",
            stderr="synth stalled\nsecond line\n",
        )

    monkeypatch.setattr(
        cdk, "require_known_tool", lambda name: ToolInfo(name, "/fake/cdk", "2.1.0")
    )
    monkeypatch.setattr(cdk.proc, "run", timing_out)

    with pytest.raises(ToolTimeoutError) as excinfo:
        cdk.synth_if_confirmed(project, confirmed=True)

    error = excinfo.value
    assert cdk.SYNTH_TIMEOUT_S == 120
    assert recorded == [cdk.SYNTH_TIMEOUT_S]
    assert error.tool == CDK
    assert error.stderr_head == ["synth stalled", "second line"]
    assert "No alternative synthesis mode" in (error.remediation or "")


def test_synth_argv_is_a_fixed_two_element_array() -> None:
    assert cdk.build_synth_argv() == [CDK, "synth"]
    assert cdk.build_synth_argv(executable="/usr/local/bin/cdk") == [
        "/usr/local/bin/cdk",
        "synth",
    ]
