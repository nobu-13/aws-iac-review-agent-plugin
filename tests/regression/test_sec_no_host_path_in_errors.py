"""Regression: no ``errors[]`` message may carry an absolute host path.

Requirement guarded
-------------------

Requirement 16 AC11: two invocations with identical input produce byte-identical
stdout, "containing no timestamps, no absolute host paths, and no other
environment-dependent values". design.md's failure mode matrix puts a parse
failure and a non-reviewable file on stdout as a partial report, so the messages
those failures carry are stdout content and fall under AC11. steering/security.md
adds the security reading: an absolute path discloses the layout of the machine
the review ran on, to whoever receives the report.

Why this is fixed as a regression
---------------------------------

The defect was live and reached four entry points.
:class:`~iacreview.errors.TemplateParseError` and
:class:`~iacreview.errors.NotReviewableError` were built from the path the caller
passed, and every standalone Skill passes what
:func:`iacreview.pathguard.resolve_within` returns -- an absolute path, correctly
so, since that is what an external tool has to be given. A malformed Template
therefore put the host's directory layout into ``errors[].message`` on stdout.
The ``iac-review`` orchestrator did not leak, because it loads Templates by their
workspace-relative path; that difference is exactly why a per-caller fix is not
enough. One caller had already worked around it locally, three had not, and the
next caller written would have had to know.

The fix renders the path once, inside :mod:`iacreview.template`
(:func:`iacreview.source.display_path`), which is the same choice
:mod:`iacreview.proc` makes for an executable path: reduce it at the single point
that builds the message, so no call site can reintroduce it. The sweep that
followed found two more messages of the same shape -- an unreadable
``--agent-findings`` file, and an unusable cfn-guard rule sidecar -- and both are
pinned here beside the original.

Each case below asserts two things: that the message still *names* the file (a
message that identifies nothing would satisfy AC11 and help nobody), and that it
names it without an absolute path.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Tuple

import pytest

from iacreview import agentin, exitcodes, template
from iacreview.cfnguard import load_rule_metadata
from iacreview.errors import (
    InputNotFoundError,
    NotReviewableError,
    TemplateParseError,
)

#: Inputs whose failure message named an absolute path before the fix.
PARSE_FAILURE_FIXTURES: Tuple[str, ...] = (
    "malformed_syntax.yaml",
    "malformed_syntax.json",
    "truncated.yaml",
    "binary_content.yaml",
    "empty_file.yaml",
    "tab_indentation.yaml",
    "unsupported_yaml_tag.yaml",
    "python_object_tag.yaml",
    "bom_prefixed.json",
)

#: Inputs that parse and are still not reviewable.
NOT_REVIEWABLE_FIXTURES: Tuple[str, ...] = (
    "no_resources.yaml",
    "empty_resources.json",
)

#: The Skill whose leak was reported: it hands ``load_template`` the resolved
#: absolute path and prints a partial report for a parse failure. One subprocess
#: case is enough here, because the fix is in the shared module and
#: ``tests/integration/test_malformed_input.py`` runs the whole matrix.
LEAKING_SKILL = Path("skills") / "iam-review" / "scripts" / "run_iam_scan.py"

TIMEOUT_S = 60


def copy_fixture(name: str, fixtures_dir: Path, destination: Path) -> Path:
    """Copy ``name`` from ``tests/fixtures/invalid`` into ``destination``.

    Returned as an *absolute* path, which is the shape a caller holds after
    containment and therefore the shape that reproduced the defect. The
    destination is outside the workspace root of the test session, so a message
    that leaked would leak the temporary directory -- visible in the assertion
    below rather than hidden behind a coincidentally relative path.
    """
    target = destination / name
    target.write_bytes((fixtures_dir / "invalid" / name).read_bytes())
    return target


def assert_names_the_file_but_not_the_path(message: str, path: Path) -> None:
    """The message identifies the file without disclosing where it lives."""
    assert path.name in message, message
    assert str(path) not in message, message
    assert str(path.parent) not in message, message


@pytest.mark.parametrize("name", PARSE_FAILURE_FIXTURES)
def test_a_parse_failure_message_carries_no_absolute_path(
    name: str, fixtures_dir: Path, tmp_path: Path
) -> None:
    path = copy_fixture(name, fixtures_dir, tmp_path)

    with pytest.raises(TemplateParseError) as caught:
        template.load_template(path)

    error = caught.value
    assert_names_the_file_but_not_the_path(error.message, path)
    # The rendered StructuredError is what actually reaches stdout, so the
    # assertion is repeated against it: a future field carrying the path would
    # pass the check above and still leak.
    assert str(path) not in json.dumps(error.to_structured_error())


@pytest.mark.parametrize("name", NOT_REVIEWABLE_FIXTURES)
def test_a_not_reviewable_message_carries_no_absolute_path(
    name: str, fixtures_dir: Path, tmp_path: Path
) -> None:
    path = copy_fixture(name, fixtures_dir, tmp_path)

    with pytest.raises(NotReviewableError) as caught:
        template.load_template(path)

    assert_names_the_file_but_not_the_path(caught.value.message, path)


def test_an_unreadable_input_leaks_neither_the_path_nor_the_oserror_filename(
    tmp_path: Path,
) -> None:
    """A directory reaches ``errors[]`` through ``iac-review``'s candidate loop.

    Two leaks in one message before the fix: the path this module was given, and
    the filename CPython appends to ``str(OSError)``. The errno and its text are
    kept, because they are the whole diagnostic value.
    """
    directory = tmp_path / "templates"
    directory.mkdir()

    with pytest.raises(InputNotFoundError) as caught:
        template.load_template(directory)

    message = caught.value.message
    assert str(directory) not in message, message
    assert "errno" in message, message


def test_an_unreadable_agent_findings_file_carries_no_absolute_path(
    tmp_path: Path,
) -> None:
    """``iac-review`` records this failure in ``errors[]`` rather than raising.

    So the message is stdout content, and the same two leaks applied: the
    resolved path and the ``OSError`` filename. A directory is used because
    :func:`iacreview.pathguard.resolve_within` has already established that the
    path exists by the time this function sees it.
    """
    directory = tmp_path / "agent-findings"
    directory.mkdir()

    with pytest.raises(InputNotFoundError) as caught:
        agentin.load_agent_findings(directory)

    message = caught.value.message
    assert str(directory) not in message, message
    assert directory.name in message, message


def test_a_broken_rule_sidecar_names_the_category_not_its_directory(
    tmp_path: Path,
) -> None:
    """The cfn-guard rule metadata failure is an ``errors[]`` entry too.

    Reached with the bundled rule set, its path is the plugin's install
    directory, which is as environment-dependent as any other absolute path. The
    category directory plus the file name is what a contributor needs to find it.
    """
    category = tmp_path / "encryption"
    category.mkdir()
    (category / "r.guard").write_text("rule r { Resources exists }", encoding="utf-8")
    (category / "_meta.json").write_text("{not json", encoding="utf-8")

    (error,) = load_rule_metadata([tmp_path]).errors

    message = str(error["message"])
    assert "encryption/_meta.json" in message, message
    assert str(tmp_path) not in message, message
    assert str(tmp_path) not in str(error["remediation"]), error["remediation"]


def test_a_standalone_skill_prints_no_absolute_path_for_a_parse_failure(
    plugin_root: Path, fixtures_dir: Path, tmp_path: Path
) -> None:
    """The defect as it was reported: from outside the process, on stdout.

    The Skill runs with the workspace as its working directory, is given a
    workspace-relative ``--target``, and resolves it to an absolute path
    internally -- which is the step that used to reach stdout.
    """
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    copy_fixture("malformed_syntax.yaml", fixtures_dir, workspace)

    completed = subprocess.run(
        [
            sys.executable,
            str(plugin_root / LEAKING_SKILL),
            "--target",
            "malformed_syntax.yaml",
        ],
        cwd=str(workspace),
        env=dict(os.environ),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=TIMEOUT_S,
    )

    assert completed.returncode == exitcodes.PARSE_FAILURE, completed.stderr
    report = json.loads(completed.stdout)
    assert [entry["error_class"] for entry in report["errors"]] == ["parse_failure"]
    assert "malformed_syntax.yaml" in str(report["errors"][0]["message"])
    for absolute in (str(workspace), str(tmp_path), sys.executable):
        assert absolute not in completed.stdout
