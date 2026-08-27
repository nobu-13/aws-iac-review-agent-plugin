"""Shared entry-point runner for the security regression cases.

Every case in this directory that pins a *process-level* outcome needs the same
three things: a workspace root to run from, one Skill started as a child process,
and the exit code plus the two streams it produced. Requirement 12 AC11's six
case types are spread over six files, so that runner lives here rather than being
copied six times.

Not a ``conftest.py``: ``tests/conftest.py`` already exists, and two modules of
that name in directories without ``__init__.py`` are ambiguous to import by name
under pytest's prepend import mode. A plainly named sibling module is
unambiguous, and importing one is already the convention here --
``tests/integration/test_tool_unavailable.py`` imports ``use_fake`` from the
module that introduced it the same way. pytest inserts a test module's own
directory at the front of :data:`sys.path` before importing it, which is what
makes the bare module name resolvable.

Why a subprocess and not ``main()``
-----------------------------------

What these cases pin is a contract of the *process*: the exit code
(Requirement 16 AC8), the separation of JSON on stdout from diagnostics on stderr
(Requirement 16 AC10), and the absence of a traceback. An in-process ``main()``
call can assert the first two but not the third -- an exception that escaped
would fail the test as an error rather than as the contract violation it is, and
asserting "no traceback reached stderr" needs a real stderr to look at.
``tests/integration/test_tool_unavailable.py`` runs entry points in-process for
the opposite and equally good reason: it has to shorten tool timeouts, which a
child process cannot be told about.

Environment discipline
----------------------

The child's environment is built from :data:`os.environ`, so it joins the
coverage measurement when one is in progress (see ``tests/conftest.py``:
a hand-built environment silently drops the child out of the coverage report).
``PATH`` is *replaced* rather than extended when a case supplies one: a fake
external tool is only a fake if it is the only thing resolvable, and a real
cfn-guard is installed on many development machines. The child interpreter is
invoked as :data:`sys.executable`, an absolute path, so an empty ``PATH`` does
not make Python itself unfindable.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, NamedTuple, Optional, Sequence

__all__ = [
    "PLUGIN_ROOT",
    "ORCHESTRATOR",
    "IAM_SKILL",
    "CFN_LINT_SKILL",
    "TIMEOUT_S",
    "TEMPLATE_TEXT",
    "SkillRun",
    "run_skill",
    "make_workspace",
    "invalid_fixture",
]

# tests/regression/skillrun.py -> tests/regression -> tests -> plugin root.
# Derived here rather than imported from ``tests/conftest.py`` for the reason the
# module docstring gives; ``tests/unit/test_bootstrap.py`` guards the same kind of
# depth assumption for the entry points themselves.
PLUGIN_ROOT: Path = Path(__file__).resolve().parents[2]

#: Entry point of the orchestrator Skill, relative to the plugin root.
ORCHESTRATOR = Path("skills") / "iac-review" / "scripts" / "run_iac_review.py"

#: The Skill that invokes no external tool at all. Preferred wherever a case is
#: about the *input* rather than about a tool, because it makes the outcome
#: independent of what happens to be installed on the machine running the suite.
IAM_SKILL = Path("skills") / "iam-review" / "scripts" / "run_iam_scan.py"

#: The Skill that fronts cfn-lint, for the cases that are about a missing tool.
CFN_LINT_SKILL = Path("skills") / "cfn-lint-review" / "scripts" / "run_cfn_lint.py"

#: Generous. Every run here is an interpreter start plus a failure detected
#: early; one that takes longer has hung, which is itself the defect to report.
TIMEOUT_S = 60

#: A Template with something for the IAM Source to find, so that a report which
#: should carry Findings can be told apart from one that merely did not crash.
TEMPLATE_TEXT = """\
AWSTemplateFormatVersion: "2010-09-09"
Resources:
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


class SkillRun(NamedTuple):
    """What one Skill invocation produced, seen from outside the process.

    Attributes:
        exit_code: The child's exit status.
        stdout: Raw stdout. Either one JSON document or empty, never a fragment.
        stderr: Raw stderr, where diagnostics and any traceback would appear.
        report: ``stdout`` parsed, or ``None`` when stdout was empty. Which of the
            two it is is itself part of what several cases assert, so it is not
            normalized away.
    """

    exit_code: int
    stdout: str
    stderr: str
    report: Optional[Dict[str, Any]]

    def error_classes(self) -> List[str]:
        """Every ``errors[]`` class in the report, in report order.

        Returns:
            The classes, or an empty list when no report was printed -- so a
            caller comparing against an expected list sees a readable difference
            rather than an :class:`AttributeError`.
        """
        if self.report is None:
            return []
        return [str(entry["error_class"]) for entry in self.report["errors"]]

    def assert_no_traceback(self) -> None:
        """Assert that no unhandled exception escaped the entry point.

        Requirement 12 AC7 and steering/security.md both require untrusted input
        to fail *cleanly*. Two independent signals, because either alone can be
        fooled: :func:`iacreview.bootstrap.run_entry_point` prints the trace on
        stderr *and* returns :data:`iacreview.exitcodes.UNEXPECTED`, so a run that
        shows neither handled its failure deliberately.
        """
        assert "Traceback" not in self.stderr, self.stderr
        assert self.exit_code != 1, self.stderr


def run_skill(
    script: Path,
    argv: Sequence[str],
    *,
    cwd: Path,
    path: Optional[Path] = None,
) -> SkillRun:
    """Run one Skill entry point as a child process and collect its output.

    Args:
        script: The entry point's path relative to the plugin root, from the
            constants above.
        argv: Arguments after the script name.
        cwd: Working directory, which is the workspace root every entry point
            derives its containment root from.
        path: Directory to use as the child's entire ``PATH``, for a case that
            needs a fake external tool to be the only one resolvable. ``None``
            inherits this process's ``PATH``.

    Returns:
        A :class:`SkillRun`.
    """
    env = dict(os.environ)
    if path is not None:
        env["PATH"] = str(path)
    completed = subprocess.run(
        [sys.executable, str(PLUGIN_ROOT / script), *argv],
        cwd=str(cwd),
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=TIMEOUT_S,
    )
    report = json.loads(completed.stdout) if completed.stdout.strip() else None
    return SkillRun(completed.returncode, completed.stdout, completed.stderr, report)


def make_workspace(tmp_path: Path) -> Path:
    """Create a workspace root under ``tmp_path`` holding ``app.yaml``.

    A subdirectory of ``tmp_path`` rather than ``tmp_path`` itself, so that a
    sibling directory *outside* the containment root exists for the path
    traversal cases to point at.

    Args:
        tmp_path: pytest's per-test temporary directory.

    Returns:
        The workspace root.
    """
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "app.yaml").write_text(TEMPLATE_TEXT, encoding="utf-8")
    return root


def invalid_fixture(name: str) -> bytes:
    """Read a committed malformed input from ``tests/fixtures/invalid``.

    Args:
        name: File name inside that directory.

    Returns:
        Its bytes, read as bytes because several of the fixtures are not valid
        UTF-8 and copying them through :class:`str` would change what is tested.
    """
    return (PLUGIN_ROOT / "tests" / "fixtures" / "invalid" / name).read_bytes()
