"""Regression: a missing or unusable external tool fails loudly, never silently.

Requirement guarded
-------------------

Requirement 12 AC7: an unavailable cfn-lint or cfn-guard yields a structured error
naming the tool and its installation instructions, with no unhandled exception.
Requirement 12 AC11 names ``missing external tool`` as one of the six security
cases the regression suite must carry, and steering/testing.md requires each of
the three external tools to fail *safely* when it is not usable.

Why this belongs in a security regression suite
-----------------------------------------------

Because the dangerous failure here is not a crash. It is a clean report of zero
Findings produced by a review during which nothing actually ran. A caller using
this plugin as a quality gate reads ``summary`` and exit 0 and merges; if a
missing cfn-guard had been quietly skipped, the gate would have passed a Template
nobody checked. Every case below therefore asserts that the *absence* is stated:

- ``errors[]`` carries the tool name and a remediation
  (:func:`test_a_missing_cfn_lint_exits_five_and_says_how_to_install_it`);
- ``tools[]`` still lists the tool, so "no findings" is distinguishable from
  "nothing looked";
- exit 0 through the orchestrator happens only because another Source really did
  review something (:func:`test_the_orchestrator_records_the_failure_and_keeps_going`),
  which is what makes that 0 a statement about work done rather than about a
  failure ignored.

The third case is the one no fake tool can produce. ``tests/fakebin/`` is full of
scripts that *run*; a tool that is present, has its execute bit set, and cannot be
started at all reaches a different branch of :mod:`iacreview.proc` -- the one where
the operating system puts the offending filename into ``str(exc)``, which is where
an absolute host path entered the report before the message was rebuilt from the
errno alone. The recipe is a file whose shebang names an interpreter that does not
exist, and it is constructed inline rather than committed to ``tests/fakebin/``
because a committed script whose shebang must stay broken is a trap for the next
reader, and because the path it must not leak has to be one this test knows.

Technique
---------

``PATH`` is *replaced* with a single directory, never extended: a fake is only a
fake if it is the only thing resolvable, and cfn-guard is installed on many
development machines. Replacing it also removes the real cfn-lint, so no case here
depends on what this machine happens to have. The child interpreter is invoked by
absolute path, so an empty ``PATH`` does not make Python itself unfindable.

Cross-references, not repeated here
-----------------------------------

``tests/integration/test_tool_unavailable.py``
    The full matrix: three tools x four situations (absent, below minimum, crash,
    timeout), each one's ``error_class``, the per-tool remediation text, the
    version-shortfall fields, and the standalone-versus-orchestrated exit code for
    all eight analyzer combinations. It owns coverage, and it runs entry points
    in-process so it can shorten timeouts. This file pins the three named examples
    at the process boundary, where a traceback would actually be observable.
``tests/integration/test_fakebin_drives_sources.py``
    That each fake reaches the branch it exists for.
``tests/unit/test_proc.py`` / ``tests/unit/test_toolcheck.py``
    The unit-level behaviour of the resolution and version gates.
"""

from __future__ import annotations

import stat
from pathlib import Path

from iacreview import exitcodes
from iacreview.toolcheck import CFN_LINT

from skillrun import CFN_LINT_SKILL, ORCHESTRATOR, make_workspace, run_skill


def test_a_missing_cfn_lint_exits_five_and_says_how_to_install_it(
    tmp_path: Path, fakebin_dir: Path
) -> None:
    """The standalone Skill: exit 5, and a report that names the gap.

    ``cfn-lint-missing/`` is an empty directory, so ``PATH`` resolves nothing at
    all. The report is still printed with a non-zero exit code, and that is the
    point: for this failure the ``errors[]`` entry *is* the content, so a Skill
    that exited 5 with an empty stdout would leave the caller with a number and no
    way to know which tool was missing.

    ``tools[]`` is asserted for the reason the module docstring gives: the tool is
    reported as unusable rather than omitted (Requirement 15 AC4).
    """
    workspace = make_workspace(tmp_path)

    run = run_skill(
        CFN_LINT_SKILL,
        ["--target", "app.yaml"],
        cwd=workspace,
        path=fakebin_dir / "cfn-lint-missing",
    )

    run.assert_no_traceback()
    assert run.exit_code == exitcodes.TOOL_UNAVAILABLE
    assert run.error_classes() == ["tool_unavailable"]
    assert run.report is not None
    error = run.report["errors"][0]
    assert error["tool"] == CFN_LINT
    assert "pip install cfn-lint" in str(error["remediation"])
    assert run.report["findings"] == []
    assert [entry["name"] for entry in run.report["tools"]] == [CFN_LINT]


def test_the_orchestrator_records_the_failure_and_keeps_going(
    tmp_path: Path, fakebin_dir: Path
) -> None:
    """Requirement 2 AC10: one unusable tool does not stop the review.

    With ``PATH`` pointing at an empty directory, *both* analyzers are missing and
    both failures are recorded. The IAM Source needs no external tool, so it still
    produces Findings -- which is what makes exit 0 defensible here and is asserted
    rather than assumed. Without that assertion this case would be indistinguishable
    from the silent-skip failure the module docstring describes.
    """
    workspace = make_workspace(tmp_path)

    run = run_skill(
        ORCHESTRATOR,
        ["--target", "app.yaml"],
        cwd=workspace,
        path=fakebin_dir / "cfn-lint-missing",
    )

    run.assert_no_traceback()
    assert run.exit_code == exitcodes.OK
    assert run.report is not None
    assert run.report["findings"], "the IAM Source should still have reported"
    assert run.error_classes() == ["tool_unavailable", "tool_unavailable"]
    assert {str(entry["tool"]) for entry in run.report["errors"]} == {
        CFN_LINT,
        "cfn-guard",
    }


def test_a_tool_that_cannot_be_started_is_reported_without_its_path(
    tmp_path: Path,
) -> None:
    """Present, executable, and unstartable: exit 6, and no host path on stdout.

    The interpreter named in the shebang does not exist, so :func:`shutil.which`
    finds the file and ``execve`` refuses it. Two claims: the failure is
    ``tool_execution`` with exit 6 rather than an unhandled ``OSError``, and the
    directory holding the broken executable appears nowhere in stdout -- the
    operating system puts that filename into ``str(exc)``, so the message has to be
    built from the errno instead (Requirement 16 AC11).
    """
    workspace = make_workspace(tmp_path)
    unusable = tmp_path / "bin"
    unusable.mkdir()
    executable = unusable / CFN_LINT
    executable.write_text(
        "#!{0}/no-such-interpreter\n".format(tmp_path), encoding="utf-8"
    )
    executable.chmod(executable.stat().st_mode | stat.S_IXUSR)

    run = run_skill(
        CFN_LINT_SKILL, ["--target", "app.yaml"], cwd=workspace, path=unusable
    )

    run.assert_no_traceback()
    assert run.exit_code == exitcodes.TOOL_EXECUTION_FAILURE
    assert run.error_classes() == ["tool_execution"]
    assert run.report is not None
    assert run.report["errors"][0]["tool"] == CFN_LINT
    assert str(tmp_path) not in run.stdout
