"""Regression: malformed YAML fails safely, with the position it failed at.

Requirement guarded
-------------------

Requirement 12 AC8: malformed YAML returns a structured error carrying the parse
error *type* and *location*, with no unhandled exception. Requirement 12 AC11
names ``malformed YAML`` as one of the six security cases the regression suite
must carry, and steering/security.md states the security half: an invalid YAML
document must not lead to arbitrary code execution, a leaked secret, disclosed
environment information, or a read of an unrelated file.

Why these examples are pinned
-----------------------------

Requirement 3 AC6 makes the *position* part of the answer, not a nicety, and a
position is the easiest thing in a report to lose to a refactor: a broad
``except`` that reports only "invalid YAML" would still satisfy "no unhandled
exception" and would still exit 4. Two of the cases below assert the exact line
and column, and ``tab_indentation.yaml`` is the reason why -- a TAB in
indentation is invisible in most editors and in most diffs, so the line and
column are the entire diagnostic value of that failure.

The other reason this file exists is
:func:`test_a_python_object_tag_is_refused_and_never_evaluated`. PyYAML's unsafe
loaders would turn ``!!python/object/apply:os.system`` into a call; the control is
that :mod:`iacreview.yamlcfn` derives its loader from ``SafeLoader`` and registers
each permitted CloudFormation short-form tag *explicitly* rather than accepting
any tag through ``add_multi_constructor``. That control is one line away from
being widened by someone adding a new short form, which is exactly the kind of
change a pinned case should survive.

Cross-references, not repeated here
-----------------------------------

``tests/integration/test_malformed_input.py``
    The full matrix -- fourteen inputs against all six entry points, 133 cases --
    including this file's fixtures. It owns coverage; this file owns the named
    security examples and the exact positions.
``tests/property/test_prop_template.py`` (Property 17, Property 21)
    Safe failure for *any* byte string, and "Template content is never executed"
    with the constructor side effect actually observed. The quantified claims;
    the cases here are the examples of them.
``tests/unit/test_template.py`` / ``tests/unit/test_yamlcfn.py``
    Which exception, which ``error_type``, and the loader's tag allowlist.
``tests/regression/test_sec_no_host_path_in_errors.py``
    That these same messages carry no absolute host path. Asserted there for
    every parse fixture, so it is not re-asserted here.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from iacreview import exitcodes, template
from iacreview.errors import TemplateParseError

from skillrun import IAM_SKILL, invalid_fixture, make_workspace, run_skill

#: The command embedded in ``python_object_tag.yaml``, and the string it would
#: print if PyYAML ever constructed that tag. Its absence from both streams is
#: what :func:`test_a_python_object_tag_is_refused_and_never_evaluated` observes.
PWNED_MARKER = "pwned"


def place(name: str, workspace: Path) -> Path:
    """Copy a committed malformed fixture into ``workspace`` under its own name.

    Copied rather than referenced in place because every ``--target`` has to
    resolve inside the workspace root the entry point runs in, and keeping the
    fixture's own name means a failing report names a file the reader can open.
    """
    destination = workspace / name
    destination.write_bytes(invalid_fixture(name))
    return destination


def test_an_unclosed_flow_sequence_reports_its_type_and_position(
    tmp_path: Path,
) -> None:
    """``malformed_syntax.yaml``: the ordinary case, with all three values present.

    The type is asserted by namespace rather than by class name. Whether PyYAML
    raises ``ParserError`` or ``ScannerError`` for a given syntax error is a detail
    of its scanner, not something this plugin defines; that it comes from ``yaml``
    and reaches the report at all is what the requirement asks for.
    """
    workspace = make_workspace(tmp_path)
    path = place("malformed_syntax.yaml", workspace)

    with pytest.raises(TemplateParseError) as caught:
        template.load_template(path)

    error = caught.value
    assert error.error_class == "parse_failure"
    assert error.exit_code == exitcodes.PARSE_FAILURE
    assert str(error.error_type).startswith("yaml.")
    assert (error.line, error.column) == (7, 1)


def test_a_tab_in_indentation_points_at_the_offending_line(tmp_path: Path) -> None:
    """``tab_indentation.yaml``: the position pinned exactly, on purpose.

    Line 8 column 1 is the TAB. This is the case where a report that said only
    "invalid YAML" would leave a user staring at a file that looks correct, so the
    coordinates are asserted as literals: they are the answer, not a detail.
    """
    workspace = make_workspace(tmp_path)
    path = place("tab_indentation.yaml", workspace)

    with pytest.raises(TemplateParseError) as caught:
        template.load_template(path)

    error = caught.value
    assert error.error_type == "yaml.scanner.ScannerError"
    assert (error.line, error.column) == (8, 1)


def test_a_tag_outside_the_cloudformation_allowlist_is_refused(tmp_path: Path) -> None:
    """``unsupported_yaml_tag.yaml``: an unknown tag is an error, not a value.

    The alternative -- constructing it into *something* -- would leave the review
    reasoning about a value the Template never expressed. The message names the
    tag, so a user who meant ``!Sub`` and typed something else can see what was
    read (design.md, "Template 内容を評価しない").
    """
    workspace = make_workspace(tmp_path)
    path = place("unsupported_yaml_tag.yaml", workspace)

    with pytest.raises(TemplateParseError) as caught:
        template.load_template(path)

    assert caught.value.error_type == "yaml.constructor.ConstructorError"
    assert "!Frobnicate" in caught.value.message


def test_a_python_object_tag_is_refused_and_never_evaluated(tmp_path: Path) -> None:
    """``python_object_tag.yaml``: Requirement 9 AC7, at the process boundary.

    The fixture asks PyYAML to construct ``os.system("echo pwned")``. Two claims,
    and the second is the security one: neither stream carries the marker that
    command would have printed. Observed from outside the process rather than by
    patching, because ``echo`` writing to the child's stdout is precisely the
    effect that would occur, and it would corrupt the JSON channel while doing it.
    """
    workspace = make_workspace(tmp_path)
    place("python_object_tag.yaml", workspace)

    run = run_skill(
        IAM_SKILL, ["--target", "python_object_tag.yaml"], cwd=workspace
    )

    run.assert_no_traceback()
    assert run.exit_code == exitcodes.PARSE_FAILURE
    assert PWNED_MARKER not in run.stdout
    assert PWNED_MARKER not in run.stderr


def test_a_malformed_target_exits_four_with_one_parse_failure_in_the_report(
    tmp_path: Path,
) -> None:
    """The contract as a user meets it: exit 4, and the position on stdout.

    A parse failure is one of the two classes for which a Skill still prints a
    report, because the ``errors[]`` entry *is* the answer -- a bare exit 4 would
    leave the caller with a number. The position is asserted through the rendered
    message rather than through fields of its own: ``errors[]`` entries carry
    exactly :data:`iacreview.errors.STRUCTURED_ERROR_KEYS`, a fixed contract that
    consumers index without existence checks, so the three values are rendered
    into ``message`` by :data:`iacreview.template.PARSE_POSITION_FORMAT`.
    """
    workspace = make_workspace(tmp_path)
    place("malformed_syntax.yaml", workspace)

    run = run_skill(
        IAM_SKILL, ["--target", "malformed_syntax.yaml"], cwd=workspace
    )

    run.assert_no_traceback()
    assert run.exit_code == exitcodes.PARSE_FAILURE
    assert run.error_classes() == ["parse_failure"]
    assert run.report is not None
    assert run.report["findings"] == []
    message = str(run.report["errors"][0]["message"])
    assert "malformed_syntax.yaml" in message
    assert "at line 7, column 1" in message
