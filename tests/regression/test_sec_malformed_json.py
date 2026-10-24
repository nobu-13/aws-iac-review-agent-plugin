"""Regression: malformed JSON fails safely, with the position it failed at.

Requirement guarded
-------------------

Requirement 12 AC8: malformed JSON returns a structured error carrying the parse
error *type* and *location*, with no unhandled exception. Requirement 12 AC11
names ``malformed JSON`` as one of the six security cases the regression suite
must carry, and steering/security.md requires that an invalid document fail
without arbitrary code execution, a leaked secret, disclosed environment
information, or a read of an unrelated file.

Why these examples are pinned
-----------------------------

JSON matters on its own rather than as "YAML's other syntax", for two reasons
that both show up below.

It is the format ``cdk synth`` produces, so a malformed JSON Template is the
shape a *generated* input fails in, and the position is what points a user at the
generator's output rather than at their own source.

And it is the format whose failure is not an exception the parser declares.
:func:`test_a_document_nested_past_the_recursion_limit_fails_as_a_parse_error`
pins the reason :func:`iacreview.template.parse_template_text` catches broadly
instead of catching only ``JSONDecodeError``: a few kilobytes of ``[`` used to
exhaust the interpreter's stack, and ``json`` raised ``RecursionError``, which is
not a subclass of ``ValueError`` and would otherwise leave the process as a
traceback with an undefined exit status. Because that limit differs by Python
version, :mod:`iacreview.template` now raises the ``RecursionError`` itself, from
the explicit bound :data:`iacreview.template.MAX_JSON_NESTING_DEPTH`, before the
decoder runs; it still travels through the same broad ``except``. A later
contributor narrowing that ``except`` to "the errors the decoder documents"
would be making a reasonable-looking change that reintroduces exactly that,
which is what makes the case worth a name.

Bounded work with a deterministic outcome is also the line this file stops at. A
YAML alias bomb is *not* here, and ``tests/integration/test_malformed_input.py``
records why at length: it is an availability attack, v0.1 sets no input size or
expansion budget to test against, and a test that merely hoped the process died
quickly would be worse than none. That is a missing requirement, not an assertion
to invent.

Cross-references, not repeated here
-----------------------------------

``tests/integration/test_malformed_input.py``
    The full matrix -- fourteen inputs against all six entry points -- including
    these fixtures, and including the counter-case that a UTF-8 BOM before a
    *YAML* Template is accepted while the same BOM before JSON is not. That
    asymmetry is a property of the two parsers and is asserted there.
``tests/property/test_prop_template.py`` (Property 17)
    Safe failure for *any* byte string written to an input file: either success or
    a documented ``IacReviewError`` subclass, never an undocumented exception.
``tests/unit/test_template.py``
    Which exception and which ``error_type`` each input yields.
``tests/regression/test_sec_no_host_path_in_errors.py``
    That these messages carry no absolute host path.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Tuple

import pytest

from iacreview import exitcodes, template
from iacreview.errors import TemplateParseError

from skillrun import IAM_SKILL, invalid_fixture, make_workspace, run_skill

#: Nesting depth for the recursion case. Past
#: :data:`iacreview.template.MAX_JSON_NESTING_DEPTH`, and small enough that the file is a few kilobytes and the
#: attempt is instant.
NESTING_DEPTH = 2000

#: Where the decoder reports the trailing comma in ``malformed_syntax.json``.
#:
#: CPython 3.13 gave a trailing comma its own message ("Illegal trailing comma
#: before end of object") and points at the comma itself, line 5 column 32.
#: Earlier versions report where they expected the next property name, line 6
#: column 5. Both directions are fixed literals, so a change on either side of
#: the boundary fails the test rather than being absorbed by it.
TRAILING_COMMA_POSITION: Tuple[int, int] = (
    (6, 5) if sys.version_info < (3, 13) else (5, 32)
)


def decoder_position(data: bytes) -> Tuple[int, int]:
    """Return the ``(lineno, colno)`` the running ``json`` decoder reports."""
    with pytest.raises(json.JSONDecodeError) as caught:
        json.loads(data.decode("utf-8"))
    return (caught.value.lineno, caught.value.colno)


def place(name: str, workspace: Path) -> Path:
    """Copy a committed malformed fixture into ``workspace`` under its own name."""
    destination = workspace / name
    destination.write_bytes(invalid_fixture(name))
    return destination


def test_a_trailing_comma_reports_its_type_and_position(tmp_path: Path) -> None:
    """``malformed_syntax.json``: the mistake a hand-edited Template makes.

    The position is :data:`TRAILING_COMMA_POSITION` for the running version. The
    coordinates are asserted as literals because they are the answer a user acts
    on, and because a broad ``except`` that reported only "invalid JSON" would
    still satisfy "no unhandled exception" and still exit 4. They are also
    checked against the decoder's own ``lineno``/``colno`` for the same bytes,
    so the product cannot report a position the decoder did not give.
    """
    workspace = make_workspace(tmp_path)
    path = place("malformed_syntax.json", workspace)

    with pytest.raises(TemplateParseError) as caught:
        template.load_template(path)

    error = caught.value
    assert error.error_class == "parse_failure"
    assert error.exit_code == exitcodes.PARSE_FAILURE
    assert error.error_type == "json.decoder.JSONDecodeError"
    assert (error.line, error.column) == TRAILING_COMMA_POSITION
    assert (error.line, error.column) == decoder_position(
        invalid_fixture("malformed_syntax.json")
    )


def test_a_byte_order_mark_before_json_is_reported_as_a_parse_failure(
    tmp_path: Path,
) -> None:
    """``bom_prefixed.json``: an invisible three bytes, so the message must say so.

    Some editors and every PowerShell redirection prepend a BOM. Python's JSON
    decoder refuses it and says which encoding would have worked, and that text is
    kept rather than replaced by a generic message: it is the one thing that turns
    a file which *looks* correct into a diagnosable one.
    """
    workspace = make_workspace(tmp_path)
    path = place("bom_prefixed.json", workspace)

    with pytest.raises(TemplateParseError) as caught:
        template.load_template(path)

    error = caught.value
    assert error.error_type == "json.decoder.JSONDecodeError"
    assert (error.line, error.column) == (1, 1)
    assert "BOM" in error.message


def test_a_document_nested_past_the_recursion_limit_fails_as_a_parse_error(
    tmp_path: Path,
) -> None:
    """A few kilobytes of ``[`` must be a parse failure, not a ``RecursionError``.

    The pin is the ``error_type``: ``RecursionError`` appears there, which is only
    possible because :func:`iacreview.template.parse_template_text` catches more
    than the decoder's declared exception. Narrow that ``except`` and this case
    turns into an unhandled exception with an undefined exit status -- the
    "untrusted input must fail cleanly" contract broken by a tidying change.
    """
    workspace = make_workspace(tmp_path)
    path = workspace / "deeply_nested.json"
    path.write_text("[" * NESTING_DEPTH + "]" * NESTING_DEPTH, encoding="utf-8")

    with pytest.raises(TemplateParseError) as caught:
        template.load_template(path)

    assert caught.value.error_class == "parse_failure"
    assert caught.value.error_type == "RecursionError"


def test_a_malformed_json_target_exits_four_with_one_parse_failure_in_the_report(
    tmp_path: Path,
) -> None:
    """The contract as a user meets it: exit 4, and the position on stdout.

    A parse failure is one of the two classes for which a Skill still prints a
    report, because the ``errors[]`` entry is the answer rather than a footnote.
    The position is read out of the rendered ``message``: ``errors[]`` entries
    carry exactly :data:`iacreview.errors.STRUCTURED_ERROR_KEYS`, a fixed contract
    consumers index without existence checks, so the type, line and column are
    rendered into the message by
    :data:`iacreview.template.PARSE_POSITION_FORMAT` instead of widening that set.
    """
    workspace = make_workspace(tmp_path)
    place("malformed_syntax.json", workspace)

    run = run_skill(
        IAM_SKILL, ["--target", "malformed_syntax.json"], cwd=workspace
    )

    run.assert_no_traceback()
    assert run.exit_code == exitcodes.PARSE_FAILURE
    assert run.error_classes() == ["parse_failure"]
    assert run.report is not None
    assert run.report["findings"] == []
    message = str(run.report["errors"][0]["message"])
    assert "malformed_syntax.json" in message
    assert "at line {0}, column {1}".format(*TRAILING_COMMA_POSITION) in message
    assert "at line {0}, column {1}".format(
        *decoder_position(invalid_fixture("malformed_syntax.json"))
    ) in message


def test_a_megabyte_of_brackets_fails_closed_without_a_traceback(
    tmp_path: Path,
) -> None:
    """Far past the explicit bound: exit 4 on every Python, with a fixed message.

    One million ``[`` is past CPython 3.13's own recursion limit as well as
    3.9's, but the outcome must not come from either: the bound
    :data:`iacreview.template.MAX_JSON_NESTING_DEPTH` is checked before the
    decoder runs, so the message is the module's fixed text on every version.
    """
    workspace = make_workspace(tmp_path)
    (workspace / "deep.json").write_text("[" * 1_000_000, encoding="utf-8")

    run = run_skill(IAM_SKILL, ["--target", "deep.json"], cwd=workspace)

    run.assert_no_traceback()
    assert run.exit_code == exitcodes.PARSE_FAILURE
    assert run.error_classes() == ["parse_failure"]
    assert run.report is not None
    message = str(run.report["errors"][0]["message"])
    assert "RecursionError at line 1, column 1" in message
    assert template.JSON_NESTING_LIMIT_MESSAGE in message
    assert str(workspace) not in run.stdout
    assert str(workspace.resolve()) not in run.stdout
