"""Regression: a YAML alias bomb fails safely, bounded, and positioned.

Requirement guarded
-------------------

Requirement 17 AC3: a YAML document that uses recursive or fan-out aliases (a
"billion laughs" style payload) must fail as a *parse failure with a position*
rather than exhausting memory or CPU. steering/security.md states the security
half: untrusted IaC must fail safely, and a malformed document must not let an
attacker hang the review or drive it out of memory.

Earlier, ``tests/integration/test_malformed_input.py`` noted that v0.1 set no
input bound and treated an alias bomb as an availability concern left for later.
v0.8.0 closes that: :mod:`iacreview.yamlcfn` counts alias references as they are
composed and refuses the document once the count passes
:data:`iacreview.yamlcfn.MAX_ALIAS_EXPANSIONS`. This file pins that the refusal
reaches a user as a positioned :class:`~iacreview.errors.TemplateParseError`.

Why this consumes no memory
---------------------------

The bound is enforced during *composition*, node by node, before the document is
deep-constructed. A ``billion_laughs.yaml`` whose deepest level would expand to
billions of scalars is abandoned in its first, cheap levels, because the alias
*references* are counted as the composer walks the events -- the count trips long
before any fan-out is materialized. The budget is monkeypatched to a small value
so the refusal is reached within a few dozen alias references; the fixture is
never expanded, in this test or by the loader, so no real memory is used
(Requirement 17 AC4: the technique is portable and does not rely on a
platform-specific resource limit).

Cross-references
----------------

``tests/unit/test_yamlcfn.py``
    The loader-level behavior: the boundary value, per-document counter reset,
    and that a normal template reusing aliases is unaffected.
``tests/regression/test_sec_malformed_yaml.py``
    The sibling malformed-YAML cases and the ``!!python/object`` refusal.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from iacreview import exitcodes, template, yamlcfn
from iacreview.errors import TemplateParseError

#: The committed fan-out fixture. Ten levels of ten references each; its deepest
#: level would expand to 10**8 elements if it were ever constructed. It is a few
#: dozen lines of text and is refused before construction, so its size on disk is
#: all it ever costs.
ALIAS_BOMB_FIXTURE = "billion_laughs.yaml"

#: A budget small enough to be crossed in the fixture's first levels. Set on the
#: module under test with ``monkeypatch`` so the refusal is reached without a
#: real billion-laughs expansion and without depending on the shipped default.
SMALL_BUDGET = 20


def place(name: str, workspace: Path, fixtures_dir: Path) -> Path:
    """Copy a committed invalid fixture into ``workspace`` under its own name."""
    destination = workspace / name
    destination.write_bytes((fixtures_dir / "invalid" / name).read_bytes())
    return destination


def test_an_alias_bomb_fails_as_a_positioned_parse_error(
    monkeypatch: pytest.MonkeyPatch, fixtures_dir: Path, tmp_path: Path
) -> None:
    """``billion_laughs.yaml``: refused via ``load_template`` before it expands.

    The budget is small and monkeypatched, so the loader raises during
    composition -- no fan-out is built, no large memory is touched. The failure
    surfaces through the existing parse path as a ``TemplateParseError`` carrying
    the ``parse_failure`` class, exit code 4, and a line/column, exactly like any
    other malformed-YAML failure.
    """
    monkeypatch.setattr(yamlcfn, "MAX_ALIAS_EXPANSIONS", SMALL_BUDGET)
    monkeypatch.setattr(yamlcfn, "_LOADER", None)

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    path = place(ALIAS_BOMB_FIXTURE, workspace, fixtures_dir)

    with pytest.raises(TemplateParseError) as caught:
        template.load_template(path)

    error = caught.value
    assert error.error_class == "parse_failure"
    assert error.exit_code == exitcodes.PARSE_FAILURE
    assert error.error_type == "yaml.constructor.ConstructorError"
    # The position is part of the answer (Requirement 3 AC6): a bounded refusal
    # that pointed nowhere would be no better than an out-of-memory crash.
    assert error.line >= 1
    assert error.column >= 1
    # The message names the file the report way -- never as an absolute path.
    assert ALIAS_BOMB_FIXTURE in error.message
    assert str(path) not in error.message
