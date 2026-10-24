"""Path containment and unsafe-argument checks.

The eight cases required by design.md ("Path containment") are covered:
accepted relative and absolute paths, ``../`` escape, multi-segment
``a/../../b`` escape, a symlink pointing outside the workspace, the
``/workspace-evil`` versus ``/workspace`` prefix trap, a filename containing a
shell metacharacter, and a missing path.

The workspace is built as ``tmp_path/workspace`` rather than ``tmp_path``
itself, so that a sibling directory can be created for the prefix-trap case.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, Optional, Type

import pytest

from iacreview import pathguard
from iacreview.errors import (
    InputNotFoundError,
    InvalidArgumentsError,
    MappingFileError,
    PathContainmentError,
    UnsafeArgumentError,
)

TEMPLATE_BODY = "Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n"


@pytest.fixture()
def workspace(tmp_path: Path) -> Path:
    """A workspace root holding ``templates/app.yaml``."""
    ws = tmp_path / "workspace"
    (ws / "templates").mkdir(parents=True)
    (ws / "templates" / "app.yaml").write_text(TEMPLATE_BODY, encoding="utf-8")
    return ws


@pytest.fixture()
def outside_file(tmp_path: Path) -> Path:
    """A file outside the workspace, used as a symlink / escape target."""
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "secret.yaml"
    target.write_text(TEMPLATE_BODY, encoding="utf-8")
    return target


# --- (a) accepted relative path ---------------------------------------------


def test_relative_path_inside_workspace_is_accepted(workspace: Path) -> None:
    resolved = pathguard.resolve_within("templates/app.yaml", workspace)

    assert resolved == (workspace / "templates" / "app.yaml").resolve()
    assert resolved.is_absolute()


# --- (b) accepted absolute path ---------------------------------------------


def test_absolute_path_inside_workspace_is_accepted(workspace: Path) -> None:
    absolute = str(workspace / "templates" / "app.yaml")

    resolved = pathguard.resolve_within(absolute, workspace)

    assert resolved == Path(absolute).resolve()


# --- (c) ../ escape ---------------------------------------------------------


def test_parent_traversal_is_rejected(workspace: Path, outside_file: Path) -> None:
    with pytest.raises(PathContainmentError) as excinfo:
        pathguard.resolve_within("../outside/secret.yaml", workspace)

    assert excinfo.value.error_class == "path_violation"
    assert str(workspace.resolve()) in str(excinfo.value)


# --- (d) multi-segment a/../../b escape -------------------------------------


def test_multi_segment_traversal_is_rejected(workspace: Path) -> None:
    """``..`` is not searched for as a substring; normalization catches this."""
    with pytest.raises(PathContainmentError):
        pathguard.resolve_within("templates/../../outside/secret.yaml", workspace)


# --- (e) symlink pointing outside the workspace -----------------------------


def test_symlink_pointing_outside_workspace_is_rejected(
    workspace: Path, outside_file: Path
) -> None:
    """The link path itself contains no ``..``; only resolution reveals it."""
    link = workspace / "templates" / "linked.yaml"
    link.symlink_to(outside_file)

    with pytest.raises(PathContainmentError) as excinfo:
        pathguard.resolve_within("templates/linked.yaml", workspace)

    # The report names the real target, not the link.
    assert str(outside_file.resolve()) in str(excinfo.value)


# --- (f) /workspace-evil against /workspace ---------------------------------


def test_sibling_directory_sharing_a_name_prefix_is_rejected(
    tmp_path: Path, workspace: Path
) -> None:
    """A string ``startswith`` test would wrongly accept this path."""
    evil = tmp_path / "workspace-evil"
    evil.mkdir()
    evil_template = evil / "evil.yaml"
    evil_template.write_text(TEMPLATE_BODY, encoding="utf-8")

    with pytest.raises(PathContainmentError):
        pathguard.resolve_within(str(evil_template), workspace)


# --- (g) filename containing a shell metacharacter --------------------------


@pytest.mark.parametrize("char", sorted(pathguard.SHELL_METACHARACTERS))
def test_shell_metacharacter_in_path_is_rejected(workspace: Path, char: str) -> None:
    candidate = "templates/app{0}.yaml".format(char)

    with pytest.raises(UnsafeArgumentError) as excinfo:
        pathguard.resolve_within(candidate, workspace)

    assert excinfo.value.error_class == "invalid_arguments"
    assert char in str(excinfo.value)


def test_metacharacter_check_runs_before_containment(workspace: Path) -> None:
    """A hostile filename is rejected as unsafe, not as a missing file."""
    hostile = "templates/app.yaml; rm -rf /"

    with pytest.raises(UnsafeArgumentError):
        pathguard.resolve_within(hostile, workspace)


def test_clean_value_passes_the_metacharacter_check() -> None:
    assert pathguard.assert_no_shell_metacharacters("templates/app-1.yaml") is None


# --- (h) missing path -------------------------------------------------------


def test_missing_path_inside_workspace_reports_input_not_found(
    workspace: Path,
) -> None:
    with pytest.raises(InputNotFoundError) as excinfo:
        pathguard.resolve_within("templates/absent.yaml", workspace)

    assert excinfo.value.error_class == "input_not_found"


def test_missing_root_reports_input_not_found(tmp_path: Path) -> None:
    with pytest.raises(InputNotFoundError):
        pathguard.resolve_within("app.yaml", tmp_path / "no-such-workspace")


def test_empty_candidate_is_rejected(workspace: Path) -> None:
    """An empty path must not silently resolve to the workspace root."""
    with pytest.raises(InvalidArgumentsError):
        pathguard.resolve_within("   ", workspace)


# --- plugin root and plugin-owned resources ---------------------------------


def test_plugin_root_is_the_directory_holding_the_manifest(plugin_root: Path) -> None:
    resolved = pathguard.plugin_root()

    assert resolved == plugin_root.resolve()
    assert (resolved / pathguard.PLUGIN_MANIFEST_NAME).is_file()


def test_resolve_plugin_owned_accepts_a_bundled_resource() -> None:
    resolved = pathguard.resolve_plugin_owned("rules")

    assert resolved == pathguard.plugin_root() / "rules"
    assert resolved.is_dir()


def test_resolve_plugin_owned_rejects_escape_from_plugin_root() -> None:
    with pytest.raises(PathContainmentError):
        pathguard.resolve_plugin_owned("../etc/passwd")


def test_resolve_plugin_owned_skips_the_metacharacter_check() -> None:
    """Plugin-owned paths fail on containment or absence, never as unsafe."""
    with pytest.raises(MappingFileError):
        pathguard.resolve_plugin_owned("rules/$absent.guard")


def test_resolve_plugin_owned_reports_missing_resource_as_mapping_file_error() -> None:
    with pytest.raises(MappingFileError) as excinfo:
        pathguard.resolve_plugin_owned("no_such_mapping.json")

    assert excinfo.value.error_class == "unexpected"


# --- (h) symlink cycles are told apart from every other symlink shape ------
#
# One workspace holding every shape, and two tables written from the
# specification rather than from a run: which candidates enter a cycle (and at
# which link), and what ``resolve_within`` must return for all the others. The
# second table is the pre-existing behaviour, which the explicit cycle check
# must not change.

#: Length of the long non-cyclic chains. 39 links is above macOS's limit of 32
#: (``ELOOP`` without a cycle there) and below Linux's 40; 45 is above both.
SHORT_CHAIN = 39
LONG_CHAIN = 45

#: Candidate -> the link (relative to the root) that closes its cycle.
CYCLE_ORIGINS: Dict[str, str] = {
    "loop_a": "loop_a",
    "ring_a": "ring_a",
    "self": "self",
    "rel_a": "rel_a",
    "dir_a/app.yaml": "dir_a",
    "dir_a/missing.yaml": "dir_a",
}

#: Candidate -> ``None`` for a path resolving to ``app.yaml`` inside the root,
#: or the error class ``resolve_within`` raises.
NON_CYCLE_OUTCOMES: Dict[str, Optional[Type[Exception]]] = {
    "app.yaml": None,
    "in_link.yaml": None,
    "chain_1": None,
    "dirlink/app.yaml": None,
    "chain{0}".format(SHORT_CHAIN - 1): None,
    "chain{0}".format(LONG_CHAIN - 1): None,
    "out_link.yaml": PathContainmentError,
    "dangle_in": InputNotFoundError,
    "dangle_out": PathContainmentError,
    "missing.yaml": InputNotFoundError,
}


@pytest.fixture()
def symlink_shapes(tmp_path: Path) -> Path:
    """A workspace root holding every shape the two tables above name."""
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "app.yaml").write_text(TEMPLATE_BODY, encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.yaml").write_text(TEMPLATE_BODY, encoding="utf-8")

    (root / "in_link.yaml").symlink_to(root / "app.yaml")
    (root / "chain_0").symlink_to(root / "app.yaml")
    (root / "chain_1").symlink_to(root / "chain_0")
    (root / "dirlink").symlink_to(root, target_is_directory=True)
    (root / "chain0").symlink_to("app.yaml")
    for index in range(1, LONG_CHAIN):
        (root / "chain{0}".format(index)).symlink_to("chain{0}".format(index - 1))
    (root / "out_link.yaml").symlink_to(outside / "secret.yaml")
    (root / "dangle_in").symlink_to(root / "not_there.yaml")
    (root / "dangle_out").symlink_to(outside / "not_there.yaml")

    (root / "loop_a").symlink_to(root / "loop_b")
    (root / "loop_b").symlink_to(root / "loop_a")
    (root / "ring_a").symlink_to(root / "ring_b")
    (root / "ring_b").symlink_to(root / "ring_c")
    (root / "ring_c").symlink_to(root / "ring_a")
    (root / "self").symlink_to(root / "self")
    (root / "rel_a").symlink_to("rel_b")
    (root / "rel_b").symlink_to("rel_a")
    (root / "dir_a").symlink_to(root / "dir_b", target_is_directory=True)
    (root / "dir_b").symlink_to(root / "dir_a", target_is_directory=True)
    return root


@pytest.mark.parametrize("candidate", sorted(CYCLE_ORIGINS))
def test_symlink_loop_origin_names_the_link_that_closes_the_cycle(
    symlink_shapes: Path, candidate: str
) -> None:
    root = symlink_shapes.resolve()

    origin = pathguard._symlink_loop_origin(str(root / candidate))

    assert origin == str(root / CYCLE_ORIGINS[candidate])


@pytest.mark.parametrize("candidate", sorted(NON_CYCLE_OUTCOMES))
def test_symlink_loop_origin_is_none_without_a_cycle(
    symlink_shapes: Path, candidate: str
) -> None:
    root = symlink_shapes.resolve()

    assert pathguard._symlink_loop_origin(str(root / candidate)) is None


@pytest.mark.parametrize(
    "candidate", sorted(set(CYCLE_ORIGINS) | set(NON_CYCLE_OUTCOMES))
)
def test_symlink_loop_origin_agrees_with_path_resolve_where_it_raises(
    symlink_shapes: Path, candidate: str
) -> None:
    """CPython 3.9-3.12's own cycle detection is the oracle where it exists.

    On those versions ``Path.resolve(strict=False)`` raises
    ``RuntimeError("Symlink loop from ...")`` exactly when it meets a cycle, so
    the detector must find one exactly then. 3.9 names the link that closes the
    cycle, which the detector must match exactly; 3.10-3.12 name the path
    ``os.path.realpath`` returned, which is that link followed by the
    components not yet resolved. 3.13 removed the detection and has no oracle;
    there the same candidates are checked against the specification table
    instead, in this same test, so it runs and asserts on every version.
    """
    root = symlink_shapes.resolve()
    path = root / candidate
    detected = pathguard._symlink_loop_origin(str(path))

    if sys.version_info < (3, 13):
        try:
            path.resolve(strict=False)
        except RuntimeError as exc:
            assert detected is not None
            if sys.version_info < (3, 10):
                assert str(exc) == "Symlink loop from {0!r}".format(detected)
            else:
                remainder = Path(candidate).relative_to(
                    Path(detected).relative_to(root)
                )
                named = Path(detected) / remainder
                assert str(exc) == "Symlink loop from {0!r}".format(str(named))
        else:
            assert detected is None
    else:
        expected = CYCLE_ORIGINS.get(candidate)
        assert detected == (None if expected is None else str(root / expected))


@pytest.mark.parametrize("candidate", sorted(NON_CYCLE_OUTCOMES))
def test_normal_symlink_outcomes_are_unchanged(
    symlink_shapes: Path, candidate: str
) -> None:
    expected = NON_CYCLE_OUTCOMES[candidate]

    if expected is None:
        resolved = pathguard.resolve_within(candidate, symlink_shapes)
        assert resolved == (symlink_shapes / "app.yaml").resolve()
    else:
        with pytest.raises(expected):
            pathguard.resolve_within(candidate, symlink_shapes)


@pytest.mark.parametrize("candidate", sorted(CYCLE_ORIGINS))
def test_every_cycle_shape_is_an_invalid_argument(
    symlink_shapes: Path, candidate: str
) -> None:
    with pytest.raises(InvalidArgumentsError) as excinfo:
        pathguard.resolve_within(candidate, symlink_shapes)

    assert excinfo.value.error_class == "invalid_arguments"
    assert excinfo.value.exit_code == 2


def test_symlink_loop_origin_resolves_dot_dot_after_a_link(
    symlink_shapes: Path,
) -> None:
    """``..`` applies to the link's resolved location, as ``Path.resolve`` does."""
    root = symlink_shapes.resolve()

    assert pathguard._symlink_loop_origin(str(root / "dirlink/../app.yaml")) is None
    assert pathguard._symlink_loop_origin(
        str(root / "app.yaml/../loop_a")
    ) == str(root / "loop_a")
