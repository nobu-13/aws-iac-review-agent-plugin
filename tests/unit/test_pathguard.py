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

from pathlib import Path

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
