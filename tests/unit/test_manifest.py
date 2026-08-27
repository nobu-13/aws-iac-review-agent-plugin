"""Manifest and packaging tests for the Agent Plugins 1.0.0 package.

Covers:
- Requirement 1 AC1  : ``plugin.json`` exists at the package root and is valid JSON
- Requirement 1 AC5  : required fields, ``name`` pattern / length, ``keywords`` type
- Requirement 1 AC6  : ``version`` uses semantic versioning
- Requirement 1 AC7  : no ``mcp.json`` in the v0.1 package
- Requirement 10 AC2 : the top-level schema is closed; vendor keys are not smuggled in,
                        and the one sanctioned way to add a vendor key stays legal
- Requirement 10 AC9 : ``extensions`` is the separation mechanism a future
                        Kiro-specific addition would use (design.md O-7,
                        ``docs/kiro-power.md``)
- Requirement 15 AC1 : no tool binaries are bundled inside the plugin directory
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterator, List

import pytest

# Agent Plugins 1.0.0 closed top-level schema (design: Skill Design / plugin.json).
ALLOWED_TOP_LEVEL_FIELDS = frozenset(
    {
        "$schema",
        "name",
        "version",
        "description",
        "author",
        "homepage",
        "repository",
        "license",
        "keywords",
        "extensions",
    }
)

# Fields Requirement 1 AC5 requires the manifest to declare.
REQUIRED_TOP_LEVEL_FIELDS = (
    "$schema",
    "name",
    "version",
    "description",
    "author",
    "license",
    "keywords",
)

# Keys that Agent Plugins 1.0.0 forbids at the top level, plus ``extensions``,
# which v0.1 deliberately does not use (design: Portability Design).
FORBIDDEN_TOP_LEVEL_FIELDS = (
    "hooks",
    "agents",
    "commands",
    "mcpServers",
    "lspServers",
    "extensions",
)

#: The reverse-domain namespace a Kiro-specific addition would use, if one is
#: ever needed (design.md O-7). Nothing uses it in v0.1.
KIRO_EXTENSION_NAMESPACE = "dev.kiro"

NAME_PATTERN = re.compile(r"^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$")
NAME_MAX_LENGTH = 128

# semver.org 2.0.0 MAJOR.MINOR.PATCH with optional prerelease / build metadata.
SEMVER_PATTERN = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)

# Directories that are not part of the distributed plugin package.
SKIPPED_DIR_NAMES = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        "cdk.out",
        ".idea",
        ".vscode",
    }
)

# Executable object-file magic numbers. A bundled tool binary would start with
# one of these (Requirement 15 AC1).
EXECUTABLE_MAGICS = (
    (b"\x7fELF", "ELF"),
    (b"\xfe\xed\xfa\xce", "Mach-O 32-bit big endian"),
    (b"\xfe\xed\xfa\xcf", "Mach-O 64-bit big endian"),
    (b"\xce\xfa\xed\xfe", "Mach-O 32-bit little endian"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit little endian"),
    (b"\xca\xfe\xba\xbe", "Mach-O universal binary"),
    (b"\xbe\xba\xfe\xca", "Mach-O universal binary (reverse)"),
)

MAGIC_LENGTH = max(len(magic) for magic, _ in EXECUTABLE_MAGICS)


@pytest.fixture(scope="module")
def manifest_path(plugin_root: Path) -> Path:
    return plugin_root / "plugin.json"


@pytest.fixture(scope="module")
def manifest_text(manifest_path: Path) -> str:
    return manifest_path.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def manifest(manifest_text: str) -> Dict[str, Any]:
    parsed = json.loads(manifest_text)
    assert isinstance(parsed, dict), "plugin.json must contain a JSON object"
    return parsed


def _iter_package_files(root: Path) -> Iterator[Path]:
    """Yield every regular file that is part of the distributed package."""
    stack = [root]
    while stack:
        current = stack.pop()
        for entry in sorted(current.iterdir()):
            if entry.is_symlink():
                # Symlinks carry no bytes of their own; containment of symlink
                # targets is covered by the pathguard tests.
                continue
            if entry.is_dir():
                if entry.name in SKIPPED_DIR_NAMES:
                    continue
                stack.append(entry)
            elif entry.is_file():
                yield entry


def test_manifest_exists_at_package_root(manifest_path: Path) -> None:
    """Requirement 1 AC1: the manifest lives at the package root."""
    assert manifest_path.is_file()


def test_manifest_is_valid_json(manifest_text: str) -> None:
    """Requirement 1 AC1 / AC11: the manifest parses as a JSON object."""
    parsed = json.loads(manifest_text)
    assert isinstance(parsed, dict)


@pytest.mark.parametrize("field", REQUIRED_TOP_LEVEL_FIELDS)
def test_required_field_is_declared(manifest: Dict[str, Any], field: str) -> None:
    """Requirement 1 AC5: every required field is present and non-empty."""
    assert field in manifest
    assert manifest[field] not in (None, "", [], {})


def _unexpected_top_level_fields(document: Dict[str, Any]) -> List[str]:
    """Keys of ``document`` that the closed top-level schema does not define."""
    return sorted(set(document) - ALLOWED_TOP_LEVEL_FIELDS)


def test_top_level_schema_is_closed(manifest: Dict[str, Any]) -> None:
    """Requirement 10 AC2: no key outside the closed top-level schema."""
    assert _unexpected_top_level_fields(manifest) == []


def test_adding_an_extensions_namespace_stays_inside_the_closed_schema(
    manifest: Dict[str, Any],
) -> None:
    """Requirement 10 AC2, AC9: the sanctioned escape hatch is known to be legal.

    v0.1 declares no ``extensions`` (design.md O-7,
    ``docs/kiro-power.md``), so nothing here asserts that it should. What is
    asserted is that if a Kiro-specific setting is ever needed, adding it the way
    the specification intends -- one reverse-domain namespace under
    ``extensions`` -- adds exactly one top-level key and leaves the manifest
    inside the closed schema. That is the property the future change depends on,
    and checking it now costs nothing and keeps the decision reversible.

    The real manifest is copied rather than modified: ``plugin.json`` is a fixture
    the rest of the suite reads, and nothing here writes to it.
    """
    hypothetical = dict(manifest)
    hypothetical["extensions"] = {
        KIRO_EXTENSION_NAMESPACE: {"note": "no such setting exists in v0.1"}
    }

    assert _unexpected_top_level_fields(hypothetical) == []
    assert set(hypothetical) - set(manifest) == {"extensions"}
    assert all(
        isinstance(value, dict) for value in hypothetical["extensions"].values()
    ), "each namespace of extensions holds an object"


@pytest.mark.parametrize("field", FORBIDDEN_TOP_LEVEL_FIELDS)
def test_forbidden_top_level_field_is_absent(
    manifest: Dict[str, Any], field: str
) -> None:
    """Agent Plugins 1.0.0 forbids these top-level keys.

    ``extensions`` is permitted by the specification but deliberately unused in
    v0.1 (design: Portability Design). If a later revision adds it, this case is
    the single place that has to change, and
    ``test_top_level_schema_is_closed`` still guards the closed schema.
    """
    assert field not in manifest


def test_name_matches_pattern_and_length(manifest: Dict[str, Any]) -> None:
    """Requirement 1 AC5: ``name`` pattern and 128 character upper bound."""
    name = manifest["name"]
    assert isinstance(name, str)
    assert NAME_PATTERN.match(name) is not None
    assert len(name) <= NAME_MAX_LENGTH


def test_version_is_semver(manifest: Dict[str, Any]) -> None:
    """Requirement 1 AC6: MAJOR.MINOR.PATCH semantic version."""
    version = manifest["version"]
    assert isinstance(version, str)
    assert SEMVER_PATTERN.match(version) is not None


def test_keywords_is_an_array_of_strings(manifest: Dict[str, Any]) -> None:
    """Requirement 1 AC5: ``keywords`` is an array of strings."""
    keywords = manifest["keywords"]
    assert isinstance(keywords, list)
    assert keywords, "keywords must not be empty"
    assert all(isinstance(item, str) and item for item in keywords)


def test_license_is_declared_as_a_string(manifest: Dict[str, Any]) -> None:
    """Requirement 1 AC5: ``license`` is a plain SPDX identifier string.

    The v0.1 provisional value is ``Apache-2.0`` (design: License Recommendation).
    """
    assert manifest["license"] == "Apache-2.0"


def test_no_mcp_json_at_plugin_root(plugin_root: Path) -> None:
    """Requirement 1 AC7: the v0.1 package ships no ``mcp.json``."""
    assert not (plugin_root / "mcp.json").exists()


def test_no_executable_binaries_in_repository(plugin_root: Path) -> None:
    """Requirement 15 AC1: tools are resolved via PATH, never bundled."""
    offenders: List[str] = []
    for path in _iter_package_files(plugin_root):
        try:
            with path.open("rb") as handle:
                head = handle.read(MAGIC_LENGTH)
        except OSError:  # pragma: no cover - unreadable file is not a binary claim
            continue
        for magic, label in EXECUTABLE_MAGICS:
            if head.startswith(magic):
                offenders.append(
                    "{0} ({1})".format(path.relative_to(plugin_root).as_posix(), label)
                )
                break
    assert offenders == []
