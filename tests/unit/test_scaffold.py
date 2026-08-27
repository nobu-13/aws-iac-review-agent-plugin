"""Repository scaffolding checks.

Verifies that the directory skeleton and the ``sys.path`` bootstrap declared by
design.md (Directory Structure) are in place, so that every later module can be
imported from the plugin root without installation.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

EXPECTED_DIRECTORIES = [
    "iacreview",
    "iacreview/iam",
    "skills",
    "rules",
    "benchmark",
    "benchmark/harness",
    "examples",
    "tests",
    "docs",
    "tests/fixtures/valid",
    "tests/fixtures/invalid",
    "tests/fixtures/tool_output",
    "tests/fixtures/security",
    "tests/unit",
    "tests/property",
    "tests/integration",
    "tests/negative",
    "tests/regression",
    "tests/fakebin",
]


@pytest.mark.parametrize("relative", EXPECTED_DIRECTORIES)
def test_expected_directory_exists(plugin_root: Path, relative: str) -> None:
    assert (plugin_root / relative).is_dir()


def test_plugin_root_is_on_sys_path(plugin_root: Path) -> None:
    assert str(plugin_root) in sys.path


def test_plugin_root_is_derived_from_this_files_location(plugin_root: Path) -> None:
    # tests/unit/test_scaffold.py -> tests/unit -> tests -> plugin root
    assert Path(__file__).resolve().parents[2] == plugin_root


def test_shared_packages_are_importable(plugin_root: Path) -> None:
    import benchmark.harness
    import iacreview
    import iacreview.iam

    for module in (iacreview, iacreview.iam, benchmark.harness):
        assert module.__file__ is not None
        assert str(plugin_root) in str(Path(module.__file__).resolve())


def test_conftest_constants_point_inside_plugin_root(
    plugin_root: Path, fixtures_dir: Path, fakebin_dir: Path
) -> None:
    assert fixtures_dir == plugin_root / "tests" / "fixtures"
    assert fakebin_dir == plugin_root / "tests" / "fakebin"


def test_pyproject_declares_runtime_and_dev_dependencies(plugin_root: Path) -> None:
    text = (plugin_root / "pyproject.toml").read_text(encoding="utf-8")
    assert 'requires-python = ">=3.9"' in text
    assert 'dependencies = ["PyYAML>=6.0"]' in text
    assert "pytest>=7.0" in text
    assert "pytest-cov>=4.0" in text
    # Pinned exactly rather than as a range: the property tests of Task 23 are
    # only reproducible against one generator version (steering/tech.md asks for
    # pinned versions, and a counterexample recorded against 6.141.1 has to mean
    # the same thing on the next run).
    assert "hypothesis==" in text
    # The plugin ships as a directory; it is never built or published to PyPI.
    assert "[build-system]" not in text


def test_hypothesis_is_a_test_only_dependency(plugin_root: Path) -> None:
    """No run-time module may import it (Requirement 16 AC3: PyYAML alone).

    Asserted over the source rather than by trying an import: the package *is*
    installed in a development environment, so an accidental run-time import
    would work locally and fail only where the plugin is used as shipped.
    """
    shipped = list((plugin_root / "iacreview").rglob("*.py")) + list(
        (plugin_root / "skills").rglob("*.py")
    )
    assert shipped
    offenders = [
        path.relative_to(plugin_root)
        for path in shipped
        if "hypothesis" in path.read_text(encoding="utf-8")
    ]
    assert offenders == []
