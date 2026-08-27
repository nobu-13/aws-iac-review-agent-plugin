"""Shared pytest configuration for aws-iac-review-agent-plugin.

The plugin is distributed as a directory, not as an installed package, so tests
resolve the plugin root from this file's location and insert it into
``sys.path``. This mirrors the ``sys.path`` bootstrap that every Skill entry
point performs at run time.

Subprocess coverage
-------------------

Every Skill entry point under ``skills/`` is exercised the way a host agent runs
it: as a child process. Lines executed there are invisible to the parent's
coverage measurement unless the child starts measuring itself, so design.md
("coverage 80% の達成方針") requires the ``COVERAGE_PROCESS_START`` wiring rather
than excluding those files from the measured set -- excluding them would be the
"measure only what is easy to measure" move the same section rules out.

Two mechanisms can start coverage in a child, and both need the environment to
survive the ``subprocess`` call:

``pytest-cov``
    Installs a ``.pth`` startup hook in ``site-packages`` that keys on the
    ``COV_CORE_*`` variables ``pytest-cov`` writes into :data:`os.environ` while a
    ``--cov`` run is in progress. Nothing in this repository has to enable it;
    it only has to be left alone.

``coverage.py``
    :func:`coverage.process_startup` keys on :data:`COVERAGE_PROCESS_START`, which
    :func:`enable_subprocess_coverage` sets to this repository's coverage
    configuration whenever the parent is measuring. Inert where no startup hook
    calls that function, which is why it is set *in addition to* the variables
    above rather than instead of them.

The practical rule for a test that starts a child process: build its environment
from :data:`os.environ`, or splice :func:`coverage_environment` into whatever it
builds instead. A test that hands a child a hand-made environment silently drops
the child out of the coverage report -- it does not fail, it just stops counting.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Dict, Optional, Tuple

import pytest

# tests/conftest.py -> tests/ -> plugin root
PLUGIN_ROOT: Path = Path(__file__).resolve().parents[1]
TESTS_ROOT: Path = PLUGIN_ROOT / "tests"
FIXTURES: Path = TESTS_ROOT / "fixtures"
FAKEBIN: Path = TESTS_ROOT / "fakebin"

#: ``coverage.py``'s own subprocess variable, naming the configuration file a
#: child should measure itself with.
COVERAGE_PROCESS_START = "COVERAGE_PROCESS_START"

#: The coverage configuration of this repository. ``pyproject.toml`` holds the
#: ``[tool.coverage.run]`` section, and there is no separate ``.coveragerc``:
#: one file for test and coverage settings is what design.md's Testing Strategy
#: specifies.
COVERAGE_CONFIG_FILE: Path = PLUGIN_ROOT / "pyproject.toml"

#: The variable ``pytest-cov``'s startup hook actually keys on. Its presence in
#: the environment is how :func:`coverage_is_active` knows the parent process is
#: measuring: ``pytest-cov`` sets it for the duration of a ``--cov`` run and
#: removes it afterwards, so it is true exactly while measurement is in progress.
PYTEST_COV_DATAFILE = "COV_CORE_DATAFILE"

#: Every variable a child process needs in order to measure itself. Listed rather
#: than matched by prefix so that what is propagated is reviewable, and so a
#: variable this repository does not understand is not forwarded by accident.
COVERAGE_ENVIRONMENT_VARIABLES: Tuple[str, ...] = (
    "COV_CORE_SOURCE",
    "COV_CORE_CONFIG",
    PYTEST_COV_DATAFILE,
    "COV_CORE_BRANCH",
    "COV_CORE_CONTEXT",
    "COVERAGE_FILE",
    COVERAGE_PROCESS_START,
)


def coverage_is_active() -> bool:
    """Whether the current process is measuring coverage.

    Returns:
        ``True`` while a ``--cov`` run is in progress. A plain ``pytest`` run is
        not measuring anything, and then there is nothing for a child to join:
        the subprocess wiring is a no-op rather than a second code path.
    """
    return bool(os.environ.get(PYTEST_COV_DATAFILE))


def enable_subprocess_coverage() -> Optional[str]:
    """Point :data:`COVERAGE_PROCESS_START` at this repository's configuration.

    Returns:
        The value the variable now holds, or ``None`` when the parent is not
        measuring coverage or the configuration file is missing. An existing
        value is respected rather than overwritten: a contributor who pointed the
        variable somewhere deliberately, or a CI job that did, means it.

    Note:
        This sets a variable in the *parent's* environment, which is what makes a
        child inherit it. Nothing here starts coverage in this process.
    """
    if not coverage_is_active():
        return None
    existing = os.environ.get(COVERAGE_PROCESS_START)
    if existing:
        return existing
    if not COVERAGE_CONFIG_FILE.is_file():
        return None
    os.environ[COVERAGE_PROCESS_START] = str(COVERAGE_CONFIG_FILE)
    return os.environ[COVERAGE_PROCESS_START]


def coverage_environment() -> Dict[str, str]:
    """The coverage variables currently set, for splicing into a child's env.

    Returns:
        Name -> value for every variable of
        :data:`COVERAGE_ENVIRONMENT_VARIABLES` that is set. Empty when the parent
        is not measuring coverage, so a caller can merge it unconditionally.
    """
    return {
        name: os.environ[name]
        for name in COVERAGE_ENVIRONMENT_VARIABLES
        if name in os.environ
    }


def _insert_plugin_root_on_sys_path() -> None:
    """Make ``iacreview`` and ``benchmark.harness`` importable from tests."""
    root = str(PLUGIN_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)


# Applied at import time so that collection of test modules that import
# ``iacreview`` at module level succeeds.
_insert_plugin_root_on_sys_path()


@pytest.fixture(scope="session", autouse=True)
def plugin_root_on_sys_path() -> Path:
    """Guarantee the plugin root stays on ``sys.path`` for the whole session."""
    _insert_plugin_root_on_sys_path()
    return PLUGIN_ROOT


@pytest.fixture(scope="session")
def plugin_root() -> Path:
    """Absolute path to the plugin root directory."""
    return PLUGIN_ROOT


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    """Absolute path to ``tests/fixtures``."""
    return FIXTURES


@pytest.fixture(scope="session")
def fakebin_dir() -> Path:
    """Absolute path to ``tests/fakebin`` (fake external tools for PATH swaps)."""
    return FAKEBIN


@pytest.fixture(scope="session", autouse=True)
def subprocess_coverage() -> Dict[str, str]:
    """Enable child-process coverage measurement for the whole session.

    Autouse and session-scoped so it is in place before the first test starts a
    Skill entry point; requested by name where a test needs the variables to
    assert on or to merge into a hand-built environment.

    Returns:
        The coverage variables a child must inherit, as
        :func:`coverage_environment` reports them. Empty when the session is not
        measuring coverage.
    """
    enable_subprocess_coverage()
    return coverage_environment()
