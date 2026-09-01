"""The cfn-lint contribution measurement series (Requirement 19 AC5).

The series is not a ground-truth harness: it records how many findings cfn-lint
contributes, pinned to the installed cfn-lint version, and reports the number
informationally. These tests assert the three things that keep it honest -- the
output has the documented shape and names the pinned version, it is byte-stable
between runs, and it never turns its count into a pass/fail -- plus that an
absent cfn-lint fails the measurement rather than reporting a zero contribution.

cfn-lint is required. A run without it is skipped (Requirement 15 AC4): a series
that cannot run cfn-lint measures nothing, which is the one thing separate from
what these tests check.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Sequence

import pytest

# tests/integration/test_cfn_lint_contribution.py -> tests/integration -> tests -> root
PLUGIN_ROOT: Path = Path(__file__).resolve().parents[2]
SERIES_DIR = "benchmark/cfn-lint-contribution"
HARNESS: Path = PLUGIN_ROOT / SERIES_DIR / "run_contribution.py"
TEMPLATES = "{0}/templates".format(SERIES_DIR)

TIMEOUT_S = 300

# The series directory has a hyphen in its name, so it is not an importable
# package; load the harness module by file path for its constant key sets. The
# module inserts the plugin root on sys.path itself, so iacreview imports resolve.
import importlib.util  # noqa: E402

sys.path.insert(0, str(PLUGIN_ROOT))
from iacreview import exitcodes  # noqa: E402


def _load_harness_module() -> Any:
    spec = importlib.util.spec_from_file_location("run_contribution", HARNESS)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


run_contribution = _load_harness_module()


def _run(
    arguments: Sequence[str], env: Dict[str, str] = None
) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(
        [sys.executable, str(HARNESS), *arguments],
        cwd=str(PLUGIN_ROOT),
        env=dict(os.environ) if env is None else env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=TIMEOUT_S,
    )


def _skip_without_cfn_lint() -> None:
    if shutil.which("cfn-lint") is None:
        pytest.skip("cfn-lint not installed; the series cannot be measured")


def test_the_series_has_the_documented_structure_and_names_the_version() -> None:
    _skip_without_cfn_lint()
    completed = _run(["--templates", TEMPLATES])
    assert completed.returncode == exitcodes.OK, completed.stderr

    document = json.loads(completed.stdout)
    assert sorted(document) == sorted(run_contribution.SUMMARY_KEYS)
    # Requirement 19 AC5: the count is pinned to a stated cfn-lint version.
    assert document["cfn_lint_version"]
    assert document["cfn_lint_version"] != "unknown"
    for entry in document["templates"]:
        assert sorted(entry) == sorted(run_contribution.TEMPLATE_KEYS)


def test_the_count_is_the_sum_of_the_per_template_counts() -> None:
    _skip_without_cfn_lint()
    document = json.loads(_run(["--templates", TEMPLATES]).stdout)

    assert document["total_findings"] == sum(
        entry["finding_count"] for entry in document["templates"]
    )
    # by_severity is present for every severity, summing to the same total.
    assert sum(document["by_severity"].values()) == document["total_findings"]


def test_the_series_is_byte_identical_between_runs() -> None:
    _skip_without_cfn_lint()
    first = _run(["--templates", TEMPLATES])
    second = _run(["--templates", TEMPLATES])
    assert first.stdout == second.stdout


def test_the_series_carries_no_absolute_host_path() -> None:
    _skip_without_cfn_lint()
    stdout = _run(["--templates", TEMPLATES]).stdout
    assert str(PLUGIN_ROOT) not in stdout
    assert os.path.expanduser("~") not in stdout


def test_an_absent_cfn_lint_fails_the_measurement_rather_than_reporting_zero() -> None:
    # Requirement 19 AC5: a zero contribution and an unmeasurable series must not
    # look the same. An empty PATH makes cfn-lint unreachable whatever the host
    # installed; the harness starts with an absolute interpreter path, so an empty
    # PATH costs nothing else.
    completed = _run(["--templates", TEMPLATES], env={})
    assert completed.returncode == exitcodes.TOOL_UNAVAILABLE
    assert completed.stdout == ""


def test_a_missing_templates_directory_is_rejected() -> None:
    completed = _run(["--templates", "no/such/dir"])
    assert completed.returncode in {
        exitcodes.INVALID_ARGUMENTS,
        exitcodes.INPUT_NOT_FOUND,
    }
    assert completed.stdout == ""
