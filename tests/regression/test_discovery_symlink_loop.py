"""Regression: a symlink cycle met while scanning a directory target.

The defect
----------

:func:`iacreview.cdk._is_contained` resolved each discovered entry with
``Path.resolve(strict=False)`` and caught ``(OSError, ValueError)``. On CPython
3.9 through 3.12 a symlink cycle raises ``RuntimeError`` from that call, which
escaped discovery: ``run_iac_review.py --target <dir>/`` exited 1 with a Python
traceback on stderr and no Review_Report. CPython 3.13 reports the cycle as an
``OSError`` and the entry was skipped. Containment never failed (nothing was
resolved or read).

The fix
-------

``RuntimeError`` joined the caught tuple, so a cycle is "not contained" and the
entry is skipped on every version, which is what 3.13 already did and what
``find_synthesized_templates`` already did for a cycle under ``cdk.out``. The
single-file path (``--target loop.yaml``) is unchanged: it still fails as
``invalid_arguments`` (``tests/regression/test_sec_symlink_loop.py``).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from iacreview import cdk

PLUGIN_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = PLUGIN_ROOT / "skills" / "iac-review" / "scripts" / "run_iac_review.py"
TEMPLATE = "Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n"


def _scan_dir(tmp_path: Path, links: dict) -> Path:
    directory = tmp_path / "d"
    directory.mkdir()
    (directory / "ok.yaml").write_text(TEMPLATE, encoding="utf-8")
    for name, target in links.items():
        os.symlink(target, str(directory / name))
    return directory


@pytest.mark.parametrize(
    "links",
    [{"loop.yaml": "loop.yaml"}, {"a.yaml": "b.yaml", "b.yaml": "a.yaml"}],
    ids=["self-loop", "two-link-cycle"],
)
def test_a_cycle_is_not_contained_and_raises_nothing(tmp_path: Path, links: dict) -> None:
    directory = _scan_dir(tmp_path, links)
    root = directory.resolve()
    for name in links:
        assert cdk._is_contained(directory / name, root) is False
    assert cdk._is_contained(directory / "ok.yaml", root) is True


@pytest.mark.parametrize(
    "links",
    [{"loop.yaml": "loop.yaml"}, {"a.yaml": "b.yaml", "b.yaml": "a.yaml"}],
    ids=["self-loop", "two-link-cycle"],
)
def test_a_directory_scan_skips_the_cycle_and_reviews_the_rest(tmp_path: Path, links: dict) -> None:
    directory = _scan_dir(tmp_path, links)
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--target", "d/", "--sources", "iam-review"],
        cwd=str(tmp_path),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=120,
        check=False,
    )
    assert "Traceback" not in result.stderr
    assert "RuntimeError" not in result.stderr
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["target"]["files"] == ["d/ok.yaml"]
    assert str(directory) not in result.stdout
