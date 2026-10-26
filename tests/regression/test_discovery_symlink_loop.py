"""Regression: a symlink cycle met while scanning a directory target.

The defect
----------

:func:`iacreview.cdk._is_contained` resolved each discovered entry with
``Path.resolve(strict=False)`` and caught ``(OSError, ValueError)``. On CPython
3.9 through 3.12 a symlink cycle raises ``RuntimeError`` from that call, which
escaped discovery: ``run_iac_review.py --target <dir>/`` exited 1 with a Python
traceback on stderr and no Review_Report. CPython 3.13 returns the cycle's path
unresolved, keeps the entry, and the reader reports it in ``errors[]`` as
``input_not_found`` (v1.1.0 on 3.13 was observed doing exactly that).

The fix
-------

A first fix (``c96896c``) made the cycle "not contained", which dropped the
entry silently on 3.9-3.12: the review then looked complete although one
candidate was never read. The fix kept here treats the ``RuntimeError`` as
"keep the entry", so every version gives the 3.13 result: the cycle is named
in ``errors[]``, nothing is read through it, and no traceback is printed.
A directory holding only cycles has nothing reviewable and exits non-zero.

Exit 0 with an ``errors[]`` entry for a mix of good and unreadable entries is
the existing v1.0 behaviour for any unreadable directory entry (a symlinked
file is reported the same way) and is not changed here. A caller that needs
"every candidate was reviewed" must check ``errors[]``; ``passed_all_checks``
looks at findings only (steering/security.md).

The single-file path (``--target loop.yaml``) is unchanged: it still fails as
``invalid_arguments`` (``tests/regression/test_sec_symlink_loop.py``).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List

import pytest

from iacreview import cdk, exitcodes

PLUGIN_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = PLUGIN_ROOT / "skills" / "iac-review" / "scripts" / "run_iac_review.py"
TEMPLATE = "Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n"
CYCLES = [{"loop.yaml": "loop.yaml"}, {"a.yaml": "b.yaml", "b.yaml": "a.yaml"}]
CYCLE_IDS = ["self-loop", "two-link-cycle"]


def _scan_dir(tmp_path: Path, links: Dict[str, str], with_template: bool = True) -> Path:
    directory = tmp_path / "d"
    directory.mkdir()
    if with_template:
        (directory / "ok.yaml").write_text(TEMPLATE, encoding="utf-8")
    for name, target in links.items():
        os.symlink(target, str(directory / name))
    return directory


def _review(tmp_path: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--target", "d/", "--sources", "iam-review"],
        cwd=str(tmp_path),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=120,
        check=False,
    )


def _unreadable(report: dict) -> List[str]:
    return sorted(e["message"] for e in report["errors"] if e["error_class"] == "input_not_found")


@pytest.mark.parametrize("links", CYCLES, ids=CYCLE_IDS)
def test_discovery_keeps_a_cycle_and_raises_nothing(tmp_path: Path, links: Dict[str, str]) -> None:
    directory = _scan_dir(tmp_path, links)
    root = directory.resolve()
    for name in links:
        assert cdk._is_contained(directory / name, root) is True
    found = [p.name for p in cdk.find_templates(directory)]
    assert found == sorted(["ok.yaml", *links])


@pytest.mark.parametrize("links", CYCLES, ids=CYCLE_IDS)
def test_a_cycle_beside_a_template_is_reported_not_dropped(tmp_path: Path, links: Dict[str, str]) -> None:
    directory = _scan_dir(tmp_path, links)
    result = _review(tmp_path)
    assert "Traceback" not in result.stderr and "RuntimeError" not in result.stderr
    assert result.returncode == exitcodes.OK, result.stderr
    report = json.loads(result.stdout)
    assert report["target"]["files"] == ["d/ok.yaml"]
    messages = _unreadable(report)
    assert len(messages) == len(links)
    for name in links:
        assert any("d/" + name in m for m in messages), messages
    assert str(directory) not in result.stdout


@pytest.mark.parametrize("links", CYCLES, ids=CYCLE_IDS)
def test_a_directory_of_cycles_only_fails(tmp_path: Path, links: Dict[str, str]) -> None:
    _scan_dir(tmp_path, links, with_template=False)
    result = _review(tmp_path)
    assert "Traceback" not in result.stderr
    assert result.returncode != exitcodes.OK
    report = json.loads(result.stdout)
    assert report["target"]["files"] == []
    assert len(_unreadable(report)) == len(links)


def test_normal_symlinks_and_subdirectories_behave_as_before(tmp_path: Path) -> None:
    directory = _scan_dir(tmp_path, {"link.yaml": "ok.yaml"})
    (directory / "sub").mkdir()
    (directory / "sub" / "s.yaml").write_text(TEMPLATE, encoding="utf-8")
    outside = tmp_path / "outside.yaml"
    outside.write_text(TEMPLATE, encoding="utf-8")
    os.symlink(str(outside), str(directory / "escape.yaml"))
    result = _review(tmp_path)
    assert result.returncode == exitcodes.OK, result.stderr
    report = json.loads(result.stdout)
    # A symlinked file is never read (O_NOFOLLOW) and is reported; one that
    # resolves outside the scanned tree is not a candidate at all (v1.0).
    assert report["target"]["files"] == ["d/ok.yaml", "d/sub/s.yaml"]
    messages = _unreadable(report)
    assert any("d/link.yaml" in m for m in messages)
    assert not any("escape.yaml" in m for m in messages)
