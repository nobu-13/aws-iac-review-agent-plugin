"""Integration tests for ``build_prompt.py`` (v0.3.0).

``skills/cloudformation-review/scripts/build_prompt.py`` is run as a real
subprocess, the way a host Agent or an MCP server runs it. What is asserted is
the Skill's contract:

* both invocation paths work: ``--target`` (extract facts in process) and
  ``--facts`` (read a facts file produced earlier);
* stdout is one JSON object with the prompt, the checklist and a schema version;
* the output is byte-identical for identical input (the prompt is deterministic);
* a path outside the workspace is refused with exit 7;
* an invalid invocation (neither or both of the mutually exclusive options) is
  exit 2 with empty stdout.

The working directory is the plugin root, the workspace root the script
contains paths against.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict

import pytest

EXTRACT = Path("skills") / "cloudformation-review" / "scripts" / "extract_facts.py"
BUILD = Path("skills") / "cloudformation-review" / "scripts" / "build_prompt.py"

BUGGY = "sample/buggy-template.yaml"
MINIMAL = "examples/minimal-s3/template.yaml"

EXIT_OK = 0
EXIT_INVALID_ARGUMENTS = 2
EXIT_PATH_VIOLATION = 7


def _run(plugin_root: Path, script: Path, *arguments: str) -> "subprocess.CompletedProcess[bytes]":
    return subprocess.run(
        [sys.executable, str(plugin_root / script), *arguments],
        cwd=str(plugin_root),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=120,
        check=False,
    )


def _payload(completed: "subprocess.CompletedProcess[bytes]") -> Dict[str, Any]:
    assert completed.returncode == EXIT_OK, completed.stderr.decode("utf-8", "replace")
    parsed = json.loads(completed.stdout.decode("utf-8"))
    assert isinstance(parsed, dict)
    return parsed


def _skip_if_missing(plugin_root: Path, target: str) -> None:
    if not (plugin_root / target).exists():
        pytest.skip("{0} not present in this checkout".format(target))


def test_target_path_produces_a_prompt(plugin_root: Path) -> None:
    """--target extracts facts in process and returns a prompt payload."""
    _skip_if_missing(plugin_root, MINIMAL)
    payload = _payload(_run(plugin_root, BUILD, "--target", MINIMAL))
    assert set(payload) == {"schema_version", "prompt", "checklist"}
    assert isinstance(payload["prompt"], str) and payload["prompt"]
    assert isinstance(payload["checklist"], list)


def test_facts_path_matches_target_path(plugin_root: Path, tmp_path: Path) -> None:
    """--facts on a file extract_facts produced gives the same prompt as --target.

    The facts file has to live inside the workspace root (the script contains
    paths against it), so it is written next to the plugin root and removed.
    """
    _skip_if_missing(plugin_root, MINIMAL)

    # Extract facts to a workspace-relative file.
    facts_file = plugin_root / "._prompt_test_facts.json"
    try:
        extract = _run(plugin_root, EXTRACT, "--target", MINIMAL)
        assert extract.returncode == EXIT_OK, extract.stderr.decode("utf-8", "replace")
        facts_file.write_bytes(extract.stdout)

        from_facts = _payload(_run(plugin_root, BUILD, "--facts", "._prompt_test_facts.json"))
        from_target = _payload(_run(plugin_root, BUILD, "--target", MINIMAL))

        assert from_facts["prompt"] == from_target["prompt"]
        assert from_facts["checklist"] == from_target["checklist"]
    finally:
        if facts_file.exists():
            facts_file.unlink()


def test_prompt_is_byte_identical_across_runs(plugin_root: Path) -> None:
    """Requirement 16 AC11: the prompt is a deterministic function of the input."""
    _skip_if_missing(plugin_root, MINIMAL)
    first = _run(plugin_root, BUILD, "--target", MINIMAL)
    second = _run(plugin_root, BUILD, "--target", MINIMAL)
    assert first.stdout == second.stdout


def test_checklist_surfaces_design_leads(plugin_root: Path) -> None:
    """The buggy sample has an unattached IGW and a single-AZ database.

    Those are exactly the design-level leads the checklist exists to surface, so
    a non-empty checklist naming them is the evidence the v0.3.0 bridge adds
    value over the raw facts.
    """
    _skip_if_missing(plugin_root, BUGGY)
    payload = _payload(_run(plugin_root, BUILD, "--target", BUGGY))
    checklist = payload["checklist"]
    assert checklist, "the buggy sample should produce design leads"
    joined = " ".join(checklist)
    assert "VPCGatewayAttachment" in joined or "default route" in joined


def test_a_path_outside_the_workspace_is_refused(plugin_root: Path) -> None:
    """Requirement 9 AC5: a target outside the workspace root is exit 7."""
    completed = _run(plugin_root, BUILD, "--target", "/etc/hosts")
    assert completed.returncode == EXIT_PATH_VIOLATION
    assert completed.stdout.strip() == b""


def test_no_target_and_no_facts_is_invalid(plugin_root: Path) -> None:
    """The two source options are mutually exclusive and one is required."""
    completed = _run(plugin_root, BUILD)
    assert completed.returncode == EXIT_INVALID_ARGUMENTS
    assert completed.stdout.strip() == b""


def test_both_target_and_facts_is_invalid(plugin_root: Path) -> None:
    completed = _run(plugin_root, BUILD, "--target", MINIMAL, "--facts", "x.json")
    assert completed.returncode == EXIT_INVALID_ARGUMENTS
    assert completed.stdout.strip() == b""
