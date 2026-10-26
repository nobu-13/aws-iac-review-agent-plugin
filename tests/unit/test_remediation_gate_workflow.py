"""Static checks of the Phase 1 reference gate (AC25, AC26; local part of C12/C24).

These read the workflow as data. They show what the file asks GitHub to do;
whether GitHub enforces it (required checks, rulesets, bypass) is shown only on
GitHub and is recorded in docs/v2/phase1/handoff.md, never here.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / "docs" / "v2" / "phase1" / "ci" / "remediation-gate.yml"
TEXT = WORKFLOW.read_text(encoding="utf-8")
DOC = yaml.safe_load(TEXT)
JOB = DOC["jobs"]["verify"]
STEPS = JOB["steps"]


def run_lines() -> str:
    return "\n".join(step.get("run", "") for step in STEPS)


def test_it_runs_from_the_base_branch_with_read_only_permissions() -> None:
    triggers = DOC.get("on", DOC.get(True))
    assert set(triggers) == {"pull_request_target"}
    assert DOC["permissions"] == {"contents": "read"}
    assert "permissions" not in JOB or JOB["permissions"] == {"contents": "read"}
    assert "secrets." not in TEXT


def test_only_the_base_commit_and_the_pinned_validator_are_checked_out() -> None:
    checkouts = [s for s in STEPS if str(s.get("uses", "")).startswith("actions/checkout@")]
    assert len(checkouts) == 2
    refs = [s["with"]["ref"] for s in checkouts]
    assert refs == ["${{ github.event.pull_request.base.sha }}", "${{ env.VALIDATOR_COMMIT }}"]
    assert all(s["with"]["persist-credentials"] is False for s in checkouts)
    assert "head.sha }}" not in "".join(str(s.get("with", {}).get("ref", "")) for s in STEPS)
    assert "head.ref" not in TEXT


def test_actions_are_pinned_to_full_commit_shas() -> None:
    for step in STEPS:
        if "uses" in step:
            assert re.match(r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$", step["uses"]), step["uses"]


def test_no_untrusted_text_is_interpolated_into_a_shell_line() -> None:
    script = run_lines()
    assert "${{" not in script
    for forbidden in ("pull_request.title", "pull_request.body", "head_ref", "head.ref", "github.event.comment"):
        assert forbidden not in TEXT


def test_no_pr_code_is_built_installed_or_executed() -> None:
    script = run_lines()
    for forbidden in ("npm ", "npx ", "cdk ", "make", "pip install -e", "pip install .", "subject/", "./subject", "bash subject", "sh subject", "git checkout", "git switch"):
        assert forbidden not in script, forbidden
    assert "validator/.github/scripts/install_cfn_guard.py" in script


def test_the_verifier_uses_the_base_contract_and_trusted_mode() -> None:
    script = run_lines()
    assert '--config-rev "$BASE_SHA"' in script
    assert '--head "$HEAD_SHA"' in script
    assert "--execution-mode trusted_ci" in script
    assert 'exit "$status"' in script
    assert "|| true" not in TEXT and "continue-on-error" not in TEXT


def test_the_fetched_head_must_equal_the_event_head() -> None:
    script = run_lines()
    assert '"$fetched" != "$HEAD_SHA"' in script
    assert "--no-recurse-submodules" in script
