"""The Phase 1 Skill document: same discipline as the five v1.0 Skills, own contract.

``tests/unit/test_skills.py`` checks the v1.0 Review_Report envelope and exit
code table, which this Skill does not use. Here the same document rules are
applied (front matter, description length and halves, one heading, section
order, ASCII) together with the Phase 1 contract: exit codes 0/20/21/22, the
CLI subcommands, the trusted-contract and stop-after-one-candidate rules.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from iacreview.remediation import rschema

ROOT = Path(__file__).resolve().parents[2]
SKILL = ROOT / "skills" / "iac-remediation-verify" / "SKILL.md"
TEXT = SKILL.read_text(encoding="utf-8")
SECTIONS = ("Purpose", "When to use this skill", "Input", "Output", "Limitations", "Dependencies")


def front_matter() -> dict:
    match = re.match(r"^---\n(.*?)\n---\n", TEXT, flags=re.S)
    assert match
    return yaml.safe_load(match.group(1))


def test_front_matter_and_description() -> None:
    fm = front_matter()
    assert fm["name"] == "iac-remediation-verify"
    description = fm["description"]
    assert 200 <= len(description) <= 1024
    assert "Use this skill when" in description and "Do not use it" in description
    assert "iac-review" in description


def test_structure_matches_the_other_skills() -> None:
    assert len(re.findall(r"^# ", TEXT, flags=re.M)) == 1
    assert tuple(re.findall(r"^## (.+)$", TEXT, flags=re.M)) == SECTIONS
    assert all(ord(ch) < 128 for ch in TEXT)


def test_the_documented_exit_codes_are_the_cli_codes() -> None:
    table = dict(re.findall(r"^\| (\d+) \| ([A-Z]+) \|", TEXT, flags=re.M))
    assert {int(k): v for k, v in table.items()} == {v: k for k, v in rschema.DECISION_EXIT_CODES.items()}


@pytest.mark.parametrize(
    "phrase",
    [
        "python3 -m iacreview.remediation init",
        "python3 -m iacreview.remediation verify",
        "python3 -m iacreview.remediation explain",
        "never read from Head or the working tree",
        "must not edit the contract",
        "stops there",
        "not an approval to\nmerge or deploy",
        "not bundled",
        "1.46.0",
        "3.2.1",
    ],
)
def test_the_document_states_the_contract(phrase: str) -> None:
    assert phrase in TEXT


def test_the_skill_ships_no_script() -> None:
    # The Skill drives the package CLI; the v1.0 script inventory is unchanged.
    assert not (SKILL.parent / "scripts").exists()
