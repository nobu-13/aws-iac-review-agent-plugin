"""Phase 1 traceability (AC41, AC42): the public AC map is complete and points at real things.

Reads ``docs/v2/phase1/`` only, so it runs on a clean checkout without
``.kiro/`` or ``.agents/``. It checks structure, not truth: a PASS status here
means "has a test or evidence entry", and the evidence itself is the test run.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PHASE1 = ROOT / "docs" / "v2" / "phase1"
MAP = json.loads((PHASE1 / "ac-traceability.json").read_text(encoding="utf-8"))
CASES = json.loads((ROOT / "benchmark" / "remediation" / "cases.json").read_text(encoding="utf-8"))["cases"]
ACS = MAP["acceptance_criteria"]


def test_all_48_acs_are_mapped_once_in_order() -> None:
    assert [a["id"] for a in ACS] == ["AC{0:02d}".format(i) for i in range(1, 49)]


def test_statuses_are_from_the_closed_set_and_pass_has_backing() -> None:
    for entry in ACS:
        assert entry["status"] in MAP["statuses"], entry["id"]
        if entry["status"] in ("PASS", "PARTIAL"):
            assert entry["tests"] or entry["evidence"], entry["id"]
        if entry["status"] in ("PARTIAL", "WAITING_HUMAN"):
            assert entry.get("note") or entry["evidence"], entry["id"]


def test_every_named_test_file_exists() -> None:
    for entry in ACS:
        for test in entry["tests"]:
            assert (ROOT / test).is_file(), (entry["id"], test)


def test_every_named_case_exists_and_every_family_is_traced() -> None:
    ids = {c["id"] for c in CASES}
    traced = set()
    for entry in ACS:
        for case in entry["cases"]:
            assert case in ids, (entry["id"], case)
            traced.add(case)
    families = {c["family"] for c in CASES if c["id"] in traced}
    assert families == {"C{0:02d}".format(i) for i in range(1, 25)}


def test_every_evidence_document_exists_and_anchors_resolve() -> None:
    for entry in ACS:
        for ref in entry["evidence"]:
            name, _, anchor = ref.partition("#")
            path = PHASE1 / name
            assert path.is_file(), (entry["id"], ref)
            if anchor:
                text = path.read_text(encoding="utf-8")
                headings = {re.sub(r"[^a-z0-9 -]", "", h.lower()).strip().replace(" ", "-") for h in re.findall(r"^#+ (.+)$", text, flags=re.M)}
                explicit = set(re.findall(r'<a id="([a-z0-9-]+)"></a>', text))
                assert anchor in headings | explicit, (entry["id"], ref)


def test_the_public_spec_documents_are_present() -> None:
    for name in ("requirements.md", "design.md", "tasks.md", "ac-traceability.json", "verification-report-schema.md", "threat-model.md", "evaluation.md", "implementation-evidence.md", "handoff.md"):
        assert (PHASE1 / name).is_file(), name
